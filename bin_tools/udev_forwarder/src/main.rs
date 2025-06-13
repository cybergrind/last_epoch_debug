use anyhow::{Result, anyhow};
use log::{debug, error, info, warn};
use std::{mem, process, ptr, time::Duration};
use tokio::{signal, sync, time::timeout};

const NETLINK_KOBJECT_UEVENT: i32 = 15;
const SOCKET_BUFFER_SIZE: i32 = 1024 * 1024; // 1MB
const EVENT_BUFFER_SIZE: usize = 8192;
const EPOLL_TIMEOUT_MS: i32 = 100;
const SHUTDOWN_TIMEOUT_SECS: u64 = 2;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("Starting udev event forwarder...");

    ensure_root_privileges()?;
    run_forwarder().await.unwrap_or_else(|e| {
        error!("Forwarder failed: {:#}", e);
        process::exit(1);
    });

    Ok(())
}

fn ensure_root_privileges() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        error!("This program must be run as root to access netlink sockets");
        process::exit(1);
    }
    Ok(())
}

async fn run_forwarder() -> Result<()> {
    info!("Setting up udev event listener...");

    let (tx, mut rx) = sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, shutdown_rx) = sync::oneshot::channel::<()>();

    let listener_handle =
        tokio::task::spawn_blocking(move || listen_netlink_events(tx, shutdown_rx));

    info!("Listening for udev events... (Press Ctrl+C to stop)");

    tokio::select! {
        _ = handle_events(&mut rx) => {},
        _ = wait_for_shutdown() => {
            info!("Shutdown signal received");
            let _ = shutdown_tx.send(());
        }
    }

    if timeout(Duration::from_secs(SHUTDOWN_TIMEOUT_SECS), listener_handle)
        .await
        .is_err()
    {
        warn!("Listener task didn't complete in time");
    }

    info!("Forwarder stopped");
    Ok(())
}

async fn handle_events(rx: &mut sync::mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(data) = rx.recv().await {
        handle_udev_event(&data);
    }
    error!("Netlink listener channel closed");
}

async fn wait_for_shutdown() {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("Failed to set up SIGTERM handler");
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .expect("Failed to set up SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => info!("Received SIGTERM"),
        _ = sigint.recv() => info!("Received SIGINT"),
    }
}

fn listen_netlink_events(
    tx: sync::mpsc::UnboundedSender<Vec<u8>>,
    mut shutdown_rx: sync::oneshot::Receiver<()>,
) -> Result<()> {
    let socket_fd = create_netlink_socket()?;
    let epoll_fd = setup_epoll(socket_fd)?;

    info!("Connected to netlink socket (epoll-based monitoring)");

    let mut buffer = vec![0u8; EVENT_BUFFER_SIZE];
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];

    loop {
        if shutdown_rx.try_recv().is_ok() {
            info!("Shutdown signal received in netlink listener");
            break;
        }

        match wait_for_socket_event(epoll_fd, &mut events) {
            Ok(true) => {
                if !process_socket_data(socket_fd, &mut buffer, &tx)? {
                    break;
                }
            }
            Ok(false) => continue, // Timeout, check shutdown signal
            Err(e) => {
                error!("Socket event error: {}", e);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    cleanup_sockets(socket_fd, epoll_fd);
    Ok(())
}

fn create_netlink_socket() -> Result<i32> {
    let socket_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            NETLINK_KOBJECT_UEVENT,
        )
    };

    if socket_fd == -1 {
        return Err(anyhow!("Failed to create netlink socket"));
    }

    // Bind to multicast group 1 for udev events
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = 1;

    let bind_result = unsafe {
        libc::bind(
            socket_fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };

    if bind_result == -1 {
        unsafe { libc::close(socket_fd) };
        return Err(anyhow!("Failed to bind netlink socket"));
    }

    // Set large buffer for event bursts
    unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &SOCKET_BUFFER_SIZE as *const _ as *const libc::c_void,
            mem::size_of::<i32>() as u32,
        );
    }

    Ok(socket_fd)
}

fn setup_epoll(socket_fd: i32) -> Result<i32> {
    let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll_fd == -1 {
        unsafe { libc::close(socket_fd) };
        return Err(anyhow!("Failed to create epoll instance"));
    }

    let mut epoll_event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: socket_fd as u64,
    };

    if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, socket_fd, &mut epoll_event) } == -1
    {
        cleanup_sockets(socket_fd, epoll_fd);
        return Err(anyhow!("Failed to add socket to epoll"));
    }

    Ok(epoll_fd)
}

fn wait_for_socket_event(epoll_fd: i32, events: &mut [libc::epoll_event]) -> Result<bool> {
    let ready_count = unsafe {
        libc::epoll_wait(
            epoll_fd,
            events.as_mut_ptr(),
            events.len() as i32,
            EPOLL_TIMEOUT_MS,
        )
    };

    match ready_count {
        -1 => {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EINTR {
                Ok(false) // Interrupted, continue
            } else {
                Err(anyhow!("epoll_wait failed: errno {}", errno))
            }
        }
        0 => Ok(false), // Timeout
        _ => Ok(true),  // Events ready
    }
}

fn process_socket_data(
    socket_fd: i32,
    buffer: &mut [u8],
    tx: &sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<bool> {
    loop {
        let bytes_received = unsafe {
            libc::recv(
                socket_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };

        match bytes_received {
            -1 => {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    break; // No more data
                }
                return Err(anyhow!("Error receiving from socket: errno {}", errno));
            }
            0 => {
                warn!("Netlink socket closed");
                return Ok(false);
            }
            n => {
                let event_data = extract_event_payload(&buffer[..n as usize]);
                if tx.send(event_data).is_err() {
                    return Ok(false); // Receiver dropped
                }
            }
        }
    }
    Ok(true)
}

fn extract_event_payload(data: &[u8]) -> Vec<u8> {
    if data.len() >= mem::size_of::<NetlinkMsgHeader>() {
        let header = unsafe { ptr::read_unaligned(data.as_ptr() as *const NetlinkMsgHeader) };
        let header_size = mem::size_of::<NetlinkMsgHeader>();

        if data.len() > header_size && header.nlmsg_len as usize >= header_size {
            let payload_size = std::cmp::min(
                header.nlmsg_len as usize - header_size,
                data.len() - header_size,
            );

            if payload_size > 0 {
                return data[header_size..header_size + payload_size].to_vec();
            }
        }
    }
    data.to_vec() // Fallback to raw data
}

fn cleanup_sockets(socket_fd: i32, epoll_fd: i32) {
    unsafe {
        libc::close(socket_fd);
        libc::close(epoll_fd);
    }
}

#[repr(C)]
struct NetlinkMsgHeader {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

fn handle_udev_event(event_data: &[u8]) {
    debug!("Processing udev event ({} bytes)", event_data.len());

    let parts: Vec<&str> = event_data
        .split(|&b| b == 0)
        .filter_map(|part| {
            if part.is_empty() {
                None
            } else {
                std::str::from_utf8(part).ok()
            }
        })
        .collect();

    if parts.is_empty() {
        warn!("Empty udev event received");
        return;
    }

    let mut event = UdevEvent::new();
    parse_event_parts(&parts, &mut event);

    log_event(&event);
}

#[derive(Debug, Default)]
struct UdevEvent {
    action: Option<String>,
    devpath: Option<String>,
    subsystem: Option<String>,
    devname: Option<String>,
    env_vars: Vec<(String, String)>,
}

impl UdevEvent {
    fn new() -> Self {
        Default::default()
    }
}

fn parse_event_parts(parts: &[&str], event: &mut UdevEvent) {
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            parse_event_header(part, event);
        } else if let Some((key, value)) = part.split_once('=') {
            parse_event_field(key, value, event);
        } else {
            debug!("Raw field: {}", part);
        }
    }
}

fn parse_event_header(header: &str, event: &mut UdevEvent) {
    if let Some((action, devpath)) = header.split_once('@') {
        event.action = Some(action.to_string());
        event.devpath = Some(devpath.to_string());
        info!("Event: {} @ {}", action, devpath);
    } else {
        info!("Event header: {}", header);
    }
}

fn parse_event_field(key: &str, value: &str, event: &mut UdevEvent) {
    match key {
        "SUBSYSTEM" => {
            event.subsystem = Some(value.to_string());
            debug!("  SUBSYSTEM: {}", value);
        }
        "DEVNAME" => {
            event.devname = Some(value.to_string());
            debug!("  DEVNAME: {}", value);
        }
        "DEVPATH" | "ACTION" | "SEQNUM" | "MAJOR" | "MINOR" => {
            debug!("  {}: {}", key, value);
        }
        _ => {
            event.env_vars.push((key.to_string(), value.to_string()));
        }
    }
}

fn log_event(event: &UdevEvent) {
    if !event.env_vars.is_empty() {
        debug!("Environment variables: {:?}", event.env_vars);
    }

    match (&event.action, &event.devpath, &event.subsystem) {
        (Some(action), Some(devpath), Some(subsystem)) => {
            let device_info = event
                .devname
                .as_ref()
                .map(|d| format!(" ({})", d))
                .unwrap_or_default();
            info!(
                "Summary: {} action on {} [{}]{}",
                action, devpath, subsystem, device_info
            );
        }
        (Some(action), Some(devpath), None) => {
            info!("Summary: {} action on {}", action, devpath);
        }
        _ => {
            warn!("Summary: Partial or malformed event");
        }
    }
}
