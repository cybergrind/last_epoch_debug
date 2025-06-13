use anyhow::{Result, anyhow};
use log::{error, info, warn};
use std::{mem, process, ptr, time::Duration};
use tokio::{signal, sync, time::timeout};

const NETLINK_KOBJECT_UEVENT: i32 = 15;
const SOCKET_BUFFER_SIZE: i32 = 1024 * 1024;
const EVENT_BUFFER_SIZE: usize = 8192;
const EPOLL_TIMEOUT_MS: i32 = 100;
const SHUTDOWN_TIMEOUT_SECS: u64 = 2;

#[repr(C)]
struct NetlinkMsgHeader {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    if unsafe { libc::geteuid() } != 0 {
        error!("This program must be run as root to access netlink sockets");
        process::exit(1);
    }

    info!("Starting udev event forwarder...");

    let (tx, mut rx) = sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, shutdown_rx) = sync::oneshot::channel::<()>();
    let listener_handle =
        tokio::task::spawn_blocking(move || listen_netlink_events(tx, shutdown_rx));

    info!("Listening for udev events... (Press Ctrl+C to stop)");

    tokio::select! {
        _ = async { while let Some(data) = rx.recv().await { handle_udev_event(&data); } } => {},
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

async fn wait_for_shutdown() {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt()).unwrap();
    tokio::select! {
        _ = sigterm.recv() => info!("Received SIGTERM"),
        _ = sigint.recv() => info!("Received SIGINT"),
    }
}

fn listen_netlink_events(
    tx: sync::mpsc::UnboundedSender<Vec<u8>>,
    mut shutdown_rx: sync::oneshot::Receiver<()>,
) -> Result<()> {
    let (socket_fd, epoll_fd) = setup_sockets()?;
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
            Ok(false) => continue,
            Err(e) => {
                error!("Socket event error: {}", e);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    unsafe {
        libc::close(socket_fd);
        libc::close(epoll_fd);
    }
    Ok(())
}

fn setup_sockets() -> Result<(i32, i32)> {
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

    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = 1;

    if unsafe {
        libc::bind(
            socket_fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    } == -1
    {
        unsafe {
            libc::close(socket_fd);
        }
        return Err(anyhow!("Failed to bind netlink socket"));
    }

    unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &SOCKET_BUFFER_SIZE as *const _ as *const libc::c_void,
            mem::size_of::<i32>() as u32,
        );
    }

    let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll_fd == -1 {
        unsafe {
            libc::close(socket_fd);
        }
        return Err(anyhow!("Failed to create epoll instance"));
    }

    let mut epoll_event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: socket_fd as u64,
    };
    if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, socket_fd, &mut epoll_event) } == -1
    {
        unsafe {
            libc::close(socket_fd);
            libc::close(epoll_fd);
        }
        return Err(anyhow!("Failed to add socket to epoll"));
    }

    Ok((socket_fd, epoll_fd))
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
                Ok(false)
            } else {
                Err(anyhow!("epoll_wait failed: errno {}", errno))
            }
        }
        0 => Ok(false),
        _ => Ok(true),
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
                    break;
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
                    return Ok(false);
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
    data.to_vec()
}

fn handle_udev_event(event_data: &[u8]) {
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

    let (mut action, mut devpath, mut subsystem, mut devname) = (None, None, None, None);

    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if let Some((a, d)) = part.split_once('@') {
                (action, devpath) = (Some(a), Some(d));
                info!("Event: {} @ {}", a, d);
            } else {
                info!("Event header: {}", part);
            }
        } else if let Some((key, value)) = part.split_once('=') {
            match key {
                "SUBSYSTEM" => subsystem = Some(value),
                "DEVNAME" => devname = Some(value),
                _ => {}
            }
        }
    }

    match (action, devpath, subsystem) {
        (Some(a), Some(d), Some(s)) => info!(
            "Summary: {} action on {} [{}]{}",
            a,
            d,
            s,
            devname.map(|n| format!(" ({})", n)).unwrap_or_default()
        ),
        (Some(a), Some(d), None) => info!("Summary: {} action on {}", a, d),
        _ => warn!("Summary: Partial or malformed event"),
    }
}
