use anyhow::{anyhow, Result};
use log::{error, info, warn};
use std::mem;
use tokio::{io::AsyncReadExt, net::UnixStream, signal};
use udev_forwarder::shared::{NetlinkMsgHeader, NETLINK_KOBJECT_UEVENT, UNIX_SOCKET_PATH};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("Starting udev event receiver...");

    // Check if running as root (required for netlink broadcasting)
    if unsafe { libc::geteuid() } != 0 {
        warn!("Not running as root - netlink broadcasting will be disabled");
        warn!("Run with sudo to enable netlink event broadcasting in namespace");
    }

    // Create netlink socket for broadcasting (if running as root)
    let netlink_fd = if unsafe { libc::geteuid() } == 0 {
        match create_netlink_broadcast_socket() {
            Ok(fd) => {
                info!("Created netlink broadcast socket");
                Some(fd)
            }
            Err(e) => {
                error!("Failed to create netlink socket: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Connect to Unix socket
    let mut stream = UnixStream::connect(UNIX_SOCKET_PATH).await?;
    info!("Connected to forwarder at {}", UNIX_SOCKET_PATH);

    let mut buffer = vec![0u8; 8192];
    let mut accumulated = Vec::new();

    loop {
        tokio::select! {
            result = stream.read(&mut buffer) => {
                match result {
                    Ok(0) => {
                        warn!("Forwarder disconnected");
                        break;
                    }
                    Ok(n) => {
                        accumulated.extend_from_slice(&buffer[..n]);
                        process_accumulated_data(&mut accumulated, netlink_fd);
                    }
                    Err(e) => {
                        error!("Failed to read from socket: {}", e);
                        break;
                    }
                }
            }
            _ = wait_for_shutdown() => {
                info!("Shutdown signal received");
                break;
            }
        }
    }

    if let Some(fd) = netlink_fd {
        unsafe {
            libc::close(fd);
        }
    }

    info!("Receiver stopped");
    Ok(())
}

fn process_accumulated_data(accumulated: &mut Vec<u8>, netlink_fd: Option<i32>) {
    loop {
        if accumulated.len() < 4 {
            break;
        }

        let size_bytes: [u8; 4] = accumulated[0..4].try_into().unwrap();
        let size = u32::from_le_bytes(size_bytes) as usize;

        if accumulated.len() < 4 + size {
            break;
        }

        let message_data = accumulated[4..4 + size].to_vec();
        accumulated.drain(0..4 + size);

        handle_udev_event(&message_data);

        // Broadcast the event via netlink if we have a socket
        if let Some(fd) = netlink_fd {
            if let Err(e) = broadcast_netlink_event(fd, &message_data) {
                error!("Failed to broadcast netlink event: {}", e);
            }
        }
    }
}

fn handle_udev_event(event_data: &[u8]) {
    println!("\n=== Received UDev Event ===");

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
    let mut other_fields = Vec::new();

    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if let Some((a, d)) = part.split_once('@') {
                (action, devpath) = (Some(a), Some(d));
                println!("Event: {} @ {}", a, d);
            } else {
                println!("Event header: {}", part);
            }
        } else if let Some((key, value)) = part.split_once('=') {
            match key {
                "SUBSYSTEM" => {
                    subsystem = Some(value);
                    println!("  SUBSYSTEM: {}", value);
                }
                "DEVNAME" => {
                    devname = Some(value);
                    println!("  DEVNAME: {}", value);
                }
                "DEVPATH" | "ACTION" | "SEQNUM" => {
                    println!("  {}: {}", key, value);
                }
                _ => {
                    other_fields.push((key, value));
                }
            }
        } else {
            println!("  Raw: {}", part);
        }
    }

    // Print other fields
    for (key, value) in other_fields {
        println!("  {}: {}", key, value);
    }

    // Print summary
    match (action, devpath, subsystem) {
        (Some(a), Some(d), Some(s)) => println!(
            "Summary: {} action on {} [{}]{}",
            a,
            d,
            s,
            devname.map(|n| format!(" ({})", n)).unwrap_or_default()
        ),
        (Some(a), Some(d), None) => println!("Summary: {} action on {}", a, d),
        _ => println!("Summary: Partial or malformed event"),
    }

    println!("==========================");
}

async fn wait_for_shutdown() {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt()).unwrap();
    tokio::select! {
        _ = sigterm.recv() => info!("Received SIGTERM"),
        _ = sigint.recv() => info!("Received SIGINT"),
    }
}

fn create_netlink_broadcast_socket() -> Result<i32> {
    // Create netlink socket
    let socket_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_KOBJECT_UEVENT,
        )
    };

    if socket_fd == -1 {
        return Err(anyhow!("Failed to create netlink socket"));
    }

    // Bind to broadcast
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0; // Use kernel PID for broadcasting
    addr.nl_groups = 1; // Broadcast to multicast group 1

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

    info!("Netlink broadcast socket created and bound");
    Ok(socket_fd)
}

fn broadcast_netlink_event(socket_fd: i32, event_data: &[u8]) -> Result<()> {
    // Create netlink message with header
    let total_len = mem::size_of::<NetlinkMsgHeader>() + event_data.len();
    let mut message = Vec::with_capacity(total_len);

    // Create and add netlink header
    let header = NetlinkMsgHeader {
        nlmsg_len: total_len as u32,
        nlmsg_type: 0, // Kernel event
        nlmsg_flags: 0,
        nlmsg_seq: 0,
        nlmsg_pid: 0, // From kernel
    };

    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            &header as *const _ as *const u8,
            mem::size_of::<NetlinkMsgHeader>(),
        )
    };
    message.extend_from_slice(header_bytes);
    message.extend_from_slice(event_data);

    // Setup destination address for broadcast
    let mut dest_addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    dest_addr.nl_family = libc::AF_NETLINK as u16;
    dest_addr.nl_pid = 0; // Broadcast to all
    dest_addr.nl_groups = 1; // Multicast group 1

    // Send the message
    let bytes_sent = unsafe {
        libc::sendto(
            socket_fd,
            message.as_ptr() as *const libc::c_void,
            message.len(),
            0,
            &dest_addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };

    if bytes_sent == -1 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(anyhow!("Failed to send netlink message: errno {}", errno));
    }

    info!("Broadcast netlink event ({} bytes)", bytes_sent);
    Ok(())
}
