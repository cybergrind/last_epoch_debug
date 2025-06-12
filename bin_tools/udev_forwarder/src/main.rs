use anyhow::{Context, Result};
use log::{error, info, warn};
use std::{
    process,
    ptr,
    mem,
};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("Starting udev event forwarder...");

    // Check if running as root (required for netlink access)
    if unsafe { libc::geteuid() } != 0 {
        error!("This program must be run as root to access netlink sockets");
        process::exit(1);
    }

    let result = run_forwarder().await;
    
    if let Err(e) = result {
        error!("Forwarder failed: {:#}", e);
        process::exit(1);
    }

    Ok(())
}

async fn run_forwarder() -> Result<()> {
    info!("Setting up udev event listener...");

    // Set up signal handling for graceful shutdown
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .context("Failed to set up SIGTERM handler")?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .context("Failed to set up SIGINT handler")?;

    // Spawn the netlink listener in a separate task
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    
    let listener_handle = tokio::task::spawn_blocking(move || {
        listen_netlink_events(tx)
    });

    info!("Listening for udev events... (Press Ctrl+C to stop)");

    loop {
        tokio::select! {
            // Handle incoming events from netlink listener
            event_data = rx.recv() => {
                match event_data {
                    Some(data) => {
                        handle_udev_event(&data);
                    }
                    None => {
                        error!("Netlink listener channel closed");
                        break;
                    }
                }
            }
            
            // Handle shutdown signals
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully...");
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down gracefully...");
                break;
            }
        }
    }

    // Wait for the listener task to complete
    listener_handle.abort();
    info!("Forwarder stopped");
    Ok(())
}

fn listen_netlink_events(tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>) -> Result<()> {
    
    // Create raw netlink socket for udev events
    let socket_fd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 15) // NETLINK_KOBJECT_UEVENT = 15
    };
    
    if socket_fd == -1 {
        return Err(anyhow::anyhow!("Failed to create netlink socket"));
    }
    
    // Bind to multicast group 1 for udev events
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0; // Kernel will assign PID
    addr.nl_groups = 1; // Subscribe to multicast group 1
    
    let bind_result = unsafe {
        libc::bind(
            socket_fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    
    if bind_result == -1 {
        unsafe { libc::close(socket_fd); }
        return Err(anyhow::anyhow!("Failed to bind netlink socket"));
    }
    
    // Increase socket buffer size to handle bursts of events
    let buffer_size = 1024 * 1024; // 1MB
    unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buffer_size as *const i32 as *const libc::c_void,
            mem::size_of::<i32>() as u32,
        );
    }
    
    info!("Connected to netlink socket for udev events (raw socket mode)");

    let mut buffer = vec![0u8; 8192]; // 8KB buffer for udev events
    
    loop {
        // Receive data from netlink socket
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
                    // No data available, continue
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                } else {
                    error!("Error receiving from netlink socket: errno {}", errno);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
            }
            0 => {
                // Socket closed
                warn!("Netlink socket closed");
                break;
            }
            n if n > 0 => {
                let event_data = buffer[..n as usize].to_vec();
                
                // Parse netlink message header to extract payload
                if event_data.len() >= mem::size_of::<NetlinkMsgHeader>() {
                    let header = unsafe {
                        ptr::read_unaligned(event_data.as_ptr() as *const NetlinkMsgHeader)
                    };
                    
                    // Extract payload (skip netlink header)
                    let header_size = mem::size_of::<NetlinkMsgHeader>();
                    if event_data.len() > header_size && header.nlmsg_len as usize >= header_size {
                        let payload_size = std::cmp::min(
                            header.nlmsg_len as usize - header_size,
                            event_data.len() - header_size
                        );
                        
                        if payload_size > 0 {
                            let payload = event_data[header_size..header_size + payload_size].to_vec();
                            if let Err(_) = tx.send(payload) {
                                // Receiver has been dropped, exit
                                break;
                            }
                        }
                    }
                } else {
                    // Treat as raw udev event if too small for netlink header
                    if let Err(_) = tx.send(event_data) {
                        break;
                    }
                }
            }
            _ => {
                error!("Unexpected return value from recv: {}", bytes_received);
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
        }
    }
    
    unsafe { libc::close(socket_fd); }
    Ok(())
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
    println!("=== UDev Event ===");
    println!("Raw bytes length: {}", event_data.len());
    
    // UDev events are structured as null-terminated strings
    // The format is typically: action@devpath\0SUBSYSTEM=...\0DEVNAME=...\0...
    let parts: Vec<&[u8]> = event_data.split(|&b| b == 0).filter(|part| !part.is_empty()).collect();
    
    if parts.is_empty() {
        println!("Empty event received");
        println!("==================\n");
        return;
    }
    
    let mut action = None;
    let mut devpath = None;
    let mut subsystem = None;
    let mut devname = None;
    let mut env_vars = Vec::new();
    
    for (i, part) in parts.iter().enumerate() {
        match std::str::from_utf8(part) {
            Ok(s) => {
                if i == 0 {
                    // First part is usually the action@devpath
                    if let Some(at_pos) = s.find('@') {
                        action = Some(s[..at_pos].to_string());
                        devpath = Some(s[at_pos + 1..].to_string());
                        println!("Event: {} @ {}", &s[..at_pos], &s[at_pos + 1..]);
                    } else {
                        println!("Event header: {}", s);
                    }
                } else if s.contains('=') {
                    let mut split = s.splitn(2, '=');
                    if let (Some(key), Some(value)) = (split.next(), split.next()) {
                        match key {
                            "SUBSYSTEM" => {
                                subsystem = Some(value.to_string());
                                println!("  SUBSYSTEM: {}", value);
                            }
                            "DEVNAME" => {
                                devname = Some(value.to_string());
                                println!("  DEVNAME: {}", value);
                            }
                            "DEVPATH" => println!("  DEVPATH: {}", value),
                            "ACTION" => println!("  ACTION: {}", value),
                            "SEQNUM" => println!("  SEQNUM: {}", value),
                            "MAJOR" => println!("  MAJOR: {}", value),
                            "MINOR" => println!("  MINOR: {}", value),
                            _ => {
                                env_vars.push((key.to_string(), value.to_string()));
                            }
                        }
                    }
                } else {
                    println!("  Raw field: {}", s);
                }
            }
            Err(_) => {
                // Binary data - show as hex
                if part.len() <= 32 {
                    println!("  Binary data: {:02x?}", part);
                } else {
                    println!("  Binary data ({} bytes): {:02x?}...", part.len(), &part[..16]);
                }
            }
        }
    }
    
    // Print environment variables if any
    if !env_vars.is_empty() {
        println!("  Environment variables:");
        for (key, value) in env_vars {
            println!("    {}: {}", key, value);
        }
    }
    
    // Print a clean summary
    match (action, devpath, subsystem) {
        (Some(action), Some(devpath), Some(subsystem)) => {
            let device_info = devname.map(|d| format!(" ({})", d)).unwrap_or_default();
            println!("Summary: {} action on {} [{}]{}", action, devpath, subsystem, device_info);
        }
        (Some(action), Some(devpath), None) => {
            println!("Summary: {} action on {}", action, devpath);
        }
        _ => {
            println!("Summary: Partial or malformed event");
        }
    }
    
    println!("==================\n");
}
