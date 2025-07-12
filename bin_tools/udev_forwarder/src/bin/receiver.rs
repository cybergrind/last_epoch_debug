use anyhow::Result;
use log::{error, info, warn};
use tokio::{net::UnixStream, io::AsyncReadExt, signal};
use udev_forwarder::shared::UNIX_SOCKET_PATH;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("Starting udev event receiver...");

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
                        process_accumulated_data(&mut accumulated);
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

    info!("Receiver stopped");
    Ok(())
}

fn process_accumulated_data(accumulated: &mut Vec<u8>) {
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