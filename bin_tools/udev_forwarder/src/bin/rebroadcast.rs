use anyhow::{anyhow, Result};
use clap::Parser;
use log::{error, info, warn};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use tokio::signal;

const PID_FILE: &str = "/run/udev-rebroadcast.pid";
const DEFAULT_NAMESPACE: &str = "novpn";

#[derive(Parser, Debug)]
#[command(author, version, about = "UDev event rebroadcaster - runs forwarder and receiver", long_about = None)]
struct Args {
    /// Network namespace name
    #[arg(long, default_value = DEFAULT_NAMESPACE)]
    namespace: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    // Check if running as root
    if unsafe { libc::geteuid() } != 0 {
        error!("This program must be run as root");
        std::process::exit(1);
    }

    // Kill any existing instances
    kill_existing_instances()?;

    // Write our PID
    write_pid_file()?;

    info!(
        "Starting udev rebroadcaster for namespace '{}'",
        args.namespace
    );

    // Get the path to our own executable directory
    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| anyhow!("Failed to get executable directory"))?;

    let forwarder_path = exe_dir.join("udev-forwarder");
    let receiver_path = exe_dir.join("udev-receiver");

    // Check that both binaries exist
    if !forwarder_path.exists() {
        return Err(anyhow!("udev-forwarder not found at {:?}", forwarder_path));
    }
    if !receiver_path.exists() {
        return Err(anyhow!("udev-receiver not found at {:?}", receiver_path));
    }

    // Start forwarder outside namespace
    info!("Starting forwarder outside namespace...");
    let mut forwarder = Command::new(&forwarder_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // Give forwarder time to start and create socket
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Check if forwarder is still running
    match forwarder.try_wait()? {
        Some(status) => {
            return Err(anyhow!("Forwarder exited early with status: {}", status));
        }
        None => info!("Forwarder started successfully"),
    }

    // Start receiver inside namespace
    info!("Starting receiver inside namespace '{}'...", args.namespace);
    let mut receiver = Command::new("ip")
        .args(&["netns", "exec", &args.namespace])
        .arg(&receiver_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // Give receiver time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Check if receiver is still running
    match receiver.try_wait()? {
        Some(status) => {
            // Kill forwarder if receiver failed
            let _ = forwarder.kill();
            return Err(anyhow!("Receiver exited early with status: {}", status));
        }
        None => info!("Receiver started successfully"),
    }

    info!("Rebroadcaster running. Press Ctrl+C to stop...");

    // Wait for shutdown signal
    wait_for_shutdown().await;

    info!("Shutting down...");

    // Kill both processes
    let _ = forwarder.kill();
    let _ = receiver.kill();

    // Wait for them to exit
    let _ = forwarder.wait();
    let _ = receiver.wait();

    // Clean up PID file
    let _ = fs::remove_file(PID_FILE);

    info!("Rebroadcaster stopped");
    Ok(())
}

fn kill_existing_instances() -> Result<()> {
    if Path::new(PID_FILE).exists() {
        match fs::read_to_string(PID_FILE) {
            Ok(pid_str) => {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    info!("Found existing instance with PID {}, killing it...", pid);
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                    // Give it time to clean up
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                }
            }
            Err(e) => {
                warn!("Failed to read PID file: {}", e);
            }
        }
        // Remove the old PID file
        let _ = fs::remove_file(PID_FILE);
    }

    // Also kill any orphaned forwarder/receiver processes
    kill_process_by_name("udev-forwarder");
    kill_process_by_name("udev-receiver");

    Ok(())
}

fn kill_process_by_name(name: &str) {
    match Command::new("pkill").arg("-f").arg(name).output() {
        Ok(_) => {}
        Err(e) => {
            warn!("Failed to run pkill for {}: {}", name, e);
        }
    }
}

fn write_pid_file() -> Result<()> {
    let pid = std::process::id();
    fs::write(PID_FILE, pid.to_string())?;
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
