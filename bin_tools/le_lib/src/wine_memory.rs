use libc::{iovec, pid_t, process_vm_readv, process_vm_writev};
use log::{error, info, warn};
use std::io;
use std::process;

/// Read memory from the current process safely, even in Wine environment
pub fn safe_read_memory(address: u64, size: usize) -> Result<Vec<u8>, String> {
    // For Wine processes, we use process_vm_readv which bypasses memory protection
    // mechanisms that might cause segfaults

    let pid = process::id() as pid_t;
    let mut buffer = vec![0u8; size];

    // Setup the local iovec which points to our buffer
    let local_iov = iovec {
        iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
        iov_len: size,
    };

    // Setup the remote iovec which points to the target memory
    let remote_iov = iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: size,
    };

    // Use process_vm_readv to read memory from the process itself
    // This bypasses normal memory protection mechanisms
    let result = unsafe {
        process_vm_readv(
            pid,
            &local_iov as *const iovec,
            1,
            &remote_iov as *const iovec,
            1,
            0,
        )
    };

    if result == -1 {
        let err = io::Error::last_os_error();
        error!("Failed to read memory at 0x{:x}: {}", address, err);
        return Err(format!("Failed to read memory at 0x{:x}: {}", address, err));
    }

    // Check if we actually read the requested amount
    if result as usize != size {
        warn!(
            "Partial read from 0x{:x}: requested {} bytes, got {}",
            address, size, result
        );
    }

    info!("Successfully read {} bytes from 0x{:x}", result, address);
    Ok(buffer)
}

/// Write memory to the current process safely, even in Wine environment
pub fn safe_write_memory(address: u64, data: &[u8]) -> Result<(), String> {
    let pid = process::id() as pid_t;
    let size = data.len();

    // Setup the local iovec which points to our data
    let local_iov = iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: size,
    };

    // Setup the remote iovec which points to the target memory
    let remote_iov = iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: size,
    };

    // Use process_vm_writev to write memory to the process itself
    // This bypasses normal memory protection mechanisms
    let result = unsafe {
        process_vm_writev(
            pid,
            &local_iov as *const iovec,
            1,
            &remote_iov as *const iovec,
            1,
            0,
        )
    };

    if result == -1 {
        let err = io::Error::last_os_error();
        error!("Failed to write memory at 0x{:x}: {}", address, err);
        return Err(format!(
            "Failed to write memory at 0x{:x}: {}",
            address, err
        ));
    }

    // Check if we actually wrote the requested amount
    if result as usize != size {
        warn!(
            "Partial write to 0x{:x}: requested {} bytes, wrote {}",
            address, size, result
        );
    }

    // Force CPU to flush write to ensure visibility
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

    info!("Successfully wrote {} bytes to 0x{:x}", result, address);
    Ok(())
}
