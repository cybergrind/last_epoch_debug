use libc::{
    iovec, pid_t, process_vm_readv, process_vm_writev, PROT_EXEC, PROT_READ, PROT_WRITE,
};
use log::{debug, error, info, warn};
use std::fs;
use std::io;
use std::io::{Write, Seek};
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

    // Log the first few bytes that were read
    if result > 0 {
        let byte_str = buffer
            .iter()
            .take(std::cmp::min(size, 16))
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(" ");
        debug!("First bytes read from 0x{:x}: {}", address, byte_str);
    }

    Ok(buffer)
}

/// Write memory to the current process safely, even in Wine environment
pub fn safe_write_memory(address: u64, data: &[u8]) -> Result<(), String> {
    // First, attempt to read the memory to ensure the address is valid
    let existing_data = safe_read_memory(address, data.len())?;

    // Log the current content for debugging
    let exist_str = existing_data
        .iter()
        .take(std::cmp::min(data.len(), 16))
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(" ");

    let new_str = data
        .iter()
        .take(std::cmp::min(data.len(), 16))
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(" ");

    info!("Current bytes at 0x{:x}: {}", address, exist_str);
    info!("New bytes to write: {}", new_str);

    // Try using process_vm_writev first (standard approach)
    let result = try_process_vm_writev(address, data);
    if result.is_ok() {
        return result;
    }

    info!("Standard process_vm_writev failed, attempting alternative methods");

    // Try using ptrace to modify memory - this requires a more complex approach
    let ptrace_result = try_ptrace_write_memory(address, data);
    if ptrace_result.is_ok() {
        return ptrace_result;
    }

    // Try using /proc/self/mem for writing (works on some systems)
    let procmem_result = try_procmem_write(address, data);
    if procmem_result.is_ok() {
        return procmem_result;
    }

    // If all direct methods failed, try temporarily remapping the memory with mprotect
    try_mprotect_and_write(address, data)
}

/// Try using process_vm_writev to write memory
fn try_process_vm_writev(address: u64, data: &[u8]) -> Result<(), String> {
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
        info!("process_vm_writev failed for address 0x{:x}: {}", address, err);
        return Err(format!("Failed to write memory at 0x{:x}: {}", address, err));
    }

    // Check if we actually wrote the requested amount
    if result as usize != size {
        warn!(
            "Partial write to 0x{:x}: requested {} bytes, wrote {}",
            address, size, result
        );
    }

    info!(
        "Successfully wrote {} bytes to 0x{:x} using process_vm_writev",
        result, address
    );
    Ok(())
}

/// Try using ptrace to write memory
fn try_ptrace_write_memory(address: u64, data: &[u8]) -> Result<(), String> {
    // We'll use ptrace to attach to our own process and modify memory
    // This is complex and might not work in all environments but can bypass some protections

    let pid = process::id() as pid_t;

    // Attach to the process
    let ptrace_attach_result = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) };
    if ptrace_attach_result == -1 {
        let err = io::Error::last_os_error();
        info!("ptrace attach failed: {}", err);
        return Err(format!("ptrace attach failed: {}", err));
    }

    // Wait for the process to stop
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    let mut success = true;

    // Write memory one word at a time
    let words = data.chunks(std::mem::size_of::<libc::c_long>());
    for (i, chunk) in words.enumerate() {
        // Create a word from the chunk, filling with zeros if needed
        let mut word: libc::c_long = 0;
        for (j, &byte) in chunk.iter().enumerate() {
            let shift = j * 8;
            word |= (byte as libc::c_long) << shift;
        }

        // Calculate address for this word
        let word_addr = address + (i * std::mem::size_of::<libc::c_long>()) as u64;

        // Write the word
        let ptrace_poke_result = unsafe {
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                pid,
                word_addr as *mut libc::c_void,
                word as *mut libc::c_void,
            )
        };

        if ptrace_poke_result == -1 {
            let err = io::Error::last_os_error();
            info!("ptrace poke failed at address 0x{:x}: {}", word_addr, err);
            success = false;
            break;
        }
    }

    // Detach from the process
    unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) };

    if success {
        info!(
            "Successfully wrote {} bytes to 0x{:x} using ptrace",
            data.len(),
            address
        );
        Ok(())
    } else {
        Err("Failed to write memory using ptrace".to_string())
    }
}

/// Try writing to /proc/self/mem directly
fn try_procmem_write(address: u64, data: &[u8]) -> Result<(), String> {
    let mem_path = "/proc/self/mem";

    // Open /proc/self/mem for writing
    let result = std::fs::OpenOptions::new().write(true).open(mem_path);

    let mut file = match result {
        Ok(f) => f,
        Err(e) => {
            info!("Failed to open {} for writing: {}", mem_path, e);
            return Err(format!("Failed to open {} for writing: {}", mem_path, e));
        }
    };

    // Seek to the target address
    if let Err(e) = file.seek(std::io::SeekFrom::Start(address)) {
        info!("Failed to seek to address 0x{:x}: {}", address, e);
        return Err(format!("Failed to seek to address 0x{:x}: {}", address, e));
    }

    // Write the data
    match file.write_all(data) {
        Ok(_) => {
            info!(
                "Successfully wrote {} bytes to 0x{:x} using /proc/self/mem",
                data.len(),
                address
            );
            Ok(())
        }
        Err(e) => {
            info!("Failed to write to /proc/self/mem: {}", e);
            Err(format!("Failed to write to /proc/self/mem: {}", e))
        }
    }
}

/// Try using mprotect to temporarily change memory protection and then write
fn try_mprotect_and_write(address: u64, data: &[u8]) -> Result<(), String> {
    // Calculate page boundaries
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let page_mask = !(page_size - 1);
    let page_start = (address & page_mask as u64) as *mut libc::c_void;
    let page_end =
        (((address + data.len() as u64 - 1) & page_mask as u64) + page_size as u64) as *mut libc::c_void;
    let region_size = (page_end as usize) - (page_start as usize);

    info!(
        "Attempting to change memory protection for region 0x{:x} - 0x{:x}",
        page_start as u64, page_end as u64
    );

    // Try to make the memory writable
    let mprotect_result = unsafe {
        libc::mprotect(
            page_start,
            region_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        )
    };

    if mprotect_result == -1 {
        let err = io::Error::last_os_error();
        info!("mprotect failed: {}", err);
        return Err(format!("mprotect failed: {}", err));
    }

    // Write the data directly
    let write_result = unsafe {
        let ptr = address as *mut u8;
        for (i, &byte) in data.iter().enumerate() {
            std::ptr::write_volatile(ptr.add(i), byte);
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        Ok(())
    };

    // Restore original protection (we use PROT_READ | PROT_EXEC as that's typical for code)
    let _ = unsafe { libc::mprotect(page_start, region_size, PROT_READ | PROT_EXEC) };

    if write_result.is_ok() {
        info!(
            "Successfully wrote {} bytes to 0x{:x} using mprotect+write",
            data.len(),
            address
        );
    }

    write_result
}

/// Helper function to log memory content as hex dump
pub fn log_memory_hex_dump(address: u64, size: usize, label: &str) -> Result<(), String> {
    match safe_read_memory(address, size) {
        Ok(data) => {
            // Format and log memory content in a readable hex dump
            let mut hex_dump = String::new();
            let mut chars = String::new();

            for (i, &byte) in data.iter().enumerate() {
                // Add address at the beginning of each line
                if i % 16 == 0 {
                    if i > 0 {
                        hex_dump.push_str(&format!("  {}\n", chars));
                        chars.clear();
                    }
                    hex_dump.push_str(&format!("{:08x}:", address as usize + i));
                }

                // Add hex value
                hex_dump.push_str(&format!(" {:02x}", byte));

                // Add printable character or dot
                if byte >= 32 && byte <= 126 {
                    chars.push(byte as char);
                } else {
                    chars.push('.');
                }
            }

            // Add padding and chars for the last line
            let remaining = data.len() % 16;
            if remaining > 0 {
                for _ in remaining..16 {
                    hex_dump.push_str("   ");
                }
            }
            hex_dump.push_str(&format!("  {}\n", chars));

            info!("{} memory at 0x{:x}:\n{}", label, address, hex_dump);
            Ok(())
        }
        Err(e) => Err(e),
    }
}
