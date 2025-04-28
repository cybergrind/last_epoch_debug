use log::info;
use std::ptr;

use crate::hook_tools::ActiveHook;
use crate::hook_tools::Hook;

/// Injects compiled code into memory and updates the game code
#[allow(unused_variables)]
pub unsafe fn inject_hook(
    hook: &Hook,
    trampoline_data: &[u8],
    jumper_data: &[u8],
) -> Result<ActiveHook, String> {
    unsafe {
        info!(
            "Injecting hook '{}' at address {}",
            hook.name, hook.target_address
        );

        // Parse the target address
        let target_address = match crate::hook_tools::parse_hex_address(&hook.target_address) {
            Ok(addr) => addr,
            Err(e) => return Err(format!("Failed to parse target address: {}", e)),
        };

        // Get the hook function address
        let hook_function_address =
            match crate::hook_tools::get_function_address(&hook.hook_function) {
                Ok(addr) => addr,
                Err(e) => return Err(format!("Failed to get hook function address: {}", e)),
            };

        // In a real implementation, we would:
        // 1. Allocate executable memory for the trampoline
        // 2. Copy the trampoline code to the allocated memory
        // 3. Save the original bytes at the target address
        // 4. Write the jumper instruction to the target address

        // For now, implement a placeholder - memory management will be added in a more extensive implementation
        let trampoline_address = allocate_executable_memory(trampoline_data.len())?;

        // Copy the trampoline data to the allocated memory
        copy_to_executable_memory(trampoline_address, trampoline_data)?;

        // Save the original bytes at the target address
        let original_bytes = read_memory(target_address, jumper_data.len())?;

        // Write the jumper code to the target address
        write_memory(target_address, jumper_data)?;

        // Create and return the active hook
        Ok(ActiveHook {
            name: hook.name.clone(),
            target_address,
            trampoline_address,
            hook_function_address,
            original_bytes,
        })
    }
}

/// Allocates memory with executable permissions
unsafe fn allocate_executable_memory(size: usize) -> Result<u64, String> {
    unsafe {
        // This is a simplified implementation - in reality we would use mmap or VirtualAlloc
        // We're using libc's mmap for Linux systems
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned_size = (size + page_size - 1) & !(page_size - 1);

        let addr = libc::mmap(
            ptr::null_mut(),
            aligned_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if addr == libc::MAP_FAILED {
            return Err(format!(
                "Failed to allocate executable memory: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(addr as u64)
    }
}

/// Copies data to executable memory
unsafe fn copy_to_executable_memory(address: u64, data: &[u8]) -> Result<(), String> {
    unsafe {
        // Make sure memory is writable and executable
        let ptr = address as *mut u8;
        if ptr.is_null() {
            return Err("Null pointer for executable memory".to_string());
        }

        // Copy the data to the allocated memory
        ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());

        // Ensure the memory is executable (might need to flush instruction cache on some platforms)
        // On x86/x64 this is typically not needed, but included for completeness

        Ok(())
    }
}

/// Reads memory from a specified address
unsafe fn read_memory(address: u64, size: usize) -> Result<Vec<u8>, String> {
    unsafe {
        // Check if memory is accessible
        if !crate::hook_tools::is_memory_accessible(address, size) {
            return Err(format!(
                "Memory at address 0x{:x} is not accessible",
                address
            ));
        }

        // Read the memory
        let ptr = address as *const u8;
        let mut buffer = Vec::with_capacity(size);

        // Use a safer approach to read memory
        for i in 0..size {
            buffer.push(ptr::read_volatile(ptr.add(i)));
        }

        Ok(buffer)
    }
}

/// Writes data to a memory address
unsafe fn write_memory(address: u64, data: &[u8]) -> Result<(), String> {
    unsafe {
        // Check if memory is accessible and writable
        if !crate::hook_tools::is_memory_accessible(address, data.len()) {
            return Err(format!(
                "Memory at address 0x{:x} is not accessible",
                address
            ));
        }

        // Set the memory protection to writable if necessary
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let page_mask = !(page_size - 1);
        let page_start = (address & page_mask as u64) as *mut libc::c_void;

        // Get the current protection - prefixed with underscore since it's unused
        let _old_protection: libc::c_int = 0;

        // Make the memory writable
        let result = libc::mprotect(
            page_start,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        );

        if result != 0 {
            return Err(format!(
                "Failed to change memory protection: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Write the data
        let ptr = address as *mut u8;
        for (i, &byte) in data.iter().enumerate() {
            ptr::write_volatile(ptr.add(i), byte);
        }

        // Restore the original protection if needed
        // In practice, game code needs to remain executable

        // Flush instruction cache if necessary (not typically needed on x86/x64)

        Ok(())
    }
}

/// Restores original bytes at a hook location to undo a hook
pub unsafe fn restore_hook(hook: &ActiveHook) -> Result<(), String> {
    unsafe {
        // Write the original bytes back to the target address
        write_memory(hook.target_address, &hook.original_bytes)?;

        // Free the trampoline memory if it was allocated
        if hook.trampoline_address != 0 {
            free_executable_memory(hook.trampoline_address, hook.original_bytes.len())?;
        }

        Ok(())
    }
}

/// Frees previously allocated executable memory
unsafe fn free_executable_memory(address: u64, size: usize) -> Result<(), String> {
    unsafe {
        if address == 0 {
            return Ok(());
        }

        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned_size = (size + page_size - 1) & !(page_size - 1);

        let result = libc::munmap(address as *mut libc::c_void, aligned_size);

        if result != 0 {
            return Err(format!(
                "Failed to free executable memory: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }
}
