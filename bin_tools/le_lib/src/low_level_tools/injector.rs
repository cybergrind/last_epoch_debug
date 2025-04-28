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

        // Ensure we allocate at least one page, even for zero-size requests
        let aligned_size = if size == 0 {
            page_size
        } else {
            (size + page_size - 1) & !(page_size - 1)
        };

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
        // Ensure we use at least one page size when freeing memory,
        // especially for zero-size allocations
        let aligned_size = if size == 0 {
            page_size
        } else {
            (size + page_size - 1) & !(page_size - 1)
        };

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    // Initialize logger once for all tests
    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            crate::initialize_logger();
        });
    }

    // Test allocating and freeing executable memory
    #[test]
    fn test_allocate_free_executable_memory() {
        setup();

        // Test allocating memory
        let size = 1024;
        let address =
            unsafe { allocate_executable_memory(size) }.expect("Failed to allocate memory");

        // Verify the address is non-zero
        assert_ne!(address, 0, "Allocated memory address should not be zero");

        // Try to free the memory
        unsafe {
            let result = free_executable_memory(address, size);
            assert!(
                result.is_ok(),
                "Failed to free executable memory: {:?}",
                result.err()
            );
        }
    }

    // Test writing to and reading from allocated memory
    #[test]
    fn test_write_read_memory() {
        setup();

        // Allocate executable memory for our test
        let test_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78];
        let size = test_data.len();

        let address =
            unsafe { allocate_executable_memory(size) }.expect("Failed to allocate memory");

        // Write test data to the allocated memory
        let write_result = unsafe { copy_to_executable_memory(address, &test_data) };
        assert!(
            write_result.is_ok(),
            "Failed to write to memory: {:?}",
            write_result.err()
        );

        // Read back the memory
        let read_result = unsafe { read_memory(address, size) };
        assert!(
            read_result.is_ok(),
            "Failed to read from memory: {:?}",
            read_result.err()
        );

        // Compare the read data with the original test data
        let read_data = read_result.unwrap();
        assert_eq!(
            read_data, test_data,
            "Memory read data doesn't match written data"
        );

        // Clean up
        unsafe { free_executable_memory(address, size).expect("Failed to free memory") };
    }

    // Test writing to memory directly using write_memory
    #[test]
    fn test_write_memory_function() {
        setup();

        // Allocate memory for testing
        let test_data = vec![0xC0, 0xDE, 0xCA, 0xFE, 0xBA, 0xBE];
        let size = test_data.len();

        let address =
            unsafe { allocate_executable_memory(size) }.expect("Failed to allocate memory");

        // Write data using write_memory function
        let write_result = unsafe { write_memory(address, &test_data) };
        assert!(
            write_result.is_ok(),
            "Failed to write to memory: {:?}",
            write_result.err()
        );

        // Read back the data
        let read_result = unsafe { read_memory(address, size) };
        assert!(
            read_result.is_ok(),
            "Failed to read from memory: {:?}",
            read_result.err()
        );

        // Compare the read data with the original test data
        let read_data = read_result.unwrap();
        assert_eq!(
            read_data, test_data,
            "Memory data doesn't match after using write_memory"
        );

        // Clean up
        unsafe { free_executable_memory(address, size).expect("Failed to free memory") };
    }

    // Test the complete hook injection process with a mock hook
    #[test]
    fn test_inject_and_restore_hook() {
        setup();

        // Instead of using static mut, allocate memory that we can use for testing
        let original_bytes = vec![0x90, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89];

        // Allocate memory for our test "original code"
        let mem_size = original_bytes.len();
        let mem_address = unsafe { allocate_executable_memory(mem_size) }
            .expect("Failed to allocate memory for original code");

        // Copy our test bytes to the allocated memory
        unsafe { copy_to_executable_memory(mem_address, &original_bytes) }
            .expect("Failed to initialize test memory");

        // Create a mock hook targeting our allocated memory
        let mock_hook = Hook {
            name: "test_hook".to_string(),
            target_address: format!("{:x}", mem_address),
            memory_content: "\\x90\\x48\\x89\\x5C\\x24\\x08\\x48\\x89".to_string(),
            hook_function: "le_lib_echo".to_string(),
            wait_for_file: None,
            base_file: None,
            target_process: None,
        };

        // Create trampoline and jumper data
        let trampoline_data = vec![0x55, 0x48, 0x89, 0xE5, 0xFF, 0xD0, 0x5D, 0xC3]; // Simple function prologue + call + epilogue
        let jumper_data = vec![0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90]; // JMP instruction + NOP padding

        // Inject the hook
        let inject_result = unsafe { inject_hook(&mock_hook, &trampoline_data, &jumper_data) };
        assert!(
            inject_result.is_ok(),
            "Failed to inject hook: {:?}",
            inject_result.err()
        );

        let active_hook = inject_result.unwrap();

        // Verify the hook was injected by reading from the target address
        let post_inject_memory = unsafe {
            read_memory(mem_address, jumper_data.len())
                .expect("Failed to read memory after injection")
        };

        // Verify that the memory was modified to contain our jumper
        assert_eq!(
            post_inject_memory, jumper_data,
            "Memory was not correctly modified by hook injection"
        );

        // Verify that the original bytes were correctly saved in the active hook
        assert_eq!(
            active_hook.original_bytes, original_bytes,
            "Original bytes were not correctly saved"
        );

        // Now restore the hook
        let restore_result = unsafe { restore_hook(&active_hook) };
        assert!(
            restore_result.is_ok(),
            "Failed to restore hook: {:?}",
            restore_result.err()
        );

        // Verify the original memory was restored
        let post_restore_memory = unsafe {
            read_memory(mem_address, mem_size).expect("Failed to read memory after restoration")
        };

        assert_eq!(
            post_restore_memory, original_bytes,
            "Original memory was not correctly restored"
        );

        // Clean up allocated memory
        unsafe { free_executable_memory(mem_address, mem_size) }
            .expect("Failed to free test memory");
    }

    // Test handling of memory access errors
    #[test]
    fn test_memory_access_errors() {
        setup();

        // Try to read from an invalid address (null pointer)
        let invalid_address = 0x0;
        let read_result = unsafe { read_memory(invalid_address, 4) };

        // This should fail because memory at address 0 shouldn't be readable
        assert!(
            read_result.is_err(),
            "Reading from invalid memory should fail"
        );

        // Try to write to an invalid address
        let write_result = unsafe { write_memory(invalid_address, &[0xDE, 0xAD, 0xBE, 0xEF]) };

        // This should also fail
        assert!(
            write_result.is_err(),
            "Writing to invalid memory should fail"
        );
    }

    // Test boundary conditions for memory allocation
    #[test]
    fn test_memory_allocation_boundaries() {
        setup();

        // Test allocating zero bytes (should still allocate a page)
        let zero_size_address = unsafe { allocate_executable_memory(0) };
        assert!(
            zero_size_address.is_ok(),
            "Should be able to allocate zero bytes"
        );

        if let Ok(address) = zero_size_address {
            unsafe { free_executable_memory(address, 0).expect("Failed to free zero-size memory") };
        }

        // Test allocating a large size (1MB)
        let large_size = 1024 * 1024;
        let large_address = unsafe { allocate_executable_memory(large_size) };
        assert!(
            large_address.is_ok(),
            "Should be able to allocate large memory"
        );

        if let Ok(address) = large_address {
            unsafe {
                free_executable_memory(address, large_size).expect("Failed to free large memory")
            };
        }
    }
}
