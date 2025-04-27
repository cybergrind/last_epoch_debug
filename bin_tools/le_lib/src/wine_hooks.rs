use crate::lib_init::notify_dll_loaded;
use lazy_static::lazy_static;
use log::{debug, error, info};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::path::Path;
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

// Define mmap syscall types and constants
type MmapFunc = unsafe extern "C" fn(
    addr: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: c_long,
) -> *mut c_void;

// Define mmap constants
const PROT_READ: c_int = 0x1;
const PROT_EXEC: c_int = 0x4;

// Store original function pointers
lazy_static! {
    static ref ORIGINAL_MMAP: Mutex<Option<MmapFunc>> = Mutex::new(None);
    static ref HOOK_INITIALIZED: Once = Once::new();
    static ref LAST_SCAN_TIME: Mutex<Instant> = Mutex::new(Instant::now());
    static ref KNOWN_MODULES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

// Interval between memory map scans (in milliseconds)
const SCAN_INTERVAL_MS: u64 = 5000;
lazy_static! {
    static ref CALLS_COUNTER: Mutex<u64> = Mutex::new(0);
}

// Hook for mmap syscall
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: c_long,
) -> *mut c_void {
    // Call the original mmap function
    let result = if let Some(original_func) = *ORIGINAL_MMAP.lock().unwrap() {
        unsafe { original_func(addr, length, prot, flags, fd, offset) }
    } else {
        error!("Original mmap function not found");
        return std::ptr::null_mut();
    };

    // Increment the call counter
    let mut counter = CALLS_COUNTER.lock().unwrap();
    *counter += 1;

    // If memory was mapped with executable permission, scan for new modules
    if !result.is_null() && (prot & PROT_EXEC) != 0 && (prot & PROT_READ) != 0 {
        debug!("Executable memory mapped - checking for new modules");
        debug!("Current mmap call count: {}", *counter);

        // Rate limit scanning to avoid excessive I/O
        let mut last_scan_time = LAST_SCAN_TIME.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*last_scan_time) > Duration::from_millis(SCAN_INTERVAL_MS) {
            *last_scan_time = now;
            // Scan in a separate thread to avoid blocking the main thread
            std::thread::spawn(|| {
                scan_proc_maps();
            });
        }
    }

    result
}

// Scan /proc/<pid>/maps for new loaded modules
fn scan_proc_maps() {
    let pid = std::process::id();
    let maps_path = format!("/proc/{}/maps", pid);

    if !Path::new(&maps_path).exists() {
        error!("Could not find process maps at {}", maps_path);
        return;
    }

    match File::open(&maps_path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            let mut known_modules = KNOWN_MODULES.lock().unwrap();

            for line in reader.lines() {
                if let Ok(content) = line {
                    // Parse the memory mapping line
                    // Format: address perms offset dev inode pathname
                    // Example: 7f9d80617000-7f9d80619000 r-xp 00000000 08:01 2097666 /lib/x86_64-linux-gnu/ld-2.31.so

                    // Split the line by spaces
                    let parts: Vec<&str> = content.split_whitespace().collect();
                    if parts.len() < 6 {
                        // No path in this line
                        continue;
                    }

                    // Get address range (first column)
                    let addr_range = parts[0];

                    // The path starts from the 6th column (index 5)
                    // If there are more than 6 parts, then the path contains spaces
                    // and we need to rejoin those parts
                    let path = if parts.len() > 6 {
                        // Join the path parts (everything from index 5 onwards)
                        parts[5..].join(" ")
                    } else {
                        parts[5].to_string()
                    };

                    // Skip entries that don't have real paths
                    if path.is_empty() || path.starts_with('[') || path.contains("SYSV") {
                        continue;
                    }

                    // Only consider Wine/Proton DLLs or potentially loaded game DLLs
                    if (path.contains(".dll") || path.contains(".so") || path.contains(".exe"))
                        && !known_modules.contains(&path)
                    {
                        // Add to known modules
                        known_modules.insert(path.to_string());

                        info!("Detected new module: {}", path);
                        let count = CALLS_COUNTER.lock().unwrap();
                        info!("Total mmap calls: {}", *count);

                        // Extract the base module name from path
                        let base_name = Path::new(&path)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or(&path);

                        // Get the memory region from the mapping line
                        let addr_parts: Vec<&str> = addr_range.split('-').collect();
                        if addr_parts.len() == 2 {
                            if let Ok(addr) = usize::from_str_radix(addr_parts[0], 16) {
                                // The base address where the module is loaded
                                let module_addr = addr as *mut c_void;
                                notify_dll_loaded(base_name, module_addr);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to open {}: {}", maps_path, e);
        }
    }
}

// Function to scan loaded modules at startup
fn scan_loaded_modules() {
    info!("Performing initial scan of loaded modules");
    scan_proc_maps();
}

// Function to find and hook the mmap syscall
fn hook_mmap_syscall() -> bool {
    // On Linux, we'll use libcall to hook the mmap system call
    // This is a simplified placeholder - in a real implementation,
    // you would need a library like `frida-gum` or similar to hook syscalls

    unsafe {
        // Get the original mmap function from libc
        let func_ptr = libc::dlsym(libc::RTLD_NEXT, "mmap\0".as_ptr() as *const c_char);

        if func_ptr.is_null() {
            error!("Failed to find original mmap function");
            false
        } else {
            let original_mmap: MmapFunc = std::mem::transmute(func_ptr);
            info!("Found original mmap at {:p}", func_ptr);
            *ORIGINAL_MMAP.lock().unwrap() = Some(original_mmap);
            true
        }
    }
}

// Initialize the hooks
pub fn initialize_wine_hooks() -> bool {
    use crate::lib_init::BYPASS_WINE_HOOKS;

    // Check if hooks are bypassed
    if *BYPASS_WINE_HOOKS.lock().unwrap() {
        info!("Wine hooks are bypassed. Skipping initialization.");
        return true; // Return success to prevent error in lib_init
    }

    let mut success = false;

    HOOK_INITIALIZED.call_once(|| {
        info!("Initializing Linux syscall hooks for memory mappings");

        // Hook the mmap syscall
        success = hook_mmap_syscall();

        if success {
            info!("Linux memory mapping hooks initialized successfully");
            // Perform an initial scan to identify already-loaded modules
            scan_loaded_modules();
        } else {
            error!("Failed to initialize Linux memory mapping hooks");
        }
    });

    success
}
