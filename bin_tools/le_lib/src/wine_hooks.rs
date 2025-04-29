use crate::lib_init::HOOK_MMAP_CALL;
use crate::lib_init::notify_dll_loaded;
use crate::low_level_tools::hook_tools::{
    Hook, is_memory_accessible, le_lib_load_hook, load_hooks_config, memory_content_to_bytes,
    parse_hex_address,
};
use crate::system_tools::maps; // Import memory map module without MEMORY_MAP
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use std::collections::HashSet;
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
    static ref CALLS_COUNTER: Mutex<u64> = Mutex::new(0);
    // Track hooks waiting for specific files to be loaded
    static ref PENDING_HOOKS: Mutex<Vec<Hook>> = Mutex::new(Vec::new());
}

// Interval between memory map scans (in milliseconds)
const SCAN_INTERVAL_MS: u64 = 5000;

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
    let guard = ORIGINAL_MMAP.lock().unwrap();
    let result = match *guard {
        Some(original_fn) => unsafe { original_fn(addr, length, prot, flags, fd, offset) },
        None => {
            error!("Original mmap function not found");
            return std::ptr::null_mut();
        }
    };

    // If HOOK_MMAP_CALL is disabled, just return the result without processing
    if !*HOOK_MMAP_CALL.lock().unwrap() {
        return result;
    }

    // Increment the call counter
    *CALLS_COUNTER.lock().unwrap() += 1;

    // If memory was mapped with executable permission, scan for new modules
    if !result.is_null() && (prot & PROT_EXEC) != 0 && (prot & PROT_READ) != 0 {
        debug!("Executable memory mapped - checking for new modules");

        // Rate limit scanning to avoid excessive I/O
        let mut last_scan_time = LAST_SCAN_TIME.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*last_scan_time) > Duration::from_millis(SCAN_INTERVAL_MS) {
            *last_scan_time = now;
            // Scan in a separate thread to avoid blocking the main thread
            std::thread::spawn(scan_proc_maps);
        }
    }

    result
}

// Scan for new loaded modules using system_tools::maps
fn scan_proc_maps() {
    // Use the MemoryMap's thread-safe scan method
    let new_entries = maps::MemoryMap::scan();
    let mut known_modules = KNOWN_MODULES.lock().unwrap();

    // Process each memory map entry
    for entry in new_entries {
        // Skip entries that don't have real paths
        let path = entry.get_pathname();
        if path.is_empty() || path.starts_with('[') || path.contains("SYSV") {
            continue;
        }

        process_module(path, entry.get_address(), &mut known_modules);
    }
}

// Function to scan loaded modules at startup - uses direct scan to avoid initialization issues
fn scan_loaded_modules() {
    info!("Performing initial scan of loaded modules");

    // Use direct scanning during initialization to avoid potential mutex issues
    let new_entries = maps::MemoryMap::scan_direct();
    let mut known_modules = KNOWN_MODULES.lock().unwrap();

    // Process each memory map entry
    for entry in new_entries {
        // Skip entries that don't have real paths
        let path = entry.get_pathname();
        if path.is_empty() || path.starts_with('[') || path.contains("SYSV") {
            continue;
        }

        process_module(path, entry.get_address(), &mut known_modules);
    }
}

// Process a module found in memory maps
fn process_module(path: &str, address: u64, known_modules: &mut HashSet<String>) {
    // Only consider Wine/Proton DLLs or potentially loaded game DLLs
    if !is_target_module(path) || known_modules.contains(path) {
        return;
    }

    // Add to known modules
    known_modules.insert(path.to_string());

    info!("Detected new module: {}", path);
    info!("Total mmap calls: {}", *CALLS_COUNTER.lock().unwrap());

    // Extract the base module name from path
    let base_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);

    // Notify that a DLL has been loaded with its address
    notify_dll_loaded(base_name, address as *mut c_void);

    // Check if any pending hooks are waiting for this file
    check_pending_hooks_for_file(path);
}

// Check if the module is a target we want to track
fn is_target_module(path: &str) -> bool {
    path.contains(".dll") || path.contains(".so") || path.contains(".exe")
}

// Check if any pending hooks are waiting for this file to be loaded
fn check_pending_hooks_for_file(loaded_file_path: &str) {
    let mut pending_hooks = PENDING_HOOKS.lock().unwrap();

    // Exit early if there are no pending hooks
    if pending_hooks.is_empty() {
        return;
    }

    // Find hooks that are waiting for this file
    let ready_hooks: Vec<usize> = pending_hooks
        .iter()
        .enumerate()
        .filter_map(|(index, hook)| {
            if let Some(wait_file) = &hook.wait_for_file {
                // Check if the loaded file matches what we're waiting for
                // Use both exact path and basename comparison for flexibility
                if loaded_file_path == wait_file
                    || loaded_file_path.ends_with(
                        Path::new(wait_file)
                            .file_name()
                            .unwrap_or_default()
                            .to_str()
                            .unwrap_or_default(),
                    )
                {
                    Some(index)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    // Process hooks that are ready (in reverse order to safely remove them)
    for &index in ready_hooks.iter().rev() {
        if index < pending_hooks.len() {
            // Safety check
            let hook = pending_hooks.remove(index);
            info!(
                "Required file {} loaded for hook '{}', attempting to apply hook",
                hook.wait_for_file
                    .as_ref()
                    .unwrap_or(&"unknown".to_string()),
                hook.name
            );

            // Attempt to apply the hook
            attempt_apply_hook(&hook);
        }
    }
}

// Attempt to apply a hook once its required file is loaded
fn attempt_apply_hook(hook: &Hook) {
    // Parse the target address
    let target_address = match parse_hex_address(&hook.target_address) {
        Ok(addr) => addr,
        Err(_) => {
            error!(
                "Invalid target address for hook '{}': {}",
                hook.name, hook.target_address
            );
            return;
        }
    };

    // Verify memory content
    let memory_matches = unsafe { verify_memory_content(target_address, &hook.memory_content) };
    if !memory_matches {
        error!(
            "Memory content doesn't match for hook '{}' at address {}. Target file loaded but memory content is different.",
            hook.name, hook.target_address
        );
        return;
    }

    // Trigger le_lib_load_hook to handle the hook installation
    // This is safer than duplicating the hook loading logic
    info!(
        "Memory content verified for hook '{}', calling le_lib_load_hook to apply hook",
        hook.name
    );
    le_lib_load_hook();
}

// Helper function to verify memory content at a specific address
unsafe fn verify_memory_content(address: u64, expected_content: &str) -> bool {
    // Convert the expected content string to bytes
    info!("Verifying memory content at address 0x{:x}", address);
    let expected_bytes = memory_content_to_bytes(expected_content);

    info!(
        "Checking memory at address 0x{:x} for {} bytes",
        address,
        expected_bytes.len()
    );

    // First check if the memory is accessible - this is critical to avoid segfaults
    if !is_memory_accessible(address, expected_bytes.len()) {
        warn!(
            "Memory at address 0x{:x} is not accessible, skipping content verification",
            address
        );
        return false;
    }

    // We'll be extremely cautious about memory access
    let result = unsafe {
        // Use a closure to contain any potential memory access issues
        let verify_result = std::panic::catch_unwind(|| {
            info!("Reading memory at address 0x{:x}", address);
            let actual_bytes =
                std::slice::from_raw_parts(address as *const u8, expected_bytes.len());
            info!("Actual bytes read: {:02X?}", actual_bytes);
            info!("Expected bytes: {:02X?}", expected_bytes);

            expected_bytes == actual_bytes
        });

        match verify_result {
            Ok(result) => result,
            Err(_) => {
                error!(
                    "Panic occurred during memory verification at address 0x{:x}",
                    address
                );
                false
            }
        }
    };

    if result {
        info!("Memory content at 0x{:x} matches expected pattern", address);
    } else {
        info!(
            "Memory content at 0x{:x} does not match expected pattern",
            address
        );
    }

    result
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
    use std::env;
    use std::panic::{self, AssertUnwindSafe};

    // Check environment variable for HOOK_MMAP_CALL setting
    let hook_mmap = env::var("HOOK_MMAP_CALL")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    // Store the setting in our global variable
    match HOOK_MMAP_CALL.lock() {
        Ok(mut guard) => {
            *guard = hook_mmap;
        }
        Err(e) => {
            // This is unlikely to happen, but handle it gracefully
            warn!("Failed to set HOOK_MMAP_CALL: {}", e);
        }
    }

    // Load hooks configuration and store hooks with wait_for_file
    // Wrap in a catch_unwind to prevent initialization failures from bringing down the whole process
    if let Err(e) = panic::catch_unwind(AssertUnwindSafe(|| {
        if let Ok(config) = load_hooks_config() {
            let mut pending_hooks = match PENDING_HOOKS.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    warn!("Failed to lock PENDING_HOOKS: {}", e);
                    return;
                }
            };

            for hook in config.hooks {
                if let Some(wait_file) = &hook.wait_for_file {
                    info!(
                        "Registered hook '{}' waiting for file: {}",
                        hook.name, wait_file
                    );
                    pending_hooks.push(hook);
                }
            }

            if !pending_hooks.is_empty() {
                info!(
                    "Loaded {} pending hooks that are waiting for files",
                    pending_hooks.len()
                );
            }
        } else {
            warn!("Could not load hooks configuration during wine_hooks initialization");
        }
    })) {
        // If there was a panic in the hook loading code, log it but continue
        warn!("Panic during hook configuration loading: {:?}", e);
    }

    info!("Initializing mmap syscall hook.");
    let mut success = false;

    // Wrap the initialization in a catch_unwind to prevent panics
    if let Err(e) = panic::catch_unwind(AssertUnwindSafe(|| {
        HOOK_INITIALIZED.call_once(|| {
            // Hook the mmap syscall - safe even if it fails
            match hook_mmap_syscall() {
                true => {
                    info!("Linux memory mapping hooks initialized successfully");
                    if hook_mmap {
                        info!("HOOK_MMAP_CALL is enabled. Scanning for loaded modules.");
                        // This calls our safer scan_loaded_modules
                        if let Err(e) = panic::catch_unwind(AssertUnwindSafe(|| {
                            scan_loaded_modules();
                        })) {
                            warn!("Panic occurred during initial module scanning: {:?}", e);
                        }
                    }
                    success = true;
                }
                false => {
                    error!("Failed to initialize Linux memory mapping hooks");
                }
            }
        });
    })) {
        warn!("Panic occurred during hook initialization: {:?}", e);
        return false;
    }

    if !hook_mmap && success {
        info!("HOOK_MMAP_CALL is disabled (default). Starting periodic module scanner.");
        // Start module scanner in a separate thread to avoid blocking
        if let Err(e) = panic::catch_unwind(AssertUnwindSafe(|| {
            start_module_scanner();
        })) {
            warn!("Failed to start module scanner: {:?}", e);
            success = false;
        }
    } else if hook_mmap {
        info!("HOOK_MMAP_CALL is enabled. No periodic scanner started.");
    }

    success
}

// Start a background thread to periodically scan for loaded modules
fn start_module_scanner() {
    info!(
        "Starting periodic module scanner with interval of {}ms",
        SCAN_INTERVAL_MS
    );

    // Perform an initial scan immediately
    scan_loaded_modules();

    // Start background thread for periodic scanning
    std::thread::spawn(move || {
        loop {
            // Sleep for the scan interval
            std::thread::sleep(Duration::from_millis(SCAN_INTERVAL_MS));

            // Scan for new modules
            debug!("Periodic scan for loaded modules");
            scan_proc_maps();
            le_lib_load_hook();
        }
    });

    info!("Module scanner thread started successfully");
}
