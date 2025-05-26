use crate::constants::SCAN_INTERVAL_MS;
use crate::lib_init::notify_dll_loaded;
use crate::low_level_tools::hook_tools::{self, Hook, le_lib_load_hook, memory_content_to_bytes};
use crate::system_tools::maps::{self, get_memory_map_guard_blocking};
use crate::system_tools::maps::{MemoryMap, get_memory_map_guard};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::os::raw::{c_int, c_long, c_void};
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

// Store original function pointers
lazy_static! {
    static ref ORIGINAL_MMAP: Mutex<Option<MmapFunc>> = Mutex::new(None);
    static ref HOOK_INITIALIZED: Once = Once::new();
    static ref NO_PENDING: Once = Once::new();
    static ref LAST_SCAN_TIME: Mutex<Instant> = Mutex::new(Instant::now());
    static ref KNOWN_MODULES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref CALLS_COUNTER: Mutex<u64> = Mutex::new(0);
    // Track hooks waiting for specific files to be loaded
    static ref PENDING_HOOKS: Mutex<Vec<Hook>> = Mutex::new(Vec::new());
}

// Interval between memory map scans (in milliseconds)

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
    let map = get_memory_map_guard_blocking();
    le_lib_load_hook(&map);
}

// Function to scan loaded modules at startup - uses direct scan to avoid initialization issues
fn scan_loaded_modules() {
    info!("Performing initial scan of loaded modules");

    // Use direct scanning during initialization to avoid potential mutex issues
    let new_entries = maps::MemoryMap::scan_direct();
    debug!("Found {} new entries in memory map", new_entries.len());
    let mut known_modules = KNOWN_MODULES.lock().unwrap();
    debug!("Known modules before scan: {}", known_modules.len());

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
    info!("Processing module: {}", path);

    // Add to known modules
    known_modules.insert(path.to_string());

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
        NO_PENDING.call_once(|| {
            info!("No pending hooks waiting for files, skipping check");
        });
        return;
    }

    // Find hooks that are waiting for this file
    let ready_hooks: Vec<usize> = pending_hooks
        .iter()
        .enumerate()
        .filter_map(|(index, hook)| {
            if let Some(wait_file) = &hook.base_file {
                // Check if the loaded file matches what we're waiting for
                // Use both exact path and basename comparison for flexibility
                if loaded_file_path == wait_file || loaded_file_path.ends_with(wait_file) {
                    info!(
                        "Hook '{}' is ready to be applied, waiting file '{}' has been loaded",
                        hook.name, wait_file
                    );
                    Some(index)
                } else {
                    info!(
                        "Hook '{}' is still waiting for file '{}', loaded file is '{}'",
                        hook.name, wait_file, loaded_file_path
                    );
                    None
                }
            } else {
                info!("Hook '{}' does not wait for a specific file", hook.name);
                None
            }
        })
        .collect();

    // Process hooks that are ready (in reverse order to safely remove them)

    let map = match get_memory_map_guard() {
        Some(guard) => guard,
        None => {
            warn!("Failed to get memory map guard during scan");
            return;
        }
    };

    for &index in ready_hooks.iter().rev() {
        if index < pending_hooks.len() {
            // Safety check
            let hook = pending_hooks.remove(index);
            info!(
                "Required file {} loaded for hook '{}', attempting to apply hook",
                hook.base_file.as_ref().unwrap_or(&"unknown".to_string()),
                hook.name
            );

            // Attempt to apply the hook
            attempt_apply_hook(&hook, &map);
        }
    }
}

// Attempt to apply a hook once its required file is loaded
fn attempt_apply_hook(hook: &Hook, map: &MemoryMap) {
    // Verify memory content
    info!(
        "Attempting to apply hook '{}', verifying memory content",
        hook.name
    );
    let real_target_address = match hook_tools::calculate_real_target_address(hook) {
        Ok(addr) => addr,
        Err(_) => {
            error!(
                "Failed to calculate real target address for hook '{}'",
                hook.name
            );
            return;
        }
    };
    info!(
        "Calculated real target address for hook '{}' is 0x{:x}",
        hook.name, real_target_address
    );
    let memory_matches =
        unsafe { verify_memory_content(&map, real_target_address, &hook.memory_content) };
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
    le_lib_load_hook(&map);
}

pub unsafe fn verify_memory_content(map: &MemoryMap, address: u64, expected_content: &str) -> bool {
    info!("Verifying memory content at address 0x{:x}", address);
    let expected_bytes = memory_content_to_bytes(expected_content);

    info!(
        "Checking memory at address 0x{:x} for {} bytes",
        address,
        expected_bytes.len()
    );

    // First check if the memory is accessible - this is critical to avoid segfaults
    if !map.is_memory_accessible(address, expected_bytes.len()) {
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
            info!("[w] Actual bytes read: {:02X?}", actual_bytes);
            info!("[w] Expected bytes: {:02X?}", expected_bytes);

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

// Initialize the hooks
pub fn initialize_wine_hooks() -> bool {
    log::info!("Initializing Wine Hooks");
    use std::panic::{self, AssertUnwindSafe};

    // Store the setting in our global variable
    // Load hooks configuration and store hooks with wait_for_file
    // Wrap in a catch_unwind to prevent initialization failures from bringing down the whole process
    if let Err(e) = panic::catch_unwind(AssertUnwindSafe(|| {
        let matching_hooks = hook_tools::get_not_active_hooks();
        let mut pending_hooks = match PENDING_HOOKS.lock() {
            Ok(guard) => guard,
            Err(e) => {
                warn!("Failed to lock PENDING_HOOKS: {}", e);
                return;
            }
        };
        for hook in matching_hooks {
            match hook.base_file {
                Some(ref file) => {
                    info!("Hook '{}' is waiting for file '{}'", hook.name, file);
                    pending_hooks.push(hook);
                }
                None => info!("Hook '{}' does not wait for a specific file", hook.name),
            }
        }
    })) {
        // If there was a panic in the hook loading code, log it but continue
        warn!("Panic during hook configuration loading: {:?}", e);
    }

    if let Err(e) = panic::catch_unwind(AssertUnwindSafe(|| start_module_scanner())) {
        warn!("Panic during module scanner initialization: {:?}", e);
        return false;
    }
    return true;
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
        }
    });

    info!("Module scanner thread started successfully");
}
