use std::collections::HashMap;
use std::sync::{Mutex, Once};
use log::{info, warn, error};
use lazy_static::lazy_static;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::marker::Send;

// Import the logger initialization function
use crate::initialize_logger;

// Type for hook function pointers
type HookFunctionPtr = *const c_void;

// Thread-safe wrapper for raw pointers
pub struct SendPtr(*const c_void);

// Implement Send for our wrapped pointer
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

// Global hashmap for storing hooks
lazy_static! {
    pub static ref HOOKS: Mutex<HashMap<String, SendPtr>> = Mutex::new(HashMap::new());
}

// Static to ensure we only initialize once
static INIT: Once = Once::new();

// DLL load notification callback type
type DllNotificationCallback = unsafe extern "C" fn(dll_path: *const c_char, base_address: *const c_void);

// Function to register for DLL notifications - this would normally link to a system function
// For Linux with Wine/Proton, we'll need to use a specific approach for hook injection
unsafe extern "C" {
    fn register_dll_notification(callback: DllNotificationCallback) -> bool;
}

// DLL load notification callback
unsafe extern "C" fn dll_loaded_callback(dll_path: *const c_char, base_address: *const c_void) {
    if dll_path.is_null() {
        warn!("DLL loaded but path is null");
        return;
    }

    unsafe {
        match CStr::from_ptr(dll_path).to_str() {
            Ok(path) => {
                info!("DLL loaded: {} at address {:p}", path, base_address);
            },
            Err(e) => {
                error!("Error converting DLL path to string: {}", e);
            }
        }
    }
}

/// Initialize the library
/// 
/// This function:
/// 1. Initializes the logger
/// 2. Sets up hook that will log after DLL is loaded in memory
/// 3. Initializes global hashmap for hooks
#[unsafe(no_mangle)]
pub extern "C" fn le_lib_init() -> bool {
    let mut success = true;
    
    INIT.call_once(|| {
        // Initialize logger
        initialize_logger();
        info!("le_lib_init: Library initialization started");

        // Initialize hooks hashmap (already done via lazy_static)
        info!("le_lib_init: Hooks hashmap initialized");
        
        // Set up DLL load notification
        match unsafe { register_dll_notification(dll_loaded_callback) } {
            true => {
                info!("le_lib_init: DLL load notification hook registered successfully");
            },
            false => {
                error!("le_lib_init: Failed to register DLL load notification hook");
                success = false;
            }
        }

        if success {
            info!("le_lib_init: Library initialization completed successfully");
        } else {
            error!("le_lib_init: Library initialization completed with errors");
        }
    });

    success
}

// Helper function to add a hook to the global hashmap
pub fn register_hook(name: &str, function_ptr: HookFunctionPtr) -> bool {
    let mut hooks = match HOOKS.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to lock hooks hashmap: {}", e);
            return false;
        }
    };

    if hooks.contains_key(name) {
        warn!("Hook '{}' already registered, overwriting", name);
    }

    hooks.insert(name.to_string(), SendPtr(function_ptr));
    info!("Hook '{}' registered at address {:p}", name, function_ptr);
    
    true
}

// Helper function to check if a hook is registered
pub fn is_hook_registered(name: &str) -> bool {
    let hooks = match HOOKS.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to lock hooks hashmap: {}", e);
            return false;
        }
    };

    hooks.contains_key(name)
}

// Helper function to get a hook function pointer
pub fn get_hook_function(name: &str) -> Option<HookFunctionPtr> {
    let hooks = match HOOKS.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to lock hooks hashmap: {}", e);
            return None;
        }
    };

    hooks.get(name).map(|send_ptr| send_ptr.0)
}