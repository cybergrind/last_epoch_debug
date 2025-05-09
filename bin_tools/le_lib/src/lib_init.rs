use lazy_static::lazy_static;
use log::{error, info, warn};
use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::marker::Send;
use std::os::raw::{c_char, c_void};
use std::sync::{Mutex, Once};

// local imports
use crate::echo::le_lib_echo;
use crate::initialize_logger;
use crate::low_level_tools::hook_tools::load_hooks_config;
use crate::wine_hooks::initialize_wine_hooks;

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
    // Static to store the DLL notification callback
    static ref DLL_NOTIFICATION_CALLBACK: Mutex<Option<DllNotificationCallback>> = Mutex::new(None);
    // Flag to indicate if we should hook mmap calls (default: false)
    pub static ref HOOK_MMAP_CALL: Mutex<bool> = Mutex::new(false);
}

// Static to ensure we only initialize once
static INIT: Once = Once::new();

// DLL load notification callback type
type DllNotificationCallback =
    unsafe extern "C" fn(dll_path: *const c_char, base_address: *const c_void);

// Implementation of register_dll_notification function
#[unsafe(no_mangle)]
pub unsafe extern "C" fn register_dll_notification(callback: DllNotificationCallback) -> bool {
    match DLL_NOTIFICATION_CALLBACK.lock() {
        Ok(mut cb_guard) => {
            *cb_guard = Some(callback);
            info!("DLL notification callback registered");
            true
        }
        Err(e) => {
            error!("Failed to register DLL notification callback: {}", e);
            false
        }
    }
}

// Helper function to simulate DLL loading (can be called from other parts of your code)
pub fn notify_dll_loaded(dll_path: &str, base_address: *const c_void) {
    let c_dll_path = std::ffi::CString::new(dll_path).unwrap();

    if let Ok(cb_guard) = DLL_NOTIFICATION_CALLBACK.lock() {
        if let Some(callback) = *cb_guard {
            unsafe {
                callback(c_dll_path.as_ptr(), base_address);
            }
        }
    }
}

// DLL load notification callback
unsafe extern "C" fn dll_loaded_callback(dll_path: *const c_char, _base_address: *const c_void) {
    if dll_path.is_null() {
        warn!("DLL loaded but path is null");
        return;
    }

    unsafe {
        match CStr::from_ptr(dll_path).to_str() {
            Ok(_path) => {
                // info!("DLL loaded: {} at address {:p}", path, base_address);
            }
            Err(e) => {
                error!("Error converting DLL path to string: {}", e);
            }
        }
    }
    // le_lib_load_hook();
}

/// Constructor attribute - This function will be called automatically when the library is loaded
/// Perfect for LD_PRELOAD usage as it ensures our initialization happens before any other code runs
#[unsafe(no_mangle)]
#[used]
#[cfg_attr(
    any(target_os = "linux", target_os = "android"),
    unsafe(link_section = ".init_array")
)]
pub static __LE_LIB_CONSTRUCTOR: extern "C" fn() = {
    extern "C" fn constructor() {
        // We must initialize logger directly here because the info! call needs it
        initialize_logger();
        info!("Library loaded - constructor function called");
        le_lib_init();
    }
    constructor
};

/// Initialize the library
///
/// This function:
/// 1. Initializes the logger
/// 2. Sets up hook that will log after DLL is loaded in memory
/// 3. Initializes global hashmap for hooks
/// 4. Initializes Wine DLL loading hooks
/// 5. Reads hooks configuration from file
#[unsafe(no_mangle)]
pub extern "C" fn le_lib_init() -> bool {
    let mut success = true;

    INIT.call_once(|| {
        // Initialize logger
        initialize_logger();
        info!("le_lib_init: Library initialization started");

        // register hook `le_lib_echo`
        if !register_hook("le_lib_echo", le_lib_echo as HookFunctionPtr) {
            error!("le_lib_init: Failed to register le_lib_echo hook");
            success = false;
        } else {
            info!("le_lib_init: le_lib_echo hook registered successfully");
        }

        // Read hooks configuration
        match load_hooks_config() {
            Ok(config) => {
                info!("le_lib_init: Loaded hooks configuration with {} hooks", config.hooks.len());
                for hook in &config.hooks {
                    info!("le_lib_init: Found hook '{}' in config targeting '{}'", hook.name, hook.target_address);
                }
            },
            Err(e) => {
                warn!("le_lib_init: Failed to load hooks config: {}", e);
                warn!("le_lib_init: Will try loading hooks when le_lib_load_hook is called");
            }
        };

        // Initialize hooks hashmap (already done via lazy_static)
        info!("le_lib_init: Hooks hashmap initialized");

        // Set up DLL load notification
        match unsafe { register_dll_notification(dll_loaded_callback) } {
            true => {
                info!("le_lib_init: DLL load notification hook registered successfully");
            }
            false => {
                error!("le_lib_init: Failed to register DLL load notification hook");
                success = false;
            }
        }

        match initialize_wine_hooks() {
            true => {
                info!("le_lib_init: Wine DLL loading hooks initialized successfully");
            }
            false => {
                error!("le_lib_init: Failed to initialize Wine DLL loading hooks");

                // Check if we should continue despite failure
                if env::var("LE_CONTINUE_ON_HOOK_FAILURE")
                    .map(|v| v == "1" || v.to_lowercase() == "true")
                    .unwrap_or(false)
                {
                    info!("le_lib_init: LE_CONTINUE_ON_HOOK_FAILURE=true, continuing despite hook failure");
                } else {
                    success = false;
                }
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
