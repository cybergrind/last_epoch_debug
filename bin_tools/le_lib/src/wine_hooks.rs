// filepath: /home/kpi/devel/github/last_epoch_debug/bin_tools/le_lib/src/wine_hooks.rs
use crate::lib_init::notify_dll_loaded;
use dlopen::raw::Library;
use lazy_static::lazy_static;
use log::{error, info};
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::sync::{Mutex, Once};

// Define Wine/Windows types
type HMODULE = *mut c_void;
type LPCSTR = *const c_char;

// Define function types for LoadLibraryA and LoadLibraryW
type LoadLibraryAFunc = unsafe extern "system" fn(lpLibFileName: LPCSTR) -> HMODULE;
type LoadLibraryWFunc = unsafe extern "system" fn(lpLibFileName: *const u16) -> HMODULE;

// Store original function pointers
lazy_static! {
    static ref ORIGINAL_LOADLIBRARYA: Mutex<Option<LoadLibraryAFunc>> = Mutex::new(None);
    static ref ORIGINAL_LOADLIBRARYW: Mutex<Option<LoadLibraryWFunc>> = Mutex::new(None);
    static ref HOOK_INITIALIZED: Once = Once::new();
}

// Hook for LoadLibraryA
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn LoadLibraryA(lpLibFileName: LPCSTR) -> HMODULE {
    if lpLibFileName.is_null() {
        if let Some(original_func) = *ORIGINAL_LOADLIBRARYA.lock().unwrap() {
            return unsafe { original_func(lpLibFileName) };
        }
        return std::ptr::null_mut();
    }

    // Call the original function
    let result = if let Some(original_func) = *ORIGINAL_LOADLIBRARYA.lock().unwrap() {
        unsafe { original_func(lpLibFileName) }
    } else {
        error!("Original LoadLibraryA function not found");
        return std::ptr::null_mut();
    };

    // If successful, log the loaded DLL
    if !result.is_null() {
        match unsafe { CStr::from_ptr(lpLibFileName) }.to_str() {
            Ok(lib_name) => {
                info!("LoadLibraryA loaded: {}", lib_name);
                notify_dll_loaded(lib_name, result);
            }
            Err(e) => error!("Failed to convert DLL name: {}", e),
        }
    }

    result
}

// Hook for LoadLibraryW
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn LoadLibraryW(lpLibFileName: *const u16) -> HMODULE {
    if lpLibFileName.is_null() {
        if let Some(original_func) = *ORIGINAL_LOADLIBRARYW.lock().unwrap() {
            return unsafe { original_func(lpLibFileName) };
        }
        return std::ptr::null_mut();
    }

    // Call the original function
    let result = if let Some(original_func) = *ORIGINAL_LOADLIBRARYW.lock().unwrap() {
        unsafe { original_func(lpLibFileName) }
    } else {
        error!("Original LoadLibraryW function not found");
        return std::ptr::null_mut();
    };

    // If successful, log the loaded DLL
    if !result.is_null() {
        // Convert wide string to narrow
        let mut length = 0;
        unsafe {
            while *lpLibFileName.add(length) != 0 {
                length += 1;
            }

            let wstr: Vec<u16> = std::slice::from_raw_parts(lpLibFileName, length).to_vec();
            match String::from_utf16(&wstr) {
                Ok(lib_name) => {
                    info!("LoadLibraryW loaded: {}", lib_name);
                    notify_dll_loaded(&lib_name, result);
                }
                Err(e) => error!("Failed to convert wide DLL name: {}", e),
            }
        }
    }

    result
}

// Initialize the hooks by finding and storing the original functions
pub fn initialize_wine_hooks() -> bool {
    let mut success = true;

    HOOK_INITIALIZED.call_once(|| {
        info!("Initializing Wine DLL load hooks");

        unsafe {
            // Try multiple possible paths for Wine libraries
            let possible_libraries = [
                "kernel32.dll",                                // Direct library name for Wine
                "libkernel32.dll",                             // Some Wine setups
                "/usr/lib/wine/kernel32.dll",                  // Potential Linux location
                "/usr/lib/i386-linux-gnu/wine/kernel32.dll",   // Debian-based 32-bit location
                "/usr/lib/x86_64-linux-gnu/wine/kernel32.dll", // Debian-based 64-bit location
            ];

            let mut lib_result = None;
            for lib_path in possible_libraries.iter() {
                info!("Trying to load Wine library from: {}", lib_path);
                match Library::open(lib_path) {
                    Ok(lib) => {
                        info!("Successfully loaded Wine library from: {}", lib_path);
                        lib_result = Some(lib);
                        break;
                    }
                    Err(e) => {
                        info!("Failed to open {}: {}", lib_path, e);
                        // Continue trying next path
                    }
                }
            }

            match lib_result {
                Some(lib) => {
                    // Find LoadLibraryA
                    match lib.symbol::<LoadLibraryAFunc>("LoadLibraryA") {
                        Ok(func) => {
                            *ORIGINAL_LOADLIBRARYA.lock().unwrap() = Some(func);
                            info!("Found original LoadLibraryA at {:p}", func as *const ());
                        }
                        Err(e) => {
                            error!("Failed to find LoadLibraryA: {}", e);
                            success = false;
                        }
                    }

                    // Find LoadLibraryW
                    match lib.symbol::<LoadLibraryWFunc>("LoadLibraryW") {
                        Ok(func) => {
                            *ORIGINAL_LOADLIBRARYW.lock().unwrap() = Some(func);
                            info!("Found original LoadLibraryW at {:p}", func as *const ());
                        }
                        Err(e) => {
                            error!("Failed to find LoadLibraryW: {}", e);
                            success = false;
                        }
                    }
                }
                None => {
                    error!("Failed to open kernel32.dll or equivalent from any known location");
                    success = false;
                }
            }
        }

        if success {
            info!("Wine DLL load hooks initialized successfully");
        } else {
            error!("Failed to initialize Wine DLL load hooks");
        }
    });

    success
}
