use lazy_static::lazy_static;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::sync::Mutex;

use crate::constants::HOOKS_CONFIG_PATH;

// Structure to represent a hook configuration
#[derive(Debug, Deserialize, Serialize)]
pub struct Hook {
    pub name: String,
    pub target_address: String,
    pub memory_content: String,
    pub hook_function: String,
}

// Structure to represent the hooks configuration
#[derive(Debug, Deserialize, Serialize)]
pub struct HooksConfig {
    pub hooks: Vec<Hook>,
}

// Struct to represent an active hook
#[derive(Debug)]
#[allow(dead_code)]
struct ActiveHook {
    name: String,
    target_address: u64,
    trampoline_address: u64,
    hook_function_address: u64,
    original_bytes: Vec<u8>,
}

// Keep track of loaded hooks
lazy_static! {
    static ref ACTIVE_HOOKS: Mutex<HashMap<String, ActiveHook>> = Mutex::new(HashMap::new());
}

/// Loads hooks from the specified YAML configuration file
fn load_hooks_config() -> Result<HooksConfig, String> {
    match fs::read_to_string(HOOKS_CONFIG_PATH) {
        Ok(yaml_content) => match serde_yaml::from_str::<HooksConfig>(&yaml_content) {
            Ok(config) => Ok(config),
            Err(e) => Err(format!("Failed to parse hooks YAML: {}", e)),
        },
        Err(e) => Err(format!("Failed to read hooks config file: {}", e)),
    }
}

/// Gets the address for a function by name
fn get_function_address(function_name: &str) -> Result<u64, String> {
    // This is a simplified implementation and would need to be expanded
    // to look up symbols in the actual game binary
    match function_name {
        "le_lib_echo" => {
            // In a real implementation, we would look up the actual address
            // For now, use a placeholder to demonstrate the concept
            Ok(crate::echo::le_lib_echo as u64)
        }
        _ => Err(format!("Unknown function: {}", function_name)),
    }
}

/// Verifies memory content at the specified address matches what's expected
unsafe fn verify_memory_content(address: u64, expected_content: &str) -> bool {
    // Convert the expected content string to bytes
    let expected_bytes = expected_content
        .replace("\\x", "")
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| {
            let hex_str = chunk.iter().collect::<String>();
            u8::from_str_radix(&hex_str, 16).unwrap_or(0)
        })
        .collect::<Vec<u8>>();

    // Read the actual memory at the address
    unsafe {
        let actual_bytes = std::slice::from_raw_parts(address as *const u8, expected_bytes.len());

        // Compare the expected and actual bytes
        expected_bytes == actual_bytes
    }
}

/// Generates assembly for the hook trampoline
fn generate_hook_assembly(
    hook_name: &str,
    target_address: u64,
    hook_function_address: u64,
) -> Result<(String, String), String> {
    // Create temporary file paths
    let trampoline_asm_path = format!("/tmp/{}_trampoline.asm", hook_name);
    let jumper_asm_path = format!("/tmp/{}_jumper.asm", hook_name);

    // Create the trampoline assembly
    let trampoline_asm = format!(
        r#"section .text
global _start
_start:
    ; Save all registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    pushfq

    ; Call the hook function
    mov rax, 0x{:X}
    call rax

    ; Restore all registers
    popfq
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ; Jump back to the original function (after our jumper)
    mov rax, 0x{:X}
    add rax, 5    ; Skip the jumper instruction (5 bytes for a typical jmp)
    jmp rax
"#,
        hook_function_address, target_address
    );

    // Create the jumper assembly (this will replace the original code)
    let jumper_asm = format!(
        r#"section .text
global _start
_start:
    ; Jump to our trampoline
    jmp qword 0x{:X}
"#,
        target_address
    );

    // Write the assembly files
    if let Err(e) = fs::write(&trampoline_asm_path, trampoline_asm) {
        return Err(format!("Failed to write trampoline assembly: {}", e));
    }

    if let Err(e) = fs::write(&jumper_asm_path, jumper_asm) {
        return Err(format!("Failed to write jumper assembly: {}", e));
    }

    Ok((trampoline_asm_path, jumper_asm_path))
}

/// Compiles assembly code using NASM
fn compile_assembly(asm_path: &str, output_path: &str) -> Result<(), String> {
    let output = Command::new("nasm")
        .args(&[
            "-o",
            output_path,
            "-f",
            "elf64",
            "-l",
            "-g",
            "-w+all",
            asm_path,
        ])
        .output()
        .map_err(|e| format!("Failed to execute nasm: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("NASM compilation failed: {}", stderr));
    }

    Ok(())
}

/// Injects compiled code into memory and updates the game code
unsafe fn inject_hook(
    hook: &Hook,
    _trampoline_path: &str,
    _jumper_path: &str,
) -> Result<ActiveHook, String> {
    // Parse the target address
    let target_address = u64::from_str_radix(&hook.target_address, 16)
        .map_err(|_| format!("Invalid target address: {}", hook.target_address))?;

    // Get the hook function address
    let hook_function_address = get_function_address(&hook.hook_function)?;

    // In a real implementation, we would:
    // 1. Load the compiled object files
    // 2. Allocate memory for them
    // 3. Copy the code into the allocated memory
    // 4. Make the memory executable
    // 5. Save the original bytes at the target address
    // 6. Write the jump instruction to the target address

    // This is a simplified placeholder implementation
    let trampoline_address = 0xDEADBEEF; // Placeholder
    let original_bytes = vec![0u8; 5]; // Placeholder for saved bytes

    // Create and return the active hook
    Ok(ActiveHook {
        name: hook.name.clone(),
        target_address,
        trampoline_address,
        hook_function_address,
        original_bytes,
    })
}

/// Loads the hooks into the game
#[unsafe(no_mangle)]
pub extern "C" fn le_lib_load_hook() -> bool {
    // Initialize logger
    crate::initialize_logger();
    info!("Loading hooks from {}", HOOKS_CONFIG_PATH);

    // Load the hooks configuration
    let hooks_config = match load_hooks_config() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load hooks config: {}", e);
            return false;
        }
    };

    // Get the active hooks
    let mut active_hooks = match ACTIVE_HOOKS.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire active hooks lock: {}", e);
            return false;
        }
    };

    // Track which hooks we've processed in this call
    let mut processed_hooks = HashSet::new();

    // Process each hook in the configuration
    for hook in &hooks_config.hooks {
        // Skip if hook is already loaded
        if active_hooks.contains_key(&hook.name) {
            info!("Hook '{}' is already loaded", hook.name);
            processed_hooks.insert(hook.name.clone());
            continue;
        }

        // Parse the target address
        let target_address = match u64::from_str_radix(&hook.target_address, 16) {
            Ok(addr) => addr,
            Err(_) => {
                error!(
                    "Invalid target address for hook '{}': {}",
                    hook.name, hook.target_address
                );
                continue;
            }
        };

        // Verify memory content
        let memory_matches = unsafe { verify_memory_content(target_address, &hook.memory_content) };
        if !memory_matches {
            error!("Memory content doesn't match for hook '{}'", hook.name);
            continue;
        }

        // Get the hook function address
        let hook_function_address = match get_function_address(&hook.hook_function) {
            Ok(addr) => addr,
            Err(e) => {
                error!(
                    "Failed to get function address for hook '{}': {}",
                    hook.name, e
                );
                continue;
            }
        };

        // Generate assembly code
        let (trampoline_asm_path, jumper_asm_path) =
            match generate_hook_assembly(&hook.name, target_address, hook_function_address) {
                Ok(paths) => paths,
                Err(e) => {
                    error!(
                        "Failed to generate assembly for hook '{}': {}",
                        hook.name, e
                    );
                    continue;
                }
            };

        // Compile the assembly code
        let trampoline_obj_path = format!("/tmp/{}_trampoline.o", hook.name);
        let jumper_obj_path = format!("/tmp/{}_jumper.o", hook.name);

        if let Err(e) = compile_assembly(&trampoline_asm_path, &trampoline_obj_path) {
            error!(
                "Failed to compile trampoline for hook '{}': {}",
                hook.name, e
            );
            continue;
        }

        if let Err(e) = compile_assembly(&jumper_asm_path, &jumper_obj_path) {
            error!("Failed to compile jumper for hook '{}': {}", hook.name, e);
            continue;
        }

        // Inject the hook
        match unsafe { inject_hook(hook, &trampoline_obj_path, &jumper_obj_path) } {
            Ok(active_hook) => {
                info!("Successfully loaded hook '{}'", hook.name);
                active_hooks.insert(hook.name.clone(), active_hook);
                processed_hooks.insert(hook.name.clone());
            }
            Err(e) => {
                error!("Failed to inject hook '{}': {}", hook.name, e);
            }
        }
    }

    // Check for hooks that need to be unloaded
    let hooks_to_remove: Vec<String> = active_hooks
        .keys()
        .filter(|name| !processed_hooks.contains(*name))
        .cloned()
        .collect();

    // Unload hooks that are no longer in the config
    for name in hooks_to_remove {
        if let Some(_hook) = active_hooks.remove(&name) {
            // In a real implementation, we would restore the original bytes here
            info!("Unloaded hook '{}'", name);
        }
    }

    true
}

/// Unloads all hooks from the game
#[unsafe(no_mangle)]
pub extern "C" fn le_lib_unload_hook() -> bool {
    // Initialize logger
    crate::initialize_logger();
    info!("Unloading all hooks");

    // Get the active hooks
    let mut active_hooks = match ACTIVE_HOOKS.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire active hooks lock: {}", e);
            return false;
        }
    };

    // Unload each active hook
    for (name, _hook) in active_hooks.drain() {
        // In a real implementation, we would restore the original bytes here
        info!("Unloaded hook '{}'", name);
    }

    true
}
