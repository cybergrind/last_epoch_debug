use lazy_static::lazy_static;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::ptr;
#[cfg(test)]
use std::sync::RwLock;
use std::sync::{Mutex, Once};

use crate::constants::get_hooks_config_path;
use crate::low_level_tools::templates::render_jumper;
use crate::low_level_tools::templates::render_trampoline;
use crate::low_level_tools::{compiler, injector};
use crate::system_tools::MEMORY_MAP;

// Structure to represent a hook configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Hook {
    pub name: String,
    pub target_address: String,
    pub memory_content: String,
    pub hook_functions: Vec<String>,
    pub align_size: u64,
    pub overwritten_instructions: String,
    pub wait_for_file: Option<String>,
    pub target_process: Option<String>,
    pub base_file: Option<String>,
    pub base_address: Option<u64>,
}

// Structure to represent the hooks configuration
#[derive(Debug, Deserialize, Serialize)]
pub struct HooksConfig {
    pub hooks: Vec<Hook>,
}

// Struct to represent an active hook
#[derive(Debug)]
pub struct ActiveHook {
    pub name: String,
    pub target_address: u64,
    pub trampoline_address: u64,
    pub hook_function_addresses: Vec<u64>,
    pub original_bytes: Vec<u8>,
}

// Keep track of loaded hooks
lazy_static! {
    static ref ACTIVE_HOOKS: Mutex<HashMap<String, ActiveHook>> = Mutex::new(HashMap::new());
}

/// Safely checks if memory at the given address is accessible
/// Returns true if the memory is mapped (even if it has no permissions)
/// so that we can try to modify the permissions before accessing
pub fn is_memory_accessible(address: u64, size: usize) -> bool {
    // Check for null address early
    if address == 0 {
        return false;
    }

    // Check if the memory region is mapped in our process
    let is_mapped = check_memory_mapped(address, size);
    if !is_mapped {
        return false;
    }

    // For injection purposes, we care if the memory is mapped, even if permissions
    // are restrictive. We'll try to change permissions before access.
    true
}

/// Special handling for Wine memory access
/// We need to take extra care when accessing memory in Wine processes
pub fn is_wine_process() -> bool {
    // Check if this process is running under Wine
    // Look for Wine-specific environment variables or files
    use std::env;

    if let Ok(wineprefix) = env::var("WINEPREFIX") {
        return !wineprefix.is_empty();
    }

    if let Ok(winedebug) = env::var("WINEDEBUG") {
        return !winedebug.is_empty();
    }

    // Check if wine libraries are loaded in the process
    let maps_path = "/proc/self/maps";
    if let Ok(content) = std::fs::read_to_string(maps_path) {
        if content.contains("wine") || content.contains("ntdll.so") {
            return true;
        }
    }

    false
}

/// Get memory permissions from /proc/self/maps
pub fn get_memory_permissions(address: u64) -> Option<String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let maps_path = "/proc/self/maps";
    match File::open(maps_path) {
        Ok(file) => {
            let reader = BufReader::new(file);

            for line in reader.lines().filter_map(Result::ok) {
                // Parse address range from line like: "7f9d80617000-7f9d80619000 r-xp ..."
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let addr_range = parts[0];
                    let perms = parts[1];

                    let addr_parts: Vec<&str> = addr_range.split('-').collect();
                    if addr_parts.len() == 2 {
                        if let (Ok(start), Ok(end)) = (
                            u64::from_str_radix(addr_parts[0], 16),
                            u64::from_str_radix(addr_parts[1], 16),
                        ) {
                            if address >= start && address < end {
                                return Some(perms.to_string());
                            }
                        }
                    }
                }
            }
            None
        }
        Err(_) => None,
    }
}

/// Check if a memory region is mapped in the process by reading /proc/self/maps
fn check_memory_mapped(address: u64, size: usize) -> bool {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    // Early check for null or very low addresses which are typically protected
    if address < 0x1000 {
        error!(
            "Address 0x{:x} is too low (likely reserved/protected)",
            address
        );
        return false;
    }

    // Early check for very large or suspiciously large sizes
    if size > 1024 * 1024 * 10 {
        // 10MB limit
        error!("Size {} is too large for safe memory operation", size);
        return false;
    }

    let maps_path = "/proc/self/maps";
    let file = match File::open(maps_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open {}: {}", maps_path, e);
            return false;
        }
    };

    let reader = BufReader::new(file);
    let end_address = address + size as u64;

    info!(
        "Checking if memory region 0x{:x} - 0x{:x} is mapped",
        address, end_address
    );

    for line in reader.lines().filter_map(Result::ok) {
        // Parse address range from line like: "7f9d80617000-7f9d80619000 r-xp ..."
        if let Some(addr_range) = line.split_whitespace().next() {
            let parts: Vec<&str> = addr_range.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (
                    u64::from_str_radix(parts[0], 16),
                    u64::from_str_radix(parts[1], 16),
                ) {
                    // Check if our target address range overlaps with this mapped range
                    if address >= start && end_address <= end {
                        info!(
                            "Memory region 0x{:x} - 0x{:x} is mapped in range 0x{:x} - 0x{:x}",
                            address, end_address, start, end
                        );
                        // Also extract and log permissions
                        let perms = line.split_whitespace().nth(1).unwrap_or("-");
                        info!("Permissions for this memory region: {}", perms);
                        return true;
                    }
                }
            }
        }
    }

    error!(
        "Memory region 0x{:x} - 0x{:x} is NOT mapped in process space",
        address, end_address
    );
    false
}

#[cfg(test)]
lazy_static! {
    static ref MOCKED_MODULE_BASE_ADDRESS: RwLock<Option<u64>> = RwLock::new(None);
}

fn get_module_base_address(module_name: &str) -> Option<u64> {
    #[cfg(test)]
    {
        // In test mode, we can mock the module base address
        if let Ok(mocked_address) = MOCKED_MODULE_BASE_ADDRESS.read() {
            if let Some(address) = *mocked_address {
                return Some(address);
            }
        }
    }

    MEMORY_MAP
        .lock()
        .unwrap()
        .get_entry_by_name(module_name)
        .and_then(|entry| Some(entry.get_address()))
}

/// Loads hooks from the specified YAML configuration file
pub fn load_hooks_config() -> Result<HooksConfig, String> {
    match fs::read_to_string(get_hooks_config_path()) {
        Ok(yaml_content) => match serde_yaml::from_str::<HooksConfig>(&yaml_content) {
            Ok(config) => Ok(config),
            Err(e) => Err(format!("Failed to parse hooks YAML: {}", e)),
        },
        Err(e) => Err(format!("Failed to read hooks config file: {}", e)),
    }
}

/// Gets the address for a function by name
pub fn get_function_address(function_name: &str) -> Result<u64, String> {
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

/// Parses a hexadecimal address string, handling the optional '0x' prefix
pub fn parse_hex_address(address_str: &str) -> Result<u64, String> {
    // Remove '0x' prefix if present
    let clean_addr = address_str.trim_start_matches("0x");

    // Parse the hexadecimal string
    match u64::from_str_radix(clean_addr, 16) {
        Ok(addr) => Ok(addr),
        Err(_) => Err(format!("Invalid hexadecimal address: {}", address_str)),
    }
}

/// Converts a memory content string to bytes, handling both raw ASCII characters and \x escape sequences
pub fn memory_content_to_bytes(content: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'x') {
            // Process \x escape sequence
            chars.next(); // Skip 'x'

            // Get the next two hex characters
            let mut hex_str = String::new();
            if let Some(h1) = chars.next() {
                hex_str.push(h1);
                if let Some(h2) = chars.next() {
                    hex_str.push(h2);

                    // Convert hex to byte
                    if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                        result.push(byte);
                    } else {
                        warn!("Invalid hex escape sequence: \\x{}", hex_str);
                        // Preserve the original characters on error
                        result.push(b'\\');
                        result.push(b'x');
                        hex_str.chars().for_each(|c| result.push(c as u8));
                    }
                } else {
                    // Not enough characters, treat as literal \xh
                    result.push(b'\\');
                    result.push(b'x');
                    result.push(h1 as u8);
                }
            } else {
                // No characters after \x, treat as literal \x
                result.push(b'\\');
                result.push(b'x');
            }
        } else {
            // Regular character, use its ASCII/Unicode value
            result.push(c as u8);
        }
    }

    result
}

/// Calculate the real target address, considering the base_file if specified
fn calculate_real_target_address(hook: &Hook) -> Result<u64, String> {
    // First parse the target address as specified in the hook
    let parsed_address = parse_hex_address(&hook.target_address)?;

    // If base_file is defined, the address is relative to the module's base address
    if let Some(base_file) = &hook.base_file {
        // Get the base address of the specified module
        if let Some(base_address) = get_module_base_address(base_file) {
            // Calculate the real address by adding the base address
            let real_address = base_address + parsed_address;
            info!(
                "Hook '{}': Base address of {} is 0x{:x}, target is 0x{:x}, real address is 0x{:x}",
                hook.name, base_file, base_address, parsed_address, real_address
            );
            return Ok(real_address);
        } else {
            return Err(format!(
                "Could not find base module '{}' for hook '{}'. Is the module loaded?",
                base_file, hook.name
            ));
        }
    }

    // If no base_file is specified, use the address as is (absolute)
    info!(
        "Hook '{}': Using absolute address 0x{:x}",
        hook.name, parsed_address
    );
    Ok(parsed_address)
}

fn get_process_name_from_proc() -> String {
    // Read the process name from /proc/self/cmdline
    let cmdline_path = "/proc/self/cmdline";
    let cmdline = fs::read_to_string(cmdline_path).unwrap_or_else(|_| "unknown".to_string());
    cmdline.split('\0').next().unwrap_or("unknown").to_string()
}

fn get_process_pid() -> u32 {
    // Read the process ID from /proc/self/stat
    let stat_path = "/proc/self/stat";
    let stat_content = fs::read_to_string(stat_path).unwrap_or_else(|_| "0".to_string());
    let pid_str = stat_content.split_whitespace().next().unwrap_or("0");
    pid_str.parse::<u32>().unwrap_or(0)
}

/// Verifies memory content at the specified address matches what's expected
unsafe fn verify_memory_content(address: u64, expected_content: &str) -> bool {
    // Get the process name for better diagnostic information
    let process_name = std::env::args()
        .next()
        .unwrap_or_else(|| "unknown".to_string());
    let pid = get_process_pid();

    // Convert the expected content string to bytes
    info!(
        "Process: {} (PID: {}) Verifying memory content at address 0x{:x}",
        process_name, pid, address
    );
    let expected_bytes = memory_content_to_bytes(expected_content);

    info!(
        "Process: {} (PID: {}) Checking memory at address 0x{:x} for {} bytes",
        process_name,
        pid,
        address,
        expected_bytes.len()
    );

    // First check if the memory is accessible - this is critical to avoid segfaults
    if !is_memory_accessible(address, expected_bytes.len()) {
        warn!(
            "Process: {} Memory at address 0x{:x} is not accessible, skipping content verification",
            process_name, address
        );
        return false;
    }

    // We'll be extremely cautious about memory access
    let result = unsafe {
        // Use a closure to contain any potential memory access issues
        let verify_result = std::panic::catch_unwind(|| {
            info!(
                "Pid: {} Process: {} Reading memory at address 0x{:x}",
                pid, process_name, address
            );

            // Read each byte individually for safer access
            let mut actual_bytes = Vec::with_capacity(expected_bytes.len());
            for i in 0..expected_bytes.len() {
                let ptr = (address as *const u8).add(i);
                let byte = ptr::read_volatile(ptr);
                actual_bytes.push(byte);
            }

            info!("Actual bytes read: {:02X?}", actual_bytes);
            info!("Expected bytes: {:02X?}", expected_bytes);

            actual_bytes == expected_bytes
        });

        match verify_result {
            Ok(result) => result,
            Err(_) => {
                error!(
                    "Process: {} Panic occurred during memory verification at address 0x{:x}",
                    process_name, address
                );
                false
            }
        }
    };

    if result {
        info!(
            "Process: {} Memory content at 0x{:x} matches expected pattern",
            process_name, address
        );
    } else {
        info!(
            "Process: {} Memory content at 0x{:x} does not match expected pattern",
            process_name, address
        );
    }

    result
}

/// Generates assembly for the hook trampoline and jumper
fn generate_hook_assembly(
    hook: &Hook,
    target_address: u64,
    hook_function_addresses: &Vec<u64>,
    trampoline_address: Option<u64>, // Optional trampoline address for jumper generation
) -> Result<(String, String), String> {
    // Get a reliable temporary directory
    let hook_name = hook.name.replace(" ", "_");

    let tmp_dir = std::env::var("TMPDIR")
        .or_else(|_| std::env::var("TMP"))
        .or_else(|_| std::env::var("TEMP"))
        .unwrap_or_else(|_| {
            if std::path::Path::new("/tmp").exists() {
                "/tmp".to_string()
            } else {
                format!("{}/tmp", std::env::var("HOME").unwrap_or(".".to_string()))
            }
        });

    // Create the directory if it doesn't exist
    if !std::path::Path::new(&tmp_dir).exists() {
        if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
            return Err(format!(
                "Failed to create temporary directory {}: {}",
                tmp_dir, e
            ));
        }
    }

    // Create temporary file paths
    let trampoline_asm_path = format!("{}/{}_trampoline.asm", tmp_dir, hook_name);
    let jumper_asm_path = format!("{}/{}_jumper.asm", tmp_dir, hook_name);

    info!("Using temporary directory: {}", tmp_dir);
    info!(
        "Generating assembly files: {} and {}",
        trampoline_asm_path, jumper_asm_path
    );

    // Create the trampoline assembly
    // prologue + each_hook*hook + epilogue
    let trampoline_asm = render_trampoline(
        hook_function_addresses.to_vec(),
        &hook.overwritten_instructions,
        target_address,
        hook.base_address.unwrap_or(0),
    );

    // Create the jumper assembly (this will replace the original code)
    let jumper_asm = render_jumper(trampoline_address);

    // Write the assembly files
    if let Err(e) = fs::write(&trampoline_asm_path, trampoline_asm) {
        return Err(format!("Failed to write trampoline assembly: {}", e));
    }

    if let Err(e) = fs::write(&jumper_asm_path, jumper_asm) {
        return Err(format!("Failed to write jumper assembly: {}", e));
    }

    Ok((trampoline_asm_path, jumper_asm_path))
}

fn align_to_size(buffer: &mut Vec<u8>, size: u64) {
    // if buffer size is less than size, fill with NOPs = 0x90
    let current_size = buffer.len() as u64;
    if current_size < size {
        let padding = size - current_size;
        buffer.extend(vec![0x90; padding as usize]);
    } else if current_size > size {
        // if buffer size is greater than size, truncate the buffer
        buffer.truncate(size as usize);
    }
    assert_eq!(buffer.len() as u64, size);
}

/// Compile and inject the hook using remote compilation service with separate trampoline and jumper steps
unsafe fn compile_and_inject_hook(hook: &Hook) -> Result<ActiveHook, String> {
    // Calculate the real target address
    let target_address = calculate_real_target_address(hook)?;

    info!(
        "Using real target address for hook '{}': 0x{:x}",
        hook.name, target_address
    );

    // Get the hook function address
    let hook_function_addresses = hook
        .hook_functions
        .iter()
        .map(|f| {
            get_function_address(f).unwrap_or_else(|_| {
                error!("Failed to get address for function '{}'", f);
                0
            })
        })
        .collect::<Vec<u64>>();

    // FIRST STEP: Generate and compile the trampoline

    // Generate assembly code for trampoline (without knowing trampoline address yet)
    let (trampoline_asm_path, _) =
        generate_hook_assembly(hook, target_address, &hook_function_addresses, None)?;

    // Read the assembly code file
    let trampoline_asm = fs::read_to_string(&trampoline_asm_path)
        .map_err(|e| format!("Failed to read trampoline assembly: {}", e))?;

    let tmp_dir = std::path::Path::new(&trampoline_asm_path)
        .parent()
        .ok_or_else(|| "Invalid trampoline path".to_string())?
        .to_string_lossy()
        .into_owned();

    // Set the output path for the compiled trampoline
    let trampoline_obj_path = format!("{}/{}_trampoline.o", tmp_dir, hook.name);

    // Compile the trampoline assembly code using the remote server
    info!("Compiling trampoline assembly using remote server");
    let trampoline_result =
        compiler::compile_assembly_remote(&trampoline_asm, &trampoline_obj_path, "bin");

    // Check compilation result
    let trampoline_data = match trampoline_result {
        compiler::CompilationResult::Success(data) => data,
        compiler::CompilationResult::Error(err) => {
            return Err(format!("Failed to compile trampoline: {}", err));
        }
    };

    // Write the trampoline to executable memory
    info!("Writing trampoline to executable memory");
    let trampoline_info = unsafe { injector::write_trampoline(&trampoline_data) }?;

    info!(
        "Trampoline written at address 0x{:X}",
        trampoline_info.address
    );

    // SECOND STEP: Now that we know the trampoline address, generate and compile the jumper

    // Generate jumper assembly with the actual trampoline address
    let (_, jumper_asm_path) = generate_hook_assembly(
        hook,
        target_address,
        &hook_function_addresses,
        Some(trampoline_info.address),
    )?;

    // Read the jumper assembly code
    let jumper_asm = fs::read_to_string(&jumper_asm_path)
        .map_err(|e| format!("Failed to read jumper assembly: {}", e))?;

    // Set the output path for the compiled jumper
    let jumper_obj_path = format!("{}/{}_jumper.o", tmp_dir, hook.name);

    // Compile the jumper assembly code
    info!("Compiling jumper assembly using remote server");
    let jumper_result = compiler::compile_assembly_remote(&jumper_asm, &jumper_obj_path, "bin");

    // Check compilation result
    let mut jumper_data = match jumper_result {
        compiler::CompilationResult::Success(data) => data,
        compiler::CompilationResult::Error(err) => {
            // Free the trampoline memory if jumper compilation fails
            unsafe {
                // use the trampoline_info to free the memory
                let _ =
                    injector::free_executable_memory(trampoline_info.address, trampoline_info.size);
            }
            return Err(format!("Failed to compile jumper: {}", err));
        }
    };
    // align jumper to hook.align_size
    align_to_size(&mut jumper_data, hook.align_size);

    // Create a modified hook with correct target address for injector
    let mut injection_hook = hook.clone();
    injection_hook.target_address = format!("{:x}", target_address);

    // Inject the hook using our injector module
    unsafe { injector::inject_hook(&injection_hook, &trampoline_info, &jumper_data) }
}

fn get_only_matching_hooks(process_name: &str) -> Vec<Hook> {
    // Filter hooks based on the process name
    let hooks_config = load_hooks_config().unwrap();
    hooks_config
        .hooks
        .into_iter()
        .filter(|hook| {
            // we need to check only the end of process_name
            // eg: 'game.exe' should match 'Z:\\Progrtam Files\\Game\\game.exe'
            if let Some(target_process) = &hook.target_process {
                process_name.ends_with(target_process)
            } else {
                true
            }
        })
        // add base addresses
        .map(|mut hook| {
            if let Some(base_file) = &hook.base_file {
                hook.base_address = get_module_base_address(base_file);
            }
            hook
        })
        .collect()
}

static ONCE_LOADING_LOG: Once = Once::new();

/// Loads the hooks into the game
#[unsafe(no_mangle)]
pub extern "C" fn le_lib_load_hook() -> bool {
    // Initialize logger
    crate::initialize_logger();

    ONCE_LOADING_LOG.call_once(|| {
        info!("Loading hooks from {}", get_hooks_config_path());
    });

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
    let process_name = get_process_name_from_proc();
    let matching_hooks = get_only_matching_hooks(&process_name);

    if matching_hooks.is_empty() {
        return false;
    }

    info!("Processing {} hooks", matching_hooks.len());
    for hook in &matching_hooks {
        // Skip if hook is already loaded
        if active_hooks.contains_key(&hook.name) {
            info!("Hook '{}' is already loaded", hook.name);
            processed_hooks.insert(hook.name.clone());
            continue;
        }

        // Calculate the real target address (absolute or relative to base_file)
        let target_address = match calculate_real_target_address(hook) {
            Ok(addr) => addr,
            Err(e) => {
                error!("Invalid target address for hook '{}': {}", hook.name, e);
                continue;
            }
        };

        // Verify memory content
        let memory_matches = unsafe { verify_memory_content(target_address, &hook.memory_content) };
        if !memory_matches {
            error!("Memory content doesn't match for hook '{}'", hook.name);
            continue;
        }

        // Compile and inject the hook using our updated two-step process
        match unsafe { compile_and_inject_hook(hook) } {
            Ok(active_hook) => {
                info!("Successfully loaded hook '{}'", hook.name);
                active_hooks.insert(hook.name.clone(), active_hook);
                processed_hooks.insert(hook.name.clone());
            }
            Err(e) => {
                error!("Failed to compile and inject hook '{}': {}", hook.name, e);
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
        if let Some(hook) = active_hooks.remove(&name) {
            // Restore original bytes using our injector
            if let Err(e) = unsafe { injector::restore_hook(&hook) } {
                error!(
                    "Failed to restore original bytes for hook '{}': {}",
                    name, e
                );
            } else {
                info!("Unloaded hook '{}'", name);
            }
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
    for (name, hook) in active_hooks.drain() {
        // Restore original bytes using our injector
        if let Err(e) = unsafe { injector::restore_hook(&hook) } {
            error!(
                "Failed to restore original bytes for hook '{}': {}",
                name, e
            );
        } else {
            info!("Unloaded hook '{}'", name);
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    // Create a temporary hooks configuration file for testing
    fn create_test_hooks_config() -> std::io::Result<()> {
        // Create a simple test hooks yaml
        let test_yaml = r#"
hooks:
  - name: test_hook
    target_address: 0xDEADBEEF
    memory_content: '\x48\x89\x5C\x24\x08'  # Some example x86_64 instructions
    hook_functions: [ le_lib_echo ]
    align_size: 16
    overwritten_instructions: '\x90\x90\x90\x90'  # NOP instructions
    process_name: test_process.exe
    base_file: test_module.dll
"#;

        // Write the test yaml to the hooks config path
        let mut file = fs::File::create(get_hooks_config_path())?;
        file.write_all(test_yaml.as_bytes())?;
        Ok(())
    }

    // Clean up the test hooks configuration file
    fn cleanup_test_hooks_config() -> std::io::Result<()> {
        if Path::new(&get_hooks_config_path()).exists() {
            fs::remove_file(get_hooks_config_path())?;
        }
        Ok(())
    }

    #[test]
    fn test_load_hooks_config() {
        // Create test hooks configuration
        create_test_hooks_config().expect("Failed to create test hooks config");

        // Test loading the configuration
        let config = load_hooks_config().expect("Failed to load hooks config");

        // Verify the loaded configuration
        assert_eq!(config.hooks.len(), 1);
        assert_eq!(config.hooks[0].name, "test_hook");
        assert_eq!(config.hooks[0].target_address, "0xDEADBEEF");
        assert_eq!(config.hooks[0].memory_content, "\\x48\\x89\\x5C\\x24\\x08");
        assert_eq!(config.hooks[0].hook_functions[0], "le_lib_echo");

        // mock function `get_module_base_address` to return a known value
        let mock_base_address = 0x12345678;
        MOCKED_MODULE_BASE_ADDRESS
            .write()
            .unwrap()
            .replace(mock_base_address);

        let matching = get_only_matching_hooks("test_process.exe");
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].base_address, Some(mock_base_address));

        MOCKED_MODULE_BASE_ADDRESS.write().unwrap().take();
        let matching = get_only_matching_hooks("test_process.exe");
        assert_eq!(matching[0].base_address, None);

        // Clean up
        cleanup_test_hooks_config().expect("Failed to clean up test hooks config");
    }

    #[test]
    fn test_verify_memory_content() {
        // Create a static byte array to ensure it stays in memory
        static TEST_BYTES: [u8; 5] = [0x48, 0x89, 0x5C, 0x24, 0x08];
        let test_address = TEST_BYTES.as_ptr() as u64;

        // Convert expected hex string to bytes for debug comparison
        let expected_hex = "\\x48\\x89\\x5C\\x24\\x08";
        let expected_bytes: Vec<u8> = expected_hex
            .replace("\\x", "")
            .chars()
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|chunk| {
                let hex_str = chunk.iter().collect::<String>();
                u8::from_str_radix(&hex_str, 16).unwrap_or(0)
            })
            .collect();

        // Print the contents for debugging
        println!("Test bytes: {:02X?}", TEST_BYTES);
        println!("Expected bytes: {:02X?}", expected_bytes);

        // Read memory at the address
        let actual_bytes = unsafe { std::slice::from_raw_parts(test_address as *const u8, 5) };
        println!("Actual bytes read from memory: {:02X?}", actual_bytes);

        // Test verification with matching content
        let result = unsafe { verify_memory_content(test_address, expected_hex) };
        assert!(
            result,
            "Memory content verification failed for matching content"
        );

        // Test verification with non-matching content
        let result = unsafe { verify_memory_content(test_address, "\\xFF\\xFF\\xFF\\xFF\\xFF") };
        assert!(
            !result,
            "Memory content verification incorrectly succeeded for non-matching content"
        );
    }

    #[test]
    fn test_memory_content_to_bytes() {
        // Test with mixed ASCII and hex escape sequences
        let mixed_content =
            "@SUVATAUAWH\\x83\\xec(\\x80=1`-\\x03\\x00M\\x8b\\xe9M\\x8b\\xe0H\\x8b\\xeaH\\x8b";
        let bytes = memory_content_to_bytes(mixed_content);

        // Expected bytes:
        // ASCII '@' = 0x40, 'S' = 0x53, 'U' = 0x55, 'V' = 0x56, 'A' = 0x41, 'T' = 0x54, 'A' = 0x41, 'U' = 0x55
        // ASCII 'A' = 0x41, 'W' = 0x57, 'H' = 0x48, then \x83 = 0x83, \xec = 0xEC, '(' = 0x28, etc.
        let expected = vec![
            0x40, 0x53, 0x55, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x28,
            0x80, 0x3D, 0x31, 0x60, 0x2D, 0x03, 0x00, 0x4D, 0x8B, 0xE9, 0x4D, 0x8B, 0xE0, 0x48,
            0x8B, 0xEA, 0x48, 0x8B,
        ];

        assert_eq!(bytes, expected, "Bytes don't match expected output");
        println!("Parsed bytes: {:02X?}", bytes);

        // Test with only ASCII content
        let ascii_only = "Hello, World!";
        let bytes = memory_content_to_bytes(ascii_only);
        let expected = vec![
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
        ];
        assert_eq!(
            bytes, expected,
            "ASCII-only bytes don't match expected output"
        );

        // Test with only hex escapes
        let hex_only = "\\x48\\x65\\x6C\\x6C\\x6F";
        let bytes = memory_content_to_bytes(hex_only);
        let expected = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        assert_eq!(
            bytes, expected,
            "Hex-only bytes don't match expected output"
        );

        // Test with invalid hex escape sequence
        let invalid_hex = "Test\\xZZ";
        let bytes = memory_content_to_bytes(invalid_hex);
        let expected = vec![0x54, 0x65, 0x73, 0x74, 0x5C, 0x78, 0x5A, 0x5A]; // Should preserve the original characters
        assert_eq!(bytes, expected, "Invalid hex escape handling is incorrect");
    }
}
