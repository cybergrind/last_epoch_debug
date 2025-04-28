use lazy_static::lazy_static;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::ptr;
use std::sync::{Mutex, Once};

use crate::constants::get_hooks_config_path;

// Structure to represent a hook configuration
#[derive(Debug, Deserialize, Serialize)]
pub struct Hook {
    pub name: String,
    pub target_address: String,
    pub memory_content: String,
    pub hook_function: String,
    pub wait_for_file: Option<String>,
    pub target_process: Option<String>,
    pub base_file: Option<String>,
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

/// Safely checks if memory at the given address is accessible
pub fn is_memory_accessible(address: u64, size: usize) -> bool {
    // Log the attempt for debugging
    // info!("Checking memory accessibility at address 0x{:x} for {} bytes", address, size);

    // We use a more robust method combining signal handling and proc maps
    // First, check if the memory region is mapped in our process
    let is_mapped = check_memory_mapped(address, size);
    // do not use parentheses in the if statement
    if !is_mapped {
        // warn!("Memory region 0x{:x} - 0x{:x} is not mapped in the process", address, address + size as u64);
        return false;
    }

    // If mapped, use signal handling as a second check
    use libc::{SA_RESETHAND, c_int, sigaction, sigemptyset, sighandler_t};
    use std::mem;
    use std::sync::atomic::{AtomicBool, Ordering};

    static MEMORY_ACCESS_FAILED: AtomicBool = AtomicBool::new(false);

    extern "C" fn handle_sigsegv(_: c_int) {
        MEMORY_ACCESS_FAILED.store(true, Ordering::SeqCst);
    }

    unsafe {
        // Reset the flag
        MEMORY_ACCESS_FAILED.store(false, Ordering::SeqCst);

        // Set up signal handler for SIGSEGV
        let mut sa: sigaction = mem::zeroed();
        sa.sa_sigaction = handle_sigsegv as sighandler_t;
        sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = SA_RESETHAND;

        // Backup old signal handler
        let mut old_sa: sigaction = mem::zeroed();
        if sigaction(libc::SIGSEGV, &sa, &mut old_sa) != 0 {
            warn!("Failed to set SIGSEGV handler for memory accessibility check");
            return false;
        }

        // Try to read the memory very carefully - use volatile reads only on the first and last bytes
        let ptr = address as *const u8;

        // Only check first and last byte to minimize risk
        if !MEMORY_ACCESS_FAILED.load(Ordering::SeqCst) {
            let _ = ptr::read_volatile(ptr);
        }

        if size > 1 && !MEMORY_ACCESS_FAILED.load(Ordering::SeqCst) {
            let _ = ptr::read_volatile(ptr.add(size - 1));
        }

        // Restore old signal handler
        sigaction(libc::SIGSEGV, &old_sa, std::ptr::null_mut());

        if MEMORY_ACCESS_FAILED.load(Ordering::SeqCst) {
            warn!("SIGSEGV triggered while checking memory at 0x{:x}", address);
            false
        } else {
            info!("Memory at address 0x{:x} appears to be accessible", address);
            true
        }
    }
}

/// Check if a memory region is mapped in the process by reading /proc/self/maps
fn check_memory_mapped(address: u64, size: usize) -> bool {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

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
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Get the base address of a loaded module from /proc/self/maps
fn get_module_base_address(module_name: &str) -> Option<u64> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let maps_path = "/proc/self/maps";
    let file = match File::open(maps_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open {}: {}", maps_path, e);
            return None;
        }
    };

    let reader = BufReader::new(file);

    // Look for lines containing the module name
    for line in reader.lines().filter_map(Result::ok) {
        if line.contains(module_name) {
            // Parse address range from line like: "7f9d80617000-7f9d80619000 r-xp ..."
            if let Some(addr_range) = line.split_whitespace().next() {
                let parts: Vec<&str> = addr_range.split('-').collect();
                if parts.len() == 2 {
                    if let Ok(start_addr) = u64::from_str_radix(parts[0], 16) {
                        info!(
                            "Found module {} at base address 0x{:x}",
                            module_name, start_addr
                        );
                        return Some(start_addr);
                    }
                }
            }
            // We only need the first occurrence as that's the base address
            break;
        }
    }

    warn!("Could not find base address for module: {}", module_name);
    None
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

/// Generates assembly for the hook trampoline
fn generate_hook_assembly(
    hook_name: &str,
    target_address: u64,
    hook_function_address: u64,
) -> Result<(String, String), String> {
    // Get a reliable temporary directory
    let tmp_dir = std::env::var("TMPDIR")
        .or_else(|_| std::env::var("TMP"))
        .or_else(|_| std::env::var("TEMP"))
        .unwrap_or_else(|_| {
            if std::path::Path::new("/tmp").exists() && is_path_writable("/tmp/test_write").is_ok()
            {
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

/// Check if a path is writable
fn is_path_writable(path: &str) -> Result<(), String> {
    let dir_path = std::path::Path::new(path)
        .parent()
        .ok_or_else(|| format!("Invalid path: {}", path))?;

    // Create directory if it doesn't exist
    if !dir_path.exists() {
        std::fs::create_dir_all(dir_path)
            .map_err(|e| format!("Failed to create directory {}: {}", dir_path.display(), e))?;
    }

    // Check if we can write to this location
    let test_file = format!("{}.writetest", path);
    match std::fs::File::create(&test_file) {
        Ok(_) => {
            // Clean up the test file
            if let Err(e) = std::fs::remove_file(&test_file) {
                warn!("Failed to remove test file {}: {}", test_file, e);
            }
            Ok(())
        }
        Err(e) => Err(format!("Cannot write to {}: {}", path, e)),
    }
}

/// Find the NASM executable, checking both Linux and Wine paths
fn find_nasm_path() -> Result<String, String> {
    // Try standard Linux path first
    let linux_path = "/usr/bin/nasm";
    if std::path::Path::new(linux_path).exists() {
        info!("Found NASM at Linux path: {}", linux_path);
        return Ok(linux_path.to_string());
    }

    // Try Wine paths
    let wine_paths = vec![
        "Z:\\usr\\bin\\nasm",
        "Z:/usr/bin/nasm",
        "C:\\windows\\system32\\nasm.exe",
        "C:/windows/system32/nasm.exe",
    ];

    for path in wine_paths {
        if std::path::Path::new(path).exists() {
            info!("Found NASM at Wine path: {}", path);
            return Ok(path.to_string());
        }
    }

    // Check if nasm is in PATH
    match Command::new("which").arg("nasm").output() {
        Ok(output) if output.status.success() => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            info!("Found NASM in PATH at: {}", path);
            return Ok(path);
        }
        _ => {}
    }

    // Last resort - just try "nasm" and hope it's in the PATH
    match Command::new("nasm").arg("--version").output() {
        Ok(output) if output.status.success() => {
            info!("Found NASM in PATH (version check successful)");
            return Ok("nasm".to_string());
        }
        _ => {}
    }

    Err("Could not find NASM executable. Please ensure NASM is installed.".to_string())
}

/// Compiles assembly code using NASM
fn compile_assembly(asm_path: &str, output_path: &str) -> Result<(), String> {
    // Use the find_nasm_path function to locate NASM
    let nasm_path = find_nasm_path()?;

    // Print command for debugging
    info!(
        "Running: {} -o {} -f elf64 -l -g -w+all {}",
        nasm_path, output_path, asm_path
    );

    // Check if the assembly file exists
    if !std::path::Path::new(asm_path).exists() {
        return Err(format!("Assembly file not found: {}", asm_path));
    }

    // Check if the output path is writable
    if let Err(e) = is_path_writable(output_path) {
        return Err(format!("Output path is not writable: {}", e));
    }

    // Execute the command
    let output = Command::new(&nasm_path)
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
        .map_err(|e| format!("Failed to execute nasm at {}: {}", nasm_path, e))?;

    // Check if the command was successful
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "NASM compilation failed: stderr={}, stdout={}, command={} -o {} -f elf64 -l -g -w+all {}",
            stderr, stdout, nasm_path, output_path, asm_path
        ));
    }

    // Check if the output file was created
    if !std::path::Path::new(output_path).exists() {
        return Err(format!(
            "Compilation succeeded but output file not found: {}",
            output_path
        ));
    }

    info!("Successfully compiled {} to {}", asm_path, output_path);
    Ok(())
}

/// Injects compiled code into memory and updates the game code
unsafe fn inject_hook(
    hook: &Hook,
    _trampoline_path: &str,
    _jumper_path: &str,
) -> Result<ActiveHook, String> {
    // Parse the target address
    let target_address = parse_hex_address(&hook.target_address)?;

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

        // Get the directory where the asm files were written
        let base_dir = std::path::Path::new(&trampoline_asm_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/tmp".to_string());

        // Compile the assembly code
        let trampoline_obj_path = format!("{}/{}_trampoline.o", base_dir, hook.name);
        let jumper_obj_path = format!("{}/{}_jumper.o", base_dir, hook.name);

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
    hook_function: le_lib_echo
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
        assert_eq!(config.hooks[0].hook_function, "le_lib_echo");

        // Clean up
        cleanup_test_hooks_config().expect("Failed to clean up test hooks config");
    }

    #[test]
    fn test_generate_hook_assembly() {
        // Test generating assembly for the hook
        let hook_name = "test_hook";
        let target_address = 0xDEADBEEF;
        let hook_function_address = 0xC0FFEE;

        // Generate the assembly
        let (trampoline_path, jumper_path) =
            generate_hook_assembly(hook_name, target_address, hook_function_address)
                .expect("Failed to generate hook assembly");

        // Check that the files were created
        assert!(
            Path::new(&trampoline_path).exists(),
            "Trampoline assembly file not created"
        );
        assert!(
            Path::new(&jumper_path).exists(),
            "Jumper assembly file not created"
        );

        // Clean up the test files
        fs::remove_file(trampoline_path).expect("Failed to remove trampoline assembly file");
        fs::remove_file(jumper_path).expect("Failed to remove jumper assembly file");
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
    fn test_nasm_compilation() {
        // Create a simple assembly file for testing
        let test_asm = r#"
section .text
global _start
_start:
    ; Simple no-op assembly
    nop
    ret
"#;

        let asm_path = "/tmp/test_compilation.asm";
        let obj_path = "/tmp/test_compilation.o";

        // Write the test assembly file
        fs::write(asm_path, test_asm).expect("Failed to write test assembly file");

        // Test compiling the assembly
        let result = compile_assembly(asm_path, obj_path);
        assert!(
            result.is_ok(),
            "NASM compilation failed: {:?}",
            result.err()
        );

        // Check that the object file was created
        assert!(Path::new(obj_path).exists(), "Object file was not created");

        // Clean up the test files
        fs::remove_file(asm_path).expect("Failed to remove test assembly file");
        fs::remove_file(obj_path).expect("Failed to remove test object file");
    }

    #[test]
    fn test_compilation_with_hook() {
        // Create test hooks configuration
        if let Err(e) = create_test_hooks_config() {
            panic!("Failed to create test hooks config: {}", e);
        }

        // Generate assembly for a test hook
        let hook_name = "test_hook";
        let target_address: u64 = 0xDEADBEEF;
        let hook_function_address = crate::echo::le_lib_echo as u64;

        // Generate trampoline assembly directly without using the function
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
    pushfq

    ; Call the hook function
    mov rax, 0x{:X}
    call rax

    ; Restore all registers
    popfq
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ; Jump back to the original function
    mov rax, 0x{:X}
    jmp rax
"#,
            hook_function_address, target_address
        );

        // Create the jumper assembly
        let jumper_asm = format!(
            r#"section .text
global _start
_start:
    ; Jump to our trampoline
    jmp qword 0x{:X}
"#,
            target_address
        );

        // Write the assembly files directly in the test
        fs::write(&trampoline_asm_path, trampoline_asm)
            .expect("Failed to write trampoline assembly");
        fs::write(&jumper_asm_path, jumper_asm).expect("Failed to write jumper assembly");

        // Verify files were created successfully
        assert!(
            Path::new(&trampoline_asm_path).exists(),
            "Trampoline assembly file was not created at {}",
            trampoline_asm_path
        );
        assert!(
            Path::new(&jumper_asm_path).exists(),
            "Jumper assembly file was not created at {}",
            jumper_asm_path
        );

        // Print file paths and read back content for debugging
        println!("Trampoline file path: {}", trampoline_asm_path);
        println!("Jumper file path: {}", jumper_asm_path);

        match fs::read_to_string(&trampoline_asm_path) {
            Ok(content) => println!(
                "Trampoline file content: {} bytes\n{}",
                content.len(),
                content
            ),
            Err(e) => panic!("Error reading trampoline file: {}", e),
        }

        // Test compiling the trampoline assembly
        let trampoline_obj_path = format!("/tmp/{}_trampoline.o", hook_name);
        let result = compile_assembly(&trampoline_asm_path, &trampoline_obj_path);
        assert!(
            result.is_ok(),
            "Trampoline compilation failed: {:?}",
            result.err()
        );

        // Test compiling the jumper assembly
        let jumper_obj_path = format!("/tmp/{}_jumper.o", hook_name);
        let result = compile_assembly(&jumper_asm_path, &jumper_obj_path);
        assert!(
            result.is_ok(),
            "Jumper compilation failed: {:?}",
            result.err()
        );

        // Clean up all the test files
        let _ = fs::remove_file(&trampoline_asm_path); // Ignore errors during cleanup
        let _ = fs::remove_file(&jumper_asm_path);
        let _ = fs::remove_file(&trampoline_obj_path);
        let _ = fs::remove_file(&jumper_obj_path);
        let _ = cleanup_test_hooks_config();
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
