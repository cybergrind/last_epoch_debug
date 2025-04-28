use base64::Engine;
use log::{info, warn};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// Enum to represent the compilation status
pub enum CompilationResult {
    Success(Vec<u8>),
    Error(String),
}

/// Compiles assembly code using a remote compilation server
pub fn compile_assembly_remote(
    asm_code: &str,
    output_path: &str,
    format: &str,
) -> CompilationResult {
    info!("Compiling assembly code remotely using the compiler server");

    // Create a temporary file for the assembly code
    let tmp_dir = get_temp_dir();
    let tmp_asm_path = PathBuf::from(&tmp_dir).join("temp_assembly.asm");

    // Write the assembly code to the temporary file
    if let Err(e) = fs::write(&tmp_asm_path, asm_code) {
        return CompilationResult::Error(format!(
            "Failed to write temporary assembly file: {}",
            e
        ));
    }
    info!("Wrote assembly code to {}", tmp_asm_path.display());

    // Create a simple HTTP client using curl
    let server_url = get_compiler_server_url();
    let curl_cmd = Command::new("curl")
        .arg("-s")
        .arg("-X").arg("POST")
        .arg("-H").arg("Content-Type: application/json")
        .arg("-d").arg(format!(
            "{{\"asm_code\": {}, \"format\": \"{}\"}}",
            serde_json::to_string(asm_code).unwrap_or_else(|_| "\"\"".to_string()),
            format
        ))
        .arg(format!("{}/compile", server_url))
        .output();
        
    // Check if curl command execution failed
    let output = match curl_cmd {
        Ok(output) => output,
        Err(e) => return CompilationResult::Error(format!("Failed to execute curl command: {}", e)),
    };
    
    // Check if curl command was successful
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return CompilationResult::Error(format!("curl command failed: {}", stderr));
    }
    
    // Parse the response
    let response_str = String::from_utf8_lossy(&output.stdout);
    let json_response: serde_json::Value = match serde_json::from_str(&response_str) {
        Ok(json) => json,
        Err(e) => return CompilationResult::Error(format!("Failed to parse server response: {}", e)),
    };
    
    // Check if the compilation was successful
    let success = match json_response.get("success").and_then(|v| v.as_bool()) {
        Some(success) => success,
        None => return CompilationResult::Error("Invalid server response format".to_string()),
    };
    
    if !success {
        let error_msg = json_response
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        return CompilationResult::Error(format!("Server reported error: {}", error_msg));
    }
    
    // Get binary data from response
    let binary_str = match json_response.get("binary").and_then(|v| v.as_str()) {
        Some(data) => data,
        None => return CompilationResult::Error("Binary data missing from server response".to_string()),
    };
    
    // Decode the base64 binary data
    let binary_data = match base64::engine::general_purpose::STANDARD.decode(binary_str) {
        Ok(data) => data,
        Err(e) => return CompilationResult::Error(format!("Failed to decode base64 binary: {}", e)),
    };
    
    // Write the binary data to the output file
    if let Err(e) = fs::write(output_path, &binary_data) {
        return CompilationResult::Error(format!(
            "Failed to write compiled binary to {}: {}", 
            output_path, e
        ));
    }
    
    info!("Successfully wrote compiled binary to {}", output_path);
    CompilationResult::Success(binary_data)
}

/// Compiles assembly code locally using the system NASM
pub fn compile_assembly_local(asm_path: &str, output_path: &str) -> Result<(), String> {
    // Log command for debugging
    info!(
        "Running local compilation: nasm -o {} -f elf64 -l -g -w+all {}",
        output_path, asm_path
    );

    // Check if the assembly file exists
    if !Path::new(asm_path).exists() {
        return Err(format!("Assembly file not found: {}", asm_path));
    }

    // Check if the output path is writable
    if let Err(e) = is_path_writable(output_path) {
        return Err(format!("Output path is not writable: {}", e));
    }

    // Find NASM executable
    let nasm_path = match find_nasm_path() {
        Ok(path) => path,
        Err(e) => return Err(e),
    };

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
    if !Path::new(output_path).exists() {
        return Err(format!(
            "Compilation succeeded but output file not found: {}",
            output_path
        ));
    }

    info!("Successfully compiled {} to {}", asm_path, output_path);
    Ok(())
}

/// Returns the URL for the compiler server
fn get_compiler_server_url() -> String {
    std::env::var("COMPILER_SERVER_URL").unwrap_or_else(|_| "http://localhost:8765".to_string())
}

/// Gets a reliable temporary directory
fn get_temp_dir() -> String {
    std::env::var("TMPDIR")
        .or_else(|_| std::env::var("TMP"))
        .or_else(|_| std::env::var("TEMP"))
        .unwrap_or_else(|_| {
            if Path::new("/tmp").exists() && is_path_writable("/tmp/test_write").is_ok() {
                "/tmp".to_string()
            } else {
                format!("{}/tmp", std::env::var("HOME").unwrap_or(".".to_string()))
            }
        })
}

/// Check if a path is writable
pub fn is_path_writable(path: &str) -> Result<(), String> {
    let dir_path = Path::new(path)
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
    if Path::new(linux_path).exists() {
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
        if Path::new(path).exists() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// Test that remote compilation works when the server is running
    #[test]
    fn test_remote_compilation() {
        // Create a simple assembly program to test compilation
        let asm_code = r#"section .text
global _start
_start:
    mov rax, 1      ; syscall number for write
    mov rdi, 1      ; file descriptor 1 is stdout
    mov rsi, msg    ; address of string to output
    mov rdx, 13     ; number of bytes
    syscall         ; invoke write syscall
    
    mov rax, 60     ; syscall number for exit
    xor rdi, rdi    ; exit code 0
    syscall         ; invoke exit syscall

section .data
msg:    db "Hello, World", 10    ; 10 is the ASCII code for new line
"#;

        // Create a temporary output path
        let tmp_dir = get_temp_dir();
        let output_path = format!("{}/test_remote_compilation.o", tmp_dir);

        // Remove any existing output file
        if Path::new(&output_path).exists() {
            fs::remove_file(&output_path).expect("Could not delete existing test output file");
        }

        // Run the remote compilation
        let result = compile_assembly_remote(asm_code, &output_path, "elf64");

        match result {
            CompilationResult::Success(binary_data) => {
                // Check that the file was created
                assert!(
                    Path::new(&output_path).exists(),
                    "Compiled output file does not exist"
                );

                // Check that binary data has a reasonable size for a simple program
                assert!(binary_data.len() > 0, "Binary data is empty");
                println!(
                    "Successfully compiled assembly code. Binary size: {} bytes",
                    binary_data.len()
                );

                // Verify that the file contains the same data
                let file_data =
                    fs::read(&output_path).expect("Could not read compiled output file");
                assert_eq!(
                    binary_data, file_data,
                    "File data does not match returned binary data"
                );

                // Clean up the test file
                fs::remove_file(&output_path).expect("Could not delete test output file");
            }
            CompilationResult::Error(err) => {
                panic!(
                    "Remote compilation failed: {}. Make sure the compilation server is running.",
                    err
                );
            }
        }
    }

    /// Test that we can get a valid server URL
    #[test]
    fn test_get_compiler_server_url() {
        let url = get_compiler_server_url();
        assert!(!url.is_empty(), "Server URL should not be empty");
        assert!(
            url.starts_with("http://"),
            "Server URL should start with http://"
        );
    }

    /// Test that we can get a valid temporary directory
    #[test]
    fn test_get_temp_dir() {
        let temp_dir = get_temp_dir();
        assert!(!temp_dir.is_empty(), "Temp directory should not be empty");
        assert!(Path::new(&temp_dir).exists(), "Temp directory should exist");
    }
}
