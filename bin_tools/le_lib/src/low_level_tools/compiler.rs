use log::{error, info, warn};
use std::fs;
use std::io::Write;
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
    match fs::write(&tmp_asm_path, asm_code) {
        Ok(_) => info!("Wrote assembly code to {}", tmp_asm_path.display()),
        Err(e) => {
            return CompilationResult::Error(format!(
                "Failed to write temporary assembly file: {}",
                e
            ));
        }
    }

    // Create a simple HTTP client using curl
    let server_url = get_compiler_server_url();
    let curl_cmd = Command::new("curl")
        .arg("-s")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(format!(
            "{{\"asm_code\": {}, \"format\": \"{}\"}}",
            serde_json::to_string(asm_code).unwrap_or_else(|_| "\"\"".to_string()),
            format
        ))
        .arg(format!("{}/compile", server_url))
        .output();

    // Process the curl command result
    match curl_cmd {
        Ok(output) => {
            if output.status.success() {
                let response_str = String::from_utf8_lossy(&output.stdout);

                // Parse the JSON response
                match serde_json::from_str::<serde_json::Value>(&response_str) {
                    Ok(json_response) => {
                        if let Some(success) =
                            json_response.get("success").and_then(|v| v.as_bool())
                        {
                            if success {
                                if let Some(binary_str) =
                                    json_response.get("binary").and_then(|v| v.as_str())
                                {
                                    // Decode the base64 binary data
                                    match base64::decode(binary_str) {
                                        Ok(binary_data) => {
                                            // Write the binary data to the output file
                                            match fs::write(output_path, &binary_data) {
                                                Ok(_) => {
                                                    info!(
                                                        "Successfully wrote compiled binary to {}",
                                                        output_path
                                                    );
                                                    CompilationResult::Success(binary_data)
                                                }
                                                Err(e) => CompilationResult::Error(format!(
                                                    "Failed to write compiled binary to {}: {}",
                                                    output_path, e
                                                )),
                                            }
                                        }
                                        Err(e) => CompilationResult::Error(format!(
                                            "Failed to decode base64 binary: {}",
                                            e
                                        )),
                                    }
                                } else {
                                    CompilationResult::Error(
                                        "Binary data missing from server response".to_string(),
                                    )
                                }
                            } else {
                                let error_msg = json_response
                                    .get("error")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown error");
                                CompilationResult::Error(format!(
                                    "Server reported error: {}",
                                    error_msg
                                ))
                            }
                        } else {
                            CompilationResult::Error("Invalid server response format".to_string())
                        }
                    }
                    Err(e) => {
                        CompilationResult::Error(format!("Failed to parse server response: {}", e))
                    }
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                CompilationResult::Error(format!("curl command failed: {}", stderr))
            }
        }
        Err(e) => CompilationResult::Error(format!("Failed to execute curl command: {}", e)),
    }
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
                assert!(Path::new(&output_path).exists(), "Compiled output file does not exist");
                
                // Check that binary data has a reasonable size for a simple program
                assert!(binary_data.len() > 0, "Binary data is empty");
                println!("Successfully compiled assembly code. Binary size: {} bytes", binary_data.len());
                
                // Verify that the file contains the same data
                let file_data = fs::read(&output_path).expect("Could not read compiled output file");
                assert_eq!(binary_data, file_data, "File data does not match returned binary data");
                
                // Clean up the test file
                fs::remove_file(&output_path).expect("Could not delete test output file");
            },
            CompilationResult::Error(err) => {
                panic!("Remote compilation failed: {}. Make sure the compilation server is running.", err);
            }
        }
    }
    
    /// Test that we can get a valid server URL
    #[test]
    fn test_get_compiler_server_url() {
        let url = get_compiler_server_url();
        assert!(!url.is_empty(), "Server URL should not be empty");
        assert!(url.starts_with("http://"), "Server URL should start with http://");
    }
    
    /// Test that we can get a valid temporary directory
    #[test]
    fn test_get_temp_dir() {
        let temp_dir = get_temp_dir();
        assert!(!temp_dir.is_empty(), "Temp directory should not be empty");
        assert!(Path::new(&temp_dir).exists(), "Temp directory should exist");
    }
}
