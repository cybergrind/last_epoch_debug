use base64::Engine;
use log::info;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use super::{CompilationResult, get_compiler_server_url, get_temp_dir};

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
        return CompilationResult::Error(format!("Failed to write temporary assembly file: {}", e));
    }
    info!("Wrote assembly code to {}", tmp_asm_path.display());

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

    // Check if curl command execution failed
    let output = match curl_cmd {
        Ok(output) => output,
        Err(e) => {
            return CompilationResult::Error(format!("Failed to execute curl command: {}", e));
        }
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
        Err(e) => {
            return CompilationResult::Error(format!("Failed to parse server response: {}", e));
        }
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
        None => {
            return CompilationResult::Error("Binary data missing from server response".to_string());
        }
    };

    // Decode the base64 binary data
    let binary_data = match base64::engine::general_purpose::STANDARD.decode(binary_str) {
        Ok(data) => data,
        Err(e) => {
            return CompilationResult::Error(format!("Failed to decode base64 binary: {}", e));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
