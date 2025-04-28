use log::info;
use std::path::Path;
use std::process::Command;

use super::is_path_writable;

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
    use std::io::Write;

    #[test]
    fn test_find_nasm_path() {
        match find_nasm_path() {
            Ok(path) => println!("Found NASM at: {}", path),
            Err(e) => println!("NASM not found: {}", e),
        }
    }

    #[test]
    fn test_local_compilation() {
        // Skip this test if NASM is not available
        if find_nasm_path().is_err() {
            println!("Skipping test_local_compilation because NASM is not installed");
            return;
        }

        // Create a simple assembly file
        let asm_code = r#"section .text
global _start
_start:
    mov rax, 60     ; syscall number for exit
    xor rdi, rdi    ; exit code 0
    syscall         ; invoke exit syscall
"#;

        // Create a temporary directory and file
        let tmp_dir = match std::env::var("TMPDIR").or_else(|_| std::env::var("TMP")) {
            Ok(dir) => dir,
            Err(_) => "/tmp".to_string(),
        };

        let asm_path = format!("{}/test_local_compilation.asm", tmp_dir);
        let output_path = format!("{}/test_local_compilation.o", tmp_dir);

        // Write assembly code to file
        let mut file = fs::File::create(&asm_path).expect("Failed to create test assembly file");
        file.write_all(asm_code.as_bytes())
            .expect("Failed to write test assembly code");

        // Compile the assembly code
        let result = compile_assembly_local(&asm_path, &output_path);

        // Clean up
        if Path::new(&asm_path).exists() {
            fs::remove_file(&asm_path).expect("Failed to clean up test assembly file");
        }

        // Check compilation result
        match result {
            Ok(_) => {
                assert!(Path::new(&output_path).exists(), "Output file should exist");
                fs::remove_file(&output_path).expect("Failed to clean up test output file");
            }
            Err(e) => panic!("Compilation failed: {}", e),
        }
    }
}
