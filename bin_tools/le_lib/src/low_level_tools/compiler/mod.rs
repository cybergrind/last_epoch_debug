use std::path::Path;

// Re-export functionality from the sub-modules
pub use self::compiler_local::compile_assembly_local;
pub use self::compiler_remote::compile_assembly_remote;

// Modules for implementation
mod compiler_local;
mod compiler_remote;

// Enum to represent the compilation status
pub enum CompilationResult {
    Success(Vec<u8>),
    Error(String),
}

/// Returns the URL for the compiler server
pub fn get_compiler_server_url() -> String {
    std::env::var("COMPILER_SERVER_URL").unwrap_or_else(|_| "http://192.168.88.38:8765".to_string())
}

/// Gets a reliable temporary directory
pub fn get_temp_dir() -> String {
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
                log::warn!("Failed to remove test file {}: {}", test_file, e);
            }
            Ok(())
        }
        Err(e) => Err(format!("Cannot write to {}: {}", path, e)),
    }
}
