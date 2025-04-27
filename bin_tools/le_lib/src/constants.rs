// Constants used across the le_lib crate

// Logging
pub const LOG_FILE_PATH: &str = "/tmp/le_lib.log";
pub const LOG_PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S.%s)} [{l}] {t}: {m}{n}";

// Hook-related constants
pub const DEFAULT_HOOKS_CONFIG_PATH: &str = "/tmp/hooks.yaml";

// Function to get hooks config path from environment variable or default
pub fn get_hooks_config_path() -> String {
    std::env::var("HOOKS_CONFIG_PATH").unwrap_or_else(|_| DEFAULT_HOOKS_CONFIG_PATH.to_string())
}
