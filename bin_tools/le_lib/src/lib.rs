use log::{LevelFilter, info};
use low_level_tools::hook_tools;
use std::sync::Once;

pub use hooks::ability_hook;
pub use hooks::ability_hook::le_lib_ability_hook;
pub use hooks::echo;
pub use hooks::echo::le_lib_echo;
pub use hooks::pickup;
pub use hooks::pickup::le_lib_pickup;
pub use hooks::player_hook;
pub use hooks::player_hook::le_lib_player_hook;
pub use lib_init::le_lib_init;
pub use low_level_tools::hook_tools::{le_lib_load_hook, le_lib_unload_hook};

// Declare modules
pub mod constants;
pub mod hooks;
pub mod lib_init;
pub mod low_level_tools;
pub mod system_tools;
pub mod wine_hooks;
pub mod wine_memory; // Add new module for Wine memory operations

static INIT: Once = Once::new();

pub fn initialize_logger() {
    let current_pid = std::process::id();
    let current_proc_name = hook_tools::get_process_name_from_proc();
    let log_pattern_with_pid = format!("[PID: {}] {}", current_pid, constants::LOG_PATTERN);
    let level = match current_proc_name.ends_with(constants::GAME_NAME) {
        true => LevelFilter::Info, // Adjust log level for the game executable
        _ => LevelFilter::Warn,    // Default log level for other executables
    };
    INIT.call_once(|| {
        let config = log4rs::append::file::FileAppender::builder()
            .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
                log_pattern_with_pid.as_str(),
            )))
            .build(constants::LOG_FILE_PATH)
            .unwrap();

        let config = log4rs::config::Config::builder()
            .appender(log4rs::config::Appender::builder().build("file", Box::new(config)))
            .build(
                log4rs::config::Root::builder()
                    .appender("file")
                    .build(level),
            )
            .unwrap();

        log4rs::init_config(config).expect("Failed to initialize logger");
        info!(
            "le_lib logger initialized for process: {}",
            current_proc_name
        );
    });
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // Initialize logger for testing
        initialize_logger();
    }

    #[test]
    fn test_le_lib_echo() {
        let current_rsp: u64;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            std::arch::asm!("mov {rsp}, rsp", rsp = out(reg) current_rsp);
        }
        le_lib_echo(current_rsp);
    }
}
