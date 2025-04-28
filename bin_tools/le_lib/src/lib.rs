use log::{LevelFilter, info};
use std::sync::Once;

pub use echo::le_lib_echo;
pub use hook_tools::{le_lib_load_hook, le_lib_unload_hook};
pub use lib_init::le_lib_init;

// Declare modules
pub mod constants;
pub mod echo;
pub mod hook_tools;
pub mod lib_init;
pub mod low_level_tools;
pub mod wine_hooks;

static INIT: Once = Once::new();

pub fn initialize_logger() {
    INIT.call_once(|| {
        let config = log4rs::append::file::FileAppender::builder()
            .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
                constants::LOG_PATTERN,
            )))
            .build(constants::LOG_FILE_PATH)
            .unwrap();

        let config = log4rs::config::Config::builder()
            .appender(log4rs::config::Appender::builder().build("file", Box::new(config)))
            .build(
                log4rs::config::Root::builder()
                    .appender("file")
                    .build(LevelFilter::Info),
            )
            .unwrap();

        log4rs::init_config(config).expect("Failed to initialize logger");
        info!("le_lib logger initialized");
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
        le_lib_echo();
    }
}
