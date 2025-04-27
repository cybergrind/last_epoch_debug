use log::{info, LevelFilter};
use std::sync::Once;

pub use echo::le_lib_echo;

// Declare the echo module
pub mod echo;

static INIT: Once = Once::new();

pub fn initialize_logger() {
    INIT.call_once(|| {
        let log_path = "/tmp/le_lib.log";
        let config = log4rs::append::file::FileAppender::builder()
            .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new("{d} {l} {t} - {m}{n}")))
            .build(log_path)
            .unwrap();

        let config = log4rs::config::Config::builder()
            .appender(log4rs::config::Appender::builder().build("file", Box::new(config)))
            .build(log4rs::config::Root::builder()
                .appender("file")
                .build(LevelFilter::Info))
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
