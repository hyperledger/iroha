//! Module with logger for iroha

use std::sync::RwLock;

use chrono::prelude::*;
use log::{Level, Log, Metadata, Record, SetLoggerError};

const RED: u8 = 31;
const GREEN: u8 = 32;
const YELLOW: u8 = 33;
const BLUE: u8 = 34;
const MAGENTA: u8 = 35;

lazy_static::lazy_static! {
    static ref LOGGER_SET: RwLock<bool> = RwLock::new(false);
}

#[derive(Default)]
struct Logger {
    terminal_color_enabled: bool,
    date_time_format: String,
}

impl Logger {
    pub fn new(configuration: &config::LoggerConfiguration) -> Logger {
        Logger {
            terminal_color_enabled: configuration.terminal_color_enabled,
            date_time_format: configuration.date_time_format.clone(),
        }
    }

    /// Default values were taken from the `pretty_env_logger` [source code](https://github.com/seanmonstar/pretty-env-logger/blob/master/src/lib.rs).
    const fn color(level: Level) -> u8 {
        match level {
            Level::Error => RED,
            Level::Warn => YELLOW,
            Level::Info => GREEN,
            Level::Debug => BLUE,
            Level::Trace => MAGENTA,
        }
    }
}

impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let log_entry = format!(
                "{} - {} - {}",
                record.level(),
                Utc::now().format(&self.date_time_format),
                record.args()
            );
            if self.terminal_color_enabled {
                println!("\x1b[{}m{}\x1b[0m", Self::color(record.level()), log_entry);
            } else {
                println!("{}", log_entry);
            }
        }
    }

    fn flush(&self) {}
}

/// Initializes `Logger` with given `LoggerConfiguration`.
/// After the initialization `log` macros will print with the use of this `Logger`.
/// For more information see [log crate](https://docs.rs/log/0.4.8/log/).
///
/// # Errors
/// Returns error from log crate
pub fn init(configuration: &config::LoggerConfiguration) -> Result<(), SetLoggerError> {
    let mut logger_set = LOGGER_SET.write().expect("Failed to acquire lock.");
    if !*logger_set {
        log::set_boxed_logger(Box::new(Logger::new(configuration)))
            .map(|()| log::set_max_level(configuration.max_log_level))?;
        *logger_set = true;
    }
    Ok(())
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    pub use log::LevelFilter;
    use serde::{Deserialize, Serialize};

    const DEFAULT_MAX_LOG_LEVEL: LevelFilter = LevelFilter::Info;
    const DEFAULT_TERMINAL_COLOR_ENABLED: bool = false;
    const DEFAULT_DATE_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S:%f";

    /// Configuration for `Logger`.
    #[derive(Clone, Deserialize, Serialize, Debug, Configurable)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    pub struct LoggerConfiguration {
        /// Maximum log level
        #[config(serde_as_str)]
        pub max_log_level: LevelFilter,
        /// Should we enable colors?
        pub terminal_color_enabled: bool,
        /// Format of date and time
        pub date_time_format: String,
    }

    impl Default for LoggerConfiguration {
        fn default() -> Self {
            Self {
                max_log_level: DEFAULT_MAX_LOG_LEVEL,
                terminal_color_enabled: DEFAULT_TERMINAL_COLOR_ENABLED,
                date_time_format: DEFAULT_DATE_TIME_FORMAT.to_owned(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use log::{debug, LevelFilter};

    use super::{config::LoggerConfiguration, init};

    #[test]
    fn init_logger() {
        init(&LoggerConfiguration {
            max_log_level: LevelFilter::Trace,
            terminal_color_enabled: true,
            date_time_format: "%Y-%m-%d %H:%M:%S:%f".to_string(),
        })
        .expect("Failed to initialize logger.");
        println!("Max level: {}", log::max_level());
        debug!("Initialized logger {}, {}", 1, 2)
    }
}
