use chrono::prelude::*;
use log::{Level, Log, Metadata, Record, SetLoggerError};
use std::sync::RwLock;

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
    fn color(&self, level: &Level) -> u8 {
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
                println!("\x1b[{}m{}\x1b[0m", self.color(&record.level()), log_entry);
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
    use iroha_error::{Result, WrapErr};
    pub use log::LevelFilter;
    use serde::Deserialize;
    use std::env;

    const MAX_LOG_LEVEL: &str = "MAX_LOG_LEVEL";
    const DEFAULT_MAX_LOG_LEVEL: LevelFilter = LevelFilter::Info;
    const TERMINAL_COLOR_ENABLED: &str = "TERMINAL_COLOR_ENABLED";
    const DEFAULT_TERMINAL_COLOR_ENABLED: bool = false;
    const DATE_TIME_FORMAT: &str = "DATE_TIME_FORMAT";
    const DEFAULT_DATE_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S:%f";

    /// Configuration for `Logger`.
    #[derive(Clone, Deserialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct LoggerConfiguration {
        #[serde(default = "default_max_log_level")]
        pub max_log_level: LevelFilter,
        #[serde(default = "default_terminal_color_enabled")]
        pub terminal_color_enabled: bool,
        #[serde(default = "default_date_time_format")]
        pub date_time_format: String,
    }

    impl LoggerConfiguration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        pub fn load_environment(&mut self) -> Result<()> {
            if let Ok(max_log_level) = env::var(MAX_LOG_LEVEL) {
                self.max_log_level = serde_json::from_str(&max_log_level)
                    .wrap_err("Failed to parse maximum log level")?;
            }
            if let Ok(terminal_color_enabled) = env::var(TERMINAL_COLOR_ENABLED) {
                self.terminal_color_enabled = serde_json::from_str(&terminal_color_enabled)
                    .wrap_err("Failed to parse terminal color enabled")?;
            }
            if let Ok(date_time_format) = env::var(DATE_TIME_FORMAT) {
                self.date_time_format = date_time_format;
            }
            Ok(())
        }
    }

    fn default_terminal_color_enabled() -> bool {
        DEFAULT_TERMINAL_COLOR_ENABLED
    }

    fn default_max_log_level() -> LevelFilter {
        DEFAULT_MAX_LOG_LEVEL
    }

    fn default_date_time_format() -> String {
        DEFAULT_DATE_TIME_FORMAT.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{config::LoggerConfiguration, init};
    use log::{debug, LevelFilter};

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
