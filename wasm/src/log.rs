//! WASM logging utilities

use core::sync::atomic::{AtomicU8, Ordering};

use super::*;

// NOTE: `u8::MAX` is a sentinel value for an undefined log level
static MAX_LOG_LEVEL: MaxLogLevel = MaxLogLevel(AtomicU8::new(u8::MAX));

/// Struct which holds a valid [`Level`] stored as an integer
struct MaxLogLevel(AtomicU8);

/// Log level supported by the host
// NOTE: This struct must be exact duplicate of `config::logger::Level`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u8)]
pub enum Level {
    /// Trace
    TRACE,
    /// Debug
    DEBUG,
    /// Info (Default)
    #[default]
    INFO,
    /// Warn
    WARN,
    /// Error
    ERROR,
}

impl MaxLogLevel {
    fn get(&self) -> Level {
        let mut log_level = self.0.load(Ordering::Relaxed);

        if log_level == u8::MAX {
            log_level = query_max_log_level() as u8;
            self.0.store(log_level, Ordering::SeqCst);
        }

        // SAFETY: `MaxLogLevel` guarantees that transmute is valid
        unsafe { core::mem::transmute(log_level) }
    }
}

#[cfg(not(test))]
mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Get the max log level set on the host
        pub(super) fn query_max_log_level() -> u8;

        /// Log string with the host logging system
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        pub(super) fn log(ptr: *const u8, len: usize);
    }
}

/// Query the max log level set on the host
fn query_max_log_level() -> Level {
    #[cfg(not(test))]
    use host::query_max_log_level as host_query_max_log_level;
    #[cfg(test)]
    use tests::_query_max_log_level_mock as host_query_max_log_level;

    unsafe { core::mem::transmute((Level::ERROR as u8).min(host_query_max_log_level())) }
}

/// Log `obj` with desired log level
pub fn log<T: alloc::string::ToString + ?Sized>(log_level: Level, obj: &T) {
    #[cfg(not(test))]
    use host::log as host_log;
    #[cfg(test)]
    use tests::_log_mock as host_log;

    if log_level >= MAX_LOG_LEVEL.get() {
        let log_level_id = log_level as u8;

        let msg = obj.to_string();
        let bytes = (log_level_id, msg).encode();
        let ptr = bytes.as_ptr();
        let len = bytes.len();

        unsafe { host_log(ptr, len) }
    }
}

/// Construct a new event
#[macro_export]
macro_rules! event {
    ($log_level:path, $msg:expr) => {
        $crate::log::log($log_level, $msg)
    };
}

/// Construct an event at the trace level.
#[macro_export]
macro_rules! trace {
    ($msg:expr) => {
        $crate::event!($crate::log::Level::TRACE, $msg)
    };
}

/// Construct an event at the debug level.
#[macro_export]
macro_rules! debug {
    ($msg:expr) => {
        $crate::event!($crate::log::Level::DEBUG, $msg)
    };
}

/// Construct an event at the info level.
#[macro_export]
macro_rules! info {
    ($msg:expr) => {
        $crate::event!($crate::log::Level::INFO, $msg)
    };
}

/// Construct an event at the warn level.
#[macro_export]
macro_rules! warn {
    ($msg:expr) => {
        $crate::event!($crate::log::Level::WARN, $msg)
    };
}

/// Construct an event at the error level.
#[macro_export]
macro_rules! error {
    ($msg:expr) => {
        $crate::event!($crate::log::Level::ERROR, $msg)
    };
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use webassembly_test::webassembly_test;

    use super::*;
    use crate::_decode_from_raw;

    fn get_log_message() -> &'static str {
        "log_message"
    }

    #[no_mangle]
    pub unsafe extern "C" fn _log_mock(ptr: *const u8, len: usize) {
        let (log_level, msg) = _decode_from_raw::<(u8, String)>(ptr, len);
        assert_eq!(log_level, 3);
        assert_eq!(msg, get_log_message());
    }

    #[no_mangle]
    pub unsafe extern "C" fn _query_max_log_level_mock() -> u8 {
        Level::default() as u8
    }

    #[webassembly_test]
    fn log_call() {
        super::warn!(get_log_message());
    }
}
