//! WASM logging utilities

use cfg_if::cfg_if;
pub use iroha_data_model::Level;

use super::*;

#[cfg(target_family = "wasm")]
#[cfg(not(test))]
mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Log string with the host logging system
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        pub(super) fn log(ptr: *const u8, len: usize);
    }
}

/// Log `obj` with desired log level
///
/// When running as a wasm smart contract, prints to the host logging system with the corresponding level.
/// When running outside of wasm, prints the output along with its level to stderr
#[doc(hidden)]
pub fn log<T: alloc::string::ToString + ?Sized>(log_level: Level, obj: &T) {
    cfg_if! {
        if #[cfg(not(target_family = "wasm"))] {
            // when not on wasm - just print it
            eprintln!("{}: {}", log_level, obj.to_string());
        } else {
            #[cfg(not(test))]
            use host::log as host_log;
            #[cfg(test)]
            use tests::_log_mock as host_log;

            let log_level_id = log_level as u8;

            let msg = obj.to_string();
            let bytes = (log_level_id, msg).encode();
            let ptr = bytes.as_ptr();
            let len = bytes.len();

            unsafe { host_log(ptr, len) }
        }
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

    fn get_log_message() -> &'static str {
        "log_message"
    }

    #[no_mangle]
    pub unsafe extern "C" fn _log_mock(ptr: *const u8, len: usize) {
        // can't use _decode_from_raw here, because we must NOT take the ownership
        let bytes = core::slice::from_raw_parts(ptr, len);
        let (log_level, msg) = <(u8, String)>::decode_all(&mut &*bytes).unwrap();
        assert_eq!(log_level, 3);
        assert_eq!(msg, get_log_message());
    }

    #[webassembly_test]
    fn log_call() {
        super::warn!(get_log_message());
    }
}
