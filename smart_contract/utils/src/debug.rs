//! WASM debugging utilities

#[cfg(feature = "debug")]
use alloc::format;
use core::fmt::Debug;

#[cfg(not(test))]
mod host {
    #[cfg(feature = "debug")]
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Prints string to the standard output by providing offset and length
        /// into WebAssembly's linear memory where string is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        pub(super) fn dbg(ptr: *const u8, len: usize);
    }
}

/// Print `obj` in debug representation to the stdout.
///
/// Do nothing if `debug` feature is not specified
pub fn dbg<T: Debug + ?Sized>(_obj: &T) {
    #[cfg(feature = "debug")]
    {
        #[cfg(not(test))]
        use host::dbg as host_dbg;
        #[cfg(test)]
        use tests::_dbg_mock as host_dbg;

        #[allow(clippy::used_underscore_binding)]
        let s = format!("{_obj:?}");
        // Safety: `host_dbg` doesn't take ownership of it's pointer parameter
        unsafe { crate::encode_and_execute(&s, host_dbg) }
    }
}

/// Print `msg` and call [`panic!`].
///
/// Only call [`panic!`] if `debug` feature is not specified.
///
/// # Panics
/// Always
pub fn dbg_panic(msg: &str) -> ! {
    dbg(msg);
    panic!()
}

/// Extension implemented for `Result` and `Option` to provide unwrapping with error message,
/// cause basic `unwrap()` does not print error due to specific panic handling in WASM Runtime.
///
/// Expands to just `unwrap()` if `debug` feature is not specified
pub trait DebugUnwrapExt {
    /// Type of the value that is returned in success
    type Output;

    /// Just like `unwrap()` but prints error message before panic
    fn dbg_unwrap(self) -> Self::Output;
}

impl<T, E: Debug> DebugUnwrapExt for Result<T, E> {
    type Output = T;

    fn dbg_unwrap(self) -> Self::Output {
        #[cfg(not(feature = "debug"))]
        return self.unwrap();

        #[cfg(feature = "debug")]
        {
            match self {
                Ok(out) => out,
                Err(err) => {
                    dbg(&format!(
                    "WASM execution panicked at `called Result::dbg_unwrap()` on an `Err` value: {err:?}",
                ));
                    panic!("");
                }
            }
        }
    }
}

impl<T> DebugUnwrapExt for Option<T> {
    type Output = T;

    fn dbg_unwrap(self) -> Self::Output {
        #[cfg(not(feature = "debug"))]
        return self.unwrap();

        #[cfg(feature = "debug")]
        #[allow(clippy::single_match_else, clippy::option_if_let_else)]
        {
            match self {
                Some(out) => out,
                None => {
                    dbg("WASM execution panicked at 'called `Option::dbg_unwrap()` on a `None` value'");
                    panic!("");
                }
            }
        }
    }
}

/// Extension implemented for `Result` and `Option` to provide expecting with error message,
/// cause basic `expect()` does not print error due to specific panic handling in WASM Runtime.
///
/// Expands to just `expect()` if `debug` feature is not specified
pub trait DebugExpectExt {
    /// Type of the value that is returned in success
    type Output;

    /// Just like `expect()` but prints error message before panic
    fn dbg_expect(self, msg: &str) -> Self::Output;
}

impl<T, E: Debug> DebugExpectExt for Result<T, E> {
    type Output = T;

    #[allow(clippy::panic)]
    fn dbg_expect(self, msg: &str) -> Self::Output {
        #[cfg(not(feature = "debug"))]
        return self.expect(msg);

        #[cfg(feature = "debug")]
        {
            match self {
                Ok(out) => out,
                Err(err) => {
                    dbg(&format!("WASM execution panicked at `{msg}: {err:?}`",));
                    panic!("");
                }
            }
        }
    }
}

impl<T> DebugExpectExt for Option<T> {
    type Output = T;

    #[allow(clippy::panic, clippy::single_match_else, clippy::option_if_let_else)]
    fn dbg_expect(self, msg: &str) -> Self::Output {
        #[cfg(not(feature = "debug"))]
        return self.expect(msg);

        #[cfg(feature = "debug")]
        {
            match self {
                Some(out) => out,
                None => {
                    dbg(&format!("WASM execution panicked at `{msg}`",));
                    panic!("");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use webassembly_test::webassembly_test;

    fn get_dbg_message() -> &'static str {
        "dbg_message"
    }

    #[no_mangle]
    pub unsafe extern "C" fn _dbg_mock(ptr: *const u8, len: usize) {
        use parity_scale_codec::DecodeAll;

        // can't use _decode_from_raw here, because we must NOT take the ownership
        let bytes = core::slice::from_raw_parts(ptr, len);
        assert_eq!(String::decode_all(&mut &*bytes).unwrap(), get_dbg_message());
    }

    #[webassembly_test]
    fn dbg_call() {
        super::dbg(get_dbg_message());
    }
}
