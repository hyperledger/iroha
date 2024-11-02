//! WASM debugging utilities

#[cfg(feature = "debug")]
use alloc::format;
use core::fmt::Debug;

use cfg_if::cfg_if;

#[cfg(target_family = "wasm")]
#[cfg(not(test))]
mod host {
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

/// Print `obj` in debug representation.
///
/// When running as a wasm smart contract, prints to host's stdout.
/// Does nothing unless `debug` feature is enabled.
///
/// When running outside of wasm, always prints the output to stderr
#[doc(hidden)]
pub fn dbg<T: Debug + ?Sized>(obj: &T) {
    cfg_if! {
        if #[cfg(not(target_family = "wasm"))] {
            // when not on wasm - just print it
            eprintln!("dbg: {obj:?}");
        } else if #[cfg(feature = "debug")] {
            // when `debug` feature is enabled - call the host `dbg` function
            #[cfg(not(test))]
            use host::dbg as host_dbg;
            #[cfg(test)]
            use tests::_dbg_mock as host_dbg;

            let s = format!("{obj:?}");
            // Safety: `host_dbg` doesn't take ownership of it's pointer parameter
            unsafe { crate::encode_and_execute(&s, host_dbg); }
        }
    }
}

/// Print `obj` in debug representation. Does nothing unless `debug` feature is enabled.
///
/// When running as a wasm smart contract, prints to host's stdout.
/// When running outside of wasm, always prints the output to stderr
#[macro_export]
macro_rules! dbg {
    () => {
        #[cfg(feature = "debug")]
        $crate::debug::dbg(concat!("[{}:{}:{}]", core::file!(), core::line!(), core::column!()));
    };
    ($val:expr $(,)?) => {{
        #[cfg(feature = "debug")]
        match $val {
            tmp => {
                let location = concat!("[{}:{}:{}]", core::file!(), core::line!(), core::column!());
                let location = format!("{location} {} = {tmp:#?}", stringify!($val));
                $crate::dbg(&location);
            }
        }
    }};
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}

/// Print `obj` in debug representation. Does nothing unless `debug` feature is enabled.
///
/// When running as a wasm smart contract, prints to host's stderr.
/// When running outside of wasm, always prints the output to stderr
#[macro_export]
macro_rules! dbg_panic {
    () => {
        dbg!();
        panic();
    };
    ($val:expr $(,)?) => {{
        match $val {
            tmp => {
                dbg!(tmp);
                panic!("{tmp:?}");
            }
        }
    }};
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
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
                    let msg = format!("WASM execution panicked at `called Result::dbg_unwrap()` on an `Err` value: {err:?}");

                    dbg!(&msg);
                    panic!("{msg}");
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
                    let msg = "WASM execution panicked at 'called `Option::dbg_unwrap()` on a `None` value'";

                    dbg!(msg);
                    panic!("{msg}");
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
                    let msg = format!("WASM execution panicked at `{msg}: {err:?}`");

                    dbg!(&msg);
                    panic!("{msg}");
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
                    let msg = format!("WASM execution panicked at `{msg}`",);

                    dbg!(&msg);
                    panic!("{msg}");
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
        dbg!(get_dbg_message());
    }
}
