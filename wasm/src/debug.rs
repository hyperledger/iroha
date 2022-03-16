use core::fmt::Debug;

use super::*;

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
        pub(crate) fn host__dbg(ptr: *const u8, len: usize);
    }
}

/// Print `obj` in debug representation to the stdout
pub fn dbg<T: Debug + ?Sized>(obj: &T) {
    #[cfg(not(test))]
    use host::host__dbg as host_dbg;
    #[cfg(test)]
    use tests::_dbg_mock as host_dbg;

    let s = format!("{:?}", obj);
    // Safety: `host_dbg` doesn't take ownership of it's pointer parameter
    unsafe { encode_and_execute(&s, host_dbg) }
}

/// Extension implemented for `Result` and `Option` to provide unwrapping with error message,
/// cause basic `unwrap()` does not print error due to specific panic handling in WASM Runtime
pub trait DebugUnwrapExt {
    type Output;

    /// Just like `unwrap()` but prints error message before panic
    fn dbg_unwrap(self) -> Self::Output;
}

impl<T, E: Debug> DebugUnwrapExt for Result<T, E> {
    type Output = T;

    #[allow(clippy::panic)]
    fn dbg_unwrap(self) -> Self::Output {
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

impl<T> DebugUnwrapExt for Option<T> {
    type Output = T;

    #[allow(clippy::panic)]
    fn dbg_unwrap(self) -> Self::Output {
        match self {
            Some(out) => out,
            None => {
                dbg("WASM execution panicked at 'called `Option::dbg_unwrap()` on a `None` value'");
                panic!("");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "debug")]
    #[no_mangle]
    pub(super) unsafe extern "C" fn _dbg_mock(ptr: *const u8, len: usize) {
        let _string_bytes = core::slice::from_raw_parts(ptr, len);
    }
}
