use core::fmt::Debug;

use super::*;

/// Print `obj` in debug representation to the stdout
pub fn dbg<T: Debug + ?Sized>(obj: &T) {
    let s = format!("{:?}", obj);
    unsafe { encode_and_execute(&s, host::dbg) }
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
