//! Structures, macros related to FFI and generation of FFI bindings.
//!
//! Conversions:
//! bool -> u8

pub use iroha_ffi_derive::*;

/// FFI compatible tuple with 2 elements
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pair<K, V>(pub K, pub V);

/// Result of execution of an FFI function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE: Enum is `repr(i32)` becasuse WebAssembly supports only
// u32/i32, u64/i64 natively. Otherwise, `repr(i8)` would suffice
#[repr(i32)]
pub enum FfiResult {
    /// Executing the wrapped method on handle returned error
    ExecutionFail = -3_i32,
    /// Raw pointer input argument to FFI function was null
    ArgIsNull = -2_i32,
    /// Given bytes don't comprise a valid UTF8 string
    Utf8Error = -1_i32,
    /// FFI function executed successfully
    Ok = 0_i32,
}
