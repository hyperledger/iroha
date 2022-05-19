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
// TODO: What should be the repr?
#[repr(C)]
pub enum FfiResult {
    /// Executing the wrapped method on handle returned error
    ExecutionFail = -3,
    /// Raw pointer input argument to FFI function was null
    ArgIsNull = -2,
    /// Given bytes don't comprise a valid UTF8 string
    Utf8Error = -1,
    /// FFI function executed successfully
    Ok = 0,
}
