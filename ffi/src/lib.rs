//! Structures, macros related to FFI and generation of FFI bindings.

pub use iroha_ffi_derive::*;

/// FFI compatible tuple with 2 elements
#[repr(C)]
pub struct Pair<K, V>(pub K, pub V);

/// Result of execution of an FFI function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// TODO: What should be the repr?
#[repr(C)]
pub enum FfiResult {
    /// FFI function executed successfully
    Ok = 0,
    /// Raw pointer input argument to FFI function was null
    ArgIsNull = 1,
}
