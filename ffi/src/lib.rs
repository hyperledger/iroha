pub use iroha_ffi_derive::*;

/// Result of execution of an FFI function
#[derive(Debug, Clone, Copy)]
// TODO: What should be the repr?
#[repr(C)]
pub enum FfiResult {
    /// FFI function executed successfully
    Ok = 0,
    /// Raw pointer input argument to FFI function was null
    ArgIsNull = 1,
}
