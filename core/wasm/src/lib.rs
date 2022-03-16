//! Library exposing memory and function table to smartcontract.
//! Smartcontract must dynamically link against this library.

// Required because of `unsafe` code and `no_mangle` use
#![allow(unsafe_code)]

#[cfg(all(not(test), not(target_pointer_width = "32")))]
compile_error!("Target architectures other then 32-bit are not supported");

#[cfg(all(not(test), not(all(target_arch = "wasm32", target_os = "unknown"))))]
compile_error!("Targets other then wasm32-unknown-unknown are not supported");

extern crate alloc as core_alloc;

pub mod alloc;

/// Host exports
mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Executes encoded query by providing offset and length
        /// into `WebAssembly`'s linear memory where query is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        ///
        /// # Safety
        ///
        /// Provided pointer and length must comprise a valid slice
        pub(super) fn execute_query(ptr: *const u8, len: usize) -> *const u8;

        /// Executes encoded instruction by providing offset and length
        /// into `WebAssembly`'s linear memory where instruction is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        ///
        /// # Safety
        ///
        /// Provided pointer and length must comprise a valid slice
        pub(super) fn execute_instruction(ptr: *const u8, len: usize);

        /// Prints string to the standard output by providing offset and length
        /// into `WebAssembly`'s linear memory where string is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        ///
        /// # Safety
        ///
        /// Provided pointer and length must comprise a valid slice
        pub(super) fn dbg(ptr: *const u8, len: usize);
    }
}

/// Forwards the call to the `host`
///
/// # Safety
///
/// Provided pointer and length must comprise a valid slice
#[no_mangle]
pub unsafe extern "C" fn host__execute_query(ptr: *const u8, len: usize) -> *const u8 {
    host::execute_query(ptr, len)
}

/// Forwards the call to the `host`
///
/// # Safety
///
/// Provided pointer and length must comprise a valid slice
#[no_mangle]
pub unsafe extern "C" fn host__execute_instruction(ptr: *const u8, len: usize) {
    host::execute_instruction(ptr, len)
}

/// Forwards the call to the `host`
///
/// # Safety
///
/// Provided pointer and length must comprise a valid slice
#[no_mangle]
pub unsafe extern "C" fn host__dbg(ptr: *const u8, len: usize) {
    host::dbg(ptr, len)
}
