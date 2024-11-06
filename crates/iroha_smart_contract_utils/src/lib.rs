//! Crate with utilities for implementing smart contract FFI
// do not use `no_std` when not running in wasm
// this is useful to implement `dbg` and `log` functions for host-side tests
#![cfg_attr(target_family = "wasm", no_std)]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::{boxed::Box, format, vec::Vec};
use core::ops::RangeFrom;

pub use dbg::*;
pub use getrandom;
pub use parity_scale_codec::{DecodeAll, Encode};

mod dbg;
pub mod log;

/// Registers a custom `getrandom` function that:
///
/// 1. prints `error` message to the log
/// 2. panics with the same message
#[doc(hidden)]
#[macro_export]
macro_rules! register_getrandom_err_callback {
    () => {
        /// Prints a log message with [`error!`] and panics.
        ///
        /// # Panics
        ///
        /// Always Panics with [`unimplemented!()`];
        ///
        /// # Errors
        ///
        /// No errors, always panics.
        fn stub_getrandom(_dest: &mut [u8]) -> Result<(), $crate::getrandom::Error> {
            const ERROR_MESSAGE: &str =
                "`getrandom()` is not implemented. To provide your custom function \
                 see https://docs.rs/getrandom/latest/getrandom/macro.register_custom_getrandom.html. \
                 Be aware that your function must give the same result on different peers at the same execution round,
                 and keep in mind the consequences of purely implemented random function.";

            // we don't support logging in our current wasm test runner implementation
            #[cfg(not(test))]
            $crate::error!(ERROR_MESSAGE);
            unimplemented!("{ERROR_MESSAGE}")
        }

        $crate::getrandom::register_custom_getrandom!(stub_getrandom);
    };
}

/// Decode the object from given pointer and length in the given range
///
/// # Warning
///
/// This method takes ownership of the given pointer
///
/// # Safety
///
/// It's safe to call this function as long as it's safe to construct, from the given
/// pointer, `Box<[u8]>` containing the encoded object
unsafe fn _decode_from_raw_in_range<T: DecodeAll>(
    ptr: *const u8,
    len: usize,
    range: RangeFrom<usize>,
) -> T {
    let bytes = Box::from_raw(core::slice::from_raw_parts_mut(ptr.cast_mut(), len));

    #[allow(clippy::expect_fun_call)]
    T::decode_all(&mut &bytes[range]).expect(
        format!(
            "Decoding of {} failed. This is a bug",
            core::any::type_name::<T>()
        )
        .as_str(),
    )
}

/// Decode the object from given pointer where first element is the size of the object
/// following it. This can be considered a custom encoding format.
///
/// # Warning
///
/// This method takes ownership of the given pointer
///
/// # Safety
///
/// It's safe to call this function as long as it's safe to construct, from the given
/// pointer, byte array of prefix length and `Box<[u8]>` containing the encoded object
#[doc(hidden)]
pub unsafe fn decode_with_length_prefix_from_raw<T: DecodeAll>(ptr: *const u8) -> T {
    let len_size_bytes = core::mem::size_of::<usize>();

    let len = usize::from_le_bytes(
        core::slice::from_raw_parts(ptr, len_size_bytes)
            .try_into()
            .expect("Prefix length size(bytes) incorrect. This is a bug."),
    );

    _decode_from_raw_in_range(ptr, len, len_size_bytes..)
}

/// Encode the given object and call the given function with the pointer and length of the allocation
///
/// # Warning
///
/// Ownership of the returned allocation is transfered to the caller
///
/// # Safety
///
/// The given function must not take ownership of the pointer argument
#[doc(hidden)]
pub unsafe fn encode_and_execute<T: Encode, O>(
    obj: &T,
    fun: unsafe extern "C" fn(*const u8, usize) -> O,
) -> O {
    // NOTE: It's imperative that encoded object is stored on the heap
    // because heap corresponds to linear memory when compiled to wasm
    let bytes = obj.encode();

    fun(bytes.as_ptr(), bytes.len())
}

/// Encode the given `val` as a vector of bytes with the size of the object at the beginning
//
// TODO: Write a separate crate for codec/protocol between Iroha and smartcontract
#[doc(hidden)]
pub fn encode_with_length_prefix<T: Encode>(val: &T) -> Box<[u8]> {
    let len_size_bytes = core::mem::size_of::<usize>();

    let mut r = Vec::with_capacity(
        len_size_bytes
            .checked_add(val.size_hint())
            .expect("Overflow during length computation"),
    );

    // Reserve space for length
    r.resize(len_size_bytes, 0);
    val.encode_to(&mut r);

    // Store length of the whole vector as byte array at the beginning of the vec
    let len = r.len();
    r[..len_size_bytes].copy_from_slice(&len.to_le_bytes());

    r.into_boxed_slice()
}
