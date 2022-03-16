//! API which simplifies writing of smartcontracts

#![feature(alloc_error_handler)]
// Required because of `unsafe` code and `no_mangle` use
#![allow(unsafe_code)]
#![no_std]

#[cfg(all(not(test), not(target_pointer_width = "32")))]
compile_error!("Target architectures other then 32-bit are not supported");

#[cfg(all(not(test), not(all(target_arch = "wasm32", target_os = "unknown"))))]
compile_error!("Targets other then wasm32-unknown-unknown are not supported");

extern crate alloc as core_alloc;

mod alloc;
pub mod data_model;

use core::ops::RangeFrom;

use core_alloc::{boxed::Box, format};
pub use iroha_wasm_derive::iroha_wasm;
use parity_scale_codec::{Decode, Encode};

#[cfg(feature = "debug")]
mod debug;
#[cfg(feature = "debug")]
pub use debug::*;

#[no_mangle]
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &::core::panic::PanicInfo) -> ! {
    // Need to provide a tiny `panic` implementation for `#![no_std]`.
    // This translates into an `unreachable` instruction that will
    // raise a `trap` in the WebAssembly if it panics at runtime.
    unreachable!("Program should have aborted")
}

#[no_mangle]
#[cfg(not(test))]
#[alloc_error_handler]
fn oom(layout: ::core::alloc::Layout) -> ! {
    panic!("Allocation({} bytes) failed", layout.size())
}

pub trait Execute {
    type Result;
    fn execute(&self) -> Self::Result;
}

impl Execute for data_model::Instruction {
    type Result = ();

    /// Execute the given instruction on the host environment
    fn execute(&self) -> Self::Result {
        #[cfg(not(test))]
        use host::_iroha_wasm_execute_instruction as host_execute_instruction;
        #[cfg(test)]
        use tests::_iroha_wasm_execute_instruction_mock as host_execute_instruction;

        let isi_ptr: *const data_model::Instruction = &*self;
        // Safety: `host_execute_instruction` doesn't take ownership of it's pointer parameter
        unsafe { host_execute_instruction(isi_ptr as usize) };
    }
}

impl Execute for data_model::query::QueryBox {
    type Result = data_model::Value;

    /// Executes the given query on the host environment
    fn execute(&self) -> Self::Result {
        #[cfg(not(test))]
        use host::_iroha_wasm_execute_query as host_execute_query;
        #[cfg(test)]
        use tests::_iroha_wasm_execute_query_mock as host_execute_query;

        let query_ptr: *const data_model::QueryBox = &*self;
        // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
        //         - ownership of the returned result is transfered into `_decode_from_raw`
        unsafe { decode_with_length_prefix_from_raw(host_execute_query(query_ptr as usize)) }
    }
}

/// Host exports
#[cfg(not(test))]
pub(crate) mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Executes encoded query by providing offset and length
        /// into WebAssembly's linear memory where query is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the query pointer
        /// but it does transfer ownership of the result to the caller
        pub(super) fn _iroha_wasm_execute_query(query_ptr: usize) -> usize;

        /// Executes encoded instruction by providing offset and length
        /// into WebAssembly's linear memory where instruction is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the instruction pointer
        /// but it does transfer ownership of the result to the caller
        pub(super) fn _iroha_wasm_execute_instruction(isi_ptr: usize);

        /// Prints string to the standard output by providing offset and length
        /// into WebAssembly's linear memory where string is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        #[cfg(feature = "debug")]
        pub(super) fn dbg(ptr: WasmUsize, len: WasmUsize);
    }
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
unsafe fn decode_with_length_prefix_from_raw<T: Decode>(ptr: usize) -> T {
    let len_size_bytes = core::mem::size_of::<usize>();

    #[allow(clippy::expect_used)]
    let len = usize::from_le_bytes(
        core::slice::from_raw_parts(ptr as *mut _, len_size_bytes)
            .try_into()
            .expect("Prefix length size(bytes) incorrect. This is a bug."),
    );

    _decode_from_raw_in_range(ptr, len, len_size_bytes..)
}

/// Decode the object from given pointer and length
///
/// # Warning
///
/// This method takes ownership of the given pointer
///
/// # Safety
///
/// It's safe to call this function as long as it's safe to construct, from the given
/// pointer, `Box<[u8]>` containing the encoded object
pub unsafe fn _decode_from_raw<T: Decode>(ptr: usize, len: usize) -> T {
    _decode_from_raw_in_range(ptr, len, 0..)
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
// `usize` is always pointer sized
#[allow(clippy::cast_possible_truncation)]
unsafe fn _decode_from_raw_in_range<T: Decode>(
    ptr: usize,
    len: usize,
    range: RangeFrom<usize>,
) -> T {
    let bytes = Box::from_raw(core::slice::from_raw_parts_mut(ptr as *mut _, len));

    #[allow(clippy::expect_used, clippy::expect_fun_call)]
    T::decode(&mut &bytes[range]).expect(
        format!(
            "Decoding of {} failed. This is a bug",
            core::any::type_name::<T>()
        )
        .as_str(),
    )
}

/// Most used items
pub mod prelude {
    pub use crate::{iroha_wasm, Execute};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]
    #![allow(clippy::pedantic)]

    use core::mem::ManuallyDrop;

    use core_alloc::vec::Vec;
    use data_model::{
        AccountId, FindAccountById, Instruction, QueryBox, RegisterBox, Value,
    };
    use webassembly_test::webassembly_test;

    use super::*;

    const QUERY_RESULT: Value = Value::U32(1234);

    fn encode_query_result(res: Value) -> Vec<u8> {
        let len_size_bytes = core::mem::size_of::<usize>();

        let mut r = Vec::with_capacity(len_size_bytes + res.size_hint());

        // Reserve space for length
        r.resize(len_size_bytes, 0);
        res.encode_to(&mut r);

        // Store length of encoded object as byte array at the beginning of the vec
        for (i, byte) in r.len().to_le_bytes().into_iter().enumerate() {
            r[i] = byte;
        }

        r
    }

    fn get_test_instruction() -> Instruction {
        let new_account_id = "mad_hatter@wonderland".parse().expect("Valid");
        let register_isi = RegisterBox::new(Account::new(new_account_id, []));

        Instruction::Register(register_isi)
    }
    fn get_test_query() -> QueryBox {
        let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
        FindAccountById::new(account_id).into()
    }

    #[no_mangle]
    pub(super) unsafe extern "C" fn _iroha_wasm_execute_instruction_mock(isi_ptr: usize) {
        let instruction = &*(isi_ptr as *const Instruction);
        assert_eq!(get_test_instruction(), *instruction);
    }

    #[cfg(feature = "debug")]
    #[no_mangle]
    pub(super) unsafe extern "C" fn _dbg(_ptr: WasmUsize, _len: WasmUsize) {}

    #[no_mangle]
    pub(super) unsafe extern "C" fn _iroha_wasm_execute_query_mock(query_ptr: usize) -> usize {
        let query = &*(query_ptr as *const QueryBox);
        assert_eq!(*query, get_test_query());

        let bytes = ManuallyDrop::new(encode_query_result(QUERY_RESULT).into_boxed_slice());
        bytes.as_ptr() as _
    }

    #[webassembly_test]
    fn execute_instruction_test() {
        get_test_instruction().execute()
    }

    #[webassembly_test]
    fn execute_query_test() {
        assert_eq!(get_test_query().execute(), QUERY_RESULT);
    }
}
