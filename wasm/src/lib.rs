//! API which simplifies writing of smartcontracts

#![feature(alloc_error_handler)]
// Required because of `unsafe` code and `no_mangle` use
#![allow(unsafe_code)]
#![no_std]

extern crate alloc;

use alloc::{boxed::Box, format, vec::Vec};

use data_model::prelude::*;
pub use iroha_data_model as data_model;
pub use iroha_wasm_derive::iroha_wasm;
use parity_scale_codec::{Decode, Encode};

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[cfg(target_pointer_width = "32")]
type WasmUsize = u32;
#[cfg(target_pointer_width = "64")]
type WasmUsize = u64;

#[no_mangle]
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &::core::panic::PanicInfo) -> ! {
    // Need to provide a tiny `panic` implementation for `#![no_std]`.
    // This translates into an `unreachable` instruction that will
    // raise a `trap` the WebAssembly execution if we panic at runtime.
    unreachable!("Program should have aborted")
}

#[no_mangle]
#[cfg(not(test))]
#[alloc_error_handler]
fn oom(layout: ::core::alloc::Layout) -> ! {
    panic!("Allocation({} bytes) failed", layout.size())
}

#[no_mangle]
// `WasmUsize` is always pointer sized
#[allow(clippy::cast_possible_truncation)]
extern "C" fn _iroha_wasm_alloc(len: WasmUsize) -> WasmUsize {
    core::mem::ManuallyDrop::new(Vec::<u8>::with_capacity(len as usize)).as_mut_ptr() as WasmUsize
}

/// Host exports
mod host {
    use super::WasmUsize;

    /// Helper struct which guarantees to be FFI safe since tuple is not
    #[repr(C)]
    #[must_use]
    #[derive(Debug, Clone, Copy)]
    pub(super) struct WasmQueryResult(pub WasmUsize, pub WasmUsize);

    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Executes encoded query by providing offset and length
        /// into WebAssembly's linear memory where query is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        #[cfg(not(test))]
        pub(super) fn execute_query(ptr: WasmUsize, len: WasmUsize) -> WasmQueryResult;

        /// Executes encoded instruction by providing offset and length
        /// into WebAssembly's linear memory where instruction is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        #[cfg(not(test))]
        pub(super) fn execute_instruction(ptr: WasmUsize, len: WasmUsize);
    }
}

/// Decode the object from given pointer and length
///
/// # Warning
///
/// This method takes ownership of the given pointer
///
/// # Safety
///
/// It's safe to call this function as long as it's safe to construct `Box<[u8]>` from the given pointer
// `WasmUsize` is always pointer sized
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn _decode_from_raw<T: Decode>(ptr: WasmUsize, len: WasmUsize) -> T {
    let bytes = Box::from_raw(core::slice::from_raw_parts_mut(ptr as *mut _, len as usize));

    #[allow(clippy::expect_used, clippy::expect_fun_call)]
    T::decode(&mut &bytes[..]).expect(
        format!(
            "Decoding of {} failed. This is a bug",
            core::any::type_name::<T>()
        )
        .as_str(),
    )
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
unsafe fn encode_and_execute<T: Encode, O>(
    obj: T,
    fun: unsafe extern "C" fn(WasmUsize, WasmUsize) -> O,
) -> O {
    // NOTE: It's imperative that encoded object is stored on the heap
    // because heap corresponds to linear memory when compiled to wasm
    let bytes = obj.encode();

    // `WasmUsize` is always pointer sized
    #[allow(clippy::cast_possible_truncation)]
    let ptr = bytes.as_ptr() as WasmUsize;
    // `WasmUsize` is always pointer sized
    #[allow(clippy::cast_possible_truncation)]
    let len = bytes.len() as WasmUsize;

    fun(ptr, len)
}

/// Executes the given query on the host environment
pub fn execute_query(query: QueryBox) -> QueryResult {
    #[cfg(not(test))]
    use host::execute_query as host_execute_query;
    #[cfg(test)]
    use tests::_iroha_wasm_execute_query_mock as host_execute_query;

    // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
    //         - ownership of the returned result is transfered into `_decode_from_raw`
    unsafe {
        let host::WasmQueryResult(res_ptr, res_len) = encode_and_execute(query, host_execute_query);
        _decode_from_raw(res_ptr, res_len)
    }
}

/// Execute the given instruction on the host environment
pub fn execute_instruction(instruction: Instruction) {
    #[cfg(not(test))]
    use host::execute_instruction as host_execute_instruction;
    #[cfg(test)]
    use tests::_iroha_wasm_execute_instruction_mock as host_execute_instruction;

    // Safety: `host_execute_instruction` doesn't take ownership of it's pointer parameter
    unsafe { encode_and_execute(instruction, host_execute_instruction) };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]
    #![allow(clippy::pedantic)]

    use core::{mem::ManuallyDrop, slice};

    use super::*;

    const QUERY_RESULT: QueryResult = QueryResult(Value::U32(1234));

    fn get_test_instruction() -> Instruction {
        let new_account_id = AccountId::test("mad_hatter", "wonderland");
        let register_isi = RegisterBox::new(NewAccount::new(new_account_id));

        Instruction::Register(register_isi)
    }
    fn get_test_query() -> QueryBox {
        let account_id = AccountId::test("alice", "wonderland");
        FindAccountById::new(account_id).into()
    }

    #[no_mangle]
    pub(super) unsafe extern "C" fn _iroha_wasm_execute_instruction_mock(
        ptr: WasmUsize,
        len: WasmUsize,
    ) {
        let bytes = slice::from_raw_parts(ptr as *const _, len as usize);
        let instruction = Instruction::decode(&mut &*bytes);
        assert_eq!(get_test_instruction(), instruction.unwrap());
    }

    #[no_mangle]
    pub(super) unsafe extern "C" fn _iroha_wasm_execute_query_mock(
        ptr: WasmUsize,
        len: WasmUsize,
    ) -> host::WasmQueryResult {
        let bytes = slice::from_raw_parts(ptr as *const _, len as usize);
        let query = QueryBox::decode(&mut &*bytes).unwrap();
        assert_eq!(query, get_test_query());

        let bytes = ManuallyDrop::new(QUERY_RESULT.encode().into_boxed_slice());
        host::WasmQueryResult(bytes.as_ptr() as WasmUsize, bytes.len() as WasmUsize)
    }

    #[test]
    fn execute_instruction_test() {
        execute_instruction(get_test_instruction())
    }

    #[test]
    fn execute_query_test() {
        assert_eq!(execute_query(get_test_query()), QUERY_RESULT);
    }
}
