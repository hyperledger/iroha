//! API which simplifies writing of smartcontracts

// Required because of `unsafe` code and `no_mangle` use
#![allow(unsafe_code)]
#![no_std]

#[cfg(all(not(test), not(target_pointer_width = "32")))]
compile_error!("Target architectures other then 32-bit are not supported");

#[cfg(all(not(test), not(all(target_arch = "wasm32", target_os = "unknown"))))]
compile_error!("Targets other then wasm32-unknown-unknown are not supported");

extern crate alloc;

use alloc::{boxed::Box, format, vec::Vec};
use core::ops::RangeFrom;

use data_model::{permission::validator::NeedsPermissionBox, prelude::*};
use debug::DebugExpectExt as _;
pub use iroha_data_model as data_model;
pub use iroha_wasm_derive::entrypoint;
use parity_scale_codec::{DecodeAll, Encode};

pub mod debug;
pub mod log;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[cfg(not(test))]
#[panic_handler]
// NOTE: UNREACHABLE: `WebAssembly` always raises a `trap` on panic
fn panic(_info: &::core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn _iroha_wasm_alloc(len: usize) -> *const u8 {
    if len == 0 {
        debug::dbg_panic("Cannot allocate 0 bytes");
    }
    let layout = core::alloc::Layout::array::<u8>(len).dbg_expect("Cannot allocate layout");
    // Safety: safe because `layout` is guaranteed to have non-zero size
    unsafe { alloc::alloc::alloc_zeroed(layout) }
}

/// # Safety
/// - `offset` is a pointer to a `[u8; len]` which is allocated in the WASM memory.
/// - This function can't call destructor of the encoded object.
#[no_mangle]
unsafe extern "C" fn _iroha_wasm_dealloc(offset: *mut u8, len: usize) {
    let _box = Box::from_raw(core::slice::from_raw_parts_mut(offset, len));
}

/// Implementing types can be executed on the host
pub trait ExecuteOnHost {
    /// The resulting value
    type Result;

    /// Execute instruction or query on the host
    fn execute(&self) -> Self::Result;
}

impl ExecuteOnHost for data_model::isi::Instruction {
    type Result = ();

    /// Execute the given instruction on the host environment
    fn execute(&self) -> Self::Result {
        #[cfg(not(test))]
        use host::execute_instruction as host_execute_instruction;
        #[cfg(test)]
        use tests::_iroha_wasm_execute_instruction_mock as host_execute_instruction;

        // Safety: `host_execute_instruction` doesn't take ownership of it's pointer parameter
        unsafe { encode_and_execute(self, host_execute_instruction) };
    }
}

impl ExecuteOnHost for data_model::query::QueryBox {
    type Result = Value;

    /// Executes the given query on the host environment
    fn execute(&self) -> Self::Result {
        #[cfg(not(test))]
        use host::execute_query as host_execute_query;
        #[cfg(test)]
        use tests::_iroha_wasm_execute_query_mock as host_execute_query;

        // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
        //         - ownership of the returned result is transferred into `_decode_from_raw`
        unsafe { decode_with_length_prefix_from_raw(encode_and_execute(self, host_execute_query)) }
    }
}

/// Calculate the result of the expression on the host side without mutating the state.
pub trait EvaluateOnHost {
    /// The resulting type of the expression.
    type Value;
    /// Type of error
    type Error;

    /// Calculate the result on the host side.
    ///
    /// # Errors
    ///
    /// Depends on the implementation.
    fn evaluate(&self) -> Result<Self::Value, Self::Error>;
}

impl<V: TryFrom<Value> + DecodeAll> EvaluateOnHost for EvaluatesTo<V> {
    type Value = V;
    type Error = <V as TryFrom<Value>>::Error;

    fn evaluate(&self) -> Result<Self::Value, Self::Error> {
        #[cfg(not(test))]
        use host::evaluate_on_host as host_evaluate_on_host;
        #[cfg(test)]
        use tests::_iroha_wasm_evaluate_on_host_mock as host_evaluate_on_host;

        // Safety: - `host_evaluate_on_host` doesn't take ownership of it's pointer parameter
        //         - ownership of the returned result is transferred into `_decode_from_raw`
        let value: data_model::prelude::Value = unsafe {
            decode_with_length_prefix_from_raw(encode_and_execute(
                self.expression(),
                host_evaluate_on_host,
            ))
        };
        value.try_into()
    }
}

/// Query the authority of the smart contract, trigger or permission validator
pub fn query_authority() -> <Account as Identifiable>::Id {
    #[cfg(not(test))]
    use host::query_authority as host_query_authority;
    #[cfg(test)]
    use tests::_iroha_wasm_query_authority_mock as host_query_authority;

    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host_query_authority()) }
}

/// Query the event which have triggered trigger execution.
///
/// # Traps
///
/// Host side will generate a trap if this function was not called from a trigger.
pub fn query_triggering_event() -> Event {
    #[cfg(not(test))]
    use host::query_triggering_event as host_query_triggering_event;
    #[cfg(test)]
    use tests::_iroha_wasm_query_triggering_event_mock as host_query_triggering_event;

    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host_query_triggering_event()) }
}

/// Query an operation which needs to be validated by a permission validator.
///
/// # Traps
///
/// Host side will generate a trap if this function was not called from a permission validator.
pub fn query_operation_to_validate() -> NeedsPermissionBox {
    #[cfg(not(test))]
    use host::query_operation_to_validate as host_query_operation_to_validate;
    #[cfg(test)]
    use tests::_iroha_wasm_query_operation_to_validate_mock as host_query_operation_to_validate;

    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host_query_operation_to_validate()) }
}

#[cfg(not(test))]
mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Execute encoded query by providing offset and length
        /// into WebAssembly's linear memory where query is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        pub(super) fn execute_query(ptr: *const u8, len: usize) -> *const u8;

        /// Execute encoded instruction by providing offset and length
        /// into WebAssembly's linear memory where instruction is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        pub(super) fn execute_instruction(ptr: *const u8, len: usize);

        /// Get the authority account id
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn query_authority() -> *const u8;

        /// Get the triggering event
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn query_triggering_event() -> *const u8;

        /// Get the operation to validate
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn query_operation_to_validate() -> *const u8;

        /// Evaluate an expression on the host side without mutating the state.
        ///
        /// # Input
        ///
        /// Expects a pointer to a valid [`ExpressionBox`] and its length.
        ///
        /// # Output
        ///
        /// Returns a pointer to a valid [`Value`] encoded with its length at the beginning.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn evaluate_on_host(ptr: *const u8, len: usize) -> *const u8;
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
unsafe fn decode_with_length_prefix_from_raw<T: DecodeAll>(ptr: *const u8) -> T {
    let len_size_bytes = core::mem::size_of::<usize>();

    let len = usize::from_le_bytes(
        core::slice::from_raw_parts(ptr, len_size_bytes)
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
unsafe fn _decode_from_raw<T: DecodeAll>(ptr: *const u8, len: usize) -> T {
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
unsafe fn _decode_from_raw_in_range<T: DecodeAll>(
    ptr: *const u8,
    len: usize,
    range: RangeFrom<usize>,
) -> T {
    let bytes = Box::from_raw(core::slice::from_raw_parts_mut(ptr as *mut _, len));

    #[allow(clippy::expect_fun_call)]
    T::decode_all(&mut &bytes[range]).expect(
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
pub fn encode_with_length_prefix<T: Encode>(val: &T) -> Box<[u8]> {
    let len_size_bytes = core::mem::size_of::<usize>();

    let mut r = Vec::with_capacity(
        len_size_bytes
            .checked_add(val.size_hint())
            .dbg_expect("Overflow during length computation"),
    );

    // Reserve space for length
    r.resize(len_size_bytes, 0);
    val.encode_to(&mut r);

    // Store length of the whole vector as byte array at the beginning of the vec
    let len = r.len();
    r[..len_size_bytes].copy_from_slice(&len.to_le_bytes());

    r.into_boxed_slice()
}

/// Most used items
pub mod prelude {
    pub use crate::{debug::*, entrypoint, ExecuteOnHost};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]
    #![allow(clippy::pedantic)]

    use core::{mem::ManuallyDrop, slice};

    use webassembly_test::webassembly_test;

    use super::*;

    const QUERY_RESULT: Value = Value::Numeric(NumericValue::U32(1234_u32));
    const EXPRESSION_RESULT: NumericValue = NumericValue::U32(5_u32);

    fn get_test_instruction() -> Instruction {
        let new_account_id = "mad_hatter@wonderland".parse().expect("Valid");
        let register_isi = RegisterBox::new(Account::new(new_account_id, []));

        register_isi.into()
    }
    fn get_test_query() -> QueryBox {
        let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
        FindAccountById::new(account_id).into()
    }
    fn get_test_authority() -> <Account as Identifiable>::Id {
        "alice@wonderland".parse().expect("Valid")
    }
    fn get_test_expression() -> EvaluatesTo<NumericValue> {
        Add::new(1_u32, 2_u32).into()
    }
    fn get_test_event() -> Event {
        DataEvent::Account(AccountEvent::Deleted(
            "alice@wonderland".parse().expect("Valid"),
        ))
        .into()
    }
    fn get_test_operation() -> NeedsPermissionBox {
        let alice_id: <Account as Identifiable>::Id = "alice@wonderland".parse().expect("Valid");
        let rose_definition_id: <AssetDefinition as Identifiable>::Id =
            "rose#wonderland".parse().expect("Valid");
        let alice_rose_id = <Asset as Identifiable>::Id::new(rose_definition_id, alice_id);

        NeedsPermissionBox::Instruction(MintBox::new(1u32, alice_rose_id).into())
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_wasm_execute_instruction_mock(ptr: *const u8, len: usize) {
        let bytes = slice::from_raw_parts(ptr, len);
        let instruction = Instruction::decode_all(&mut &*bytes);
        assert_eq!(get_test_instruction(), instruction.unwrap());
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_wasm_execute_query_mock(
        ptr: *const u8,
        len: usize,
    ) -> *const u8 {
        let bytes = slice::from_raw_parts(ptr, len);
        let query = QueryBox::decode_all(&mut &*bytes).unwrap();
        assert_eq!(query, get_test_query());

        ManuallyDrop::new(encode_with_length_prefix(&QUERY_RESULT)).as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_wasm_query_authority_mock() -> *const u8 {
        ManuallyDrop::new(encode_with_length_prefix(&get_test_authority())).as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_wasm_query_triggering_event_mock() -> *const u8 {
        ManuallyDrop::new(encode_with_length_prefix(&get_test_event())).as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_wasm_query_operation_to_validate_mock() -> *const u8 {
        ManuallyDrop::new(encode_with_length_prefix(&get_test_operation())).as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_wasm_evaluate_on_host_mock(
        ptr: *const u8,
        len: usize,
    ) -> *const u8 {
        let bytes = slice::from_raw_parts(ptr, len);
        let expression = ExpressionBox::decode_all(&mut &*bytes).unwrap();
        assert_eq!(*expression, *get_test_expression().expression());

        ManuallyDrop::new(encode_with_length_prefix(&Value::from(EXPRESSION_RESULT))).as_ptr()
    }

    #[webassembly_test]
    fn execute_instruction() {
        get_test_instruction().execute()
    }

    #[webassembly_test]
    fn execute_query() {
        assert_eq!(get_test_query().execute(), QUERY_RESULT);
    }

    #[webassembly_test]
    fn evaluate_expression() {
        assert_eq!(get_test_expression().evaluate(), Ok(EXPRESSION_RESULT));
    }

    #[webassembly_test]
    fn get_authority() {
        assert_eq!(query_authority(), get_test_authority());
    }

    #[webassembly_test]
    fn get_trigger_event() {
        assert_eq!(query_triggering_event(), get_test_event());
    }

    #[webassembly_test]
    fn get_operation_to_validate() {
        assert_eq!(query_operation_to_validate(), get_test_operation());
    }
}
