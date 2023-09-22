//! API which simplifies writing of smartcontracts
#![no_std]
// Required because of `unsafe` code and `no_mangle` use
#![allow(unsafe_code)]

#[cfg(all(not(test), not(target_pointer_width = "32")))]
compile_error!("Target architectures other then 32-bit are not supported");

#[cfg(all(not(test), not(all(target_arch = "wasm32", target_os = "unknown"))))]
compile_error!("Targets other then wasm32-unknown-unknown are not supported");

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, format, vec::Vec};
use core::ops::RangeFrom;

#[cfg(not(test))]
use data_model::wasm::payloads;
use data_model::{
    isi::Instruction,
    prelude::*,
    query::{Query, QueryBox},
};
use debug::DebugExpectExt as _;
pub use iroha_data_model as data_model;
pub use iroha_wasm_derive::main;
use lol_alloc::{FreeListAllocator, LockedAllocator};
use parity_scale_codec::{DecodeAll, Encode};

pub mod debug;
pub mod log;

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

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

/// Implementing instructions can be executed on the host
pub trait ExecuteOnHost: Instruction {
    /// Execute instruction on the host
    ///
    /// # Errors
    ///
    /// - If instruction validation failed
    /// - If instruction execution failed
    fn execute(&self) -> Result<(), ValidationFail>;
}

/// Implementing queries can be executed on the host
pub trait QueryHost: Query {
    /// Execute query on the host
    ///
    /// # Errors
    ///
    /// - If query validation failed
    /// - If query execution failed
    fn execute(&self) -> Result<Self::Output, ValidationFail>;
}

// TODO: Remove the Clone bound. It can be done by custom serialization to InstructionBox
impl<I: Instruction + Into<InstructionBox> + Encode + Clone> ExecuteOnHost for I {
    fn execute(&self) -> Result<(), ValidationFail> {
        #[cfg(not(test))]
        use host::execute_instruction as host_execute_instruction;
        #[cfg(test)]
        use tests::_iroha_wasm_execute_instruction_mock as host_execute_instruction;

        // TODO: Redundant conversion into `InstructionBox`
        let isi_box: InstructionBox = self.clone().into();
        // Safety: `host_execute_instruction` doesn't take ownership of it's pointer parameter
        unsafe {
            decode_with_length_prefix_from_raw(encode_and_execute(
                &isi_box,
                host_execute_instruction,
            ))
        }
    }
}

// TODO: Remove the Clone bound. It can be done by custom serialization/deserialization to QueryBox
impl<Q: Query + Into<QueryBox> + Encode + Clone> QueryHost for Q
where
    Q::Output: DecodeAll,
    <Q::Output as TryFrom<Value>>::Error: core::fmt::Debug,
{
    fn execute(&self) -> Result<Q::Output, ValidationFail> {
        #[cfg(not(test))]
        use host::execute_query as host_execute_query;
        #[cfg(test)]
        use tests::_iroha_wasm_execute_query_mock as host_execute_query;

        // TODO: Redundant conversion into `QueryBox`
        let query_box: QueryBox = self.clone().into();
        // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
        //         - ownership of the returned result is transferred into `_decode_from_raw`
        let res: Result<Value, ValidationFail> = unsafe {
            decode_with_length_prefix_from_raw(encode_and_execute(&query_box, host_execute_query))
        };

        res.map(|value| value.try_into().expect("Query returned invalid type"))
    }
}

/// World state view of the host
#[derive(Debug, Clone, Copy)]
pub struct Host;

impl iroha_data_model::evaluate::ExpressionEvaluator for Host {
    fn evaluate<E: Evaluate>(
        &self,
        expression: &E,
    ) -> Result<E::Value, iroha_data_model::evaluate::EvaluationError> {
        expression.evaluate(&Context::new())
    }
}

/// Context of expression evaluation
#[derive(Clone, Default)]
#[repr(transparent)]
pub struct Context {
    values: BTreeMap<Name, Value>,
}

impl Context {
    /// Create new [`Self`]
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }
}

impl iroha_data_model::evaluate::Context for Context {
    fn query(&self, query: &QueryBox) -> Result<Value, ValidationFail> {
        query.execute()
    }

    fn get(&self, name: &Name) -> Option<&Value> {
        self.values.get(name)
    }

    fn update(&mut self, other: impl IntoIterator<Item = (Name, Value)>) {
        self.values.extend(other)
    }
}

/// Get payload for smart contract `main()` entrypoint.
#[cfg(not(test))]
pub fn get_smart_contract_payload() -> payloads::SmartContract {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_smart_contract_payload()) }
}

/// Get payload for trigger `main()` entrypoint.
#[cfg(not(test))]
pub fn get_trigger_payload() -> payloads::Trigger {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_trigger_payload()) }
}

/// Get payload for `validate_transaction()` entrypoint.
///
/// # Traps
///
/// Host side will generate a trap if this function was called not from a
/// validator `validate_transaction()` entrypoint.
#[cfg(not(test))]
pub fn get_validate_transaction_payload() -> payloads::ValidateTransaction {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_validate_transaction_payload()) }
}

/// Get payload for `validate_instruction()` entrypoint.
///
/// # Traps
///
/// Host side will generate a trap if this function was called not from a
/// validator `validate_instruction()` entrypoint.
#[cfg(not(test))]
pub fn get_validate_instruction_payload() -> payloads::ValidateInstruction {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_validate_instruction_payload()) }
}

/// Get payload for `validate_query()` entrypoint.
///
/// # Traps
///
/// Host side will generate a trap if this function was called not from a
/// validator `validate_query()` entrypoint.
#[cfg(not(test))]
pub fn get_validate_query_payload() -> payloads::ValidateQuery {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_validate_query_payload()) }
}

/// Get payload for `migrate()` entrypoint.
///
/// # Traps
///
/// Host side will generate a trap if this function was called not from a
/// validator `migrate()` entrypoint.
#[cfg(not(test))]
pub fn get_migrate_payload() -> payloads::Migrate {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_migrate_payload()) }
}

/// Set new [`PermissionTokenSchema`].
///
/// # Errors
///
/// - If execution on Iroha side failed
///
/// # Traps
///
/// Host side will generate a trap if this function was not called from a
/// validator's `migrate()` entrypoint.
#[cfg(not(test))]
pub fn set_permission_token_schema(schema: &data_model::permission::PermissionTokenSchema) {
    // Safety: - ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { encode_and_execute(&schema, host::set_permission_token_schema) }
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
        pub(super) fn execute_instruction(ptr: *const u8, len: usize) -> *const u8;

        /// Get payload for smart contract `main()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_smart_contract_payload() -> *const u8;

        /// Get payload for trigger `main()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_trigger_payload() -> *const u8;

        /// Get payload for `validate_transaction()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_validate_transaction_payload() -> *const u8;

        /// Get payload for `validate_instruction()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_validate_instruction_payload() -> *const u8;

        /// Get payload for `validate_query()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_validate_query_payload() -> *const u8;

        /// Get payload for `migrate()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_migrate_payload() -> *const u8;

        /// Set new [`PermissionTokenSchema`].
        pub(super) fn set_permission_token_schema(ptr: *const u8, len: usize);
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
    pub use crate::{debug::*, ExecuteOnHost, QueryHost};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]
    #![allow(clippy::pedantic)]

    use core::{mem::ManuallyDrop, slice};

    use webassembly_test::webassembly_test;

    use super::*;

    const QUERY_RESULT: Result<Value, ValidationFail> =
        Ok(Value::Numeric(NumericValue::U32(1234_u32)));
    const ISI_RESULT: Result<(), ValidationFail> = Ok(());
    const EXPRESSION_RESULT: NumericValue = NumericValue::U32(5_u32);

    fn get_test_instruction() -> InstructionBox {
        let new_account_id = "mad_hatter@wonderland".parse().expect("Valid");
        let register_isi = RegisterBox::new(Account::new(new_account_id, []));

        register_isi.into()
    }

    fn get_test_query() -> QueryBox {
        let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
        FindAccountById::new(account_id).into()
    }

    fn get_test_expression() -> EvaluatesTo<NumericValue> {
        Add::new(1_u32, 2_u32).into()
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_wasm_execute_instruction_mock(
        ptr: *const u8,
        len: usize,
    ) -> *const u8 {
        let bytes = slice::from_raw_parts(ptr, len);
        let instruction = InstructionBox::decode_all(&mut &*bytes);
        assert_eq!(get_test_instruction(), instruction.unwrap());

        ManuallyDrop::new(encode_with_length_prefix(&ISI_RESULT)).as_ptr()
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

    #[webassembly_test]
    fn execute_instruction() {
        get_test_instruction().execute().unwrap();
    }

    #[webassembly_test]
    fn execute_query() {
        assert_eq!(get_test_query().execute(), QUERY_RESULT);
    }

    #[webassembly_test]
    fn evaluate_expression() {
        assert_eq!(
            get_test_expression().evaluate(&Context::new()),
            Ok(EXPRESSION_RESULT)
        );
    }
}
