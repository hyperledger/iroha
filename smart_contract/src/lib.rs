//! API which simplifies writing of smartcontracts
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap};

#[cfg(not(test))]
use data_model::smart_contract::payloads;
use data_model::{
    isi::Instruction,
    prelude::*,
    query::{Query, QueryBox},
};
pub use iroha_data_model as data_model;
pub use iroha_smart_contract_derive::main;
pub use iroha_smart_contract_utils::{debug, log};
use iroha_smart_contract_utils::{
    debug::DebugExpectExt as _, decode_with_length_prefix_from_raw, encode_and_execute,
};
use parity_scale_codec::{DecodeAll, Encode};

#[no_mangle]
extern "C" fn _iroha_smart_contract_alloc(len: usize) -> *const u8 {
    if len == 0 {
        iroha_smart_contract_utils::debug::dbg_panic("Cannot allocate 0 bytes");
    }
    let layout = core::alloc::Layout::array::<u8>(len).dbg_expect("Cannot allocate layout");
    // Safety: safe because `layout` is guaranteed to have non-zero size
    unsafe { alloc::alloc::alloc_zeroed(layout) }
}

/// # Safety
/// - `offset` is a pointer to a `[u8; len]` which is allocated in the WASM memory.
/// - This function can't call destructor of the encoded object.
#[no_mangle]
unsafe extern "C" fn _iroha_smart_contract_dealloc(offset: *mut u8, len: usize) {
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

// TODO: Remove the Clone bound. It can be done by custom serialization to InstructionExpr
impl<I: Instruction + Encode + Clone> ExecuteOnHost for I {
    fn execute(&self) -> Result<(), ValidationFail> {
        #[cfg(not(test))]
        use host::execute_instruction as host_execute_instruction;
        #[cfg(test)]
        use tests::_iroha_smart_contract_execute_instruction_mock as host_execute_instruction;

        // TODO: Redundant conversion into `InstructionExpr`
        let isi_box: InstructionExpr = self.clone().into();
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
        use tests::_iroha_smart_contract_execute_query_mock as host_execute_query;

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

impl data_model::evaluate::ExpressionEvaluator for Host {
    fn evaluate<E: Evaluate>(
        &self,
        expression: &E,
    ) -> Result<E::Value, data_model::evaluate::EvaluationError> {
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

impl data_model::evaluate::Context for Context {
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
    }
}

/// Most used items
pub mod prelude {
    pub use crate::{ExecuteOnHost, QueryHost};
}

#[cfg(test)]
mod tests {
    use core::{mem::ManuallyDrop, slice};

    use iroha_smart_contract_utils::encode_with_length_prefix;
    use webassembly_test::webassembly_test;

    use super::*;

    const QUERY_RESULT: Result<Value, ValidationFail> =
        Ok(Value::Numeric(NumericValue::U32(1234_u32)));
    const ISI_RESULT: Result<(), ValidationFail> = Ok(());
    const EXPRESSION_RESULT: NumericValue = NumericValue::U32(5_u32);

    fn get_test_instruction() -> InstructionExpr {
        let new_account_id = "mad_hatter@wonderland".parse().expect("Valid");
        let register_isi = RegisterExpr::new(Account::new(new_account_id, []));

        register_isi.into()
    }

    fn get_test_query() -> QueryBox {
        let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
        FindAccountById::new(account_id).into()
    }

    fn get_test_expression() -> EvaluatesTo<NumericValue> {
        Add::new(2_u32, 3_u32).into()
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_smart_contract_execute_instruction_mock(
        ptr: *const u8,
        len: usize,
    ) -> *const u8 {
        let bytes = slice::from_raw_parts(ptr, len);
        let instruction = InstructionExpr::decode_all(&mut &*bytes);
        assert_eq!(get_test_instruction(), instruction.unwrap());

        ManuallyDrop::new(encode_with_length_prefix(&ISI_RESULT)).as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_smart_contract_execute_query_mock(
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
