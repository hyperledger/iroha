//! API which simplifies writing of smartcontracts
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::fmt::Debug;

use data_model::{
    isi::BuiltInInstruction,
    prelude::*,
    query::{parameters::ForwardCursor, Query},
};
pub use iroha_data_model as data_model;
use iroha_data_model::query::{
    builder::{QueryBuilder, QueryExecutor},
    predicate::HasPredicateBox,
    QueryOutputBatchBox, QueryRequest, QueryResponse, QueryWithParams, SingularQuery,
    SingularQueryBox, SingularQueryOutputBox,
};
pub use iroha_smart_contract_derive::main;
pub use iroha_smart_contract_utils::{debug, error, info, log, warn};
use iroha_smart_contract_utils::{
    debug::{dbg_panic, DebugExpectExt as _},
    decode_with_length_prefix_from_raw, encode_and_execute,
};
use parity_scale_codec::{Decode, Encode};

/// An iterable query cursor for use in smart contracts.
#[derive(Debug, Clone, Encode, Decode)]
pub struct QueryCursor {
    cursor: ForwardCursor,
}

/// Client for the host environment
#[derive(Debug, Clone, Encode, Decode)]
#[allow(missing_copy_implementations)]
pub struct Iroha;

impl Iroha {
    /// Submits one Iroha Special Instruction
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    pub fn submit<I: BuiltInInstruction + Encode>(&self, isi: &I) -> Result<(), ValidationFail> {
        self.submit_all([isi])
    }

    /// Submits several Iroha Special Instructions
    ///
    /// # Errors
    /// Fails if sending transaction to peer fails or if it response with error
    #[expect(clippy::unused_self)]
    pub fn submit_all<'isi, I: BuiltInInstruction + Encode + 'isi>(
        &self,
        instructions: impl IntoIterator<Item = &'isi I>,
    ) -> Result<(), ValidationFail> {
        instructions.into_iter().try_for_each(|isi| {
            #[cfg(not(test))]
            use host::execute_instruction as host_execute_instruction;
            #[cfg(test)]
            use tests::_iroha_smart_contract_execute_instruction_mock as host_execute_instruction;

            let bytes = isi.encode_as_instruction_box();
            // Safety: `host_execute_instruction` doesn't take ownership of it's pointer parameter
            unsafe {
                decode_with_length_prefix_from_raw::<Result<_, ValidationFail>>(
                    host_execute_instruction(bytes.as_ptr(), bytes.len()),
                )
            }
        })?;

        Ok(())
    }

    /// Build an iterable query for execution in a smart contract.
    pub fn query<Q>(
        &self,
        query: Q,
    ) -> QueryBuilder<Self, Q, <<Q as Query>::Item as HasPredicateBox>::PredicateBoxType>
    where
        Q: Query,
    {
        QueryBuilder::new(self, query)
    }

    /// Run a singular query in a smart contract.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub fn query_single<Q>(&self, query: Q) -> Result<Q::Output, ValidationFail>
    where
        Q: SingularQuery,
        SingularQueryBox: From<Q>,
        Q::Output: TryFrom<SingularQueryOutputBox>,
        <Q::Output as TryFrom<SingularQueryOutputBox>>::Error: Debug,
    {
        let query = SingularQueryBox::from(query);

        let result = self.execute_singular_query(query)?;

        Ok(result
            .try_into()
            .expect("BUG: iroha returned unexpected type in singular query"))
    }

    fn execute_query(query: &QueryRequest) -> Result<QueryResponse, ValidationFail> {
        #[cfg(not(test))]
        use host::execute_query as host_execute_query;
        #[cfg(test)]
        use tests::_iroha_smart_contract_execute_query_mock as host_execute_query;

        // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
        //         - ownership of the returned result is transferred into `_decode_from_raw`
        unsafe {
            decode_with_length_prefix_from_raw(encode_and_execute(&query, host_execute_query))
        }
    }
}

impl QueryExecutor for Iroha {
    type Cursor = QueryCursor;
    type Error = ValidationFail;

    fn execute_singular_query(
        &self,
        query: SingularQueryBox,
    ) -> Result<SingularQueryOutputBox, Self::Error> {
        let QueryResponse::Singular(output) = Self::execute_query(&QueryRequest::Singular(query))?
        else {
            dbg_panic("BUG: iroha returned unexpected type in singular query");
        };

        Ok(output)
    }

    fn start_query(
        &self,
        query: QueryWithParams,
    ) -> Result<(QueryOutputBatchBox, u64, Option<Self::Cursor>), Self::Error> {
        let QueryResponse::Iterable(output) = Self::execute_query(&QueryRequest::Start(query))?
        else {
            dbg_panic("BUG: iroha returned unexpected type in iterable query");
        };

        let (batch, remaining_items, cursor) = output.into_parts();

        Ok((
            batch,
            remaining_items,
            cursor.map(|cursor| QueryCursor { cursor }),
        ))
    }

    fn continue_query(
        cursor: Self::Cursor,
    ) -> Result<(QueryOutputBatchBox, u64, Option<Self::Cursor>), Self::Error> {
        let QueryResponse::Iterable(output) =
            Self::execute_query(&QueryRequest::Continue(cursor.cursor))?
        else {
            dbg_panic("BUG: iroha returned unexpected type in iterable query");
        };

        let (batch, remaining_items, cursor) = output.into_parts();

        Ok((
            batch,
            remaining_items,
            cursor.map(|cursor| QueryCursor { cursor }),
        ))
    }
}

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

/// Stub for [`getrandom::getrandom()`] for Iroha smart contracts.
/// Prints a log message with [`error!`] and panics.
///
/// Required in order to crates like `iroha_crypto` to compile. Should never be called.
///
/// # Panics
///
/// Always Panics with [`unimplemented!()`];
///
/// # Errors
///
/// No errors, always panics.
///
/// # Example
///
/// ```
/// // Cargo.toml
/// // getrandom = { version = "0.2", features = ["custom"] }
///
/// getrandom::register_custom_getrandom!(iroha_smart_contract::stub_getrandom);
/// ```
pub fn stub_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    const ERROR_MESSAGE: &str =
        "`getrandom()` is not implemented. To provide your custom function \
         see https://docs.rs/getrandom/latest/getrandom/macro.register_custom_getrandom.html. \
         Be aware that your function must give the same result on different peers at the same execution round,
         and keep in mind the consequences of purely implemented random function.";

    // we don't support logging in our current wasm test runner implementation
    #[cfg(not(test))]
    error!(ERROR_MESSAGE);
    unimplemented!("{ERROR_MESSAGE}")
}

/// Get context for smart contract `main()` entrypoint.
#[cfg(not(test))]
pub fn get_smart_contract_context() -> data_model::smart_contract::payloads::SmartContractContext {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_smart_contract_context()) }
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

        /// Get context for smart contract `main()` entrypoint.
        /// # Warning
        ///
        /// This function transfers ownership of the result to the caller
        pub(super) fn get_smart_contract_context() -> *const u8;
    }
}

/// Most used items
pub mod prelude {
    pub use iroha_smart_contract_derive::main;
    pub use iroha_smart_contract_utils::debug::DebugUnwrapExt;

    pub use crate::{
        data_model::{prelude::*, smart_contract::payloads::SmartContractContext as Context},
        Iroha,
    };
}

#[cfg(test)]
mod tests {
    use core::{mem::ManuallyDrop, slice};

    use iroha_smart_contract_utils::encode_with_length_prefix;
    use parity_scale_codec::DecodeAll;
    use webassembly_test::webassembly_test;

    use super::*;

    getrandom::register_custom_getrandom!(super::stub_getrandom);

    const QUERY_RESULT: Result<Numeric, ValidationFail> = Ok(numeric!(1234));
    const ISI_RESULT: Result<(), ValidationFail> = Ok(());

    fn get_test_instruction() -> InstructionBox {
        let new_asset_id: AssetId = "tulip##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();
        Register::asset(Asset::new(new_asset_id, 1_u32)).into()
    }

    fn get_test_query() -> FindAssetQuantityById {
        let asset_id: AssetId = "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();
        FindAssetQuantityById::new(asset_id)
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_smart_contract_execute_instruction_mock(
        ptr: *const u8,
        len: usize,
    ) -> *const u8 {
        let bytes = slice::from_raw_parts(ptr, len);
        let instruction = InstructionBox::decode_all(&mut &*bytes);
        assert_eq!(get_test_instruction(), instruction.unwrap());

        ManuallyDrop::new(encode_with_length_prefix(&ISI_RESULT)).as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn _iroha_smart_contract_execute_query_mock(
        ptr: *const u8,
        len: usize,
    ) -> *const u8 {
        let bytes = slice::from_raw_parts(ptr, len);
        let query_request = QueryRequest::decode_all(&mut &*bytes).unwrap();
        let QueryRequest::Singular(query) = query_request else {
            panic!("Expected a singular query")
        };
        let query: FindAssetQuantityById = query.try_into().expect("Unexpected query type");
        assert_eq!(query, get_test_query());

        let response: Result<QueryResponse, ValidationFail> =
            Ok(QueryResponse::Singular(QUERY_RESULT.unwrap().into()));
        ManuallyDrop::new(encode_with_length_prefix(&response)).as_ptr()
    }

    #[webassembly_test]
    fn execute_instruction() {
        let host = Iroha;
        host.submit(&get_test_instruction()).unwrap();
    }

    #[webassembly_test]
    fn execute_query() {
        let host = Iroha;
        assert_eq!(host.query_single(get_test_query()), QUERY_RESULT);
    }
}
