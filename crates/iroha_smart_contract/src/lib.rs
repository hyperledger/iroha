//! API which simplifies writing of smartcontracts
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
#[cfg(feature = "debug")]
use alloc::format;
use core::fmt::Debug;

use data_model::{
    isi::BuiltInInstruction,
    prelude::*,
    query::{parameters::ForwardCursor, Query},
};
pub use iroha_data_model as data_model;
use iroha_data_model::query::{
    builder::{QueryBuilder, QueryExecutor},
    QueryOutputBatchBoxTuple, QueryRequest, QueryResponse, QueryWithParams, SingularQuery,
    SingularQueryBox, SingularQueryOutputBox,
};
pub use iroha_smart_contract_derive::main;
pub use iroha_smart_contract_utils::{dbg, dbg_panic, DebugExpectExt, DebugUnwrapExt};
use iroha_smart_contract_utils::{decode_with_length_prefix_from_raw, encode_and_execute};
use parity_scale_codec::{Decode, Encode};

#[doc(hidden)]
pub mod utils {
    //! Crate with utilities

    pub use iroha_smart_contract_utils::register_getrandom_err_callback;

    /// Get context for smart contract `main()` entrypoint.
    ///
    /// # Safety
    ///
    /// It's safe to call this function as long as it's safe to construct, from the given
    /// pointer, byte array of prefix length and `Box<[u8]>` containing the encoded object
    #[doc(hidden)]
    #[cfg(not(test))]
    pub unsafe fn __decode_smart_contract_context(
        context: *const u8,
    ) -> crate::data_model::smart_contract::payloads::SmartContractContext {
        iroha_smart_contract_utils::decode_with_length_prefix_from_raw(context)
    }
}

pub mod log {
    //! WASM logging utilities
    pub use iroha_smart_contract_utils::{debug, error, event, info, trace, warn};
}

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
    pub fn query<Q>(&self, query: Q) -> QueryBuilder<Self, Q, Q::Item>
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
            dbg_panic!("BUG: iroha returned unexpected type in singular query");
        };

        Ok(output)
    }

    fn start_query(
        &self,
        query: QueryWithParams,
    ) -> Result<(QueryOutputBatchBoxTuple, u64, Option<Self::Cursor>), Self::Error> {
        let QueryResponse::Iterable(output) = Self::execute_query(&QueryRequest::Start(query))?
        else {
            dbg_panic!("BUG: iroha returned unexpected type in iterable query");
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
    ) -> Result<(QueryOutputBatchBoxTuple, u64, Option<Self::Cursor>), Self::Error> {
        let QueryResponse::Iterable(output) =
            Self::execute_query(&QueryRequest::Continue(cursor.cursor))?
        else {
            dbg_panic!("BUG: iroha returned unexpected type in iterable query");
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
        dbg_panic!("Cannot allocate 0 bytes");
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
    }
}

/// Most used items
pub mod prelude {
    pub use crate::{
        data_model::{prelude::*, smart_contract::payloads::SmartContractContext as Context},
        dbg, dbg_panic, DebugExpectExt, DebugUnwrapExt, Iroha,
    };
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::{mem::ManuallyDrop, slice};

    use iroha_data_model::query::{
        parameters::QueryParams, QueryOutput, QueryOutputBatchBox, QueryWithFilter,
    };
    use iroha_smart_contract_utils::encode_with_length_prefix;
    use parity_scale_codec::DecodeAll;
    use webassembly_test::webassembly_test;

    use super::*;

    const ISI_RESULT: Result<(), ValidationFail> = Ok(());

    fn get_test_instruction() -> InstructionBox {
        let new_asset_id: AssetId = "tulip##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();
        Register::asset(Asset::new(new_asset_id, 1_u32)).into()
    }

    fn get_test_query() -> QueryWithParams {
        let asset_id: AssetId = "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();

        QueryWithParams::new(
            QueryBox::FindAssets(QueryWithFilter::new(
                FindAssets,
                CompoundPredicate::<Asset>::build(|asset| asset.id.eq(asset_id)),
                SelectorTuple::<Asset>::build(|asset| asset.value.numeric),
            )),
            QueryParams::default(),
        )
    }
    fn get_query_result() -> QueryOutputBatchBoxTuple {
        QueryOutputBatchBoxTuple::new(vec![QueryOutputBatchBox::Numeric(vec![numeric!(1234)])])
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
        let QueryRequest::Start(query_with_params) = query_request else {
            panic!("Expected Start query, but got {:?}", query_request);
        };
        assert_eq!(query_with_params, get_test_query());

        let response: Result<QueryResponse, ValidationFail> = Ok(QueryResponse::Iterable(
            QueryOutput::new(get_query_result(), 0, None),
        ));
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
        let (output, remaining_items, next_cursor) = host.start_query(get_test_query()).unwrap();
        assert_eq!(output, get_query_result());
        assert_eq!(remaining_items, 0);
        assert!(
            next_cursor.is_none(),
            "Expected no cursor, but got {:?}",
            next_cursor
        );
    }
}
