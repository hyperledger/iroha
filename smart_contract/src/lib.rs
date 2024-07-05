//! API which simplifies writing of smartcontracts
#![no_std]
#![allow(unsafe_code)]
#![warn(unused, missing_docs)] // TODO

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::fmt::Debug;

#[cfg(not(test))]
use data_model::smart_contract::payloads;
use data_model::{
    isi::BuiltInInstruction,
    prelude::*,
    query::{
        cursor::ForwardCursor, predicate::PredicateBox, sorting::Sorting, IterableQuery,
        Pagination, Query, QueryOutputBox,
    },
    BatchedResponse,
};
pub use iroha_data_model as data_model;
use iroha_data_model::query::{
    builder::{IterableQueryBuilder, QueryExecutor, SingleQueryError},
    predicate::HasPredicateBox,
    IterableQueryOutputBatchBox, IterableQueryWithParams, QueryRequest2, QueryResponse2,
    SingularQuery, SingularQueryBox, SingularQueryOutputBox,
};
use iroha_macro::FromVariant;
pub use iroha_smart_contract_derive::main;
pub use iroha_smart_contract_utils::{debug, error, info, log, warn};
use iroha_smart_contract_utils::{
    debug::{dbg_panic, DebugExpectExt as _},
    decode_with_length_prefix_from_raw, encode_and_execute,
};
use parity_scale_codec::{Decode, DecodeAll, Encode};

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

/// Implementing instructions can be executed on the host
pub trait ExecuteOnHost {
    /// Execute instruction on the host
    ///
    /// # Errors
    ///
    /// - If instruction validation failed
    /// - If instruction execution failed
    fn execute(&self) -> Result<(), ValidationFail>;
}

impl<I: BuiltInInstruction + Encode> ExecuteOnHost for I {
    fn execute(&self) -> Result<(), ValidationFail> {
        #[cfg(not(test))]
        use host::execute_instruction as host_execute_instruction;
        #[cfg(test)]
        use tests::_iroha_smart_contract_execute_instruction_mock as host_execute_instruction;

        let bytes = self.encode_as_instruction_box();
        // Safety: `host_execute_instruction` doesn't take ownership of it's pointer parameter
        unsafe {
            decode_with_length_prefix_from_raw(host_execute_instruction(
                bytes.as_ptr(),
                bytes.len(),
            ))
        }
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct SmartContractQueryCursor {
    cursor: ForwardCursor,
}

fn execute_query(query: QueryRequest2) -> Result<QueryResponse2, ValidationFail> {
    #[cfg(not(test))]
    use host::execute_query as host_execute_query;
    #[cfg(test)]
    use tests::_iroha_smart_contract_execute_query_mock as host_execute_query;

    // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
    //         - ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(encode_and_execute(&query, host_execute_query)) }
}

#[derive(Debug, displaydoc::Display, FromVariant)]
pub enum SmartContractSingularQueryError {
    /// Query validation error
    Validation(ValidationFail),
    /// Failed to constrain the query to a single result
    Single(SingleQueryError),
}

#[derive(Copy, Clone, Debug)]
pub struct SmartContractQueryExecutor;

impl QueryExecutor for SmartContractQueryExecutor {
    type Cursor = SmartContractQueryCursor;
    type Error = ValidationFail;
    type SingularError = SmartContractSingularQueryError;

    fn execute_singular_query(
        &self,
        query: SingularQueryBox,
    ) -> Result<SingularQueryOutputBox, Self::Error> {
        let QueryResponse2::Singular(output) = execute_query(QueryRequest2::Singular(query))?
        else {
            dbg_panic("BUG: iroha returned unexpected type in singular query");
        };

        Ok(output)
    }

    fn start_iterable_query(
        &self,
        query: IterableQueryWithParams,
    ) -> Result<(IterableQueryOutputBatchBox, Option<Self::Cursor>), Self::Error> {
        let QueryResponse2::Iterable(output) = execute_query(QueryRequest2::StartIterable(query))?
        else {
            dbg_panic("BUG: iroha returned unexpected type in iterable query");
        };

        let (batch, cursor) = output.into_parts();

        Ok((
            batch,
            cursor.map(|cursor| SmartContractQueryCursor { cursor }),
        ))
    }

    fn continue_iterable_query(
        cursor: Self::Cursor,
    ) -> Result<(IterableQueryOutputBatchBox, Option<Self::Cursor>), Self::Error> {
        let QueryResponse2::Iterable(output) =
            execute_query(QueryRequest2::ContinueIterable(cursor.cursor))?
        else {
            dbg_panic("BUG: iroha returned unexpected type in iterable query");
        };

        let (batch, cursor) = output.into_parts();

        Ok((
            batch,
            cursor.map(|cursor| SmartContractQueryCursor { cursor }),
        ))
    }
}

pub fn iter_query<Q>(
    query: Q,
) -> IterableQueryBuilder<
    'static,
    SmartContractQueryExecutor,
    Q,
    <Q::Item as HasPredicateBox>::PredicateBoxType,
>
where
    Q: IterableQuery,
    Q::Item: HasPredicateBox,
{
    IterableQueryBuilder::new(&SmartContractQueryExecutor, query)
}

pub fn query<Q>(query: Q) -> Result<Q::Output, ValidationFail>
where
    Q: SingularQuery,
    SingularQueryBox: From<Q>,
    Q::Output: TryFrom<SingularQueryOutputBox>,
    <Q::Output as TryFrom<SingularQueryOutputBox>>::Error: Debug,
{
    let query = SingularQueryBox::from(query);

    let result = SmartContractQueryExecutor.execute_singular_query(query)?;

    Ok(result
        .try_into()
        .expect("BUG: iroha returned unexpected type in singular query"))
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
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_smart_contract_payload() -> *const u8;
    }
}

/// Most used items
pub mod prelude {
    pub use iroha_smart_contract_derive::main;
    pub use iroha_smart_contract_utils::debug::DebugUnwrapExt;

    pub use crate::{data_model::prelude::*, ExecuteOnHost};
}

#[cfg(test)]
mod tests {
    use core::{mem::ManuallyDrop, slice};

    use data_model::{prelude::numeric, query::asset::FindAssetQuantityById, BatchedResponseV1};
    use iroha_smart_contract_utils::encode_with_length_prefix;
    use parity_scale_codec::Decode;
    use webassembly_test::webassembly_test;

    use super::*;

    getrandom::register_custom_getrandom!(super::stub_getrandom);

    const ISI_RESULT: Result<(), ValidationFail> = Ok(());

    fn get_test_instruction() -> InstructionBox {
        let new_asset_id: AssetId = "tulip##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();
        Register::asset(Asset::new(new_asset_id, 1_u32)).into()
    }

    // TODO
    // fn get_test_query() -> QueryBox {
    //     let asset_id: AssetId = "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();
    //     FindAssetQuantityById::new(asset_id).into()
    // }

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

    #[warn(unused)] // TODO
    #[no_mangle]
    pub unsafe extern "C" fn _iroha_smart_contract_execute_query_mock(
        ptr: *const u8,
        len: usize,
    ) -> *const u8 {
        todo!()
        // let bytes = slice::from_raw_parts(ptr, len);
        // let query_request = SmartContractQueryRequest::decode_all(&mut &*bytes).unwrap();
        // let query = query_request.unwrap_query().0;
        // assert_eq!(query, get_test_query());
        //
        // let response: Result<BatchedResponse<QueryOutputBox>, ValidationFail> =
        //     Ok(BatchedResponseV1::new(
        //         QUERY_RESULT.unwrap().collect().unwrap(),
        //         todo!(), // ForwardCursor::new(None, None),
        //     )
        //     .into());
        // ManuallyDrop::new(encode_with_length_prefix(&response)).as_ptr()
    }

    #[webassembly_test]
    fn execute_instruction() {
        get_test_instruction().execute().unwrap();
    }

    // #[webassembly_test]
    // fn execute_query() {
    //     assert_eq!(get_test_query().execute(), QUERY_RESULT);
    // }
}
