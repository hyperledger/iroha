//! API which simplifies writing of smartcontracts
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};

#[cfg(not(test))]
use data_model::smart_contract::payloads;
use data_model::{
    isi::Instruction,
    prelude::*,
    query::{cursor::ForwardCursor, sorting::Sorting, Pagination, Query, QueryOutputBox},
    BatchedResponse,
};
use derive_more::Display;
pub use iroha_data_model as data_model;
pub use iroha_smart_contract_derive::main;
pub use iroha_smart_contract_utils::{debug, error, info, log, warn};
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
#[cfg(not(test))]
pub fn stub_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    const ERROR_MESSAGE: &str =
        "`getrandom()` is not implemented. To provide your custom function \
         see https://docs.rs/getrandom/latest/getrandom/macro.register_custom_getrandom.html. \
         Be aware that your function must give the same result on different peers at the same execution round,
         and keep in mind the consequences of purely implemented random function.";

    error!(ERROR_MESSAGE);
    unimplemented!("{ERROR_MESSAGE}")
}

/// Returns the annotated type of value parsed from the given expression, or fails with [`dbg_expect`](debug::DebugExpectExt::dbg_expect) message.
/// Panics if the internal parsing fails.
///
/// # Examples
///
/// FIXME `cargo test --all-features -p iroha_smart_contract --doc -- parse`
/// ```ignore
/// use iroha_smart_contract::{parse, prelude::*};
///
/// let from_literal = parse!(DomainId, "wonderland");
/// let expr = "wonderland";
/// // Although "expr" would be less informative in debug message
/// let from_expr = parse!(DomainId, expr);
/// ```
#[macro_export]
macro_rules! parse {
    (_, $e:expr) => {
        compile_error!(
            "Don't use `_` as a type in this macro, \
             otherwise panic message would be less informative"
        )
    };
    ($t:ty, $e:expr) => {
        $crate::debug::DebugExpectExt::dbg_expect(
            $e.parse::<$t>(),
            concat!(
                "Failed to parse `",
                stringify!($e),
                "` as `",
                stringify!($t),
                "`"
            ),
        )
    };
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

impl<I: Instruction + Encode> ExecuteOnHost for I {
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

#[derive(Debug, Encode)]
enum QueryRequest<'a, Q> {
    Query(QueryWithParameters<'a, Q>),
    Cursor(&'a ForwardCursor),
}

/// Generic query request containing additional parameters.
#[derive(Debug)]
pub struct QueryWithParameters<'a, Q> {
    query: &'a Q,
    sorting: Sorting,
    pagination: Pagination,
    fetch_size: FetchSize,
}

impl<Q: Query> Encode for QueryWithParameters<'_, Q> {
    fn encode(&self) -> Vec<u8> {
        let mut output = self.query.encode_as_query_box();
        self.sorting.encode_to(&mut output);
        self.pagination.encode_to(&mut output);
        self.fetch_size.encode_to(&mut output);
        output
    }
}

/// Implementing queries can be executed on the host
pub trait ExecuteQueryOnHost: Sized {
    /// Query output type.
    type Output;

    /// Apply sorting to a query
    fn sort(&self, sorting: Sorting) -> QueryWithParameters<Self>;

    /// Apply pagination to a query
    fn paginate(&self, pagination: Pagination) -> QueryWithParameters<Self>;

    /// Set fetch size for a query. Default is [`DEFAULT_FETCH_SIZE`]
    fn fetch_size(&self, fetch_size: FetchSize) -> QueryWithParameters<Self>;

    /// Execute query on the host
    ///
    /// # Errors
    ///
    /// - If query validation failed
    /// - If query execution failed
    fn execute(&self) -> Result<QueryOutputCursor<Self::Output>, ValidationFail>;
}

impl<Q> ExecuteQueryOnHost for Q
where
    Q: Query + Encode,
    Q::Output: DecodeAll,
    <Q::Output as TryFrom<QueryOutputBox>>::Error: core::fmt::Debug,
{
    type Output = Q::Output;

    fn sort(&self, sorting: Sorting) -> QueryWithParameters<Self> {
        QueryWithParameters {
            query: self,
            sorting,
            pagination: Pagination::default(),
            fetch_size: FetchSize::default(),
        }
    }

    fn paginate(&self, pagination: Pagination) -> QueryWithParameters<Self> {
        QueryWithParameters {
            query: self,
            sorting: Sorting::default(),
            pagination,
            fetch_size: FetchSize::default(),
        }
    }

    fn fetch_size(&self, fetch_size: FetchSize) -> QueryWithParameters<Self> {
        QueryWithParameters {
            query: self,
            sorting: Sorting::default(),
            pagination: Pagination::default(),
            fetch_size,
        }
    }

    fn execute(&self) -> Result<QueryOutputCursor<Self::Output>, ValidationFail> {
        QueryWithParameters {
            query: self,
            sorting: Sorting::default(),
            pagination: Pagination::default(),
            fetch_size: FetchSize::default(),
        }
        .execute()
    }
}

impl<Q> QueryWithParameters<'_, Q>
where
    Q: Query + Encode,
    Q::Output: DecodeAll,
    <Q::Output as TryFrom<QueryOutputBox>>::Error: core::fmt::Debug,
{
    /// Apply sorting to a query
    #[must_use]
    pub fn sort(mut self, sorting: Sorting) -> Self {
        self.sorting = sorting;
        self
    }

    /// Apply pagination to a query
    #[must_use]
    pub fn paginate(mut self, pagination: Pagination) -> Self {
        self.pagination = pagination;
        self
    }

    /// Set fetch size for a query. Default is [`DEFAULT_FETCH_SIZE`]
    #[must_use]
    pub fn fetch_size(mut self, fetch_size: FetchSize) -> Self {
        self.fetch_size = fetch_size;
        self
    }

    /// Execute query on the host
    ///
    /// # Errors
    ///
    /// - If query validation failed
    /// - If query execution failed
    pub fn execute(self) -> Result<QueryOutputCursor<Q::Output>, ValidationFail> {
        #[cfg(not(test))]
        use host::execute_query as host_execute_query;
        #[cfg(test)]
        use tests::_iroha_smart_contract_execute_query_mock as host_execute_query;

        // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
        //         - ownership of the returned result is transferred into `_decode_from_raw`
        let res: Result<BatchedResponse<QueryOutputBox>, ValidationFail> = unsafe {
            decode_with_length_prefix_from_raw(encode_and_execute(
                &QueryRequest::Query(self),
                host_execute_query,
            ))
        };

        let (value, cursor) = res?.into();
        let typed_value = Q::Output::try_from(value).expect("Query output has incorrect type");
        Ok(QueryOutputCursor {
            batch: typed_value,
            cursor,
        })
    }
}

/// Cursor over query results implementing [`IntoIterator`].
///
/// If you execute [`QueryBox`] when you probably want to use [`collect()`](Self::collect) method
/// instead of [`into_iter()`](Self::into_iter) to ensure that all results vere consumed.
#[derive(Debug, Encode, PartialEq, Eq)]
pub struct QueryOutputCursor<T> {
    batch: T,
    cursor: ForwardCursor,
}

impl<T> QueryOutputCursor<T> {
    /// Returns the query result
    pub fn into_inner(self) -> T {
        self.batch
    }
}

impl QueryOutputCursor<QueryOutputBox> {
    /// Same as [`into_inner()`](Self::into_inner) but collects all values of [`QueryOutputBox::Vec`]
    /// in case if there are some cached results left on the host side.
    ///
    /// # Errors
    ///
    /// May fail due to the same reasons [`QueryOutputCursorIterator`] can fail to iterate.
    pub fn collect(self) -> Result<QueryOutputBox, QueryOutputCursorError> {
        let QueryOutputBox::Vec(v) = self.batch else {
            return Ok(self.batch);
        };

        // Making sure we received all values
        let cursor = QueryOutputCursor {
            batch: v,
            cursor: self.cursor,
        };
        cursor
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map(QueryOutputBox::Vec)
    }
}

impl<U: TryFrom<QueryOutputBox>> IntoIterator for QueryOutputCursor<Vec<U>> {
    type Item = Result<U, QueryOutputCursorError>;
    type IntoIter = QueryOutputCursorIterator<U>;

    fn into_iter(self) -> Self::IntoIter {
        QueryOutputCursorIterator {
            iter: self.batch.into_iter(),
            cursor: self.cursor,
        }
    }
}

/// Iterator over query results.
///
/// # Errors
///
/// Iteration may fail due to the following reasons:
///
/// - Failed to get next batch of results from the host
/// - Failed to convert batch of results into the requested type
pub struct QueryOutputCursorIterator<T> {
    iter: <Vec<T> as IntoIterator>::IntoIter,
    cursor: ForwardCursor,
}

impl<T: TryFrom<QueryOutputBox>> QueryOutputCursorIterator<T> {
    fn next_batch(&self) -> Result<Self, QueryOutputCursorError> {
        #[cfg(not(test))]
        use host::execute_query as host_execute_query;
        #[cfg(test)]
        use tests::_iroha_smart_contract_execute_query_mock as host_execute_query;

        // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
        //         - ownership of the returned result is transferred into `_decode_from_raw`
        let res: Result<BatchedResponse<QueryOutputBox>, ValidationFail> = unsafe {
            decode_with_length_prefix_from_raw(encode_and_execute(
                &QueryRequest::<QueryBox>::Cursor(&self.cursor),
                host_execute_query,
            ))
        };
        let (value, cursor) = res?.into();
        let vec = Vec::<T>::try_from(value).expect("Host returned unexpected output type");
        Ok(Self {
            iter: vec.into_iter(),
            cursor,
        })
    }
}

impl<T: TryFrom<QueryOutputBox>> Iterator for QueryOutputCursorIterator<T> {
    type Item = Result<T, QueryOutputCursorError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.iter.next() {
            return Some(Ok(item));
        }

        let mut next_iter = match self.next_batch() {
            Ok(next_iter) => next_iter,
            Err(QueryOutputCursorError::Validation(ValidationFail::QueryFailed(
                data_model::query::error::QueryExecutionFail::UnknownCursor,
            ))) => return None,
            Err(err) => return Some(Err(err)),
        };

        core::mem::swap(self, &mut next_iter);
        self.iter.next().map(Ok)
    }
}

/// Error iterating other query results.
#[derive(Debug, Display, iroha_macro::FromVariant)]
pub enum QueryOutputCursorError {
    /// Validation error on the host side during next batch retrieval.
    Validation(ValidationFail),
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

    pub use crate::{data_model::prelude::*, ExecuteOnHost, ExecuteQueryOnHost};
}

#[cfg(test)]
mod tests {
    use core::{mem::ManuallyDrop, slice};

    use data_model::{prelude::numeric, query::asset::FindAssetQuantityById, BatchedResponseV1};
    use iroha_smart_contract_utils::encode_with_length_prefix;
    use parity_scale_codec::Decode;
    use webassembly_test::webassembly_test;

    use super::*;

    #[derive(Decode)]
    struct QueryWithParameters<Q> {
        query: Q,
        sorting: Sorting,
        pagination: Pagination,
        #[allow(dead_code)]
        fetch_size: FetchSize,
    }

    #[derive(Decode)]
    enum QueryRequest<Q> {
        Query(QueryWithParameters<Q>),
        Cursor(#[allow(dead_code)] ForwardCursor),
    }

    #[derive(Decode)]
    #[repr(transparent)]
    struct SmartContractQueryRequest(pub QueryRequest<QueryBox>);

    impl SmartContractQueryRequest {
        fn unwrap_query(self) -> (QueryBox, Sorting, Pagination) {
            match self.0 {
                QueryRequest::Query(query) => (query.query, query.sorting, query.pagination),
                QueryRequest::Cursor(_) => panic!("Expected query, got cursor"),
            }
        }
    }

    const QUERY_RESULT: Result<QueryOutputCursor<QueryOutputBox>, ValidationFail> =
        Ok(QueryOutputCursor {
            batch: QueryOutputBox::Numeric(numeric!(1234)),
            cursor: ForwardCursor::new(None, None),
        });
    const ISI_RESULT: Result<(), ValidationFail> = Ok(());

    fn get_test_instruction() -> InstructionBox {
        let new_asset_id: AssetId = "tulip##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();
        Register::asset(Asset::new(new_asset_id, 1_u32)).into()
    }

    fn get_test_query() -> QueryBox {
        let asset_id: AssetId = "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap();
        FindAssetQuantityById::new(asset_id).into()
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
        let query_request = SmartContractQueryRequest::decode_all(&mut &*bytes).unwrap();
        let query = query_request.unwrap_query().0;
        assert_eq!(query, get_test_query());

        let response: Result<BatchedResponse<QueryOutputBox>, ValidationFail> =
            Ok(BatchedResponseV1::new(
                QUERY_RESULT.unwrap().collect().unwrap(),
                ForwardCursor::new(None, None),
            )
            .into());
        ManuallyDrop::new(encode_with_length_prefix(&response)).as_ptr()
    }

    #[webassembly_test]
    fn execute_instruction() {
        get_test_instruction().execute().unwrap();
    }

    #[webassembly_test]
    fn execute_query() {
        assert_eq!(get_test_query().execute(), QUERY_RESULT);
    }
}
