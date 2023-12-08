//! API which simplifies writing of smartcontracts
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

#[cfg(not(test))]
use data_model::smart_contract::payloads;
use data_model::{
    isi::Instruction,
    prelude::*,
    query::{cursor::ForwardCursor, sorting::Sorting, Pagination, Query, QueryBox},
    smart_contract::SmartContractQueryRequest,
    BatchedResponse,
};
use derive_more::Display;
pub use iroha_data_model as data_model;
use iroha_macro::error::ErrorTryFromEnum;
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

/// Macro to parse literal as a type. Panics if failed.
///
/// # Example
///
/// ```
/// use iroha_smart_contract::{prelude::*, parse};
///
/// let account_id = parse!("alice@wonderland" as AccountId);
/// ```
#[macro_export]
macro_rules! parse {
    ($l:literal as _) => {
        compile_error!(
            "Don't use `_` as a type in this macro, \
             otherwise panic message would be less informative"
        )
    };
    ($l:literal as $t:ty) => {
        $crate::debug::DebugExpectExt::dbg_expect(
            $l.parse::<$t>(),
            concat!("Failed to parse `", $l, "` as `", stringify!($t), "`"),
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

/// Generic query request containing additional parameters.
#[derive(Debug)]
pub struct QueryRequest<Q> {
    query: Q,
    sorting: Sorting,
    pagination: Pagination,
    fetch_size: FetchSize,
}

impl<Q: Query> From<QueryRequest<Q>> for SmartContractQueryRequest {
    fn from(query_request: QueryRequest<Q>) -> Self {
        SmartContractQueryRequest::query(
            query_request.query.into(),
            query_request.sorting,
            query_request.pagination,
            query_request.fetch_size,
        )
    }
}

/// Implementing queries can be executed on the host
///
/// TODO: `&self` should be enough
pub trait ExecuteQueryOnHost: Sized {
    /// Query output type.
    type Output;

    /// Type of [`QueryRequest`].
    type QueryRequest;

    /// Apply sorting to a query
    fn sort(self, sorting: Sorting) -> Self::QueryRequest;

    /// Apply pagination to a query
    fn paginate(self, pagination: Pagination) -> Self::QueryRequest;

    /// Set fetch size for a query. Default is [`DEFAULT_FETCH_SIZE`]
    fn fetch_size(self, fetch_size: FetchSize) -> Self::QueryRequest;

    /// Execute query on the host
    ///
    /// # Errors
    ///
    /// - If query validation failed
    /// - If query execution failed
    fn execute(self) -> Result<QueryOutputCursor<Self::Output>, ValidationFail>;
}

impl<Q: Query + Encode> ExecuteQueryOnHost for Q
where
    Q::Output: DecodeAll,
    <Q::Output as TryFrom<Value>>::Error: core::fmt::Debug,
{
    type Output = Q::Output;
    type QueryRequest = QueryRequest<Self>;

    fn sort(self, sorting: Sorting) -> Self::QueryRequest {
        QueryRequest {
            query: self,
            sorting,
            pagination: Pagination::default(),
            fetch_size: FetchSize::default(),
        }
    }

    fn paginate(self, pagination: Pagination) -> Self::QueryRequest {
        QueryRequest {
            query: self,
            sorting: Sorting::default(),
            pagination,
            fetch_size: FetchSize::default(),
        }
    }

    fn fetch_size(self, fetch_size: FetchSize) -> Self::QueryRequest {
        QueryRequest {
            query: self,
            sorting: Sorting::default(),
            pagination: Pagination::default(),
            fetch_size,
        }
    }

    fn execute(self) -> Result<QueryOutputCursor<Self::Output>, ValidationFail> {
        QueryRequest {
            query: self,
            sorting: Sorting::default(),
            pagination: Pagination::default(),
            fetch_size: FetchSize::default(),
        }
        .execute()
    }
}

impl<Q: Query + Encode> ExecuteQueryOnHost for QueryRequest<Q>
where
    Q::Output: DecodeAll,
    <Q::Output as TryFrom<Value>>::Error: core::fmt::Debug,
{
    type Output = Q::Output;
    type QueryRequest = Self;

    fn sort(mut self, sorting: Sorting) -> Self {
        self.sorting = sorting;
        self
    }

    fn paginate(mut self, pagination: Pagination) -> Self {
        self.pagination = pagination;
        self
    }

    fn fetch_size(mut self, fetch_size: FetchSize) -> Self::QueryRequest {
        self.fetch_size = fetch_size;
        self
    }

    #[allow(irrefutable_let_patterns)]
    fn execute(self) -> Result<QueryOutputCursor<Self::Output>, ValidationFail> {
        #[cfg(not(test))]
        use host::execute_query as host_execute_query;
        #[cfg(test)]
        use tests::_iroha_smart_contract_execute_query_mock as host_execute_query;

        let wasm_query_request = SmartContractQueryRequest::from(self);

        // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
        //         - ownership of the returned result is transferred into `_decode_from_raw`
        let res: Result<BatchedResponse<Value>, ValidationFail> = unsafe {
            decode_with_length_prefix_from_raw(encode_and_execute(
                &wasm_query_request,
                host_execute_query,
            ))
        };

        let (value, cursor) = res?.into();
        let typed_value = Self::Output::try_from(value).expect("Query output has incorrect type");
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
    /// Get inner values of batch and cursor, consuming [`Self`].
    pub fn into_raw_parts(self) -> (T, ForwardCursor) {
        (self.batch, self.cursor)
    }
}

impl QueryOutputCursor<Value> {
    /// Same as [`into_inner()`](Self::into_inner) but collects all values of [`Value::Vec`]
    /// in case if there are some cached results left on the host side.
    ///
    /// # Errors
    ///
    /// May fail due to the same reasons [`QueryOutputCursorIterator`] can fail to iterate.
    pub fn collect(self) -> Result<Value, QueryOutputCursorError<Vec<Value>>> {
        let Value::Vec(v) = self.batch else {
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
            .map(Value::Vec)
    }
}

impl<U: TryFrom<Value>> IntoIterator for QueryOutputCursor<Vec<U>> {
    type Item = Result<U, QueryOutputCursorError<Vec<U>>>;
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
///
/// # Panics
///
/// Panics if response from host is not [`BatchedResponse::V1`].
pub struct QueryOutputCursorIterator<T> {
    iter: <Vec<T> as IntoIterator>::IntoIter,
    cursor: ForwardCursor,
}

impl<T: TryFrom<Value>> QueryOutputCursorIterator<T> {
    #[allow(irrefutable_let_patterns)]
    fn next_batch(&self) -> Result<Self, QueryOutputCursorError<Vec<T>>> {
        #[cfg(not(test))]
        use host::execute_query as host_execute_query;
        #[cfg(test)]
        use tests::_iroha_smart_contract_execute_query_mock as host_execute_query;

        let wasm_query_request = SmartContractQueryRequest::cursor(self.cursor.clone());

        // Safety: - `host_execute_query` doesn't take ownership of it's pointer parameter
        //         - ownership of the returned result is transferred into `_decode_from_raw`
        let res: Result<BatchedResponse<Value>, ValidationFail> = unsafe {
            decode_with_length_prefix_from_raw(encode_and_execute(
                &wasm_query_request,
                host_execute_query,
            ))
        };
        let (value, cursor) = res?.into();
        let vec = Vec::<T>::try_from(value)?;
        Ok(Self {
            iter: vec.into_iter(),
            cursor,
        })
    }
}

impl<T: TryFrom<Value>> Iterator for QueryOutputCursorIterator<T> {
    type Item = Result<T, QueryOutputCursorError<Vec<T>>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.iter.next() {
            return Some(Ok(item));
        }

        let mut next_iter = match self.next_batch() {
            Ok(next_iter) => next_iter,
            Err(QueryOutputCursorError::Validation(ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::UnknownCursor,
            ))) => return None,
            Err(err) => return Some(Err(err)),
        };

        core::mem::swap(self, &mut next_iter);
        self.iter.next().map(Ok)
    }
}

/// Error iterating other query results.
#[derive(Debug, Display, iroha_macro::FromVariant)]
pub enum QueryOutputCursorError<T> {
    /// Validation error on the host side during next batch retrieval.
    Validation(ValidationFail),
    /// Host returned unexpected output type.
    Conversion(ErrorTryFromEnum<Value, T>),
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
        let value_cursor = query.clone().execute()?;
        match value_cursor.collect() {
            Ok(value) => Ok(value),
            Err(QueryOutputCursorError::Validation(err)) => Err(err),
            Err(QueryOutputCursorError::Conversion(err)) => {
                panic!("Conversion error during collecting query result: {err:?}")
            }
        }
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
    pub use iroha_smart_contract_derive::main;
    pub use iroha_smart_contract_utils::debug::DebugUnwrapExt;

    pub use crate::{data_model::prelude::*, ExecuteOnHost, ExecuteQueryOnHost};
}

#[cfg(test)]
mod tests {
    use core::{mem::ManuallyDrop, slice};

    use data_model::{query::asset::FindAssetQuantityById, BatchedResponseV1};
    use iroha_smart_contract_utils::encode_with_length_prefix;
    use webassembly_test::webassembly_test;

    use super::*;

    const QUERY_RESULT: Result<QueryOutputCursor<Value>, ValidationFail> = Ok(QueryOutputCursor {
        batch: Value::Numeric(NumericValue::U32(1234_u32)),
        cursor: ForwardCursor::new(None, None),
    });
    const ISI_RESULT: Result<(), ValidationFail> = Ok(());
    const EXPRESSION_RESULT: NumericValue = NumericValue::U32(5_u32);

    fn get_test_instruction() -> InstructionExpr {
        let new_account_id = "mad_hatter@wonderland".parse().expect("Valid");
        let register_isi = RegisterExpr::new(Account::new(new_account_id, []));

        register_isi.into()
    }

    fn get_test_query() -> QueryBox {
        let asset_id: AssetId = "rose##alice@wonderland".parse().expect("Valid");
        FindAssetQuantityById::new(asset_id).into()
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
        let query_request = SmartContractQueryRequest::decode_all(&mut &*bytes).unwrap();
        let query = query_request.unwrap_query().0;
        assert_eq!(query, get_test_query());

        let response: Result<BatchedResponse<Value>, ValidationFail> = Ok(BatchedResponseV1::new(
            QUERY_RESULT.unwrap().into_raw_parts().0,
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

    #[webassembly_test]
    fn evaluate_expression() {
        assert_eq!(
            get_test_expression().evaluate(&Context::new()),
            Ok(EXPRESSION_RESULT)
        );
    }
}
