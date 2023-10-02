//! This module contains data and structures related only to smart contract execution

use parity_scale_codec::{Decode, Encode};

pub use self::model::*;
use crate::query::{
    cursor::ForwardCursor, sorting::Sorting, Pagination, QueryBox, QueryRequest,
    QueryWithParameters,
};

pub mod payloads {
    //! Payloads with function arguments for different entrypoints

    use parity_scale_codec::{Decode, Encode};

    use crate::prelude::*;

    /// Payload for smart contract entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct SmartContract {
        /// Smart contract owner who submitted transaction with it
        pub owner: AccountId,
    }

    /// Payload for trigger entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct Trigger {
        /// Trigger owner who registered the trigger
        pub owner: AccountId,
        /// Event which triggered the execution
        pub event: Event,
    }

    /// Payload for migrate entrypoint
    #[derive(Debug, Clone, Copy, Encode, Decode)]
    pub struct Migrate {
        /// Height of the latest block in the blockchain
        pub block_height: u64,
    }

    /// Generic payload for `validate_*()` entrypoints of executor.
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct Validate<T> {
        /// Authority which executed the operation to be validated
        pub authority: AccountId,
        /// Height of the latest block in the blockchain
        pub block_height: u64,
        /// Operation to be validated
        pub to_validate: T,
    }
}

#[crate::model]
pub mod model {
    use super::*;

    /// Request type for `execute_query()` function.
    #[derive(Debug, derive_more::Display, Clone, Decode, Encode)]
    pub struct SmartContractQueryRequest(pub QueryRequest<QueryBox>);
}

impl SmartContractQueryRequest {
    /// Construct a new request containing query.
    pub fn query(query: QueryBox, sorting: Sorting, pagination: Pagination) -> Self {
        Self(QueryRequest::Query(QueryWithParameters::new(
            query, sorting, pagination,
        )))
    }

    /// Construct a new request containing cursor.
    pub fn cursor(cursor: ForwardCursor) -> Self {
        Self(QueryRequest::Cursor(cursor))
    }

    /// Unwrap [`Self`] if it was previously constructed with [`query()`](Self::query).
    ///
    /// # Panics
    ///
    /// Panics if [`Self`] was constructed with [`cursor()`](Self::cursor).
    pub fn unwrap_query(self) -> (QueryBox, Sorting, Pagination) {
        match self.0 {
            QueryRequest::Query(query) => (query.query, query.sorting, query.pagination),
            QueryRequest::Cursor(_) => panic!("Expected query, got cursor"),
        }
    }

    /// Unwrap [`Self`] if it was previously constructed with [`cursor()`](Self::cursor).
    ///
    /// # Panics
    ///
    /// Panics if [`Self`] was constructed with [`query()`](Self::query).
    pub fn unwrap_cursor(self) -> ForwardCursor {
        match self.0 {
            QueryRequest::Query(_) => panic!("Expected cursor, got query"),
            QueryRequest::Cursor(cursor) => cursor,
        }
    }
}
