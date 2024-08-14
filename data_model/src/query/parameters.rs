//! Defines parameters that can be sent along with a query.

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec::Vec};
use core::num::NonZeroU64;

use derive_more::{Constructor, Display};
use getset::Getters;
use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use nonzero_ext::nonzero;
use serde::{Deserialize, Serialize};

use crate::name::Name;

/// Default value for `fetch_size` parameter in queries.
pub const DEFAULT_FETCH_SIZE: NonZeroU64 = nonzero!(100_u64);
/// Max value for `fetch_size` parameter in queries.
pub const MAX_FETCH_SIZE: NonZeroU64 = nonzero!(10_000_u64);

pub use self::model::*;

/// Unique id of a query
pub type QueryId = String;

#[model]
mod model {
    use super::*;

    /// Forward-only (a.k.a non-scrollable) cursor
    #[derive(
        Debug, Clone, PartialEq, Eq, Getters, Encode, Decode, Serialize, Deserialize, IntoSchema,
    )]
    #[getset(get = "pub")]
    pub struct ForwardCursor {
        /// Unique ID of query. When provided in a query the query will look up if there
        /// is was already a query with a matching ID and resume returning result batches
        pub query: QueryId,
        /// Pointer to the next element in the result set
        pub cursor: NonZeroU64,
    }

    /// Structure for pagination requests
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Default,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Constructor,
    )]
    #[display(
        fmt = "{}--{}",
        "offset",
        "limit.map_or(\".inf\".to_owned(), |n| n.to_string())"
    )]
    pub struct Pagination {
        /// start of indexing
        pub offset: u64,
        /// limit of indexing
        pub limit: Option<NonZeroU64>,
    }

    /// Struct for sorting requests
    #[derive(
        Debug,
        Clone,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Constructor,
    )]
    pub struct Sorting {
        /// Sort query result using [`Name`] of the key in [`Asset`]'s metadata.
        pub sort_by_metadata_key: Option<Name>,
    }

    /// Structure for query fetch size parameter encoding/decoding
    #[derive(
        Debug,
        Default,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Constructor,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FetchSize {
        /// Inner value of a fetch size.
        ///
        /// If not specified then [`DEFAULT_FETCH_SIZE`] is used.
        pub fetch_size: Option<NonZeroU64>,
    }

    /// Parameters that can modify iterable query execution.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Default,
        Constructor,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct QueryParams {
        pub pagination: Pagination,
        pub sorting: Sorting,
        pub fetch_size: FetchSize,
    }
}

impl Sorting {
    /// Creates a sorting by [`Name`] of the key.
    pub fn by_metadata_key(key: Name) -> Self {
        Self {
            sort_by_metadata_key: Some(key),
        }
    }
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::{FetchSize, Pagination, Sorting};
}
