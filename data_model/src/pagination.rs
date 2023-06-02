//! Structures and traits related to pagination.

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned as _,
    collections::btree_map,
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::btree_map;

use derive_more::{Constructor, Display};
use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};
use warp::{
    http::StatusCode,
    reply::{self, Response},
    Reply,
};

pub use self::model::*;

const PAGINATION_START: &str = "start";
const PAGINATION_LIMIT: &str = "limit";

#[model]
pub mod model {
    use super::*;

    /// Structure for pagination requests
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
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
    #[display(
        fmt = "{}--{}",
        "start.unwrap_or(0)",
        "limit.map_or(\".inf\".to_owned(), |n| n.to_string())"
    )]
    pub struct Pagination {
        /// start of indexing
        pub start: Option<u32>,
        /// limit of indexing
        pub limit: Option<u32>,
    }
}

/// Error for pagination
#[derive(Debug, Display, Clone, Eq, PartialEq)]
#[display(fmt = "Failed to decode pagination. Error: {_0}")]
pub struct PaginateError(pub core::num::ParseIntError);

#[cfg(feature = "std")]
impl std::error::Error for PaginateError {}

impl Reply for PaginateError {
    fn into_response(self) -> Response {
        reply::with_status(self.to_string(), StatusCode::BAD_REQUEST).into_response()
    }
}

impl From<Pagination> for btree_map::BTreeMap<String, String> {
    fn from(pagination: Pagination) -> Self {
        let mut query_params = Self::new();
        if let Some(start) = pagination.start {
            query_params.insert(String::from(PAGINATION_START), start.to_string());
        }
        if let Some(limit) = pagination.limit {
            query_params.insert(String::from(PAGINATION_LIMIT), limit.to_string());
        }
        query_params
    }
}

impl From<Pagination> for Vec<(&'static str, usize)> {
    fn from(pagination: Pagination) -> Self {
        match (pagination.start, pagination.limit) {
            (Some(start), Some(limit)) => {
                vec![
                    (
                        PAGINATION_START,
                        start.try_into().expect("u32 should always fit in usize"),
                    ),
                    (
                        PAGINATION_LIMIT,
                        limit.try_into().expect("u32 should always fit in usize"),
                    ),
                ]
            }
            (Some(start), None) => vec![(
                PAGINATION_START,
                start.try_into().expect("u32 should always fit in usize"),
            )],
            (None, Some(limit)) => vec![(
                PAGINATION_LIMIT,
                limit.try_into().expect("u32 should always fit in usize"),
            )],
            (None, None) => Vec::new(),
        }
    }
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
}
