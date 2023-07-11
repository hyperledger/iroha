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
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
#[cfg(feature = "std")]
use std::collections::btree_map;

use derive_more::{Constructor, Display};
use iroha_data_model_derive::model;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use warp::{
    http::StatusCode,
    reply::{self, Response},
    Reply,
};

const PAGINATION_START: &str = "start";
const PAGINATION_LIMIT: &str = "limit";

/// Structure for pagination requests
#[derive(Debug, Display, Clone, Copy, Default, Decode, Encode, Deserialize, Serialize)]
#[display(
    fmt = "{}--{}",
    "start.map(NonZeroU64::get).unwrap_or(0)",
    "limit.map_or(\".inf\".to_owned(), |n| n.to_string())"
)]
pub struct Pagination {
    /// limit of indexing
    pub limit: Option<NonZeroU32>,
    /// start of indexing
    // TODO: Rename to offset
    pub start: Option<NonZeroU64>,
}

impl From<Pagination> for Vec<(&'static str, NonZeroU64)> {
    fn from(pagination: Pagination) -> Self {
        match (pagination.start, pagination.limit) {
            (Some(start), Some(limit)) => {
                vec![(PAGINATION_LIMIT, limit.into()), (PAGINATION_START, start)]
            }
            (Some(start), None) => vec![(PAGINATION_START, start)],
            (None, Some(limit)) => vec![(PAGINATION_LIMIT, limit.into())],
            (None, None) => Vec::new(),
        }
    }
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
}
