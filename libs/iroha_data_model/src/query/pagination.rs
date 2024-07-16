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
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

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
)]
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

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
}
