//! Structures and traits related to server-side cursor.

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use core::num::NonZeroU64;

use getset::Getters;
use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode, Input};
use serde::{Deserialize, Serialize};

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
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
}
