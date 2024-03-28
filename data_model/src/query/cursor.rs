//! Structures and traits related to server-side cursor.

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use core::num::{NonZeroU64, NonZeroUsize};

use getset::Getters;
use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode, Input};
use serde::Serialize;

pub use self::model::*;
use super::QueryId;

const QUERY_ID: &str = "query_id";
const CURSOR: &str = "cursor";

#[model]
mod model {
    use super::*;

    /// Forward-only (a.k.a non-scrollable) cursor
    #[derive(Debug, Clone, PartialEq, Eq, Default, Getters, Encode, Serialize, IntoSchema)]
    #[getset(get = "pub")]
    pub struct ForwardCursor {
        /// Unique ID of query. When provided in a query the query will look up if there
        /// is was already a query with a matching ID and resume returning result batches
        pub query_id: Option<QueryId>,
        /// Pointer to the next element in the result set
        pub cursor: Option<NonZeroU64>,
    }

    impl ForwardCursor {
        /// Create a new cursor.
        pub const fn new(query_id: Option<QueryId>, cursor: Option<NonZeroU64>) -> Self {
            Self { query_id, cursor }
        }
    }
}

mod candidate {
    use serde::{de::Error as _, Deserialize};

    use super::*;

    #[derive(Decode, Deserialize)]
    struct ForwardCursorCandidate {
        query_id: Option<QueryId>,
        cursor: Option<NonZeroU64>,
    }

    impl<'de> Deserialize<'de> for ForwardCursor {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let candidate = ForwardCursorCandidate::deserialize(deserializer)?;

            if let Some(query_id) = candidate.query_id {
                Ok(ForwardCursor {
                    query_id: Some(query_id),
                    cursor: candidate.cursor,
                })
            } else if candidate.cursor.is_some() {
                Err(D::Error::custom("Cursor missing query id"))
            } else {
                Ok(ForwardCursor::default())
            }
        }
    }

    impl Decode for ForwardCursor {
        fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
            let candidate = ForwardCursorCandidate::decode(input)?;

            if let Some(query_id) = candidate.query_id {
                Ok(ForwardCursor {
                    query_id: Some(query_id),
                    cursor: candidate.cursor,
                })
            } else if candidate.cursor.is_some() {
                Err("Cursor missing query id".into())
            } else {
                Ok(ForwardCursor::default())
            }
        }
    }
}

impl From<ForwardCursor> for Vec<(&'static str, QueryId)> {
    fn from(cursor: ForwardCursor) -> Self {
        match (cursor.query_id, cursor.cursor) {
            (Some(query_id), Some(cursor)) => {
                vec![(QUERY_ID, query_id), (CURSOR, cursor.to_string())]
            }
            (Some(query_id), None) => vec![(QUERY_ID, query_id)],
            (None, Some(_)) => unreachable!(),
            (None, None) => Vec::new(),
        }
    }
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
}
