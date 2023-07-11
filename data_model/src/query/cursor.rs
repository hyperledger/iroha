//! Structures and traits related to server-side cursor.

use core::num::{NonZeroU64, NonZeroUsize};

use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;

const CURSOR: &str = "cursor";

#[model]
pub mod model {
    use super::*;

    /// Forward-only (a.k.a non-scrollable) cursor
    #[derive(
        Debug,
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
    pub struct ForwardCursor {
        pub cursor: Option<NonZeroU64>,
    }
}

impl ForwardCursor {
    /// Get cursor position
    pub fn get(self) -> Option<NonZeroU64> {
        self.cursor
    }
}

impl From<ForwardCursor> for Vec<(&'static str, NonZeroU64)> {
    fn from(cursor: ForwardCursor) -> Self {
        if let Some(cursor) = cursor.cursor {
            return vec![(CURSOR, cursor)];
        }

        Vec::new()
    }
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
}
