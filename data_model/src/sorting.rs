//! Structures and traits related to sorting.

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString as _},
    vec::Vec,
};

use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{model, prelude::*};

const SORT_BY_KEY: &str = "sort_by_metadata_key";

model! {
    /// Enum for sorting requests
    #[derive(Debug, Clone, Default, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct Sorting {
        /// Sort query result using [`Name`] of the key in [`Asset`]'s metadata.
        pub sort_by_metadata_key: Option<Name>,
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

impl From<Sorting> for Vec<(&'static str, String)> {
    fn from(sorting: Sorting) -> Self {
        let mut vec = Vec::new();
        if let Some(key) = sorting.sort_by_metadata_key {
            vec.push((SORT_BY_KEY, key.to_string()));
        }
        vec
    }
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
}
