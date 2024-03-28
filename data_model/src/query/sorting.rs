//! Structures and traits related to sorting.

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};

use iroha_data_model_derive::model;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::{name::Name, prelude::*};

const SORT_BY_KEY: &str = "sort_by_metadata_key";

#[model]
mod model {
    use super::*;

    /// Struct for sorting requests
    #[derive(Debug, Clone, Default, PartialEq, Eq, Decode, Encode, Deserialize, Serialize)]
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

impl Sorting {
    /// Converts self to iterator of tuples to be used in queries
    ///
    /// The length of the output iterator is not constant and has either 0 or 1 value
    pub fn into_query_parameters(self) -> impl IntoIterator<Item = (&'static str, Name)> + Clone {
        self.sort_by_metadata_key
            .map(|key| (SORT_BY_KEY, key))
            .into_iter()
    }
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
}
