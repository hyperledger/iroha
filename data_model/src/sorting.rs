//! Structures and traits related to sorting.

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString as _},
    vec::Vec,
};

use serde::{Deserialize, Serialize};
#[cfg(feature = "warp")]
use warp::{Filter, Rejection};

use crate::prelude::*;

const SORT_BY_KEY: &str = "sort_by_metadata_key";

/// Enum for sorting requests
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sorting {
    /// Sort query result using [`Name`] of the key in [`Asset`]'s metadata.
    pub sort_by_metadata_key: Option<Name>,
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

#[cfg(feature = "warp")]
/// Filter for warp which extracts sorting
pub fn sorting() -> impl Filter<Extract = (Sorting,), Error = Rejection> + Copy {
    warp::query()
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::*;
}
