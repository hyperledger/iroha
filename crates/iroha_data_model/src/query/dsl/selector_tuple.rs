#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use derive_where::derive_where;
use iroha_macro::serde_where;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::query::{
    dsl::{HasProjection, SelectorMarker},
    QueryOutputBatchBox,
};

#[derive_where(Debug, Eq, PartialEq, Clone; T::Projection)]
#[serde_where(T::Projection)]
#[derive(Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct SelectorTuple<T: HasProjection<SelectorMarker, AtomType = ()>>(Vec<T::Projection>);

impl<T: HasProjection<SelectorMarker, AtomType = ()>> SelectorTuple<T> {
    pub fn new(selectors: Vec<T::Projection>) -> Self {
        Self(selectors)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T::Projection> {
        self.0.iter()
    }
}

impl<T: HasProjection<SelectorMarker, AtomType = ()>> Default for SelectorTuple<T> {
    fn default() -> Self {
        Self(vec![T::atom(())])
    }
}
