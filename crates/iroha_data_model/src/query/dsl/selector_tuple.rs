#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use derive_where::derive_where;
use iroha_macro::serde_where;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::query::dsl::{
    BaseProjector, HasProjection, HasPrototype, IntoSelectorTuple, SelectorMarker,
};

/// A tuple of selectors selecting some subfields from `T`.
#[derive_where(Debug, Eq, PartialEq, Clone; T::Projection)]
#[serde_where(T::Projection)]
#[derive(Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct SelectorTuple<T: HasProjection<SelectorMarker, AtomType = ()>>(Vec<T::Projection>);

impl<T: HasProjection<SelectorMarker, AtomType = ()>> SelectorTuple<T> {
    /// Create a new selector tuple from a list of selectors.
    pub fn new(selectors: Vec<T::Projection>) -> Self {
        Self(selectors)
    }

    /// Build a selector tuple using a prototype.
    ///
    /// Note that unlike predicates, the result of this function cannot be fed into the query builder.
    pub fn build<F, O>(f: F) -> Self
    where
        T: HasPrototype,
        F: FnOnce(
            <T as HasPrototype>::Prototype<SelectorMarker, BaseProjector<SelectorMarker, T>>,
        ) -> O,
        <T as HasPrototype>::Prototype<SelectorMarker, BaseProjector<SelectorMarker, T>>: Default,
        O: IntoSelectorTuple<SelectingType = T>,
    {
        f(Default::default()).into_selector_tuple()
    }

    /// Iterate over the selectors in the tuple.
    pub fn iter(&self) -> impl Iterator<Item = &T::Projection> {
        self.0.iter()
    }
}

impl<T: HasProjection<SelectorMarker, AtomType = ()>> Default for SelectorTuple<T> {
    fn default() -> Self {
        Self(vec![T::atom(())])
    }
}
