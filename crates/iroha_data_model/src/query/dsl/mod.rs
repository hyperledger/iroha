//! This module contains the domain-specific language (DSL) for constructing queries.
//!
//! # Prototypes and Projections
//!
//! Each data type that can be returned from a query (including nested types) has corresponding prototype and projection types.
//!
//! ## Purpose
//!
//! Prototypes exist to allow constructing queries with a type-safe API.
//! They do not get encoded in the query, existing only for the DSL purposes.
//! They are zero-sized objects that mimic the actual data model types by having the same files as them.
//! They allow constructing query predicates and selectors with a type-safe API.
//!
//! Projections are used as part of the representation of predicates and selectors.
//! Projections by themselves are used to select a subfield of the data model type (possibly deeply nested).
//!
//! ## Usage of prototypes
//!
//! The end-user of iroha gets exposed to prototypes when constructing query predicates and selectors.
//!
//! For both of these, they have to provide a function that takes a prototype and returns something representing the predicates or selector they want to construct.
//!
//! For predicates, they have to return the [`CompoundPredicate`] type, which is by itself a predicate.
//!
//! To get this [`CompoundPredicate`] they have to call one of the helper methods on any of the prototypes they've got access to.
//!
//! ```rust
//! # use iroha_data_model::{domain::DomainId, account::AccountId, query::dsl::CompoundPredicate};
//! let filter_by_domain_name = CompoundPredicate::<AccountId>::build(|account_id| account_id.domain.name.eq("wonderland"));
//! ```
//! For selectors, they have to return a type implementing the [`IntoSelectorTuple`] trait.
//!
//! It can be either a standalone prototype or a tuple of prototypes.
//!
//! ```rust
//! # use iroha_data_model::{domain::DomainId, account::AccountId, query::dsl::SelectorTuple};
//! let select_domain_name = SelectorTuple::<AccountId>::build(|account_id| account_id.domain.name);
//! let select_domain_name_and_signatory =
//!     SelectorTuple::<AccountId>::build(|account_id| (account_id.domain.name, account_id.signatory));
//! ```
//!
//! ## Implementation details
//!
//! Projections types are shared between the filters and selectors by using the [`Projectable`] trait and its marker parameter.
//! For predicates the marker parameter is [`PredicateMarker`], for selectors it is [`SelectorMarker`].
//!
//! All projections have an `Atom` variant, representing the end of field traversal.
//! They also have variants for each field of the data model type, containing a projection for that field type inside.
//!
//! What is stored in the `Atom` variant is decided by the [`Projectable`] trait implementation for the type.
//!
//! # Object projectors
//!
//! To facilitate conversion of prototypes into actual predicates and selectors, there also exist object projectors implementing the [`ObjectProjector`] trait.
//!
//! They get passed as a type parameter to the prototype and describe the path over the type hierarchy that this particular prototype comes from.
//! An object projector accepts a projection or a selector of a more specific type and returns a projection or a selector of a more general type wrapped in a projection.
//!
//! For example, [`type_descriptions::AccountIdDomainProjector`] accepts a predicate or a selector on [`DomainId`](crate::domain::DomainId) and returns a predicate or a selector on [`AccountId`](crate::account::AccountId) by wrapping it with [`type_descriptions::AccountIdProjection`].
//! Notice the difference between projector and projection: projector is just zero-sized utility type, while projection is actually a predicate or a selector.
//!
//! A special kind of projector is a [`BaseProjector`]: it does not change the type of the projection, it just returns it as is.
//! It used to terminate the recursion in the projector hierarchy.
//!
//! # Compound predicates and selectors
//!
//! Normally a predicate has just a single condition on a single field.
//! [`CompoundPredicate`] allows composition of multiple predicates using logical operators.
//! This is the type that is actually sent when a query is requested.
//!
//! A selector also selects just a single field. To allow selecting multiple fields, [`SelectorTuple`] is used in queries.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::marker::PhantomData;

mod compound_predicate;
pub mod predicates;
mod selector_traits;
mod selector_tuple;
pub mod type_descriptions;

use iroha_schema::IntoSchema;

pub use self::{
    compound_predicate::CompoundPredicate,
    selector_traits::{IntoSelector, IntoSelectorTuple},
    selector_tuple::SelectorTuple,
};
use crate::query::{error::QueryExecutionFail, QueryOutputBatchBox};

/// Trait implemented on all evaluable predicates for type `T`.
pub trait EvaluatePredicate<T: ?Sized> {
    /// Evaluate the predicate on the given input.
    fn applies(&self, input: &T) -> bool;
}

/// Trait that allows to get the predicate type for a given type.
pub trait HasPredicateAtom {
    /// The type of the predicate for this type.
    type Predicate: EvaluatePredicate<Self>;
}

/// Trait implemented on all evaluable selectors for type `T`.
pub trait EvaluateSelector<T: 'static> {
    /// Select the field from each of the elements in the input and type-erase the result. Cloning version.
    #[expect(single_use_lifetimes)] // FP, this the suggested change is not allowed on stable
    fn project_clone<'a>(
        &self,
        batch: impl Iterator<Item = &'a T>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail>;
    /// Select the field from each of the elements in the input and type-erase the result.
    fn project(
        &self,
        batch: impl Iterator<Item = T>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail>;
}
// The IntoSchema derive is only needed for `PredicateMarker` to have `type_name`
// the actual value of these types is never encoded
/// A marker type to be used as parameter in the [`Projectable`] trait. This marker is used for predicates.
#[derive(IntoSchema)]
#[allow(missing_copy_implementations)]
pub struct PredicateMarker;
/// A marker type to be used as parameter in the [`Projectable`] trait. This marker is used for selectors.
#[derive(IntoSchema)]
#[allow(missing_copy_implementations)]
pub struct SelectorMarker;

/// A trait implemented on all types that want to get projection implemented on. It is used by the projection implementation to determine the atom type.
pub trait Projectable<Marker> {
    /// The type of the atom for this type. Atom gets stored in the projection when this type ends up being the destination of the type hierarchy traversal.
    type AtomType;
}

impl<T: HasPredicateAtom> Projectable<PredicateMarker> for T {
    // Predicate is the atom for predicates
    type AtomType = T::Predicate;
}

impl<T> Projectable<SelectorMarker> for T {
    // Selectors don't store anything in the atom
    type AtomType = ();
}

/// A trait allowing to get the projection for the type.
pub trait HasProjection<Marker>: Projectable<Marker> {
    /// The type of the projection for this type.
    type Projection;
    /// Construct an atom projection for this type.
    fn atom(atom: Self::AtomType) -> Self::Projection;
}

/// A trait allowing to get the prototype for the type.
pub trait HasPrototype {
    /// The prototype type for this type.
    type Prototype<Marker, Projector>;
}

/// Describes how to convert a projection on `InputType` to a projection on `OutputType` by wrapping it in a projection.
pub trait ObjectProjector<Marker> {
    /// The type of input projection.
    type InputType: HasProjection<Marker>;
    /// The type of output projection.
    type OutputType: HasProjection<Marker>;

    /// Convert the projection on [`Self::InputType`] to a projection on [`Self::OutputType`].
    fn project(
        &self,
        projection: <Self::InputType as HasProjection<Marker>>::Projection,
    ) -> <Self::OutputType as HasProjection<Marker>>::Projection;

    /// Construct a projection from an atom and convert it to a projection on [`Self::OutputType`].
    fn wrap_atom(
        &self,
        atom: <Self::InputType as Projectable<Marker>>::AtomType,
    ) -> <Self::OutputType as HasProjection<Marker>>::Projection {
        let input_projection = <Self::InputType as HasProjection<Marker>>::atom(atom);
        self.project(input_projection)
    }
}

/// An [`ObjectProjector`] that does not change the type, serving as a base case for the recursion.
#[derive_where::derive_where(Default, Copy, Clone)]
pub struct BaseProjector<Marker, T>(PhantomData<(Marker, T)>);

impl<Marker, T> ObjectProjector<Marker> for BaseProjector<Marker, T>
where
    T: HasProjection<Marker>,
{
    type InputType = T;
    type OutputType = T;

    fn project(&self, projection: T::Projection) -> T::Projection {
        projection
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        predicates::prelude::*, type_descriptions::prelude::*, CompoundPredicate, SelectorTuple,
    };
}
