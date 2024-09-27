// TODO
#![allow(unused, missing_docs)]

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::marker::PhantomData;

use derive_where::derive_where;

mod compound_predicate;
pub mod predicates;
pub mod type_descriptions;

pub use compound_predicate::CompoundPredicate;
use iroha_schema::IntoSchema;

pub trait EvaluatePredicate<T: ?Sized> {
    fn applies(&self, input: &T) -> bool;
}

pub trait HasPredicateAtom {
    type Predicate: EvaluatePredicate<Self>;
}
// this derive is only neede for `PredicateMarker` to have `type_name`
#[derive(IntoSchema)]
#[allow(missing_copy_implementations)]
pub struct PredicateMarker;

pub trait Projectable<Marker> {
    type AtomType;
}

impl<T: HasPredicateAtom> Projectable<PredicateMarker> for T {
    type AtomType = T::Predicate;
}

pub trait HasProjection<Marker>: Projectable<Marker> {
    type Projection;
    fn atom(atom: Self::AtomType) -> Self::Projection;
}

pub trait HasPrototype {
    type Prototype<Marker, Projector>: Default + Copy;
}

pub trait ObjectProjector<Marker> {
    type InputType: HasProjection<Marker>;
    type OutputType: HasProjection<Marker>;

    fn project(
        projection: <Self::InputType as HasProjection<Marker>>::Projection,
    ) -> <Self::OutputType as HasProjection<Marker>>::Projection;

    fn wrap_atom(
        atom: <Self::InputType as Projectable<Marker>>::AtomType,
    ) -> <Self::OutputType as HasProjection<Marker>>::Projection {
        let input_projection = <Self::InputType as HasProjection<Marker>>::atom(atom);
        Self::project(input_projection)
    }
}

pub struct BaseProjector<Marker, T>(PhantomData<(Marker, T)>);

impl<Marker, T> ObjectProjector<Marker> for BaseProjector<Marker, T>
where
    T: HasProjection<Marker>,
{
    type InputType = T;
    type OutputType = T;

    fn project(projection: T::Projection) -> T::Projection {
        projection
    }
}

pub mod prelude {
    pub use super::{
        predicates::prelude::*, type_descriptions::prelude::*, CompoundPredicate, PredicateMarker,
    };
}
