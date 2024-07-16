//! Account-related prototypes, mirroring types in [`crate::parameter`].

use core::marker::PhantomData;

use super::impl_prototype;
use crate::query::{
    predicate::{predicate_atoms::parameter::ParameterPredicateBox, projectors::ObjectProjector},
    AstPredicate, HasPrototype,
};

/// A prototype of [`crate::parameter::Parameter`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct ParameterPrototype<Projector> {
    phantom: PhantomData<Projector>,
}
impl_prototype!(ParameterPrototype: ParameterPredicateBox);
