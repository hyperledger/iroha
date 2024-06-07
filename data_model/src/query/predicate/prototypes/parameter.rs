use std::marker::PhantomData;

use super::impl_prototype;
use crate::query::{
    predicate::{predicate_atoms::parameter::ParameterPredicateBox, projectors::ObjectProjector},
    AstPredicate, HasPrototype,
};

#[derive(Default, Copy, Clone)]
pub struct ParameterPrototype<Projector> {
    phantom: PhantomData<Projector>,
}
impl_prototype!(ParameterPrototype: ParameterPredicateBox);
