use std::marker::PhantomData;

use super::impl_prototype;
use crate::query::{
    predicate::{predicate_atoms::peer::PeerPredicateBox, projectors::ObjectProjector},
    AstPredicate, HasPrototype,
};

#[derive(Default, Copy, Clone)]
pub struct PeerPrototype<Projector> {
    phantom: PhantomData<Projector>,
}
impl_prototype!(PeerPrototype: PeerPredicateBox);
