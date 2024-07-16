//! Account-related prototypes, mirroring types in [`crate::peer`].

use core::marker::PhantomData;

use super::impl_prototype;
use crate::query::{
    predicate::{predicate_atoms::peer::PeerPredicateBox, projectors::ObjectProjector},
    AstPredicate, HasPrototype,
};

/// A prototype of [`crate::peer::Peer`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct PeerPrototype<Projector> {
    phantom: PhantomData<Projector>,
}
impl_prototype!(PeerPrototype: PeerPredicateBox);
