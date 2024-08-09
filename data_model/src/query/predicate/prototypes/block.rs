//! Account-related prototypes, mirroring types in [`crate::block`].

use core::marker::PhantomData;

use super::impl_prototype;
use crate::query::predicate::{
    predicate_atoms::block::{
        BlockHeaderPredicateBox, SignedBlockPredicateBox, TransactionQueryOutputPredicateBox,
    },
    projectors::ObjectProjector,
    AstPredicate, HasPrototype,
};

/// A prototype of [`crate::block::BlockHeader`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct BlockHeaderPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(BlockHeaderPrototype: BlockHeaderPredicateBox);

/// A prototype of [`crate::block::SignedBlock`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct SignedBlockPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(SignedBlockPrototype: SignedBlockPredicateBox);

/// A prototype of [`crate::query::TransactionQueryOutput`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct TransactionQueryOutputPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(TransactionQueryOutputPrototype: TransactionQueryOutputPredicateBox);
