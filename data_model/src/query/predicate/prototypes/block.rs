use core::marker::PhantomData;

use super::impl_prototype;
use crate::query::predicate::{
    predicate_atoms::block::{
        BlockHeaderPredicateBox, SignedBlockPredicateBox, TransactionQueryOutputPredicateBox,
    },
    projectors::ObjectProjector,
    AstPredicate, HasPrototype,
};

#[derive(Default, Copy, Clone)]
pub struct BlockHeaderPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(BlockHeaderPrototype: BlockHeaderPredicateBox);

#[derive(Default, Copy, Clone)]
pub struct SignedBlockPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(SignedBlockPrototype: SignedBlockPredicateBox);

#[derive(Default, Copy, Clone)]
pub struct TransactionQueryOutputPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(TransactionQueryOutputPrototype: TransactionQueryOutputPredicateBox);
