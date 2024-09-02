//! Account-related prototypes, mirroring types in [`crate::block`].

use core::marker::PhantomData;

use iroha_crypto::HashOf;

use super::impl_prototype;
use crate::{
    block::BlockHeader,
    query::predicate::{
        predicate_atoms::block::{
            BlockHashPredicateBox, BlockHeaderPredicateBox, SignedBlockPredicateBox,
            TransactionQueryOutputPredicateBox,
        },
        projectors::{BlockHeaderHashProjector, ObjectProjector, SignedBlockHeaderProjector},
        AstPredicate, HasPrototype,
    },
};

/// A prototype of [`HashOf<BlockHeader>`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct BlockHashPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(BlockHashPrototype: BlockHashPredicateBox);

impl<Projector> BlockHashPrototype<Projector>
where
    Projector: ObjectProjector<Input = BlockHashPredicateBox>,
{
    /// Creates a predicate that checks if the hash equals the expected value.
    pub fn eq(
        &self,
        expected: HashOf<BlockHeader>,
    ) -> Projector::ProjectedPredicate<BlockHashPredicateBox> {
        Projector::project_predicate(BlockHashPredicateBox::Equals(expected))
    }
}

/// A prototype of [`crate::block::BlockHeader`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct BlockHeaderPrototype<Projector> {
    /// Build a predicate on hash of this [`crate::block::BlockHeader`]
    pub hash: BlockHashPrototype<BlockHeaderHashProjector<Projector>>,
}

impl_prototype!(BlockHeaderPrototype: BlockHeaderPredicateBox);

/// A prototype of [`crate::block::SignedBlock`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct SignedBlockPrototype<Projector> {
    /// Build a predicate on header of this [`crate::block::SignedBlock`]
    pub header: BlockHeaderPrototype<SignedBlockHeaderProjector<Projector>>,
}

impl_prototype!(SignedBlockPrototype: SignedBlockPredicateBox);

/// A prototype of [`crate::query::TransactionQueryOutput`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct TransactionQueryOutputPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(TransactionQueryOutputPrototype: TransactionQueryOutputPredicateBox);
