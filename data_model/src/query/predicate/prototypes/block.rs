//! Account-related prototypes, mirroring types in [`crate::block`].

use core::marker::PhantomData;

use iroha_crypto::HashOf;

use super::impl_prototype;
use crate::{
    block::BlockHeader,
    query::predicate::{
        predicate_ast_extensions::AstPredicateExt,
        predicate_atoms::block::{
            BlockHashPredicateBox, BlockHeaderPredicateBox, CommittedTransactionPredicateBox,
            SignedBlockPredicateBox, SignedTransactionPredicateBox, TransactionErrorPredicateBox,
            TransactionHashPredicateBox, TransactionQueryOutputPredicateBox,
        },
        predicate_combinators::NotAstPredicate,
        projectors::{
            BlockHeaderHashProjector, CommittedTransactionErrorProjector,
            CommittedTransactionValueProjector, ObjectProjector, SignedBlockHeaderProjector,
            SignedTransactionAuthorityProjector, SignedTransactionHashProjector,
            TransactionQueryOutputBlockHashProjector, TransactionQueryOutputTransactionProjector,
        },
        prototypes::account::AccountIdPrototype,
        AstPredicate, HasPrototype,
    },
    transaction::SignedTransaction,
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

/// A prototype of [`BlockHeader`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct BlockHeaderPrototype<Projector> {
    /// Build a predicate on hash of this [`BlockHeader`]
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

/// A prototype of [`HashOf<SignedTransaction>`]
#[derive(Default, Copy, Clone)]
pub struct TransactionHashPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(TransactionHashPrototype: TransactionHashPredicateBox);

impl<Projector> TransactionHashPrototype<Projector>
where
    Projector: ObjectProjector<Input = TransactionHashPredicateBox>,
{
    /// Creates a predicate that checks if the hash equals the expected value.
    pub fn eq(
        &self,
        expected: HashOf<SignedTransaction>,
    ) -> Projector::ProjectedPredicate<TransactionHashPredicateBox> {
        Projector::project_predicate(TransactionHashPredicateBox::Equals(expected))
    }
}

/// A prototype of [`SignedTransaction`]
#[derive(Default, Copy, Clone)]
pub struct SignedTransactionPrototype<Projector> {
    /// Build a predicate on hash of this [`SignedTransaction`]
    pub hash: TransactionHashPrototype<SignedTransactionHashProjector<Projector>>,
    /// Build a predicate on the transaction authority
    pub authority: AccountIdPrototype<SignedTransactionAuthorityProjector<Projector>>,
}

impl_prototype!(SignedTransactionPrototype: SignedTransactionPredicateBox);

/// A prototype of [`Option<crate::transaction::error::TransactionRejectionReason>`]
#[derive(Default, Copy, Clone)]
pub struct TransactionErrorPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(TransactionErrorPrototype: TransactionErrorPredicateBox);

impl<Projector> TransactionErrorPrototype<Projector>
where
    Projector: ObjectProjector<Input = TransactionErrorPredicateBox>,
{
    /// Creates a predicate that checks if there is an error.
    pub fn is_some(&self) -> Projector::ProjectedPredicate<TransactionErrorPredicateBox> {
        Projector::project_predicate(TransactionErrorPredicateBox::IsSome)
    }

    /// Creates a predicate that checks if there is no error.
    pub fn is_none(
        &self,
    ) -> NotAstPredicate<Projector::ProjectedPredicate<TransactionErrorPredicateBox>> {
        Projector::project_predicate(TransactionErrorPredicateBox::IsSome).not()
    }
}

/// A prototype of [`crate::transaction::CommittedTransaction`]
#[derive(Default, Copy, Clone)]
pub struct CommittedTransactionPrototype<Projector> {
    /// Build a predicate on the signed transaction inside
    pub value: SignedTransactionPrototype<CommittedTransactionValueProjector<Projector>>,
    /// Build a predicate on the transaction error
    pub error: TransactionErrorPrototype<CommittedTransactionErrorProjector<Projector>>,
}

impl_prototype!(CommittedTransactionPrototype: CommittedTransactionPredicateBox);

/// A prototype of [`crate::query::TransactionQueryOutput`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct TransactionQueryOutputPrototype<Projector> {
    /// Build a predicate on the transaction inside
    pub transaction:
        CommittedTransactionPrototype<TransactionQueryOutputTransactionProjector<Projector>>,
    /// Build a predicate on the block hash inside
    pub block_hash: BlockHashPrototype<TransactionQueryOutputBlockHashProjector<Projector>>,
}

impl_prototype!(TransactionQueryOutputPrototype: TransactionQueryOutputPredicateBox);
