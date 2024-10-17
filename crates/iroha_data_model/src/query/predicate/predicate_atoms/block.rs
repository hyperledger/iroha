//! This module contains predicates for block-related objects, mirroring [`crate::block`].

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};

use iroha_crypto::HashOf;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    block::{BlockHeader, SignedBlock},
    prelude::{AccountIdPredicateBox, TransactionRejectionReason},
    query::{
        predicate::{
            predicate_ast_extensions::AstPredicateExt as _,
            predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
            projectors::BaseProjector,
            AstPredicate, CompoundPredicate, EvaluatePredicate, HasPredicateBox, HasPrototype,
        },
        TransactionQueryOutput,
    },
    transaction::{CommittedTransaction, SignedTransaction},
};

/// A predicate that can be applied to a [`HashOf<BlockHeader>`]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum BlockHashPredicateBox {
    // object-specific predicates
    /// Checks if the input is equal to the expected value.
    Equals(HashOf<BlockHeader>),
}

impl_predicate_box!(HashOf<BlockHeader>: BlockHashPredicateBox);

impl EvaluatePredicate<HashOf<BlockHeader>> for BlockHashPredicateBox {
    fn applies(&self, input: &HashOf<BlockHeader>) -> bool {
        match self {
            BlockHashPredicateBox::Equals(hash) => input == hash,
        }
    }
}

/// A predicate that can be applied to a [`BlockHeader`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum BlockHeaderPredicateBox {
    // projections
    /// Checks if a predicate applies to the hash of the block header.
    Hash(BlockHashPredicateBox),
}

impl_predicate_box!(BlockHeader: BlockHeaderPredicateBox);

impl EvaluatePredicate<BlockHeader> for BlockHeaderPredicateBox {
    fn applies(&self, input: &BlockHeader) -> bool {
        match self {
            BlockHeaderPredicateBox::Hash(hash) => hash.applies(&input.hash()),
        }
    }
}

/// A predicate that can be applied to a [`SignedBlock`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum SignedBlockPredicateBox {
    // projections
    /// Checks if a predicate applies to the header of the block.
    Header(BlockHeaderPredicateBox),
}

impl_predicate_box!(SignedBlock: SignedBlockPredicateBox);

impl EvaluatePredicate<SignedBlock> for SignedBlockPredicateBox {
    fn applies(&self, input: &SignedBlock) -> bool {
        match self {
            SignedBlockPredicateBox::Header(header) => header.applies(&input.header()),
        }
    }
}

/// A predicate that can be applied to a [`HashOf<SignedTransaction>`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum TransactionHashPredicateBox {
    // object-specific predicates
    /// Checks if the input is equal to the expected value.
    Equals(HashOf<SignedTransaction>),
}

impl_predicate_box!(HashOf<SignedTransaction>: TransactionHashPredicateBox);

impl EvaluatePredicate<HashOf<SignedTransaction>> for TransactionHashPredicateBox {
    fn applies(&self, input: &HashOf<SignedTransaction>) -> bool {
        match self {
            TransactionHashPredicateBox::Equals(hash) => input == hash,
        }
    }
}

/// A predicate that can be applied to a [`SignedTransaction`]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum SignedTransactionPredicateBox {
    // projections
    /// Checks if a predicate applies to the hash of the signed transaction.
    Hash(TransactionHashPredicateBox),
    /// Checks if a predicate applies to the authority of the signed transaction.
    Authority(AccountIdPredicateBox),
}

impl_predicate_box!(SignedTransaction: SignedTransactionPredicateBox);

impl EvaluatePredicate<SignedTransaction> for SignedTransactionPredicateBox {
    fn applies(&self, input: &SignedTransaction) -> bool {
        match self {
            SignedTransactionPredicateBox::Hash(hash) => hash.applies(&input.hash()),
            SignedTransactionPredicateBox::Authority(authority) => {
                authority.applies(input.authority())
            }
        }
    }
}

// TODO: maybe we would want to have a generic `Option` predicate box & predicate
/// A predicate that can be applied to an [`Option<TransactionRejectionReason>`]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum TransactionErrorPredicateBox {
    // object-specific predicates
    /// Checks if there was an error while applying the transaction.
    IsSome,
}

impl_predicate_box!(Option<Box<TransactionRejectionReason>>: TransactionErrorPredicateBox);

impl EvaluatePredicate<Option<Box<TransactionRejectionReason>>> for TransactionErrorPredicateBox {
    fn applies(&self, input: &Option<Box<TransactionRejectionReason>>) -> bool {
        match self {
            TransactionErrorPredicateBox::IsSome => input.is_some(),
        }
    }
}

/// A predicate that can be applied to a [`CommittedTransaction`]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum CommittedTransactionPredicateBox {
    // projections
    /// Checks if a predicate applies to the signed transaction inside.
    Value(SignedTransactionPredicateBox),
    /// Checks if a predicate applies to the error of the transaction.
    Error(TransactionErrorPredicateBox),
}

impl_predicate_box!(CommittedTransaction: CommittedTransactionPredicateBox);

impl EvaluatePredicate<CommittedTransaction> for CommittedTransactionPredicateBox {
    fn applies(&self, input: &CommittedTransaction) -> bool {
        match self {
            CommittedTransactionPredicateBox::Value(signed_transaction) => {
                signed_transaction.applies(&input.value)
            }
            CommittedTransactionPredicateBox::Error(error) => error.applies(&input.error),
        }
    }
}

/// A predicate that can be applied to a [`TransactionQueryOutput`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum TransactionQueryOutputPredicateBox {
    // projections
    /// Checks if a predicate applies to the committed transaction inside.
    Transaction(CommittedTransactionPredicateBox),
    /// Checks if a predicate applies to the hash of the block the transaction was included in.
    BlockHash(BlockHashPredicateBox),
}

impl_predicate_box!(TransactionQueryOutput: TransactionQueryOutputPredicateBox);

impl EvaluatePredicate<TransactionQueryOutput> for TransactionQueryOutputPredicateBox {
    fn applies(&self, input: &TransactionQueryOutput) -> bool {
        match self {
            TransactionQueryOutputPredicateBox::Transaction(committed_transaction) => {
                committed_transaction.applies(&input.transaction)
            }
            TransactionQueryOutputPredicateBox::BlockHash(block_hash) => {
                block_hash.applies(&input.block_hash)
            }
        }
    }
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::{
        BlockHashPredicateBox, BlockHeaderPredicateBox, CommittedTransactionPredicateBox,
        SignedBlockPredicateBox, SignedTransactionPredicateBox, TransactionErrorPredicateBox,
        TransactionHashPredicateBox, TransactionQueryOutputPredicateBox,
    };
}

#[cfg(test)]
mod test {
    use iroha_crypto::{Hash, HashOf};

    use crate::{
        account::AccountId,
        prelude::{
            AccountIdPredicateBox, BlockHeaderPredicateBox, CompoundPredicate,
            SignedBlockPredicateBox, TransactionQueryOutputPredicateBox,
        },
        query::predicate::predicate_atoms::block::{
            BlockHashPredicateBox, CommittedTransactionPredicateBox, SignedTransactionPredicateBox,
            TransactionErrorPredicateBox, TransactionHashPredicateBox,
        },
    };

    #[test]
    fn transaction_smoke() {
        let hash = Hash::prehashed([0; 32]);
        let account_id: AccountId =
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland"
                .parse()
                .unwrap();

        let predicate = TransactionQueryOutputPredicateBox::build(|tx| {
            tx.block_hash.eq(HashOf::from_untyped_unchecked(hash))
                & tx.transaction.error.is_some()
                & tx.transaction.value.authority.eq(account_id.clone())
                & tx.transaction
                    .value
                    .hash
                    .eq(HashOf::from_untyped_unchecked(hash))
        });

        assert_eq!(
            predicate,
            CompoundPredicate::And(vec![
                CompoundPredicate::Atom(TransactionQueryOutputPredicateBox::BlockHash(
                    BlockHashPredicateBox::Equals(HashOf::from_untyped_unchecked(hash))
                )),
                CompoundPredicate::Atom(TransactionQueryOutputPredicateBox::Transaction(
                    CommittedTransactionPredicateBox::Error(TransactionErrorPredicateBox::IsSome)
                )),
                CompoundPredicate::Atom(TransactionQueryOutputPredicateBox::Transaction(
                    CommittedTransactionPredicateBox::Value(
                        SignedTransactionPredicateBox::Authority(AccountIdPredicateBox::Equals(
                            account_id.clone()
                        ))
                    )
                )),
                CompoundPredicate::Atom(TransactionQueryOutputPredicateBox::Transaction(
                    CommittedTransactionPredicateBox::Value(SignedTransactionPredicateBox::Hash(
                        TransactionHashPredicateBox::Equals(HashOf::from_untyped_unchecked(hash))
                    ))
                )),
            ])
        );
    }

    #[test]
    fn block_smoke() {
        let hash = Hash::prehashed([0; 32]);

        let predicate = SignedBlockPredicateBox::build(|block| {
            block.header.hash.eq(HashOf::from_untyped_unchecked(hash))
        });

        assert_eq!(
            predicate,
            CompoundPredicate::Atom(SignedBlockPredicateBox::Header(
                BlockHeaderPredicateBox::Hash(BlockHashPredicateBox::Equals(
                    HashOf::from_untyped_unchecked(hash)
                ))
            ))
        );
    }
}
