//! Query module provides [`Query`] Transaction related implementations.

use std::sync::Arc;

use eyre::Result;
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{BlockHeader, SignedBlock},
    prelude::*,
    query::{dsl::CompoundPredicate, error::QueryExecutionFail, CommittedTransaction},
    transaction::error::TransactionRejectionReason,
};
use iroha_telemetry::metrics;
use nonzero_ext::nonzero;

use super::*;
use crate::smartcontracts::ValidQuery;

/// Iterates transactions of a block in reverse order
pub(crate) struct BlockTransactionIter(Arc<SignedBlock>, usize);
pub(crate) struct BlockTransactionRef(Arc<SignedBlock>, usize);

impl BlockTransactionIter {
    fn new(block: Arc<SignedBlock>) -> Self {
        let n_transactions = block.transactions().len();
        Self(block, n_transactions)
    }
}

impl Iterator for BlockTransactionIter {
    type Item = BlockTransactionRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.1 != 0 {
            self.1 -= 1;
            return Some(BlockTransactionRef(Arc::clone(&self.0), self.1));
        }

        None
    }
}

impl BlockTransactionRef {
    fn block_hash(&self) -> HashOf<BlockHeader> {
        self.0.hash()
    }

    fn value(&self) -> (SignedTransaction, Option<TransactionRejectionReason>) {
        (
            self.0
                .transactions()
                .nth(self.1)
                .expect("INTERNAL BUG: The transaction is not found")
                .clone(),
            self.0.error(self.1).cloned(),
        )
    }
}

impl ValidQuery for FindTransactions {
    #[metrics(+"find_transactions")]
    fn execute(
        self,
        filter: CompoundPredicate<CommittedTransaction>,
        state_ro: &impl StateReadOnly,
    ) -> Result<impl Iterator<Item = Self::Item>, QueryExecutionFail> {
        Ok(state_ro
            .all_blocks(nonzero!(1_usize))
            .rev()
            .flat_map(BlockTransactionIter::new)
            .map(|tx| {
                let (value, error) = tx.value();

                CommittedTransaction {
                    block_hash: tx.block_hash(),
                    value,
                    error,
                }
            })
            .filter(move |tx| filter.applies(tx)))
    }
}
