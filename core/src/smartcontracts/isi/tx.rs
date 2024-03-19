//! Query module provides [`Query`] Transaction related implementations.

use std::sync::Arc;

use eyre::Result;
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::SignedBlock,
    prelude::*,
    query::{
        error::{FindError, QueryExecutionFail},
        TransactionQueryOutput,
    },
    transaction::TransactionValue,
};
use iroha_telemetry::metrics;

use super::*;

pub(crate) struct BlockTransactionIter(Arc<SignedBlock>, usize);
pub(crate) struct BlockTransactionRef(Arc<SignedBlock>, usize);

impl BlockTransactionIter {
    fn new(block: Arc<SignedBlock>) -> Self {
        Self(block, 0)
    }
}

impl Iterator for BlockTransactionIter {
    type Item = BlockTransactionRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.1 < self.0.transactions().len() {
            let res = Some(BlockTransactionRef(Arc::clone(&self.0), self.1));

            self.1 += 1;
            return res;
        }

        None
    }
}

impl BlockTransactionRef {
    fn block_hash(&self) -> HashOf<SignedBlock> {
        self.0.hash()
    }

    fn authority(&self) -> &AccountId {
        self.0
            .transactions()
            .nth(self.1)
            .expect("The transaction is not found")
            .as_ref()
            .authority()
    }
    fn value(&self) -> TransactionValue {
        self.0
            .transactions()
            .nth(self.1)
            .expect("The transaction is not found")
            .clone()
    }
}

impl ValidQuery for FindAllTransactions {
    #[metrics(+"find_all_transactions")]
    fn execute<'state>(
        &self,
        state_ro: &'state impl StateReadOnly,
    ) -> Result<Box<dyn Iterator<Item = TransactionQueryOutput> + 'state>, QueryExecutionFail> {
        Ok(Box::new(
            state_ro
                .all_blocks()
                .flat_map(BlockTransactionIter::new)
                .map(|tx| TransactionQueryOutput {
                    block_hash: tx.block_hash(),
                    transaction: tx.value(),
                }),
        ))
    }
}

impl ValidQuery for FindTransactionsByAccountId {
    #[metrics(+"find_transactions_by_account_id")]
    fn execute<'state>(
        &self,
        state_ro: &'state impl StateReadOnly,
    ) -> Result<Box<dyn Iterator<Item = TransactionQueryOutput> + 'state>, QueryExecutionFail> {
        let account_id = self.account_id.clone();

        Ok(Box::new(
            state_ro
                .all_blocks()
                .flat_map(BlockTransactionIter::new)
                .filter(move |tx| *tx.authority() == account_id)
                .map(|tx| TransactionQueryOutput {
                    block_hash: tx.block_hash(),
                    transaction: tx.value(),
                }),
        ))
    }
}

impl ValidQuery for FindTransactionByHash {
    #[metrics(+"find_transaction_by_hash")]
    fn execute(
        &self,
        state_ro: &impl StateReadOnly,
    ) -> Result<TransactionQueryOutput, QueryExecutionFail> {
        let tx_hash = self.hash;

        iroha_logger::trace!(%tx_hash);
        if !state_ro.has_transaction(tx_hash) {
            return Err(FindError::Transaction(tx_hash).into());
        };
        let block = state_ro
            .block_with_tx(&tx_hash)
            .ok_or_else(|| FindError::Transaction(tx_hash))?;

        let block_hash = block.hash();

        let mut transactions = block.transactions();
        transactions
            .find(|transaction| transaction.value.hash() == tx_hash)
            .cloned()
            .map(|transaction| TransactionQueryOutput {
                block_hash,
                transaction,
            })
            .ok_or_else(|| FindError::Transaction(tx_hash).into())
    }
}
