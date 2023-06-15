//! Query module provides [`Query`] Transaction related implementations.

use std::sync::Arc;

use eyre::{Result, WrapErr};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::VersionedCommittedBlock,
    evaluate::ExpressionEvaluator,
    prelude::*,
    query::{
        error::{FindError, QueryExecutionFail},
        TransactionQueryResult,
    },
    transaction::TransactionValue,
};
use iroha_telemetry::metrics;

use super::{query::Lazy, *};

pub(crate) struct BlockTransactionIter(Arc<VersionedCommittedBlock>, usize);
pub(crate) struct BlockTransactionRef(Arc<VersionedCommittedBlock>, usize);

impl BlockTransactionIter {
    fn new(block: Arc<VersionedCommittedBlock>) -> Self {
        Self(block, 0)
    }
}

impl Iterator for BlockTransactionIter {
    type Item = BlockTransactionRef;

    fn next(&mut self) -> Option<Self::Item> {
        let block = self.0.as_v1();

        if self.1 < block.transactions.len() {
            return Some(BlockTransactionRef(Arc::clone(&self.0), self.1));
        }

        None
    }
}

impl BlockTransactionRef {
    fn block_hash(&self) -> HashOf<VersionedCommittedBlock> {
        self.0.hash()
    }

    fn authority(&self) -> &AccountId {
        let block = self.0.as_v1();

        &block.transactions[self.1].payload().authority
    }
    fn value(&self) -> TransactionValue {
        self.0.as_v1().transactions[self.1].clone()
    }
}

impl ValidQuery for FindAllTransactions {
    #[metrics(+"find_all_transactions")]
    fn execute<'wsv>(
        &self,
        wsv: &'wsv WorldStateView,
    ) -> Result<<Self::Output as Lazy>::Lazy<'wsv>, QueryExecutionFail> {
        Ok(Box::new(
            wsv.all_blocks()
                .flat_map(BlockTransactionIter::new)
                .map(|tx| TransactionQueryResult {
                    block_hash: tx.block_hash(),
                    transaction: tx.value(),
                }),
        ))
    }
}

impl ValidQuery for FindTransactionsByAccountId {
    #[metrics(+"find_transactions_by_account_id")]
    fn execute<'wsv>(
        &self,
        wsv: &'wsv WorldStateView,
    ) -> Result<<Self::Output as Lazy>::Lazy<'wsv>, QueryExecutionFail> {
        let account_id = wsv
            .evaluate(&self.account_id)
            .wrap_err("Failed to get account id")
            .map_err(|e| QueryExecutionFail::Evaluate(e.to_string()))?;

        Ok(Box::new(
            wsv.all_blocks()
                .flat_map(BlockTransactionIter::new)
                .filter(move |tx| *tx.authority() == account_id)
                .map(|tx| TransactionQueryResult {
                    block_hash: tx.block_hash(),
                    transaction: tx.value(),
                }),
        ))
    }
}

impl ValidQuery for FindTransactionByHash {
    #[metrics(+"find_transaction_by_hash")]
    fn execute<'wsv>(
        &self,
        wsv: &'wsv WorldStateView,
    ) -> Result<<Self::Output as Lazy>::Lazy<'wsv>, QueryExecutionFail> {
        let tx_hash = wsv
            .evaluate(&self.hash)
            .wrap_err("Failed to get hash")
            .map_err(|e| QueryExecutionFail::Evaluate(e.to_string()))?;
        iroha_logger::trace!(%tx_hash);
        if !wsv.has_transaction(tx_hash) {
            return Err(FindError::Transaction(tx_hash).into());
        };
        let block = wsv
            .block_with_tx(&tx_hash)
            .ok_or_else(|| FindError::Transaction(tx_hash))?;

        let block_hash = block.hash();
        let block = block.as_v1();

        block
            .transactions
            .iter()
            .find(|transaction| transaction.value.hash() == tx_hash)
            .cloned()
            .map(|transaction| TransactionQueryResult {
                block_hash,
                transaction,
            })
            .ok_or_else(|| FindError::Transaction(tx_hash).into())
    }
}
