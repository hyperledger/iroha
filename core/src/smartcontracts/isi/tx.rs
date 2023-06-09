//! Query module provides [`Query`] Transaction related implementations.

use eyre::{Result, WrapErr};
use iroha_crypto::HashOf;
use iroha_data_model::{
    evaluate::ExpressionEvaluator,
    prelude::*,
    query::error::{FindError, QueryExecutionFail},
};
use iroha_telemetry::metrics;

use super::*;

impl ValidQuery for FindAllTransactions {
    #[metrics(+"find_all_transactions")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, QueryExecutionFail> {
        let mut txs = wsv.transaction_values();
        txs.reverse();
        Ok(txs)
    }
}

impl ValidQuery for FindTransactionsByAccountId {
    #[metrics(+"find_transactions_by_account_id")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, QueryExecutionFail> {
        let id = wsv
            .evaluate(&self.account_id)
            .wrap_err("Failed to get account id")
            .map_err(|e| QueryExecutionFail::Evaluate(e.to_string()))?;
        iroha_logger::trace!(%id);
        Ok(wsv.transactions_values_by_account_id(&id))
    }
}

impl ValidQuery for FindTransactionByHash {
    #[metrics(+"find_transaction_by_hash")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, QueryExecutionFail> {
        let hash = wsv
            .evaluate(&self.hash)
            .wrap_err("Failed to get hash")
            .map_err(|e| QueryExecutionFail::Evaluate(e.to_string()))?;
        iroha_logger::trace!(%hash);
        let hash = HashOf::from_untyped_unchecked(hash);
        if !wsv.has_transaction(hash) {
            return Err(FindError::Transaction(hash).into());
        };
        wsv.transaction_value_by_hash(&hash)
            .ok_or_else(|| FindError::Transaction(hash).into())
    }
}
