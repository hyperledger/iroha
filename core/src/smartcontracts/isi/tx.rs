//! Query module provides [`Query`] Transaction related implementations.

use eyre::{Result, WrapErr};
use iroha_data_model::{
    prelude::*,
    query::error::{FindError, QueryExecutionFailure as Error},
};
use iroha_telemetry::metrics;

use super::*;
use crate::evaluate_with_error_msg;

impl ValidQuery for FindAllTransactions {
    #[metrics(+"find_all_transactions")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
        let mut txs = wsv.transaction_values();
        txs.reverse();
        Ok(txs)
    }
}

impl ValidQuery for FindTransactionsByAccountId {
    #[metrics(+"find_transactions_by_account_id")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
        let id = evaluate_with_error_msg!(self.account_id, wsv, "Failed to get account id");
        iroha_logger::trace!(%id);
        Ok(wsv.transactions_values_by_account_id(&id))
    }
}

impl ValidQuery for FindTransactionByHash {
    #[metrics(+"find_transaction_by_hash")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
        let hash = evaluate_with_error_msg!(self.hash, wsv, "Failed to get hash");
        iroha_logger::trace!(%hash);
        let hash = hash.typed();
        if !wsv.has_transaction(&hash) {
            return Err(FindError::Transaction(hash).into());
        };
        wsv.transaction_value_by_hash(&hash)
            .ok_or_else(|| FindError::Transaction(hash).into())
    }
}
