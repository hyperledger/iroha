//! Query module provides [`Query`] Transaction related implementations.

use eyre::{Result, WrapErr};
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use iroha_telemetry::metrics;

use super::*;

impl<W: WorldTrait> ValidQuery<W> for FindTransactionsByAccountId {
    #[log]
    #[metrics(+"find_transactions_by_account_id")]
    fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, query::Error> {
        let id = self
            .account_id
            .evaluate(wsv, &Context::default())
            .wrap_err("Failed to get account id")
            .map_err(|e| query::Error::Evaluate(e.to_string()))?;
        Ok(wsv.transactions_values_by_account_id(&id))
    }
}

impl<W: WorldTrait> ValidQuery<W> for FindTransactionByHash {
    #[log]
    #[metrics(+"find_transaction_by_hash")]
    fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, query::Error> {
        let hash = self
            .hash
            .evaluate(wsv, &Context::default())
            .wrap_err("Failed to get hash")
            .map_err(|e| query::Error::Evaluate(e.to_string()))?;
        let hash = hash.typed();
        if !wsv.has_transaction(&hash) {
            return Err(FindError::Transaction(hash).into());
        };
        wsv.transaction_value_by_hash(&hash)
            .ok_or_else(|| FindError::Transaction(hash).into())
    }
}
