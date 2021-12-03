//! Query module provides [`Query`] Transaction related implementations.

use eyre::{Result, WrapErr};
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;

use super::*;

impl<W: WorldTrait> ValidQuery<W> for FindTransactionsByAccountId {
    #[log]
    fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
        let id = self
            .account_id
            .evaluate(wsv, &Context::default())
            .wrap_err("Failed to get id")?;
        Ok(wsv.transactions_values_by_account_id(&id))
    }
}

impl<W: WorldTrait> ValidQuery<W> for FindTransactionByHash {
    #[log]
    fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
        let hash = self
            .hash
            .evaluate(wsv, &Context::default())
            .wrap_err("Failed to get hash")?;
        let hash = HashOf::from_hash(hash);
        if !wsv.has_transaction(&hash) {
            return Err(eyre!("Transaction not found"));
        };
        wsv.transaction_value_by_hash(&hash)
            .ok_or_else(|| eyre!("Failed to fetch transaction"))
    }
}
