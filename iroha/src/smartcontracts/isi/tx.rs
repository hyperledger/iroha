//! Query module provides [`IrohaQuery`] Transaction related implementations.

use iroha_data_model::prelude::*;
use iroha_error::{Result, WrapErr};

use super::*;

impl Query for FindTransactionsByAccountId {
    #[iroha_logger::log]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
        let id = self
            .account_id
            .evaluate(wsv, &Context::default())
            .wrap_err("Failed to get id")?;
        Ok(wsv.transactions_values_by_account_id(&id))
    }
}
