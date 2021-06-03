//! Query module provides [`IrohaQuery`] Transaction related implementations.

use iroha_data_model::prelude::*;
use iroha_error::{Result, WrapErr};

use super::*;

impl Query for FindTransactionsByAccountId {
    #[iroha_logger::log]
    fn execute(&self, world_state_view: &WorldStateView) -> Result<Self::Output> {
        let id = self
            .account_id
            .evaluate(world_state_view, &Context::default())
            .wrap_err("Failed to get id")?;
        Ok(world_state_view.transactions_values_by_account_id(&id))
    }
}
