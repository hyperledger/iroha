//! This module contains `Account` structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::prelude::*;

use crate::prelude::*;

/// Iroha Special Instructions module provides `AccountInstruction` enum with all possible types of
/// Account related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AccountInstruction` variants into generic ISI.
pub mod isi {
    use iroha_error::{error, Result};

    use super::*;
    use crate::isi::prelude::*;

    impl Execute for Mint<Account, PublicKey> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let public_key = self.object.clone();
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or_else(|| error!("Failed to find account."))?;
            account.signatories.push(public_key);
            Ok(world_state_view)
        }
    }

    impl Execute for Mint<Account, SignatureCheckCondition> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or_else(|| error!("Failed to find account."))?;
            account.signature_check_condition = self.object;
            Ok(world_state_view)
        }
    }

    impl Execute for Burn<Account, PublicKey> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let public_key = self.object.clone();
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or_else(|| error!("Failed to find account."))?;
            if let Some(index) = account
                .signatories
                .iter()
                .position(|key| key == &public_key)
            {
                let _ = account.signatories.remove(index);
            }
            Ok(world_state_view)
        }
    }

    impl Execute for SetKeyValue<Account, String, Value> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let account_metadata_limits = world_state_view.config.account_metadata_limits;
            let account = world_state_view
                .account(&self.object_id)
                .ok_or_else(|| error!("Failed to find account."))?;
            let _ =
                account
                    .metadata
                    .insert_with_limits(self.key, self.value, account_metadata_limits);
            Ok(world_state_view)
        }
    }

    impl Execute for RemoveKeyValue<Account, String> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let account = world_state_view
                .account(&self.object_id)
                .ok_or_else(|| error!("Failed to find account."))?;
            let _ = account
                .metadata
                .remove(&self.key)
                .ok_or_else(|| error!("Key not found."))?;
            Ok(world_state_view)
        }
    }

    impl Execute for Grant<Account, PermissionToken> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or_else(|| error!("Failed to find account."))?;
            let _ = account.permission_tokens.insert(self.permission_token);
            Ok(world_state_view)
        }
    }
}

/// Query module provides `IrohaQuery` Account related implementations.
pub mod query {
    use iroha_error::{error, Result, WrapErr};
    use iroha_logger::log;

    use super::*;
    use crate::expression::Evaluate;

    impl Query for FindAllAccounts {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_accounts()
                .into_iter()
                .cloned()
                .collect())
        }
    }

    impl Query for FindAccountById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let id = self
                .id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get id")?;
            Ok(world_state_view
                .read_account(&id)
                .map(Clone::clone)
                .ok_or_else(|| error!("Failed to get an account."))?
                .into())
        }
    }

    impl Query for FindAccountsByName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let name = self
                .name
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get account name")?;
            Ok(world_state_view
                .read_all_accounts()
                .into_iter()
                .filter(|account| account.id.name == name)
                .cloned()
                .collect())
        }
    }

    impl Query for FindAccountsByDomainName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let name = self
                .domain_name
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get domain name")?;
            Ok(world_state_view
                .read_all_accounts()
                .into_iter()
                .filter(|account| account.id.domain_name == name)
                .cloned()
                .collect())
        }
    }

    impl Query for FindAccountKeyValueByIdAndKey {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let id = self
                .id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get account id")?;
            let key = self
                .key
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get key")?;
            world_state_view
                .read_account(&id)
                .ok_or_else(|| error!("Failed to get an account."))?
                .metadata
                .get(&key)
                .map(Clone::clone)
                .ok_or_else(|| error!("No metadata entry with this key."))
        }
    }
}
