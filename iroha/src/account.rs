//! This module contains `Account` structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::prelude::*;

use crate::prelude::*;

/// Iroha Special Instructions module provides `AccountInstruction` enum with all possible types of
/// Account related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AccountInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use crate::isi::prelude::*;

    impl Execute for Mint<Account, PublicKey> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let public_key = self.object.clone();
            world_state_view.account(&self.destination_id, |account| {
                account.signatories.write().push(public_key);
            })?;
            Ok(())
        }
    }

    impl Execute for Mint<Account, SignatureCheckCondition> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let id = self.destination_id.clone();
            world_state_view.account(&id, |account| {
                *account.signature_check_condition.write() = self.object;
            })?;
            Ok(())
        }
    }

    impl Execute for Burn<Account, PublicKey> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let public_key = self.object.clone();
            world_state_view.account(&self.destination_id, |account| {
                if let Some(index) = account
                    .signatories
                    .read()
                    .iter()
                    .position(|key| key == &public_key)
                {
                    let _ = account.signatories.write().remove(index);
                }
            })?;
            Ok(())
        }
    }

    impl Execute for SetKeyValue<Account, String, Value> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let account_metadata_limits = world_state_view.config.account_metadata_limits;
            let id = self.object_id.clone();
            world_state_view.account(&id, |account| {
                let _ = account.metadata.write().insert_with_limits(
                    self.key.clone(),
                    self.value,
                    account_metadata_limits,
                );
            })?;
            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Account, String> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            world_state_view.account(&self.object_id, |account| {
                let _ = account
                    .metadata
                    .write()
                    .remove(&self.key)
                    .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;
                Ok(())
            })?
        }
    }

    impl Execute for Grant<Account, PermissionToken> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let id = self.destination_id.clone();
            world_state_view.account(&id, |account| {
                let _ = account
                    .permission_tokens
                    .write()
                    .insert(self.permission_token);
            })?;
            Ok(())
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
            let mut vec = Vec::new();
            for domain in world_state_view.domains().iter() {
                for account in domain.accounts.iter() {
                    vec.push(Value::from(account.clone()))
                }
            }
            Ok(vec.into())
        }
    }

    impl Query for FindAccountById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let id = self
                .id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get id")?;
            Ok(world_state_view.account(&id, Clone::clone)?.into())
        }
    }

    impl Query for FindAccountsByName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let name = self
                .name
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get account name")?;
            let mut vec = Vec::new();
            for domain in world_state_view.domains().iter() {
                for account in domain.accounts.iter() {
                    if account.id.name == name {
                        vec.push(Value::from(account.clone()))
                    }
                }
            }
            Ok(vec.into())
        }
    }

    impl Query for FindAccountsByDomainName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let name = self
                .domain_name
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get domain name")?;
            let vec = world_state_view.domain(&name, |domain| {
                let mut vec = Vec::new();
                for account in domain.accounts.iter() {
                    vec.push(Value::from(account.clone()))
                }
                vec
            })?;
            Ok(vec.into())
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
                .account(&id, |account| {
                    account.metadata.read().get(&key).map(Clone::clone)
                })?
                .ok_or_else(|| error!("No metadata entry with this key."))
        }
    }
}
