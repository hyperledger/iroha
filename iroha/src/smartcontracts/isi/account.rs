//! This module contains `Account` structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::prelude::*;

use crate::prelude::*;

/// Iroha Special Instructions module provides `AccountInstruction` enum with all possible types of
/// Account related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AccountInstruction` variants into generic ISI.
pub mod isi {
    use super::super::prelude::*;
    use super::*;

    impl Execute for Mint<Account, PublicKey> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            let public_key = self.object.clone();
            wsv.modify_account(&self.destination_id, |account| {
                account.signatories.push(public_key);
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for Mint<Account, SignatureCheckCondition> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            let id = self.destination_id.clone();
            wsv.modify_account(&id, |account| {
                account.signature_check_condition = self.object;
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for Burn<Account, PublicKey> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            let public_key = self.object.clone();
            wsv.modify_account(&self.destination_id, |account| {
                if let Some(index) = account
                    .signatories
                    .iter()
                    .position(|key| key == &public_key)
                {
                    drop(account.signatories.remove(index));
                }
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for SetKeyValue<Account, String, Value> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            let account_metadata_limits = wsv.config.account_metadata_limits;
            let id = self.object_id.clone();
            wsv.modify_account(&id, |account| {
                drop(account.metadata.insert_with_limits(
                    self.key.clone(),
                    self.value,
                    account_metadata_limits,
                ));
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Account, String> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            wsv.modify_account(&self.object_id, |account| {
                drop(
                    account
                        .metadata
                        .remove(&self.key)
                        .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?,
                );
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for Grant<Account, PermissionToken> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            let id = self.destination_id.clone();
            wsv.modify_account(&id, |account| {
                let _ = account.permission_tokens.insert(self.object);
                Ok(())
            })?;
            Ok(())
        }
    }

    #[cfg(feature = "roles")]
    impl Execute for Grant<Account, RoleId> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            drop(
                wsv.world()
                    .roles
                    .get(&self.object)
                    .ok_or_else(|| FindError::Role(self.object.clone()))?,
            );

            let id = self.destination_id.clone();
            wsv.modify_account(&id, |account| {
                let _ = account.roles.insert(self.object);
                Ok(())
            })?;
            Ok(())
        }
    }
}

/// Query module provides `IrohaQuery` Account related implementations.
pub mod query {

    use iroha_error::{error, Result, WrapErr};
    use iroha_logger::log;

    use super::super::expression::Evaluate;
    use super::*;

    #[cfg(feature = "roles")]
    impl Query for FindRolesByAccountId {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let account_id = self.id.evaluate(wsv, &Context::new())?;
            let roles = wsv.map_account(&account_id, |account| {
                account.roles.iter().cloned().collect::<Vec<_>>()
            })?;
            Ok(roles)
        }
    }

    impl Query for FindPermissionTokensByAccountId {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let account_id = self.id.evaluate(wsv, &Context::new())?;
            let tokens = wsv.map_account(&account_id, |account| {
                account
                    .permission_tokens(&wsv.world)
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
            })?;
            Ok(tokens)
        }
    }

    impl Query for FindAllAccounts {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts.values() {
                    vec.push(account.clone())
                }
            }
            Ok(vec)
        }
    }

    impl Query for FindAccountById {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get id")?;
            Ok(wsv.map_account(&id, Clone::clone)?)
        }
    }

    impl Query for FindAccountsByName {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let name = self
                .name
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account name")?;
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for (id, account) in &domain.accounts {
                    if id.name == name {
                        vec.push(account.clone())
                    }
                }
            }
            Ok(vec)
        }
    }

    impl Query for FindAccountsByDomainName {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let name = self
                .domain_name
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain name")?;
            Ok(wsv
                .domain(&name)?
                .accounts
                .values()
                .cloned()
                .collect::<Vec<_>>())
        }
    }

    impl Query for FindAccountKeyValueByIdAndKey {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account id")?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")?;
            wsv.map_account(&id, |account| account.metadata.get(&key).map(Clone::clone))?
                .ok_or_else(|| error!("No metadata entry with this key."))
        }
    }
}
