//! This module contains implementations of smart-contract traits and instructions for [`Account`] structure
//! and implementations of [`Query`]'s to [`WorldStateView<W>`] about [`Account`].

use iroha_data_model::prelude::*;
use iroha_telemetry::metrics;

use crate::prelude::*;

/// All instructions related to accounts:
/// - minting/burning public key into account signatories
/// - minting/burning signature condition check
/// - update metadata
/// - grant permissions and roles
/// - TODO Revoke permissions or roles
pub mod isi {
    use super::{super::prelude::*, *};

    impl<W: WorldTrait> Execute<W> for Mint<Account, PublicKey> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"mint_account_pubkey")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let public_key = self.object.clone();
            wsv.modify_account(&self.destination_id, |account| {
                account.signatories.push(public_key);
                Ok(())
            })?;
            Ok(self.into())
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Account, SignatureCheckCondition> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"mint_account_signature_check_condition")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let id = self.destination_id.clone();
            wsv.modify_account(&id, |account| {
                account.signature_check_condition = self.object.clone();
                Ok(())
            })?;
            Ok(self.into())
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Account, PublicKey> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"burn_account_pubkey")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let public_key = self.object.clone();
            wsv.modify_account(&self.destination_id, |account| {
                if let Some(index) = account
                    .signatories
                    .iter()
                    .position(|key| key == &public_key)
                {
                    account.signatories.remove(index);
                }
                Ok(())
            })?;
            Ok(self.into())
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<Account, Name, Value> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"set_key_value_account_string_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let account_metadata_limits = wsv.config.account_metadata_limits;
            let id = self.object_id.clone();
            wsv.modify_account(&id, |account| {
                account.metadata.insert_with_limits(
                    self.key.clone(),
                    self.value.clone(),
                    account_metadata_limits,
                )?;
                Ok(())
            })?;
            Ok(self.into())
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<Account, Name> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"remove_account_key_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            wsv.modify_account(&self.object_id, |account| {
                account
                    .metadata
                    .remove(&self.key)
                    .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;
                Ok(())
            })?;
            Ok(self.into())
        }
    }

    impl<W: WorldTrait> Execute<W> for Grant<Account, PermissionToken> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"grant_account_permission_token")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let id = self.destination_id.clone();
            wsv.modify_account(&id, |account| {
                let _ = account.permission_tokens.insert(self.object.clone());
                Ok(())
            })?;
            Ok(self.into())
        }
    }

    #[cfg(feature = "roles")]
    impl<W: WorldTrait> Execute<W> for Grant<Account, RoleId> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"grant_account_role")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            wsv.world()
                .roles
                .get(&self.object)
                .ok_or_else(|| FindError::Role(self.object.clone()))?;

            let id = self.destination_id.clone();
            wsv.modify_account(&id, |account| {
                let _ = account.roles.insert(self.object.clone());
                Ok(())
            })?;
            Ok(self.into())
        }
    }
}

/// Account-related [`Query`] instructions.
pub mod query {

    use eyre::{Result, WrapErr};
    use iroha_logger::prelude::*;

    use super::{super::Evaluate, *};
    use crate::smartcontracts::{isi::prelude::WorldTrait, query::Error, FindError};

    #[cfg(feature = "roles")]
    impl<W: WorldTrait> ValidQuery<W> for FindRolesByAccountId {
        #[log]
        #[metrics(+"find_roles_by_account_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let account_id = self
                .id
                .evaluate(wsv, &Context::new())
                .wrap_err("Failed to evaluate account id")
                .map_err(Error::Evaluate)?;
            let roles = wsv.map_account(&account_id, |account| {
                account.roles.iter().cloned().collect::<Vec<_>>()
            })?;
            Ok(roles)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindPermissionTokensByAccountId {
        #[log]
        #[metrics(+"find_permission_tokens_by_account_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let account_id = self
                .id
                .evaluate(wsv, &Context::new())
                .wrap_err("Failed to evaluate account id")
                .map_err(Error::Evaluate)?;
            let tokens = wsv.map_account(&account_id, |account| {
                wsv.account_permission_tokens(account)
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
            })?;
            Ok(tokens)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAllAccounts {
        #[log]
        #[metrics(+"find_all_accounts")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts.values() {
                    vec.push(account.clone())
                }
            }
            Ok(vec)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAccountById {
        #[log]
        #[metrics(+"find_account_by_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get id")
                .map_err(Error::Evaluate)?;
            wsv.map_account(&id, Clone::clone).map_err(Into::into)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAccountsByName {
        #[log]
        #[metrics(+"find_account_by_name")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let name = self
                .name
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account name")
                .map_err(Error::Evaluate)?;
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

    impl<W: WorldTrait> ValidQuery<W> for FindAccountsByDomainId {
        #[log]
        #[metrics(+"find_accounts_by_domain_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .domain_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain id")
                .map_err(Error::Evaluate)?;
            Ok(wsv
                .domain(&id)?
                .accounts
                .values()
                .cloned()
                .collect::<Vec<_>>())
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAccountKeyValueByIdAndKey {
        #[log]
        #[metrics(+"find_account_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account id")
                .map_err(Error::Evaluate)?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")
                .map_err(Error::Evaluate)?;
            wsv.map_account(&id, |account| account.metadata.get(&key).map(Clone::clone))?
                .ok_or_else(|| query::Error::Find(Box::new(FindError::MetadataKey(key))))
        }
    }
}
