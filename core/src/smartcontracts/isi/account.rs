//! This module contains implementations of smart-contract traits and instructions for [`Account`] structure
//! and implementations of [`Query`]'s to [`WorldStateView<W>`] about [`Account`].

use iroha_data_model::prelude::*;

use crate::prelude::*;

/// ISI module contains all instructions related to accounts:
/// - minting/burning public key into account signatories
/// - minting/burning signature condition check
/// - update metadata
/// - grant permissions and roles
pub mod isi {
    use super::{super::prelude::*, *};

    impl<W: WorldTrait> Execute<W> for Mint<Account, PublicKey> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            let public_key = self.object.clone();
            wsv.modify_account(&self.destination_id, |account| {
                account.signatories.push(public_key);
                Ok(())
            })?;
            Ok(())
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Account, SignatureCheckCondition> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            let id = self.destination_id.clone();
            wsv.modify_account(&id, |account| {
                account.signature_check_condition = self.object;
                Ok(())
            })?;
            Ok(())
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Account, PublicKey> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
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
            Ok(())
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<Account, String, Value> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            let account_metadata_limits = wsv.config.account_metadata_limits;
            let id = self.object_id.clone();
            wsv.modify_account(&id, |account| {
                account.metadata.insert_with_limits(
                    self.key.clone(),
                    self.value,
                    account_metadata_limits,
                )?;
                Ok(())
            })?;
            Ok(())
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<Account, String> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            wsv.modify_account(&self.object_id, |account| {
                account
                    .metadata
                    .remove(&self.key)
                    .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;
                Ok(())
            })?;
            Ok(())
        }
    }

    impl<W: WorldTrait> Execute<W> for Grant<Account, PermissionToken> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
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
    impl<W: WorldTrait> Execute<W> for Grant<Account, RoleId> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            wsv.world()
                .roles
                .get(&self.object)
                .ok_or_else(|| FindError::Role(self.object.clone()))?;

            let id = self.destination_id.clone();
            wsv.modify_account(&id, |account| {
                let _ = account.roles.insert(self.object);
                Ok(())
            })?;
            Ok(())
        }
    }
}

/// Query module provides [`Query`] Account related implementations.
pub mod query {

    use eyre::{eyre, Result, WrapErr};
    use iroha_logger::prelude::*;

    use super::{super::Evaluate, *};
    use crate::smartcontracts::isi::prelude::WorldTrait;

    #[cfg(feature = "roles")]
    impl<W: WorldTrait> ValidQuery<W> for FindRolesByAccountId {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
            let account_id = self.id.evaluate(wsv, &Context::new())?;
            let roles = wsv.map_account(&account_id, |account| {
                account.roles.iter().cloned().collect::<Vec<_>>()
            })?;
            Ok(roles)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindPermissionTokensByAccountId {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
            let account_id = self.id.evaluate(wsv, &Context::new())?;
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
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
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
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get id")?;
            wsv.map_account(&id, Clone::clone)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAccountsByName {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
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

    impl<W: WorldTrait> ValidQuery<W> for FindAccountsByDomainName {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
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

    impl<W: WorldTrait> ValidQuery<W> for FindAccountKeyValueByIdAndKey {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account id")?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")?;
            wsv.map_account(&id, |account| account.metadata.get(&key).map(Clone::clone))?
                .ok_or_else(|| eyre!("No metadata entry with this key."))
        }
    }
}
