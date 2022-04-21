//! This module contains implementations of smart-contract traits and instructions for [`Account`] structure
//! and implementations of [`Query`]'s to [`WorldStateView<W>`] about [`Account`].

use iroha_data_model::prelude::*;
use iroha_telemetry::metrics;

use crate::{ValidQuery, WorldStateView};

/// All instructions related to accounts:
/// - minting/burning public key into account signatories
/// - minting/burning signature condition check
/// - update metadata
/// - grant permissions and roles
/// - Revoke permissions or roles
pub mod isi {
    use super::{super::prelude::*, *};

    impl<W: WorldTrait> Execute<W> for Mint<Account, PublicKey> {
        type Error = Error;

        #[metrics(+"mint_account_pubkey")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.destination_id;
            let public_key = self.object;

            wsv.modify_account(&account_id, |account| {
                if account.contains_signatory(&public_key) {
                    return Err(
                        ValidationError::new("Account already contains this signatory").into(),
                    );
                }

                account.add_signatory(public_key);
                Ok(AccountEvent::AuthenticationAdded(account_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Account, PublicKey> {
        type Error = Error;

        #[metrics(+"burn_account_pubkey")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.destination_id;
            let public_key = self.object;

            wsv.modify_account(&account_id, |account| {
                if account.signatories().len() < 2 {
                    return Err(ValidationError::new(
                        "Public keys cannot be burned to nothing. If you want to delete the account, please use an unregister instruction.",
                    ).into());
                }
                if !account.remove_signatory(&public_key) {
                    return Err(ValidationError::new("Public key not found").into())
                }

                Ok(AccountEvent::AuthenticationRemoved(account_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Account, SignatureCheckCondition> {
        type Error = Error;

        #[metrics(+"mint_account_signature_check_condition")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.destination_id;
            let signature_check_condition = self.object;

            wsv.modify_account(&account_id, |account| {
                account.set_signature_check_condition(signature_check_condition);
                Ok(AccountEvent::AuthenticationAdded(account_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<Account, Name, Value> {
        type Error = Error;

        #[metrics(+"set_key_value_account_string_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.object_id;

            wsv.modify_account(&account_id, |account| {
                let account_metadata_limits = wsv.config.account_metadata_limits;

                account.metadata_mut().insert_with_limits(
                    self.key,
                    self.value,
                    account_metadata_limits,
                )?;

                Ok(AccountEvent::MetadataInserted(account_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<Account, Name> {
        type Error = Error;

        #[metrics(+"remove_account_key_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.object_id;

            wsv.modify_account(&account_id, |account| {
                account
                    .metadata_mut()
                    .remove(&self.key)
                    .ok_or(FindError::MetadataKey(self.key))?;

                Ok(AccountEvent::MetadataRemoved(account_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Grant<Account, PermissionToken> {
        type Error = Error;

        #[metrics(+"grant_account_permission_token")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.destination_id;
            let permission = self.object;

            wsv.modify_account(&account_id.clone(), |account| {
                if account.contains_permission(&permission) {
                    return Err(ValidationError::new("Permission already exists").into());
                }

                account.add_permission(permission);
                Ok(AccountEvent::PermissionAdded(account_id))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Revoke<Account, PermissionToken> {
        type Error = Error;

        #[metrics(+"revoke_account_permission_token")]
        fn execute(
            self,
            _authority: AccountId,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.destination_id;
            let permission = self.object;

            wsv.modify_account(&account_id, |account| {
                if !account.remove_permission(&permission) {
                    return Err(ValidationError::new("Permission not found").into());
                }

                Ok(AccountEvent::PermissionRemoved(account_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Grant<Account, RoleId> {
        type Error = Error;

        #[metrics(+"grant_account_role")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.destination_id;
            let role_id = self.object;

            wsv.world()
                .roles
                .get(&role_id)
                .ok_or_else(|| FindError::Role(role_id.clone()))?;

            wsv.modify_account(&account_id.clone(), |account| {
                if !account.add_role(role_id.clone()) {
                    return Err(Error::Repetition(
                        InstructionType::Grant,
                        IdBox::RoleId(role_id),
                    ));
                }

                Ok(AccountEvent::PermissionAdded(account_id))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Revoke<Account, RoleId> {
        type Error = Error;

        #[metrics(+"revoke_account_role")]
        fn execute(
            self,
            _authority: AccountId,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.destination_id;
            let role_id = self.object;

            wsv.world()
                .roles
                .get(&role_id)
                .ok_or_else(|| FindError::Role(role_id.clone()))?;

            wsv.modify_account(&account_id.clone(), |account| {
                if !account.remove_role(&role_id) {
                    return Err(Error::Find(Box::new(FindError::Account(account_id))));
                }

                Ok(AccountEvent::PermissionRemoved(account_id))
            })
        }
    }
}

/// Account-related [`Query`] instructions.
pub mod query {

    use eyre::{Result, WrapErr};
    use iroha_logger::prelude::*;

    use super::{super::Evaluate, *};
    use crate::smartcontracts::{isi::prelude::WorldTrait, query::Error, FindError};

    impl<W: WorldTrait> ValidQuery<W> for FindRolesByAccountId {
        #[log]
        #[metrics(+"find_roles_by_account_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let account_id = self
                .id
                .evaluate(wsv, &Context::new())
                .wrap_err("Failed to evaluate account id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let roles = wsv.map_account(&account_id, |account| {
                account.roles().cloned().collect::<Vec<_>>()
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let tokens = wsv.map_account(&account_id, |account| {
                wsv.account_permission_tokens(account)
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
                for account in domain.accounts() {
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts() {
                    if account.id().name == name {
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            Ok(wsv.domain(&id)?.accounts().cloned().collect::<Vec<_>>())
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            wsv.map_account(&id, |account| {
                account.metadata().get(&key).map(Clone::clone)
            })?
            .ok_or_else(|| query::Error::Find(Box::new(FindError::MetadataKey(key))))
        }
    }
}
