//! This module contains implementations of smart-contract traits and instructions for [`Account`] structure
//! and implementations of [`Query`]'s about [`Account`].

use iroha_data_model::{prelude::*, query::error::FindError};
use iroha_telemetry::metrics;

use super::prelude::*;
use crate::ValidSingularQuery;

impl Registrable for iroha_data_model::account::NewAccount {
    type Target = Account;

    #[must_use]
    #[inline]
    fn build(self, _authority: &AccountId) -> Self::Target {
        self.into_account()
    }
}

/// All instructions related to accounts:
/// - minting/burning public key into account signatories
/// - minting/burning signature condition check
/// - update metadata
/// - grant permissions and roles
/// - Revoke permissions or roles
pub mod isi {
    use iroha_data_model::{
        asset::{AssetType, AssetValue},
        isi::{
            error::{MintabilityError, RepetitionError},
            InstructionType,
        },
        query::error::QueryExecutionFail,
    };
    use iroha_primitives::numeric::Numeric;

    use self::asset::isi::assert_numeric_spec;
    use super::*;
    use crate::{role::RoleIdWithOwner, state::StateTransaction};

    impl Execute for Register<Asset> {
        #[metrics(+"register_asset")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_id = self.object.id;

            match state_transaction.world.asset(&asset_id) {
                Err(err) => match err {
                    QueryExecutionFail::Find(FindError::Asset(_)) => {
                        assert_can_register(
                            &asset_id.definition,
                            state_transaction,
                            &self.object.value,
                        )?;
                        let asset = state_transaction
                            .world
                            .asset_or_insert(asset_id.clone(), self.object.value)
                            .expect("Account exists");

                        match asset.value {
                            AssetValue::Numeric(increment) => {
                                state_transaction
                                    .world
                                    .increase_asset_total_amount(&asset_id.definition, increment)?;
                            }
                            AssetValue::Store(_) => {
                                state_transaction.world.increase_asset_total_amount(
                                    &asset_id.definition,
                                    Numeric::ONE,
                                )?;
                            }
                        }
                        Ok(())
                    }
                    _ => Err(err.into()),
                },
                Ok(_) => Err(RepetitionError {
                    instruction: InstructionType::Register,
                    id: IdBox::AssetId(asset_id.clone()),
                }
                .into()),
            }
        }
    }

    impl Execute for Unregister<Asset> {
        #[metrics(+"unregister_asset")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_id = self.object;

            let asset = state_transaction
                .world
                .assets
                .remove(asset_id.clone())
                .ok_or_else(|| FindError::Asset(asset_id))?;

            match asset.value {
                AssetValue::Numeric(increment) => {
                    state_transaction
                        .world
                        .decrease_asset_total_amount(&asset.id.definition, increment)?;
                }
                AssetValue::Store(_) => {
                    state_transaction
                        .world
                        .decrease_asset_total_amount(&asset.id.definition, Numeric::ONE)?;
                }
            }

            state_transaction
                .world
                .emit_events(Some(AccountEvent::Asset(AssetEvent::Removed(
                    AssetChanged {
                        asset: asset.id,
                        amount: asset.value,
                    },
                ))));

            Ok(())
        }
    }

    impl Execute for Transfer<Account, AssetDefinitionId, Account> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let Transfer {
                source,
                object,
                destination,
            } = self;

            let _ = state_transaction.world.account(&source)?;
            let _ = state_transaction.world.account(&destination)?;

            let asset_definition = state_transaction.world.asset_definition_mut(&object)?;

            if asset_definition.owned_by != source {
                return Err(Error::Find(FindError::Account(source)));
            }

            asset_definition.owned_by = destination.clone();
            state_transaction
                .world
                .emit_events(Some(AssetDefinitionEvent::OwnerChanged(
                    AssetDefinitionOwnerChanged {
                        asset_definition: object,
                        new_owner: destination,
                    },
                )));

            Ok(())
        }
    }

    impl Execute for SetKeyValue<Account> {
        #[metrics(+"set_account_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.object;

            state_transaction
                .world
                .account_mut(&account_id)
                .map_err(Error::from)
                .map(|account| {
                    account
                        .metadata
                        .insert(self.key.clone(), self.value.clone())
                })?;

            state_transaction
                .world
                .emit_events(Some(AccountEvent::MetadataInserted(MetadataChanged {
                    target: account_id,
                    key: self.key,
                    value: self.value,
                })));

            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Account> {
        #[metrics(+"remove_account_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.object;

            let value = state_transaction
                .world
                .account_mut(&account_id)
                .and_then(|account| {
                    account
                        .metadata
                        .remove(&self.key)
                        .ok_or_else(|| FindError::MetadataKey(self.key.clone()))
                })?;

            state_transaction
                .world
                .emit_events(Some(AccountEvent::MetadataRemoved(MetadataChanged {
                    target: account_id,
                    key: self.key,
                    value,
                })));

            Ok(())
        }
    }

    impl Execute for Grant<Permission, Account> {
        #[metrics(+"grant_account_permission")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.destination;
            let permission = self.object;

            // Check if account exists
            state_transaction.world.account_mut(&account_id)?;

            if state_transaction
                .world
                .account_contains_inherent_permission(&account_id, &permission)
            {
                return Err(RepetitionError {
                    instruction: InstructionType::Grant,
                    id: permission.into(),
                }
                .into());
            }

            state_transaction
                .world
                .add_account_permission(&account_id, permission.clone());

            state_transaction
                .world
                .emit_events(Some(AccountEvent::PermissionAdded(
                    AccountPermissionChanged {
                        account: account_id,
                        permission,
                    },
                )));

            Ok(())
        }
    }

    impl Execute for Revoke<Permission, Account> {
        #[metrics(+"revoke_account_permission")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.destination;
            let permission = self.object;

            // Check if account exists
            state_transaction.world.account(&account_id)?;

            if !state_transaction
                .world
                .remove_account_permission(&account_id, &permission)
            {
                return Err(FindError::Permission(permission).into());
            }

            state_transaction
                .world
                .emit_events(Some(AccountEvent::PermissionRemoved(
                    AccountPermissionChanged {
                        account: account_id,
                        permission,
                    },
                )));

            Ok(())
        }
    }

    impl Execute for Grant<RoleId, Account> {
        #[metrics(+"grant_account_role")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.destination;
            let role_id = self.object;

            let permissions = state_transaction
                .world
                .roles
                .get(&role_id)
                .ok_or_else(|| FindError::Role(role_id.clone()))?
                .permissions
                .clone();

            state_transaction.world.account(&account_id)?;

            if state_transaction
                .world
                .account_roles
                .insert(
                    RoleIdWithOwner::new(account_id.clone(), role_id.clone()),
                    (),
                )
                .is_some()
            {
                return Err(RepetitionError {
                    instruction: InstructionType::Grant,
                    id: IdBox::RoleId(role_id),
                }
                .into());
            }

            state_transaction.world.emit_events({
                let account_id_clone = account_id.clone();
                permissions
                    .into_iter()
                    .zip(core::iter::repeat_with(move || account_id.clone()))
                    .map(|(permission, account_id)| AccountPermissionChanged {
                        account: account_id,
                        permission,
                    })
                    .map(AccountEvent::PermissionAdded)
                    .chain(std::iter::once(AccountEvent::RoleGranted(
                        AccountRoleChanged {
                            account: account_id_clone,
                            role: role_id,
                        },
                    )))
            });

            Ok(())
        }
    }

    impl Execute for Revoke<RoleId, Account> {
        #[metrics(+"revoke_account_role")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.destination;
            let role_id = self.object;

            let permissions = state_transaction
                .world
                .roles
                .get(&role_id)
                .ok_or_else(|| FindError::Role(role_id.clone()))?
                .permissions
                .clone();

            if state_transaction
                .world
                .account_roles
                .remove(RoleIdWithOwner {
                    account: account_id.clone(),
                    id: role_id.clone(),
                })
                .is_none()
            {
                return Err(FindError::Role(role_id).into());
            }

            state_transaction.world.emit_events({
                let account_id_clone = account_id.clone();
                permissions
                    .into_iter()
                    .zip(core::iter::repeat_with(move || account_id.clone()))
                    .map(|(permission, account_id)| AccountPermissionChanged {
                        account: account_id,
                        permission,
                    })
                    .map(AccountEvent::PermissionRemoved)
                    .chain(std::iter::once(AccountEvent::RoleRevoked(
                        AccountRoleChanged {
                            account: account_id_clone,
                            role: role_id,
                        },
                    )))
            });

            Ok(())
        }
    }

    /// Assert that this asset can be registered to an account.
    fn assert_can_register(
        definition_id: &AssetDefinitionId,
        state_transaction: &mut StateTransaction<'_, '_>,
        value: &AssetValue,
    ) -> Result<(), Error> {
        let expected_asset_type = match value.type_() {
            AssetType::Numeric(_) => asset::isi::expected_asset_type_numeric,
            AssetType::Store => asset::isi::expected_asset_type_store,
        };
        let definition =
            asset::isi::assert_asset_type(definition_id, state_transaction, expected_asset_type)?;
        if let AssetValue::Numeric(numeric) = value {
            assert_numeric_spec(numeric, &definition)?;
        }

        match definition.mintable {
            Mintable::Infinitely => Ok(()),
            Mintable::Not => Err(Error::Mintability(MintabilityError::MintUnmintable)),
            Mintable::Once => {
                if !value.is_zero_value() {
                    let asset_definition = state_transaction
                        .world
                        .asset_definition_mut(definition_id)?;
                    forbid_minting(asset_definition)?;
                    state_transaction.world.emit_events(Some(
                        AssetDefinitionEvent::MintabilityChanged(definition_id.clone()),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Stop minting on the [`AssetDefinition`] globally.
    ///
    /// # Errors
    /// If the [`AssetDefinition`] is not `Mintable::Once`.
    #[inline]
    pub fn forbid_minting(definition: &mut AssetDefinition) -> Result<(), MintabilityError> {
        if definition.mintable == Mintable::Once {
            definition.mintable = Mintable::Not;
            Ok(())
        } else {
            Err(MintabilityError::ForbidMintOnMintable)
        }
    }

    #[cfg(test)]
    mod test {
        use iroha_data_model::{prelude::AssetDefinition, ParseError};
        use test_samples::gen_account_in;

        use crate::smartcontracts::isi::Registrable as _;

        #[test]
        fn cannot_forbid_minting_on_asset_mintable_infinitely() -> Result<(), ParseError> {
            let (authority, _authority_keypair) = gen_account_in("wonderland");
            let mut definition = AssetDefinition::numeric("test#hello".parse()?).build(&authority);
            assert!(super::forbid_minting(&mut definition).is_err());
            Ok(())
        }
    }
}

/// Account-related [`Query`] instructions.
pub mod query {

    use eyre::Result;
    use iroha_data_model::{
        account::Account,
        permission::Permission,
        query::{
            error::QueryExecutionFail as Error,
            predicate::{
                predicate_atoms::{
                    account::AccountPredicateBox, permission::PermissionPredicateBox,
                    role::RoleIdPredicateBox,
                },
                CompoundPredicate,
            },
        },
    };
    use iroha_primitives::json::JsonString;

    use super::*;
    use crate::{smartcontracts::ValidQuery, state::StateReadOnly};

    impl ValidQuery for FindRolesByAccountId {
        #[metrics(+"find_roles_by_account_id")]
        fn execute<'state>(
            self,
            filter: CompoundPredicate<RoleIdPredicateBox>,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<impl Iterator<Item = RoleId> + 'state, Error> {
            let account_id = &self.id;
            state_ro.world().account(account_id)?;
            Ok(state_ro
                .world()
                .account_roles_iter(account_id)
                .filter(move |&role_id| filter.applies(role_id))
                .cloned())
        }
    }

    impl ValidQuery for FindPermissionsByAccountId {
        #[metrics(+"find_permissions_by_account_id")]
        fn execute<'state>(
            self,
            filter: CompoundPredicate<PermissionPredicateBox>,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Permission> + 'state, Error> {
            let account_id = &self.id;
            Ok(state_ro
                .world()
                .account_permissions_iter(account_id)?
                .filter(move |&permission| filter.applies(permission))
                .cloned())
        }
    }

    impl ValidQuery for FindAccounts {
        #[metrics(+"find_accounts")]
        fn execute<'state>(
            self,
            filter: CompoundPredicate<AccountPredicateBox>,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Account> + 'state, Error> {
            Ok(state_ro
                .world()
                .accounts_iter()
                .filter(move |&account| filter.applies(account))
                .cloned())
        }
    }

    impl ValidSingularQuery for FindAccountMetadata {
        #[metrics(+"find_account_key_value_by_id_and_key")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<JsonString, Error> {
            let id = &self.id;
            let key = &self.key;
            iroha_logger::trace!(%id, %key);
            state_ro
                .world()
                .map_account(id, |account| account.metadata.get(key).cloned())?
                .ok_or_else(|| FindError::MetadataKey(key.clone()).into())
                .map(Into::into)
        }
    }

    impl ValidQuery for FindAccountsWithAsset {
        #[metrics(+"find_accounts_with_asset")]
        fn execute<'state>(
            self,
            filter: CompoundPredicate<AccountPredicateBox>,
            state_ro: &'state impl StateReadOnly,
        ) -> std::result::Result<impl Iterator<Item = Account> + 'state, Error> {
            let asset_definition_id = self.asset_definition.clone();
            iroha_logger::trace!(%asset_definition_id);

            Ok(state_ro
                .world()
                .accounts_iter()
                .filter(move |account| {
                    state_ro
                        .world()
                        .assets()
                        .get(&AssetId::new(
                            asset_definition_id.clone(),
                            account.id().clone(),
                        ))
                        .is_some()
                })
                .filter(move |&account| filter.applies(account))
                .cloned())
        }
    }
}
