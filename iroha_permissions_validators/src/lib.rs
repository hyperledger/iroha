//! Out of box implementations for common permission checks.

#![allow(clippy::module_name_repetitions)]

use std::convert::TryInto;

use iroha::{
    expression::Evaluate,
    permissions::{prelude::*, PermissionsValidator, PermissionsValidatorBuilder},
    prelude::*,
};
use iroha_data_model::{isi::*, prelude::*};

/// Permission checks asociated with use cases that can be summarized as public blockchains.
pub mod public_blockchain {
    use super::*;

    /// A preconfigured set of permissions for simple use cases.
    pub fn default_permissions() -> PermissionsValidatorBox {
        PermissionsValidatorBuilder::new()
            .with_recursive_validator(transfer::OnlyOwnedAssets)
            .with_recursive_validator(unregister::OnlyAssetsCreatedByThisAccount)
            .with_recursive_validator(mint::OnlyAssetsCreatedByThisAccount)
            .with_recursive_validator(burn::OnlyOwnedAssets)
            .with_recursive_validator(burn::OnlyAssetsCreatedByThisAccount)
            .with_recursive_validator(keyvalue::AccountSetOnlyForSignerAccount)
            .with_recursive_validator(keyvalue::AccountRemoveOnlyForSignerAccount)
            .with_recursive_validator(keyvalue::AssetSetOnlyForSignerAccount)
            .with_recursive_validator(keyvalue::AssetRemoveOnlyForSignerAccount)
            .build()
    }

    macro_rules! from_boxed_unit {
        ( $ty:ty ) => {
            impl From<$ty> for PermissionsValidatorBox {
                fn from(permissions: $ty) -> Self {
                    Box::new(permissions)
                }
            }
        };
    }
    macro_rules! try_into_or_exit {
        ( $ident:ident ) => {
            if let Ok(into) = $ident.try_into() {
                into
            } else {
                return Ok(());
            }
        };
    }

    pub mod transfer {
        //! Module with permission for transfering

        use super::*;

        /// Checks that account transfers only the assets that he owns.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyOwnedAssets;

        from_boxed_unit!(OnlyOwnedAssets);

        impl PermissionsValidator for OnlyOwnedAssets {
            fn check_instruction(
                &self,
                authority: AccountId,
                instruction: Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let transfer_box: TransferBox = try_into_or_exit!(instruction);
                let transfer_box = transfer_box
                    .source_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let source_id: AssetId = try_into_or_exit!(transfer_box);

                if source_id.account_id != authority {
                    return Err("Can't transfer assets of the other account.".to_owned());
                }
                Ok(())
            }
        }
    }

    pub mod unregister {
        //! Module with permission for unregistering

        use super::*;

        /// Checks that account can unregister only the assets which were registered by this account in the first place.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        from_boxed_unit!(OnlyAssetsCreatedByThisAccount);

        impl PermissionsValidator for OnlyAssetsCreatedByThisAccount {
            fn check_instruction(
                &self,
                authority: AccountId,
                instruction: Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction: UnregisterBox = try_into_or_exit!(instruction);
                let instruction = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_definition_id: AssetDefinitionId = try_into_or_exit!(instruction);

                let low_authority = wsv
                    .read_asset_definition_entry(&asset_definition_id)
                    .map_or(false, |asset_definiton_entry| {
                        asset_definiton_entry.registered_by != authority
                    });

                if low_authority {
                    return Err("Can't unregister assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }
    }

    pub mod mint {
        //! Module with permission for minting

        use super::*;

        /// Checks that account can mint only the assets which were registered by this account.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        from_boxed_unit!(OnlyAssetsCreatedByThisAccount);

        impl PermissionsValidator for OnlyAssetsCreatedByThisAccount {
            fn check_instruction(
                &self,
                authority: AccountId,
                instruction: Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction: MintBox = try_into_or_exit!(instruction);
                let instruction = instruction
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(instruction);

                let low_authority = wsv
                    .read_asset_definition_entry(&asset_id.definition_id)
                    .map_or(false, |asset_definiton_entry| {
                        asset_definiton_entry.registered_by != authority
                    });

                if low_authority {
                    return Err("Can't mint assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }
    }

    pub mod burn {
        //! Module with permission for burning

        use super::*;

        /// Checks that account can burn only the assets which were registered by this account.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        from_boxed_unit!(OnlyAssetsCreatedByThisAccount);

        impl PermissionsValidator for OnlyAssetsCreatedByThisAccount {
            fn check_instruction(
                &self,
                authority: AccountId,
                instruction: Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction: BurnBox = try_into_or_exit!(instruction);
                let instruction = instruction
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(instruction);

                let low_authority = wsv
                    .read_asset_definition_entry(&asset_id.definition_id)
                    .map_or(false, |asset_definiton_entry| {
                        asset_definiton_entry.registered_by != authority
                    });
                if low_authority {
                    return Err("Can't mint assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }

        /// Checks that account can burn only the assets that he currently owns.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyOwnedAssets;

        from_boxed_unit!(OnlyOwnedAssets);

        impl PermissionsValidator for OnlyOwnedAssets {
            fn check_instruction(
                &self,
                authority: AccountId,
                instruction: Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction: BurnBox = try_into_or_exit!(instruction);
                let instruction = instruction
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(instruction);
                if asset_id.account_id != authority {
                    return Err("Can't burn assets from another account.".to_owned());
                }
                Ok(())
            }
        }
    }

    pub mod keyvalue {
        //! Module with permission for burning

        use super::*;

        /// Checks that account can set keys for assets only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetSetOnlyForSignerAccount;

        from_boxed_unit!(AssetSetOnlyForSignerAccount);

        impl PermissionsValidator for AssetSetOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: AccountId,
                instruction: Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction: SetKeyValueBox = try_into_or_exit!(instruction);
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match object_id {
                    IdBox::AssetId(asset_id) if asset_id.account_id != authority => {
                        Err("Can't set value to asset store from another account.".to_owned())
                    }
                    _ => Ok(()),
                }
            }
        }

        /// Checks that account can set keys only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AccountSetOnlyForSignerAccount;

        from_boxed_unit!(AccountSetOnlyForSignerAccount);

        impl PermissionsValidator for AccountSetOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: AccountId,
                instruction: Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction: SetKeyValueBox = try_into_or_exit!(instruction);
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match object_id {
                    IdBox::AccountId(account_id) if account_id != authority => {
                        Err("Can't set value to account store from another account.".to_owned())
                    }
                    _ => Ok(()),
                }
            }
        }

        /// Checks that account can remove keys for assets only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetRemoveOnlyForSignerAccount;

        from_boxed_unit!(AssetRemoveOnlyForSignerAccount);

        impl PermissionsValidator for AssetRemoveOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: AccountId,
                instruction: Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction: RemoveKeyValueBox = try_into_or_exit!(instruction);
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match object_id {
                    IdBox::AssetId(asset_id) if asset_id.account_id != authority => {
                        Err("Can't remove value from asset store from another account.".to_owned())
                    }
                    _ => Ok(()),
                }
            }
        }

        /// Checks that account can remove keys only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AccountRemoveOnlyForSignerAccount;

        from_boxed_unit!(AccountRemoveOnlyForSignerAccount);

        impl PermissionsValidator for AccountRemoveOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: AccountId,
                instruction: Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction: RemoveKeyValueBox = try_into_or_exit!(instruction);
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match object_id {
                    IdBox::AccountId(account_id) if account_id != authority => Err(
                        "Can't remove value from account store from another account.".to_owned(),
                    ),
                    _ => Ok(()),
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use maplit::{btreemap, btreeset};

        use super::*;

        #[test]
        fn transfer_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "bob", "test");
            let wsv = WorldStateView::new(World::new());
            let transfer = Instruction::Transfer(TransferBox {
                source_id: IdBox::AssetId(alice_xor_id).into(),
                object: Value::U32(10).into(),
                destination_id: IdBox::AssetId(bob_xor_id).into(),
            });
            assert!(transfer::OnlyOwnedAssets
                .check_instruction(alice_id, transfer.clone(), &wsv)
                .is_ok());
            assert!(transfer::OnlyOwnedAssets
                .check_instruction(bob_id, transfer, &wsv)
                .is_err());
        }

        #[test]
        fn unregister_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_string() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_string(),
                    asset_definitions: btreemap! {
                        xor_id.clone() =>
                        AssetDefinitionEntry {
                            definition: xor_definition,
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let unregister =
                Instruction::Unregister(UnregisterBox::new(IdBox::AssetDefinitionId(xor_id)));
            assert!(unregister::OnlyAssetsCreatedByThisAccount
                .check_instruction(alice_id, unregister.clone(), &wsv)
                .is_ok());
            assert!(unregister::OnlyAssetsCreatedByThisAccount
                .check_instruction(bob_id, unregister, &wsv)
                .is_err());
        }

        #[test]
        fn mint_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_string() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_string(),
                    asset_definitions: btreemap! {
                        xor_id =>
                        AssetDefinitionEntry {
                            definition: xor_definition,
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let mint = Instruction::Mint(MintBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(mint::OnlyAssetsCreatedByThisAccount
                .check_instruction(alice_id, mint.clone(), &wsv)
                .is_ok());
            assert!(mint::OnlyAssetsCreatedByThisAccount
                .check_instruction(bob_id, mint, &wsv)
                .is_err());
        }

        #[test]
        fn burn_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_string() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_string(),
                    asset_definitions: btreemap! {
                        xor_id =>
                        AssetDefinitionEntry {
                            definition: xor_definition,
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let burn = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(burn::OnlyAssetsCreatedByThisAccount
                .check_instruction(alice_id, burn.clone(), &wsv)
                .is_ok());
            assert!(burn::OnlyAssetsCreatedByThisAccount
                .check_instruction(bob_id, burn, &wsv)
                .is_err());
        }

        #[test]
        fn burn_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let wsv = WorldStateView::new(World::new());
            let burn = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(burn::OnlyOwnedAssets
                .check_instruction(alice_id, burn.clone(), &wsv)
                .is_ok());
            assert!(burn::OnlyOwnedAssets
                .check_instruction(bob_id, burn, &wsv)
                .is_err());
        }

        #[test]
        fn set_to_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::SetKeyValue(SetKeyValueBox::new(
                IdBox::AssetId(alice_xor_id),
                Value::from("key".to_owned()),
                Value::from("value".to_owned()),
            ));
            assert!(keyvalue::AssetSetOnlyForSignerAccount
                .check_instruction(alice_id, set.clone(), &wsv)
                .is_ok());
            assert!(keyvalue::AssetSetOnlyForSignerAccount
                .check_instruction(bob_id, set, &wsv)
                .is_err());
        }

        #[test]
        fn remove_to_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
                IdBox::AssetId(alice_xor_id),
                Value::from("key".to_owned()),
            ));
            assert!(keyvalue::AssetRemoveOnlyForSignerAccount
                .check_instruction(alice_id, set.clone(), &wsv)
                .is_ok());
            assert!(keyvalue::AssetRemoveOnlyForSignerAccount
                .check_instruction(bob_id, set, &wsv)
                .is_err());
        }

        #[test]
        fn set_to_only_owned_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::SetKeyValue(SetKeyValueBox::new(
                IdBox::AccountId(alice_id.clone()),
                Value::from("key".to_owned()),
                Value::from("value".to_owned()),
            ));
            assert!(keyvalue::AccountSetOnlyForSignerAccount
                .check_instruction(alice_id, set.clone(), &wsv)
                .is_ok());
            assert!(keyvalue::AccountSetOnlyForSignerAccount
                .check_instruction(bob_id, set, &wsv)
                .is_err());
        }

        #[test]
        fn remove_to_only_owned_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
                IdBox::AccountId(alice_id.clone()),
                Value::from("key".to_owned()),
            ));
            assert!(keyvalue::AccountRemoveOnlyForSignerAccount
                .check_instruction(alice_id, set.clone(), &wsv)
                .is_ok());
            assert!(keyvalue::AccountRemoveOnlyForSignerAccount
                .check_instruction(bob_id, set, &wsv)
                .is_err());
        }
    }
}
