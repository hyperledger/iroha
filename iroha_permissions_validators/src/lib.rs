//! Out of box implementations for common permission checks.

#![warn(
    anonymous_parameters,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    private_doc_tests,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    future_incompatible,
    nonstandard_style,
    unsafe_code,
    unused_import_braces,
    unused_results,
    variant_size_differences
)]

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
            .with_recursive_validator(TransferOnlyOwnedAssets.into())
            .with_recursive_validator(UnregisterOnlyAssetsCreatedByThisAccount.into())
            .with_recursive_validator(MintOnlyAssetsCreatedByThisAccount.into())
            .with_recursive_validator(BurnOnlyOwnedAssets.into())
            .with_recursive_validator(BurnOnlyAssetsCreatedByThisAccount.into())
            .build()
    }

    /// Checks that account transfers only the assets that he owns.
    #[derive(Debug, Copy, Clone)]
    pub struct TransferOnlyOwnedAssets;

    impl PermissionsValidator for TransferOnlyOwnedAssets {
        fn check_instruction(
            &self,
            authority: AccountId,
            instruction: Instruction,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            if let Instruction::Transfer(transfer_box) = instruction {
                if let IdBox::AssetId(source_id) =
                    transfer_box.source_id.evaluate(wsv, &Context::new())?
                {
                    if source_id.account_id == authority {
                        Ok(())
                    } else {
                        Err("Can't transfer assets of the other account.".to_string())
                    }
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        }
    }

    impl From<TransferOnlyOwnedAssets> for PermissionsValidatorBox {
        fn from(_: TransferOnlyOwnedAssets) -> Self {
            Box::new(TransferOnlyOwnedAssets)
        }
    }

    /// Checks that account can unregister only the assets which were registered by this account in the first place.
    #[derive(Debug, Copy, Clone)]
    pub struct UnregisterOnlyAssetsCreatedByThisAccount;

    impl PermissionsValidator for UnregisterOnlyAssetsCreatedByThisAccount {
        fn check_instruction(
            &self,
            authority: AccountId,
            instruction: Instruction,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            if let Instruction::Unregister(instruction) = instruction {
                if let IdBox::AssetDefinitionId(asset_definition_id) =
                    instruction.object_id.evaluate(wsv, &Context::new())?
                {
                    if let Some(asset_definiton_entry) =
                        wsv.read_asset_definition_entry(&asset_definition_id)
                    {
                        if asset_definiton_entry.registered_by == authority {
                            Ok(())
                        } else {
                            Err("Can't unregister assets registered by other accounts.".to_string())
                        }
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        }
    }

    impl From<UnregisterOnlyAssetsCreatedByThisAccount> for PermissionsValidatorBox {
        fn from(_: UnregisterOnlyAssetsCreatedByThisAccount) -> Self {
            Box::new(UnregisterOnlyAssetsCreatedByThisAccount)
        }
    }

    /// Checks that account can mint only the assets which were registered by this account.
    #[derive(Debug, Copy, Clone)]
    pub struct MintOnlyAssetsCreatedByThisAccount;

    impl PermissionsValidator for MintOnlyAssetsCreatedByThisAccount {
        fn check_instruction(
            &self,
            authority: AccountId,
            instruction: Instruction,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            if let Instruction::Mint(instruction) = instruction {
                if let IdBox::AssetId(asset_id) =
                    instruction.destination_id.evaluate(wsv, &Context::new())?
                {
                    if let Some(asset_definiton_entry) =
                        wsv.read_asset_definition_entry(&asset_id.definition_id)
                    {
                        if asset_definiton_entry.registered_by == authority {
                            Ok(())
                        } else {
                            Err("Can't mint assets registered by other accounts.".to_string())
                        }
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        }
    }

    impl From<MintOnlyAssetsCreatedByThisAccount> for PermissionsValidatorBox {
        fn from(_: MintOnlyAssetsCreatedByThisAccount) -> Self {
            Box::new(MintOnlyAssetsCreatedByThisAccount)
        }
    }

    /// Checks that account can burn only the assets which were registered by this account.
    #[derive(Debug, Copy, Clone)]
    pub struct BurnOnlyAssetsCreatedByThisAccount;

    impl PermissionsValidator for BurnOnlyAssetsCreatedByThisAccount {
        fn check_instruction(
            &self,
            authority: AccountId,
            instruction: Instruction,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            if let Instruction::Burn(instruction) = instruction {
                if let IdBox::AssetId(asset_id) =
                    instruction.destination_id.evaluate(wsv, &Context::new())?
                {
                    if let Some(asset_definiton_entry) =
                        wsv.read_asset_definition_entry(&asset_id.definition_id)
                    {
                        if asset_definiton_entry.registered_by == authority {
                            Ok(())
                        } else {
                            Err("Can't mint assets registered by other accounts.".to_string())
                        }
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        }
    }

    impl From<BurnOnlyAssetsCreatedByThisAccount> for PermissionsValidatorBox {
        fn from(_: BurnOnlyAssetsCreatedByThisAccount) -> Self {
            Box::new(BurnOnlyAssetsCreatedByThisAccount)
        }
    }

    /// Checks that account can burn only the assets that he currently owns.
    #[derive(Debug, Copy, Clone)]
    pub struct BurnOnlyOwnedAssets;

    impl PermissionsValidator for BurnOnlyOwnedAssets {
        fn check_instruction(
            &self,
            authority: AccountId,
            instruction: Instruction,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            if let Instruction::Burn(instruction) = instruction {
                if let IdBox::AssetId(asset_id) =
                    instruction.destination_id.evaluate(wsv, &Context::new())?
                {
                    if asset_id.account_id == authority {
                        Ok(())
                    } else {
                        Err("Can't burn assets from another account.".to_string())
                    }
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        }
    }

    impl From<BurnOnlyOwnedAssets> for PermissionsValidatorBox {
        fn from(_: BurnOnlyOwnedAssets) -> Self {
            Box::new(BurnOnlyOwnedAssets)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use maplit::{btreemap, btreeset};

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
            assert!(TransferOnlyOwnedAssets
                .check_instruction(alice_id, transfer.clone(), &wsv)
                .is_ok());
            assert!(TransferOnlyOwnedAssets
                .check_instruction(bob_id, transfer, &wsv)
                .is_err());
        }

        #[test]
        fn unregister_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new(xor_id.clone());
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
            assert!(UnregisterOnlyAssetsCreatedByThisAccount
                .check_instruction(alice_id, unregister.clone(), &wsv)
                .is_ok());
            assert!(UnregisterOnlyAssetsCreatedByThisAccount
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
            let xor_definition = AssetDefinition { id: xor_id.clone() };
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
            assert!(MintOnlyAssetsCreatedByThisAccount
                .check_instruction(alice_id, mint.clone(), &wsv)
                .is_ok());
            assert!(MintOnlyAssetsCreatedByThisAccount
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
            let xor_definition = AssetDefinition { id: xor_id.clone() };
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
            assert!(BurnOnlyAssetsCreatedByThisAccount
                .check_instruction(alice_id, burn.clone(), &wsv)
                .is_ok());
            assert!(BurnOnlyAssetsCreatedByThisAccount
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
            assert!(BurnOnlyOwnedAssets
                .check_instruction(alice_id, burn.clone(), &wsv)
                .is_ok());
            assert!(BurnOnlyOwnedAssets
                .check_instruction(bob_id, burn, &wsv)
                .is_err());
        }
    }
}
