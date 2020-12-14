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
    permissions::{prelude::*, PermissionsValidator},
    prelude::*,
};
use iroha_data_model::{isi::*, prelude::*};

/// Permission checks asociated with use cases that can be summarized as public blockchains.
pub mod public_blockchain {
    use super::*;

    /// Checks that account transfers only the assets that he owns.
    #[derive(Debug, Copy, Clone)]
    pub struct TransferOnlyOwnedAssets;

    impl PermissionsValidator for TransferOnlyOwnedAssets {
        fn check_instruction(
            &self,
            authority: AccountId,
            instruction: InstructionBox,
            _wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            match instruction {
                InstructionBox::Transfer(TransferBox {
                    source_id: IdBox::AssetId(source_id),
                    object: ValueBox::U32(_),
                    destination_id: IdBox::AssetId(_),
                }) => {
                    if source_id.account_id == authority {
                        Ok(())
                    } else {
                        Err("Can't transfer assets of the other account.".to_string())
                    }
                }
                _ => Ok(()),
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
            instruction: InstructionBox,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            match instruction {
                InstructionBox::Unregister(UnregisterBox {
                    object: IdentifiableBox::AssetDefinition(asset_definition),
                    ..
                }) => {
                    if let Some(asset_definiton_entry) =
                        wsv.read_asset_definition_entry(&asset_definition.id)
                    {
                        if asset_definiton_entry.registered_by == authority {
                            Ok(())
                        } else {
                            Err("Can't unregister assets registered by other accounts.".to_string())
                        }
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            }
        }
    }

    /// Checks that account can mint only the assets which were registered by this account.
    #[derive(Debug, Copy, Clone)]
    pub struct MintOnlyAssetsCreatedByThisAccount;

    impl PermissionsValidator for MintOnlyAssetsCreatedByThisAccount {
        fn check_instruction(
            &self,
            authority: AccountId,
            instruction: InstructionBox,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            match instruction {
                InstructionBox::Mint(MintBox {
                    destination_id: IdBox::AssetId(asset_id),
                    ..
                }) => {
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
                }
                _ => Ok(()),
            }
        }
    }

    /// Checks that account can burn only the assets which were registered by this account.
    #[derive(Debug, Copy, Clone)]
    pub struct BurnOnlyAssetsCreatedByThisAccount;

    impl PermissionsValidator for BurnOnlyAssetsCreatedByThisAccount {
        fn check_instruction(
            &self,
            authority: AccountId,
            instruction: InstructionBox,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            match instruction {
                InstructionBox::Burn(BurnBox {
                    destination_id: IdBox::AssetId(asset_id),
                    ..
                }) => {
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
                }
                _ => Ok(()),
            }
        }
    }

    /// Checks that account can burn only the assets that he currently owns.
    #[derive(Debug, Copy, Clone)]
    pub struct BurnOnlyOwnedAssets;

    impl PermissionsValidator for BurnOnlyOwnedAssets {
        fn check_instruction(
            &self,
            authority: AccountId,
            instruction: InstructionBox,
            _wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            match instruction {
                InstructionBox::Burn(BurnBox {
                    destination_id: IdBox::AssetId(asset_id),
                    ..
                }) => {
                    if asset_id.account_id == authority {
                        Ok(())
                    } else {
                        Err("Can't burn assets from another account.".to_string())
                    }
                }
                _ => Ok(()),
            }
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
            let transfer = InstructionBox::Transfer(TransferBox {
                source_id: IdBox::AssetId(alice_xor_id),
                object: ValueBox::U32(10),
                destination_id: IdBox::AssetId(bob_xor_id),
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
            let xor_definition = AssetDefinition { id: xor_id.clone() };
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_string() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_string(),
                    asset_definitions: btreemap! {
                        xor_id.clone() =>
                        AssetDefinitionEntry {
                            definition: xor_definition.clone(),
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let unregister = InstructionBox::Unregister(UnregisterBox {
                object: IdentifiableBox::AssetDefinition(Box::new(xor_definition)),
                destination_id: IdBox::DomainName("test".to_string()),
            });
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
                        xor_id.clone() =>
                        AssetDefinitionEntry {
                            definition: xor_definition.clone(),
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let mint = InstructionBox::Mint(MintBox {
                object: ValueBox::U32(100),
                destination_id: IdBox::AssetId(alice_xor_id),
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
                        xor_id.clone() =>
                        AssetDefinitionEntry {
                            definition: xor_definition.clone(),
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let burn = InstructionBox::Burn(BurnBox {
                object: ValueBox::U32(100),
                destination_id: IdBox::AssetId(alice_xor_id),
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
            let burn = InstructionBox::Burn(BurnBox {
                object: ValueBox::U32(100),
                destination_id: IdBox::AssetId(alice_xor_id),
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
