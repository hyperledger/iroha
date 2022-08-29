//! Permission checks asociated with use cases that can be summarized as public blockchains.

use iroha_core::smartcontracts::permissions::Result;
use iroha_macro::{FromVariant, VariantCount};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::*;

pub mod burn;
pub mod key_value;
pub mod mint;
pub mod transfer;
pub mod unregister;

/// Enum listing preconfigured permission tokens
#[derive(
    Debug, Clone, Encode, Decode, Serialize, Deserialize, FromVariant, IntoSchema, VariantCount,
)]
pub enum PredefinedPermissionToken {
    /// Can burn asset with the corresponding asset definition.
    BurnAssetWithDefinition(burn::CanBurnAssetWithDefinition),
    /// Can burn user's assets permission token name.
    BurnUserAssets(burn::CanBurnUserAssets),
    /// Can set key value in user's assets permission token name.
    SetKeyValueInUserAssets(key_value::CanSetKeyValueInUserAssets),
    /// Can remove key value in user's assets permission token name.
    RemoveKeyValueInUserAssets(key_value::CanRemoveKeyValueInUserAssets),
    /// Can set key value in user metadata
    SetKeyValueInUserMetadata(key_value::CanSetKeyValueInUserMetadata),
    /// Can remove key value in user metadata
    RemoveKeyValueInUserMetadata(key_value::CanRemoveKeyValueInUserMetadata),
    /// Can set key value in the corresponding asset definition.
    SetKeyValueInAssetDefinition(key_value::CanSetKeyValueInAssetDefinition),
    /// Can remove key value in the corresponding asset definition.
    RemoveKeyValueInAssetDefinition(key_value::CanRemoveKeyValueInAssetDefinition),
    /// Can mint asset with the corresponding asset definition.
    MintUserAssetDefinitions(mint::CanMintUserAssetDefinitions),
    /// Can transfer user's assets
    TransferUserAssets(transfer::CanTransferUserAssets),
    /// Can transfer only fixed number of times per some time period
    TransferOnlyFixedNumberOfTimesPerPeriod(transfer::CanTransferOnlyFixedNumberOfTimesPerPeriod),
    /// Can un-register asset with the corresponding asset definition.
    UnregisterAssetWithDefinition(unregister::CanUnregisterAssetWithDefinition),
}

impl From<PredefinedPermissionToken> for PermissionToken {
    fn from(value: PredefinedPermissionToken) -> Self {
        match value {
            PredefinedPermissionToken::BurnAssetWithDefinition(inner) => inner.into(),
            PredefinedPermissionToken::BurnUserAssets(inner) => inner.into(),
            PredefinedPermissionToken::SetKeyValueInUserAssets(inner) => inner.into(),
            PredefinedPermissionToken::RemoveKeyValueInUserAssets(inner) => inner.into(),
            PredefinedPermissionToken::SetKeyValueInUserMetadata(inner) => inner.into(),
            PredefinedPermissionToken::RemoveKeyValueInUserMetadata(inner) => inner.into(),
            PredefinedPermissionToken::SetKeyValueInAssetDefinition(inner) => inner.into(),
            PredefinedPermissionToken::RemoveKeyValueInAssetDefinition(inner) => inner.into(),
            PredefinedPermissionToken::MintUserAssetDefinitions(inner) => inner.into(),
            PredefinedPermissionToken::TransferUserAssets(inner) => inner.into(),
            PredefinedPermissionToken::TransferOnlyFixedNumberOfTimesPerPeriod(inner) => {
                inner.into()
            }
            PredefinedPermissionToken::UnregisterAssetWithDefinition(inner) => inner.into(),
        }
    }
}

/// List ids of all predefined permission tokens, e.g. for easier
/// registration in genesis block.
pub fn default_permission_token_definitions(
) -> [&'static PermissionTokenDefinition; PredefinedPermissionToken::VARIANT_COUNT] {
    [
        unregister::CanUnregisterAssetWithDefinition::definition(),
        burn::CanBurnAssetWithDefinition::definition(),
        burn::CanBurnUserAssets::definition(),
        key_value::CanSetKeyValueInUserAssets::definition(),
        key_value::CanRemoveKeyValueInUserAssets::definition(),
        key_value::CanSetKeyValueInUserMetadata::definition(),
        key_value::CanRemoveKeyValueInUserMetadata::definition(),
        key_value::CanSetKeyValueInAssetDefinition::definition(),
        key_value::CanRemoveKeyValueInAssetDefinition::definition(),
        mint::CanMintUserAssetDefinitions::definition(),
        transfer::CanTransferUserAssets::definition(),
        transfer::CanTransferOnlyFixedNumberOfTimesPerPeriod::definition(),
    ]
}

/// A preconfigured set of permissions for simple use cases.
pub fn default_permissions() -> InstructionJudgeBoxed {
    // Grant instruction checks are or unioned, so that if one permission validator approves this Grant it will succeed.
    let grant_instruction_validator =
        JudgeBuilder::with_validator(transfer::GrantMyAssetAccess.into_validator())
            .with_validator(unregister::GrantRegisteredByMeAccess.into_validator())
            .with_validator(mint::GrantRegisteredByMeAccess.into_validator())
            .with_validator(burn::GrantMyAssetAccess.into_validator())
            .with_validator(burn::GrantRegisteredByMeAccess.into_validator())
            .with_validator(key_value::GrantMyAssetAccessRemove.into_validator())
            .with_validator(key_value::GrantMyAssetAccessSet.into_validator())
            .with_validator(key_value::GrantMyMetadataAccessSet.into_validator())
            .with_validator(key_value::GrantMyMetadataAccessRemove.into_validator())
            .with_validator(key_value::GrantMyAssetDefinitionSet.into_validator())
            .with_validator(key_value::GrantMyAssetDefinitionRemove.into_validator())
            .no_denies()
            .disable_display_of_operation_on_error()
            .build()
            .into_validator()
            .display_as("Grant validator");
    Box::new(
        JudgeBuilder::with_recursive_validator(grant_instruction_validator)
            .with_recursive_validator(
                transfer::OnlyOwnedAssets.or(transfer::GrantedByAssetOwner.into_validator()),
            )
            .with_recursive_validator(
                unregister::OnlyAssetsCreatedByThisAccount
                    .or(unregister::GrantedByAssetCreator.into_validator()),
            )
            .with_recursive_validator(
                mint::OnlyAssetsCreatedByThisAccount
                    .or(mint::GrantedByAssetCreator.into_validator()),
            )
            .with_recursive_validator(
                burn::OnlyOwnedAssets.or(burn::GrantedByAssetOwner.into_validator()),
            )
            .with_recursive_validator(
                burn::OnlyAssetsCreatedByThisAccount
                    .or(burn::GrantedByAssetCreator.into_validator()),
            )
            .with_recursive_validator(
                key_value::AccountSetOnlyForSignerAccount
                    .or(key_value::SetGrantedByAccountOwner.into_validator()),
            )
            .with_recursive_validator(
                key_value::AccountRemoveOnlyForSignerAccount
                    .or(key_value::RemoveGrantedByAccountOwner.into_validator()),
            )
            .with_recursive_validator(
                key_value::AssetSetOnlyForSignerAccount
                    .or(key_value::SetGrantedByAssetOwner.into_validator()),
            )
            .with_recursive_validator(
                key_value::AssetRemoveOnlyForSignerAccount
                    .or(key_value::RemoveGrantedByAssetOwner.into_validator()),
            )
            .with_recursive_validator(
                key_value::AssetDefinitionSetOnlyForSignerAccount
                    .or(key_value::SetGrantedByAssetDefinitionOwner.into_validator()),
            )
            .with_recursive_validator(
                key_value::AssetDefinitionRemoveOnlyForSignerAccount
                    .or(key_value::RemoveGrantedByAssetDefinitionOwner.into_validator()),
            )
            .no_denies()
            .at_least_one_allow()
            .build(),
    )
}

/// Checks that asset creator is `authority` in the supplied `definition_id`.
///
/// # Errors
/// - Asset creator is not `authority`
pub fn check_asset_creator_for_asset_definition(
    definition_id: &AssetDefinitionId,
    authority: &AccountId,
    wsv: &WorldStateView,
) -> ValidatorVerdict {
    let registered_by_signer_account = wsv
        .asset_definition_entry(definition_id)
        .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
        .unwrap_or(false);
    if !registered_by_signer_account {
        return Deny("Cannot grant access for assets registered by another account.".to_owned());
    }
    Allow
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{
        collections::{BTreeSet, HashSet},
        str::FromStr as _,
    };

    use iroha_core::wsv::World;

    use super::*;

    fn new_xor_definition(xor_id: &AssetDefinitionId) -> AssetDefinition {
        AssetDefinition::quantity(xor_id.clone()).build()
    }

    #[test]
    fn transfer_only_owned_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let bob_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("bob@test").expect("Valid"),
        );
        let wsv = WorldStateView::new(World::new());
        let transfer = Instruction::Transfer(TransferBox {
            source_id: IdBox::AssetId(alice_xor_id).into(),
            object: Value::U32(10).into(),
            destination_id: IdBox::AssetId(bob_xor_id).into(),
        });
        assert!(transfer::OnlyOwnedAssets
            .check(&alice_id, &transfer, &wsv)
            .is_allow());
        assert!(transfer::OnlyOwnedAssets
            .check(&bob_id, &transfer, &wsv)
            .is_deny());
    }

    #[test]
    fn transfer_granted_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let bob_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("bob@test").expect("Valid"),
        );
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        let bob_account = Account::new(bob_id.clone(), []).build();
        assert!(domain.add_account(bob_account).is_none());
        let wsv = WorldStateView::new(World::with([domain], BTreeSet::new()));
        assert!(wsv.add_account_permission(
            &bob_id,
            transfer::CanTransferUserAssets::new(alice_xor_id.clone()).into()
        ));
        let transfer = Instruction::Transfer(TransferBox {
            source_id: IdBox::AssetId(alice_xor_id).into(),
            object: Value::U32(10).into(),
            destination_id: IdBox::AssetId(bob_xor_id).into(),
        });
        let validator =
            transfer::OnlyOwnedAssets.or(transfer::GrantedByAssetOwner.into_validator());
        assert!(validator.check(&alice_id, &transfer, &wsv).is_allow());
        assert!(validator.check(&bob_id, &transfer, &wsv).is_allow());
    }

    #[test]
    fn grant_transfer_of_my_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let permission_token_to_alice: PermissionToken =
            transfer::CanTransferUserAssets::new(alice_xor_id).into();
        let wsv = WorldStateView::new(World::new());
        let grant = Instruction::Grant(GrantBox::new(
            permission_token_to_alice,
            IdBox::AccountId(bob_id.clone()),
        ));
        let validator = transfer::GrantMyAssetAccess.into_validator();
        assert!(validator.check(&alice_id, &grant, &wsv).is_allow());
        assert!(validator.check(&bob_id, &grant, &wsv).is_deny());
    }

    #[test]
    fn unregister_only_assets_created_by_this_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let domain_id = DomainId::from_str("test").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], []));
        let unregister =
            Instruction::Unregister(UnregisterBox::new(IdBox::AssetDefinitionId(xor_id)));
        assert!(unregister::OnlyAssetsCreatedByThisAccount
            .check(&alice_id, &unregister, &wsv)
            .is_allow());
        assert!(unregister::OnlyAssetsCreatedByThisAccount
            .check(&bob_id, &unregister, &wsv)
            .is_deny());
    }

    #[test]
    fn unregister_granted_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        let bob_account = Account::new(bob_id.clone(), []).build();
        assert!(domain.add_account(bob_account).is_none());
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], []));
        let instruction = Instruction::Unregister(UnregisterBox::new(xor_id.clone()));
        let validator = unregister::OnlyAssetsCreatedByThisAccount
            .or(unregister::GrantedByAssetCreator.into_validator());
        assert!(wsv.add_account_permission(
            &bob_id,
            unregister::CanUnregisterAssetWithDefinition::new(xor_id).into()
        ));
        assert!(validator.check(&alice_id, &instruction, &wsv).is_allow());
        assert!(validator.check(&bob_id, &instruction, &wsv).is_allow());
    }

    #[test]
    fn grant_unregister_of_assets_created_by_this_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let permission_token_to_alice: PermissionToken =
            unregister::CanUnregisterAssetWithDefinition::new(xor_id).into();
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());

        let wsv = WorldStateView::new(World::with([domain], []));
        let grant = Instruction::Grant(GrantBox {
            object: permission_token_to_alice.into(),
            destination_id: IdBox::AccountId(bob_id.clone()).into(),
        });
        let validator = unregister::GrantRegisteredByMeAccess.into_validator();
        assert!(validator.check(&alice_id, &grant, &wsv).is_allow());
        assert!(validator.check(&bob_id, &grant, &wsv).is_deny());
    }

    #[test]
    fn mint_only_assets_created_by_this_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let domain_id = DomainId::from_str("test").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], []));
        let mint = Instruction::Mint(MintBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        assert!(mint::OnlyAssetsCreatedByThisAccount
            .check(&alice_id, &mint, &wsv)
            .is_allow());
        assert!(mint::OnlyAssetsCreatedByThisAccount
            .check(&bob_id, &mint, &wsv)
            .is_deny());
    }

    #[test]
    fn mint_granted_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        let bob_account = Account::new(bob_id.clone(), []).build();
        assert!(domain.add_account(bob_account).is_none());
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], []));
        assert!(wsv.add_account_permission(
            &bob_id,
            mint::CanMintUserAssetDefinitions::new(xor_id).into()
        ));
        let instruction = Instruction::Mint(MintBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        let validator =
            mint::OnlyAssetsCreatedByThisAccount.or(mint::GrantedByAssetCreator.into_validator());
        assert!(validator.check(&alice_id, &instruction, &wsv).is_allow());
        assert!(validator.check(&bob_id, &instruction, &wsv).is_allow());
    }

    #[test]
    fn grant_mint_of_assets_created_by_this_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let permission_token_to_alice: PermissionToken =
            mint::CanMintUserAssetDefinitions::new(xor_id).into();
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], vec![]));
        let grant = Instruction::Grant(GrantBox {
            object: permission_token_to_alice.into(),
            destination_id: IdBox::AccountId(bob_id.clone()).into(),
        });
        let validator = mint::GrantRegisteredByMeAccess.into_validator();
        assert!(validator.check(&alice_id, &grant, &wsv).is_allow());
        assert!(validator.check(&bob_id, &grant, &wsv).is_deny());
    }

    #[test]
    fn burn_only_assets_created_by_this_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let domain_id = DomainId::from_str("test").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], []));
        let burn = Instruction::Burn(BurnBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        assert!(burn::OnlyAssetsCreatedByThisAccount
            .check(&alice_id, &burn, &wsv)
            .is_allow());
        assert!(burn::OnlyAssetsCreatedByThisAccount
            .check(&bob_id, &burn, &wsv)
            .is_deny());
    }

    #[test]
    fn burn_granted_asset_definition() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        let bob_account = Account::new(bob_id.clone(), []).build();
        assert!(domain.add_account(bob_account).is_none());
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], vec![]));
        assert!(wsv.add_account_permission(
            &bob_id,
            burn::CanBurnAssetWithDefinition::new(xor_id).into()
        ));
        let instruction = Instruction::Burn(BurnBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        let validator =
            burn::OnlyAssetsCreatedByThisAccount.or(burn::GrantedByAssetCreator.into_validator());
        assert!(validator.check(&alice_id, &instruction, &wsv).is_allow());
        assert!(validator.check(&bob_id, &instruction, &wsv).is_allow());
    }

    #[test]
    fn grant_burn_of_assets_created_by_this_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let permission_token_to_alice: PermissionToken =
            burn::CanBurnAssetWithDefinition::new(xor_id).into();
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], vec![]));
        let grant = Instruction::Grant(GrantBox {
            object: permission_token_to_alice.into(),
            destination_id: IdBox::AccountId(bob_id.clone()).into(),
        });
        let validator = burn::GrantRegisteredByMeAccess.into_validator();
        assert!(validator.check(&alice_id, &grant, &wsv).is_allow());
        assert!(validator.check(&bob_id, &grant, &wsv).is_deny());
    }

    #[test]
    fn burn_only_owned_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let wsv = WorldStateView::new(World::new());
        let burn = Instruction::Burn(BurnBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        assert!(burn::OnlyOwnedAssets
            .check(&alice_id, &burn, &wsv)
            .is_allow());
        assert!(burn::OnlyOwnedAssets.check(&bob_id, &burn, &wsv).is_deny());
    }

    #[test]
    fn burn_granted_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        let bob_account = Account::new(bob_id.clone(), []).build();
        assert!(domain.add_account(bob_account).is_none());
        let wsv = WorldStateView::new(World::with([domain], vec![]));
        assert!(wsv.add_account_permission(
            &bob_id,
            burn::CanBurnUserAssets::new(alice_xor_id.clone()).into()
        ));
        let transfer = Instruction::Burn(BurnBox {
            object: Value::U32(10).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        let validator = burn::OnlyOwnedAssets.or(burn::GrantedByAssetOwner.into_validator());
        assert!(validator.check(&alice_id, &transfer, &wsv).is_allow());
        assert!(validator.check(&bob_id, &transfer, &wsv).is_allow());
    }

    #[test]
    fn grant_burn_of_my_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let permission_token_to_alice: PermissionToken =
            burn::CanBurnUserAssets::new(alice_xor_id).into();
        let wsv = WorldStateView::new(World::new());
        let grant = Instruction::Grant(GrantBox::new(
            permission_token_to_alice,
            IdBox::AccountId(bob_id.clone()),
        ));
        let validator = burn::GrantMyAssetAccess.into_validator();
        assert!(validator.check(&alice_id, &grant, &wsv).is_allow());
        assert!(validator.check(&bob_id, &grant, &wsv).is_deny());
    }

    #[test]
    fn set_to_only_owned_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let wsv = WorldStateView::new(World::new());
        let key: Name = "key".parse().expect("Valid");
        let set = Instruction::SetKeyValue(SetKeyValueBox::new(
            IdBox::AssetId(alice_xor_id),
            key,
            Value::from("value".to_owned()),
        ));
        assert!(key_value::AssetSetOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_allow());
        assert!(key_value::AssetSetOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_deny());
    }

    #[test]
    fn remove_to_only_owned_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let wsv = WorldStateView::new(World::new());
        let key: Name = "key".parse().expect("Valid");
        let set =
            Instruction::RemoveKeyValue(RemoveKeyValueBox::new(IdBox::AssetId(alice_xor_id), key));
        assert!(key_value::AssetRemoveOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_allow());
        assert!(key_value::AssetRemoveOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_deny());
    }

    #[test]
    fn set_to_only_owned_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let wsv = WorldStateView::new(World::new());
        let key: Name = "key".parse().expect("Valid");
        let set = Instruction::SetKeyValue(SetKeyValueBox::new(
            IdBox::AccountId(alice_id.clone()),
            key,
            Value::from("value".to_owned()),
        ));
        assert!(key_value::AccountSetOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_allow());
        assert!(key_value::AccountSetOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_deny());
    }

    #[test]
    fn remove_to_only_owned_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let wsv = WorldStateView::new(World::new());
        let key: Name = "key".parse().expect("Valid");
        let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
            IdBox::AccountId(alice_id.clone()),
            key,
        ));
        assert!(key_value::AccountRemoveOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_allow());
        assert!(key_value::AccountRemoveOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_deny());
    }

    #[test]
    fn set_to_only_owned_asset_definition() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let domain_id = DomainId::from_str("test").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], []));
        let key: Name = "key".parse().expect("Valid");
        let set = Instruction::SetKeyValue(SetKeyValueBox::new(
            IdBox::AssetDefinitionId(xor_id),
            key,
            Value::from("value".to_owned()),
        ));
        assert!(key_value::AssetDefinitionSetOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_allow());
        assert!(key_value::AssetDefinitionSetOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_deny());
    }

    #[test]
    fn remove_to_only_owned_asset_definition() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let domain_id = DomainId::from_str("test").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::new(World::with([domain], []));
        let key: Name = "key".parse().expect("Valid");
        let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
            IdBox::AssetDefinitionId(xor_id),
            key,
        ));
        assert!(key_value::AssetDefinitionRemoveOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_allow());
        assert!(key_value::AssetDefinitionRemoveOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_deny());
    }

    #[test]
    fn default_permission_token_definitions_are_unique() {
        let permissions_set = HashSet::from(default_permission_token_definitions());
        assert_eq!(
            permissions_set.len(),
            default_permission_token_definitions().len()
        );
    }
}
