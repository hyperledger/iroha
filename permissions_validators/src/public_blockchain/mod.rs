//! Permission checks asociated with use cases that can be summarized as public blockchains.

use iroha_macro::FromVariant;
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
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, FromVariant, IntoSchema)]
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

/// A preconfigured set of permissions for simple use cases.
pub fn default_permissions<W: WorldTrait>() -> IsInstructionAllowedBoxed<W> {
    // Grant instruction checks are or unioned, so that if one permission validator approves this Grant it will succeed.
    let grant_instruction_validator = ValidatorBuilder::new()
        .with_validator(transfer::GrantMyAssetAccess)
        .with_validator(unregister::GrantRegisteredByMeAccess)
        .with_validator(mint::GrantRegisteredByMeAccess)
        .with_validator(burn::GrantMyAssetAccess)
        .with_validator(burn::GrantRegisteredByMeAccess)
        .with_validator(key_value::GrantMyAssetAccessRemove)
        .with_validator(key_value::GrantMyAssetAccessSet)
        .with_validator(key_value::GrantMyMetadataAccessSet)
        .with_validator(key_value::GrantMyMetadataAccessRemove)
        .with_validator(key_value::GrantMyAssetDefinitionSet)
        .with_validator(key_value::GrantMyAssetDefinitionRemove)
        .any_should_succeed("Grant instruction validator.");
    ValidatorBuilder::new()
        .with_recursive_validator(grant_instruction_validator)
        .with_recursive_validator(transfer::OnlyOwnedAssets.or(transfer::GrantedByAssetOwner))
        .with_recursive_validator(
            unregister::OnlyAssetsCreatedByThisAccount.or(unregister::GrantedByAssetCreator),
        )
        .with_recursive_validator(
            mint::OnlyAssetsCreatedByThisAccount.or(mint::GrantedByAssetCreator),
        )
        .with_recursive_validator(burn::OnlyOwnedAssets.or(burn::GrantedByAssetOwner))
        .with_recursive_validator(
            burn::OnlyAssetsCreatedByThisAccount.or(burn::GrantedByAssetCreator),
        )
        .with_recursive_validator(
            key_value::AccountSetOnlyForSignerAccount.or(key_value::SetGrantedByAccountOwner),
        )
        .with_recursive_validator(
            key_value::AccountRemoveOnlyForSignerAccount.or(key_value::RemoveGrantedByAccountOwner),
        )
        .with_recursive_validator(
            key_value::AssetSetOnlyForSignerAccount.or(key_value::SetGrantedByAssetOwner),
        )
        .with_recursive_validator(
            key_value::AssetRemoveOnlyForSignerAccount.or(key_value::RemoveGrantedByAssetOwner),
        )
        .with_recursive_validator(
            key_value::AssetDefinitionSetOnlyForSignerAccount
                .or(key_value::SetGrantedByAssetDefinitionOwner),
        )
        .with_recursive_validator(
            key_value::AssetDefinitionRemoveOnlyForSignerAccount
                .or(key_value::RemoveGrantedByAssetDefinitionOwner),
        )
        .all_should_succeed()
}

/// Extracts specialized token from `GrantBox`
///
/// # Errors
/// - Cannot evaluate `instruction`
/// - `instruction` doesn't evaluate to `PermissionToken`
/// - Generic `PermissionToken` can't be converted to requested specialized token.
pub fn extract_specialized_token<T, W>(
    instruction: &GrantBox,
    wsv: &WorldStateView<W>,
) -> Result<T, String>
where
    T: TryFrom<PermissionToken, Error = PredefinedTokenConversionError>,
    W: iroha_core::wsv::WorldTrait,
{
    let permission_token: PermissionToken = instruction
        .object
        .evaluate(wsv, &Context::new())
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;

    let specialized_token: T = permission_token
        .try_into()
        .map_err(|e: PredefinedTokenConversionError| e.to_string())?;

    Ok(specialized_token)
}

/// Checks that asset creator is `authority` in the supplied `definition_id`.
///
/// # Errors
/// - Asset creator is not `authority`
pub fn check_asset_creator_for_asset_definition<W: WorldTrait>(
    definition_id: &AssetDefinitionId,
    authority: &AccountId,
    wsv: &WorldStateView<W>,
) -> Result<(), String> {
    let registered_by_signer_account = wsv
        .asset_definition_entry(definition_id)
        .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
        .unwrap_or(false);
    if !registered_by_signer_account {
        return Err("Can not grant access for assets, registered by another account.".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{collections::BTreeSet, str::FromStr as _};

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
        let wsv = WorldStateView::<World>::new(World::new());
        let transfer = Instruction::Transfer(TransferBox {
            source_id: IdBox::AssetId(alice_xor_id).into(),
            object: Value::U32(10).into(),
            destination_id: IdBox::AssetId(bob_xor_id).into(),
        });
        assert!(transfer::OnlyOwnedAssets
            .check(&alice_id, &transfer, &wsv)
            .is_ok());
        assert!(transfer::OnlyOwnedAssets
            .check(&bob_id, &transfer, &wsv)
            .is_err());
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
        let mut bob_account = Account::new(bob_id.clone(), []).build();
        assert!(bob_account
            .add_permission(transfer::CanTransferUserAssets::new(alice_xor_id.clone()).into()));
        assert!(domain.add_account(bob_account).is_none());
        let wsv = WorldStateView::<World>::new(World::with([domain], BTreeSet::new()));
        let transfer = Instruction::Transfer(TransferBox {
            source_id: IdBox::AssetId(alice_xor_id).into(),
            object: Value::U32(10).into(),
            destination_id: IdBox::AssetId(bob_xor_id).into(),
        });
        let validator: IsInstructionAllowedBoxed<World> = transfer::OnlyOwnedAssets
            .or(transfer::GrantedByAssetOwner)
            .into();
        assert!(validator.check(&alice_id, &transfer, &wsv).is_ok());
        assert!(validator.check(&bob_id, &transfer, &wsv).is_ok());
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
        let wsv = WorldStateView::<World>::new(World::new());
        let grant = Instruction::Grant(GrantBox::new(
            permission_token_to_alice,
            IdBox::AccountId(bob_id.clone()),
        ));
        let validator: IsInstructionAllowedBoxed<World> = transfer::GrantMyAssetAccess.into();
        assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
        assert!(validator.check(&bob_id, &grant, &wsv).is_err());
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
        let wsv = WorldStateView::<World>::new(World::with([domain], []));
        let unregister =
            Instruction::Unregister(UnregisterBox::new(IdBox::AssetDefinitionId(xor_id)));
        assert!(unregister::OnlyAssetsCreatedByThisAccount
            .check(&alice_id, &unregister, &wsv)
            .is_ok());
        assert!(unregister::OnlyAssetsCreatedByThisAccount
            .check(&bob_id, &unregister, &wsv)
            .is_err());
    }

    #[test]
    fn unregister_granted_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let xor_id = AssetDefinitionId::from_str("xor#test").expect("Valid");
        let xor_definition = new_xor_definition(&xor_id);
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        let mut bob_account = Account::new(bob_id.clone(), []).build();
        assert!(bob_account.add_permission(
            unregister::CanUnregisterAssetWithDefinition::new(xor_id.clone()).into()
        ));
        assert!(domain.add_account(bob_account).is_none());
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::<World>::new(World::with([domain], []));
        let instruction = Instruction::Unregister(UnregisterBox::new(xor_id));
        let validator: IsInstructionAllowedBoxed<World> =
            unregister::OnlyAssetsCreatedByThisAccount
                .or(unregister::GrantedByAssetCreator)
                .into();
        assert!(validator.check(&alice_id, &instruction, &wsv).is_ok());
        assert!(validator.check(&bob_id, &instruction, &wsv).is_ok());
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

        let wsv = WorldStateView::<World>::new(World::with([domain], []));
        let grant = Instruction::Grant(GrantBox {
            object: permission_token_to_alice.into(),
            destination_id: IdBox::AccountId(bob_id.clone()).into(),
        });
        let validator: IsInstructionAllowedBoxed<World> =
            unregister::GrantRegisteredByMeAccess.into();
        assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
        assert!(validator.check(&bob_id, &grant, &wsv).is_err());
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
        let wsv = WorldStateView::<World>::new(World::with([domain], []));
        let mint = Instruction::Mint(MintBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        assert!(mint::OnlyAssetsCreatedByThisAccount
            .check(&alice_id, &mint, &wsv)
            .is_ok());
        assert!(mint::OnlyAssetsCreatedByThisAccount
            .check(&bob_id, &mint, &wsv)
            .is_err());
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
        let mut bob_account = Account::new(bob_id.clone(), []).build();
        assert!(bob_account.add_permission(mint::CanMintUserAssetDefinitions::new(xor_id).into()));
        assert!(domain.add_account(bob_account).is_none());
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::<World>::new(World::with([domain], []));
        let instruction = Instruction::Mint(MintBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        let validator: IsInstructionAllowedBoxed<World> = mint::OnlyAssetsCreatedByThisAccount
            .or(mint::GrantedByAssetCreator)
            .into();
        assert!(validator.check(&alice_id, &instruction, &wsv).is_ok());
        assert!(validator.check(&bob_id, &instruction, &wsv).is_ok());
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
        let wsv = WorldStateView::<World>::new(World::with([domain], vec![]));
        let grant = Instruction::Grant(GrantBox {
            object: permission_token_to_alice.into(),
            destination_id: IdBox::AccountId(bob_id.clone()).into(),
        });
        let validator: IsInstructionAllowedBoxed<World> = mint::GrantRegisteredByMeAccess.into();
        assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
        assert!(validator.check(&bob_id, &grant, &wsv).is_err());
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
        let wsv = WorldStateView::<World>::new(World::with([domain], []));
        let burn = Instruction::Burn(BurnBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        assert!(burn::OnlyAssetsCreatedByThisAccount
            .check(&alice_id, &burn, &wsv)
            .is_ok());
        assert!(burn::OnlyAssetsCreatedByThisAccount
            .check(&bob_id, &burn, &wsv)
            .is_err());
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
        let mut bob_account = Account::new(bob_id.clone(), []).build();
        assert!(bob_account.add_permission(burn::CanBurnAssetWithDefinition::new(xor_id).into()));
        assert!(domain.add_account(bob_account).is_none());
        assert!(domain
            .add_asset_definition(xor_definition, alice_id.clone())
            .is_none());
        let wsv = WorldStateView::<World>::new(World::with([domain], vec![]));
        let instruction = Instruction::Burn(BurnBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        let validator: IsInstructionAllowedBoxed<World> = burn::OnlyAssetsCreatedByThisAccount
            .or(burn::GrantedByAssetCreator)
            .into();
        assert!(validator.check(&alice_id, &instruction, &wsv).is_ok());
        assert!(validator.check(&bob_id, &instruction, &wsv).is_ok());
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
        let wsv = WorldStateView::<World>::new(World::with([domain], vec![]));
        let grant = Instruction::Grant(GrantBox {
            object: permission_token_to_alice.into(),
            destination_id: IdBox::AccountId(bob_id.clone()).into(),
        });
        let validator: IsInstructionAllowedBoxed<World> = burn::GrantRegisteredByMeAccess.into();
        assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
        assert!(validator.check(&bob_id, &grant, &wsv).is_err());
    }

    #[test]
    fn burn_only_owned_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let wsv = WorldStateView::<World>::new(World::new());
        let burn = Instruction::Burn(BurnBox {
            object: Value::U32(100).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        assert!(burn::OnlyOwnedAssets.check(&alice_id, &burn, &wsv).is_ok());
        assert!(burn::OnlyOwnedAssets.check(&bob_id, &burn, &wsv).is_err());
    }

    #[test]
    fn burn_granted_assets() -> Result<(), String> {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        let mut bob_account = Account::new(bob_id.clone(), []).build();
        assert!(
            bob_account.add_permission(burn::CanBurnUserAssets::new(alice_xor_id.clone()).into())
        );
        assert!(domain.add_account(bob_account).is_none());
        let wsv = WorldStateView::<World>::new(World::with([domain], vec![]));
        let transfer = Instruction::Burn(BurnBox {
            object: Value::U32(10).into(),
            destination_id: IdBox::AssetId(alice_xor_id).into(),
        });
        let validator: IsInstructionAllowedBoxed<World> =
            burn::OnlyOwnedAssets.or(burn::GrantedByAssetOwner).into();
        validator.check(&alice_id, &transfer, &wsv)?;
        assert!(validator.check(&bob_id, &transfer, &wsv).is_ok());
        Ok(())
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
        let wsv = WorldStateView::<World>::new(World::new());
        let grant = Instruction::Grant(GrantBox::new(
            permission_token_to_alice,
            IdBox::AccountId(bob_id.clone()),
        ));
        let validator: IsInstructionAllowedBoxed<World> = burn::GrantMyAssetAccess.into();
        assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
        assert!(validator.check(&bob_id, &grant, &wsv).is_err());
    }

    #[test]
    fn set_to_only_owned_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let wsv = WorldStateView::<World>::new(World::new());
        let set = Instruction::SetKeyValue(SetKeyValueBox::new(
            IdBox::AssetId(alice_xor_id),
            Value::from("key".to_owned()),
            Value::from("value".to_owned()),
        ));
        assert!(key_value::AssetSetOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_ok());
        assert!(key_value::AssetSetOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_err());
    }

    #[test]
    fn remove_to_only_owned_assets() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let wsv = WorldStateView::<World>::new(World::new());
        let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
            IdBox::AssetId(alice_xor_id),
            Value::from("key".to_owned()),
        ));
        assert!(key_value::AssetRemoveOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_ok());
        assert!(key_value::AssetRemoveOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_err());
    }

    #[test]
    fn set_to_only_owned_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let wsv = WorldStateView::<World>::new(World::new());
        let set = Instruction::SetKeyValue(SetKeyValueBox::new(
            IdBox::AccountId(alice_id.clone()),
            Value::from("key".to_owned()),
            Value::from("value".to_owned()),
        ));
        assert!(key_value::AccountSetOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_ok());
        assert!(key_value::AccountSetOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_err());
    }

    #[test]
    fn remove_to_only_owned_account() {
        let alice_id = AccountId::from_str("alice@test").expect("Valid");
        let bob_id = AccountId::from_str("bob@test").expect("Valid");
        let wsv = WorldStateView::<World>::new(World::new());
        let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
            IdBox::AccountId(alice_id.clone()),
            Value::from("key".to_owned()),
        ));
        assert!(key_value::AccountRemoveOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_ok());
        assert!(key_value::AccountRemoveOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_err());
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
        let wsv = WorldStateView::<World>::new(World::with([domain], []));
        let set = Instruction::SetKeyValue(SetKeyValueBox::new(
            IdBox::AssetDefinitionId(xor_id),
            Value::from("key".to_owned()),
            Value::from("value".to_owned()),
        ));
        assert!(key_value::AssetDefinitionSetOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_ok());
        assert!(key_value::AssetDefinitionSetOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_err());
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
        let wsv = WorldStateView::<World>::new(World::with([domain], []));
        let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
            IdBox::AssetDefinitionId(xor_id),
            Value::from("key".to_owned()),
        ));
        assert!(key_value::AssetDefinitionRemoveOnlyForSignerAccount
            .check(&alice_id, &set, &wsv)
            .is_ok());
        assert!(key_value::AssetDefinitionRemoveOnlyForSignerAccount
            .check(&bob_id, &set, &wsv)
            .is_err());
    }
}
