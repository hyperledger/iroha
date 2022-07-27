//! Module with permission for burning

use iroha_core::smartcontracts::permissions::ValidatorVerdict;
use iroha_data_model::asset::DefinitionId;

use super::*;

declare_token!(
    /// Can burn and unregister assets with the corresponding asset definition.
    CanBurnAssetWithDefinition {
        /// Asset definition id.
        asset_definition_id ("asset_definition_id"): DefinitionId,
    },
    "can_burn_asset_with_definition"
);

declare_token!(
    /// Can burn user's assets.
    CanBurnUserAssets {
        /// Asset id
        asset_id ("asset_id"): AssetId,
    },
    "can_burn_user_assets"
);

/// Checks that account can burn only the assets which were registered by this account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow to burn only the assets registered by the signer")]
pub struct OnlyAssetsCreatedByThisAccount;

impl IsAllowed for OnlyAssetsCreatedByThisAccount {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        match instruction {
            Instruction::Unregister(unregister) => {
                if let IdBox::AssetId(asset_id) = try_evaluate_or_deny!(unregister.object_id, wsv) {
                    let registered_by_signer_account = wsv
                        .asset_definition_entry(&asset_id.definition_id)
                        .map(|asset_definition_entry| {
                            asset_definition_entry.registered_by() == authority
                        })
                        .unwrap_or(false);
                    if !registered_by_signer_account {
                        return Deny(
                            "Can't unregister assets with definitions registered by other accounts.".to_owned()
                        );
                    }
                }
                Allow
            }
            Instruction::Burn(burn_box) => {
                let destination_id = try_evaluate_or_deny!(burn_box.destination_id, wsv);
                let asset_id: AssetId = ok_or_skip!(destination_id.try_into());
                let registered_by_signer_account = wsv
                    .asset_definition_entry(&asset_id.definition_id)
                    .map(|asset_definition_entry| {
                        asset_definition_entry.registered_by() == authority
                    })
                    .unwrap_or(false);
                if !registered_by_signer_account {
                    return Deny(
                        "Can't burn assets with definitions registered by other accounts."
                            .to_owned(),
                    );
                }
                Allow
            }
            _ => Skip,
        }
    }
}

/// Allows burning assets from a different account than the creator's of this asset if the corresponding user granted the permission token
/// for a specific asset.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct GrantedByAssetCreator;

impl HasToken for GrantedByAssetCreator {
    type Token = CanBurnAssetWithDefinition;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        match instruction {
            Instruction::Unregister(unregister) => {
                if let IdBox::AssetId(asset_id) = unregister
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                {
                    Ok(CanBurnAssetWithDefinition::new(asset_id.definition_id))
                } else {
                    Err("Expected the unregister asset instruction".to_owned())
                }
            }
            Instruction::Burn(burn_box) => {
                let destination_id = burn_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = if let Ok(dest_id) = destination_id.try_into() {
                    dest_id
                } else {
                    return Err("Destination is not an Asset.".to_owned());
                };

                Ok(CanBurnAssetWithDefinition::new(asset_id.definition_id))
            }
            _ => Err("Expected burn or unregister asset instruction".to_owned()),
        }
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the asset creator")]
pub struct GrantRegisteredByMeAccess;

impl IsGrantAllowed for GrantRegisteredByMeAccess {
    type Token = CanBurnAssetWithDefinition;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}

/// Checks that account can burn only the assets that he currently owns.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow to burn only the owned assets")]
pub struct OnlyOwnedAssets;

impl IsAllowed for OnlyOwnedAssets {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        match instruction {
            Instruction::Unregister(unregister) => {
                if let IdBox::AssetId(asset_id) = try_evaluate_or_deny!(unregister.object_id, wsv) {
                    if &asset_id.account_id != authority {
                        return Deny("Can't unregister assets from another account.".to_owned());
                    }
                }
                Allow
            }
            Instruction::Burn(burn_box) => {
                let destination_id = try_evaluate_or_deny!(burn_box.destination_id, wsv);
                let asset_id: AssetId = ok_or_skip!(destination_id.try_into());
                if &asset_id.account_id != authority {
                    return Deny("Can't burn assets from another account.".to_owned());
                }
                Allow
            }
            _ => Skip,
        }
    }
}

/// Allows burning user's assets from a different account if the corresponding user granted this permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantedByAssetOwner;

impl HasToken for GrantedByAssetOwner {
    type Token = CanBurnUserAssets;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        match instruction {
            Instruction::Unregister(unregister) => {
                if let IdBox::AssetId(asset_id) = unregister
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                {
                    Ok(CanBurnUserAssets::new(asset_id))
                } else {
                    Err("Expected the unregister asset instruction".to_owned())
                }
            }
            Instruction::Burn(burn_box) => {
                let destination_id = burn_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let destination_id: AssetId = if let Ok(dest_id) = destination_id.try_into() {
                    dest_id
                } else {
                    return Err("Source id is not an AssetId.".to_owned());
                };
                Ok(CanBurnUserAssets::new(destination_id))
            }
            _ => Err("Expected burn or unregister asset instruction".to_owned()),
        }
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the asset owner")]
pub struct GrantMyAssetAccess;

impl IsGrantAllowed for GrantMyAssetAccess {
    type Token = CanBurnUserAssets;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        _wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if &token.asset_id.account_id != authority {
            return Deny(
                "The signer does not own the account specified in the permission token.".to_owned(),
            );
        }

        Allow
    }
}
