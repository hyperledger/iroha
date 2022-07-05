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
#[derive(Debug, Copy, Clone, Serialize)]
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
                        return ValidatorVerdict::Deny(
                            "Can't unregister assets with definitions registered by other accounts.".to_owned().into()
                        );
                    }
                }
                ValidatorVerdict::Allow
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
                    return ValidatorVerdict::Deny(
                        "Can't burn assets with definitions registered by other accounts."
                            .to_owned()
                            .into(),
                    );
                }
                ValidatorVerdict::Allow
            }
            _ => ValidatorVerdict::Skip,
        }
    }
}

/// Allows burning assets from a different account than the creator's of this asset if the corresponding user granted the permission token
/// for a specific asset.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct GrantedByAssetCreator;

impl HasToken for GrantedByAssetCreator {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<PermissionToken, String> {
        match instruction {
            Instruction::Unregister(unregister) => {
                if let IdBox::AssetId(asset_id) = unregister
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                {
                    Ok(CanBurnAssetWithDefinition::new(asset_id.definition_id).into())
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

                Ok(CanBurnAssetWithDefinition::new(asset_id.definition_id).into())
            }
            _ => Err("Expected burn or unregister asset instruction".to_owned()),
        }
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantRegisteredByMeAccess;

impl IsGrantAllowed for GrantRegisteredByMeAccess {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let token: CanBurnAssetWithDefinition =
            ok_or_skip!(extract_specialized_token(instruction, wsv));

        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}

/// Checks that account can burn only the assets that he currently owns.
#[derive(Debug, Copy, Clone, Serialize)]
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
                        return ValidatorVerdict::Deny(
                            "Can't unregister assets from another account."
                                .to_owned()
                                .into(),
                        );
                    }
                }
                ValidatorVerdict::Allow
            }
            Instruction::Burn(burn_box) => {
                let destination_id = try_evaluate_or_deny!(burn_box.destination_id, wsv);
                let asset_id: AssetId = ok_or_skip!(destination_id.try_into());
                if &asset_id.account_id != authority {
                    return ValidatorVerdict::Deny(
                        "Can't burn assets from another account.".to_owned().into(),
                    );
                }
                ValidatorVerdict::Allow
            }
            _ => ValidatorVerdict::Skip,
        }
    }
}

/// Allows burning user's assets from a different account if the corresponding user granted this permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantedByAssetOwner;

impl HasToken for GrantedByAssetOwner {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<PermissionToken, String> {
        match instruction {
            Instruction::Unregister(unregister) => {
                if let IdBox::AssetId(asset_id) = unregister
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                {
                    Ok(CanBurnUserAssets::new(asset_id).into())
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
                Ok(CanBurnUserAssets::new(destination_id).into())
            }
            _ => Err("Expected burn or unregister asset instruction".to_owned()),
        }
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantMyAssetAccess;

impl IsGrantAllowed for GrantMyAssetAccess {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let token: CanBurnUserAssets = ok_or_skip!(extract_specialized_token(instruction, wsv));

        if &token.asset_id.account_id != authority {
            return ValidatorVerdict::Deny(
                "Asset specified in permission token is not owned by signer."
                    .to_owned()
                    .into(),
            );
        }

        ValidatorVerdict::Allow
    }
}
