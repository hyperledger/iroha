//! Module with permission for minting
use iroha_data_model::asset::DefinitionId;

use super::*;

declare_token!(
    /// Can register and mint assets with the corresponding asset definition.
    CanMintUserAssetDefinitions {
        /// Asset definition id
        asset_definition_id ("asset_definition_id"): DefinitionId,
    },
    "can_mint_user_asset_definitions"
);

/// Checks that account can mint only the assets which were registered by this account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow to mint only the assets created by the signer")]
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
            Instruction::Register(register) => {
                if let RegistrableBox::Asset(asset) = try_evaluate_or_deny!(register.object, wsv) {
                    let registered_by_signer_account = wsv
                        .asset_definition_entry(&asset.id().definition_id)
                        .map(|asset_definition_entry| {
                            asset_definition_entry.registered_by() == authority
                        })
                        .unwrap_or(false);

                    if !registered_by_signer_account {
                        return Deny(
                            "Can't register assets with definitions registered by other accounts."
                                .to_owned(),
                        );
                    }
                }
                Allow
            }
            Instruction::Mint(mint_box) => {
                let destination_id = try_evaluate_or_deny!(mint_box.destination_id, wsv);
                let asset_id: AssetId = ok_or_skip!(destination_id.try_into());
                let registered_by_signer_account = wsv
                    .asset_definition_entry(&asset_id.definition_id)
                    .map(|asset_definition_entry| {
                        asset_definition_entry.registered_by() == authority
                    })
                    .unwrap_or(false);
                if !registered_by_signer_account {
                    return Deny(
                        "Can't mint assets with definitions registered by other accounts."
                            .to_owned(),
                    );
                }
                Allow
            }
            _ => Skip,
        }
    }
}

/// Allows minting assets from a different account if the corresponding user granted the permission token
/// for a specific asset.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantedByAssetCreator;

impl HasToken for GrantedByAssetCreator {
    type Token = CanMintUserAssetDefinitions;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        match instruction {
            Instruction::Register(register) => {
                if let RegistrableBox::Asset(asset) = register
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                {
                    Ok(CanMintUserAssetDefinitions::new(
                        asset.id().definition_id.clone(),
                    ))
                } else {
                    Err("Expected the register asset instruction".to_owned())
                }
            }
            Instruction::Mint(mint_box) => {
                let destination_id = mint_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = if let Ok(dest_id) = destination_id.try_into() {
                    dest_id
                } else {
                    return Err("Destination is not an Asset.".to_owned());
                };
                Ok(CanMintUserAssetDefinitions::new(asset_id.definition_id))
            }
            _ => Err("Expected mint or register asset instruction".to_owned()),
        }
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the asset creator")]
pub struct GrantRegisteredByMeAccess;

impl IsGrantAllowed for GrantRegisteredByMeAccess {
    type Token = CanMintUserAssetDefinitions;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}
