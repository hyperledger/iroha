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
#[derive(Debug, Copy, Clone, Serialize)]
pub struct OnlyAssetsCreatedByThisAccount;

impl_from_item_for_instruction_validator_box!(OnlyAssetsCreatedByThisAccount);

impl IsAllowed<Instruction> for OnlyAssetsCreatedByThisAccount {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<()> {
        match instruction {
            Instruction::Register(register) => {
                if let RegistrableBox::Asset(asset) = register
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                {
                    let registered_by_signer_account = wsv
                        .asset_definition_entry(&asset.id().definition_id)
                        .map(|asset_definition_entry| {
                            asset_definition_entry.registered_by() == authority
                        })
                        .unwrap_or(false);

                    if !registered_by_signer_account {
                        return Err(
                            "Can't register assets with definitions registered by other accounts."
                                .to_owned()
                                .into(),
                        );
                    }
                }
                Ok(())
            }
            Instruction::Mint(mint_box) => {
                let destination_id = mint_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(destination_id);
                let registered_by_signer_account = wsv
                    .asset_definition_entry(&asset_id.definition_id)
                    .map(|asset_definition_entry| {
                        asset_definition_entry.registered_by() == authority
                    })
                    .unwrap_or(false);
                if !registered_by_signer_account {
                    return Err(
                        "Can't mint assets with definitions registered by other accounts."
                            .to_owned()
                            .into(),
                    );
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Allows minting assets from a different account if the corresponding user granted the permission token
/// for a specific asset.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantedByAssetCreator;

impl_from_item_for_granted_token_validator_box!(GrantedByAssetCreator);

impl HasToken for GrantedByAssetCreator {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<PermissionToken, String> {
        match instruction {
            Instruction::Register(register) => {
                if let RegistrableBox::Asset(asset) = register
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                {
                    Ok(CanMintUserAssetDefinitions::new(asset.id().definition_id.clone()).into())
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
                Ok(CanMintUserAssetDefinitions::new(asset_id.definition_id).into())
            }
            _ => Err("Expected mint or register asset instruction".to_owned()),
        }
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantRegisteredByMeAccess;

impl_from_item_for_grant_instruction_validator_box!(GrantRegisteredByMeAccess);

impl IsGrantAllowed for GrantRegisteredByMeAccess {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView,
    ) -> Result<()> {
        let token: CanMintUserAssetDefinitions = extract_specialized_token(instruction, wsv)?;
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}
