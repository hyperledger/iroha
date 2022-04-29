//! Module with permission for minting
use iroha_data_model::asset::DefinitionId;

use super::*;

declare_token!(
    /// Can mint asset with the corresponding asset definition.
    CanMintUserAssetDefinitions {
        /// Asset definition id
        asset_definition_id ("asset_definition_id"): DefinitionId,
    },
    "can_mint_user_asset_definitions"
);

/// Checks that account can mint only the assets which were registered by this account.
#[derive(Debug, Copy, Clone)]
pub struct OnlyAssetsCreatedByThisAccount;

impl_from_item_for_instruction_validator_box!(OnlyAssetsCreatedByThisAccount);

impl<W: WorldTrait> IsAllowed<W, Instruction> for OnlyAssetsCreatedByThisAccount {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let mint_box = if let Instruction::Mint(mint) = instruction {
            mint
        } else {
            return Ok(());
        };
        let destination_id = mint_box
            .destination_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let asset_id: AssetId = try_into_or_exit!(destination_id);
        let registered_by_signer_account = wsv
            .asset_definition_entry(&asset_id.definition_id)
            .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
            .unwrap_or(false);
        if !registered_by_signer_account {
            return Err("Can't mint assets registered by other accounts.".to_owned());
        }
        Ok(())
    }
}

/// Allows minting assets from a different account if the corresponding user granted the permission token
/// for a specific asset.
#[derive(Debug, Clone, Copy)]
pub struct GrantedByAssetCreator;

impl_from_item_for_granted_token_validator_box!(GrantedByAssetCreator);

impl<W: WorldTrait> HasToken<W> for GrantedByAssetCreator {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        let mint_box = if let Instruction::Mint(mint) = instruction {
            mint
        } else {
            return Err("Instruction is not mint.".to_owned());
        };
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
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Clone, Copy)]
pub struct GrantRegisteredByMeAccess;

impl_from_item_for_grant_instruction_validator_box!(GrantRegisteredByMeAccess);

impl<W: WorldTrait> IsGrantAllowed<W> for GrantRegisteredByMeAccess {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let token: CanMintUserAssetDefinitions = extract_specialized_token(instruction, wsv)?;
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}
