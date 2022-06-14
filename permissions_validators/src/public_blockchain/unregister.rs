//! Module with permission for unregistering
use iroha_data_model::asset::DefinitionId;

use super::*;

declare_token!(
    /// Can un-register asset with the corresponding asset definition.
    CanUnregisterAssetWithDefinition {
        /// Asset definition id
        asset_definition_id ("asset_definition_id"): DefinitionId,
    },
    "can_unregister_asset_with_definition"
);

/// Checks that account can un-register only the assets which were
/// registered by this account in the first place.
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
        let unregister_box = if let Instruction::Unregister(unregister) = instruction {
            unregister
        } else {
            return Ok(());
        };
        let object_id = unregister_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let asset_definition_id: AssetDefinitionId = try_into_or_exit!(object_id);
        let registered_by_signer_account = wsv
            .asset_definition_entry(&asset_definition_id)
            .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
            .unwrap_or(false);
        if !registered_by_signer_account {
            return Err("Can't unregister assets registered by other accounts."
                .to_owned()
                .into());
        }
        Ok(())
    }
}

/// Allows un-registering a user's assets from a different account if
/// the corresponding user granted the permission token for a specific
/// asset.
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
        let unregister_box = if let Instruction::Unregister(unregister) = instruction {
            unregister
        } else {
            return Err("Instruction is not unregister.".to_owned());
        };
        let object_id = unregister_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AssetDefinitionId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AssetDefinitionId.".to_owned());
        };
        Ok(CanUnregisterAssetWithDefinition::new(object_id).into())
    }
}

/// Validator that checks Grant instruction so that the access is
/// granted to the assets of the signer account.
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
        let token: CanUnregisterAssetWithDefinition = extract_specialized_token(instruction, wsv)?;
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}

/// Validator that checks Revoke instructions, such that the access is
/// revoked and the assets of the signer's account are no longer
/// accessible.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RevokeRegisteredByMeAccess;

impl_from_item_for_revoke_instruction_validator_box!(RevokeRegisteredByMeAccess);

impl IsRevokeAllowed for RevokeRegisteredByMeAccess {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &RevokeBox,
        wsv: &WorldStateView,
    ) -> Result<()> {
        let permission_token: PermissionToken = instruction
            .object
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;

        let token: CanUnregisterAssetWithDefinition = permission_token
            .try_into()
            .map_err(|e: PredefinedTokenConversionError| e.to_string())?;

        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}
