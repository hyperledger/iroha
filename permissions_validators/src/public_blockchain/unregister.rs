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

impl IsAllowed for OnlyAssetsCreatedByThisAccount {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let unregister_box = if let Instruction::Unregister(unregister) = instruction {
            unregister
        } else {
            return Skip;
        };

        let object_id = try_evaluate_or_deny!(unregister_box.object_id, wsv);
        let asset_definition_id: AssetDefinitionId = ok_or_skip!(object_id.try_into());
        let registered_by_signer_account = wsv
            .asset_definition_entry(&asset_definition_id)
            .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
            .unwrap_or(false);
        if !registered_by_signer_account {
            return Deny("Cannot unregister assets registered by other accounts.".to_owned());
        }
        Allow
    }
}

/// Allows un-registering a user's assets from a different account if
/// the corresponding user granted the permission token for a specific
/// asset.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantedByAssetCreator;

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

impl IsGrantAllowed for GrantRegisteredByMeAccess {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let token: CanUnregisterAssetWithDefinition =
            ok_or_skip!(extract_specialized_token(instruction, wsv));
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}

/// Validator that checks Revoke instructions, such that the access is
/// revoked and the assets of the signer's account are no longer
/// accessible.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RevokeRegisteredByMeAccess;

impl IsRevokeAllowed for RevokeRegisteredByMeAccess {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &RevokeBox,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let value = try_evaluate_or_deny!(instruction.object, wsv);
        let permission_token: PermissionToken = ok_or_skip!(value
            .try_into()
            .map_err(|e: ErrorTryFromEnum<_, _>| (e.to_string())));

        let token: CanUnregisterAssetWithDefinition = ok_or_skip!(permission_token
            .try_into()
            .map_err(|e: PredefinedTokenConversionError| (e.to_string())));

        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}
