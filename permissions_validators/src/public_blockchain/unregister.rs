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
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow to unregister only the assets created by the signer")]
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
    type Token = CanUnregisterAssetWithDefinition;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> core::result::Result<Self::Token, String> {
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
        Ok(CanUnregisterAssetWithDefinition::new(object_id))
    }
}

/// Validator that checks Grant instruction so that the access is
/// granted to the assets of the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the asset creator")]
pub struct GrantRegisteredByMeAccess;

impl IsGrantAllowed for GrantRegisteredByMeAccess {
    type Token = CanUnregisterAssetWithDefinition;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}

/// Validator that checks Revoke instructions, such that the access is
/// revoked and the assets of the signer's account are no longer
/// accessible.
#[derive(Debug, Display, Clone, Copy, Serialize)]
#[display(fmt = "the signer is the asset creator")]
pub struct RevokeRegisteredByMeAccess;

impl IsRevokeAllowed for RevokeRegisteredByMeAccess {
    type Token = CanUnregisterAssetWithDefinition;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}
