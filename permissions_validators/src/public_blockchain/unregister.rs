//! Module with permission for unregistering

use std::str::FromStr as _;

use super::*;

#[allow(clippy::expect_used)]
/// Can un-register asset with the corresponding asset definition.
pub static CAN_UNREGISTER_ASSET_WITH_DEFINITION: Lazy<Name> =
    Lazy::new(|| Name::from_str("can_unregister_asset_with_definition").expect("Tested. Works."));

/// Checks that account can un-register only the assets which were
/// registered by this account in the first place.
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
            return Err("Can't unregister assets registered by other accounts.".to_owned());
        }
        Ok(())
    }
}

/// Allows un-registering a user's assets from a different account if
/// the corresponding user granted the permission token for a specific
/// asset.
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
        let mut params = BTreeMap::new();
        params.insert(
            ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.clone(),
            object_id.into(),
        );
        Ok(PermissionToken::new(
            CAN_UNREGISTER_ASSET_WITH_DEFINITION.clone(),
            params,
        ))
    }
}

/// Validator that checks Grant instruction so that the access is
/// granted to the assets of the signer account.
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
        let permission_token: PermissionToken = instruction
            .object
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
        if permission_token.name != CAN_UNREGISTER_ASSET_WITH_DEFINITION.clone() {
            return Err("Grant instruction is not for unregister permission.".to_owned());
        }
        check_asset_creator_for_token(&permission_token, authority, wsv)
    }
}

/// Validator that checks Revoke instructions, such that the access is
/// revoked and the assets of the signer's account are no longer
/// accessible.
#[derive(Debug, Clone, Copy)]
pub struct RevokeRegisteredByMeAccess;

impl_from_item_for_revoke_instruction_validator_box!(RevokeRegisteredByMeAccess);

impl<W: WorldTrait> IsRevokeAllowed<W> for RevokeRegisteredByMeAccess {
    fn check_revoke(
        &self,
        authority: &AccountId,
        instruction: &RevokeBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let permission_token: PermissionToken = instruction
            .object
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
        if permission_token.name != CAN_UNREGISTER_ASSET_WITH_DEFINITION.clone() {
            return Err("Revoke instruction is not for unregister permission.".to_owned());
        }
        check_asset_creator_for_token(&permission_token, authority, wsv)
    }
}
