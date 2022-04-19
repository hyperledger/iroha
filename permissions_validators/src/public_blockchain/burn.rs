//! Module with permission for burning

use std::str::FromStr as _;

use super::*;

/// Can burn asset with the corresponding asset definition.
#[allow(clippy::expect_used)]
pub static CAN_BURN_ASSET_WITH_DEFINITION: Lazy<Name> =
    Lazy::new(|| Name::from_str("can_burn_asset_with_definition").expect("normal name"));
#[allow(clippy::expect_used)]
/// Can burn user's assets permission token name.
pub static CAN_BURN_USER_ASSETS_TOKEN: Lazy<Name> =
    Lazy::new(|| Name::from_str("can_burn_user_assets").expect("normal name"));

/// Checks that account can burn only the assets which were registered by this account.
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
        let burn_box = if let Instruction::Burn(burn) = instruction {
            burn
        } else {
            return Ok(());
        };
        let destination_id = burn_box
            .destination_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let asset_id: AssetId = try_into_or_exit!(destination_id);
        let registered_by_signer_account = wsv
            .asset_definition_entry(&asset_id.definition_id)
            .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
            .unwrap_or(false);
        if !registered_by_signer_account {
            return Err("Can't burn assets registered by other accounts.".to_owned());
        }
        Ok(())
    }
}

/// Allows burning assets from a different account than the creator's of this asset if the corresponding user granted the permission token
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
        let burn_box = if let Instruction::Burn(burn) = instruction {
            burn
        } else {
            return Err("Instruction is not burn.".to_owned());
        };
        let destination_id = burn_box
            .destination_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let asset_id: AssetId = if let Ok(dest_id) = destination_id.try_into() {
            dest_id
        } else {
            return Err("Destination is not an Asset.".to_owned());
        };

        Ok(
            PermissionToken::new(CAN_BURN_ASSET_WITH_DEFINITION.clone()).with_params([(
                ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned(),
                asset_id.definition_id.into(),
            )]),
        )
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
        let permission_token: PermissionToken = instruction
            .object
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
        if permission_token.name() != &*CAN_BURN_ASSET_WITH_DEFINITION {
            return Err("Grant instruction is not for burn permission.".to_owned());
        }
        check_asset_creator_for_token(&permission_token, authority, wsv)
    }
}

/// Checks that account can burn only the assets that he currently owns.
#[derive(Debug, Copy, Clone)]
pub struct OnlyOwnedAssets;

impl_from_item_for_instruction_validator_box!(OnlyOwnedAssets);

impl<W: WorldTrait> IsAllowed<W, Instruction> for OnlyOwnedAssets {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let burn_box = if let Instruction::Burn(burn) = instruction {
            burn
        } else {
            return Ok(());
        };
        let destination_id = burn_box
            .destination_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let asset_id: AssetId = try_into_or_exit!(destination_id);
        if &asset_id.account_id != authority {
            return Err("Can't burn assets from another account.".to_owned());
        }
        Ok(())
    }
}

/// Allows burning user's assets from a different account if the corresponding user granted this permission token.
#[derive(Debug, Clone, Copy)]
pub struct GrantedByAssetOwner;

impl_from_item_for_granted_token_validator_box!(GrantedByAssetOwner);

impl<W: WorldTrait> HasToken<W> for GrantedByAssetOwner {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        let burn_box = if let Instruction::Burn(burn_box) = instruction {
            burn_box
        } else {
            return Err("Instruction is not burn.".to_owned());
        };
        let destination_id = burn_box
            .destination_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let destination_id: AssetId = if let Ok(dest_id) = destination_id.try_into() {
            dest_id
        } else {
            return Err("Source id is not an AssetId.".to_owned());
        };
        Ok(PermissionToken::new(CAN_BURN_USER_ASSETS_TOKEN.clone())
            .with_params([(ASSET_ID_TOKEN_PARAM_NAME.to_owned(), destination_id.into())]))
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Clone, Copy)]
pub struct GrantMyAssetAccess;

impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccess);

impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetAccess {
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
        if permission_token.name() != &*CAN_BURN_USER_ASSETS_TOKEN {
            return Err("Grant instruction is not for burn permission.".to_owned());
        }
        check_asset_owner_for_token(&permission_token, authority)?;
        Ok(())
    }
}
