//! Module with permission for burning

use iroha_data_model::asset::DefinitionId;

use super::*;

declare_token!(
    /// Can set key value in user's assets permission.
    CanSetKeyValueInUserAssets {
        /// Asset id.
        asset_id ("asset_id"): AssetId,
    },
    "can_set_key_value_in_user_assets"
);

declare_token!(
    /// Can remove key value in user's assets permission.
    CanRemoveKeyValueInUserAssets {
        /// Asset id
        asset_id ("asset_id"): AssetId,
    },
    "can_remove_key_value_in_user_assets"
);

declare_token!(
    /// Can set key value in user metadata.
    CanSetKeyValueInUserMetadata {
        /// Account id.
        account_id ("account_id"): AccountId,
    },
    "can_set_key_value_in_user_metadata"
);

declare_token!(
    /// Can remove key value in user metadata.
    CanRemoveKeyValueInUserMetadata {
        /// Account id.
        account_id ("account_id"): AccountId,
    },
    "can_remove_key_value_in_user_metadata"
);

declare_token!(
    /// Can set key value in the corresponding asset definition.
    CanSetKeyValueInAssetDefinition {
        /// Asset definition id.
        asset_definition_id ("asset_definition_id"): DefinitionId,
    },
    "can_set_key_value_in_asset_definition"
);

declare_token!(
    /// Can remove key value in the corresponding asset definition.
    CanRemoveKeyValueInAssetDefinition {
        /// Asset definition id.
        asset_definition_id ("asset_definition_id"): DefinitionId,
    },
    "can_remove_key_value_in_asset_definition"
);

/// Checks that account can set keys for assets only for the signer account.
#[derive(Debug, Copy, Clone)]
pub struct AssetSetOnlyForSignerAccount;

impl_from_item_for_instruction_validator_box!(AssetSetOnlyForSignerAccount);

impl<W: WorldTrait> IsAllowed<W, Instruction> for AssetSetOnlyForSignerAccount {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Ok(());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;

        match object_id {
            IdBox::AssetId(asset_id) if &asset_id.account_id != authority => {
                Err("Can't set value to asset store from another account.".to_owned())
            }
            _ => Ok(()),
        }
    }
}

/// Allows setting user's assets key value map from a different account
/// if the corresponding user granted this permission token.
#[derive(Debug, Clone, Copy)]
pub struct SetGrantedByAssetOwner;

impl_from_item_for_granted_token_validator_box!(SetGrantedByAssetOwner);

impl<W: WorldTrait> HasToken<W> for SetGrantedByAssetOwner {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Err("Instruction is not set.".to_owned());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AssetId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AssetId.".to_owned());
        };
        Ok(CanSetKeyValueInUserAssets::new(object_id).into())
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Clone, Copy)]
pub struct GrantMyAssetAccessSet;

impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccessSet);

impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetAccessSet {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let token: CanSetKeyValueInUserAssets = extract_specialized_token(instruction, wsv)?;

        if &token.asset_id.account_id != authority {
            return Err("Asset specified in permission token is not owned by signer.".to_owned());
        }

        Ok(())
    }
}

/// Checks that account can set keys only the for signer account.
#[derive(Debug, Copy, Clone)]
pub struct AccountSetOnlyForSignerAccount;

impl_from_item_for_instruction_validator_box!(AccountSetOnlyForSignerAccount);

impl<W: WorldTrait> IsAllowed<W, Instruction> for AccountSetOnlyForSignerAccount {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Ok(());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;

        match &object_id {
            IdBox::AccountId(account_id) if account_id != authority => {
                Err("Can't set value to account store from another account.".to_owned())
            }
            _ => Ok(()),
        }
    }
}

/// Allows setting user's metadata key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Clone, Copy)]
pub struct SetGrantedByAccountOwner;

impl_from_item_for_granted_token_validator_box!(SetGrantedByAccountOwner);

impl<W: WorldTrait> HasToken<W> for SetGrantedByAccountOwner {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Err("Instruction is not set.".to_owned());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AccountId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AccountId.".to_owned());
        };
        Ok(CanSetKeyValueInUserMetadata::new(object_id).into())
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Clone, Copy)]
pub struct GrantMyMetadataAccessSet;

impl_from_item_for_grant_instruction_validator_box!(GrantMyMetadataAccessSet);

impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyMetadataAccessSet {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let token: CanSetKeyValueInUserMetadata = extract_specialized_token(instruction, wsv)?;
        if &token.account_id != authority {
            return Err("Account specified in permission token is not owned by signer.".to_owned());
        }
        Ok(())
    }
}

/// Checks that account can remove keys for assets only the for signer account.
#[derive(Debug, Copy, Clone)]
pub struct AssetRemoveOnlyForSignerAccount;

impl_from_item_for_instruction_validator_box!(AssetRemoveOnlyForSignerAccount);

impl<W: WorldTrait> IsAllowed<W, Instruction> for AssetRemoveOnlyForSignerAccount {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Ok(());
        };
        let object_id = rem_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        match object_id {
            IdBox::AssetId(asset_id) if &asset_id.account_id != authority => {
                Err("Can't remove value from asset store from another account.".to_owned())
            }
            _ => Ok(()),
        }
    }
}

/// Allows removing user's assets key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Clone, Copy)]
pub struct RemoveGrantedByAssetOwner;

impl_from_item_for_granted_token_validator_box!(RemoveGrantedByAssetOwner);

impl<W: WorldTrait> HasToken<W> for RemoveGrantedByAssetOwner {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Err("Instruction is not set.".to_owned());
        };
        let object_id = rem_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AssetId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AssetId.".to_owned());
        };
        Ok(CanRemoveKeyValueInUserAssets::new(object_id).into())
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Clone, Copy)]
pub struct GrantMyAssetAccessRemove;

impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccessRemove);

impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetAccessRemove {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let token: CanRemoveKeyValueInUserAssets = extract_specialized_token(instruction, wsv)?;

        if &token.asset_id.account_id != authority {
            return Err("Asset specified in permission token is not owned by signer.".to_owned());
        }
        Ok(())
    }
}

/// Checks that account can remove keys only the for signer account.
#[derive(Debug, Copy, Clone)]
pub struct AccountRemoveOnlyForSignerAccount;

impl_from_item_for_instruction_validator_box!(AccountRemoveOnlyForSignerAccount);

impl<W: WorldTrait> IsAllowed<W, Instruction> for AccountRemoveOnlyForSignerAccount {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Ok(());
        };
        let object_id = rem_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;

        match object_id {
            IdBox::AccountId(account_id) if &account_id != authority => {
                Err("Can't remove value from account store from another account.".to_owned())
            }
            _ => Ok(()),
        }
    }
}

/// Allows removing user's metadata key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Clone, Copy)]
pub struct RemoveGrantedByAccountOwner;

impl_from_item_for_granted_token_validator_box!(RemoveGrantedByAccountOwner);

impl<W: WorldTrait> HasToken<W> for RemoveGrantedByAccountOwner {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Err("Instruction is not remove.".to_owned());
        };
        let object_id = rem_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AccountId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AccountId.".to_owned());
        };
        Ok(CanRemoveKeyValueInUserMetadata::new(object_id).into())
    }
}

/// Validator that checks Grant instruction so that the access is granted to the metadata
/// of the signer account.
#[derive(Debug, Clone, Copy)]
pub struct GrantMyMetadataAccessRemove;

impl_from_item_for_grant_instruction_validator_box!(GrantMyMetadataAccessRemove);

impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyMetadataAccessRemove {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let token: CanRemoveKeyValueInUserMetadata = extract_specialized_token(instruction, wsv)?;

        if &token.account_id != authority {
            return Err("Account specified in permission token is not owned by signer.".to_owned());
        }
        Ok(())
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets defintion
/// registered by signer account.
#[derive(Debug, Clone, Copy)]
pub struct GrantMyAssetDefinitionSet;

impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetDefinitionSet);

impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetDefinitionSet {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let token: CanSetKeyValueInAssetDefinition = extract_specialized_token(instruction, wsv)?;

        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}

// Validator that checks Grant instruction so that the access is granted to the assets defintion
/// registered by signer account.
#[derive(Debug, Clone, Copy)]
pub struct GrantMyAssetDefinitionRemove;

impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetDefinitionRemove);

impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetDefinitionRemove {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let token: CanRemoveKeyValueInAssetDefinition =
            extract_specialized_token(instruction, wsv)?;

        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}

/// Checks that account can set keys for asset definitions only registered by the signer account.
#[derive(Debug, Copy, Clone)]
pub struct AssetDefinitionSetOnlyForSignerAccount;

impl_from_item_for_instruction_validator_box!(AssetDefinitionSetOnlyForSignerAccount);

impl<W: WorldTrait> IsAllowed<W, Instruction> for AssetDefinitionSetOnlyForSignerAccount {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Ok(());
        };
        let obj_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;

        let object_id: AssetDefinitionId = try_into_or_exit!(obj_id);
        let registered_by_signer_account = wsv
            .asset_definition_entry(&object_id)
            .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
            .unwrap_or(false);
        if !registered_by_signer_account {
            return Err(
                "Can't set key value to asset definition registered by other accounts.".to_owned(),
            );
        }
        Ok(())
    }
}

/// Checks that account can set keys for asset definitions only registered by the signer account.
#[derive(Debug, Copy, Clone)]
pub struct AssetDefinitionRemoveOnlyForSignerAccount;

impl_from_item_for_instruction_validator_box!(AssetDefinitionRemoveOnlyForSignerAccount);

impl<W: WorldTrait> IsAllowed<W, Instruction> for AssetDefinitionRemoveOnlyForSignerAccount {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Ok(());
        };
        let obj_id = rem_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;

        let object_id: AssetDefinitionId = try_into_or_exit!(obj_id);
        let registered_by_signer_account = wsv
            .asset_definition_entry(&object_id)
            .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
            .unwrap_or(false);
        if !registered_by_signer_account {
            return Err(
                "Can't remove key value to asset definition registered by other accounts."
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Allows setting asset definition's metadata key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Clone, Copy)]
pub struct SetGrantedByAssetDefinitionOwner;

impl_from_item_for_granted_token_validator_box!(SetGrantedByAssetDefinitionOwner);

impl<W: WorldTrait> HasToken<W> for SetGrantedByAssetDefinitionOwner {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Err("Instruction is not set.".to_owned());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AssetDefinitionId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AssetDefinitionId.".to_owned());
        };
        Ok(CanSetKeyValueInAssetDefinition::new(object_id).into())
    }
}

/// Allows setting asset definition's metadata key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Clone, Copy)]
pub struct RemoveGrantedByAssetDefinitionOwner;

impl_from_item_for_granted_token_validator_box!(RemoveGrantedByAssetDefinitionOwner);

impl<W: WorldTrait> HasToken<W> for RemoveGrantedByAssetDefinitionOwner {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        let set_kv_box = if let Instruction::RemoveKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Err("Instruction is not remove key value.".to_owned());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AssetDefinitionId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AssetDefinitionId.".to_owned());
        };
        Ok(CanRemoveKeyValueInAssetDefinition::new(object_id).into())
    }
}
