//! Module with permission for setting and removing key values

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
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow only the asset owner to set asset metadata keys")]
pub struct AssetSetOnlyForSignerAccount;

impl IsAllowed for AssetSetOnlyForSignerAccount {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Skip;
        };
        let object_id = try_evaluate_or_deny!(set_kv_box.object_id, wsv);

        match object_id {
            IdBox::AssetId(asset_id) if &asset_id.account_id != authority => {
                Deny("Cannot set value to the asset store of another account".to_owned())
            }
            _ => Allow,
        }
    }
}

/// Allows setting user's assets key value map from a different account
/// if the corresponding user granted this permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct SetGrantedByAssetOwner;

impl HasToken for SetGrantedByAssetOwner {
    type Token = CanSetKeyValueInUserAssets;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Err("Instruction is not set".to_owned());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AssetId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AssetId".to_owned());
        };
        Ok(CanSetKeyValueInUserAssets::new(object_id))
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the asset owner")]
pub struct GrantMyAssetAccessSet;

impl IsGrantAllowed for GrantMyAssetAccessSet {
    type Token = CanSetKeyValueInUserAssets;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        _wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if &token.asset_id.account_id != authority {
            return Deny(
                "The signer does not own the account specified in the permission token".to_owned(),
            );
        }

        Allow
    }
}

/// Checks that account can set keys only the for signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow only the account owner to set account metadata keys")]
pub struct AccountSetOnlyForSignerAccount;

impl IsAllowed for AccountSetOnlyForSignerAccount {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Skip;
        };
        let object_id = try_evaluate_or_deny!(set_kv_box.object_id, wsv);

        match &object_id {
            IdBox::AccountId(account_id) if account_id != authority => {
                Deny("Cannot set values to the account store of another account".to_owned())
            }
            _ => Allow,
        }
    }
}

/// Allows setting user's metadata key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct SetGrantedByAccountOwner;

impl HasToken for SetGrantedByAccountOwner {
    type Token = CanSetKeyValueInUserMetadata;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Err("Instruction is not set".to_owned());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AccountId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AccountId".to_owned());
        };
        Ok(CanSetKeyValueInUserMetadata::new(object_id))
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the account owner")]
pub struct GrantMyMetadataAccessSet;

impl IsGrantAllowed for GrantMyMetadataAccessSet {
    type Token = CanSetKeyValueInUserMetadata;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        _wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if &token.account_id != authority {
            return Deny(
                "The signer does not own the account specified in the permission token".to_owned(),
            );
        }
        Allow
    }
}

/// Checks that account can remove keys for assets only the for signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow only the asset owner to remove asset metadata keys")]
pub struct AssetRemoveOnlyForSignerAccount;

impl IsAllowed for AssetRemoveOnlyForSignerAccount {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Skip;
        };
        let object_id = try_evaluate_or_deny!(rem_kv_box.object_id, wsv);
        match object_id {
            IdBox::AssetId(asset_id) if &asset_id.account_id != authority => {
                Deny("Cannot remove values from the asset store of another account".to_owned())
            }
            _ => Allow,
        }
    }
}

/// Allows removing user's assets key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct RemoveGrantedByAssetOwner;

impl HasToken for RemoveGrantedByAssetOwner {
    type Token = CanRemoveKeyValueInUserAssets;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Err("Instruction is not set".to_owned());
        };
        let object_id = rem_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AssetId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AssetId".to_owned());
        };
        Ok(CanRemoveKeyValueInUserAssets::new(object_id))
    }
}

/// Validator that checks Grant instruction so that the access is granted to the assets
/// of the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the account owner")]
pub struct GrantMyAssetAccessRemove;

impl IsGrantAllowed for GrantMyAssetAccessRemove {
    type Token = CanRemoveKeyValueInUserAssets;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        _wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if &token.asset_id.account_id != authority {
            return Deny(
                "The signer does not own the account specified in the permission token".to_owned(),
            );
        }
        Allow
    }
}

/// Checks that account can remove keys only the for signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow only the account owner to remove account metadata keys")]
pub struct AccountRemoveOnlyForSignerAccount;

impl IsAllowed for AccountRemoveOnlyForSignerAccount {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Skip;
        };
        let object_id = try_evaluate_or_deny!(rem_kv_box.object_id, wsv);

        match object_id {
            IdBox::AccountId(account_id) if &account_id != authority => {
                Deny("Cannot remove values from the account store of another account".to_owned())
            }
            _ => Allow,
        }
    }
}

/// Allows removing user's metadata key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct RemoveGrantedByAccountOwner;

impl HasToken for RemoveGrantedByAccountOwner {
    type Token = CanRemoveKeyValueInUserMetadata;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Err("Instruction is not remove".to_owned());
        };
        let object_id = rem_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AccountId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AccountId".to_owned());
        };
        Ok(CanRemoveKeyValueInUserMetadata::new(object_id))
    }
}

/// Validator that checks Grant instruction so that the access is granted to the metadata
/// of the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the account owner")]
pub struct GrantMyMetadataAccessRemove;

impl IsGrantAllowed for GrantMyMetadataAccessRemove {
    type Token = CanRemoveKeyValueInUserMetadata;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        _wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if &token.account_id != authority {
            return Deny(
                "The signer does not own the account specified in the permission token".to_owned(),
            );
        }
        Allow
    }
}

/// Validator that checks Grant instruction so that the access to the asset definition
/// is granted by the asset creator.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the asset creator")]
pub struct GrantMyAssetDefinitionSet;

impl IsGrantAllowed for GrantMyAssetDefinitionSet {
    type Token = CanSetKeyValueInAssetDefinition;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}

// Validator that checks Grant instruction so that the access is granted to the assets defintion
/// registered by signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the asset creator")]
pub struct GrantMyAssetDefinitionRemove;

impl IsGrantAllowed for GrantMyAssetDefinitionRemove {
    type Token = CanRemoveKeyValueInAssetDefinition;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        check_asset_creator_for_asset_definition(&token.asset_definition_id, authority, wsv)
    }
}

/// Checks that account can set keys for asset definitions only registered by the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow only the asset creator to set asset definition metadata keys")]
pub struct AssetDefinitionSetOnlyForSignerAccount;

impl IsAllowed for AssetDefinitionSetOnlyForSignerAccount {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Skip;
        };

        let object_id: AssetDefinitionId =
            ok_or_skip!(try_evaluate_or_deny!(set_kv_box.object_id, wsv).try_into());

        let registered_by_signer_account = wsv
            .asset_definition_entry(&object_id)
            .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
            .unwrap_or(false);
        if !registered_by_signer_account {
            return Deny(
                "Cannot set key values to asset definitions registered by other accounts"
                    .to_owned(),
            );
        }
        Allow
    }
}

/// Checks that account can set keys for asset definitions only registered by the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow only the asset creator to remove asset definition metadata keys")]
pub struct AssetDefinitionRemoveOnlyForSignerAccount;

impl IsAllowed for AssetDefinitionRemoveOnlyForSignerAccount {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
            rem_kv
        } else {
            return Skip;
        };

        let object_id: AssetDefinitionId =
            ok_or_skip!(try_evaluate_or_deny!(rem_kv_box.object_id, wsv).try_into());

        let registered_by_signer_account = wsv
            .asset_definition_entry(&object_id)
            .map(|asset_definition_entry| asset_definition_entry.registered_by() == authority)
            .unwrap_or(false);
        if !registered_by_signer_account {
            return Deny(
                "Cannot remove key values from asset definitions registered by other accounts"
                    .to_owned(),
            );
        }
        Allow
    }
}

/// Allows setting asset definition's metadata key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct SetGrantedByAssetDefinitionOwner;

impl HasToken for SetGrantedByAssetDefinitionOwner {
    type Token = CanSetKeyValueInAssetDefinition;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Err("Instruction is not set".to_owned());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AssetDefinitionId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AssetDefinitionId".to_owned());
        };
        Ok(CanSetKeyValueInAssetDefinition::new(object_id))
    }
}

/// Allows setting asset definition's metadata key value pairs from a different account if the corresponding user granted this permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct RemoveGrantedByAssetDefinitionOwner;

impl HasToken for RemoveGrantedByAssetDefinitionOwner {
    type Token = CanRemoveKeyValueInAssetDefinition;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        let set_kv_box = if let Instruction::RemoveKeyValue(set_kv) = instruction {
            set_kv
        } else {
            return Err("Instruction is not remove key value".to_owned());
        };
        let object_id = set_kv_box
            .object_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let object_id: AssetDefinitionId = if let Ok(obj_id) = object_id.try_into() {
            obj_id
        } else {
            return Err("Source id is not an AssetDefinitionId".to_owned());
        };
        Ok(CanRemoveKeyValueInAssetDefinition::new(object_id))
    }
}
