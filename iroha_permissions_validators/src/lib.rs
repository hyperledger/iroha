//! Out of box implementations for common permission checks.

#![allow(clippy::module_name_repetitions)]

use std::{collections::BTreeMap, convert::TryInto};

use iroha::{
    expression::Evaluate,
    permissions::{
        prelude::*, GrantedTokenValidator, PermissionsValidator, PermissionsValidatorBuilder,
        ValidatorApplyOr,
    },
    prelude::*,
};
use iroha_data_model::{isi::*, prelude::*};

macro_rules! impl_from_item_for_validator_box {
    ( $ty:ty ) => {
        impl From<$ty> for PermissionsValidatorBox {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_granted_token_validator_box {
    ( $ty:ty ) => {
        impl From<$ty> for GrantedTokenValidatorBox {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }

        impl From<$ty> for PermissionsValidatorBox {
            fn from(validator: $ty) -> Self {
                let validator: GrantedTokenValidatorBox = validator.into();
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_grant_instruction_validator_box {
    ( $ty:ty ) => {
        impl From<$ty> for GrantInstructionValidatorBox {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }

        impl From<$ty> for PermissionsValidatorBox {
            fn from(validator: $ty) -> Self {
                let validator: GrantInstructionValidatorBox = validator.into();
                Box::new(validator)
            }
        }
    };
}

macro_rules! try_into_or_exit {
    ( $ident:ident ) => {
        if let Ok(into) = $ident.try_into() {
            into
        } else {
            return Ok(());
        }
    };
}

/// Permission checks asociated with use cases that can be summarized as private blockchains (e.g. CBDC).
pub mod private_blockchain {

    use super::*;

    /// A preconfigured set of permissions for simple use cases.
    pub fn default_permissions() -> PermissionsValidatorBox {
        PermissionsValidatorBuilder::new()
            .with_recursive_validator(
                register::ProhibitRegisterDomains.or(register::GrantedAllowedRegisterDomains),
            )
            .all_should_succeed()
    }

    /// Prohibits using `Grant` instruction at runtime.
    /// This means `Grant` instruction will only be used in genesis to specify rights.
    #[derive(Debug, Copy, Clone)]
    pub struct ProhibitGrant;

    impl_from_item_for_grant_instruction_validator_box!(ProhibitGrant);

    impl GrantInstructionValidator for ProhibitGrant {
        fn check_grant(
            &self,
            _authority: &AccountId,
            _instruction: &GrantBox,
            _wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            Err("Granting at runtime is prohibited.".to_owned())
        }
    }

    pub mod register {
        //! Module with permissions for registering.

        use std::collections::BTreeMap;

        use super::*;

        /// Can register domains permission token name.
        pub const CAN_REGISTER_DOMAINS_TOKEN: &str = "can_register_domains";

        /// Prohibits registering domains.
        #[derive(Debug, Copy, Clone)]
        pub struct ProhibitRegisterDomains;

        impl_from_item_for_validator_box!(ProhibitRegisterDomains);

        impl PermissionsValidator for ProhibitRegisterDomains {
            fn check_instruction(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                _wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let _register_box = if let Instruction::Register(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                Err("Domain registration is prohibited.".to_owned())
            }
        }

        /// Validator that allows to register domains for accounts with the corresponding permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedAllowedRegisterDomains;

        impl_from_item_for_granted_token_validator_box!(GrantedAllowedRegisterDomains);

        impl GrantedTokenValidator for GrantedAllowedRegisterDomains {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                _instruction: &Instruction,
                _wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                Ok(PermissionToken::new(
                    CAN_REGISTER_DOMAINS_TOKEN,
                    BTreeMap::new(),
                ))
            }
        }
    }
}

/// Permission checks asociated with use cases that can be summarized as public blockchains.
pub mod public_blockchain {
    use super::*;

    /// Origin asset id param used in permission tokens.
    pub const ASSET_ID_TOKEN_PARAM_NAME: &str = "asset_id";
    /// Origin account id param used in permission tokens.
    pub const ACCOUNT_ID_TOKEN_PARAM_NAME: &str = "account_id";
    /// Origin asset definition param used in permission tokens.
    pub const ASSET_DEFINITION_ID_TOKEN_PARAM_NAME: &str = "asset_definition_id";

    /// A preconfigured set of permissions for simple use cases.
    pub fn default_permissions() -> PermissionsValidatorBox {
        // Grant instruction checks are or unioned, so that if one permission validator approves this Grant it will succeed.
        let grant_instruction_validator = PermissionsValidatorBuilder::new()
            .with_validator(transfer::GrantMyAssetAccess)
            .with_validator(unregister::GrantRegisteredByMeAccess)
            .with_validator(mint::GrantRegisteredByMeAccess)
            .with_validator(burn::GrantMyAssetAccess)
            .with_validator(burn::GrantRegisteredByMeAccess)
            .with_validator(key_value::GrantMyAssetAccessRemove)
            .with_validator(key_value::GrantMyAssetAccessSet)
            .with_validator(key_value::GrantMyMetadataAccessSet)
            .with_validator(key_value::GrantMyMetadataAccessRemove)
            .any_should_succeed("Grant instruction validator.");
        PermissionsValidatorBuilder::new()
            .with_recursive_validator(grant_instruction_validator)
            .with_recursive_validator(transfer::OnlyOwnedAssets.or(transfer::GrantedByAssetOwner))
            .with_recursive_validator(
                unregister::OnlyAssetsCreatedByThisAccount.or(unregister::GrantedByAssetCreator),
            )
            .with_recursive_validator(
                mint::OnlyAssetsCreatedByThisAccount.or(mint::GrantedByAssetCreator),
            )
            .with_recursive_validator(burn::OnlyOwnedAssets.or(burn::GrantedByAssetOwner))
            .with_recursive_validator(
                burn::OnlyAssetsCreatedByThisAccount.or(burn::GrantedByAssetCreator),
            )
            .with_recursive_validator(
                key_value::AccountSetOnlyForSignerAccount.or(key_value::SetGrantedByAccountOwner),
            )
            .with_recursive_validator(
                key_value::AccountRemoveOnlyForSignerAccount
                    .or(key_value::RemoveGrantedByAccountOwner),
            )
            .with_recursive_validator(
                key_value::AssetSetOnlyForSignerAccount.or(key_value::SetGrantedByAssetOwner),
            )
            .with_recursive_validator(
                key_value::AssetRemoveOnlyForSignerAccount.or(key_value::RemoveGrantedByAssetOwner),
            )
            .all_should_succeed()
    }

    /// Checks that `authority` is account owner for account supplied in `permission_token`.
    ///
    /// # Errors
    /// - The `permission_token` is of improper format.
    /// - Account owner is not `authority`
    pub fn check_account_owner_for_token(
        permission_token: &PermissionToken,
        authority: &AccountId,
    ) -> Result<(), String> {
        let account_id = if let Value::Id(IdBox::AccountId(account_id)) = permission_token
            .params
            .get(ACCOUNT_ID_TOKEN_PARAM_NAME)
            .ok_or(format!(
                "Failed to find permission param {}.",
                ACCOUNT_ID_TOKEN_PARAM_NAME
            ))? {
            account_id
        } else {
            return Err(format!(
                "Permission param {} is not an AccountId.",
                ACCOUNT_ID_TOKEN_PARAM_NAME
            ));
        };
        if account_id != authority {
            return Err("Account specified in permission token is not owned by signer.".to_owned());
        }
        Ok(())
    }

    /// Checks that `authority` is asset owner for asset supplied in `permission_token`.
    ///
    /// # Errors
    /// - The `permission_token` is of improper format.
    /// - Asset owner is not `authority`
    pub fn check_asset_owner_for_token(
        permission_token: &PermissionToken,
        authority: &AccountId,
    ) -> Result<(), String> {
        let asset_id = if let Value::Id(IdBox::AssetId(asset_id)) = permission_token
            .params
            .get(ASSET_ID_TOKEN_PARAM_NAME)
            .ok_or(format!(
                "Failed to find permission param {}.",
                ASSET_ID_TOKEN_PARAM_NAME
            ))? {
            asset_id
        } else {
            return Err(format!(
                "Permission param {} is not an AssetId.",
                ASSET_ID_TOKEN_PARAM_NAME
            ));
        };
        if &asset_id.account_id != authority {
            return Err("Asset specified in permission token is not owned by signer.".to_owned());
        }
        Ok(())
    }

    /// Checks that asset creator is `authority` in the supplied `permission_token`.
    ///
    /// # Errors
    /// - The `permission_token` is of improper format.
    /// - Asset creator is not `authority`
    pub fn check_asset_creator_for_token(
        permission_token: &PermissionToken,
        authority: &AccountId,
        wsv: &WorldStateView,
    ) -> Result<(), String> {
        let definition_id = if let Value::Id(IdBox::AssetDefinitionId(definition_id)) =
            permission_token
                .params
                .get(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME)
                .ok_or(format!(
                    "Failed to find permission param {}.",
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME
                ))? {
            definition_id
        } else {
            return Err(format!(
                "Permission param {} is not an AssetDefinitionId.",
                ASSET_DEFINITION_ID_TOKEN_PARAM_NAME
            ));
        };
        let registered_by_signer_account = wsv
            .read_asset_definition_entry(definition_id)
            .map_or(false, |asset_definiton_entry| {
                &asset_definiton_entry.registered_by == authority
            });
        if !registered_by_signer_account {
            return Err(
                "Can not grant access for unregistering assets, registered by another account."
                    .to_owned(),
            );
        }
        Ok(())
    }

    pub mod transfer {
        //! Module with permission for transfering

        use super::*;

        /// Can transfer user's assets permission token name.
        pub const CAN_TRANSFER_USER_ASSETS_TOKEN: &str = "can_transfer_user_assets";

        /// Checks that account transfers only the assets that he owns.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyOwnedAssets;

        impl_from_item_for_validator_box!(OnlyOwnedAssets);

        impl PermissionsValidator for OnlyOwnedAssets {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let transfer_box = if let Instruction::Transfer(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let source_id = transfer_box
                    .source_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let source_id: AssetId = try_into_or_exit!(source_id);

                if &source_id.account_id != authority {
                    return Err("Can't transfer assets of the other account.".to_owned());
                }
                Ok(())
            }
        }

        /// Allows transfering user's assets from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedByAssetOwner;

        impl_from_item_for_granted_token_validator_box!(GrantedByAssetOwner);

        impl GrantedTokenValidator for GrantedByAssetOwner {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                let transfer_box = if let Instruction::Transfer(transfer_box) = instruction {
                    transfer_box
                } else {
                    return Err("Instruction is not transfer.".to_owned());
                };
                let source_id = transfer_box
                    .source_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let source_id: AssetId = if let Ok(source_id) = source_id.try_into() {
                    source_id
                } else {
                    return Err("Source id is not an AssetId.".to_owned());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(ASSET_ID_TOKEN_PARAM_NAME.to_owned(), source_id.into());
                Ok(PermissionToken::new(CAN_TRANSFER_USER_ASSETS_TOKEN, params))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccess);

        impl GrantInstructionValidator for GrantMyAssetAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                if permission_token.name != transfer::CAN_TRANSFER_USER_ASSETS_TOKEN {
                    return Err("Grant instruction is not for transfer permission.".to_owned());
                }
                check_asset_owner_for_token(&permission_token, authority)
            }
        }
    }

    pub mod unregister {
        //! Module with permission for unregistering

        use super::*;

        /// Can unregister asset with the corresponding asset definition.
        pub const CAN_UNREGISTER_ASSET_WITH_DEFINITION: &str =
            "can_unregister_asset_with_definition";

        /// Checks that account can unregister only the assets which were registered by this account in the first place.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        impl_from_item_for_validator_box!(OnlyAssetsCreatedByThisAccount);

        impl PermissionsValidator for OnlyAssetsCreatedByThisAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::Unregister(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_definition_id: AssetDefinitionId = try_into_or_exit!(object_id);
                let registered_by_signer_account = wsv
                    .read_asset_definition_entry(&asset_definition_id)
                    .map_or(false, |asset_definiton_entry| {
                        &asset_definiton_entry.registered_by == authority
                    });
                if !registered_by_signer_account {
                    return Err("Can't unregister assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }

        /// Allows unregistering user's assets from a different account if the corresponding user granted the permission token
        /// for a specific asset.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedByAssetCreator;

        impl_from_item_for_granted_token_validator_box!(GrantedByAssetCreator);

        impl GrantedTokenValidator for GrantedByAssetCreator {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                let unregister_box = if let Instruction::Unregister(instruction) = instruction {
                    instruction
                } else {
                    return Err("Instruction is not unregister.".to_owned());
                };
                let object_id = unregister_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AssetDefinitionId = if let Ok(object_id) = object_id.try_into() {
                    object_id
                } else {
                    return Err("Source id is not an AssetDefinitionId.".to_owned());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned(),
                    object_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_UNREGISTER_ASSET_WITH_DEFINITION,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantRegisteredByMeAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantRegisteredByMeAccess);

        impl GrantInstructionValidator for GrantRegisteredByMeAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                if permission_token.name != CAN_UNREGISTER_ASSET_WITH_DEFINITION {
                    return Err("Grant instruction is not for unregister permission.".to_owned());
                }
                check_asset_creator_for_token(&permission_token, authority, wsv)
            }
        }
    }

    pub mod mint {
        //! Module with permission for minting

        use super::*;

        /// Can mint asset with the corresponding asset definition.
        pub const CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN: &str = "can_mint_user_asset_definitions";

        /// Checks that account can mint only the assets which were registered by this account.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        impl_from_item_for_validator_box!(OnlyAssetsCreatedByThisAccount);

        impl PermissionsValidator for OnlyAssetsCreatedByThisAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::Mint(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let destination_id = instruction
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(destination_id);

                let low_authority = wsv
                    .read_asset_definition_entry(&asset_id.definition_id)
                    .map_or(false, |asset_definiton_entry| {
                        &asset_definiton_entry.registered_by != authority
                    });

                if low_authority {
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

        impl GrantedTokenValidator for GrantedByAssetCreator {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                let mint_box = if let Instruction::Mint(instruction) = instruction {
                    instruction
                } else {
                    return Err("Instruction is not mint.".to_owned());
                };
                let destination_id = mint_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = if let Ok(destination_id) = destination_id.try_into() {
                    destination_id
                } else {
                    return Err("Destination is not an Asset.".to_owned());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned(),
                    asset_id.definition_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantRegisteredByMeAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantRegisteredByMeAccess);

        impl GrantInstructionValidator for GrantRegisteredByMeAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                if permission_token.name != CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN {
                    return Err("Grant instruction is not for mint permission.".to_owned());
                }
                check_asset_creator_for_token(&permission_token, authority, wsv)
            }
        }
    }

    pub mod burn {
        //! Module with permission for burning

        use super::*;

        /// Can burn asset with the corresponding asset definition.
        pub const CAN_BURN_ASSET_WITH_DEFINITION: &str = "can_burn_asset_with_definition";
        /// Can burn user's assets permission token name.
        pub const CAN_BURN_USER_ASSETS_TOKEN: &str = "can_burn_user_assets";

        /// Checks that account can burn only the assets which were registered by this account.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        impl_from_item_for_validator_box!(OnlyAssetsCreatedByThisAccount);

        impl PermissionsValidator for OnlyAssetsCreatedByThisAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::Burn(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let destination_id = instruction
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(destination_id);

                let low_authority = wsv
                    .read_asset_definition_entry(&asset_id.definition_id)
                    .map_or(false, |asset_definiton_entry| {
                        &asset_definiton_entry.registered_by != authority
                    });
                if low_authority {
                    return Err("Can't mint assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }

        /// Allows burning assets from a different account than the creator's of this asset if the corresponding user granted the permission token
        /// for a specific asset.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedByAssetCreator;

        impl_from_item_for_granted_token_validator_box!(GrantedByAssetCreator);

        impl GrantedTokenValidator for GrantedByAssetCreator {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                let burn_box = if let Instruction::Burn(instruction) = instruction {
                    instruction
                } else {
                    return Err("Instruction is not burn.".to_owned());
                };
                let destination_id = burn_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = if let Ok(destination_id) = destination_id.try_into() {
                    destination_id
                } else {
                    return Err("Destination is not an Asset.".to_owned());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned(),
                    asset_id.definition_id.into(),
                );
                Ok(PermissionToken::new(CAN_BURN_ASSET_WITH_DEFINITION, params))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantRegisteredByMeAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantRegisteredByMeAccess);

        impl GrantInstructionValidator for GrantRegisteredByMeAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                if permission_token.name != CAN_BURN_ASSET_WITH_DEFINITION {
                    return Err("Grant instruction is not for burn permission.".to_owned());
                }
                check_asset_creator_for_token(&permission_token, authority, wsv)
            }
        }

        /// Checks that account can burn only the assets that he currently owns.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyOwnedAssets;

        impl_from_item_for_validator_box!(OnlyOwnedAssets);

        impl PermissionsValidator for OnlyOwnedAssets {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::Burn(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let destination_id = instruction
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

        impl GrantedTokenValidator for GrantedByAssetOwner {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
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
                let destination_id: AssetId = if let Ok(destination_id) = destination_id.try_into()
                {
                    destination_id
                } else {
                    return Err("Source id is not an AssetId.".to_owned());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(ASSET_ID_TOKEN_PARAM_NAME.to_owned(), destination_id.into());
                Ok(PermissionToken::new(CAN_BURN_USER_ASSETS_TOKEN, params))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccess);

        impl GrantInstructionValidator for GrantMyAssetAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                if permission_token.name != CAN_BURN_USER_ASSETS_TOKEN {
                    return Err("Grant instruction is not for burn permission.".to_owned());
                }
                check_asset_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }
    }

    pub mod key_value {
        //! Module with permission for burning

        use super::*;

        /// Can set key value in user's assets permission token name.
        pub const CAN_SET_KEY_VALUE_USER_ASSETS_TOKEN: &str = "can_set_key_value_in_user_assets";
        /// Can remove key value in user's assets permission token name.
        pub const CAN_REMOVE_KEY_VALUE_IN_USER_ASSETS: &str = "can_remove_key_value_in_user_assets";
        /// Can burn user's assets permission token name.
        pub const CAN_SET_KEY_VALUE_IN_USER_METADATA: &str = "can_set_key_value_in_user_metadata";
        /// Can burn user's assets permission token name.
        pub const CAN_REMOVE_KEY_VALUE_IN_USER_METADATA: &str =
            "can_remove_key_value_in_user_metadata";
        /// Target account id for setting and removing key value permission tokens.
        pub const ACCOUNT_ID_TOKEN_PARAM_NAME: &str = "account_id";

        /// Checks that account can set keys for assets only for the signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetSetOnlyForSignerAccount;

        impl_from_item_for_validator_box!(AssetSetOnlyForSignerAccount);

        impl PermissionsValidator for AssetSetOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::SetKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
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

        /// Allows setting user's assets key value map from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct SetGrantedByAssetOwner;

        impl_from_item_for_granted_token_validator_box!(SetGrantedByAssetOwner);

        impl GrantedTokenValidator for SetGrantedByAssetOwner {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                let set_box = if let Instruction::SetKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Err("Instruction is not set.".to_owned());
                };
                let object_id = set_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AssetId = if let Ok(object_id) = object_id.try_into() {
                    object_id
                } else {
                    return Err("Source id is not an AssetId.".to_owned());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(ASSET_ID_TOKEN_PARAM_NAME.to_owned(), object_id.into());
                Ok(PermissionToken::new(
                    CAN_SET_KEY_VALUE_USER_ASSETS_TOKEN,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetAccessSet;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccessSet);

        impl GrantInstructionValidator for GrantMyAssetAccessSet {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                if permission_token.name != CAN_SET_KEY_VALUE_USER_ASSETS_TOKEN {
                    return Err("Grant instruction is not for set permission.".to_owned());
                }
                check_asset_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }

        /// Checks that account can set keys only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AccountSetOnlyForSignerAccount;

        impl_from_item_for_validator_box!(AccountSetOnlyForSignerAccount);

        impl PermissionsValidator for AccountSetOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::SetKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
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

        impl GrantedTokenValidator for SetGrantedByAccountOwner {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                let set_box = if let Instruction::SetKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Err("Instruction is not set.".to_owned());
                };
                let object_id = set_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AccountId = if let Ok(object_id) = object_id.try_into() {
                    object_id
                } else {
                    return Err("Source id is not an AccountId.".to_owned());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(ACCOUNT_ID_TOKEN_PARAM_NAME.to_owned(), object_id.into());
                Ok(PermissionToken::new(
                    CAN_SET_KEY_VALUE_IN_USER_METADATA,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyMetadataAccessSet;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyMetadataAccessSet);

        impl GrantInstructionValidator for GrantMyMetadataAccessSet {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                if permission_token.name != CAN_SET_KEY_VALUE_IN_USER_METADATA {
                    return Err("Grant instruction is not for set permission.".to_owned());
                }
                check_account_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }

        /// Checks that account can remove keys for assets only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetRemoveOnlyForSignerAccount;

        impl_from_item_for_validator_box!(AssetRemoveOnlyForSignerAccount);

        impl PermissionsValidator for AssetRemoveOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::RemoveKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
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

        impl GrantedTokenValidator for RemoveGrantedByAssetOwner {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                let remove_box = if let Instruction::RemoveKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Err("Instruction is not set.".to_owned());
                };
                let object_id = remove_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AssetId = if let Ok(object_id) = object_id.try_into() {
                    object_id
                } else {
                    return Err("Source id is not an AssetId.".to_owned());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(ASSET_ID_TOKEN_PARAM_NAME.to_owned(), object_id.into());
                Ok(PermissionToken::new(
                    CAN_REMOVE_KEY_VALUE_IN_USER_ASSETS,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetAccessRemove;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccessRemove);

        impl GrantInstructionValidator for GrantMyAssetAccessRemove {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                if permission_token.name != CAN_REMOVE_KEY_VALUE_IN_USER_ASSETS {
                    return Err("Grant instruction is not for set permission.".to_owned());
                }
                check_asset_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }

        /// Checks that account can remove keys only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AccountRemoveOnlyForSignerAccount;

        impl_from_item_for_validator_box!(AccountRemoveOnlyForSignerAccount);

        impl PermissionsValidator for AccountRemoveOnlyForSignerAccount {
            fn check_instruction(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let instruction = if let Instruction::RemoveKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Ok(());
                };
                let object_id = instruction
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match object_id {
                    IdBox::AccountId(account_id) if &account_id != authority => Err(
                        "Can't remove value from account store from another account.".to_owned(),
                    ),
                    _ => Ok(()),
                }
            }
        }

        /// Allows removing user's metadata key value pairs from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct RemoveGrantedByAccountOwner;

        impl_from_item_for_granted_token_validator_box!(RemoveGrantedByAccountOwner);

        impl GrantedTokenValidator for RemoveGrantedByAccountOwner {
            fn should_have_token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView,
            ) -> Result<PermissionToken, String> {
                let remove_box = if let Instruction::RemoveKeyValue(instruction) = instruction {
                    instruction
                } else {
                    return Err("Instruction is not remove.".to_owned());
                };
                let object_id = remove_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AccountId = if let Ok(object_id) = object_id.try_into() {
                    object_id
                } else {
                    return Err("Source id is not an AccountId.".to_owned());
                };
                let mut params = BTreeMap::new();
                let _ = params.insert(ACCOUNT_ID_TOKEN_PARAM_NAME.to_owned(), object_id.into());
                Ok(PermissionToken::new(
                    CAN_REMOVE_KEY_VALUE_IN_USER_METADATA,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the metadata
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyMetadataAccessRemove;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyMetadataAccessRemove);

        impl GrantInstructionValidator for GrantMyMetadataAccessRemove {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView,
            ) -> Result<(), DenialReason> {
                let permission_token = instruction
                    .permission_token
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                if permission_token.name != CAN_REMOVE_KEY_VALUE_IN_USER_METADATA {
                    return Err("Grant instruction is not for remove permission.".to_owned());
                }
                check_account_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::restriction)]

        use maplit::{btreemap, btreeset};

        use super::*;

        #[test]
        fn transfer_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "bob", "test");
            let wsv = WorldStateView::new(World::new());
            let transfer = Instruction::Transfer(TransferBox {
                source_id: IdBox::AssetId(alice_xor_id).into(),
                object: Value::U32(10).into(),
                destination_id: IdBox::AssetId(bob_xor_id).into(),
            });
            assert!(transfer::OnlyOwnedAssets
                .check_instruction(&alice_id, &transfer, &wsv)
                .is_ok());
            assert!(transfer::OnlyOwnedAssets
                .check_instruction(&bob_id, &transfer, &wsv)
                .is_err());
        }

        #[test]
        fn transfer_granted_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "bob", "test");
            let mut domain = Domain::new("test");
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                transfer::CAN_TRANSFER_USER_ASSETS_TOKEN,
                btreemap! {
                    ASSET_ID_TOKEN_PARAM_NAME.to_owned() => alice_xor_id.clone().into(),
                },
            ));
            let _ = domain.accounts.insert(bob_id.clone(), bob_account);
            let domains = btreemap! {
                "test".to_owned() => domain
            };
            let wsv = WorldStateView::new(World::with(domains, btreeset! {}));
            let transfer = Instruction::Transfer(TransferBox {
                source_id: IdBox::AssetId(alice_xor_id).into(),
                object: Value::U32(10).into(),
                destination_id: IdBox::AssetId(bob_xor_id).into(),
            });
            let validator: PermissionsValidatorBox = transfer::OnlyOwnedAssets
                .or(transfer::GrantedByAssetOwner)
                .into();
            assert!(validator
                .check_instruction(&alice_id, &transfer, &wsv)
                .is_ok());
            assert!(validator
                .check_instruction(&bob_id, &transfer, &wsv)
                .is_ok());
        }

        #[test]
        fn grant_transfer_of_my_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let permission_token_to_alice = PermissionToken::new(
                transfer::CAN_TRANSFER_USER_ASSETS_TOKEN,
                btreemap! {
                    ASSET_ID_TOKEN_PARAM_NAME.to_owned() => alice_xor_id.into(),
                },
            );
            let wsv = WorldStateView::new(World::new());
            let grant = Instruction::Grant(GrantBox {
                permission_token: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: PermissionsValidatorBox = transfer::GrantMyAssetAccess.into();
            assert!(validator.check_instruction(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check_instruction(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn unregister_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_owned() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_owned(),
                    asset_definitions: btreemap! {
                        xor_id.clone() =>
                        AssetDefinitionEntry {
                            definition: xor_definition,
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let unregister =
                Instruction::Unregister(UnregisterBox::new(IdBox::AssetDefinitionId(xor_id)));
            assert!(unregister::OnlyAssetsCreatedByThisAccount
                .check_instruction(&alice_id, &unregister, &wsv)
                .is_ok());
            assert!(unregister::OnlyAssetsCreatedByThisAccount
                .check_instruction(&bob_id, &unregister, &wsv)
                .is_err());
        }

        #[test]
        fn unregister_granted_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let mut domain = Domain::new("test");
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                unregister::CAN_UNREGISTER_ASSET_WITH_DEFINITION,
                btreemap! {
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned() => xor_id.clone().into(),
                },
            ));
            let _ = domain.accounts.insert(bob_id.clone(), bob_account);
            let _ = domain.asset_definitions.insert(
                xor_id.clone(),
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = btreemap! {
                "test".to_owned() => domain
            };
            let wsv = WorldStateView::new(World::with(domains, btreeset! {}));
            let instruction = Instruction::Unregister(UnregisterBox::new(xor_id));
            let validator: PermissionsValidatorBox = unregister::OnlyAssetsCreatedByThisAccount
                .or(unregister::GrantedByAssetCreator)
                .into();
            assert!(validator
                .check_instruction(&alice_id, &instruction, &wsv)
                .is_ok());
            assert!(validator
                .check_instruction(&bob_id, &instruction, &wsv)
                .is_ok());
        }

        #[test]
        fn grant_unregister_of_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let permission_token_to_alice = PermissionToken::new(
                unregister::CAN_UNREGISTER_ASSET_WITH_DEFINITION,
                btreemap! {
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned() => xor_id.clone().into(),
                },
            );
            let mut domain = Domain::new("test");
            let _ = domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = btreemap! {
                "test".to_owned() => domain
            };
            let wsv = WorldStateView::new(World::with(domains, btreeset! {}));
            let grant = Instruction::Grant(GrantBox {
                permission_token: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: PermissionsValidatorBox = unregister::GrantRegisteredByMeAccess.into();
            assert!(validator.check_instruction(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check_instruction(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn mint_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_owned() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_owned(),
                    asset_definitions: btreemap! {
                        xor_id =>
                        AssetDefinitionEntry {
                            definition: xor_definition,
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let mint = Instruction::Mint(MintBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(mint::OnlyAssetsCreatedByThisAccount
                .check_instruction(&alice_id, &mint, &wsv)
                .is_ok());
            assert!(mint::OnlyAssetsCreatedByThisAccount
                .check_instruction(&bob_id, &mint, &wsv)
                .is_err());
        }

        #[test]
        fn mint_granted_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let mut domain = Domain::new("test");
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                mint::CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN,
                btreemap! {
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned() => xor_id.clone().into(),
                },
            ));
            let _ = domain.accounts.insert(bob_id.clone(), bob_account);
            let _ = domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = btreemap! {
                "test".to_owned() => domain
            };
            let wsv = WorldStateView::new(World::with(domains, btreeset! {}));
            let instruction = Instruction::Mint(MintBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            let validator: PermissionsValidatorBox = mint::OnlyAssetsCreatedByThisAccount
                .or(mint::GrantedByAssetCreator)
                .into();
            assert!(validator
                .check_instruction(&alice_id, &instruction, &wsv)
                .is_ok());
            assert!(validator
                .check_instruction(&bob_id, &instruction, &wsv)
                .is_ok());
        }

        #[test]
        fn grant_mint_of_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let permission_token_to_alice = PermissionToken::new(
                mint::CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN,
                btreemap! {
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned() => xor_id.clone().into(),
                },
            );
            let mut domain = Domain::new("test");
            let _ = domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = btreemap! {
                "test".to_owned() => domain
            };
            let wsv = WorldStateView::new(World::with(domains, btreeset! {}));
            let grant = Instruction::Grant(GrantBox {
                permission_token: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: PermissionsValidatorBox = mint::GrantRegisteredByMeAccess.into();
            assert!(validator.check_instruction(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check_instruction(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn burn_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let wsv = WorldStateView::new(World::with(
                btreemap! {
                    "test".to_owned() => Domain {
                    accounts: btreemap! {},
                    name: "test".to_owned(),
                    asset_definitions: btreemap! {
                        xor_id =>
                        AssetDefinitionEntry {
                            definition: xor_definition,
                            registered_by: alice_id.clone()
                        }
                    },
                }},
                btreeset! {},
            ));
            let burn = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(burn::OnlyAssetsCreatedByThisAccount
                .check_instruction(&alice_id, &burn, &wsv)
                .is_ok());
            assert!(burn::OnlyAssetsCreatedByThisAccount
                .check_instruction(&bob_id, &burn, &wsv)
                .is_err());
        }

        #[test]
        fn burn_granted_asset_definition() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let mut domain = Domain::new("test");
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                burn::CAN_BURN_ASSET_WITH_DEFINITION,
                btreemap! {
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned() => xor_id.clone().into(),
                },
            ));
            let _ = domain.accounts.insert(bob_id.clone(), bob_account);
            let _ = domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = btreemap! {
                "test".to_owned() => domain
            };
            let wsv = WorldStateView::new(World::with(domains, btreeset! {}));
            let instruction = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            let validator: PermissionsValidatorBox = burn::OnlyAssetsCreatedByThisAccount
                .or(burn::GrantedByAssetCreator)
                .into();
            assert!(validator
                .check_instruction(&alice_id, &instruction, &wsv)
                .is_ok());
            assert!(validator
                .check_instruction(&bob_id, &instruction, &wsv)
                .is_ok());
        }

        #[test]
        fn grant_burn_of_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test");
            let xor_definition = AssetDefinition::new_quantity(xor_id.clone());
            let permission_token_to_alice = PermissionToken::new(
                burn::CAN_BURN_ASSET_WITH_DEFINITION,
                btreemap! {
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME.to_owned() => xor_id.clone().into(),
                },
            );
            let mut domain = Domain::new("test");
            let _ = domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = btreemap! {
                "test".to_owned() => domain
            };
            let wsv = WorldStateView::new(World::with(domains, btreeset! {}));
            let grant = Instruction::Grant(GrantBox {
                permission_token: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: PermissionsValidatorBox = burn::GrantRegisteredByMeAccess.into();
            assert!(validator.check_instruction(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check_instruction(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn burn_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let wsv = WorldStateView::new(World::new());
            let burn = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(burn::OnlyOwnedAssets
                .check_instruction(&alice_id, &burn, &wsv)
                .is_ok());
            assert!(burn::OnlyOwnedAssets
                .check_instruction(&bob_id, &burn, &wsv)
                .is_err());
        }

        #[test]
        fn burn_granted_assets() -> Result<(), String> {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let mut domain = Domain::new("test");
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                burn::CAN_BURN_USER_ASSETS_TOKEN,
                btreemap! {
                    ASSET_ID_TOKEN_PARAM_NAME.to_owned() => alice_xor_id.clone().into(),
                },
            ));
            let _ = domain.accounts.insert(bob_id.clone(), bob_account);
            let domains = btreemap! {
                "test".to_owned() => domain
            };
            let wsv = WorldStateView::new(World::with(domains, btreeset! {}));
            let transfer = Instruction::Burn(BurnBox {
                object: Value::U32(10).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            let validator: PermissionsValidatorBox =
                burn::OnlyOwnedAssets.or(burn::GrantedByAssetOwner).into();
            validator.check_instruction(&alice_id, &transfer, &wsv)?;
            assert!(validator
                .check_instruction(&bob_id, &transfer, &wsv)
                .is_ok());
            Ok(())
        }

        #[test]
        fn grant_burn_of_my_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let permission_token_to_alice = PermissionToken::new(
                burn::CAN_BURN_USER_ASSETS_TOKEN,
                btreemap! {
                    ASSET_ID_TOKEN_PARAM_NAME.to_owned() => alice_xor_id.into(),
                },
            );
            let wsv = WorldStateView::new(World::new());
            let grant = Instruction::Grant(GrantBox {
                permission_token: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: PermissionsValidatorBox = burn::GrantMyAssetAccess.into();
            assert!(validator.check_instruction(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check_instruction(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn set_to_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::SetKeyValue(SetKeyValueBox::new(
                IdBox::AssetId(alice_xor_id),
                Value::from("key".to_owned()),
                Value::from("value".to_owned()),
            ));
            assert!(key_value::AssetSetOnlyForSignerAccount
                .check_instruction(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AssetSetOnlyForSignerAccount
                .check_instruction(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn remove_to_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
                IdBox::AssetId(alice_xor_id),
                Value::from("key".to_owned()),
            ));
            assert!(key_value::AssetRemoveOnlyForSignerAccount
                .check_instruction(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AssetRemoveOnlyForSignerAccount
                .check_instruction(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn set_to_only_owned_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::SetKeyValue(SetKeyValueBox::new(
                IdBox::AccountId(alice_id.clone()),
                Value::from("key".to_owned()),
                Value::from("value".to_owned()),
            ));
            assert!(key_value::AccountSetOnlyForSignerAccount
                .check_instruction(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AccountSetOnlyForSignerAccount
                .check_instruction(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn remove_to_only_owned_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let wsv = WorldStateView::new(World::new());
            let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
                IdBox::AccountId(alice_id.clone()),
                Value::from("key".to_owned()),
            ));
            assert!(key_value::AccountRemoveOnlyForSignerAccount
                .check_instruction(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AccountRemoveOnlyForSignerAccount
                .check_instruction(&bob_id, &set, &wsv)
                .is_err());
        }
    }
}
