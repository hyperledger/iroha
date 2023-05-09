use account::{
    validate_burn_account_public_key, validate_mint_account_public_key,
    validate_mint_account_signature_check_condition, validate_remove_account_key_value,
    validate_set_account_key_value, validate_unregister_account,
};
use asset::{
    validate_burn_asset, validate_mint_asset, validate_register_asset,
    validate_remove_asset_key_value, validate_set_asset_key_value, validate_transfer_asset,
    validate_unregister_asset,
};
use asset_definition::{
    validate_remove_asset_definition_key_value, validate_set_asset_definition_key_value,
    validate_transfer_asset_definition, validate_unregister_asset_definition,
};
use domain::{
    validate_remove_domain_key_value, validate_set_domain_key_value, validate_unregister_domain,
};
use iroha_validator::{data_model::prelude::*, permission, permission::Token as _, prelude::*};
use parameter::{validate_new_parameter, validate_set_parameter};
use peer::validate_unregister_peer;
use permission_token::{
    validate_grant_account_permission, validate_register_permission_token,
    validate_revoke_account_permission,
};
use role::{validate_grant_account_role, validate_revoke_account_role, validate_unregister_role};
use trigger::{
    validate_execute_trigger, validate_mint_trigger_repetitions, validate_unregister_trigger,
};
use validator::validate_upgrade_validator;

use super::*;

macro_rules! custom_impls {
    ( $($validator:ident($operation:ty)),+ $(,)? ) => { $(
        fn $validator(&mut self, authority: &AccountId, operation: $operation) -> Verdict {
            $validator(self, authority, operation)
        } )+
    }
}

/// Apply `callback` macro for all token types from this crate.
///
/// Callback technique is used because of macro expansion order. With that technique we can
/// apply callback to token types declared in other modules.
///
/// # WARNING !!!
///
/// If you add new module with tokens don't forget to add it here!
macro_rules! map_all_crate_tokens {
    ($callback:ident) => {
        $crate::default::account::map_tokens!($callback);
        $crate::default::asset::map_tokens!($callback);
        $crate::default::asset_definition::map_tokens!($callback);
        $crate::default::domain::map_tokens!($callback);
        $crate::default::parameter::map_tokens!($callback);
        $crate::default::peer::map_tokens!($callback);
        $crate::default::role::map_tokens!($callback);
        $crate::default::trigger::map_tokens!($callback);
        $crate::default::validator::map_tokens!($callback);
    };
}

macro_rules! tokens {
    (
        pattern = {
            $(#[$meta:meta])*
            $vis:vis struct _ {
                $(
                    $(#[$field_meta:meta])*
                    $field_vis:vis $field:ident: $field_type:ty
                ),* $(,)?
            }
        },
        $module:ident :: tokens: [$($name:ident),+ $(,)?]
    ) => {
        declare_tokens!($(
            crate::default::$module::tokens::$name
        ),+);

        pub mod tokens {
            //! Permission tokens for concrete operations.

            use super::*;

            macro_rules! single_token {
                ($name_internal:ident) => {
                    $(#[$meta])*
                    #[allow(missing_docs)]
                    $vis struct $name_internal {
                        $(
                            $(#[$field_meta])*
                            $field_vis $field: $field_type
                        ),*
                    }
                };
            }

            $(single_token!($name);)+
        }
    };
}

pub(crate) use map_all_crate_tokens;
pub(crate) use tokens;

/// Validator that replaces some of [`Validate`]'s methods with sensible defaults
///
/// # Warning
///
/// The defaults are not guaranteed to be stable.
#[derive(Debug, Clone, Copy)]
pub struct DefaultValidator;

impl Validate for DefaultValidator {
    //fn evaluator(&mut self) -> E {
    //    self.0
    //}

    custom_impls! {
        // Peer validation
        validate_unregister_peer(Unregister<Peer>),

        // Domain validation
        validate_unregister_domain(Unregister<Domain>),
        validate_set_domain_key_value(SetKeyValue<Domain>),
        validate_remove_domain_key_value(RemoveKeyValue<Domain>),

        // Account validation
        validate_unregister_account(Unregister<Account>),
        validate_mint_account_public_key(Mint<Account, PublicKey>),
        validate_burn_account_public_key(Burn<Account, PublicKey>),
        validate_mint_account_signature_check_condition(Mint<Account, SignatureCheckCondition>),
        validate_set_account_key_value(SetKeyValue<Account>),
        validate_remove_account_key_value(RemoveKeyValue<Account>),

        // Asset validation
        validate_register_asset(Register<Asset>),
        validate_unregister_asset(Unregister<Asset>),
        validate_mint_asset(Mint<Asset, NumericValue>),
        validate_burn_asset(Burn<Asset, NumericValue>),
        validate_transfer_asset(Transfer<Asset, NumericValue, Account>),
        validate_set_asset_key_value(SetKeyValue<Asset>),
        validate_remove_asset_key_value(RemoveKeyValue<Asset>),

        // AssetDefinition validation
        validate_unregister_asset_definition(Unregister<AssetDefinition>),
        validate_transfer_asset_definition(Transfer<Account, AssetDefinition, Account>),
        validate_set_asset_definition_key_value(SetKeyValue<AssetDefinition>),
        validate_remove_asset_definition_key_value(RemoveKeyValue<AssetDefinition>),

        // Permission validation
        validate_register_permission_token(Register<PermissionTokenDefinition>),
        validate_grant_account_permission(Grant<Account, PermissionToken>),
        validate_revoke_account_permission(Revoke<Account, PermissionToken>),

        // Role validation
        validate_unregister_role(Unregister<Role>),
        validate_grant_account_role(Grant<Account, RoleId>),
        validate_revoke_account_role(Revoke<Account, RoleId>),

        // Trigger validation
        validate_unregister_trigger(Unregister<Trigger<FilterBox, Executable>>),
        validate_mint_trigger_repetitions(Mint<Trigger<FilterBox, Executable>, u32>),
        validate_execute_trigger(ExecuteTrigger),

        // Parameter validation
        validate_set_parameter(SetParameter),
        validate_new_parameter(NewParameter),

        // Upgrade validation
        validate_upgrade_validator(Upgrade<iroha_validator::data_model::validator::Validator>),
    }
}

pub mod peer {
    //! Validation and tokens related to peer operations.

    use super::*;

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            #[derive(Clone, Copy)]
            pub struct _ {}
        },
        peer::tokens: [
            CanUnregisterAnyPeer,
        ]
    );

    #[allow(missing_docs, clippy::needless_pass_by_value)]
    pub fn validate_unregister_peer<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        _isi: Unregister<Peer>,
    ) -> Verdict {
        const CAN_UNREGISTER_PEER_TOKEN: tokens::CanUnregisterAnyPeer =
            tokens::CanUnregisterAnyPeer {};

        if CAN_UNREGISTER_PEER_TOKEN.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't unregister peer");
    }
}

pub mod domain {
    //! Validation and tokens related to domain operations.

    use super::*;

    // TODO: We probably need a better way to allow accounts to modify domains.
    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            pub struct _ {
                pub domain_id: <Domain as Identifiable>::Id,
            }
        },
        domain::tokens: [
            CanUnregisterDomain,
            CanSetKeyValueInDomain,
            CanRemoveKeyValueInDomain,
        ]
    );

    #[allow(missing_docs)]
    pub fn validate_unregister_domain<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Domain>,
    ) -> Verdict {
        let domain_id = isi.object_id;

        let can_unregister_domain_token = tokens::CanUnregisterDomain { domain_id };
        if can_unregister_domain_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't unregister domain");
    }

    #[allow(missing_docs)]
    pub fn validate_set_domain_key_value<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Domain>,
    ) -> Verdict {
        let domain_id = isi.object_id;

        let can_set_key_value_in_domain_token = tokens::CanSetKeyValueInDomain { domain_id };
        if can_set_key_value_in_domain_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't set key value in domain metadata");
    }

    #[allow(missing_docs)]
    pub fn validate_remove_domain_key_value<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Domain>,
    ) -> Verdict {
        let domain_id = isi.object_id;

        let can_remove_key_value_in_domain_token = tokens::CanRemoveKeyValueInDomain { domain_id };
        if can_remove_key_value_in_domain_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't remove key value in domain metadata");
    }
}

pub mod account {
    //! Validation and tokens related to account operations.

    use super::*;

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
            #[validate(permission::account::Owner)]
            pub struct _ {
                pub account_id: AccountId,
            }
        },
        account::tokens: [
            CanUnregisterAccount,
            CanMintUserPublicKeys,
            CanBurnUserPublicKeys,
            CanMintUserSignatureCheckConditions,
            CanSetKeyValueInUserAccount,
            CanRemoveKeyValueInUserAccount,
        ]
    );

    fn is_authority(account_id: &AccountId, authority: &AccountId) -> bool {
        account_id == authority
    }

    #[allow(missing_docs)]
    pub fn validate_unregister_account<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Account>,
    ) -> Verdict {
        let account_id = isi.object_id;

        if is_authority(&account_id, authority) {
            pass!();
        }
        let can_unregister_user_account = tokens::CanUnregisterAccount { account_id };
        if can_unregister_user_account.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't unregister another account");
    }

    #[allow(missing_docs)]
    pub fn validate_mint_account_public_key<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Mint<Account, PublicKey>,
    ) -> Verdict {
        let account_id = isi.destination_id;

        if is_authority(&account_id, authority) {
            pass!();
        }
        let can_mint_user_public_keys = tokens::CanMintUserPublicKeys { account_id };
        if can_mint_user_public_keys.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't mint public keys of another account");
    }

    #[allow(missing_docs)]
    pub fn validate_burn_account_public_key<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Burn<Account, PublicKey>,
    ) -> Verdict {
        let account_id = isi.destination_id;

        if is_authority(&account_id, authority) {
            pass!();
        }
        let can_burn_user_public_keys = tokens::CanBurnUserPublicKeys { account_id };
        if can_burn_user_public_keys.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't burn public keys of another account");
    }

    #[allow(missing_docs)]
    pub fn validate_mint_account_signature_check_condition<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Mint<Account, SignatureCheckCondition>,
    ) -> Verdict {
        let account_id = isi.destination_id;

        if is_authority(&account_id, authority) {
            pass!();
        }
        let can_mint_user_signature_check_conditions_token =
            tokens::CanMintUserSignatureCheckConditions { account_id };
        if can_mint_user_signature_check_conditions_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't mint signature check conditions of another account");
    }

    #[allow(missing_docs)]
    pub fn validate_set_account_key_value<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Account>,
    ) -> Verdict {
        let account_id = isi.object_id;

        if is_authority(&account_id, authority) {
            pass!();
        }
        let can_set_key_value_in_user_account_token =
            tokens::CanSetKeyValueInUserAccount { account_id };
        if can_set_key_value_in_user_account_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't set value to the metadata of another account");
    }

    #[allow(missing_docs)]
    pub fn validate_remove_account_key_value<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Account>,
    ) -> Verdict {
        let account_id = isi.object_id;

        if is_authority(&account_id, authority) {
            pass!();
        }
        let can_remove_key_value_in_user_account_token =
            tokens::CanRemoveKeyValueInUserAccount { account_id };
        if can_remove_key_value_in_user_account_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't remove value from the metadata of another account");
    }
}

pub mod asset_definition {
    //! Validation and tokens related to asset definition operations.
    use iroha_validator::permission::asset_definition::is_asset_definition_owner;

    use super::*;

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
            #[validate(permission::asset_definition::Owner)]
            pub struct _ {
                pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
            }
        },
        asset_definition::tokens: [
            CanUnregisterAssetDefinition,
            CanSetKeyValueInAssetDefinition,
            CanRemoveKeyValueInAssetDefinition,
        ]
    );

    #[allow(missing_docs)]
    pub fn validate_unregister_asset_definition<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Unregister<AssetDefinition>,
    ) -> Verdict {
        let asset_definition_id = isi.object_id;

        if is_asset_definition_owner(&asset_definition_id, authority) {
            pass!();
        }
        let can_unregister_asset_definition_token = tokens::CanUnregisterAssetDefinition {
            asset_definition_id,
        };
        if can_unregister_asset_definition_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't unregister assets registered by other accounts");
    }

    #[allow(missing_docs)]
    pub fn validate_transfer_asset_definition<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Transfer<Account, AssetDefinition, Account>,
    ) -> Verdict {
        let source_id = isi.source_id;
        let destination_id = isi.object;

        if &source_id == authority {
            pass!();
        }
        if is_asset_definition_owner(destination_id.id(), authority) {
            pass!();
        }

        deny!("Can't transfer asset definition of another account");
    }

    #[allow(missing_docs)]
    pub fn validate_set_asset_definition_key_value<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<AssetDefinition>,
    ) -> Verdict {
        let asset_definition_id = isi.object_id;

        if is_asset_definition_owner(&asset_definition_id, authority) {
            pass!();
        }
        let can_set_key_value_in_asset_definition_token = tokens::CanSetKeyValueInAssetDefinition {
            asset_definition_id,
        };
        if can_set_key_value_in_asset_definition_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't set value to the asset definition metadata created by another account");
    }

    #[allow(missing_docs)]
    pub fn validate_remove_asset_definition_key_value<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<AssetDefinition>,
    ) -> Verdict {
        let asset_definition_id = isi.object_id;

        if is_asset_definition_owner(&asset_definition_id, authority) {
            pass!();
        }
        let can_remove_key_value_in_asset_definition_token =
            tokens::CanRemoveKeyValueInAssetDefinition {
                asset_definition_id,
            };
        if can_remove_key_value_in_asset_definition_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't remove value from the asset definition metadata created by another account");
    }
}

pub mod asset {
    //! Validation and tokens related to asset operations.

    use iroha_validator::permission::asset_definition::is_asset_definition_owner;

    use super::*;

    declare_tokens!(
        crate::default::asset::tokens::CanRegisterAssetsWithDefinition,
        crate::default::asset::tokens::CanUnregisterAssetsWithDefinition,
        crate::default::asset::tokens::CanUnregisterUserAsset,
        crate::default::asset::tokens::CanBurnAssetsWithDefinition,
        crate::default::asset::tokens::CanBurnUserAsset,
        crate::default::asset::tokens::CanMintAssetsWithDefinition,
        crate::default::asset::tokens::CanTransferAssetsWithDefinition,
        crate::default::asset::tokens::CanTransferUserAsset,
        crate::default::asset::tokens::CanSetKeyValueInUserAsset,
        crate::default::asset::tokens::CanRemoveKeyValueInUserAsset,
    );

    pub mod tokens {
        //! Permission tokens for asset operations

        use super::*;

        /// Strongly-typed representation of `can_register_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanRegisterAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_unregister_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanUnregisterAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_unregister_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanUnregisterUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_burn_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanBurnAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strong-typed representation of `can_burn_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanBurnUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_mint_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanMintAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_transfer_assets_with_definition` permission token.
        #[derive(
            Token, ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner,
        )]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanTransferAssetsWithDefinition {
            pub asset_definition_id: <AssetDefinition as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_transfer_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanTransferUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_set_key_value_in_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanSetKeyValueInUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
        }

        /// Strongly-typed representation of `can_remove_key_value_in_user_asset` permission token.
        #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanRemoveKeyValueInUserAsset {
            pub asset_id: <Asset as Identifiable>::Id,
        }
    }

    fn is_authority(asset_id: &AssetId, authority: &AccountId) -> bool {
        asset_id.account_id() == authority
    }

    #[allow(missing_docs)]
    pub fn validate_register_asset<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Register<Asset>,
    ) -> Verdict {
        let asset = isi.object;

        if is_asset_definition_owner(asset.id().definition_id(), authority) {
            pass!();
        }
        let can_register_assets_with_definition_token = tokens::CanRegisterAssetsWithDefinition {
            asset_definition_id: asset.id().definition_id().clone(),
        };
        if can_register_assets_with_definition_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't register assets with definitions registered by other accounts");
    }

    #[allow(missing_docs)]
    pub fn validate_unregister_asset<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Asset>,
    ) -> Verdict {
        let asset_id = isi.object_id;

        if is_authority(&asset_id, authority) {
            pass!();
        }
        if is_asset_definition_owner(asset_id.definition_id(), authority) {
            pass!();
        }
        let can_unregister_assets_with_definition_token =
            tokens::CanUnregisterAssetsWithDefinition {
                asset_definition_id: asset_id.definition_id().clone(),
            };
        if can_unregister_assets_with_definition_token.is_owned_by(authority) {
            pass!();
        }
        let can_unregister_user_asset_token = tokens::CanUnregisterUserAsset { asset_id };
        if can_unregister_user_asset_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't unregister asset from another account");
    }

    #[allow(missing_docs)]
    pub fn validate_mint_asset<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Mint<Asset, NumericValue>,
    ) -> Verdict {
        let asset_id = isi.destination_id;

        if is_asset_definition_owner(asset_id.definition_id(), authority) {
            pass!();
        }
        let can_mint_assets_with_definition_token = tokens::CanMintAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_mint_assets_with_definition_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't mint assets with definitions registered by other accounts");
    }

    #[allow(missing_docs)]
    pub fn validate_burn_asset<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Burn<Asset, NumericValue>,
    ) -> Verdict {
        let asset_id = isi.destination_id;

        if is_authority(&asset_id, authority) {
            pass!()
        }
        if is_asset_definition_owner(asset_id.definition_id(), authority) {
            pass!();
        }
        let can_burn_assets_with_definition_token = tokens::CanBurnAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_burn_assets_with_definition_token.is_owned_by(authority) {
            pass!();
        }
        let can_burn_user_asset_token = tokens::CanBurnUserAsset { asset_id };
        if can_burn_user_asset_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't burn assets from another account");
    }

    #[allow(missing_docs)]
    pub fn validate_transfer_asset<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Transfer<Asset, NumericValue, Account>,
    ) -> Verdict {
        let asset_id = isi.source_id;

        if is_authority(&asset_id, authority) {
            pass!();
        }
        if is_asset_definition_owner(asset_id.definition_id(), authority) {
            pass!();
        }
        let can_transfer_assets_with_definition_token = tokens::CanTransferAssetsWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_transfer_assets_with_definition_token.is_owned_by(authority) {
            pass!()
        }
        let can_transfer_user_asset_token = tokens::CanTransferUserAsset { asset_id };
        if can_transfer_user_asset_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't transfer assets of another account");
    }

    #[allow(missing_docs)]
    pub fn validate_set_asset_key_value<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: SetKeyValue<Asset>,
    ) -> Verdict {
        let asset_id = isi.object_id;

        if is_authority(&asset_id, authority) {
            pass!();
        }
        let can_set_key_value_in_user_asset_token = tokens::CanSetKeyValueInUserAsset { asset_id };
        if can_set_key_value_in_user_asset_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't set value to the asset metadata of another account");
    }

    #[allow(missing_docs)]
    pub fn validate_remove_asset_key_value<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: RemoveKeyValue<Asset>,
    ) -> Verdict {
        let asset_id = isi.object_id;

        if is_authority(&asset_id, authority) {
            pass!();
        }
        let can_remove_key_value_in_user_asset_token =
            tokens::CanRemoveKeyValueInUserAsset { asset_id };
        if can_remove_key_value_in_user_asset_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't remove value from the asset metadata of another account");
    }
}

pub mod parameter {
    //! Validation and tokens related to parameter operations.

    use iroha_validator::permission::ValidateGrantRevoke;

    use super::*;

    declare_tokens!(
        crate::default::parameter::tokens::CanGrantPermissionToCreateParameters,
        crate::default::parameter::tokens::CanRevokePermissionToCreateParameters,
        crate::default::parameter::tokens::CanCreateParameters,
        crate::default::parameter::tokens::CanGrantPermissionToSetParameters,
        crate::default::parameter::tokens::CanRevokePermissionToSetParameters,
        crate::default::parameter::tokens::CanSetParameters,
    );

    pub mod tokens {
        //! Permission tokens for asset definition operations

        use super::*;

        /// Strongly-typed representation of `can_grant_permission_to_create_parameters` permission token.
        #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanGrantPermissionToCreateParameters;

        /// Strongly-typed representation of `can_revoke_permission_to_create_parameters` permission token.
        #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanRevokePermissionToCreateParameters;

        /// Strongly-typed representation of `can_create_parameters` permission token.
        #[derive(Token, Clone, Copy)]
        pub struct CanCreateParameters;

        impl ValidateGrantRevoke for CanCreateParameters {
            fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
                if CanGrantPermissionToCreateParameters.is_owned_by(authority) {
                    pass!();
                }

                deny!("Can't grant permission to create new configuration parameters without permission from genesis");
            }

            fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
                if CanRevokePermissionToCreateParameters.is_owned_by(authority) {
                    pass!();
                }

                deny!("Can't revoke permission to create new configuration parameters without permission from genesis");
            }
        }

        /// Strongly-typed representation of `can_grant_permission_to_set_parameters` permission token.
        #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanGrantPermissionToSetParameters;

        /// Strongly-typed representation of `can_revoke_permission_to_set_parameters` permission token.
        #[derive(Token, ValidateGrantRevoke, Clone, Copy)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanRevokePermissionToSetParameters;

        /// Strongly-typed representation of `can_set_parameters` permission token.
        #[derive(Token, Clone, Copy)]
        pub struct CanSetParameters;

        impl ValidateGrantRevoke for CanSetParameters {
            fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
                if !CanGrantPermissionToSetParameters.is_owned_by(authority) {
                    pass!();
                }

                deny!("Can't grant permission to set configuration parameters without permission from genesis");
            }

            fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
                if CanRevokePermissionToSetParameters.is_owned_by(authority) {
                    pass!();
                }

                deny!("Can't revoke permission to set configuration parameters without permission from genesis");
            }
        }
    }

    #[allow(missing_docs, clippy::needless_pass_by_value)]
    pub fn validate_new_parameter<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        _isi: NewParameter,
    ) -> Verdict {
        if !tokens::CanCreateParameters.is_owned_by(authority) {
            deny!("Can't create new configuration parameters without permission");
        }

        pass!();
    }

    #[allow(missing_docs, clippy::needless_pass_by_value)]
    pub fn validate_set_parameter<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        _isi: SetParameter,
    ) -> Verdict {
        if !tokens::CanSetParameters.is_owned_by(authority) {
            deny!("Can't set configuration parameters without permission");
        }

        pass!();
    }
}

pub mod role {
    //! Validation and tokens related to role operations.

    use super::*;

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            #[derive(Clone, Copy)]
            pub struct _ {}
        },
        role::tokens: [
            CanUnregisterAnyRole,
        ]
    );

    macro_rules! impl_validate {
        ($self:ident, $authority:ident, $method:ident) => {
            let role_id = $self.object;

            let find_role_query_res = QueryBox::from(FindRoleByRoleId::new(role_id)).execute();
            let role = Role::try_from(find_role_query_res)
                .dbg_expect("Failed to convert `FindRoleByRoleId` query result to `Role`");

            for token in role.permissions() {
                macro_rules! validate_internal {
                    ($token_ty:ty) => {
                        if let Ok(concrete_token) =
                            <$token_ty as ::core::convert::TryFrom<_>>::try_from(
                                <
                                    ::iroha_validator::data_model::permission::PermissionToken as
                                    ::core::clone::Clone
                                >::clone(token)
                            )
                        {
                            let verdict = <$token_ty as ::iroha_validator::permission::ValidateGrantRevoke>::$method(
                                &concrete_token,
                                $authority,
                            );
                            if verdict.is_err() {
                                return verdict;
                            }
                            // Continue because token can correspond to only one concrete token
                            continue;
                        }
                    };
                }

                map_all_crate_tokens!(validate_internal);

                // In normal situation we either did early return or continue before reaching this line
                ::iroha_validator::iroha_wasm::debug::dbg_panic("Role contains unknown permission token, this should never happen");
            }

            pass!()
        };
    }

    #[allow(missing_docs, clippy::needless_pass_by_value)]
    pub fn validate_unregister_role<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        _isi: Unregister<Role>,
    ) -> Verdict {
        const CAN_UNREGISTER_ROLE_TOKEN: tokens::CanUnregisterAnyRole =
            tokens::CanUnregisterAnyRole {};

        if CAN_UNREGISTER_ROLE_TOKEN.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't unregister role");
    }

    #[allow(missing_docs)]
    pub fn validate_grant_account_role<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Grant<Account, RoleId>,
    ) -> Verdict {
        impl_validate!(isi, authority, validate_grant);
    }

    #[allow(missing_docs)]
    pub fn validate_revoke_account_role<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Revoke<Account, RoleId>,
    ) -> Verdict {
        impl_validate!(isi, authority, validate_revoke);
    }
}

pub mod trigger {
    //! Validation and tokens related to trigger operations

    use iroha_validator::permission::trigger::is_trigger_owner;

    use super::*;

    macro_rules! impl_froms {
        ($($name:path),+ $(,)?) => {$(
            impl<'token> From<&'token $name> for permission::trigger::Owner<'token> {
                fn from(value: &'token $name) -> Self {
                    Self {
                        trigger_id: &value.trigger_id,
                    }
                }
            }
        )+};
    }

    tokens!(
        pattern = {
            #[derive(Token, Clone, ValidateGrantRevoke)]
            #[validate(permission::trigger::Owner)]
            pub struct _ {
                pub trigger_id: <Trigger<FilterBox, Executable> as Identifiable>::Id,
            }
        },
        trigger::tokens: [
            CanExecuteUserTrigger,
            CanUnregisterUserTrigger,
            CanMintUserTrigger,
        ]
    );

    impl_froms!(
        tokens::CanExecuteUserTrigger,
        tokens::CanUnregisterUserTrigger,
        tokens::CanMintUserTrigger,
    );

    #[allow(missing_docs)]
    pub fn validate_unregister_trigger<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Unregister<Trigger<FilterBox, Executable>>,
    ) -> Verdict {
        let trigger_id = isi.object_id;

        if is_trigger_owner(trigger_id.clone(), authority) {
            pass!();
        }
        let can_unregister_user_trigger_token = tokens::CanUnregisterUserTrigger { trigger_id };
        if can_unregister_user_trigger_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't unregister trigger owned by another account")
    }

    #[allow(missing_docs)]
    pub fn validate_mint_trigger_repetitions<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Mint<Trigger<FilterBox, Executable>, u32>,
    ) -> Verdict {
        let trigger_id = isi.destination_id;

        if is_trigger_owner(trigger_id.clone(), authority) {
            pass!();
        }
        let can_mint_user_trigger_token = tokens::CanMintUserTrigger { trigger_id };
        if can_mint_user_trigger_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't mint execution count for trigger owned by another account");
    }

    #[allow(missing_docs)]
    pub fn validate_execute_trigger<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: ExecuteTrigger,
    ) -> Verdict {
        let trigger_id = isi.trigger_id;

        if is_trigger_owner(trigger_id.clone(), authority) {
            pass!();
        }
        let can_execute_trigger_token = tokens::CanExecuteUserTrigger { trigger_id };
        if can_execute_trigger_token.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't execute trigger owned by another account");
    }
}

pub mod permission_token {
    use super::*;

    macro_rules! impl_validate {
        ($self:ident, $authority:ident, $method:ident) => {
            let token = $self.object;

            macro_rules! validate_internal {
                ($token_ty:ty) => {
                    if let Ok(concrete_token) =
                        <$token_ty as ::core::convert::TryFrom<_>>::try_from(token.clone())
                    {
                        return <$token_ty as ::iroha_validator::permission::ValidateGrantRevoke>::$method(
                            &concrete_token,
                            $authority,
                        );
                    }
                };
            }

            map_all_crate_tokens!(validate_internal);
            deny!("Unknown permission token")
        };
    }

    #[allow(missing_docs, clippy::needless_pass_by_value)]
    pub fn validate_register_permission_token<V: Validate + ?Sized>(
        _validator: &mut V,
        _authority: &AccountId,
        _isi: Register<PermissionTokenDefinition>,
    ) -> Verdict {
        deny!("Registering new permission token is allowed only in genesis");
    }

    #[allow(missing_docs)]
    pub fn validate_grant_account_permission<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Grant<Account, PermissionToken>,
    ) -> Verdict {
        impl_validate!(isi, authority, validate_grant);
    }

    #[allow(missing_docs)]
    pub fn validate_revoke_account_permission<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        isi: Revoke<Account, PermissionToken>,
    ) -> Verdict {
        impl_validate!(isi, authority, validate_revoke);
    }
}

pub mod validator {
    //! Validation and tokens related to validator operations.

    use super::*;

    tokens!(
        pattern = {
            #[derive(Token, ValidateGrantRevoke)]
            #[validate(permission::OnlyGenesis)]
            #[derive(Clone, Copy)]
            pub struct _ {}
        },
        validator::tokens: [
            CanUpgradeValidator,
        ]
    );

    #[allow(missing_docs, clippy::needless_pass_by_value)]
    pub fn validate_upgrade_validator<V: Validate + ?Sized>(
        _validator: &mut V,
        authority: &AccountId,
        _isi: Upgrade<iroha_validator::data_model::validator::Validator>,
    ) -> Verdict {
        const CAN_UPGRADE_VALIDATOR_TOKEN: tokens::CanUpgradeValidator =
            tokens::CanUpgradeValidator {};
        if CAN_UPGRADE_VALIDATOR_TOKEN.is_owned_by(authority) {
            pass!();
        }

        deny!("Can't upgrade validator");
    }
}
