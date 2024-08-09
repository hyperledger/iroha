//! Module with permission related functionality.

use alloc::borrow::ToOwned as _;

use iroha_executor_data_model::permission::Permission;
use iroha_smart_contract::{
    data_model::{executor::Result, permission::Permission as PermissionObject, prelude::*},
    query,
};
use iroha_smart_contract_utils::debug::DebugExpectExt as _;

/// Declare token types of current module. Use it with a full path to the token.
/// Used to iterate over tokens to validate `Grant` and `Revoke` instructions.
///
///
/// Example:
///
/// ```ignore
/// mod tokens {
///     use std::borrow::ToOwned;
///
///     use iroha_schema::IntoSchema;
///     use iroha_executor_derive::Token;
///     use serde::{Deserialize, Serialize};
///
///     #[derive(Clone, PartialEq, Deserialize, Serialize, IntoSchema, Token)]
///     #[validate(iroha_executor::permission::OnlyGenesis)]
///     pub struct MyToken;
/// }
/// ```
macro_rules! declare_permissions {
    ($($($token_path:ident ::)+ { $token_ty:ident }),+ $(,)?) => {
        /// Enum with every default token
        #[allow(clippy::enum_variant_names)]
        #[derive(Clone)]
        pub(crate) enum AnyPermission { $(
            $token_ty($($token_path::)+$token_ty), )*
        }

        impl TryFrom<&PermissionObject> for AnyPermission {
            type Error = iroha_executor_data_model::TryFromDataModelObjectError;

            fn try_from(token: &PermissionObject) -> Result<Self, Self::Error> {
                match token.name().as_ref() { $(
                    stringify!($token_ty) => {
                        let token = <$($token_path::)+$token_ty>::try_from(token)?;
                        Ok(Self::$token_ty(token))
                    } )+
                    _ => Err(Self::Error::UnknownIdent(token.name().to_owned()))
                }
            }
        }

        impl From<AnyPermission> for PermissionObject {
            fn from(token: AnyPermission) -> Self {
                match token { $(
                    AnyPermission::$token_ty(token) => token.into(), )*
                }
            }
        }

        impl ValidateGrantRevoke for AnyPermission {
            fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
                match self { $(
                    AnyPermission::$token_ty(token) => token.validate_grant(authority, block_height), )*
                }
            }

            fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
                match self { $(
                    AnyPermission::$token_ty(token) => token.validate_revoke(authority, block_height), )*
                }
            }
        }

        macro_rules! map_default_permissions {
            ($callback:ident) => { $(
                $callback!($($token_path::)+$token_ty); )+
            };
        }

        pub(crate) use map_default_permissions;
    };
}

declare_permissions! {
    iroha_executor_data_model::permission::peer::{CanUnregisterAnyPeer},

    iroha_executor_data_model::permission::domain::{CanUnregisterDomain},
    iroha_executor_data_model::permission::domain::{CanSetKeyValueInDomain},
    iroha_executor_data_model::permission::domain::{CanRemoveKeyValueInDomain},
    iroha_executor_data_model::permission::domain::{CanRegisterAccountInDomain},
    iroha_executor_data_model::permission::domain::{CanRegisterAssetDefinitionInDomain},

    iroha_executor_data_model::permission::account::{CanUnregisterAccount},
    iroha_executor_data_model::permission::account::{CanSetKeyValueInAccount},
    iroha_executor_data_model::permission::account::{CanRemoveKeyValueInAccount},

    iroha_executor_data_model::permission::asset_definition::{CanUnregisterAssetDefinition},
    iroha_executor_data_model::permission::asset_definition::{CanSetKeyValueInAssetDefinition},
    iroha_executor_data_model::permission::asset_definition::{CanRemoveKeyValueInAssetDefinition},

    iroha_executor_data_model::permission::asset::{CanRegisterAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanUnregisterAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanUnregisterUserAsset},
    iroha_executor_data_model::permission::asset::{CanBurnAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanMintAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanMintUserAsset},
    iroha_executor_data_model::permission::asset::{CanBurnUserAsset},
    iroha_executor_data_model::permission::asset::{CanTransferAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanTransferUserAsset},
    iroha_executor_data_model::permission::asset::{CanSetKeyValueInUserAsset},
    iroha_executor_data_model::permission::asset::{CanRemoveKeyValueInUserAsset},

    iroha_executor_data_model::permission::parameter::{CanSetParameters},
    iroha_executor_data_model::permission::role::{CanUnregisterAnyRole},

    iroha_executor_data_model::permission::trigger::{CanRegisterUserTrigger},
    iroha_executor_data_model::permission::trigger::{CanExecuteUserTrigger},
    iroha_executor_data_model::permission::trigger::{CanUnregisterUserTrigger},
    iroha_executor_data_model::permission::trigger::{CanMintUserTrigger},
    iroha_executor_data_model::permission::trigger::{CanBurnUserTrigger},
    iroha_executor_data_model::permission::trigger::{CanSetKeyValueInTrigger},
    iroha_executor_data_model::permission::trigger::{CanRemoveKeyValueInTrigger},

    iroha_executor_data_model::permission::executor::{CanUpgradeExecutor},
}

/// Trait that enables using permissions on the blockchain
pub trait ExecutorPermision: Permission + PartialEq {
    /// Check if the account owns this token
    fn is_owned_by(&self, account_id: &AccountId) -> bool
    where
        for<'a> Self: TryFrom<&'a crate::data_model::permission::Permission>,
    {
        query(FindPermissionsByAccountId::new(account_id.clone()))
            .execute()
            .expect("INTERNAL BUG: `FindPermissionsByAccountId` must never fail")
            .map(|res| res.dbg_expect("Failed to get permission from cursor"))
            .filter_map(|permission| Self::try_from(&permission).ok())
            .any(|permission| *self == permission)
    }
}

impl<T: Permission + PartialEq> ExecutorPermision for T {}

/// Trait that should be implemented for all permission tokens.
/// Provides a function to check validity of [`Grant`] and [`Revoke`]
/// instructions containing implementing token.
pub(super) trait ValidateGrantRevoke {
    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result;

    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result;
}

/// Predicate-like trait used for pass conditions to identify if [`Grant`] or [`Revoke`] should be allowed.
pub(crate) trait PassCondition {
    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate(&self, authority: &AccountId, block_height: u64) -> Result;
}

mod executor {
    use iroha_executor_data_model::permission::executor::CanUpgradeExecutor;

    use super::*;

    impl ValidateGrantRevoke for CanUpgradeExecutor {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            OnlyGenesis::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            OnlyGenesis::from(self).validate(authority, block_height)
        }
    }
}

mod peer {
    use iroha_executor_data_model::permission::peer::CanUnregisterAnyPeer;

    use super::*;

    impl ValidateGrantRevoke for CanUnregisterAnyPeer {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            OnlyGenesis::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            OnlyGenesis::from(self).validate(authority, block_height)
        }
    }
}

mod role {
    use iroha_executor_data_model::permission::role::CanUnregisterAnyRole;

    use super::*;

    impl ValidateGrantRevoke for CanUnregisterAnyRole {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            OnlyGenesis::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            OnlyGenesis::from(self).validate(authority, block_height)
        }
    }
}

mod parameter {
    //! Module with pass conditions for parameter related tokens
    use iroha_executor_data_model::permission::parameter::CanSetParameters;

    use super::*;

    impl ValidateGrantRevoke for CanSetParameters {
        fn validate_grant(&self, authority: &AccountId, _block_height: u64) -> Result {
            if CanSetParameters.is_owned_by(authority) {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Current authority doesn't have the permission to set parameters, therefore it can't grant it to another account"
                    .to_owned()
            ))
        }

        fn validate_revoke(&self, authority: &AccountId, _block_height: u64) -> Result {
            if CanSetParameters.is_owned_by(authority) {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Current authority doesn't have the permission to set parameters, therefore it can't revoke it from another account"
                    .to_owned()
            ))
        }
    }
}

pub mod asset {
    //! Module with pass conditions for asset related tokens

    use iroha_executor_data_model::permission::asset::{
        CanBurnAssetWithDefinition, CanBurnUserAsset, CanMintAssetWithDefinition, CanMintUserAsset,
        CanRegisterAssetWithDefinition, CanRemoveKeyValueInUserAsset, CanSetKeyValueInUserAsset,
        CanTransferAssetWithDefinition, CanTransferUserAsset, CanUnregisterAssetWithDefinition,
        CanUnregisterUserAsset,
    };

    use super::*;

    /// Check if `authority` is the owner of asset.
    ///
    /// `authority` is owner of asset if:
    /// - `asset_id.account_id` is `account_id`
    /// - `asset_id.account_id.domain_id` domain is owned by `authority`
    ///
    /// # Errors
    ///
    /// Fails if `is_account_owner` fails
    pub fn is_asset_owner(asset_id: &AssetId, authority: &AccountId) -> Result<bool> {
        crate::permission::account::is_account_owner(asset_id.account(), authority)
    }

    /// Pass condition that checks if `authority` is the owner of asset.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset> {
        /// Asset id to check against
        pub asset: &'asset AssetId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_asset_owner(self.asset, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access asset owned by another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanRegisterAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanUnregisterAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanBurnAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanMintAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanTransferAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanUnregisterUserAsset {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanMintUserAsset {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanBurnUserAsset {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanTransferUserAsset {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanSetKeyValueInUserAsset {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }
    impl ValidateGrantRevoke for CanRemoveKeyValueInUserAsset {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    macro_rules! impl_froms {
        ($($name:ty),+ $(,)?) => {$(
            impl<'t> From<&'t $name> for Owner<'t> {
                fn from(value: &'t $name) -> Self {
                    Self { asset: &value.asset}
                }
            })+
        };
    }

    impl_froms!(
        CanUnregisterUserAsset,
        CanMintUserAsset,
        CanBurnUserAsset,
        CanTransferUserAsset,
        CanSetKeyValueInUserAsset,
        CanRemoveKeyValueInUserAsset,
    );
}

pub mod asset_definition {
    //! Module with pass conditions for asset definition related tokens

    use iroha_executor_data_model::permission::asset_definition::{
        CanRemoveKeyValueInAssetDefinition, CanSetKeyValueInAssetDefinition,
        CanUnregisterAssetDefinition,
    };
    use iroha_smart_contract::data_model::{
        isi::error::InstructionExecutionError,
        query::{
            builder::{QueryBuilderExt, SingleQueryError},
            error::FindError,
        },
    };

    use super::*;

    /// Check if `authority` is the owner of asset definition

    /// `authority` is owner of asset definition if:
    /// - `asset_definition.owned_by` is `authority`
    /// - `asset_definition.domain_id` domain is owned by `authority`
    ///
    /// # Errors
    /// - if `FindAssetDefinitionById` fails
    /// - if `is_domain_owner` fails
    pub fn is_asset_definition_owner(
        asset_definition_id: &AssetDefinitionId,
        authority: &AccountId,
    ) -> Result<bool> {
        let asset_definition = query(FindAssetsDefinitions)
            .filter_with(|asset_definition| asset_definition.id.eq(asset_definition_id.clone()))
            .execute_single()
            .map_err(|e| match e {
                SingleQueryError::QueryError(e) => e,
                SingleQueryError::ExpectedOneGotNone => {
                    // assuming this can only happen due to such a domain not existing
                    ValidationFail::InstructionFailed(InstructionExecutionError::Find(
                        FindError::AssetDefinition(asset_definition_id.clone()),
                    ))
                }
                _ => unreachable!(),
            })?;
        if asset_definition.owned_by() == authority {
            Ok(true)
        } else {
            crate::permission::domain::is_domain_owner(asset_definition_id.domain(), authority)
        }
    }

    /// Pass condition that checks if `authority` is the owner of asset definition.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset_definition> {
        /// Asset definition id to check against
        pub asset_definition: &'asset_definition AssetDefinitionId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_asset_definition_owner(self.asset_definition, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access asset definition owned by another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanUnregisterAssetDefinition {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanSetKeyValueInAssetDefinition {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanRemoveKeyValueInAssetDefinition {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    macro_rules! impl_froms {
        ($($name:ty),+ $(,)?) => {$(
            impl<'t> From<&'t $name> for Owner<'t> {
                fn from(value: &'t $name) -> Self {
                    Self { asset_definition: &value.asset_definition }
                }
            })+
        };
    }

    impl_froms!(
        CanUnregisterAssetDefinition,
        CanSetKeyValueInAssetDefinition,
        CanRemoveKeyValueInAssetDefinition,
        iroha_executor_data_model::permission::asset::CanRegisterAssetWithDefinition,
        iroha_executor_data_model::permission::asset::CanUnregisterAssetWithDefinition,
        iroha_executor_data_model::permission::asset::CanBurnAssetWithDefinition,
        iroha_executor_data_model::permission::asset::CanMintAssetWithDefinition,
        iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition,
    );
}

pub mod account {
    //! Module with pass conditions for asset related tokens

    use iroha_executor_data_model::permission::account::{
        CanRemoveKeyValueInAccount, CanSetKeyValueInAccount, CanUnregisterAccount,
    };

    use super::*;

    /// Check if `authority` is the owner of account.
    ///
    /// `authority` is owner of account if:
    /// - `account_id` is `authority`
    /// - `account_id.domain_id` is owned by `authority`
    ///
    /// # Errors
    ///
    /// Fails if `is_domain_owner` fails
    pub fn is_account_owner(account_id: &AccountId, authority: &AccountId) -> Result<bool> {
        if account_id == authority {
            Ok(true)
        } else {
            crate::permission::domain::is_domain_owner(account_id.domain(), authority)
        }
    }

    /// Pass condition that checks if `authority` is the owner of account.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset> {
        /// Account id to check against
        pub account: &'asset AccountId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_account_owner(self.account, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanUnregisterAccount {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanSetKeyValueInAccount {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanRemoveKeyValueInAccount {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    macro_rules! impl_froms {
        ($($name:ty),+ $(,)?) => {$(
            impl<'t> From<&'t $name> for Owner<'t> {
                fn from(value: &'t $name) -> Self {
                    Self { account: &value.account }
                }
            })+
        };
    }

    impl_froms!(
        CanUnregisterAccount,
        CanSetKeyValueInAccount,
        CanRemoveKeyValueInAccount,
        iroha_executor_data_model::permission::trigger::CanRegisterUserTrigger,
        iroha_executor_data_model::permission::trigger::CanUnregisterUserTrigger,
    );
}

pub mod trigger {
    //! Module with pass conditions for trigger related tokens
    use iroha_executor_data_model::permission::trigger::{
        CanBurnUserTrigger, CanExecuteUserTrigger, CanMintUserTrigger, CanRegisterUserTrigger,
        CanRemoveKeyValueInTrigger, CanSetKeyValueInTrigger, CanUnregisterUserTrigger,
    };
    use iroha_smart_contract::query_single;

    use super::*;
    use crate::permission::domain::is_domain_owner;

    /// Check if `authority` is the owner of trigger.
    ///
    /// `authority` is owner of trigger if:
    /// - `trigger.action.authority` is `authority`
    /// - `trigger.action.authority.domain_id` is owned by `authority`
    ///
    /// # Errors
    /// - `FindTrigger` fails
    /// - `is_domain_owner` fails
    pub fn is_trigger_owner(trigger_id: &TriggerId, authority: &AccountId) -> Result<bool> {
        let trigger = find_trigger(trigger_id)?;

        Ok(trigger.action().authority() == authority
            || is_domain_owner(trigger.action().authority().domain(), authority)?)
    }
    /// Returns the trigger.
    pub(crate) fn find_trigger(trigger_id: &TriggerId) -> Result<Trigger> {
        query_single(FindTriggerById::new(trigger_id.clone()))
    }

    /// Pass condition that checks if `authority` is the owner of trigger.
    #[derive(Debug, Clone)]
    pub struct Owner<'trigger> {
        /// Trigger id to check against
        pub trigger: &'trigger TriggerId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_trigger_owner(self.trigger, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't give permission to access trigger owned by another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanRegisterUserTrigger {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            super::account::Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            super::account::Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanExecuteUserTrigger {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanUnregisterUserTrigger {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            super::account::Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            super::account::Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanMintUserTrigger {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanBurnUserTrigger {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }
    impl ValidateGrantRevoke for CanSetKeyValueInTrigger {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanRemoveKeyValueInTrigger {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    macro_rules! impl_froms {
        ($($name:ty),+ $(,)?) => {$(
            impl<'t> From<&'t $name> for Owner<'t> {
                fn from(value: &'t $name) -> Self {
                    Self { trigger: &value.trigger }
                }
            })+
        };
    }

    impl_froms!(
        CanMintUserTrigger,
        CanBurnUserTrigger,
        CanExecuteUserTrigger,
        CanSetKeyValueInTrigger,
        CanRemoveKeyValueInTrigger,
    );
}

pub mod domain {
    //! Module with pass conditions for domain related tokens
    use iroha_executor_data_model::permission::domain::{
        CanRegisterAccountInDomain, CanRegisterAssetDefinitionInDomain, CanRemoveKeyValueInDomain,
        CanSetKeyValueInDomain, CanUnregisterDomain,
    };
    use iroha_smart_contract::data_model::{
        isi::error::InstructionExecutionError,
        query::{
            builder::{QueryBuilderExt, SingleQueryError},
            error::FindError,
        },
    };

    use super::*;

    /// Check if `authority` is owner of domain
    ///
    /// # Errors
    /// Fails if query fails
    pub fn is_domain_owner(domain_id: &DomainId, authority: &AccountId) -> Result<bool> {
        query(FindDomains)
            .filter_with(|domain| domain.id.eq(domain_id.clone()))
            .execute_single()
            .map(|domain| domain.owned_by() == authority)
            .map_err(|e| match e {
                SingleQueryError::QueryError(e) => e,
                SingleQueryError::ExpectedOneGotNone => {
                    // assuming this can only happen due to such a domain not existing
                    ValidationFail::InstructionFailed(InstructionExecutionError::Find(
                        FindError::Domain(domain_id.clone()),
                    ))
                }
                _ => unreachable!(),
            })
    }

    /// Pass condition that checks if `authority` is the owner of domain.
    #[derive(Debug, Clone)]
    pub struct Owner<'domain> {
        /// Domain id to check against
        pub domain: &'domain DomainId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_domain_owner(self.domain, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access domain owned by another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanUnregisterDomain {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanSetKeyValueInDomain {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanRemoveKeyValueInDomain {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanRegisterAccountInDomain {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    impl ValidateGrantRevoke for CanRegisterAssetDefinitionInDomain {
        fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
        fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result {
            Owner::from(self).validate(authority, block_height)
        }
    }

    macro_rules! impl_froms {
        ($($name:ty),+ $(,)?) => {$(
            impl<'t> From<&'t $name> for Owner<'t> {
                fn from(value: &'t $name) -> Self {
                    Self { domain: &value.domain }
                }
            })+
        };
    }

    impl_froms!(
        CanUnregisterDomain,
        CanSetKeyValueInDomain,
        CanRemoveKeyValueInDomain,
        CanRegisterAccountInDomain,
        CanRegisterAssetDefinitionInDomain,
    );
}

/// Pass condition that allows operation only in genesis.
///
/// In other words it always operation only if block height is 0.
#[derive(Debug, Default, Copy, Clone)]
pub(crate) struct OnlyGenesis;

impl PassCondition for OnlyGenesis {
    fn validate(&self, _: &AccountId, block_height: u64) -> Result {
        if block_height == 0 {
            Ok(())
        } else {
            Err(ValidationFail::NotPermitted(
                "This operation is only allowed inside the genesis block".to_owned(),
            ))
        }
    }
}

impl<T: Permission> From<&T> for OnlyGenesis {
    fn from(_: &T) -> Self {
        Self
    }
}

/// Iterator over all accounts and theirs permission tokens
pub(crate) fn accounts_permissions() -> impl Iterator<Item = (AccountId, PermissionObject)> {
    query(FindAccounts)
        .execute()
        .dbg_expect("INTERNAL BUG: `FindAllAccounts` must never fail")
        .map(|account| account.dbg_expect("Failed to get account from cursor"))
        .flat_map(|account| {
            query(FindPermissionsByAccountId::new(account.id().clone()))
                .execute()
                .dbg_expect("INTERNAL BUG: `FindPermissionsByAccountId` must never fail")
                .map(|token| token.dbg_expect("Failed to get permission from cursor"))
                .map(move |token| (account.id().clone(), token))
        })
}

/// Iterator over all roles and theirs permission tokens
pub(crate) fn roles_permissions() -> impl Iterator<Item = (RoleId, PermissionObject)> {
    query(FindRoles)
        .execute()
        .dbg_expect("INTERNAL BUG: `FindAllRoles` must never fail")
        .map(|role| role.dbg_expect("Failed to get role from cursor"))
        .flat_map(|role| {
            role.permissions()
                .cloned()
                .collect::<alloc::vec::Vec<_>>()
                .into_iter()
                .map(move |token| (role.id().clone(), token))
        })
}
