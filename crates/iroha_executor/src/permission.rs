//! Module with permission related functionality.

use alloc::{borrow::ToOwned as _, vec::Vec};

use iroha_executor_data_model::permission::Permission;

use crate::{
    prelude::Context,
    smart_contract::{
        data_model::{executor::Result, permission::Permission as PermissionObject, prelude::*},
        debug::DebugExpectExt as _,
        Iroha,
    },
};

/// Declare permission types of current module. Use it with a full path to the permission.
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
///     use iroha_executor_derive::Permission;
///     use serde::{Deserialize, Serialize};
///
///     #[derive(Clone, PartialEq, Deserialize, Serialize, IntoSchema, Permission)]
///     #[validate(iroha_executor::permission::OnlyGenesis)]
///     pub struct MyToken;
/// }
/// ```
macro_rules! declare_permissions {
    ($($($token_path:ident ::)+ { $token_ty:ident }),+ $(,)?) => {
        /// Enum with every default permission
        #[allow(clippy::enum_variant_names)]
        #[derive(Clone)]
        pub(crate) enum AnyPermission { $(
            $token_ty($($token_path::)+$token_ty), )*
        }

        impl TryFrom<&PermissionObject> for AnyPermission {
            type Error = iroha_executor_data_model::TryFromDataModelObjectError;

            fn try_from(permission: &PermissionObject) -> Result<Self, Self::Error> {
                match permission.name().as_ref() { $(
                    stringify!($token_ty) => {
                        let permission = <$($token_path::)+$token_ty>::try_from(permission)?;
                        Ok(Self::$token_ty(permission))
                    } )+
                    _ => Err(Self::Error::UnknownIdent(permission.name().to_owned()))
                }
            }
        }

        impl From<AnyPermission> for PermissionObject {
            fn from(permission: AnyPermission) -> Self {
                match permission { $(
                    AnyPermission::$token_ty(permission) => permission.into(), )*
                }
            }
        }

        impl ValidateGrantRevoke for AnyPermission {
            fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
                match self { $(
                    AnyPermission::$token_ty(permission) => permission.validate_grant(authority, context, host), )*
                }
            }

            fn validate_revoke(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
                match self { $(
                    AnyPermission::$token_ty(permission) => permission.validate_revoke(authority, context, host), )*
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
    iroha_executor_data_model::permission::peer::{CanManagePeers},

    iroha_executor_data_model::permission::domain::{CanRegisterDomain},
    iroha_executor_data_model::permission::domain::{CanUnregisterDomain},
    iroha_executor_data_model::permission::domain::{CanModifyDomainMetadata},

    iroha_executor_data_model::permission::account::{CanRegisterAccount},
    iroha_executor_data_model::permission::account::{CanUnregisterAccount},
    iroha_executor_data_model::permission::account::{CanModifyAccountMetadata},

    iroha_executor_data_model::permission::asset_definition::{CanRegisterAssetDefinition},
    iroha_executor_data_model::permission::asset_definition::{CanUnregisterAssetDefinition},
    iroha_executor_data_model::permission::asset_definition::{CanModifyAssetDefinitionMetadata},

    iroha_executor_data_model::permission::asset::{CanRegisterAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanUnregisterAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanMintAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanBurnAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanTransferAssetWithDefinition},
    iroha_executor_data_model::permission::asset::{CanRegisterAsset},
    iroha_executor_data_model::permission::asset::{CanUnregisterAsset},
    iroha_executor_data_model::permission::asset::{CanMintAsset},
    iroha_executor_data_model::permission::asset::{CanBurnAsset},
    iroha_executor_data_model::permission::asset::{CanTransferAsset},
    iroha_executor_data_model::permission::asset::{CanModifyAssetMetadata},

    iroha_executor_data_model::permission::parameter::{CanSetParameters},
    iroha_executor_data_model::permission::role::{CanManageRoles},

    iroha_executor_data_model::permission::trigger::{CanRegisterAnyTrigger},
    iroha_executor_data_model::permission::trigger::{CanUnregisterAnyTrigger},
    iroha_executor_data_model::permission::trigger::{CanRegisterTrigger},
    iroha_executor_data_model::permission::trigger::{CanUnregisterTrigger},
    iroha_executor_data_model::permission::trigger::{CanModifyTrigger},
    iroha_executor_data_model::permission::trigger::{CanExecuteTrigger},
    iroha_executor_data_model::permission::trigger::{CanModifyTriggerMetadata},

    iroha_executor_data_model::permission::executor::{CanUpgradeExecutor},
}

/// Trait that enables using permissions on the blockchain
pub trait ExecutorPermission: Permission + PartialEq {
    /// Check if the account owns this permission
    fn is_owned_by(&self, authority: &AccountId, host: &Iroha) -> bool
    where
        for<'a> Self: TryFrom<&'a crate::data_model::permission::Permission>,
    {
        if host
            .query(FindPermissionsByAccountId::new(authority.clone()))
            .execute()
            .expect("INTERNAL BUG: `FindPermissionsByAccountId` must never fail")
            .map(|res| res.dbg_expect("Failed to get permission from cursor"))
            .filter_map(|permission| Self::try_from(&permission).ok())
            .any(|permission| *self == permission)
        {
            return true;
        }

        // build a big OR predicate over all roles we are interested in
        let role_predicate = host
            .query(FindRolesByAccountId::new(authority.clone()))
            .execute()
            .expect("INTERNAL BUG: `FindRolesByAccountId` must never fail")
            .map(|role_id| role_id.dbg_expect("Failed to get role from cursor"))
            .fold(CompoundPredicate::Or(Vec::new()), |predicate, role_id| {
                predicate.or(RolePredicateBox::build(|role| role.id.eq(role_id)))
            });

        // check if any of the roles have the permission we need
        host.query(FindRoles)
            .filter(role_predicate)
            .execute()
            .expect("INTERNAL BUG: `FindRoles` must never fail")
            .map(|role| role.dbg_expect("Failed to get role from cursor"))
            .any(|role| {
                role.permissions()
                    .filter_map(|permission| Self::try_from(permission).ok())
                    .any(|permission| *self == permission)
            })
    }
}

impl<T: Permission + PartialEq> ExecutorPermission for T {}

/// Trait that should be implemented for all permission tokens.
/// Provides a function to check validity of [`Grant`] and [`Revoke`]
/// instructions containing implementing permission.
pub(super) trait ValidateGrantRevoke {
    fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result;

    fn validate_revoke(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result;
}

/// Predicate-like trait used for pass conditions to identify if [`Grant`] or [`Revoke`] should be allowed.
pub(crate) trait PassCondition {
    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate(&self, authority: &AccountId, host: &Iroha, context: &Context) -> Result;
}

mod executor {
    use iroha_executor_data_model::permission::executor::CanUpgradeExecutor;

    use super::*;

    impl ValidateGrantRevoke for CanUpgradeExecutor {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
    }
}

mod peer {
    use iroha_executor_data_model::permission::peer::CanManagePeers;

    use super::*;

    impl ValidateGrantRevoke for CanManagePeers {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
    }
}

mod role {
    use iroha_executor_data_model::permission::role::CanManageRoles;

    use super::*;

    impl ValidateGrantRevoke for CanManageRoles {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
    }
}

mod parameter {
    //! Module with pass conditions for parameter related tokens
    use iroha_executor_data_model::permission::parameter::CanSetParameters;

    use super::*;

    impl ValidateGrantRevoke for CanSetParameters {
        fn validate_grant(
            &self,
            authority: &AccountId,
            _context: &Context,
            host: &Iroha,
        ) -> Result {
            if CanSetParameters.is_owned_by(authority, host) {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Current authority doesn't have the permission to set parameters, therefore it can't grant it to another account"
                    .to_owned()
            ))
        }

        fn validate_revoke(
            &self,
            authority: &AccountId,
            _context: &Context,
            host: &Iroha,
        ) -> Result {
            if CanSetParameters.is_owned_by(authority, host) {
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
        CanBurnAsset, CanBurnAssetWithDefinition, CanMintAsset, CanMintAssetWithDefinition,
        CanModifyAssetMetadata, CanRegisterAsset, CanRegisterAssetWithDefinition, CanTransferAsset,
        CanTransferAssetWithDefinition, CanUnregisterAsset, CanUnregisterAssetWithDefinition,
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
    pub fn is_asset_owner(asset_id: &AssetId, authority: &AccountId, host: &Iroha) -> Result<bool> {
        crate::permission::account::is_account_owner(asset_id.account(), authority, host)
    }

    /// Pass condition that checks if `authority` is the owner of asset.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset> {
        /// Asset id to check against
        pub asset: &'asset AssetId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, host: &Iroha, _context: &Context) -> Result {
            if is_asset_owner(self.asset, authority, host)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access asset owned by another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanRegisterAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanUnregisterAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanMintAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanBurnAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanTransferAssetWithDefinition {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            super::asset_definition::Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanRegisterAsset {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            super::account::Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            super::account::Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanUnregisterAsset {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanMintAsset {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanBurnAsset {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanTransferAsset {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanModifyAssetMetadata {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl<'t> From<&'t CanRegisterAsset> for super::account::Owner<'t> {
        fn from(value: &'t CanRegisterAsset) -> Self {
            Self {
                account: &value.owner,
            }
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
        CanUnregisterAsset,
        CanMintAsset,
        CanBurnAsset,
        CanTransferAsset,
        CanModifyAssetMetadata,
    );
}

pub mod asset_definition {
    //! Module with pass conditions for asset definition related tokens

    use iroha_executor_data_model::permission::asset_definition::{
        CanModifyAssetDefinitionMetadata, CanRegisterAssetDefinition, CanUnregisterAssetDefinition,
    };

    use super::*;
    use crate::smart_contract::{
        data_model::{
            isi::error::InstructionExecutionError,
            query::{builder::SingleQueryError, error::FindError},
        },
        Iroha,
    };

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
        host: &Iroha,
    ) -> Result<bool> {
        let asset_definition = host
            .query(FindAssetsDefinitions)
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
            crate::permission::domain::is_domain_owner(
                asset_definition_id.domain(),
                authority,
                host,
            )
        }
    }

    /// Pass condition that checks if `authority` is the owner of asset definition.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset_definition> {
        /// Asset definition id to check against
        pub asset_definition: &'asset_definition AssetDefinitionId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, host: &Iroha, _context: &Context) -> Result {
            if is_asset_definition_owner(self.asset_definition, authority, host)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access asset definition owned by another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanRegisterAssetDefinition {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            super::domain::Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            super::domain::Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanUnregisterAssetDefinition {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanModifyAssetDefinitionMetadata {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
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
        CanModifyAssetDefinitionMetadata,
        iroha_executor_data_model::permission::asset::CanRegisterAssetWithDefinition,
        iroha_executor_data_model::permission::asset::CanUnregisterAssetWithDefinition,
        iroha_executor_data_model::permission::asset::CanMintAssetWithDefinition,
        iroha_executor_data_model::permission::asset::CanBurnAssetWithDefinition,
        iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition,
    );
}

pub mod account {
    //! Module with pass conditions for asset related tokens

    use iroha_executor_data_model::permission::account::{
        CanModifyAccountMetadata, CanRegisterAccount, CanUnregisterAccount,
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
    pub fn is_account_owner(
        account_id: &AccountId,
        authority: &AccountId,
        host: &Iroha,
    ) -> Result<bool> {
        if account_id == authority {
            Ok(true)
        } else {
            crate::permission::domain::is_domain_owner(account_id.domain(), authority, host)
        }
    }

    /// Pass condition that checks if `authority` is the owner of account.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset> {
        /// Account id to check against
        pub account: &'asset AccountId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, host: &Iroha, _context: &Context) -> Result {
            if is_account_owner(self.account, authority, host)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanRegisterAccount {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            super::domain::Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            super::domain::Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanUnregisterAccount {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanModifyAccountMetadata {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
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

    impl_froms!(CanUnregisterAccount, CanModifyAccountMetadata,);
}

pub mod trigger {
    //! Module with pass conditions for trigger related tokens
    use iroha_executor_data_model::permission::trigger::{
        CanExecuteTrigger, CanModifyTrigger, CanModifyTriggerMetadata, CanRegisterAnyTrigger,
        CanRegisterTrigger, CanUnregisterAnyTrigger, CanUnregisterTrigger,
    };

    use super::*;
    use crate::{
        data_model::{
            isi::error::InstructionExecutionError,
            query::{builder::SingleQueryError, error::FindError, trigger::FindTriggers},
        },
        permission::domain::is_domain_owner,
    };

    /// Check if `authority` is the owner of trigger.
    ///
    /// `authority` is owner of trigger if:
    /// - `trigger.action.authority` is `authority`
    /// - `trigger.action.authority.domain_id` is owned by `authority`
    ///
    /// # Errors
    /// - `FindTrigger` fails
    /// - `is_domain_owner` fails
    pub fn is_trigger_owner(
        trigger_id: &TriggerId,
        authority: &AccountId,
        host: &Iroha,
    ) -> Result<bool> {
        let trigger = find_trigger(trigger_id, host)?;

        Ok(trigger.action().authority() == authority
            || is_domain_owner(trigger.action().authority().domain(), authority, host)?)
    }
    /// Returns the trigger.
    pub(crate) fn find_trigger(trigger_id: &TriggerId, host: &Iroha) -> Result<Trigger> {
        host.query(FindTriggers::new())
            .filter_with(|trigger| trigger.id.eq(trigger_id.clone()))
            .execute_single()
            .map_err(|e| match e {
                SingleQueryError::QueryError(e) => e,
                SingleQueryError::ExpectedOneGotNone => ValidationFail::InstructionFailed(
                    InstructionExecutionError::Find(FindError::Trigger(trigger_id.clone())),
                ),
                _ => unreachable!(),
            })
    }

    /// Pass condition that checks if `authority` is the owner of trigger.
    #[derive(Debug, Clone)]
    pub struct Owner<'trigger> {
        /// Trigger id to check against
        pub trigger: &'trigger TriggerId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, host: &Iroha, _context: &Context) -> Result {
            if is_trigger_owner(self.trigger, authority, host)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't give permission to access trigger owned by another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanRegisterAnyTrigger {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanUnregisterAnyTrigger {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanRegisterTrigger {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            super::account::Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            super::account::Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanExecuteTrigger {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanUnregisterTrigger {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanModifyTrigger {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanModifyTriggerMetadata {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl<'t> From<&'t CanRegisterTrigger> for super::account::Owner<'t> {
        fn from(value: &'t CanRegisterTrigger) -> Self {
            Self {
                account: &value.authority,
            }
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
        CanUnregisterTrigger,
        CanModifyTrigger,
        CanExecuteTrigger,
        CanModifyTriggerMetadata,
    );
}

pub mod domain {
    //! Module with pass conditions for domain related tokens
    use iroha_executor_data_model::permission::domain::{
        CanModifyDomainMetadata, CanRegisterDomain, CanUnregisterDomain,
    };
    use iroha_smart_contract::data_model::{
        isi::error::InstructionExecutionError,
        query::{builder::SingleQueryError, error::FindError},
    };

    use super::*;

    /// Check if `authority` is owner of domain
    ///
    /// # Errors
    /// Fails if query fails
    pub fn is_domain_owner(
        domain_id: &DomainId,
        authority: &AccountId,
        host: &Iroha,
    ) -> Result<bool> {
        host.query(FindDomains)
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
        fn validate(&self, authority: &AccountId, host: &Iroha, _context: &Context) -> Result {
            if is_domain_owner(self.domain, authority, host)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access domain owned by another account".to_owned(),
            ))
        }
    }

    impl ValidateGrantRevoke for CanRegisterDomain {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            OnlyGenesis::from(self).validate(authority, host, context)
        }
    }
    impl ValidateGrantRevoke for CanUnregisterDomain {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
    }

    impl ValidateGrantRevoke for CanModifyDomainMetadata {
        fn validate_grant(&self, authority: &AccountId, context: &Context, host: &Iroha) -> Result {
            Owner::from(self).validate(authority, host, context)
        }
        fn validate_revoke(
            &self,
            authority: &AccountId,
            context: &Context,
            host: &Iroha,
        ) -> Result {
            Owner::from(self).validate(authority, host, context)
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
        CanModifyDomainMetadata,
        iroha_executor_data_model::permission::account::CanRegisterAccount,
        iroha_executor_data_model::permission::asset_definition::CanRegisterAssetDefinition,
    );
}

/// Pass condition that allows operation only in genesis.
///
/// In other words it always operation only if block height is 0.
#[derive(Debug, Default, Copy, Clone)]
pub(crate) struct OnlyGenesis;

impl PassCondition for OnlyGenesis {
    fn validate(&self, _authority: &AccountId, _host: &Iroha, context: &Context) -> Result {
        if context.curr_block.is_genesis() {
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
pub(crate) fn accounts_permissions(
    host: &Iroha,
) -> impl Iterator<Item = (AccountId, PermissionObject)> + '_ {
    host.query(FindAccounts)
        .execute()
        .dbg_expect("INTERNAL BUG: `FindAllAccounts` must never fail")
        .map(|account| account.dbg_expect("Failed to get account from cursor"))
        .flat_map(|account| {
            host.query(FindPermissionsByAccountId::new(account.id().clone()))
                .execute()
                .dbg_expect("INTERNAL BUG: `FindPermissionsByAccountId` must never fail")
                .map(|permission| permission.dbg_expect("Failed to get permission from cursor"))
                .map(move |permission| (account.id().clone(), permission))
        })
}

/// Iterator over all roles and theirs permission tokens
pub(crate) fn roles_permissions(host: &Iroha) -> impl Iterator<Item = (RoleId, PermissionObject)> {
    host.query(FindRoles)
        .execute()
        .dbg_expect("INTERNAL BUG: `FindAllRoles` must never fail")
        .map(|role| role.dbg_expect("Failed to get role from cursor"))
        .flat_map(|role| {
            role.permissions()
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .map(move |permission| (role.id().clone(), permission))
        })
}
