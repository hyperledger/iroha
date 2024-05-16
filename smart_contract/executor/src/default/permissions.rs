//! Definition of Iroha default permission tokens
#![allow(missing_docs, clippy::missing_errors_doc)]

use alloc::{borrow::ToOwned, format, string::String, vec::Vec};

use iroha_executor_derive::ValidateGrantRevoke;
use iroha_smart_contract::data_model::{executor::Result, prelude::*};

use crate::permission::{self, Permission as _};

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
///     use iroha_executor_derive::{Token, ValidateGrantRevoke};
///     use serde::{Deserialize, Serialize};
///
///     #[derive(Clone, PartialEq, Deserialize, Serialize, IntoSchema, Token, ValidateGrantRevoke)]
///     #[validate(iroha_executor::permission::OnlyGenesis)]
///     pub struct MyToken;
/// }
/// ```
macro_rules! declare_permissions {
    ($($($token_path:ident ::)+ { $token_ty:ident }),+ $(,)?) => {
        macro_rules! map_default_permissions {
            ($callback:ident) => { $(
                $callback!($($token_path::)+$token_ty); )+
            };
        }

        /// Enum with every default token
        #[allow(clippy::enum_variant_names)]
        #[derive(Clone)]
        pub(crate) enum AnyPermission { $(
            $token_ty($($token_path::)+$token_ty), )*
        }

        impl TryFrom<&$crate::data_model::permission::Permission> for AnyPermission {
            type Error = $crate::TryFromDataModelObjectError;

            fn try_from(token: &$crate::data_model::permission::Permission) -> Result<Self, Self::Error> {
                match token.id().name().as_ref() { $(
                    stringify!($token_ty) => {
                        let token = <$($token_path::)+$token_ty>::try_from_object(token)?;
                        Ok(Self::$token_ty(token))
                    } )+
                    _ => Err(Self::Error::Id(token.id().name().clone()))
                }
            }
        }

        impl From<AnyPermission> for $crate::data_model::permission::Permission {
            fn from(token: AnyPermission) -> Self {
                match token { $(
                    AnyPermission::$token_ty(token) => token.to_object(), )*
                }
            }
        }

        impl $crate::permission::ValidateGrantRevoke for AnyPermission {
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

        pub(crate) use map_default_permissions;
    };
}

macro_rules! permission {
    ($($meta:meta)* $item:item) => {
        #[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[derive(Clone, iroha_executor_derive::Permission)]
        #[derive(iroha_schema::IntoSchema)]
        $($meta)*
        $item
    };
}

declare_permissions! {
    crate::default::permissions::peer::{CanUnregisterAnyPeer},

    crate::default::permissions::domain::{CanUnregisterDomain},
    crate::default::permissions::domain::{CanSetKeyValueInDomain},
    crate::default::permissions::domain::{CanRemoveKeyValueInDomain},
    crate::default::permissions::domain::{CanRegisterAccountInDomain},
    crate::default::permissions::domain::{CanRegisterAssetDefinitionInDomain},

    crate::default::permissions::account::{CanUnregisterAccount},
    crate::default::permissions::account::{CanMintUserPublicKeys},
    crate::default::permissions::account::{CanBurnUserPublicKeys},
    crate::default::permissions::account::{CanMintUserSignatureCheckConditions},
    crate::default::permissions::account::{CanSetKeyValueInAccount},
    crate::default::permissions::account::{CanRemoveKeyValueInAccount},

    crate::default::permissions::asset_definition::{CanUnregisterAssetDefinition},
    crate::default::permissions::asset_definition::{CanSetKeyValueInAssetDefinition},
    crate::default::permissions::asset_definition::{CanRemoveKeyValueInAssetDefinition},

    crate::default::permissions::asset::{CanRegisterAssetWithDefinition},
    crate::default::permissions::asset::{CanUnregisterAssetWithDefinition},
    crate::default::permissions::asset::{CanUnregisterUserAsset},
    crate::default::permissions::asset::{CanBurnAssetWithDefinition},
    crate::default::permissions::asset::{CanMintAssetWithDefinition},
    crate::default::permissions::asset::{CanMintUserAsset},
    crate::default::permissions::asset::{CanBurnUserAsset},
    crate::default::permissions::asset::{CanTransferAssetWithDefinition},
    crate::default::permissions::asset::{CanTransferUserAsset},
    crate::default::permissions::asset::{CanSetKeyValueInUserAsset},
    crate::default::permissions::asset::{CanRemoveKeyValueInUserAsset},

    crate::default::permissions::parameter::{CanGrantPermissionToCreateParameters},
    crate::default::permissions::parameter::{CanRevokePermissionToCreateParameters},
    crate::default::permissions::parameter::{CanCreateParameters},
    crate::default::permissions::parameter::{CanGrantPermissionToSetParameters},
    crate::default::permissions::parameter::{CanRevokePermissionToSetParameters},
    crate::default::permissions::parameter::{CanSetParameters},

    crate::default::permissions::role::{CanUnregisterAnyRole},

    crate::default::permissions::trigger::{CanRegisterUserTrigger},
    crate::default::permissions::trigger::{CanExecuteUserTrigger},
    crate::default::permissions::trigger::{CanUnregisterUserTrigger},
    crate::default::permissions::trigger::{CanMintUserTrigger},
    crate::default::permissions::trigger::{CanBurnUserTrigger},
    crate::default::permissions::trigger::{CanSetKeyValueInTrigger},
    crate::default::permissions::trigger::{CanRemoveKeyValueInTrigger},

    crate::default::permissions::executor::{CanUpgradeExecutor},
}

pub mod peer {
    use super::*;

    permission! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanUnregisterAnyPeer;
    }
}

pub mod domain {
    use super::*;

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::domain::Owner)]
        #[validate(permission::domain::Owner)]
        pub struct CanUnregisterDomain {
            pub domain_id: DomainId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::domain::Owner)]
        #[validate(permission::domain::Owner)]
        pub struct CanSetKeyValueInDomain {
            pub domain_id: DomainId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::domain::Owner)]
        #[validate(permission::domain::Owner)]
        pub struct CanRemoveKeyValueInDomain {
            pub domain_id: DomainId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::domain::Owner)]
        #[validate(permission::domain::Owner)]
        pub struct CanRegisterAccountInDomain {
            pub domain_id: DomainId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::domain::Owner)]
        #[validate(permission::domain::Owner)]
        pub struct CanRegisterAssetDefinitionInDomain {
            pub domain_id: DomainId,
        }
    }
}

pub mod account {
    use super::*;

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanUnregisterAccount {
            pub account_id: AccountId,
        }
    }
    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanMintUserPublicKeys {
            pub account_id: AccountId,
        }
    }
    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanBurnUserPublicKeys {
            pub account_id: AccountId,
        }
    }
    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanMintUserSignatureCheckConditions {
            pub account_id: AccountId,
        }
    }
    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanSetKeyValueInAccount {
            pub account_id: AccountId,
        }
    }
    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanRemoveKeyValueInAccount {
            pub account_id: AccountId,
        }
    }
}

pub mod asset_definition {
    use super::*;

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanUnregisterAssetDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanSetKeyValueInAssetDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanRemoveKeyValueInAssetDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }
}

pub mod asset {
    use super::*;

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanRegisterAssetWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanUnregisterAssetWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanUnregisterUserAsset {
            pub asset_id: AssetId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanBurnAssetWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanBurnUserAsset {
            pub asset_id: AssetId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanMintAssetWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanMintUserAsset {
            pub asset_id: AssetId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanTransferAssetWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanTransferUserAsset {
            pub asset_id: AssetId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanSetKeyValueInUserAsset {
            pub asset_id: AssetId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanRemoveKeyValueInUserAsset {
            pub asset_id: AssetId,
        }
    }
}

pub mod parameter {
    use permission::ValidateGrantRevoke;

    use super::*;

    permission! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanGrantPermissionToCreateParameters;
    }

    permission! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanRevokePermissionToCreateParameters;
    }

    permission! {
        #[derive(Copy)]
        pub struct CanCreateParameters;
    }

    permission! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanGrantPermissionToSetParameters;
    }

    permission! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanRevokePermissionToSetParameters;
    }

    permission! {
        #[derive(Copy)]
        pub struct CanSetParameters;
    }

    impl ValidateGrantRevoke for CanCreateParameters {
        fn validate_grant(&self, authority: &AccountId, _block_height: u64) -> Result {
            if CanGrantPermissionToCreateParameters.is_owned_by(authority) {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't grant permission to create new configuration parameters outside genesis without permission from genesis"
                    .to_owned()
            ))
        }

        fn validate_revoke(&self, authority: &AccountId, _block_height: u64) -> Result {
            if CanGrantPermissionToCreateParameters.is_owned_by(authority) {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't revoke permission to create new configuration parameters outside genesis without permission from genesis"
                    .to_owned()
            ))
        }
    }

    impl ValidateGrantRevoke for CanSetParameters {
        fn validate_grant(&self, authority: &AccountId, _block_height: u64) -> Result {
            if CanGrantPermissionToSetParameters.is_owned_by(authority) {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't grant permission to set configuration parameters outside genesis without permission from genesis"
                    .to_owned()
            ))
        }

        fn validate_revoke(&self, authority: &AccountId, _block_height: u64) -> Result {
            if CanRevokePermissionToSetParameters.is_owned_by(authority) {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't revoke permission to set configuration parameters outside genesis without permission from genesis"
                    .to_owned()
            ))
        }
    }
}

pub mod role {
    use super::*;

    permission! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanUnregisterAnyRole;
    }
}

pub mod trigger {
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

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanRegisterUserTrigger {
            pub account_id: AccountId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke)]
        #[validate(permission::trigger::Owner)]
        pub struct CanExecuteUserTrigger {
            pub trigger_id: TriggerId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanUnregisterUserTrigger {
            pub account_id: AccountId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke)]
        #[validate(permission::trigger::Owner)]
        pub struct CanMintUserTrigger {
            pub trigger_id: TriggerId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke)]
        #[validate(permission::trigger::Owner)]
        pub struct CanBurnUserTrigger {
            pub trigger_id: TriggerId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke)]
        #[validate(permission::trigger::Owner)]
        pub struct CanSetKeyValueInTrigger {
            pub trigger_id: TriggerId,
        }
    }

    permission! {
        #[derive(ValidateGrantRevoke)]
        #[validate(permission::trigger::Owner)]
        pub struct CanRemoveKeyValueInTrigger {
            pub trigger_id: TriggerId,
        }
    }

    impl_froms!(
        CanMintUserTrigger,
        CanBurnUserTrigger,
        CanExecuteUserTrigger,
        CanSetKeyValueInTrigger,
        CanRemoveKeyValueInTrigger,
    );
}

pub mod executor {
    use super::*;

    permission! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanUpgradeExecutor;
    }
}
