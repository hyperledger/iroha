//! Definition of Iroha default permission tokens
#![allow(missing_docs, clippy::missing_errors_doc)]

use alloc::{borrow::ToOwned, format, string::String, vec::Vec};

use iroha_executor_derive::ValidateGrantRevoke;
use iroha_smart_contract::data_model::{executor::Result, prelude::*};

use crate::permission::{self, Token as _};

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
macro_rules! declare_tokens {
    ($($($token_path:ident ::)+ { $token_ty:ident }),+ $(,)?) => {
        macro_rules! map_token {
            ($token:ident => $callback:ident) => {
                match $token.definition_id().as_ref() { $(
                    stringify!($token_ty) => {
                        if let Ok(token) = <$($token_path::)+$token_ty>::try_from($token.clone()) {
                            $callback!(token);
                        }
                    } )+
                    _ => {}
                }

            };
        }

        macro_rules! map_token_type {
            ($callback:ident) => { $(
                $callback!($($token_path::)+$token_ty); )+
            };
        }

        pub(crate) use map_token;
        pub(crate) use map_token_type;
    };
}

macro_rules! token {
    ($($meta:meta)* $item:item) => {
        #[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[derive(Clone, iroha_executor_derive::Token)]
        #[derive(iroha_schema::IntoSchema)]
        $($meta)*
        $item
    };
}

declare_tokens! {
    crate::default::tokens::peer::{CanUnregisterAnyPeer},

    crate::default::tokens::domain::{CanUnregisterDomain},
    crate::default::tokens::domain::{CanSetKeyValueInDomain},
    crate::default::tokens::domain::{CanRemoveKeyValueInDomain},

    crate::default::tokens::account::{CanUnregisterAccount},
    crate::default::tokens::account::{CanMintUserPublicKeys},
    crate::default::tokens::account::{CanBurnUserPublicKeys},
    crate::default::tokens::account::{CanMintUserSignatureCheckConditions},
    crate::default::tokens::account::{CanSetKeyValueInUserAccount},
    crate::default::tokens::account::{CanRemoveKeyValueInUserAccount},

    crate::default::tokens::asset_definition::{CanUnregisterAssetDefinition},
    crate::default::tokens::asset_definition::{CanSetKeyValueInAssetDefinition},
    crate::default::tokens::asset_definition::{CanRemoveKeyValueInAssetDefinition},

    crate::default::tokens::asset::{CanRegisterAssetsWithDefinition},
    crate::default::tokens::asset::{CanUnregisterAssetsWithDefinition},
    crate::default::tokens::asset::{CanUnregisterUserAsset},
    crate::default::tokens::asset::{CanBurnAssetsWithDefinition},
    crate::default::tokens::asset::{CanBurnUserAsset},
    crate::default::tokens::asset::{CanMintAssetsWithDefinition},
    crate::default::tokens::asset::{CanTransferAssetsWithDefinition},
    crate::default::tokens::asset::{CanTransferUserAsset},
    crate::default::tokens::asset::{CanSetKeyValueInUserAsset},
    crate::default::tokens::asset::{CanRemoveKeyValueInUserAsset},

    crate::default::tokens::parameter::{CanGrantPermissionToCreateParameters},
    crate::default::tokens::parameter::{CanRevokePermissionToCreateParameters},
    crate::default::tokens::parameter::{CanCreateParameters},
    crate::default::tokens::parameter::{CanGrantPermissionToSetParameters},
    crate::default::tokens::parameter::{CanRevokePermissionToSetParameters},
    crate::default::tokens::parameter::{CanSetParameters},

    crate::default::tokens::role::{CanUnregisterAnyRole},

    crate::default::tokens::trigger::{CanExecuteUserTrigger},
    crate::default::tokens::trigger::{CanUnregisterUserTrigger},
    crate::default::tokens::trigger::{CanMintUserTrigger},
    crate::default::tokens::trigger::{CanBurnUserTrigger},

    crate::default::tokens::executor::{CanUpgradeExecutor},
}

pub mod peer {
    use super::*;

    token! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanUnregisterAnyPeer;
    }
}

pub mod domain {
    use super::*;

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::domain::Owner)]
        #[validate(permission::domain::Owner)]
        pub struct CanUnregisterDomain {
            pub domain_id: DomainId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::domain::Owner)]
        #[validate(permission::domain::Owner)]
        pub struct CanSetKeyValueInDomain {
            pub domain_id: DomainId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::domain::Owner)]
        #[validate(permission::domain::Owner)]
        pub struct CanRemoveKeyValueInDomain {
            pub domain_id: DomainId,
        }
    }
}

pub mod account {
    use super::*;

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanUnregisterAccount {
            pub account_id: AccountId,
        }
    }
    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanMintUserPublicKeys {
            pub account_id: AccountId,
        }
    }
    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanBurnUserPublicKeys {
            pub account_id: AccountId,
        }
    }
    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanMintUserSignatureCheckConditions {
            pub account_id: AccountId,
        }
    }
    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanSetKeyValueInUserAccount {
            pub account_id: AccountId,
        }
    }
    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::account::Owner)]
        #[validate(permission::account::Owner)]
        pub struct CanRemoveKeyValueInUserAccount {
            pub account_id: AccountId,
        }
    }
}

pub mod asset_definition {
    use super::*;

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanUnregisterAssetDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanSetKeyValueInAssetDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanRemoveKeyValueInAssetDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }
}

pub mod asset {
    use super::*;

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanRegisterAssetsWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanUnregisterAssetsWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanUnregisterUserAsset {
            pub asset_id: AssetId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanBurnAssetsWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanBurnUserAsset {
            pub asset_id: AssetId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanMintAssetsWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset_definition::Owner)]
        #[validate(permission::asset_definition::Owner)]
        pub struct CanTransferAssetsWithDefinition {
            pub asset_definition_id: AssetDefinitionId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanTransferUserAsset {
            pub asset_id: AssetId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
        #[validate(permission::asset::Owner)]
        pub struct CanSetKeyValueInUserAsset {
            pub asset_id: AssetId,
        }
    }

    token! {
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

    token! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanGrantPermissionToCreateParameters;
    }

    token! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanRevokePermissionToCreateParameters;
    }

    token! {
        #[derive(Copy)]
        pub struct CanCreateParameters;
    }

    token! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanGrantPermissionToSetParameters;
    }

    token! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanRevokePermissionToSetParameters;
    }

    token! {
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

    token! {
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

    token! {
        #[derive(ValidateGrantRevoke)]
        #[validate(permission::trigger::Owner)]
        pub struct CanExecuteUserTrigger {
            pub trigger_id: TriggerId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke)]
        #[validate(permission::trigger::Owner)]
        pub struct CanUnregisterUserTrigger {
            pub trigger_id: TriggerId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke)]
        #[validate(permission::trigger::Owner)]
        pub struct CanMintUserTrigger {
            pub trigger_id: TriggerId,
        }
    }

    token! {
        #[derive(ValidateGrantRevoke)]
        #[validate(permission::trigger::Owner)]
        pub struct CanBurnUserTrigger {
            pub trigger_id: TriggerId,
        }
    }

    impl_froms!(
        CanExecuteUserTrigger,
        CanUnregisterUserTrigger,
        CanMintUserTrigger,
        CanBurnUserTrigger,
    );
}

pub mod executor {
    use super::*;

    token! {
        #[derive(Copy, ValidateGrantRevoke)]
        #[validate(permission::OnlyGenesis)]
        pub struct CanUpgradeExecutor;
    }
}
