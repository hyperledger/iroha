//! Module with permission tokens and permission related functionality.

use alloc::borrow::ToOwned as _;

use iroha_schema::IntoSchema;
use iroha_smart_contract::{data_model::JsonString, QueryOutputCursor};
use iroha_smart_contract_utils::debug::DebugExpectExt as _;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    prelude::{Permission as PermissionObject, *},
    TryFromDataModelObjectError,
};

/// Is used to check if the permission token is owned by the account.
pub trait Permission:
    Serialize + DeserializeOwned + IntoSchema + PartialEq<Self> + ValidateGrantRevoke
{
    /// Check if the account owns this token
    fn is_owned_by(&self, account_id: &AccountId) -> bool;

    /// Permission id, according to [`IntoSchema`].
    fn id() -> PermissionId {
        PermissionId::new(
            <Self as iroha_schema::IntoSchema>::type_name()
                .parse()
                .dbg_expect("Failed to parse permission id as `Name`"),
        )
    }

    /// Try to convert from [`PermissionObject`]
    /// # Errors
    /// See [`TryFromDataModelObjectError`]
    fn try_from_object(object: &PermissionObject) -> Result<Self, TryFromDataModelObjectError> {
        if *object.id() != <Self as Permission>::id() {
            return Err(TryFromDataModelObjectError::Id(object.id().name().clone()));
        }
        object
            .payload()
            .deserialize()
            .map_err(TryFromDataModelObjectError::Deserialize)
    }

    /// Convert into [`PermissionObject`]
    fn to_object(&self) -> PermissionObject {
        PermissionObject::new(
            <Self as Permission>::id(),
            JsonString::serialize(&self)
                .expect("failed to serialize concrete data model entity; this is a bug"),
        )
    }
}

/// Trait that should be implemented for all permission tokens.
/// Provides a function to check validity of [`Grant`] and [`Revoke`]
/// instructions containing implementing token.
pub trait ValidateGrantRevoke {
    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate_grant(&self, authority: &AccountId, block_height: u64) -> Result;

    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate_revoke(&self, authority: &AccountId, block_height: u64) -> Result;
}

/// Predicate-like trait used for pass conditions to identify if [`Grant`] or [`Revoke`] should be allowed.
pub trait PassCondition {
    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate(&self, authority: &AccountId, block_height: u64) -> Result;
}

pub mod derive_conversions {
    //! Module with derive macros to generate conversion from custom strongly-typed token
    //! to some pass condition to successfully derive [`ValidateGrantRevoke`](iroha_executor_derive::ValidateGrantRevoke)

    pub mod asset {
        //! Module with derives related to asset tokens

        pub use iroha_executor_derive::RefIntoAssetOwner as Owner;
    }

    pub mod asset_definition {
        //! Module with derives related to asset definition tokens

        pub use iroha_executor_derive::RefIntoAssetDefinitionOwner as Owner;
    }

    pub mod account {
        //! Module with derives related to account tokens

        pub use iroha_executor_derive::RefIntoAccountOwner as Owner;
    }

    pub mod domain {
        //! Module with derives related to domain tokens

        pub use iroha_executor_derive::RefIntoDomainOwner as Owner;
    }
}

pub mod asset {
    //! Module with pass conditions for asset related tokens

    use super::*;

    /// Check if `authority` is the owner of `asset_id`.
    ///
    /// `authority` is owner of `asset_id` if:
    /// - `asset_id.account_id` is `account_id`
    /// - `asset_id.account_id.domain_id` domain is owned by `authority`
    ///
    /// # Errors
    ///
    /// Fails if `is_account_owner` fails
    pub fn is_asset_owner(asset_id: &AssetId, authority: &AccountId) -> Result<bool> {
        crate::permission::account::is_account_owner(asset_id.account_id(), authority)
    }

    /// Pass condition that checks if `authority` is the owner of `asset_id`.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset> {
        /// Asset id to check against
        pub asset_id: &'asset AssetId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_asset_owner(self.asset_id, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access asset owned by another account".to_owned(),
            ))
        }
    }
}

pub mod asset_definition {
    //! Module with pass conditions for asset definition related tokens

    use super::*;

    /// Check if `authority` is the owner of `asset_definition_id`

    /// `authority` is owner of `asset_definition_id` if:
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
        let asset_definition = FindAssetDefinitionById::new(asset_definition_id.clone())
            .execute()
            .map(QueryOutputCursor::into_inner)?;
        if asset_definition.owned_by() == authority {
            Ok(true)
        } else {
            crate::permission::domain::is_domain_owner(asset_definition_id.domain_id(), authority)
        }
    }

    /// Pass condition that checks if `authority` is the owner of `asset_definition_id`.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset_definition> {
        /// Asset definition id to check against
        pub asset_definition_id: &'asset_definition AssetDefinitionId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_asset_definition_owner(self.asset_definition_id, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access asset definition owned by another account".to_owned(),
            ))
        }
    }
}

pub mod account {
    //! Module with pass conditions for asset related tokens

    use super::*;

    /// Check if `authority` is the owner of `account_id`.
    ///
    /// `authority` is owner of `account_id` if:
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
            crate::permission::domain::is_domain_owner(account_id.domain_id(), authority)
        }
    }

    /// Pass condition that checks if `authority` is the owner of `account_id`.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset> {
        /// Account id to check against
        pub account_id: &'asset AccountId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_account_owner(self.account_id, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access another account".to_owned(),
            ))
        }
    }
}

pub mod trigger {
    //! Module with pass conditions for trigger related tokens
    use super::*;
    use crate::permission::domain::is_domain_owner;

    /// Check if `authority` is the owner of `trigger_id`.
    ///
    /// `authority` is owner of `trigger_id` if:
    /// - `trigger.action.authority` is `authority`
    /// - `trigger.action.authority.domain_id` is owned by `authority`
    /// - `trigger.domain_id` is not none and domain is owned by `authority`
    ///
    /// # Errors
    /// - `FindTrigger` fails
    /// - `is_domain_owner` fails
    pub fn is_trigger_owner(trigger_id: &TriggerId, authority: &AccountId) -> Result<bool> {
        let trigger = find_trigger(trigger_id)?;

        Ok(trigger.action().authority() == authority
            || is_domain_owner(trigger.action().authority().domain_id(), authority)?
            || match trigger_id.domain_id() {
                Some(domain) => is_domain_owner(domain, authority)?,
                None => false,
            })
    }
    /// Returns the trigger.
    pub(crate) fn find_trigger(trigger_id: &TriggerId) -> Result<Trigger> {
        let trigger = FindTriggerById::new(trigger_id.clone())
            .execute()
            .map(QueryOutputCursor::into_inner)?;
        Ok(trigger)
    }

    /// Pass condition that checks if `authority` is the owner of `trigger_id`.
    #[derive(Debug, Clone)]
    pub struct Owner<'trigger> {
        /// Trigger id to check against
        pub trigger_id: &'trigger TriggerId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_trigger_owner(self.trigger_id, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't give permission to access trigger owned by another account".to_owned(),
            ))
        }
    }
}

pub mod domain {
    //! Module with pass conditions for domain related tokens
    use super::*;

    /// Check if `authority` is owner of `domain_id`
    ///
    /// # Errors
    /// Fails if query fails
    pub fn is_domain_owner(domain_id: &DomainId, authority: &AccountId) -> Result<bool> {
        FindDomainById::new(domain_id.clone())
            .execute()
            .map(QueryOutputCursor::into_inner)
            .map(|domain| domain.owned_by() == authority)
    }

    /// Pass condition that checks if `authority` is the owner of `domain_id`.
    #[derive(Debug, Clone)]
    pub struct Owner<'domain> {
        /// Domain id to check against
        pub domain_id: &'domain DomainId,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &AccountId, _block_height: u64) -> Result {
            if is_domain_owner(self.domain_id, authority)? {
                return Ok(());
            }

            Err(ValidationFail::NotPermitted(
                "Can't access domain owned by another account".to_owned(),
            ))
        }
    }
}

/// Pass condition that always passes.
#[derive(Debug, Default, Copy, Clone)]
pub struct AlwaysPass;

impl PassCondition for AlwaysPass {
    fn validate(&self, _authority: &AccountId, _block_height: u64) -> Result {
        Ok(())
    }
}

impl<T: Permission> From<&T> for AlwaysPass {
    fn from(_: &T) -> Self {
        Self
    }
}

/// Pass condition that allows operation only in genesis.
///
/// In other words it always operation only if block height is 0.
#[derive(Debug, Default, Copy, Clone)]
pub struct OnlyGenesis;

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
    FindAllAccounts
        .execute()
        .dbg_expect("failed to query all accounts")
        .into_iter()
        .map(|account| account.dbg_expect("failed to retrieve account"))
        .flat_map(|account| {
            FindPermissionsByAccountId::new(account.id().clone())
                .execute()
                .dbg_expect("failed to query permssion token for account")
                .into_iter()
                .map(|token| token.dbg_expect("failed to retrieve permission token"))
                .map(move |token| (account.id().clone(), token))
        })
}

/// Iterator over all roles and theirs permission tokens
pub(crate) fn roles_permissions() -> impl Iterator<Item = (RoleId, PermissionObject)> {
    FindAllRoles
        .execute()
        .dbg_expect("failed to query all accounts")
        .into_iter()
        .map(|role| role.dbg_expect("failed to retrieve account"))
        .flat_map(|role| {
            role.permissions()
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .map(move |token| (role.id().clone(), token))
        })
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String};

    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[test]
    fn convert_token() {
        #[derive(
            Serialize, Deserialize, IntoSchema, PartialEq, ValidateGrantRevoke, Permission,
        )]
        #[validate(AlwaysPass)]
        struct SampleToken {
            can_do_whatever: bool,
        }

        let object = PermissionObject::new(
            "SampleToken".parse().unwrap(),
            json!({ "can_do_whatever": false }),
        );
        let parsed = SampleToken::try_from_object(&object).expect("valid");

        assert!(!parsed.can_do_whatever);
    }
}
