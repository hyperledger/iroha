//! Module with permission tokens and permission related functionality.

use alloc::borrow::ToOwned as _;

use iroha_schema::IntoSchema;
use iroha_smart_contract::data_model::permission::PermissionToken;
use iroha_smart_contract_utils::debug::DebugExpectExt as _;
use serde::{de::DeserializeOwned, Serialize};

use crate::{data_model::prelude::*, prelude::*};

/// [`Token`] trait is used to check if the token is owned by the account.
pub trait Token:
    Serialize
    + DeserializeOwned
    + IntoSchema
    + TryFrom<PermissionToken, Error = PermissionTokenConversionError>
    + PartialEq<Self>
    + ValidateGrantRevoke
{
    /// Return name of this permission token
    fn name() -> Name {
        <Self as iroha_schema::IntoSchema>::type_name()
            .parse()
            .dbg_expect("Failed to parse permission token as `Name`")
    }

    /// Check if token is owned by the account
    fn is_owned_by(&self, account_id: &AccountId) -> bool;
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

/// Error type for `TryFrom<PermissionToken>` implementations.
#[derive(Debug)]
pub enum PermissionTokenConversionError {
    /// Unexpected token id.
    Id(PermissionTokenId),
    /// Failed to deserialize JSON
    Deserialize(serde_json::Error),
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
        let asset_definition =
            FindAssetDefinitionById::new(asset_definition_id.clone()).execute()?;
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

    /// Check if `authority` is the owner of `trigger_id`.
    ///
    /// `authority` is owner of `trigger_id` if:
    /// - `trigger.action.authority` is `authority`
    /// - `trigger.domain_id` is not none and domain is owned by `authority`
    ///
    /// # Errors
    /// - `FindTrigger` fails
    /// - `is_domain_owner` fails
    pub fn is_trigger_owner(trigger_id: &TriggerId, authority: &AccountId) -> Result<bool> {
        let trigger = FindTriggerById::new(trigger_id.clone()).execute()?;
        if trigger.action().authority() == authority {
            Ok(true)
        } else {
            trigger_id
                .domain_id()
                .as_ref()
                .map_or(Ok(false), |domain_id| {
                    crate::permission::domain::is_domain_owner(domain_id, authority)
                })
        }
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

impl<T: Token> From<&T> for AlwaysPass {
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

impl<T: Token> From<&T> for OnlyGenesis {
    fn from(_: &T) -> Self {
        Self
    }
}

/// Iterator over all accounts and theirs permission tokens
pub(crate) fn accounts_permission_tokens() -> impl Iterator<Item = (AccountId, PermissionToken)> {
    FindAllAccounts
        .execute()
        .dbg_expect("failed to query all accounts")
        .into_iter()
        .flat_map(|account| {
            FindPermissionTokensByAccountId::new(account.id().clone())
                .execute()
                .dbg_expect("failed to query permssion token for account")
                .into_iter()
                .map(move |token| (account.id().clone(), token))
        })
}
