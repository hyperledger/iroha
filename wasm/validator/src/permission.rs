//! Module with permission tokens and permission related functionality.

use alloc::borrow::ToOwned as _;

use crate::{data_model::prelude::*, prelude::*};

/// [`Token`] trait is used to check if the token is owned by the account.
pub trait Token:
    TryFrom<PermissionToken, Error = PermissionTokenConversionError> + ValidateGrantRevoke
{
    /// Get definition of this token
    fn definition() -> PermissionTokenDefinition;

    /// Check if token is owned by the account using evaluation on host.
    ///
    /// Basically it's a wrapper around [`DoesAccountHavePermissionToken`] query.
    fn is_owned_by(&self, account_id: &<Account as Identifiable>::Id) -> bool;
}

/// Trait that should be implemented for all permission tokens.
/// Provides a function to check validity of [`Grant`] and [`Revoke`]
/// instructions containing implementing token.
pub trait ValidateGrantRevoke {
    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Result;

    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Result;
}

/// Predicate-like trait used for pass conditions to identify if [`Grant`] or [`Revoke`] should be allowed.
pub trait PassCondition {
    #[allow(missing_docs, clippy::missing_errors_doc)]
    fn validate(&self, authority: &<Account as Identifiable>::Id) -> Result;
}

/// Error type for `TryFrom<PermissionToken>` implementations.
#[derive(Debug, Clone)]
pub enum PermissionTokenConversionError {
    /// Unexpected token id.
    Id(PermissionTokenId),
    /// Missing parameter.
    Param(&'static str),
    // TODO: Improve this error
    /// Unexpected parameter value.
    Value(alloc::string::String),
}

pub mod derive_conversions {
    //! Module with derive macros to generate conversion from custom strongly-typed token
    //! to some pass condition to successfully derive [`ValidateGrantRevoke`](iroha_validator_derive::ValidateGrantRevoke)

    pub mod asset {
        //! Module with derives related to asset tokens

        pub use iroha_validator_derive::RefIntoAssetOwner as Owner;
    }

    pub mod asset_definition {
        //! Module with derives related to asset definition tokens

        pub use iroha_validator_derive::RefIntoAssetDefinitionOwner as Owner;
    }

    pub mod account {
        //! Module with derives related to account tokens

        pub use iroha_validator_derive::RefIntoAccountOwner as Owner;
    }
}

pub mod asset {
    //! Module with pass conditions for asset related tokens

    use super::*;

    /// Pass condition that checks if `authority` is the owner of `asset_id`.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset> {
        pub asset_id: &'asset <Asset as Identifiable>::Id,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &<Account as Identifiable>::Id) -> Result {
            if self.asset_id.account_id() != authority {
                return Err(ValidationFail::NotPermitted(
                    "Can't access asset owned by another account".to_owned(),
                ));
            }

            Ok(())
        }
    }
}

pub mod asset_definition {
    //! Module with pass conditions for asset definition related tokens

    use super::*;

    fn is_asset_definition_owner(
        asset_definition_id: &<AssetDefinition as Identifiable>::Id,
        authority: &<Account as Identifiable>::Id,
    ) -> Result<bool> {
        IsAssetDefinitionOwner::new(asset_definition_id.clone(), authority.clone()).execute()
    }

    /// Pass condition that checks if `authority` is the owner of `asset_definition_id`.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset_definition> {
        pub asset_definition_id: &'asset_definition <AssetDefinition as Identifiable>::Id,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &<Account as Identifiable>::Id) -> Result {
            if !is_asset_definition_owner(self.asset_definition_id, authority)? {
                return Err(ValidationFail::NotPermitted(
                    "Can't access asset definition owned by another account".to_owned(),
                ));
            }

            Ok(())
        }
    }
}

pub mod account {
    //! Module with pass conditions for asset related tokens

    use super::*;

    /// Pass condition that checks if `authority` is the owner of `account_id`.
    #[derive(Debug, Clone)]
    pub struct Owner<'asset> {
        pub account_id: &'asset <Account as Identifiable>::Id,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &<Account as Identifiable>::Id) -> Result {
            if self.account_id != authority {
                return Err(ValidationFail::NotPermitted(
                    "Can't access another account".to_owned(),
                ));
            }

            Ok(())
        }
    }
}

pub mod trigger {
    //! Module with pass conditions for trigger related tokens
    use super::*;

    /// Check if `authority` is the owner of `trigger_id`.
    ///
    /// Wrapper around [`FindTriggerById`](crate::data_model::prelude::FindTriggerById) query.
    ///
    /// # Errors
    ///
    /// Fails if query fails
    pub fn is_trigger_owner(
        trigger_id: <Trigger<FilterBox, Executable> as Identifiable>::Id,
        authority: &<Account as Identifiable>::Id,
    ) -> Result<bool> {
        FindTriggerById::new(trigger_id)
            .execute()
            .map(|trigger| trigger.action().authority() == authority)
    }

    /// Pass condition that checks if `authority` is the owner of `trigger_id`.
    #[derive(Debug, Clone)]
    pub struct Owner<'trigger> {
        pub trigger_id: &'trigger <Trigger<FilterBox, Executable> as Identifiable>::Id,
    }

    impl PassCondition for Owner<'_> {
        fn validate(&self, authority: &<Account as Identifiable>::Id) -> Result {
            if !is_trigger_owner(self.trigger_id.clone(), authority)? {
                return Err(ValidationFail::NotPermitted(
                    "Can't give permission to access trigger owned by another account".to_owned(),
                ));
            }

            Ok(())
        }
    }
}

/// Pass condition that always passes.
#[derive(Debug, Default, Copy, Clone)]
pub struct AlwaysPass;

impl PassCondition for AlwaysPass {
    fn validate(&self, _: &<Account as Identifiable>::Id) -> Result {
        Ok(())
    }
}

impl<T: Token> From<&T> for AlwaysPass {
    fn from(_: &T) -> Self {
        Self::default()
    }
}

/// Pass condition that allows operation only in genesis.
///
/// In other words it always denies the operation, because runtime validator is not used
/// in genesis validation.
#[derive(Debug, Default, Copy, Clone)]
pub struct OnlyGenesis;

impl PassCondition for OnlyGenesis {
    fn validate(&self, _: &<Account as Identifiable>::Id) -> Result {
        Err(ValidationFail::NotPermitted(
            "This operation is always denied and only allowed inside the genesis block".to_owned(),
        ))
    }
}

impl<T: Token> From<&T> for OnlyGenesis {
    fn from(_: &T) -> Self {
        Self::default()
    }
}
