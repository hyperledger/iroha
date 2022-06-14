#![allow(clippy::module_name_repetitions)]

//! This module contains permissions related Iroha functionality.

use std::{fmt::Debug, marker::PhantomData, sync::Arc};

pub use checks::*;
pub use combinators::ValidatorApplyOr as _;
use error::*;
pub use has_token::*;
use iroha_data_model::prelude::*;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
pub use is_allowed::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::wsv::WorldStateView;

pub mod builder;
mod checks;
pub mod combinators;
mod has_token;
mod is_allowed;
pub mod roles;

/// Result type for permission validators
pub type Result<T> = std::result::Result<T, DenialReason>;

/// Operation for which the permission should be checked.
pub trait NeedsPermission: Debug {}

impl NeedsPermission for Instruction {}

impl NeedsPermission for QueryBox {}

// Expression might contain a query, therefore needs to be checked.
impl NeedsPermission for Expression {}

/// Type of object validator can check
#[derive(Debug, Copy, Clone, PartialEq, Eq, derive_more::Display, Encode, Decode, IntoSchema)]
pub enum ValidatorType {
    /// [`Instruction`] variant
    Instruction,
    /// [`QueryBox`] variant
    Query,
    /// [`Expression`] variant
    Expression,
}
pub mod error {
    //! Contains errors structures

    use std::{convert::Infallible, str::FromStr};

    use super::{Decode, Encode, IntoSchema, ValidatorType};
    use crate::smartcontracts::Mismatch;

    /// Wrong validator expectation error
    ///
    /// I.e. used when user tries to validate [`QueryBox`](super::QueryBox) with
    /// [`IsAllowedBoxed`](super::IsAllowedBoxed) containing
    /// [`IsAllowedBoxed::Instruction`](super::IsAllowedBoxed::Instruction) variant
    pub type ValidatorTypeMismatch = Mismatch<ValidatorType>;

    /// Reason for prohibiting the execution of the particular instruction.
    #[derive(Debug, Clone, thiserror::Error, Decode, Encode, IntoSchema)]
    #[allow(variant_size_differences)]
    pub enum DenialReason {
        /// [`ValidatorTypeMismatch`] variant
        #[error("Wrong validator type: {0}")]
        ValidatorTypeMismatch(#[from] ValidatorTypeMismatch),
        /// Variant for custom error
        #[error("{0}")]
        Custom(String),
        /// Variant used when at least one [`Validator`](super::IsAllowed) should be provided
        #[error("No validators provided")]
        NoValidatorsProvided,
    }

    impl From<String> for DenialReason {
        fn from(s: String) -> Self {
            Self::Custom(s)
        }
    }

    impl FromStr for DenialReason {
        type Err = Infallible;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(Self::Custom(s.to_owned()))
        }
    }
}

pub mod prelude {
    //! Exports common types for permissions.

    pub use super::{
        builder::Validator as ValidatorBuilder,
        combinators::{AllowAll, ValidatorApplyOr as _},
        error::DenialReason,
        roles::{IsGrantAllowed, IsGrantAllowedBoxed, IsRevokeAllowed, IsRevokeAllowedBoxed},
        HasTokenBoxed, IsAllowedBoxed,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{collections::BTreeSet, str::FromStr as _};

    use iroha_data_model::{expression::prelude::*, isi::*};

    use super::{builder::Validator as ValidatorBuilder, combinators::DenyAll, *};
    use crate::wsv::World;

    #[derive(Debug, Clone, Serialize)]
    struct DenyBurn;

    impl From<DenyBurn> for IsInstructionAllowedBoxed {
        fn from(permissions: DenyBurn) -> Self {
            Box::new(permissions)
        }
    }

    impl IsAllowed<Instruction> for DenyBurn {
        fn check(
            &self,
            _authority: &AccountId,
            instruction: &Instruction,
            _wsv: &WorldStateView,
        ) -> Result<()> {
            match instruction {
                Instruction::Burn(_) => Err("Denying sequence isi.".to_owned().into()),
                _ => Ok(()),
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    struct DenyAlice;

    impl IsAllowed<Instruction> for DenyAlice {
        fn check(
            &self,
            authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView,
        ) -> Result<()> {
            if authority.name.as_ref() == "alice" {
                Err("Alice account is denied.".to_owned().into())
            } else {
                Ok(())
            }
        }
    }

    impl From<DenyAlice> for IsInstructionAllowedBoxed {
        fn from(value: DenyAlice) -> Self {
            Box::new(value)
        }
    }

    #[derive(Debug, Clone, Serialize)]
    struct GrantedToken;

    // TODO: ADD some Revoke tests.

    impl HasToken for GrantedToken {
        fn token(
            &self,
            _authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView,
        ) -> std::result::Result<PermissionToken, String> {
            Ok(PermissionToken::new(
                Name::from_str("token").expect("Valid"),
            ))
        }
    }

    fn asset_id(
        asset_name: &str,
        asset_domain: &str,
        account_name: &str,
        account_domain: &str,
    ) -> IdBox {
        IdBox::AssetId(AssetId::new(
            AssetDefinitionId::new(
                asset_name.parse().expect("Valid"),
                asset_domain.parse().expect("Valid"),
            ),
            AccountId::new(
                account_name.parse().expect("Valid"),
                account_domain.parse().expect("Valid"),
            ),
        ))
    }

    #[test]
    pub fn multiple_validators_combined() {
        let permissions_validator: IsInstructionAllowedBoxed =
            ValidatorBuilder::with_validator(DenyBurn)
                .with_validator(DenyAlice)
                .all_should_succeed()
                .build();
        let instruction_burn: Instruction =
            BurnBox::new(Value::U32(10), asset_id("xor", "test", "alice", "test")).into();
        let instruction_fail = Instruction::Fail(FailBox {
            message: "fail message".to_owned(),
        });
        let account_bob = <Account as Identifiable>::Id::from_str("bob@test").expect("Valid");
        let account_alice = <Account as Identifiable>::Id::from_str("alice@test").expect("Valid");
        let wsv = WorldStateView::new(World::new());
        assert!(permissions_validator
            .check(&account_bob, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_alice, &instruction_fail, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_bob, &instruction_fail, &wsv)
            .is_ok());
    }

    #[test]
    pub fn recursive_validator() {
        let permissions_validator = ValidatorBuilder::with_recursive_validator(DenyBurn)
            .all_should_succeed()
            .build();
        let instruction_burn: Instruction =
            BurnBox::new(Value::U32(10), asset_id("xor", "test", "alice", "test")).into();
        let instruction_fail = Instruction::Fail(FailBox {
            message: "fail message".to_owned(),
        });
        let nested_instruction_sequence =
            Instruction::If(If::new(true, instruction_burn.clone()).into());
        let account_alice = <Account as Identifiable>::Id::from_str("alice@test").expect("Valid");
        let wsv = WorldStateView::new(World::new());
        assert!(permissions_validator
            .check(&account_alice, &instruction_fail, &wsv)
            .is_ok());
        assert!(permissions_validator
            .check(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_alice, &nested_instruction_sequence, &wsv)
            .is_err());
    }

    #[test]
    pub fn granted_permission() -> eyre::Result<()> {
        let alice_id = <Account as Identifiable>::Id::from_str("alice@test")?;
        let bob_id = <Account as Identifiable>::Id::from_str("bob@test")?;
        let alice_xor_id = <Asset as Identifiable>::Id::new(
            AssetDefinitionId::from_str("xor#test").expect("Valid"),
            AccountId::from_str("alice@test").expect("Valid"),
        );
        let instruction_burn: Instruction = BurnBox::new(Value::U32(10), alice_xor_id).into();
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        let mut bob_account = Account::new(bob_id.clone(), []).build();
        assert!(bob_account.add_permission(PermissionToken::new(
            Name::from_str("token").expect("Valid")
        )));
        assert!(domain.add_account(bob_account).is_none());
        let wsv = WorldStateView::new(World::with([domain], BTreeSet::new()));
        let validator: HasTokenBoxed = Box::new(GrantedToken);
        assert!(validator.check(&alice_id, &instruction_burn, &wsv).is_err());
        assert!(validator.check(&bob_id, &instruction_burn, &wsv).is_ok());
        Ok(())
    }

    #[test]
    pub fn check_query_permissions_nested() {
        let instruction: Instruction = Pair::new(
            TransferBox::new(
                asset_id("btc", "crypto", "seller", "company"),
                Expression::Add(Add::new(
                    Expression::Query(
                        FindAssetQuantityById::new(AssetId::new(
                            AssetDefinitionId::from_str("btc2eth_rate#exchange").expect("Valid"),
                            AccountId::from_str("dex@exchange").expect("Valid"),
                        ))
                        .into(),
                    ),
                    10_u32,
                )),
                asset_id("btc", "crypto", "buyer", "company"),
            ),
            TransferBox::new(
                asset_id("eth", "crypto", "buyer", "company"),
                15_u32,
                asset_id("eth", "crypto", "seller", "company"),
            ),
        )
        .into();
        let wsv = WorldStateView::new(World::new());
        let alice_id = <Account as Identifiable>::Id::from_str("alice@test").expect("Valid");
        assert!(check_query_in_instruction(&alice_id, &instruction, &wsv, &DenyAll.into()).is_err())
    }
}
