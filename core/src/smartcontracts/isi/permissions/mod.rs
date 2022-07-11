#![allow(clippy::module_name_repetitions)]

//! This module contains permissions related Iroha functionality.

use std::{fmt::Debug, marker::PhantomData, ops::Deref};

pub use checks::*;
pub use has_token::*;
use iroha_data_model::prelude::*;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::wsv::WorldStateView;

mod checks;
pub mod combinators;
mod has_token;
pub mod judge;
pub mod roles;

/// Result type associated with permission validators
pub type Result<T> = std::result::Result<T, DenialReason>;

/// Operation for which the permission should be checked
pub trait NeedsPermission: Debug {
    /// Get the type of validator required to check the operation
    ///
    /// Accepts `self` because of the [`NeedsPermissionBox`]
    fn required_validator_type(&self) -> ValidatorType;
}

impl NeedsPermission for Instruction {
    fn required_validator_type(&self) -> ValidatorType {
        ValidatorType::Instruction
    }
}

impl NeedsPermission for QueryBox {
    fn required_validator_type(&self) -> ValidatorType {
        ValidatorType::Query
    }
}

// Expression might contain a query, therefore needs to be checked.
impl NeedsPermission for Expression {
    fn required_validator_type(&self) -> ValidatorType {
        ValidatorType::Expression
    }
}

/// Boxed version of [`NeedsPermission`]
#[derive(Debug, derive_more::From, derive_more::TryInto)]
pub enum NeedsPermissionBox {
    /// [`Instruction`] operation
    Instruction(Instruction),
    /// [`QueryBox`] operation
    Query(QueryBox),
    /// [`Expression`] operation
    Expression(Expression),
}

impl NeedsPermission for NeedsPermissionBox {
    fn required_validator_type(&self) -> ValidatorType {
        match self {
            NeedsPermissionBox::Instruction(_) => ValidatorType::Instruction,
            NeedsPermissionBox::Query(_) => ValidatorType::Query,
            NeedsPermissionBox::Expression(_) => ValidatorType::Expression,
        }
    }
}

/// Implementation of this trait provides custom permission checks for the Iroha-base
pub trait IsAllowed: Debug {
    /// Type of operation to be checked
    type Operation: NeedsPermission;

    /// Check if the `authority` is allowed to perform `instruction`
    /// given the current state of `wsv`.
    ///
    /// # Reasons to deny
    /// If the execution of `instruction` under given `authority` with
    /// the current state of `wsv` is disallowed.
    fn check(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict;
}

/// Box with dyn type implementing [`IsAllowed`]
pub type IsOperationAllowedBoxed<O> = Box<dyn IsAllowed<Operation = O> + Send + Sync>;

/// Type of validator
#[derive(Debug, Copy, Clone, PartialEq, Eq, derive_more::Display, Encode, Decode, IntoSchema)]
pub enum ValidatorType {
    /// Validator checking [`Instruction`]
    Instruction,
    /// Validator checking [`QueryBox`]
    Query,
    /// Validator checking [`Expression`]
    Expression,
}

/// Verdict returned by validators
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display, Encode, Decode, IntoSchema)]
pub enum ValidatorVerdict {
    /// Deny the execution of an operation and provide the [`DenialReason`].
    ///
    /// Something went wrong and the validator voted to deny the execution of the instruction.
    Deny(DenialReason),
    /// Skip an operation.
    ///
    /// The validator votes to skip an operation if it is not supported by the validator
    /// or has no meaning in a particular context.
    Skip,
    /// Allow the execution of an instruction.
    ///
    /// The validator allows an instruction to be executed if
    /// the operation is correct from its point of view.
    Allow,
}

impl PartialOrd for ValidatorVerdict {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}

// Deny < Skip < Allow
impl Ord for ValidatorVerdict {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let lhs: u8 = **self;
        let rhs: u8 = **other;
        lhs.cmp(&rhs)
    }
}

impl Deref for ValidatorVerdict {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        match self {
            ValidatorVerdict::Deny(_) => &0,
            ValidatorVerdict::Skip => &1,
            ValidatorVerdict::Allow => &2,
        }
    }
}

impl ValidatorVerdict {
    /// Check if verdict is [`Allow`](ValidatorVerdict::Allow)
    #[inline]
    pub fn is_allow(&self) -> bool {
        matches!(self, ValidatorVerdict::Allow)
    }

    /// Check if verdict is [`Deny`](ValidatorVerdict::Deny)
    #[inline]
    pub fn is_deny(&self) -> bool {
        matches!(self, ValidatorVerdict::Deny(_))
    }

    /// Check if verdict is [`Skip`](ValidatorVerdict::Skip)
    #[inline]
    pub fn is_skip(&self) -> bool {
        matches!(self, ValidatorVerdict::Skip)
    }

    /// Compare `self` with `other` and return the least permissive one
    ///
    /// Returns `self` if both are equal
    #[must_use]
    #[inline]
    pub fn least_permissive(self, other: Self) -> Self {
        std::cmp::min(self, other)
    }

    /// Similar to [`least_permissive`](Self::least_permissive)
    /// but won't compute `f` if `self` is [`Deny`](ValidatorVerdict::Deny)
    #[must_use]
    pub fn least_permissive_with(self, f: impl FnOnce() -> Self) -> Self {
        if let Self::Deny(_) = &self {
            self
        } else {
            self.least_permissive(f())
        }
    }

    /// Compare `self` with `other` and return the most permissive one
    ///
    /// Returns `self` if both are equal
    #[must_use]
    #[inline]
    pub fn most_permissive(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }

    /// Similar to [`most_permissive`](Self::most_permissive)
    /// but won't compute `f` if `self` is [`Allow`](ValidatorVerdict::Allow)
    #[must_use]
    pub fn most_permissive_with(self, f: impl FnOnce() -> Self) -> Self {
        if let Self::Allow = &self {
            self
        } else {
            self.most_permissive(f())
        }
    }
}

impl From<Result<()>> for ValidatorVerdict {
    fn from(result: Result<()>) -> Self {
        match result {
            Ok(_) => ValidatorVerdict::Allow,
            Err(reason) => ValidatorVerdict::Deny(reason),
        }
    }
}

/// Reason for denying the execution of a particular instruction.
pub type DenialReason = String;

pub mod prelude {
    //! Exports common types for permissions.

    pub use super::{
        combinators::ValidatorApplyOr as _,
        judge::{
            builder::Builder as JudgeBuilder, AllowAll, DenyAll, Judge, OperationJudgeBoxed,
            QueryJudgeArc,
        },
        roles::{IsGrantAllowed, IsRevokeAllowed},
        DenialReason, IsAllowed, ValidatorVerdict,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{collections::BTreeSet, str::FromStr as _};

    use iroha_data_model::{expression::prelude::*, isi::*};

    use super::{judge::DenyAll, prelude::*, *};
    use crate::wsv::World;

    #[derive(Debug, Clone, Serialize)]
    struct DenyBurn;

    impl IsAllowed for DenyBurn {
        type Operation = Instruction;

        fn check(
            &self,
            _authority: &AccountId,
            instruction: &Instruction,
            _wsv: &WorldStateView,
        ) -> ValidatorVerdict {
            match instruction {
                Instruction::Burn(_) => ValidatorVerdict::Deny("Denying sequence isi.".to_owned()),
                _ => ValidatorVerdict::Skip,
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    struct DenyAlice;

    impl IsAllowed for DenyAlice {
        type Operation = Instruction;

        fn check(
            &self,
            authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView,
        ) -> ValidatorVerdict {
            if authority.name.as_ref() == "alice" {
                ValidatorVerdict::Deny("Alice account is denied.".to_owned())
            } else {
                ValidatorVerdict::Skip
            }
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
        let permissions_validator = JudgeBuilder::with_validator(DenyBurn)
            .with_validator(DenyAlice)
            .no_denies()
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
            .judge(&account_bob, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .judge(&account_alice, &instruction_fail, &wsv)
            .is_err());
        assert!(permissions_validator
            .judge(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .judge(&account_bob, &instruction_fail, &wsv)
            .is_ok());
    }

    #[test]
    pub fn recursive_validator() {
        let permissions_validator = JudgeBuilder::with_recursive_validator(DenyBurn)
            .no_denies()
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
            .judge(&account_alice, &instruction_fail, &wsv)
            .is_ok());
        assert!(permissions_validator
            .judge(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .judge(&account_alice, &nested_instruction_sequence, &wsv)
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
        let validator = GrantedToken.into_validator();
        assert!(validator
            .check(&alice_id, &instruction_burn, &wsv)
            .is_deny());
        assert!(validator.check(&bob_id, &instruction_burn, &wsv).is_allow());
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
        let judge = JudgeBuilder::with_validator(DenyAll::new().into_validator())
            .no_denies()
            .build();
        assert!(check_query_in_instruction(&alice_id, &instruction, &wsv, &judge).is_err())
    }
}
