//! This module contains permissions related Iroha functionality.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
#![allow(clippy::module_name_repetitions)]

use core::{
    fmt::Display,
    marker::PhantomData,
    ops::{ControlFlow, Deref, Not},
};

pub use checks::*;
use derive_more::Display;
pub use has_token::*;
use iroha_data_model::{
    permission::validator::{DenialReason, NeedsPermission},
    predicate::GenericPredicateBox,
    prelude::*,
    utils::*,
    PredicateSymbol,
};
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
pub type Result<T> = core::result::Result<T, DenialReason>;

/// Implementation of this trait provides custom permission checks for the Iroha-base
pub trait IsAllowed: Display {
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
pub type IsOperationAllowedBoxed<O> =
    GenericPredicateBox<Box<dyn IsAllowed<Operation = O> + Send + Sync>>;

impl<O: NeedsPermission> IsAllowed for IsOperationAllowedBoxed<O> {
    type Operation = O;

    fn check(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        self.applies((authority, operation, wsv))
    }
}

impl<O: NeedsPermission> PredicateTrait<(&AccountId, &O, &WorldStateView)>
    for Box<dyn IsAllowed<Operation = O> + Send + Sync>
{
    type EvaluatesTo = ValidatorVerdict;

    fn applies(&self, input: (&AccountId, &O, &WorldStateView)) -> Self::EvaluatesTo {
        let (account_id, operation, wsv) = input;
        self.check(account_id, operation, wsv)
    }
}

/// Extension trait for [`IsAllowed`] implementing convenience functions
/// See implementation of [`PredicateSymbol`] for [`ValidatorVerdict`]
/// for details on logical operator behaviour.
pub trait IsAllowedExt: IsAllowed + Send + Sync + 'static + Sized {
    /// Convert to `IsOperationAllowedBoxed`
    fn boxed(self) -> IsOperationAllowedBoxed<Self::Operation> {
        IsOperationAllowedBoxed::Raw(Box::new(self))
    }

    /// Create [`IsOperationAllowedBoxed`] which combines validation
    /// results from `self` and `other` with logical "or"
    fn or(
        self,
        other: impl IsAllowed<Operation = Self::Operation> + Send + Sync + 'static,
    ) -> IsOperationAllowedBoxed<Self::Operation> {
        IsOperationAllowedBoxed::or(self.boxed(), other.boxed())
    }

    /// Create [`IsOperationAllowedBoxed`] which combines validation
    /// results from `self` and `other` with logical "and"
    fn and(
        self,
        other: impl IsAllowed<Operation = Self::Operation> + Send + Sync + 'static,
    ) -> IsOperationAllowedBoxed<Self::Operation> {
        IsOperationAllowedBoxed::and(self.boxed(), other.boxed())
    }

    /// Create [`IsOperationAllowedBoxed`] which negates output
    /// of `self`
    fn negate(self) -> IsOperationAllowedBoxed<Self::Operation> {
        IsOperationAllowedBoxed::negate(self.boxed())
    }
}

impl<T> IsAllowedExt for T where T: IsAllowed + Send + Sync + 'static {}

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

/// Logical operations on [`ValidatorVerdict`] behave as follows:
///
/// | Not   |      |
/// |-------|------|
/// | Allow | Deny |
/// | Skip  | Skip |
/// | Deny  | Allow|
///
/// | And  | Allow | Skip  | Deny |
/// |------|-------|-------|------|
/// |Allow | Allow | Allow | Deny |
/// |Skip  | Allow | Skip  | Deny |
/// |Deny  | Deny  | Deny  | Deny |
///
///
/// | Or   | Allow | Skip  | Deny  |
/// |------|-------|-------|-------|
/// |Allow | Allow | Allow | Allow |
/// |Skip  | Allow | Skip  | Deny  |
/// |Deny  | Allow | Deny  | Deny  |
///
impl PredicateSymbol for ValidatorVerdict {
    #[allow(clippy::unnested_or_patterns)] // More verbose, but more readable here
    fn and(self, other: Self) -> ControlFlow<Self, Self> {
        match (self, other) {
            // Deny AND x => Deny
            (deny @ Self::Deny(_), _) | (_, deny @ Self::Deny(_)) => ControlFlow::Break(deny),
            // Skip AND Skip => Skip
            (Self::Skip, Self::Skip) => ControlFlow::Continue(Self::Skip),
            // Allow AND Allow => Allow
            (Self::Allow, Self::Allow) |
            //  Allow AND Skip => Allow
            (Self::Allow, Self::Skip) | (Self::Skip, Self::Allow) => {
                ControlFlow::Continue(Self::Allow)
            }
        }
    }

    fn or(self, other: Self) -> ControlFlow<Self, Self> {
        match (self, other) {
            // Allow OR x => Allow
            (Self::Allow, _) | (_, Self::Allow) => ControlFlow::Break(Self::Allow),
            // Skip OR Skip => Skip
            (Self::Skip, Self::Skip) => ControlFlow::Continue(Self::Skip),
            // Deny OR Deny => Deny(combined reasons)
            (Self::Deny(left), Self::Deny(right)) => {
                ControlFlow::Continue(ValidatorVerdict::Deny(format!(
                    "Neither the first validator succeeded: {}, \
                     nor the second validator : {}",
                    left, right
                )))
            }
            // Deny OR Skip => Deny
            (deny @ Self::Deny(_), Self::Skip) | (Self::Skip, deny @ Self::Deny(_)) => {
                ControlFlow::Continue(deny)
            }
        }
    }
}

impl Not for ValidatorVerdict {
    type Output = Self;

    fn not(self) -> Self::Output {
        match &self {
            ValidatorVerdict::Deny(_) => ValidatorVerdict::Allow,
            ValidatorVerdict::Skip => ValidatorVerdict::Skip,
            _ => ValidatorVerdict::Deny("Negated Allow verdict".to_owned()),
        }
    }
}

impl PartialOrd for ValidatorVerdict {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}

// Deny < Skip < Allow
impl Ord for ValidatorVerdict {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
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
        core::cmp::min(self, other)
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
        core::cmp::max(self, other)
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

/// Trait for hard-coded strongly-typed permission tokens.
///
/// # Examples
///
/// ```
/// use iroha_core::smartcontracts::isi::permissions::{
///     PermissionTokenTrait, PredefinedTokenConversionError,
/// };
/// use iroha_data_model::prelude::*;
///
/// struct ExampleToken {
///     pub param: String,
/// }
///
/// impl PermissionTokenTrait for ExampleToken {
///     #[inline]
///     fn definition() -> &'static PermissionTokenDefinition {
///         static DEFINITION: once_cell::sync::Lazy<PermissionTokenDefinition> =
///             once_cell::sync::Lazy::new(|| PermissionTokenDefinition::new("example_token".parse().expect("Valid")));
///         &DEFINITION
///     }
/// }
///
/// impl From<ExampleToken> for PermissionToken {
///     fn from(example_token: ExampleToken) -> Self {
///         PermissionToken::new(ExampleToken::definition_id().clone())
///             .with_params([(
///                 "param".parse().expect("Valid"),
///                 Value::String(example_token.param)
///             )])
///     }
/// }
///
/// impl TryFrom<PermissionToken> for ExampleToken {
///     type Error = PredefinedTokenConversionError;
///
///     fn try_from(token: PermissionToken) -> core::result::Result<Self, Self::Error> {
///         static PARAM_NAME: once_cell::sync::Lazy<Name> =
///             once_cell::sync::Lazy::new(|| "param".parse().expect("Valid"));
///
///         if token.definition_id() != Self::definition_id() {
///             return Err(
///                 PredefinedTokenConversionError::Id(
///                     token.definition_id().clone()
///                 )
///             );
///         }
///         if let Some(Value::String(ref param)) = token.get_param(&PARAM_NAME) {
///             return Ok(ExampleToken { param: param.clone() });
///         }
///
///         Err(PredefinedTokenConversionError::Param(&PARAM_NAME))
///     }
/// }
/// ```
pub trait PermissionTokenTrait:
    Into<PermissionToken> + TryFrom<PermissionToken, Error = PredefinedTokenConversionError>
{
    /// Get associated [`PermissionTokenDefinition`].
    fn definition() -> &'static PermissionTokenDefinition;

    /// Get associated [`PermissionTokenDefinition`] id.
    fn definition_id() -> &'static <PermissionTokenDefinition as Identifiable>::Id {
        Self::definition().id()
    }
}

/// Errors that may appear when converting specialized permission tokens
/// to universal `[PermissionToken]`
#[derive(Debug, thiserror::Error)]
pub enum PredefinedTokenConversionError {
    /// Wrong token definition id
    #[error("Wrong token definition id: {0}")]
    Id(<PermissionTokenDefinition as Identifiable>::Id),
    /// Parameter not present in token parameters
    #[error("Parameter {0} not found")]
    Param(&'static Name),
    /// Unexpected value for parameter
    #[error("Wrong value for parameter {0}")]
    Value(&'static Name),
}

pub mod prelude {
    //! Exports common types for permissions.

    pub use super::{
        judge::{
            builder::Builder as JudgeBuilder, AllowAll, DenyAll, Judge, OperationJudgeBoxed,
            QueryJudgeArc,
        },
        roles::{IsGrantAllowed, IsRevokeAllowed},
        IsAllowed, IsAllowedExt, ValidatorVerdict,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{collections::BTreeSet, str::FromStr as _};

    use iroha_data_model::{expression::prelude::*, isi::*};

    use super::{judge::DenyAll, prelude::*, *};
    use crate::{kura::Kura, wsv::World};

    #[derive(Debug, Clone, Serialize, Display)]
    #[display(fmt = "Deny all burn operations")]
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

    #[derive(Debug, Clone, Serialize, Display)]
    #[display(fmt = "Deny all Alice's operations")]
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
    struct TestToken;

    impl PermissionTokenTrait for TestToken {
        #[inline]
        fn definition() -> &'static PermissionTokenDefinition {
            static DEFINITION: once_cell::sync::Lazy<PermissionTokenDefinition> =
                once_cell::sync::Lazy::new(|| {
                    PermissionTokenDefinition::new("test_token".parse().expect("Valid"))
                });
            &DEFINITION
        }
    }

    impl From<TestToken> for PermissionToken {
        fn from(_: TestToken) -> Self {
            PermissionToken::new(TestToken::definition_id().clone())
        }
    }

    impl TryFrom<PermissionToken> for TestToken {
        type Error = PredefinedTokenConversionError;
        fn try_from(token: PermissionToken) -> std::result::Result<Self, Self::Error> {
            if token.definition_id() == Self::definition_id() {
                Ok(Self)
            } else {
                Err(PredefinedTokenConversionError::Id(
                    token.definition_id().clone(),
                ))
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    struct HasTestToken;

    // TODO: ADD some Revoke tests.

    impl HasToken for HasTestToken {
        type Token = TestToken;

        fn token(
            &self,
            _authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView,
        ) -> core::result::Result<TestToken, String> {
            Ok(TestToken)
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

    // Convenience macro to concisely test truth tables
    macro_rules! assert_maps {
        ($op:path; $($($left:ident),* => $right:pat_param $(=$cont:ident)?),*) => {{
            use crate::ValidatorVerdict::{Allow, Deny, Skip};
            $(assert!(
                 matches!(
                     $op($($left.clone()),*),
                     wrap_cf!($($cont,)? $right)
                  )
            ));*
        }}
    }

    // Helper for `assert_maps!`
    macro_rules! wrap_cf {
        ($p:pat) => {
            $p
        };
        (cont, $p:pat) => {
            core::ops::ControlFlow::Continue($p)
        };
        (brk, $p:pat) => {
            core::ops::ControlFlow::Break($p)
        };
    }

    #[test]
    #[allow(clippy::cognitive_complexity)] // Clippy gets confused by macros here, I think?
    pub fn validator_verdict_logic() {
        fn shallow_eq(left: &ValidatorVerdict, right: &ValidatorVerdict) -> bool {
            (left.is_allow() && right.is_allow())
                || (left.is_skip() && right.is_skip())
                || (left.is_deny() && right.is_deny())
        }

        let allow = ValidatorVerdict::Allow;
        let skip = ValidatorVerdict::Skip;
        let deny = ValidatorVerdict::Deny("dummy".into());

        PredicateSymbol::test_conformity_with_eq(
            vec![allow.clone(), skip.clone(), deny.clone()],
            shallow_eq,
        );

        assert_maps! {
            core::ops::Not::not;
            allow => Deny(_),
            skip  => Skip,
            deny  => Allow
        }

        assert_maps! {
            PredicateSymbol::and;
            allow, allow => Allow    =cont,
            allow, skip  => Allow    =cont,
            allow, deny  => Deny(_)  =brk,
            skip,  allow => Allow    =cont,
            skip,  skip  => Skip     =cont,
            skip,  deny  => Deny(_)  =brk,
            deny,  allow => Deny(_)  =brk,
            deny,  skip  => Deny(_)  =brk,
            deny,  deny  => Deny(_)  =brk
        }

        assert_maps! {
            PredicateSymbol::or;
            allow, allow => Allow    =brk,
            allow, skip  => Allow    =brk,
            allow, deny  => Allow    =brk,
            skip,  allow => Allow    =brk,
            skip,  skip  => Skip     =cont,
            skip,  deny  => Deny(_)  =cont,
            deny,  allow => Allow    =brk,
            deny,  skip  => Deny(_)  =cont,
            deny,  deny  => Deny(_)  =cont
        }
    }

    #[test]
    pub fn multiple_validators_combined() {
        let permissions_validator = JudgeBuilder::with_validator(DenyBurn)
            .with_validator(DenyAlice)
            .no_denies()
            .build();
        let instruction_burn: Instruction =
            BurnBox::new(10_u32.to_value(), asset_id("xor", "test", "alice", "test")).into();
        let instruction_fail = Instruction::Fail(FailBox {
            message: "fail message".to_owned(),
        });
        let account_bob = <Account as Identifiable>::Id::from_str("bob@test").expect("Valid");
        let account_alice = <Account as Identifiable>::Id::from_str("alice@test").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::new(), kura);
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
            BurnBox::new(10_u32.to_value(), asset_id("xor", "test", "alice", "test")).into();
        let instruction_fail = Instruction::Fail(FailBox {
            message: "fail message".to_owned(),
        });
        let nested_instruction_sequence =
            Instruction::If(If::new(true, instruction_burn.clone()).into());
        let account_alice = <Account as Identifiable>::Id::from_str("alice@test").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::new(), kura);
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
        let instruction_burn: Instruction = BurnBox::new(10_u32.to_value(), alice_xor_id).into();
        let mut domain = Domain::new(DomainId::from_str("test").expect("Valid")).build();
        let bob_account = Account::new(bob_id.clone(), []).build();
        assert!(domain.add_account(bob_account).is_none());
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::with([domain], BTreeSet::new()), kura);
        let validator = HasTestToken.into_validator();
        assert!(wsv.add_account_permission(&bob_id, TestToken.into()));
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
                EvaluatesTo::new_evaluates_to_value(
                    Add::new(
                        EvaluatesTo::new_unchecked(
                            Expression::Query(
                                FindAssetQuantityById::new(AssetId::new(
                                    AssetDefinitionId::from_str("btc2eth_rate#exchange")
                                        .expect("Valid"),
                                    AccountId::from_str("dex@exchange").expect("Valid"),
                                ))
                                .into(),
                            )
                            .into(),
                        ),
                        10_u32,
                    )
                    .into(),
                ),
                asset_id("btc", "crypto", "buyer", "company"),
            ),
            TransferBox::new(
                asset_id("eth", "crypto", "buyer", "company"),
                15_u32,
                asset_id("eth", "crypto", "seller", "company"),
            ),
        )
        .into();
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::new(), kura);
        let alice_id = <Account as Identifiable>::Id::from_str("alice@test").expect("Valid");
        let judge = JudgeBuilder::with_validator(DenyAll::new().into_validator())
            .no_denies()
            .build();
        assert!(check_query_in_instruction(&alice_id, &instruction, &wsv, &judge).is_err())
    }
}
