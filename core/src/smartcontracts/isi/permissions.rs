#![allow(clippy::module_name_repetitions)]

//! This module contains permissions related Iroha functionality.

use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use iroha_data_model::{isi::RevokeBox, prelude::*};
use iroha_macro::FromVariant;
use serde::{Deserialize, Serialize};

use super::Evaluate;
#[cfg(test)]
use crate::wsv::MockWorld;
use crate::wsv::{World, WorldStateView, WorldTrait};

/// Operation for which the permission should be checked.
pub trait NeedsPermission: Debug {}

impl NeedsPermission for Instruction {}

impl NeedsPermission for QueryBox {}

// Expression might contain a query, therefore needs to be checked.
impl NeedsPermission for Expression {}

/// Type of object validator can check
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ValidatorType {
    /// [`Instruction`] variant
    Instruction,
    /// [`QueryBox`] variant
    Query,
    /// [`Expression`] variant
    Expression,
}

impl ValidatorType {
    /// Checks if `self` equals to `another`
    ///
    /// # Errors
    /// If `self` doesn't equal to `another`
    pub fn check_equal(
        self,
        another: ValidatorType,
    ) -> std::result::Result<(), ValidatorTypeMismatch> {
        if self != another {
            return Err(ValidatorTypeMismatch::expected(another).found(self));
        }

        Ok(())
    }
}

impl std::fmt::Display for ValidatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidatorType::Instruction => write!(f, "Instruction"),
            ValidatorType::Query => write!(f, "Query"),
            ValidatorType::Expression => write!(f, "Expression"),
        }
    }
}

pub mod error {
    //! Contains errors structures

    use super::ValidatorType;

    /// Reason for prohibiting the execution of the particular instruction.
    #[derive(Debug, Clone, thiserror::Error)]
    #[allow(variant_size_differences)]
    pub enum DenialReason {
        /// [`ValidatorTypeMismatch`] variant
        #[error("{0}")]
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

    /// Wrong validator expectation error
    ///
    /// I.e. used when user tries to validate [`QueryBox`](super::QueryBox) with
    /// [`IsAllowedBoxed`](super::IsAllowedBoxed) containing
    /// [`IsAllowedBoxed::Instruction`](super::IsAllowedBoxed::Instruction) variant
    #[derive(Debug, Copy, Clone, thiserror::Error)]
    #[error("Expected `{expected}` validator type, but found `{found}`")]
    pub struct ValidatorTypeMismatch {
        expected: ValidatorType,
        found: ValidatorType,
    }

    impl ValidatorTypeMismatch {
        /// Start construction of [`ValidatorTypeMismatch`] by providing *expected* type
        pub fn expected(expected: ValidatorType) -> Expected {
            Expected { expected }
        }
    }

    /// Helper struct for constructing [`ValidatorTypeMismatch`]
    #[derive(Debug, Copy, Clone)]
    pub struct Expected {
        expected: ValidatorType,
    }

    impl Expected {
        /// Finish construction of [`ValidatorTypeMismatch`] by providing *found* type
        pub fn found(self, found: ValidatorType) -> ValidatorTypeMismatch {
            ValidatorTypeMismatch {
                expected: self.expected,
                found,
            }
        }
    }
}

use error::*;

/// Result type for permission validators
pub type Result<T> = std::result::Result<T, DenialReason>;

/// Implement this to provide custom permission checks for the Iroha based blockchain.
pub trait IsAllowed<W: WorldTrait, O: NeedsPermission>:
    Debug + dyn_clone::DynClone + erased_serde::Serialize
{
    /// Checks if the `authority` is allowed to perform `instruction`
    /// given the current state of `wsv`.
    ///
    /// # Errors
    /// If the execution of `instruction` under given `authority` with
    /// the current state of `wsv` is disallowed.
    fn check(&self, authority: &AccountId, operation: &O, wsv: &WorldStateView<W>) -> Result<()>;
}

dyn_clone::clone_trait_object!(<W, O> IsAllowed<W, O> where W: WorldTrait, O: NeedsPermission);
erased_serde::serialize_trait_object!(<W, O> IsAllowed<W, O> where W: WorldTrait, O: NeedsPermission);

/// Box with permissions validator.
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum IsAllowedBoxed {
    /// [`Instruction`] validator
    Instruction(IsInstructionAllowedBoxed),
    /// [`QueryBox`] validator
    Query(IsQueryAllowedBoxed),
    /// [`Expression`] validator
    Expression(IsExpressionAllowedBoxed),
}

impl IsAllowedBoxed {
    /// Get type of validator inside [`IsAllowedBoxed`]
    pub fn validator_type(&self) -> ValidatorType {
        match self {
            IsAllowedBoxed::Instruction(_) => ValidatorType::Instruction,
            IsAllowedBoxed::Query(_) => ValidatorType::Query,
            IsAllowedBoxed::Expression(_) => ValidatorType::Expression,
        }
    }
}

impl IsAllowed<World, Instruction> for IsAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        if let IsAllowedBoxed::Instruction(instruction) = self {
            instruction.check(authority, operation, wsv)
        } else {
            Err(ValidatorTypeMismatch::expected(ValidatorType::Instruction)
                .found(self.validator_type())
                .into())
        }
    }
}

impl IsAllowed<World, QueryBox> for IsAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        if let IsAllowedBoxed::Query(query) = self {
            query.check(authority, operation, wsv)
        } else {
            Err(ValidatorTypeMismatch::expected(ValidatorType::Query)
                .found(self.validator_type())
                .into())
        }
    }
}

impl IsAllowed<World, Expression> for IsAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        if let IsAllowedBoxed::Expression(expression) = self {
            expression.check(authority, operation, wsv)
        } else {
            Err(ValidatorTypeMismatch::expected(ValidatorType::Expression)
                .found(self.validator_type())
                .into())
        }
    }
}

/// Box with permissions validator for [`Instruction`].
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum IsInstructionAllowedBoxed {
    /// Validator for [`World`]
    World(#[skip_container] Box<dyn IsAllowed<World, Instruction> + Send + Sync>),
    /// Validator for [`MockWorld`]
    #[cfg(test)]
    Mock(#[skip_container] Box<dyn IsAllowed<MockWorld, Instruction> + Send + Sync>),
}

#[allow(clippy::panic_in_result_fn, clippy::unimplemented)]
impl IsAllowed<World, Instruction> for IsInstructionAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        match self {
            IsInstructionAllowedBoxed::World(instruction) => {
                instruction.check(authority, operation, wsv)
            }
            #[cfg(test)]
            IsInstructionAllowedBoxed::Mock(_) => unimplemented!(),
        }
    }
}

/// Box with permissions validator for [`QueryBox`].
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum IsQueryAllowedBoxed {
    /// Validator for [`World`]
    World(#[skip_container] Box<dyn IsAllowed<World, QueryBox> + Send + Sync>),
    /// Validator for [`MockWorld`]
    #[cfg(test)]
    Mock(#[skip_container] Box<dyn IsAllowed<MockWorld, QueryBox> + Send + Sync>),
}

#[allow(clippy::panic_in_result_fn, clippy::unimplemented)]
impl IsAllowed<World, QueryBox> for IsQueryAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        match self {
            IsQueryAllowedBoxed::World(query) => query.check(authority, operation, wsv),
            #[cfg(test)]
            IsQueryAllowedBoxed::Mock(_) => unimplemented!(),
        }
    }
}

/// Box with permissions validator for [`Expression`].
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum IsExpressionAllowedBoxed {
    /// Validator for [`World`]
    World(#[skip_container] Box<dyn IsAllowed<World, Expression> + Send + Sync>),
    /// Validator for [`MockWorld`]
    #[cfg(test)]
    Mock(#[skip_container] Box<dyn IsAllowed<MockWorld, Expression> + Send + Sync>),
}

#[allow(clippy::panic_in_result_fn, clippy::unimplemented)]
impl IsAllowed<World, Expression> for IsExpressionAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        match self {
            IsExpressionAllowedBoxed::World(expression) => {
                expression.check(authority, operation, wsv)
            }
            #[cfg(test)]
            IsExpressionAllowedBoxed::Mock(_) => unimplemented!(),
        }
    }
}

/// Trait for joining validators with `or` method, auto-implemented
/// for all types which are convertible to something implementing [`IsAllowed`]
pub trait ValidatorApplyOr<W: WorldTrait, O: NeedsPermission, V: IsAllowed<W, O>>: Into<V> {
    /// Combines two validators into [`Or`].
    ///
    /// # Errors
    /// If validators have different types
    fn or(self, another: impl Into<V>) -> Or<W, O, V>;
}

impl<W: WorldTrait, O: NeedsPermission, V: IsAllowed<W, O>, I: Into<V>> ValidatorApplyOr<W, O, V>
    for I
{
    fn or(self, another: impl Into<V>) -> Or<W, O, V> {
        Or::new(self, another)
    }
}

/// `check` succeeds if either `first` or `second` validator succeeds.
#[derive(Debug, Clone, Serialize)]
pub struct Or<W: WorldTrait, O: NeedsPermission, V: IsAllowed<W, O>> {
    first: V,
    second: V,
    #[serde(skip_serializing, default)]
    _phantom_world: PhantomData<W>,
    #[serde(skip_serializing, default)]
    _phantom_operation: PhantomData<O>,
}

impl<W: WorldTrait, O: NeedsPermission, V: IsAllowed<W, O>> Or<W, O, V> {
    /// Constructs new [`Or`]
    ///
    /// # Errors
    /// If validators have different types
    pub fn new(first: impl Into<V>, second: impl Into<V>) -> Self {
        Or {
            first: first.into(),
            second: second.into(),
            _phantom_world: PhantomData,
            _phantom_operation: PhantomData,
        }
    }
}

impl IsAllowed<World, Instruction> for Or<World, Instruction, IsInstructionAllowedBoxed> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.first
            .check(authority, operation, wsv)
            .or_else(|first_error| {
                self.second
                    .check(authority, operation, wsv)
                    .map_err(|second_error| {
                        format!(
                            "Failed to pass first check with {} and second check with {}.",
                            first_error, second_error
                        )
                        .into()
                    })
            })
    }
}

impl From<Or<World, Instruction, IsInstructionAllowedBoxed>> for IsInstructionAllowedBoxed {
    fn from(value: Or<World, Instruction, IsInstructionAllowedBoxed>) -> Self {
        IsInstructionAllowedBoxed::World(Box::new(value))
    }
}

impl IsAllowed<World, QueryBox> for Or<World, QueryBox, IsQueryAllowedBoxed> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.first
            .check(authority, operation, wsv)
            .or_else(|first_error| {
                self.second
                    .check(authority, operation, wsv)
                    .map_err(|second_error| {
                        format!(
                            "Failed to pass first check with {} and second check with {}.",
                            first_error, second_error
                        )
                        .into()
                    })
            })
    }
}

impl From<Or<World, QueryBox, IsQueryAllowedBoxed>> for IsQueryAllowedBoxed {
    fn from(value: Or<World, QueryBox, IsQueryAllowedBoxed>) -> Self {
        IsQueryAllowedBoxed::World(Box::new(value))
    }
}

impl IsAllowed<World, Expression> for Or<World, Expression, IsExpressionAllowedBoxed> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.first
            .check(authority, operation, wsv)
            .or_else(|first_error| {
                self.second
                    .check(authority, operation, wsv)
                    .map_err(|second_error| {
                        format!(
                            "Failed to pass first check with {} and second check with {}.",
                            first_error, second_error
                        )
                        .into()
                    })
            })
    }
}

impl From<Or<World, Expression, IsExpressionAllowedBoxed>> for IsExpressionAllowedBoxed {
    fn from(value: Or<World, Expression, IsExpressionAllowedBoxed>) -> Self {
        IsExpressionAllowedBoxed::World(Box::new(value))
    }
}

/// Wraps validator to check nested permissions.  Pay attention to
/// wrap only validators that do not check nested instructions by
/// themselves.
#[derive(Debug, Clone, Serialize)]
pub struct CheckNested {
    validator: IsInstructionAllowedBoxed,
}

impl CheckNested {
    /// Wraps `validator` to check nested permissions.
    pub fn new(validator: IsInstructionAllowedBoxed) -> Self {
        CheckNested { validator }
    }
}

impl IsAllowed<World, Instruction> for CheckNested {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        match instruction {
            Instruction::Register(_)
            | Instruction::Unregister(_)
            | Instruction::Mint(_)
            | Instruction::Burn(_)
            | Instruction::SetKeyValue(_)
            | Instruction::RemoveKeyValue(_)
            | Instruction::Transfer(_)
            | Instruction::Grant(_)
            | Instruction::Revoke(_)
            | Instruction::Fail(_)
            | Instruction::ExecuteTrigger(_) => self.validator.check(authority, instruction, wsv),
            Instruction::If(if_box) => {
                self.check(authority, &if_box.then, wsv)
                    .and_then(|_| match &if_box.otherwise {
                        Some(this_instruction) => self.check(authority, this_instruction, wsv),
                        None => Ok(()),
                    })
            }
            Instruction::Pair(pair_box) => self
                .check(authority, &pair_box.left_instruction, wsv)
                .and(self.check(authority, &pair_box.right_instruction, wsv)),
            Instruction::Sequence(sequence_box) => sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| self.check(authority, this_instruction, wsv)),
        }
    }
}

/// Checks an expression recursively to evaluate if there is a query
/// inside of it and if the user has permission to execute this query.
///
/// As the function is recursive, caution should be exercised to have
/// a limit of nestedness, that would not cause stack overflow.  Up to
/// 2^13 calls were tested and are ok. This is within default
/// instruction limit.
///
/// # Errors
/// If a user is not allowed to execute one of the inner queries,
/// given the current `validator`.
fn check_query_in_expression(
    authority: &AccountId,
    expression: &Expression,
    wsv: &WorldStateView<World>,
    validator: &IsQueryAllowedBoxed,
) -> Result<()> {
    macro_rules! check_binary_expression {
        ($e:ident) => {
            check_query_in_expression(authority, &($e).left.expression, wsv, validator).and(
                check_query_in_expression(authority, &($e).right.expression, wsv, validator),
            )
        };
    }

    match expression {
        Expression::Add(expression) => check_binary_expression!(expression),
        Expression::Subtract(expression) => check_binary_expression!(expression),
        Expression::Multiply(expression) => check_binary_expression!(expression),
        Expression::Divide(expression) => check_binary_expression!(expression),
        Expression::Mod(expression) => check_binary_expression!(expression),
        Expression::RaiseTo(expression) => check_binary_expression!(expression),
        Expression::Greater(expression) => check_binary_expression!(expression),
        Expression::Less(expression) => check_binary_expression!(expression),
        Expression::Equal(expression) => check_binary_expression!(expression),
        Expression::Not(expression) => {
            check_query_in_expression(authority, &expression.expression.expression, wsv, validator)
        }
        Expression::And(expression) => check_binary_expression!(expression),
        Expression::Or(expression) => check_binary_expression!(expression),
        Expression::If(expression) => {
            check_query_in_expression(authority, &expression.condition.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.then_expression.expression,
                    wsv,
                    validator,
                ))
                .and(check_query_in_expression(
                    authority,
                    &expression.else_expression.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::Query(query) => validator.check(authority, query, wsv),
        Expression::Contains(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.element.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::ContainsAll(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.elements.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::ContainsAny(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.elements.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::Where(expression) => {
            check_query_in_expression(authority, &expression.expression.expression, wsv, validator)
        }
        Expression::ContextValue(_) | Expression::Raw(_) => Ok(()),
    }
}

/// Checks an instruction recursively to evaluate if there is a query
/// inside of it and if the user has permission to execute this query.
///
/// As the function is recursive, caution should be exercised to have
/// a limit of nesting, that would not cause stack overflow.  Up to
/// 2^13 calls were tested and are ok. This is within default
/// instruction limit.
///
/// # Errors
/// If a user is not allowed to execute one of the inner queries,
/// given the current `validator`.
#[allow(clippy::too_many_lines)]
fn check_query_in_instruction(
    authority: &AccountId,
    instruction: &Instruction,
    wsv: &WorldStateView<World>,
    validator: &IsQueryAllowedBoxed,
) -> Result<()> {
    match instruction {
        Instruction::Register(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
        }
        Instruction::Unregister(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv, validator)
        }
        Instruction::Mint(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Burn(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Transfer(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
                .and(check_query_in_expression(
                    authority,
                    &instruction.source_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::SetKeyValue(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.key.expression,
                    wsv,
                    validator,
                ))
                .and(check_query_in_expression(
                    authority,
                    &instruction.value.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::RemoveKeyValue(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.key.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Grant(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Revoke(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::If(if_box) => {
            check_query_in_instruction(authority, &if_box.then, wsv, validator).and_then(|_| {
                match &if_box.otherwise {
                    Some(this_instruction) => {
                        check_query_in_instruction(authority, this_instruction, wsv, validator)
                    }
                    None => Ok(()),
                }
            })
        }
        Instruction::Pair(pair_box) => {
            check_query_in_instruction(authority, &pair_box.left_instruction, wsv, validator).and(
                check_query_in_instruction(authority, &pair_box.right_instruction, wsv, validator),
            )
        }
        Instruction::Sequence(sequence_box) => {
            sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| {
                    check_query_in_instruction(authority, this_instruction, wsv, validator)
                })
        }
        Instruction::Fail(_) | Instruction::ExecuteTrigger(_) => Ok(()),
    }
}

fn check_all_validators_have_the_same_type(validators: &[IsAllowedBoxed]) -> Result<()> {
    let first_type = if let Some(first) = validators.first() {
        first.validator_type()
    } else {
        return Ok(());
    };

    for validator in validators.iter().skip(1) {
        let validator_type = validator.validator_type();
        if validator_type != first_type {
            return Err(ValidatorTypeMismatch::expected(first_type)
                .found(validator_type)
                .into());
        }
    }

    Ok(())
}

/// A container for multiple permissions validators. It will succeed if all validators succeed.
#[derive(Debug, Clone, Serialize)]
pub struct AllShouldSucceed {
    validators: Vec<IsAllowedBoxed>,
}

impl AllShouldSucceed {
    /// Creates new [`AllShouldSucceed`]
    ///
    /// # Errors
    /// If provided validators have different types.
    /// Type of the first element in the `validators` is considered exemplary
    pub fn new(validators: Vec<IsAllowedBoxed>) -> Result<Self> {
        check_all_validators_have_the_same_type(&validators)?;
        Ok(Self { validators })
    }

    fn check_type(&self, validator_type: ValidatorType) -> Result<()> {
        if let Ok(self_type) = self.validator_type() {
            if self_type != validator_type {
                return Err(ValidatorTypeMismatch::expected(validator_type)
                    .found(self_type)
                    .into());
            }
        }

        Ok(())
    }

    fn validator_type(&self) -> Result<ValidatorType> {
        self.validators
            .first()
            .map_or(Err(DenialReason::NoValidatorsProvided), |first| {
                Ok(first.validator_type())
            })
    }
}

impl IsAllowed<World, Instruction> for AllShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.check_type(ValidatorType::Instruction)?;

        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl IsAllowed<World, QueryBox> for AllShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.check_type(ValidatorType::Query)?;

        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl IsAllowed<World, Expression> for AllShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.check_type(ValidatorType::Expression)?;

        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl TryFrom<AllShouldSucceed> for IsAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        match value.validator_type()? {
            ValidatorType::Instruction => {
                Ok(IsInstructionAllowedBoxed::World(Box::new(value)).into())
            }
            ValidatorType::Query => Ok(IsQueryAllowedBoxed::World(Box::new(value)).into()),
            ValidatorType::Expression => {
                Ok(IsExpressionAllowedBoxed::World(Box::new(value)).into())
            }
        }
    }
}

impl TryFrom<AllShouldSucceed> for IsInstructionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        validator_type.check_equal(ValidatorType::Instruction)?;

        Ok(IsInstructionAllowedBoxed::World(Box::new(value)))
    }
}

impl TryFrom<AllShouldSucceed> for IsQueryAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        validator_type.check_equal(ValidatorType::Query)?;

        Ok(IsQueryAllowedBoxed::World(Box::new(value)))
    }
}

impl TryFrom<AllShouldSucceed> for IsExpressionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        validator_type.check_equal(ValidatorType::Expression)?;

        Ok(IsExpressionAllowedBoxed::World(Box::new(value)))
    }
}

/// A container for multiple permissions validators. It will succeed if any validator succeeds.
#[derive(Debug, Clone, Serialize)]
pub struct AnyShouldSucceed {
    name: String,
    validators: Vec<IsAllowedBoxed>,
}

impl AnyShouldSucceed {
    /// Creates new [`AnyShouldSucceed`]
    ///
    /// # Errors
    /// If provided validators have different types.
    /// Type of the first element in the `validators` is considered exemplary
    pub fn new(name: String, validators: Vec<IsAllowedBoxed>) -> Result<Self> {
        check_all_validators_have_the_same_type(&validators)?;

        Ok(Self { name, validators })
    }

    fn check_type(&self, validator_type: ValidatorType) -> Result<()> {
        if let Ok(self_type) = self.validator_type() {
            if self_type != validator_type {
                return Err(ValidatorTypeMismatch::expected(validator_type)
                    .found(self_type)
                    .into());
            }
        }

        Ok(())
    }

    fn validator_type(&self) -> Result<ValidatorType> {
        self.validators
            .first()
            .map_or(Err(DenialReason::NoValidatorsProvided), |first| {
                Ok(first.validator_type())
            })
    }
}

impl IsAllowed<World, Instruction> for AnyShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.check_type(ValidatorType::Instruction)?;

        for validator in &self.validators {
            if validator.check(authority, operation, wsv).is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "None of the instructions succeeded in Any permission check block with name: {}",
            self.name
        )
        .into())
    }
}

impl IsAllowed<World, QueryBox> for AnyShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.check_type(ValidatorType::Query)?;

        for validator in &self.validators {
            if validator.check(authority, operation, wsv).is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "None of the instructions succeeded in Any permission check block with name: {}",
            self.name
        )
        .into())
    }
}

impl IsAllowed<World, Expression> for AnyShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.check_type(ValidatorType::Expression)?;

        for validator in &self.validators {
            if validator.check(authority, operation, wsv).is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "None of the instructions succeeded in Any permission check block with name: {}",
            self.name
        )
        .into())
    }
}

impl TryFrom<AnyShouldSucceed> for IsAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        match value.validator_type()? {
            ValidatorType::Instruction => {
                Ok(IsInstructionAllowedBoxed::World(Box::new(value)).into())
            }
            ValidatorType::Query => Ok(IsQueryAllowedBoxed::World(Box::new(value)).into()),
            ValidatorType::Expression => {
                Ok(IsExpressionAllowedBoxed::World(Box::new(value)).into())
            }
        }
    }
}

impl TryFrom<AnyShouldSucceed> for IsInstructionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        validator_type.check_equal(ValidatorType::Instruction)?;

        Ok(IsInstructionAllowedBoxed::World(Box::new(value)))
    }
}

impl TryFrom<AnyShouldSucceed> for IsQueryAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        validator_type.check_equal(ValidatorType::Query)?;

        Ok(IsQueryAllowedBoxed::World(Box::new(value)))
    }
}

impl TryFrom<AnyShouldSucceed> for IsExpressionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        validator_type.check_equal(ValidatorType::Expression)?;

        Ok(IsExpressionAllowedBoxed::World(Box::new(value)))
    }
}

/// Builder to combine multiple validation checks into one.
#[derive(Debug, Copy, Clone)]
pub struct ValidatorBuilder;

/// Helper struct for [`ValidatorBuilder`].
/// Makes sure there is at least one validator and all validators have the same type
#[derive(Debug, Clone)]
#[must_use]
pub struct ValidatorBuilderWithValidators<
    O: NeedsPermission,
    V: IsAllowed<World, O> + Into<IsAllowedBoxed>,
> {
    validators: Vec<IsAllowedBoxed>,
    _phantom_operation: PhantomData<O>,
    _phantom_validator: PhantomData<V>,
}

impl ValidatorBuilder {
    /// Returns new [`ValidatorBuilderWithValidators`] with provided `validator`
    pub fn with_validator<O, V, E>(validator: impl Into<V>) -> ValidatorBuilderWithValidators<O, V>
    where
        O: NeedsPermission,
        V: IsAllowed<World, O>
            + Into<IsAllowedBoxed>
            + TryFrom<AllShouldSucceed, Error = E>
            + TryFrom<AnyShouldSucceed, Error = E>,
        E: Debug,
    {
        ValidatorBuilderWithValidators::new(validator)
    }

    /// Returns new [`ValidatorBuilderWithValidators`]
    /// with provided recursive instruction `validator`
    pub fn with_recursive_validator(
        validator: impl Into<IsInstructionAllowedBoxed>,
    ) -> ValidatorBuilderWithValidators<Instruction, IsInstructionAllowedBoxed> {
        let instruction_validator =
            IsInstructionAllowedBoxed::World(Box::new(CheckNested::new(validator.into())));
        ValidatorBuilderWithValidators::new(instruction_validator)
    }
}

#[allow(clippy::expect_used)]
impl<O, V, E> ValidatorBuilderWithValidators<O, V>
where
    O: NeedsPermission,
    V: IsAllowed<World, O>
        + Into<IsAllowedBoxed>
        + TryFrom<AllShouldSucceed, Error = E>
        + TryFrom<AnyShouldSucceed, Error = E>,
    E: Debug,
{
    fn new(validator: impl Into<V>) -> Self {
        Self {
            validators: vec![validator.into().into()],
            _phantom_operation: PhantomData,
            _phantom_validator: PhantomData,
        }
    }

    /// Adds a validator to the list.
    pub fn with_validator(mut self, validator: impl Into<V>) -> Self {
        self.validators.push(validator.into().into());
        self
    }

    /// Returns *validator* that will check all the checks of previously supplied validators.
    pub fn all_should_succeed(self) -> V {
        AllShouldSucceed::new(self.validators)
            .expect(
                "`ValidatorBuilder` guarantees that all validators have the same specified type",
            )
            .try_into()
            .expect("`ValidatorBuilder` guarantees that there is at least one validator")
    }

    /// Returns *validator* that will succeed if any of the checks of previously supplied validators succeeds.
    ///
    /// # Errors
    /// If provided validators have different types.
    /// Type of the first validators is considered exemplary
    pub fn any_should_succeed(self, check_name: impl Into<String>) -> V {
        AnyShouldSucceed::new(check_name.into(), self.validators)
            .expect(
                "`ValidatorBuilder` guarantees that all validators have the same specified type",
            )
            .try_into()
            .expect("`ValidatorBuilder` guarantees that there is at least one validator")
    }
}

impl ValidatorBuilderWithValidators<Instruction, IsInstructionAllowedBoxed> {
    /// Adds a validator to the list and wraps it with `CheckNested` to check nested permissions.
    pub fn with_recursive_validator(self, validator: impl Into<IsInstructionAllowedBoxed>) -> Self {
        let instruction_validator =
            IsInstructionAllowedBoxed::World(Box::new(CheckNested::new(validator.into())));
        self.with_validator(instruction_validator)
    }
}

/// Allows all operations to be executed for all possible values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct AllowAll;

impl AllowAll {
    /// Construct permission which allows all items
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T>() -> Arc<T>
    where
        Self: Into<T>,
    {
        Arc::new(Self.into())
    }
}

/// Disallows all operations to be executed for all possible
/// values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DenyAll;

impl DenyAll {
    /// Construct permission which denies all items
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T>() -> Arc<T>
    where
        Self: Into<T>,
    {
        Arc::new(Self.into())
    }
}

impl<W: WorldTrait, O: NeedsPermission> IsAllowed<W, O> for AllowAll {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &O,
        _wsv: &WorldStateView<W>,
    ) -> Result<()> {
        Ok(())
    }
}

impl From<AllowAll> for IsInstructionAllowedBoxed {
    fn from(value: AllowAll) -> Self {
        IsInstructionAllowedBoxed::World(Box::new(value))
    }
}

impl From<AllowAll> for IsQueryAllowedBoxed {
    fn from(value: AllowAll) -> Self {
        IsQueryAllowedBoxed::World(Box::new(value))
    }
}

impl From<AllowAll> for IsExpressionAllowedBoxed {
    fn from(value: AllowAll) -> Self {
        IsExpressionAllowedBoxed::World(Box::new(value))
    }
}

impl<W: WorldTrait, O: NeedsPermission> IsAllowed<W, O> for DenyAll {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &O,
        _wsv: &WorldStateView<W>,
    ) -> Result<()> {
        Err("All operations are denied.".to_owned().into())
    }
}

impl From<DenyAll> for IsInstructionAllowedBoxed {
    fn from(value: DenyAll) -> Self {
        IsInstructionAllowedBoxed::World(Box::new(value))
    }
}

impl From<DenyAll> for IsQueryAllowedBoxed {
    fn from(value: DenyAll) -> Self {
        IsQueryAllowedBoxed::World(Box::new(value))
    }
}

impl From<DenyAll> for IsExpressionAllowedBoxed {
    fn from(value: DenyAll) -> Self {
        IsExpressionAllowedBoxed::World(Box::new(value))
    }
}

/// Boxed validator implementing [`HasToken`] validator trait.
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum HasTokenBoxed {
    /// Validator for [`World`]
    World(#[skip_container] Box<dyn HasToken<World> + Send + Sync>),
    /// Validator for [`MockWorld`]
    #[cfg(test)]
    Mock(#[skip_container] Box<dyn HasToken<MockWorld> + Send + Sync>),
}

/// Trait that should be implemented by validator that checks the need to have permission token for a certain action.
pub trait HasToken<W: WorldTrait>: Debug + dyn_clone::DynClone + erased_serde::Serialize {
    /// This function should return the token that `authority` should
    /// possess, given the `instruction` they are planning to execute
    /// on the current state of `wsv`
    ///
    /// # Errors
    ///
    /// In the case when it is impossible to deduce the required token
    /// given current data (e.g. inexistent account or unapplicable
    /// instruction).
    fn token(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> std::result::Result<PermissionToken, String>;
}

#[allow(clippy::panic_in_result_fn, clippy::unimplemented)]
impl HasToken<World> for HasTokenBoxed {
    fn token(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> std::result::Result<PermissionToken, String> {
        match self {
            HasTokenBoxed::World(world) => world.token(authority, instruction, wsv),
            #[cfg(test)]
            HasTokenBoxed::Mock(_) => unimplemented!(),
        }
    }
}

dyn_clone::clone_trait_object!(<W> HasToken<W> where W: WorldTrait);
erased_serde::serialize_trait_object!(<W> HasToken<W> where W: WorldTrait);

impl IsAllowed<World, Instruction> for HasTokenBoxed {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        let permission_token = self
            .token(authority, instruction, wsv)
            .map_err(|err| format!("Unable to identify corresponding permission token: {}", err))?;
        let contain = wsv
            .map_account(authority, |account| {
                account.contains_permission(&permission_token)
            })
            .map_err(|e| e.to_string())?;
        if contain {
            Ok(())
        } else {
            Err(format!(
                "Account does not have the needed permission token: {:?}.",
                permission_token
            )
            .into())
        }
    }
}

// TODO: rewrite when specialization reaches stable
// Currently we simply can't do the following:
// impl <T: IsGrantAllowed> PermissionsValidator for T {}
// when we have
// impl <T: HasToken> PermissionsValidator for T {}
/// Boxed validator implementing [`IsGrantAllowed`] trait.
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum IsGrantAllowedBoxed {
    /// Validator for [`World`]
    World(#[skip_container] Box<dyn IsGrantAllowed<World> + Send + Sync>),
    /// Validator for [`MockWorld`]
    #[cfg(test)]
    Mock(#[skip_container] Box<dyn IsGrantAllowed<MockWorld> + Send + Sync>),
}

/// Checks the [`GrantBox`] instruction.
pub trait IsGrantAllowed<W: WorldTrait>:
    Debug + dyn_clone::DynClone + erased_serde::Serialize
{
    /// Checks the [`GrantBox`] instruction.
    ///
    /// # Errors
    /// If this validator doesn't approve this Grant instruction.
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<()>;
}

dyn_clone::clone_trait_object!(<W> IsGrantAllowed<W> where W: WorldTrait);
erased_serde::serialize_trait_object!(<W> IsGrantAllowed<W> where W: WorldTrait);

#[allow(clippy::panic_in_result_fn, clippy::unimplemented)]
impl IsGrantAllowed<World> for IsGrantAllowedBoxed {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        match self {
            IsGrantAllowedBoxed::World(world) => world.check_grant(authority, instruction, wsv),
            #[cfg(test)]
            IsGrantAllowedBoxed::Mock(_) => unimplemented!(),
        }
    }
}

/// Boxed validator implementing the [`IsRevokeAllowed`] trait.
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum IsRevokeAllowedBoxed {
    /// Validator for [`World`]
    World(#[skip_container] Box<dyn IsRevokeAllowed<World> + Send + Sync>),
    /// Validator for [`MockWorld`]
    #[cfg(test)]
    Mock(#[skip_container] Box<dyn IsRevokeAllowed<MockWorld> + Send + Sync>),
}

/// Checks the [`RevokeBox`] instruction.
pub trait IsRevokeAllowed<W: WorldTrait>:
    Debug + dyn_clone::DynClone + erased_serde::Serialize
{
    /// Checks the [`RevokeBox`] instruction.
    ///
    /// # Errors
    /// If this validator doesn't approve this Revoke instruction.
    fn check_revoke(
        &self,
        authority: &AccountId,
        instruction: &RevokeBox,
        wsv: &WorldStateView<W>,
    ) -> Result<()>;
}

dyn_clone::clone_trait_object!(<W> IsRevokeAllowed<W> where W: WorldTrait);
erased_serde::serialize_trait_object!(<W> IsRevokeAllowed<W> where W: WorldTrait);

#[allow(clippy::panic_in_result_fn, clippy::unimplemented)]
impl IsRevokeAllowed<World> for IsRevokeAllowedBoxed {
    fn check_revoke(
        &self,
        authority: &AccountId,
        instruction: &RevokeBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        match self {
            IsRevokeAllowedBoxed::World(world) => world.check_revoke(authority, instruction, wsv),
            #[cfg(test)]
            IsRevokeAllowedBoxed::Mock(_) => unimplemented!(),
        }
    }
}

impl IsAllowed<World, Instruction> for IsGrantAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        if let Instruction::Grant(isi) = instruction {
            self.check_grant(authority, isi, wsv)
        } else {
            Ok(())
        }
    }
}

impl IsAllowed<World, Instruction> for IsRevokeAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        if let Instruction::Revoke(isi) = instruction {
            self.check_revoke(authority, isi, wsv)
        } else {
            Ok(())
        }
    }
}

/// Unpacks instruction if it is Grant of a Role into several Grants
/// fo Permission Token.  If instruction is not Grant of Role, returns
/// it as inly instruction inside the vec.  Should be called before
/// permission checks by validators.
///
/// Semantically means that user can grant a role only if they can
/// grant each of the permission tokens that the role consists of.
///
/// # Errors
/// Evaluation failure of instruction fields.
fn unpack_if_role_grant<W: WorldTrait>(
    instruction: Instruction,
    wsv: &WorldStateView<W>,
) -> eyre::Result<Vec<Instruction>> {
    let grant = if let Instruction::Grant(grant) = &instruction {
        grant
    } else {
        return Ok(vec![instruction]);
    };
    let id = if let Value::Id(IdBox::RoleId(id)) = grant.object.evaluate(wsv, &Context::new())? {
        id
    } else {
        return Ok(vec![instruction]);
    };

    let instructions = if let Some(role) = wsv.world.roles.get(&id) {
        let destination_id = grant.destination_id.evaluate(wsv, &Context::new())?;
        role.permissions()
            .cloned()
            .map(|permission_token| GrantBox::new(permission_token, destination_id.clone()).into())
            .collect()
    } else {
        Vec::new()
    };
    Ok(instructions)
}

/// Unpack instruction if it is a Revoke of a Role, into several
/// Revocations of Permission Tokens. If the instruction is not a
/// Revoke of Role, returns it as an internal instruction inside the
/// vec.
///
/// This `fn` should be called before permission checks (by
/// validators).
///
/// Semantically: the user can revoke a role only if they can revoke
/// each of the permission tokens that the role consists of of.
///
/// # Errors
/// Evaluation failure of each of the instruction fields.
pub fn unpack_if_role_revoke<W: WorldTrait>(
    instruction: Instruction,
    wsv: &WorldStateView<W>,
) -> eyre::Result<Vec<Instruction>> {
    let revoke = if let Instruction::Revoke(revoke) = &instruction {
        revoke
    } else {
        return Ok(vec![instruction]);
    };
    let id = if let Value::Id(IdBox::RoleId(id)) = revoke.object.evaluate(wsv, &Context::new())? {
        id
    } else {
        return Ok(vec![instruction]);
    };

    let instructions = if let Some(role) = wsv.world.roles.get(&id) {
        let destination_id = revoke.destination_id.evaluate(wsv, &Context::new())?;
        role.permissions()
            .cloned()
            .map(|permission_token| RevokeBox::new(permission_token, destination_id.clone()).into())
            .collect()
    } else {
        Vec::new()
    };
    Ok(instructions)
}

/// Verify that the given instruction is allowed to execute
///
/// # Errors
///
/// If given instruction is not permitted to execute
#[allow(clippy::expect_used)]
pub fn check_instruction_permissions(
    account_id: &AccountId,
    instruction: &Instruction,
    is_instruction_allowed: &IsInstructionAllowedBoxed,
    is_query_allowed: &IsQueryAllowedBoxed,
    wsv: &WorldStateView<World>,
) -> std::result::Result<(), TransactionRejectionReason> {
    let granted_instructions = &unpack_if_role_grant(instruction.clone(), wsv)
        .expect("Infallible. Evaluations have been checked by instruction execution.");

    for isi in granted_instructions {
        is_instruction_allowed
            .check(account_id, isi, wsv)
            .map_err(|reason| NotPermittedFail {
                reason: reason.to_string(),
            })
            .map_err(TransactionRejectionReason::NotPermitted)?;
    }
    check_query_in_instruction(account_id, instruction, wsv, is_query_allowed)
        .map_err(|reason| NotPermittedFail {
            reason: reason.to_string(),
        })
        .map_err(TransactionRejectionReason::NotPermitted)?;

    Ok(())
}

pub mod prelude {
    //! Exports common types for permissions.

    pub use super::{
        error::DenialReason, AllowAll, HasTokenBoxed, IsAllowedBoxed, IsGrantAllowed,
        IsGrantAllowedBoxed, IsRevokeAllowed, IsRevokeAllowedBoxed,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{collections::BTreeSet, str::FromStr as _};

    use iroha_data_model::{expression::prelude::*, isi::*};

    use super::*;
    use crate::wsv::World;

    #[derive(Debug, Clone, Serialize)]
    struct DenyBurn;

    impl From<DenyBurn> for IsInstructionAllowedBoxed {
        fn from(permissions: DenyBurn) -> Self {
            IsInstructionAllowedBoxed::World(Box::new(permissions))
        }
    }

    impl<W: WorldTrait> IsAllowed<W, Instruction> for DenyBurn {
        fn check(
            &self,
            _authority: &AccountId,
            instruction: &Instruction,
            _wsv: &WorldStateView<W>,
        ) -> Result<()> {
            match instruction {
                Instruction::Burn(_) => Err("Denying sequence isi.".to_owned().into()),
                _ => Ok(()),
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    struct DenyAlice;

    impl<W: WorldTrait> IsAllowed<W, Instruction> for DenyAlice {
        fn check(
            &self,
            authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView<W>,
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
            IsInstructionAllowedBoxed::World(Box::new(value))
        }
    }

    #[derive(Debug, Clone, Serialize)]
    struct GrantedToken;

    // TODO: ADD some Revoke tests.

    impl<W: WorldTrait> HasToken<W> for GrantedToken {
        fn token(
            &self,
            _authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView<W>,
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
                .all_should_succeed();
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
        let permissions_validator =
            ValidatorBuilder::with_recursive_validator(DenyBurn).all_should_succeed();
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
        let validator = HasTokenBoxed::World(Box::new(GrantedToken));
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
