//! Module with [`IsAllowed`] trait and boxed containers

use super::*;

/// Implement this to provide custom permission checks for the Iroha based blockchain.
pub trait IsAllowed<O: NeedsPermission>: Debug {
    /// Checks if the `authority` is allowed to perform `instruction`
    /// given the current state of `wsv`.
    ///
    /// # Errors
    /// If the execution of `instruction` under given `authority` with
    /// the current state of `wsv` is disallowed.
    fn check(&self, authority: &AccountId, operation: &O, wsv: &WorldStateView) -> Result<()>;
}

/// Box with permissions validator.
#[derive(Debug, FromVariant)]
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

impl IsAllowed<Instruction> for IsAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<()> {
        if let IsAllowedBoxed::Instruction(instruction) = self {
            instruction.check(authority, operation, wsv)
        } else {
            Err(ValidatorTypeMismatch {
                expected: ValidatorType::Instruction,
                actual: self.validator_type(),
            }
            .into())
        }
    }
}

impl IsAllowed<QueryBox> for IsAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView,
    ) -> Result<()> {
        if let IsAllowedBoxed::Query(query) = self {
            query.check(authority, operation, wsv)
        } else {
            Err(ValidatorTypeMismatch {
                expected: ValidatorType::Query,
                actual: self.validator_type(),
            }
            .into())
        }
    }
}

impl IsAllowed<Expression> for IsAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView,
    ) -> Result<()> {
        if let IsAllowedBoxed::Expression(expression) = self {
            expression.check(authority, operation, wsv)
        } else {
            Err(ValidatorTypeMismatch {
                expected: ValidatorType::Expression,
                actual: self.validator_type(),
            }
            .into())
        }
    }
}

impl<O: NeedsPermission> IsAllowed<O> for Box<dyn IsAllowed<O> + Send + Sync> {
    fn check(&self, authority: &AccountId, operation: &O, wsv: &WorldStateView) -> Result<()> {
        IsAllowed::check(self.as_ref(), authority, operation, wsv)
    }
}

/// Box with permissions validator for [`Instruction`].
pub type IsInstructionAllowedBoxed = Box<dyn IsAllowed<Instruction> + Send + Sync>;

/// Box with permissions validator for [`QueryBox`].
pub type IsQueryAllowedBoxed = Box<dyn IsAllowed<QueryBox> + Send + Sync>;

/// Box with permissions validator for [`Expression`].
pub type IsExpressionAllowedBoxed = Box<dyn IsAllowed<Expression> + Send + Sync>;
