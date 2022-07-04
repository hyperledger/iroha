//! Module with [`IsAllowed`] trait and boxed containers

use super::*;

/// Implement this to provide custom permission checks for the Iroha based blockchain.
pub trait IsAllowed: Debug {
    type Operation: NeedsPermission;

    /// Checks if the `authority` is allowed to perform `instruction`
    /// given the current state of `wsv`.
    ///
    /// # Denial reasons
    /// If the execution of `instruction` under given `authority` with
    /// the current state of `wsv` is disallowed.
    fn check(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict;
}

/// Box with permissions validator.
///
/// # Panics
///
/// If you try to call [`IsAllowed::check`] with wrong type of `operation` it will panic.
///
/// It's a programmer responsibility to control data flow such way that it's impossible to run
/// validation with incompatible types. Using *validator* of one type to check `operation` of
/// another type can't be legal behaviour and should be tracked as soon as possible.
///
/// This error can't be resolved at compile time because that will require to introduce generics
/// which would be a big problem for *validator* deserialization.
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
    pub fn validator_type(&self) -> ValidatorType {
        match self {
            IsAllowedBoxed::Instruction(_) => ValidatorType::Instruction,
            IsAllowedBoxed::Query(_) => ValidatorType::Query,
            IsAllowedBoxed::Expression(_) => ValidatorType::Expression,
        }
    }
}

impl IsAllowed for IsAllowedBoxed {
    type Operation = NeedsPermissionBox;

    fn check(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        match (self, operation) {
            (
                IsAllowedBoxed::Instruction(validator),
                NeedsPermissionBox::Instruction(instruction),
            ) => validator.check(authority, instruction, wsv),
            (IsAllowedBoxed::Query(validator), NeedsPermissionBox::Query(query)) => {
                validator.check(authority, query, wsv)
            }
            (IsAllowedBoxed::Expression(validator), NeedsPermissionBox::Expression(expression)) => {
                validator.check(authority, expression, wsv)
            }
            // Technically we can return `ValidatorVerdict::Skip` or
            // `ValidatorVerdict::Deny` here, but error of that kind is
            // probably a programmer error, so we want to know about it as soon
            // as possible
            _ => panic!(
                "Validator type mismatch: expected {}, got {}",
                operation.required_validator_type(),
                self.validator_type()
            ),
        }
    }
}

/// Box with permissions validator for generic operation
pub type IsOperationAllowedBoxed<O> = Box<dyn IsAllowed<Operation = O> + Send + Sync>;

/// Box with permissions validator for [`Instruction`].
pub type IsInstructionAllowedBoxed = IsOperationAllowedBoxed<Instruction>;

/// Box with permissions validator for [`QueryBox`].
pub type IsQueryAllowedBoxed = IsOperationAllowedBoxed<QueryBox>;

/// Box with permissions validator for [`Expression`].
pub type IsExpressionAllowedBoxed = IsOperationAllowedBoxed<Expression>;
