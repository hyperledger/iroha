//! Module with [`IsAllowed`] trait and boxed containers

use super::*;

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
            Err(ValidatorTypeMismatch {
                expected: ValidatorType::Instruction,
                actual: self.validator_type(),
            }
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
            Err(ValidatorTypeMismatch {
                expected: ValidatorType::Query,
                actual: self.validator_type(),
            }
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
            Err(ValidatorTypeMismatch {
                expected: ValidatorType::Expression,
                actual: self.validator_type(),
            }
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
