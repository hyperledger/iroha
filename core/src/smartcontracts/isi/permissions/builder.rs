//! This module contains validator builder to construct complex validator

use super::{
    combinators::{AllShouldSucceed, AnyShouldSucceed, CheckNested},
    *,
};

/// Builder to combine multiple validation checks into one.
#[derive(Debug, Copy, Clone)]
pub struct ValidatorBuilder;

/// Helper struct for [`ValidatorBuilder`].
/// Makes sure there is at least one validator and all validators have the same type
#[derive(Debug, Clone)]
#[must_use]
pub struct ValidatorBuilderWithValidators<
    O: NeedsPermission,
    V: IsAllowed<O> + Into<IsAllowedBoxed>,
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
        V: IsAllowed<O>
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
        let instruction_validator: IsInstructionAllowedBoxed =
            Box::new(CheckNested::new(validator.into()));
        ValidatorBuilderWithValidators::new(instruction_validator)
    }
}

#[allow(clippy::expect_used)]
impl<O, V, E> ValidatorBuilderWithValidators<O, V>
where
    O: NeedsPermission,
    V: IsAllowed<O>
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
    pub fn any_should_succeed(self, check_name: String) -> V {
        AnyShouldSucceed::new(check_name, self.validators)
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
        let instruction_validator: IsInstructionAllowedBoxed =
            Box::new(CheckNested::new(validator.into()));
        self.with_validator(instruction_validator)
    }
}
