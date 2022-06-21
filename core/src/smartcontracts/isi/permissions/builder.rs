//! This module contains validator builder to construct complex validator

use super::{
    combinators::{AllShouldSucceed, AnyShouldSucceed, CheckNested},
    *,
};

/// Builder to combine multiple validation checks into one.
#[derive(Debug, Copy, Clone)]
pub struct Validator;

/// Helper struct for [`Validator`].
/// Makes sure there is at least one validator and all validators have the same type
#[derive(Debug)]
#[must_use]
pub struct WithValidators<O: NeedsPermission, V: IsAllowed<O> + Into<IsAllowedBoxed>> {
    validators: Vec<IsAllowedBoxed>,
    _phantom_operation: PhantomData<O>,
    _phantom_validator: PhantomData<V>,
}

/// Helper struct for [`Validator`].
/// Contains final [`build()`][ShouldSucceedValidator::build()] step
#[derive(Debug, Clone)]
#[must_use]
pub struct ShouldSucceedValidator<
    O: NeedsPermission,
    V: IsAllowed<O> + Into<IsAllowedBoxed>,
    S: TryInto<V>,
> {
    should_succeed: S,
    _phantom_operation: PhantomData<O>,
    _phantom_validator: PhantomData<V>,
}

impl Validator {
    /// Returns new [`ValidatorBuilderWithValidators`][WithValidators] with provided `validator`
    pub fn with_validator<O, V, E>(validator: impl Into<V>) -> WithValidators<O, V>
    where
        O: NeedsPermission,
        V: IsAllowed<O>
            + Into<IsAllowedBoxed>
            + TryFrom<AllShouldSucceed, Error = E>
            + TryFrom<AnyShouldSucceed, Error = E>,
        E: Debug,
    {
        WithValidators::new(validator)
    }

    /// Returns new [`ValidatorBuilderWithValidators`][WithValidators]
    /// with provided recursive instruction `validator`
    pub fn with_recursive_validator(
        validator: impl Into<IsInstructionAllowedBoxed>,
    ) -> WithValidators<Instruction, IsInstructionAllowedBoxed> {
        let instruction_validator: IsInstructionAllowedBoxed =
            Box::new(CheckNested::new(validator.into()));
        WithValidators::new(instruction_validator)
    }
}

#[allow(clippy::expect_used)]
impl<O, V, E> WithValidators<O, V>
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

    /// Returns [`AllShouldSucceed`] *validator* builder
    pub fn all_should_succeed(self) -> ShouldSucceedValidator<O, V, AllShouldSucceed> {
        let all_should_succeed = AllShouldSucceed::new(self.validators).expect(
            "`ValidatorBuilder` guarantees that all validators have the same specified type",
        );
        ShouldSucceedValidator::new(all_should_succeed)
    }

    /// Returns [`AnyShouldSucceed`] *validator* builder
    pub fn any_should_succeed(
        self,
        check_name: String,
    ) -> ShouldSucceedValidator<O, V, AnyShouldSucceed> {
        let any_should_succeed = AnyShouldSucceed::new(check_name, self.validators).expect(
            "`ValidatorBuilder` guarantees that all validators have the same specified type",
        );

        ShouldSucceedValidator::new(any_should_succeed)
    }
}

impl WithValidators<Instruction, IsInstructionAllowedBoxed> {
    /// Adds a validator to the list and wraps it with `CheckNested` to check nested permissions.
    pub fn with_recursive_validator(self, validator: impl Into<IsInstructionAllowedBoxed>) -> Self {
        let instruction_validator: IsInstructionAllowedBoxed =
            Box::new(CheckNested::new(validator.into()));
        self.with_validator(instruction_validator)
    }
}

#[allow(clippy::expect_used)]
impl<O, V, S, E> ShouldSucceedValidator<O, V, S>
where
    O: NeedsPermission,
    V: IsAllowed<O> + Into<IsAllowedBoxed> + TryFrom<S, Error = E>,
    E: Debug,
{
    fn new(should_succeed: S) -> Self {
        Self {
            should_succeed,
            _phantom_operation: PhantomData,
            _phantom_validator: PhantomData,
        }
    }

    /// Builds *validator*
    pub fn build(self) -> V {
        self.should_succeed
            .try_into()
            .expect("`ValidatorBuilder` guarantees that there is at least one validator")
    }
}
