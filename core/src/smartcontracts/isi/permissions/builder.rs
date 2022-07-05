//! This module contains validator builder to construct complex validator

use super::{
    combinators::CheckNested,
    judge::{AtLeastOneAllow, Judge, NoDenies},
    *,
};

/// Builder to combine multiple validation checks into one.
#[derive(Debug, Copy, Clone)]
pub struct Validator;

/// Helper struct for [`Validator`].
/// Makes sure there is at least one validator and all validators have the same type
#[derive(Debug)]
#[must_use]
pub struct WithValidators<O: NeedsPermission> {
    validators: Vec<IsOperationAllowedBoxed<O>>,
    _phantom_operation: PhantomData<O>,
}

/// Helper struct for [`Validator`].
/// Contains final [`build()`][ShouldSucceedValidator::build()] step
#[derive(Debug, Clone)]
#[must_use]
pub struct WithJudge<O: NeedsPermission, J: Judge<Operation = O>> {
    judge: J,
    _phantom_operation: PhantomData<O>,
}

impl Validator {
    /// Returns new [`ValidatorBuilderWithValidators`][WithValidators] with provided `validator`
    pub fn with_validator<
        O: NeedsPermission + 'static,
        V: IsAllowed<Operation = O> + Send + Sync + 'static,
    >(
        validator: V,
    ) -> WithValidators<O> {
        WithValidators::new(validator)
    }

    /// Returns new [`ValidatorBuilderWithValidators`][WithValidators]
    /// with provided recursive instruction `validator`
    pub fn with_recursive_validator<
        V: IsAllowed<Operation = Instruction> + Send + Sync + 'static,
    >(
        validator: V,
    ) -> WithValidators<Instruction> {
        let nested_validator = CheckNested::new(Box::new(validator));
        WithValidators::new(nested_validator)
    }
}

impl<O: NeedsPermission + 'static> WithValidators<O> {
    fn new<V: IsAllowed<Operation = O> + Send + Sync + 'static>(validator: V) -> Self {
        Self {
            validators: vec![Box::new(validator)],
            _phantom_operation: PhantomData,
        }
    }

    /// Adds a validator to the list.
    pub fn with_validator<V: IsAllowed<Operation = O> + Send + Sync + 'static>(
        mut self,
        validator: V,
    ) -> Self {
        self.validators.push(Box::new(validator));
        self
    }

    /// Returns [`AtLeastOneAllow`] *judge* builder
    pub fn at_least_one_allow(self) -> WithJudge<O, AtLeastOneAllow<O>> {
        let at_least_one_allow = AtLeastOneAllow {
            validators: self.validators,
        };
        WithJudge::new(at_least_one_allow)
    }

    /// Returns [`NoDenies`] *judge* builder
    pub fn no_denies(self) -> WithJudge<O, NoDenies<O>> {
        let no_denies = NoDenies {
            validators: self.validators,
        };

        WithJudge::new(no_denies)
    }
}

impl WithValidators<Instruction> {
    /// Adds a validator to the list and wraps it with `CheckNested` to check nested permissions.
    pub fn with_recursive_validator<
        V: IsAllowed<Operation = Instruction> + Send + Sync + 'static,
    >(
        self,
        validator: V,
    ) -> Self {
        let nested_validator = CheckNested::new(Box::new(validator));
        self.with_validator(nested_validator)
    }
}

impl<O, J> WithJudge<O, J>
where
    O: NeedsPermission,
    J: Judge<Operation = O> + Sync + Send + 'static,
{
    #[inline]
    fn new(judge: J) -> Self {
        Self {
            judge,
            _phantom_operation: PhantomData,
        }
    }

    /// Builds *judge*
    #[inline]
    pub fn build(self) -> J {
        self.judge
    }
}

impl<O, J> WithJudge<O, J>
where
    O: NeedsPermission + Clone + Into<NeedsPermissionBox> + Send + Sync + 'static,
    J: Judge<Operation = O> + IsAllowed<Operation = O> + Send + Sync + 'static,
{
    /// Adds a validator to the list.
    #[inline]
    pub fn with_validator<V: IsAllowed<Operation = O> + Send + Sync + 'static>(
        self,
        validator: V,
    ) -> WithValidators<O> {
        WithValidators::new(self.judge).with_validator(validator)
    }
}

impl<J> WithJudge<Instruction, J>
where
    J: Judge<Operation = Instruction> + IsAllowed<Operation = Instruction> + Send + Sync + 'static,
{
    /// Adds a validator to the list and wraps it with `CheckNested` to check nested permissions.
    #[inline]
    pub fn with_recursive_validator<
        V: IsAllowed<Operation = Instruction> + Send + Sync + 'static,
    >(
        self,
        validator: V,
    ) -> WithValidators<Instruction> {
        WithValidators::new(self.judge).with_recursive_validator(validator)
    }
}

impl<O> WithJudge<O, AtLeastOneAllow<O>>
where
    O: NeedsPermission + 'static,
{
    pub fn no_denies(self) -> WithJudge<O, NoDenies<O>> {
        let no_denies = NoDenies {
            validators: vec![(Box::new(self.judge.into_validator()))],
        };
        WithJudge::new(no_denies)
    }
}

impl<O> WithJudge<O, NoDenies<O>>
where
    O: NeedsPermission + 'static,
{
    pub fn at_least_one_allow(self) -> WithJudge<O, AtLeastOneAllow<O>> {
        let at_least_one_allow = AtLeastOneAllow {
            validators: vec![(Box::new(self.judge.into_validator()))],
        };
        WithJudge::new(at_least_one_allow)
    }
}
