//! This module contains validator builder to construct complex validator

use super::{
    combinators::CheckNested,
    judge::{AtLeastOneAllow, Judge, JudgeBox, NoDenies},
    *,
};

/// Builder to combine multiple validation checks into one.
#[derive(Debug, Copy, Clone)]
pub struct Validator;

/// Helper struct for [`Validator`].
/// Makes sure there is at least one validator and all validators have the same type
#[derive(Debug)]
#[must_use]
pub struct WithValidators<O: NeedsPermission, V: Into<IsAllowedBoxed>> {
    validators: Vec<IsAllowedBoxed>,
    _phantom_operation: PhantomData<O>,
    _phantom_validator: PhantomData<V>,
}

/// Helper struct for [`Validator`].
/// Contains final [`build()`][ShouldSucceedValidator::build()] step
#[derive(Debug, Clone)]
#[must_use]
pub struct WithJudge<O: NeedsPermission, V: Into<IsAllowedBoxed>, J: Judge> {
    judge: J,
    _phantom_operation: PhantomData<O>,
    _phantom_validator: PhantomData<V>,
}

impl Validator {
    /// Returns new [`ValidatorBuilderWithValidators`][WithValidators] with provided `validator`
    pub fn with_validator<O>(
        validator: Box<impl IsAllowed<Operation = O> + Send + Sync + 'static>,
    ) -> WithValidators<O, IsOperationAllowedBoxed<O>>
    where
        O: NeedsPermission,
        IsOperationAllowedBoxed<O>: Into<IsAllowedBoxed>,
    {
        WithValidators::new(validator as IsOperationAllowedBoxed<O>)
    }

    /// Returns new [`ValidatorBuilderWithValidators`][WithValidators]
    /// with provided recursive instruction `validator`
    pub fn with_recursive_validator(
        validator: IsInstructionAllowedBoxed,
    ) -> WithValidators<Instruction, IsInstructionAllowedBoxed> {
        let instruction_validator: IsInstructionAllowedBoxed =
            Box::new(CheckNested::new(validator.into()));
        WithValidators::new(instruction_validator)
    }
}

impl<O, V> WithValidators<O, V>
where
    O: NeedsPermission,
    V: Into<IsAllowedBoxed>,
{
    fn new(validator: V) -> Self {
        Self {
            validators: vec![validator.into()],
            _phantom_operation: PhantomData,
            _phantom_validator: PhantomData,
        }
    }

    /// Adds a validator to the list.
    pub fn with_validator(mut self, validator: V) -> Self {
        self.validators.push(validator.into());
        self
    }

    /// Returns [`AtLeastOneAllow`] *judge* builder
    pub fn at_least_one_allow(self) -> WithJudge<O, V, AtLeastOneAllow> {
        let at_least_one_allow = AtLeastOneAllow {
            validators: self.validators,
        };
        WithJudge::new(at_least_one_allow)
    }

    /// Returns [`NoDenies`] *judge* builder
    pub fn no_denies(self) -> WithJudge<O, V, NoDenies> {
        let no_denies = NoDenies {
            validators: self.validators,
        };

        WithJudge::new(no_denies)
    }
}

impl WithValidators<Instruction, IsInstructionAllowedBoxed> {
    /// Adds a validator to the list and wraps it with `CheckNested` to check nested permissions.
    pub fn with_recursive_validator(self, validator: IsInstructionAllowedBoxed) -> Self {
        let instruction_validator: IsInstructionAllowedBoxed =
            Box::new(CheckNested::new(validator.into()));
        self.with_validator(instruction_validator)
    }
}

impl<O, V, J> WithJudge<O, V, J>
where
    O: NeedsPermission,
    V: Into<IsAllowedBoxed>,
    J: Judge + Sync + Send + 'static,
{
    #[inline]
    fn new(judge: J) -> Self {
        Self {
            judge,
            _phantom_operation: PhantomData,
            _phantom_validator: PhantomData,
        }
    }

    /// Builds *judge*
    #[inline]
    pub fn build(self) -> JudgeBox {
        Box::new(self.judge)
    }
}

impl<O, J> WithJudge<O, IsOperationAllowedBoxed<O>, J>
where
    O: NeedsPermission + Clone + Into<NeedsPermissionBox> + Send + Sync + 'static,
    J: Judge + IsAllowed<Operation = NeedsPermissionBox> + Send + Sync + 'static,
    IsOperationAllowedBoxed<O>: Into<IsAllowedBoxed>,
{
    /// Adds a validator to the list.
    #[inline]
    pub fn with_validator(
        self,
        validator: IsOperationAllowedBoxed<O>,
    ) -> WithValidators<O, IsOperationAllowedBoxed<O>> {
        let proxy = Box::new(judge::proxy::IsAllowed::new(self.judge));
        WithValidators::new(proxy as IsOperationAllowedBoxed<O>).with_validator(validator)
    }
}

impl<J> WithJudge<Instruction, IsInstructionAllowedBoxed, J>
where
    J: Judge + IsAllowed<Operation = Instruction> + Send + Sync + 'static,
{
    /// Adds a validator to the list and wraps it with `CheckNested` to check nested permissions.
    #[inline]
    pub fn with_recursive_validator(
        self,
        validator: IsInstructionAllowedBoxed,
    ) -> WithValidators<Instruction, IsInstructionAllowedBoxed> {
        let proxy = Box::new(judge::proxy::IsAllowed::new(self.judge));
        WithValidators::new(proxy as IsInstructionAllowedBoxed).with_recursive_validator(validator)
    }
}

impl<O, V> WithJudge<O, V, AtLeastOneAllow>
where
    O: NeedsPermission + Clone + Into<NeedsPermissionBox> + 'static,
    V: Into<IsAllowedBoxed>,
    IsAllowedBoxed: From<Box<dyn IsAllowed<Operation = O>>>,
{
    pub fn no_denies(self) -> WithJudge<O, V, NoDenies> {
        let proxy = Box::new(judge::proxy::IsAllowed::new(self.judge));
        let no_denies = NoDenies {
            validators: vec![(proxy as Box<dyn IsAllowed<Operation = O>>).into()],
        };
        WithJudge::new(no_denies)
    }
}

impl<O, V> WithJudge<O, V, NoDenies>
where
    O: NeedsPermission + Clone + Into<NeedsPermissionBox> + 'static,
    V: Into<IsAllowedBoxed>,
    IsAllowedBoxed: From<Box<dyn IsAllowed<Operation = O>>>,
{
    pub fn at_least_one_allow(self) -> WithJudge<O, V, AtLeastOneAllow> {
        let proxy = Box::new(judge::proxy::IsAllowed::new(self.judge));
        let at_least_one_allow = AtLeastOneAllow {
            validators: vec![(proxy as Box<dyn IsAllowed<Operation = O>>).into()],
        };
        WithJudge::new(at_least_one_allow)
    }
}
