use std::sync::Arc;

use super::*;

pub type OperationJudgeBoxed<O> = Box<dyn Judge<Operation = O> + Send + Sync>;
pub type InstructionJudgeBoxed = OperationJudgeBoxed<Instruction>;
pub type QueryJudgeBoxed = OperationJudgeBoxed<QueryBox>;
pub type ExpressionJudgeBoxed = OperationJudgeBoxed<Expression>;

pub type OperationJudgeArc<O> = Arc<dyn Judge<Operation = O> + Send + Sync>;
pub type InstructionJudgeArc = OperationJudgeArc<Instruction>;
pub type QueryJudgeArc = OperationJudgeArc<QueryBox>;
pub type ExpressionJudgeArc = OperationJudgeArc<Expression>;

pub trait Judge: std::fmt::Debug {
    type Operation: NeedsPermission;

    fn judge(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason>;

    fn into_validator(self) -> JudgeAsValidator<Self::Operation, Self>
    where
        Self: Sized,
    {
        JudgeAsValidator { judge: self }
    }
}

#[derive(Debug)]
pub struct JudgeAsValidator<O: NeedsPermission, J: Judge<Operation = O>> {
    judge: J,
}

impl<O: NeedsPermission, J: Judge<Operation = O>> IsAllowed for JudgeAsValidator<O, J> {
    type Operation = O;

    fn check(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        self.judge.judge(authority, operation, wsv).into()
    }
}

#[derive(Debug)]
pub struct AtLeastOneAllow<O: NeedsPermission> {
    pub(crate) validators: Vec<IsOperationAllowedBoxed<O>>,
}

impl<O: NeedsPermission> Judge for AtLeastOneAllow<O> {
    type Operation = O;

    fn judge(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        let mut messages = Vec::new();

        for validator in &self.validators {
            match validator.check(authority, operation, wsv) {
                ValidatorVerdict::Allow => return Ok(()),
                ValidatorVerdict::Deny(reason) => {
                    messages.push(format!("Validator {validator:?} denied: {reason}"));
                }
                ValidatorVerdict::Skip => {
                    messages.push(format!("Validator {validator:?} skipped"));
                }
            }
        }

        Err(DenialReason::Custom(format!(
            "None of the validators has allowed operation {operation:?}: {messages:#?}",
        )))
    }
}

#[derive(Debug)]
pub struct NoDenies<O: NeedsPermission> {
    pub(crate) validators: Vec<IsOperationAllowedBoxed<O>>,
}

impl<O: NeedsPermission> Judge for NoDenies<O> {
    type Operation = O;

    fn judge(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        for validator in &self.validators {
            if let ValidatorVerdict::Deny(reason) = validator.check(authority, operation, wsv) {
                return Err(DenialReason::Custom(format!(
                    "Validator {validator:?} denied operation {operation:?}: {reason}"
                )));
            }
        }

        Ok(())
    }
}

/// Allows all operations to be executed for all possible values.
/// Mostly for tests and simple cases.
///
/// # Panic
/// [`AllowAll`] implements [`GetValidatorType`] to satisfy [`Judge`] bounds,
/// but calling [`GetValidatorType::get_validator_type`] will panic because
/// the exact implementation has no meaning.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct AllowAll<O: NeedsPermission> {
    #[serde(skip_serializing, default)]
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission> AllowAll<O> {
    #[inline]
    pub fn new() -> Self {
        Self {
            _phantom_operation: PhantomData,
        }
    }
}

impl<O: NeedsPermission> Judge for AllowAll<O> {
    type Operation = O;

    fn judge(
        &self,
        _authority: &AccountId,
        _operation: &Self::Operation,
        _wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        Ok(())
    }
}

/// Disallows all operations to be executed for all possible
/// values. Mostly for tests and simple cases.
///
/// # Panic
/// [`DenyAll`] implements [`GetValidatorType`] to satisfy [`Judge`] bounds,
/// but calling [`GetValidatorType::get_validator_type`] will panic because
/// the exact implementation has no meaning.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct DenyAll<O: NeedsPermission> {
    #[serde(default, skip_serializing)]
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission> DenyAll<O> {
    #[inline]
    pub fn new() -> Self {
        Self {
            _phantom_operation: PhantomData,
        }
    }
}

impl<O: NeedsPermission> Judge for DenyAll<O> {
    type Operation = O;

    fn judge(
        &self,
        _authority: &AccountId,
        _operation: &Self::Operation,
        _wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        Err("All operations are denied.".to_owned().into())
    }
}

pub mod builder {
    //! This module contains [`Judge`] builder to combine validators

    use super::{
        combinators::CheckNested,
        judge::{AtLeastOneAllow, Judge, NoDenies},
        *,
    };

    /// Builder to combine multiple validation checks into one.
    #[derive(Debug, Copy, Clone)]
    pub struct Builder;

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

    impl Builder {
        /// Returns new [`JudgeBuilderWithValidators`][WithValidators] with provided `validator`
        pub fn with_validator<
            O: NeedsPermission + 'static,
            V: IsAllowed<Operation = O> + Send + Sync + 'static,
        >(
            validator: V,
        ) -> WithValidators<O> {
            WithValidators::new(validator)
        }

        /// Returns new [`JudgeBuilderWithValidators`][WithValidators]
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
        J: Judge<Operation = Instruction>
            + IsAllowed<Operation = Instruction>
            + Send
            + Sync
            + 'static,
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
}
