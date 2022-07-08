//! Module with [`Judge`] trait and its implementations

use std::sync::Arc;

use super::*;

/// Boxed generic judge
pub type OperationJudgeBoxed<O> = Box<dyn Judge<Operation = O> + Send + Sync>;
/// Boxed [`Instruction`] judge
pub type InstructionJudgeBoxed = OperationJudgeBoxed<Instruction>;
/// Boxed [`QueryBox`] judge
pub type QueryJudgeBoxed = OperationJudgeBoxed<QueryBox>;
/// Boxed [`Expression`] judge
pub type ExpressionJudgeBoxed = OperationJudgeBoxed<Expression>;

/// [`Arc`] with generic judge
pub type OperationJudgeArc<O> = Arc<dyn Judge<Operation = O> + Send + Sync>;
/// [`Arc`] with [`Instruction`] judge
pub type InstructionJudgeArc = OperationJudgeArc<Instruction>;
/// [`Arc`] with [`QueryBox`] judge
pub type QueryJudgeArc = OperationJudgeArc<QueryBox>;
/// [`Arc`] with [`Expression`] judge
pub type ExpressionJudgeArc = OperationJudgeArc<Expression>;

/// The judge that gives the final decision
/// whether or not the `operation` should be accepted.
///
/// Unlike [`IsAllowed`], this trait requires the [`Result`] to be returned.
///
/// The judge accumulates [`verdicts`](ValidatorVerdict) from all validators,
/// makes a decision, and returns the result.
pub trait Judge {
    /// Type of operation to be checked
    type Operation: NeedsPermission;

    /// Check if `operation` is allowed for `authority`
    ///
    /// # Errors
    ///
    /// Returns an error if `operation` is not permitted
    fn judge(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> Result<()>;

    /// Convert this object to a type implementing [`IsAllowed`] trait
    ///
    /// Could not use `impl<O: NeedsPermission, J: Judge<Operation = O>> IsAllowed for J`
    /// because of conflicting trait implementations
    fn into_validator(self) -> JudgeAsValidator<Self::Operation, Self>
    where
        Self: Sized,
    {
        JudgeAsValidator { judge: self }
    }
}

/// Wrapper for types implementing [`Judge`]
///
/// Implements [`IsAllowed`] trait so that
/// it's possible to use it in [`JudgeBuilder`](super::judge::builder::Builder)
#[derive(Debug)]
pub struct JudgeAsValidator<O: NeedsPermission, J: Judge<Operation = O>> {
    judge: J,
}

impl<O: NeedsPermission, J: Judge<Operation = O> + std::fmt::Debug> IsAllowed
    for JudgeAsValidator<O, J>
{
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

/// The judge that succeeds only if there is at least one
/// [`Allow`](ValidatorVerdict::Allow) verdict from the contained validators.
///
/// Stops on first successful verdict.
///
/// Provides detailed message as [`DenialReason`] if none of the validators
/// returned [`Allow`](ValidatorVerdict::Allow) verdict.
#[derive(Debug)]
pub struct AtLeastOneAllow<O: NeedsPermission> {
    validators: Vec<IsOperationAllowedBoxed<O>>,
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

        Err(format!(
            "None of the validators has allowed operation {operation:?}: {messages:#?}",
        ))
    }
}

/// The judge that succeeds only if there is no
/// [`Deny`](ValidatorVerdict::Deny) verdict from the contained validators.
///
/// Iterates over all validators.
#[derive(Debug)]
pub struct NoDenies<O: NeedsPermission> {
    validators: Vec<IsOperationAllowedBoxed<O>>,
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
                return Err(format!(
                    "Validator {validator:?} denied operation {operation:?}: {reason}"
                ));
            }
        }

        Ok(())
    }
}

/// The judge that succeeds only if there is no
/// [`Deny`](ValidatorVerdict::Deny) verdict and there is at least one
/// [`Allow`](ValidatorVerdict::Allow) verdict from the contained validators.
///
/// Iterates over all validators until first `Deny` is found or
/// all validators are checked.
#[derive(Debug)]
pub struct NoDeniesAndAtLeastOneAllow<O: NeedsPermission> {
    validators: Vec<IsOperationAllowedBoxed<O>>,
}

impl<O: NeedsPermission> Judge for NoDeniesAndAtLeastOneAllow<O> {
    type Operation = O;

    fn judge(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        let mut messages = Vec::new();
        let mut allowed = false;

        for validator in &self.validators {
            match validator.check(authority, operation, wsv) {
                ValidatorVerdict::Allow => allowed = true,
                ValidatorVerdict::Deny(reason) => {
                    return Err(format!(
                        "Validator {validator:?} denied operation {operation:?}: {reason}"
                    ));
                }
                ValidatorVerdict::Skip => {
                    messages.push(format!("Validator {validator:?} skipped"));
                }
            }
        }

        if allowed {
            Ok(())
        } else {
            Err(format!(
                "None of the validators has allowed operation {operation:?}: {messages:#?}",
            ))
        }
    }
}

/// All operations are allowed to be executed for all possible values.
/// Mostly for tests and simple cases.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct AllowAll<O: NeedsPermission> {
    #[serde(skip_serializing, default)]
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission> AllowAll<O> {
    /// Create new [`AllowAll`] instance
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

/// All operations are disallowed to be executed for all possible
/// values. Mostly for tests and simple cases.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct DenyAll<O: NeedsPermission> {
    #[serde(default, skip_serializing)]
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission> DenyAll<O> {
    /// Create new [`DenyAll`] instance
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
        Err("All operations are denied.".to_owned())
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

    /// Helper struct for [`Builder`].
    /// Makes sure there is at least one validator and all validators have the same type
    #[derive(Debug)]
    #[must_use]
    pub struct WithValidators<O: NeedsPermission> {
        validators: Vec<IsOperationAllowedBoxed<O>>,
    }

    /// Helper struct for [`Builder`].
    /// Contains final [`build()`][WithJudge::build()] step
    #[derive(Debug, Clone)]
    #[must_use]
    pub struct WithJudge<O: NeedsPermission, J: Judge<Operation = O>> {
        judge: J,
    }

    impl Builder {
        /// Add a validator to the list
        ///
        /// Returns new [`JudgeBuilder with validators`][WithValidators] with provided `validator`
        #[inline]
        pub fn with_validator<
            O: NeedsPermission + 'static,
            V: IsAllowed<Operation = O> + Send + Sync + 'static,
        >(
            validator: V,
        ) -> WithValidators<O> {
            WithValidators::new(validator)
        }

        /// Add a validator to the list
        ///
        /// Returns new [`JudgeBuilder with validators`][WithValidators]
        /// with provided recursive instruction `validator`
        #[inline]
        pub fn with_recursive_validator<
            V: IsAllowed<Operation = Instruction> + Send + Sync + 'static,
        >(
            validator: V,
        ) -> WithValidators<Instruction> {
            let nested_validator = CheckNested::new(validator);
            WithValidators::new(nested_validator)
        }
    }

    impl<O: NeedsPermission + 'static> WithValidators<O> {
        #[inline]
        fn new<V: IsAllowed<Operation = O> + Send + Sync + 'static>(validator: V) -> Self {
            Self {
                validators: vec![Box::new(validator)],
            }
        }

        /// Add a validator to the list
        #[inline]
        pub fn with_validator<V: IsAllowed<Operation = O> + Send + Sync + 'static>(
            mut self,
            validator: V,
        ) -> Self {
            self.validators.push(Box::new(validator));
            self
        }

        /// Wrap provided validators with [`AtLeastOneAllow`] *judge*
        #[inline]
        pub fn at_least_one_allow(self) -> WithJudge<O, AtLeastOneAllow<O>> {
            let at_least_one_allow = AtLeastOneAllow {
                validators: self.validators,
            };
            WithJudge::new(at_least_one_allow)
        }

        /// Wrap provided validators with [`NoDenies`] *judge*
        #[inline]
        pub fn no_denies(self) -> WithJudge<O, NoDenies<O>> {
            let no_denies = NoDenies {
                validators: self.validators,
            };

            WithJudge::new(no_denies)
        }
    }

    impl WithValidators<Instruction> {
        /// Add a validator to the list and wrap it with [`CheckNested`] to check nested permissions.
        #[inline]
        pub fn with_recursive_validator<
            V: IsAllowed<Operation = Instruction> + Send + Sync + 'static,
        >(
            self,
            validator: V,
        ) -> Self {
            let nested_validator = CheckNested::new(validator);
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
            Self { judge }
        }

        /// Build *judge*
        #[inline]
        pub fn build(self) -> J {
            self.judge
        }
    }

    impl<O, J> WithJudge<O, J>
    where
        O: NeedsPermission + Send + Sync + 'static,
        J: Judge<Operation = O> + IsAllowed<Operation = O> + Send + Sync + 'static,
    {
        /// Add a validator to the list.
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
        /// Add a validator to the list and wrap it with `CheckNested` to check nested permissions.
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
        /// Apply [`NoDenies`] together with [`AtLeastOneAllow`]
        ///
        /// The effect of calling this method is the same as
        /// calling [`WithValidators::no_denies()`]
        /// and then [`WithJudge::at_least_one_allow()`]
        #[inline]
        pub fn no_denies(self) -> WithJudge<O, NoDeniesAndAtLeastOneAllow<O>> {
            let no_denies_and_at_least_one_allow = NoDeniesAndAtLeastOneAllow {
                validators: self.judge.validators,
            };
            WithJudge::new(no_denies_and_at_least_one_allow)
        }
    }

    impl<O> WithJudge<O, NoDenies<O>>
    where
        O: NeedsPermission + 'static,
    {
        /// Apply [`AtLeastOneAllow`] together with [`NoDenies`]
        ///
        /// The effect of calling this method is the same as
        /// calling [`WithValidators::at_least_one_allow()`]
        /// and then [`WithJudge::no_denies()`]
        #[inline]
        pub fn at_least_one_allow(self) -> WithJudge<O, NoDeniesAndAtLeastOneAllow<O>> {
            let no_denies_and_at_least_one_allow = NoDeniesAndAtLeastOneAllow {
                validators: self.judge.validators,
            };
            WithJudge::new(no_denies_and_at_least_one_allow)
        }
    }
}
