//! Module with [`Judge`] trait and its implementations
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{fmt::Display, sync::Arc};

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

    /// Disable showing the operation description in the validation error message
    ///
    /// Use this when you have one [`Judge`] nested inside another, as it will prevent
    /// printing the same error message twice.
    fn disable_display_of_operation_on_error(&mut self);

    /// Convert this object to a type implementing [`IsAllowed`] trait
    ///
    /// Could not use `impl<O: NeedsPermission, J: Judge<Operation = O>> IsAllowed for J`
    /// because of conflicting trait implementations
    fn into_validator(self) -> JudgeAsValidator<Self::Operation, Self>
    where
        Self: Sized,
    {
        JudgeAsValidator::new(self)
    }
}

/// Wrapper for types implementing [`Judge`]
///
/// Implements [`IsAllowed`] trait so that
/// it's possible to use it in [`JudgeBuilder`](super::judge::builder::Builder)
#[derive(Debug, Display)]
#[display(bound = "J: Display")]
#[display(fmt = "{}", "self.name()")]
pub struct JudgeAsValidator<O: NeedsPermission, J: Judge<Operation = O>> {
    judge: J,
    name: Option<&'static str>,
}

impl<O: NeedsPermission, J: Judge<Operation = O>> JudgeAsValidator<O, J> {
    /// Create new [`JudgeAsValidator`] with given `judge`
    #[inline]
    fn new(judge: J) -> Self {
        Self { judge, name: None }
    }

    /// Display `judge` with given `name` instead of default detailed description
    #[must_use]
    #[inline]
    pub fn display_as(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }
}

impl<O: NeedsPermission, J: Judge<Operation = O> + Display> JudgeAsValidator<O, J> {
    #[inline]
    fn name(&self) -> std::borrow::Cow<str> {
        if let Some(name) = self.name {
            return name.into();
        }
        self.judge.to_string().into()
    }
}

impl<O: NeedsPermission, J: Judge<Operation = O> + Display> IsAllowed for JudgeAsValidator<O, J> {
    type Operation = O;

    #[inline]
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
pub struct AtLeastOneAllow<O: NeedsPermission> {
    validators: Vec<IsOperationAllowedBoxed<O>>,
    display_operation: bool,
}

impl<O: NeedsPermission> AtLeastOneAllow<O> {
    /// Create new [`AtLeastOneAllow`] judge with given `validators`
    fn new(validators: Vec<IsOperationAllowedBoxed<O>>) -> Self {
        AtLeastOneAllow {
            validators,
            display_operation: true,
        }
    }
}

impl<O: NeedsPermission> Display for AtLeastOneAllow<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("At least one allow in: ")?;

        format_comma_separated(self.validators.iter().back_quoted(), ('[', ']'), f)
    }
}

impl<O: NeedsPermission + Display> Judge for AtLeastOneAllow<O> {
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
                    messages.push(format!("Validator `{validator}` denied: {reason}"));
                }
                ValidatorVerdict::Skip => {
                    messages.push(format!("Validator `{validator}` skipped"));
                }
            }
        }

        Err(format!(
            "None of the validators has allowed the operation{}: {messages:#?}",
            construct_operation_string(&operation, self.display_operation, authority)
        ))
    }

    fn disable_display_of_operation_on_error(&mut self) {
        self.display_operation = false;
    }
}

/// The judge that succeeds only if there is no
/// [`Deny`](ValidatorVerdict::Deny) verdict from the contained validators.
///
/// Iterates over all validators.
pub struct NoDenies<O: NeedsPermission> {
    validators: Vec<IsOperationAllowedBoxed<O>>,
    display_operation: bool,
}

impl<O: NeedsPermission> NoDenies<O> {
    /// Create new [`NoDenies`] judge with given `validators`
    fn new(validators: Vec<IsOperationAllowedBoxed<O>>) -> Self {
        NoDenies {
            validators,
            display_operation: true,
        }
    }
}

impl<O: NeedsPermission> Display for NoDenies<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("No denies in: ")?;

        format_comma_separated(self.validators.iter().back_quoted(), ('[', ']'), f)
    }
}

impl<O: NeedsPermission + Display> Judge for NoDenies<O> {
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
                    "Validator `{validator}` denied the operation{}: {reason}",
                    construct_operation_string(&operation, self.display_operation, authority)
                ));
            }
        }

        Ok(())
    }

    fn disable_display_of_operation_on_error(&mut self) {
        self.display_operation = false;
    }
}

/// The judge that succeeds only if there is no
/// [`Deny`](ValidatorVerdict::Deny) verdict and there is at least one
/// [`Allow`](ValidatorVerdict::Allow) verdict from the contained validators.
///
/// Iterates over all validators until first `Deny` is found or
/// all validators are checked.
pub struct NoDeniesAndAtLeastOneAllow<O: NeedsPermission> {
    validators: Vec<IsOperationAllowedBoxed<O>>,
    display_operation: bool,
}

impl<O: NeedsPermission> NoDeniesAndAtLeastOneAllow<O> {
    /// Create new [`NoDeniesAndAtLeastOneAllow`] judge with given `validators`
    fn new(validators: Vec<IsOperationAllowedBoxed<O>>) -> Self {
        NoDeniesAndAtLeastOneAllow {
            validators,
            display_operation: true,
        }
    }
}

impl<O: NeedsPermission> Display for NoDeniesAndAtLeastOneAllow<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("No denies and at least one allow in: ")?;

        format_comma_separated(self.validators.iter().back_quoted(), ('[', ']'), f)
    }
}

impl<O: NeedsPermission + Display> Judge for NoDeniesAndAtLeastOneAllow<O> {
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
                        "Validator `{validator}` denied the operation{}: {reason}",
                        construct_operation_string(&operation, self.display_operation, authority)
                    ));
                }
                ValidatorVerdict::Skip => {
                    messages.push(format!("Validator `{validator}` skipped"));
                }
            }
        }

        if allowed {
            Ok(())
        } else {
            Err(format!(
                "None of the validators has allowed operation{}: {messages:#?}",
                construct_operation_string(&operation, self.display_operation, authority)
            ))
        }
    }

    fn disable_display_of_operation_on_error(&mut self) {
        self.display_operation = false;
    }
}

/// All operations are allowed to be executed for all possible values.
/// Mostly for tests and simple cases.
#[derive(Debug, Display, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[display(fmt = "Allow all operations")]
pub struct AllowAll<O: NeedsPermission> {
    #[serde(skip_serializing, default)]
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission> AllowAll<O> {
    /// Create new [`AllowAll`] instance
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<O: NeedsPermission> Default for AllowAll<O> {
    fn default() -> Self {
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

    fn disable_display_of_operation_on_error(&mut self) {
        // [`AllowAll`] never displays operation, hence no-op.
    }
}

/// All operations are disallowed to be executed for all possible
/// values. Mostly for tests and simple cases.
#[derive(Debug, Display, Clone, Serialize)]
#[display(fmt = "Deny all operations")]
pub struct DenyAll<O: NeedsPermission> {
    #[serde(default, skip_serializing)]
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission> DenyAll<O> {
    /// Create new [`DenyAll`] instance
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<O: NeedsPermission> Default for DenyAll<O> {
    fn default() -> Self {
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

    fn disable_display_of_operation_on_error(&mut self) {
        // [`DenyAll`] never displays operation, hence no-op.
    }
}

/// Create a string with an operation description and a
/// **leading** space if `display_operation` is `true`.
/// Return empty string if `display_operation` is `false`.
fn construct_operation_string<O: Display>(
    operation: &O,
    display_operation: bool,
    authority: &<Account as Identifiable>::Id,
) -> String {
    if display_operation {
        format!(" `{}` by `{}`", operation, authority)
    } else {
        String::new()
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
            O: NeedsPermission + Display + 'static,
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

    impl<O: NeedsPermission + Display + 'static> WithValidators<O> {
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
            let at_least_one_allow = AtLeastOneAllow::new(self.validators);
            WithJudge::new(at_least_one_allow)
        }

        /// Wrap provided validators with [`NoDenies`] *judge*
        #[inline]
        pub fn no_denies(self) -> WithJudge<O, NoDenies<O>> {
            let no_denies = NoDenies::new(self.validators);

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
        O: NeedsPermission + Display + Send + Sync + 'static,
        J: Judge<Operation = O> + Display + Send + Sync + 'static,
    {
        /// Add a validator to the list.
        #[inline]
        pub fn with_validator<V: IsAllowed<Operation = O> + Send + Sync + 'static>(
            self,
            validator: V,
        ) -> WithValidators<O> {
            WithValidators::new(self.judge.into_validator()).with_validator(validator)
        }

        /// Disable showing the operation description in the validation error message
        ///
        /// Use this when you have one [`Judge`] nested inside another, as it will prevent
        /// printing the same error message twice.
        #[inline]
        pub fn disable_display_of_operation_on_error(mut self) -> Self {
            self.judge.disable_display_of_operation_on_error();
            self
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
        /// Add a validator to the list and wrap it with
        /// [`CheckNested`] to check nested permissions.
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
        O: NeedsPermission + Display + 'static,
    {
        /// Apply [`NoDenies`] together with [`AtLeastOneAllow`]
        ///
        /// The effect of calling this method is the same as
        /// calling [`WithValidators::no_denies()`]
        /// and then [`WithJudge::at_least_one_allow()`]
        #[inline]
        pub fn no_denies(self) -> WithJudge<O, NoDeniesAndAtLeastOneAllow<O>> {
            let no_denies_and_at_least_one_allow =
                NoDeniesAndAtLeastOneAllow::new(self.judge.validators);
            WithJudge::new(no_denies_and_at_least_one_allow)
        }
    }

    impl<O> WithJudge<O, NoDenies<O>>
    where
        O: NeedsPermission + Display + 'static,
    {
        /// Apply [`AtLeastOneAllow`] together with [`NoDenies`]
        ///
        /// The effect of calling this method is the same as
        /// calling [`WithValidators::at_least_one_allow()`]
        /// and then [`WithJudge::no_denies()`]
        #[inline]
        pub fn at_least_one_allow(self) -> WithJudge<O, NoDeniesAndAtLeastOneAllow<O>> {
            let no_denies_and_at_least_one_allow =
                NoDeniesAndAtLeastOneAllow::new(self.judge.validators);
            WithJudge::new(no_denies_and_at_least_one_allow)
        }
    }
}
