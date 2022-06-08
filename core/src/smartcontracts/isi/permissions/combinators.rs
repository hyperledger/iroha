//! Module with combinators for permission validators

use super::*;

/// Checks if `validator` equals to `expected`
///
/// # Errors
/// If `validator` doesn't equal to `expected`
pub fn check_equal(
    validator: ValidatorType,
    expected: ValidatorType,
) -> std::result::Result<(), ValidatorTypeMismatch> {
    if validator != expected {
        return Err(ValidatorTypeMismatch {
            expected,
            actual: validator,
        });
    }

    Ok(())
}

/// Trait for joining validators with `or` method, auto-implemented
/// for all types which are convertible to a concrete type implementing [`IsAllowed`]
pub trait ValidatorApplyOr<O: NeedsPermission, V: IsAllowed<O>>: Into<V> {
    /// Combines two validators into [`Or`].
    ///
    /// # Errors
    /// If validators have different types
    fn or(self, another: impl Into<V>) -> Or<O, V>;
}

impl<O: NeedsPermission, V: IsAllowed<O>, I: Into<V>> ValidatorApplyOr<O, V> for I {
    fn or(self, another: impl Into<V>) -> Or<O, V> {
        Or::new(self, another)
    }
}

/// `check` succeeds if either `first` or `second` validator succeeds.
#[derive(Debug, Clone, Serialize)]
pub struct Or<O: NeedsPermission, V: IsAllowed<O>> {
    first: V,
    second: V,
    #[serde(skip_serializing, default)]
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission, V: IsAllowed<O>> Or<O, V> {
    /// Constructs new [`Or`]
    ///
    /// # Errors
    /// If validators have different types
    pub fn new(first: impl Into<V>, second: impl Into<V>) -> Self {
        Or {
            first: first.into(),
            second: second.into(),
            _phantom_operation: PhantomData,
        }
    }
}

impl IsAllowed<Instruction> for Or<Instruction, IsInstructionAllowedBoxed> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<()> {
        self.first
            .check(authority, operation, wsv)
            .or_else(|first_error| {
                self.second
                    .check(authority, operation, wsv)
                    .map_err(|second_error| {
                        format!(
                            "Failed to pass first check with {} and second check with {}.",
                            first_error, second_error
                        )
                        .into()
                    })
            })
    }
}

impl From<Or<Instruction, IsInstructionAllowedBoxed>> for IsInstructionAllowedBoxed {
    fn from(value: Or<Instruction, IsInstructionAllowedBoxed>) -> Self {
        Box::new(value)
    }
}

impl IsAllowed<QueryBox> for Or<QueryBox, IsQueryAllowedBoxed> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView,
    ) -> Result<()> {
        self.first
            .check(authority, operation, wsv)
            .or_else(|first_error| {
                self.second
                    .check(authority, operation, wsv)
                    .map_err(|second_error| {
                        format!(
                            "Failed to pass first check with {} and second check with {}.",
                            first_error, second_error
                        )
                        .into()
                    })
            })
    }
}

impl From<Or<QueryBox, IsQueryAllowedBoxed>> for IsQueryAllowedBoxed {
    fn from(value: Or<QueryBox, IsQueryAllowedBoxed>) -> Self {
        Box::new(value)
    }
}

impl IsAllowed<Expression> for Or<Expression, IsExpressionAllowedBoxed> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView,
    ) -> Result<()> {
        self.first
            .check(authority, operation, wsv)
            .or_else(|first_error| {
                self.second
                    .check(authority, operation, wsv)
                    .map_err(|second_error| {
                        format!(
                            "Failed to pass first check with {} and second check with {}.",
                            first_error, second_error
                        )
                        .into()
                    })
            })
    }
}

impl From<Or<Expression, IsExpressionAllowedBoxed>> for IsExpressionAllowedBoxed {
    fn from(value: Or<Expression, IsExpressionAllowedBoxed>) -> Self {
        Box::new(value)
    }
}

/// Wraps validator to check nested permissions.  Pay attention to
/// wrap only validators that do not check nested instructions by
/// themselves.
#[derive(Debug)]
pub struct CheckNested {
    validator: IsInstructionAllowedBoxed,
}

impl CheckNested {
    /// Wraps `validator` to check nested permissions.
    pub fn new(validator: IsInstructionAllowedBoxed) -> Self {
        CheckNested { validator }
    }
}

impl IsAllowed<Instruction> for CheckNested {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<()> {
        match instruction {
            Instruction::Register(_)
            | Instruction::Unregister(_)
            | Instruction::Mint(_)
            | Instruction::Burn(_)
            | Instruction::SetKeyValue(_)
            | Instruction::RemoveKeyValue(_)
            | Instruction::Transfer(_)
            | Instruction::Grant(_)
            | Instruction::Revoke(_)
            | Instruction::Fail(_)
            | Instruction::ExecuteTrigger(_) => self.validator.check(authority, instruction, wsv),
            Instruction::If(if_box) => {
                self.check(authority, &if_box.then, wsv)
                    .and_then(|_| match &if_box.otherwise {
                        Some(this_instruction) => self.check(authority, this_instruction, wsv),
                        None => Ok(()),
                    })
            }
            Instruction::Pair(pair_box) => self
                .check(authority, &pair_box.left_instruction, wsv)
                .and(self.check(authority, &pair_box.right_instruction, wsv)),
            Instruction::Sequence(sequence_box) => sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| self.check(authority, this_instruction, wsv)),
        }
    }
}

fn check_all_validators_have_the_same_type(validators: &[IsAllowedBoxed]) -> Result<()> {
    let first_type = if let Some(first) = validators.first() {
        first.validator_type()
    } else {
        return Ok(());
    };

    for validator in validators.iter().skip(1) {
        let validator_type = validator.validator_type();
        if validator_type != first_type {
            return Err(ValidatorTypeMismatch {
                expected: first_type,
                actual: validator_type,
            }
            .into());
        }
    }

    Ok(())
}

/// A container for multiple permissions validators. It will succeed if all validators succeed.
#[derive(Debug)]
pub struct AllShouldSucceed {
    validators: Vec<IsAllowedBoxed>,
}

impl AllShouldSucceed {
    /// Create new [`AllShouldSucceed`]
    ///
    /// # Errors
    /// If provided validators have different types.
    /// Type of the first element in the `validators` is considered exemplary
    pub fn new(validators: Vec<IsAllowedBoxed>) -> Result<Self> {
        check_all_validators_have_the_same_type(&validators)?;
        Ok(Self { validators })
    }

    fn check_type(&self, validator_type: ValidatorType) -> Result<()> {
        if let Ok(self_type) = self.validator_type() {
            if self_type != validator_type {
                return Err(ValidatorTypeMismatch {
                    expected: validator_type,
                    actual: self_type,
                }
                .into());
            }
        }

        Ok(())
    }

    fn validator_type(&self) -> Result<ValidatorType> {
        self.validators
            .first()
            .map_or(Err(DenialReason::NoValidatorsProvided), |first| {
                Ok(first.validator_type())
            })
    }
}

impl IsAllowed<Instruction> for AllShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<()> {
        self.check_type(ValidatorType::Instruction)?;

        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl IsAllowed<QueryBox> for AllShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView,
    ) -> Result<()> {
        self.check_type(ValidatorType::Query)?;

        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl IsAllowed<Expression> for AllShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView,
    ) -> Result<()> {
        self.check_type(ValidatorType::Expression)?;

        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl TryFrom<AllShouldSucceed> for IsAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        match value.validator_type()? {
            ValidatorType::Instruction => Ok(IsAllowedBoxed::Instruction(Box::new(value))),
            ValidatorType::Query => Ok(IsAllowedBoxed::Query(Box::new(value))),
            ValidatorType::Expression => Ok(IsAllowedBoxed::Expression(Box::new(value))),
        }
    }
}

impl TryFrom<AllShouldSucceed> for IsInstructionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Instruction)?;

        Ok(Box::new(value))
    }
}

impl TryFrom<AllShouldSucceed> for IsQueryAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Query)?;

        Ok(Box::new(value))
    }
}

impl TryFrom<AllShouldSucceed> for IsExpressionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Expression)?;

        Ok(Box::new(value))
    }
}

/// A container for multiple permissions validators. It will succeed if any validator succeeds.
#[derive(Debug)]
pub struct AnyShouldSucceed {
    name: String,
    validators: Vec<IsAllowedBoxed>,
}

impl AnyShouldSucceed {
    /// Creates new [`AnyShouldSucceed`]
    ///
    /// # Errors
    /// If provided validators have different types.
    /// Type of the first element in the `validators` is considered exemplary
    pub fn new(name: String, validators: Vec<IsAllowedBoxed>) -> Result<Self> {
        check_all_validators_have_the_same_type(&validators)?;

        Ok(Self { name, validators })
    }

    fn check_type(&self, validator_type: ValidatorType) -> Result<()> {
        if let Ok(self_type) = self.validator_type() {
            if self_type != validator_type {
                return Err(ValidatorTypeMismatch {
                    expected: validator_type,
                    actual: self_type,
                }
                .into());
            }
        }

        Ok(())
    }

    fn validator_type(&self) -> Result<ValidatorType> {
        self.validators
            .first()
            .map_or(Err(DenialReason::NoValidatorsProvided), |first| {
                Ok(first.validator_type())
            })
    }
}

impl IsAllowed<Instruction> for AnyShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<()> {
        self.check_type(ValidatorType::Instruction)?;

        for validator in &self.validators {
            if validator.check(authority, operation, wsv).is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "None of the instructions succeeded in Any permission check block with name: {}",
            self.name
        )
        .into())
    }
}

impl IsAllowed<QueryBox> for AnyShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView,
    ) -> Result<()> {
        self.check_type(ValidatorType::Query)?;

        for validator in &self.validators {
            if validator.check(authority, operation, wsv).is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "None of the instructions succeeded in Any permission check block with name: {}",
            self.name
        )
        .into())
    }
}

impl IsAllowed<Expression> for AnyShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView,
    ) -> Result<()> {
        self.check_type(ValidatorType::Expression)?;

        for validator in &self.validators {
            if validator.check(authority, operation, wsv).is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "None of the instructions succeeded in Any permission check block with name: {}",
            self.name
        )
        .into())
    }
}

impl TryFrom<AnyShouldSucceed> for IsAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        match value.validator_type()? {
            ValidatorType::Instruction => Ok(IsAllowedBoxed::Instruction(Box::new(value))),
            ValidatorType::Query => Ok(IsAllowedBoxed::Query(Box::new(value))),
            ValidatorType::Expression => Ok(IsAllowedBoxed::Expression(Box::new(value))),
        }
    }
}

impl TryFrom<AnyShouldSucceed> for IsInstructionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Instruction)?;

        Ok(Box::new(value))
    }
}

impl TryFrom<AnyShouldSucceed> for IsQueryAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Query)?;

        Ok(Box::new(value))
    }
}

impl TryFrom<AnyShouldSucceed> for IsExpressionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Expression)?;

        Ok(Box::new(value))
    }
}

/// Allows all operations to be executed for all possible values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct AllowAll;

impl AllowAll {
    /// Construct permission which allows all items
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T>() -> Arc<T>
    where
        Self: Into<T>,
    {
        Arc::new(Self.into())
    }
}

/// Disallows all operations to be executed for all possible
/// values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DenyAll;

impl DenyAll {
    /// Construct permission which denies all items
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T>() -> Arc<T>
    where
        Self: Into<T>,
    {
        Arc::new(Self.into())
    }
}

/// Generate [`From`] implementations from type implementing [`IsAllowed`] to boxed types like:
/// [`IsInstructionAllowedBoxed`], [`IsQueryAllowedBoxed`] and [`IsExpressionAllowedBoxed`]
///
/// See usage below
macro_rules! impl_from_for_allowed_boxed {
    ($($t:ty => $b:ty),+ $(,)?) => {
        $(
            impl From<$t> for $b {
                fn from(value: $t) -> Self {
                    Box::new(value)
                }
            }
        )+
    };
}

impl<O: NeedsPermission> IsAllowed<O> for AllowAll {
    fn check(&self, _authority: &AccountId, _instruction: &O, _wsv: &WorldStateView) -> Result<()> {
        Ok(())
    }
}

impl_from_for_allowed_boxed! {
    AllowAll => IsInstructionAllowedBoxed,
    AllowAll => IsQueryAllowedBoxed,
    AllowAll => IsExpressionAllowedBoxed,
}

impl<O: NeedsPermission> IsAllowed<O> for DenyAll {
    fn check(&self, _authority: &AccountId, _instruction: &O, _wsv: &WorldStateView) -> Result<()> {
        Err("All operations are denied.".to_owned().into())
    }
}

impl_from_for_allowed_boxed! {
    DenyAll => IsInstructionAllowedBoxed,
    DenyAll => IsQueryAllowedBoxed,
    DenyAll => IsExpressionAllowedBoxed,
}
