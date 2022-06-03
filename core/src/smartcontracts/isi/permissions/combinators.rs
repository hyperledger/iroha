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
pub trait ValidatorApplyOr<W: WorldTrait, O: NeedsPermission, V: IsAllowed<W, O>>: Into<V> {
    /// Combines two validators into [`Or`].
    ///
    /// # Errors
    /// If validators have different types
    fn or(self, another: impl Into<V>) -> Or<W, O, V>;
}

impl<W: WorldTrait, O: NeedsPermission, V: IsAllowed<W, O>, I: Into<V>> ValidatorApplyOr<W, O, V>
    for I
{
    fn or(self, another: impl Into<V>) -> Or<W, O, V> {
        Or::new(self, another)
    }
}

/// `check` succeeds if either `first` or `second` validator succeeds.
#[derive(Debug, Clone, Serialize)]
pub struct Or<W: WorldTrait, O: NeedsPermission, V: IsAllowed<W, O>> {
    first: V,
    second: V,
    #[serde(skip_serializing, default)]
    _phantom_world: PhantomData<W>,
    #[serde(skip_serializing, default)]
    _phantom_operation: PhantomData<O>,
}

impl<W: WorldTrait, O: NeedsPermission, V: IsAllowed<W, O>> Or<W, O, V> {
    /// Constructs new [`Or`]
    ///
    /// # Errors
    /// If validators have different types
    pub fn new(first: impl Into<V>, second: impl Into<V>) -> Self {
        Or {
            first: first.into(),
            second: second.into(),
            _phantom_world: PhantomData,
            _phantom_operation: PhantomData,
        }
    }
}

impl IsAllowed<World, Instruction> for Or<World, Instruction, IsInstructionAllowedBoxed> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView<World>,
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

impl From<Or<World, Instruction, IsInstructionAllowedBoxed>> for IsInstructionAllowedBoxed {
    fn from(value: Or<World, Instruction, IsInstructionAllowedBoxed>) -> Self {
        IsInstructionAllowedBoxed::World(Box::new(value))
    }
}

impl IsAllowed<World, QueryBox> for Or<World, QueryBox, IsQueryAllowedBoxed> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView<World>,
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

impl From<Or<World, QueryBox, IsQueryAllowedBoxed>> for IsQueryAllowedBoxed {
    fn from(value: Or<World, QueryBox, IsQueryAllowedBoxed>) -> Self {
        IsQueryAllowedBoxed::World(Box::new(value))
    }
}

impl IsAllowed<World, Expression> for Or<World, Expression, IsExpressionAllowedBoxed> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView<World>,
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

impl From<Or<World, Expression, IsExpressionAllowedBoxed>> for IsExpressionAllowedBoxed {
    fn from(value: Or<World, Expression, IsExpressionAllowedBoxed>) -> Self {
        IsExpressionAllowedBoxed::World(Box::new(value))
    }
}

/// Wraps validator to check nested permissions.  Pay attention to
/// wrap only validators that do not check nested instructions by
/// themselves.
#[derive(Debug, Clone, Serialize)]
pub struct CheckNested {
    validator: IsInstructionAllowedBoxed,
}

impl CheckNested {
    /// Wraps `validator` to check nested permissions.
    pub fn new(validator: IsInstructionAllowedBoxed) -> Self {
        CheckNested { validator }
    }
}

impl IsAllowed<World, Instruction> for CheckNested {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
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
#[derive(Debug, Clone, Serialize)]
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

impl IsAllowed<World, Instruction> for AllShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.check_type(ValidatorType::Instruction)?;

        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl IsAllowed<World, QueryBox> for AllShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        self.check_type(ValidatorType::Query)?;

        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl IsAllowed<World, Expression> for AllShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView<World>,
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
            ValidatorType::Instruction => {
                Ok(IsInstructionAllowedBoxed::World(Box::new(value)).into())
            }
            ValidatorType::Query => Ok(IsQueryAllowedBoxed::World(Box::new(value)).into()),
            ValidatorType::Expression => {
                Ok(IsExpressionAllowedBoxed::World(Box::new(value)).into())
            }
        }
    }
}

impl TryFrom<AllShouldSucceed> for IsInstructionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Instruction)?;

        Ok(IsInstructionAllowedBoxed::World(Box::new(value)))
    }
}

impl TryFrom<AllShouldSucceed> for IsQueryAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Query)?;

        Ok(IsQueryAllowedBoxed::World(Box::new(value)))
    }
}

impl TryFrom<AllShouldSucceed> for IsExpressionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AllShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Expression)?;

        Ok(IsExpressionAllowedBoxed::World(Box::new(value)))
    }
}

/// A container for multiple permissions validators. It will succeed if any validator succeeds.
#[derive(Debug, Clone, Serialize)]
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

impl IsAllowed<World, Instruction> for AnyShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Instruction,
        wsv: &WorldStateView<World>,
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

impl IsAllowed<World, QueryBox> for AnyShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &QueryBox,
        wsv: &WorldStateView<World>,
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

impl IsAllowed<World, Expression> for AnyShouldSucceed {
    fn check(
        &self,
        authority: &AccountId,
        operation: &Expression,
        wsv: &WorldStateView<World>,
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
            ValidatorType::Instruction => {
                Ok(IsInstructionAllowedBoxed::World(Box::new(value)).into())
            }
            ValidatorType::Query => Ok(IsQueryAllowedBoxed::World(Box::new(value)).into()),
            ValidatorType::Expression => {
                Ok(IsExpressionAllowedBoxed::World(Box::new(value)).into())
            }
        }
    }
}

impl TryFrom<AnyShouldSucceed> for IsInstructionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Instruction)?;

        Ok(IsInstructionAllowedBoxed::World(Box::new(value)))
    }
}

impl TryFrom<AnyShouldSucceed> for IsQueryAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Query)?;

        Ok(IsQueryAllowedBoxed::World(Box::new(value)))
    }
}

impl TryFrom<AnyShouldSucceed> for IsExpressionAllowedBoxed {
    type Error = DenialReason;

    fn try_from(value: AnyShouldSucceed) -> std::result::Result<Self, Self::Error> {
        let validator_type = value.validator_type()?;
        check_equal(validator_type, ValidatorType::Expression)?;

        Ok(IsExpressionAllowedBoxed::World(Box::new(value)))
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
                    <$b>::World(Box::new(value))
                }
            }
        )+
    };
}

impl<W: WorldTrait, O: NeedsPermission> IsAllowed<W, O> for AllowAll {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &O,
        _wsv: &WorldStateView<W>,
    ) -> Result<()> {
        Ok(())
    }
}

impl_from_for_allowed_boxed! {
    AllowAll => IsInstructionAllowedBoxed,
    AllowAll => IsQueryAllowedBoxed,
    AllowAll => IsExpressionAllowedBoxed,
}

impl<W: WorldTrait, O: NeedsPermission> IsAllowed<W, O> for DenyAll {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &O,
        _wsv: &WorldStateView<W>,
    ) -> Result<()> {
        Err("All operations are denied.".to_owned().into())
    }
}

impl_from_for_allowed_boxed! {
    DenyAll => IsInstructionAllowedBoxed,
    DenyAll => IsQueryAllowedBoxed,
    DenyAll => IsExpressionAllowedBoxed,
}
