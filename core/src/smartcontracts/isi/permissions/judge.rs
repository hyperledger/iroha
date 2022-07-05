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
        let mut deny_messages = Vec::new();

        for validator in &self.validators {
            match validator.check(authority, operation, wsv) {
                ValidatorVerdict::Allow => return Ok(()),
                ValidatorVerdict::Deny(reason) => {
                    deny_messages.push(format!("Validator {validator:?} denied: {reason}"));
                }
                ValidatorVerdict::Skip => {}
            }
        }

        Err(DenialReason::Custom(format!(
            "None of the validators has allowed operation {operation:?}: {deny_messages:#?}",
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
