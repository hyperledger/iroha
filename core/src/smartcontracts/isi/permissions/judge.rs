use super::*;

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::AtLeastOneAllow {}

    impl Sealed for super::NoDenies {}
}

pub type JudgeBox = Box<dyn Judge + Send + Sync>;

pub trait Judge: GetValidatorType + std::fmt::Debug {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &NeedsPermissionBox,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason>;

    fn judge(
        &self,
        authority: &AccountId,
        operation: &NeedsPermissionBox,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        let expected_type = operation.required_validator_type();
        let actual_type = self.get_validator_type();
        if actual_type != expected_type {
            // Technically we can return `ValidatorVerdict::Skip` or
            // `ValidatorVerdict::Deny` here, but error of that kind is
            // probably a programmer error, so we want to know about it as soon
            // as possible
            panic!(
                "Validator type mismatch: expected {}, got {}",
                expected_type, actual_type,
            );
        }

        self.judge_type_independent(authority, operation, wsv)
    }
}

/// Every *sealed* [`Judge`] is also a `Validator`
///
/// [`sealed::Sealed`] is used to prevent conflicting trait implementations
/// for [`IsAllowedBoxed`].
/// *Sealed* makes it impossible to generate this implementation for anything
/// that is not listed in [`sealed`] module.
impl<J: Judge + sealed::Sealed> IsAllowed for J {
    type Operation = NeedsPermissionBox;

    fn check(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        self.judge(authority, operation, wsv).into()
    }
}

#[derive(Debug)]
pub struct AtLeastOneAllow {
    pub(crate) validators: Vec<IsAllowedBoxed>,
}

impl GetValidatorType for AtLeastOneAllow {
    fn get_validator_type(&self) -> ValidatorType {
        // Since [`Self`] can be constructed only with TODO it's always panic-safe
        let first: &IsAllowedBoxed = self
            .validators
            .first()
            .expect("Expected at least one validator for `AtLeastOneAllow` judge");

        <IsAllowedBoxed as GetValidatorType>::get_validator_type(first)
    }
}

impl Judge for AtLeastOneAllow {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &NeedsPermissionBox,
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
pub struct NoDenies {
    pub(crate) validators: Vec<IsAllowedBoxed>,
}

impl GetValidatorType for NoDenies {
    fn get_validator_type(&self) -> ValidatorType {
        // Since [`Self`] can be constructed only with TODO it's always panic-safe
        let first: &IsAllowedBoxed = self
            .validators
            .first()
            .expect("Expected at least one validator for `AtLeastOneAllow` judge");

        <IsAllowedBoxed as GetValidatorType>::get_validator_type(first)
    }
}

impl Judge for NoDenies {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &NeedsPermissionBox,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct AllowAll;

impl GetValidatorType for AllowAll {
    fn get_validator_type(&self) -> ValidatorType {
        unimplemented!("Implementation `GetValidatorType` for `AllowAll` has no meaning")
    }
}

impl Judge for AllowAll {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &NeedsPermissionBox,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        Ok(())
    }

    /// Reimplementing this function to remove *validator type* checking cause it has no meaning
    fn judge(
        &self,
        authority: &AccountId,
        operation: &NeedsPermissionBox,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        self.judge_type_independent(authority, operation, wsv)
    }
}

/// Disallows all operations to be executed for all possible
/// values. Mostly for tests and simple cases.
///
/// # Panic
/// [`DenyAll`] implements [`GetValidatorType`] to satisfy [`Judge`] bounds,
/// but calling [`GetValidatorType::get_validator_type`] will panic because
/// the exact implementation has no meaning.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DenyAll;

impl GetValidatorType for DenyAll {
    fn get_validator_type(&self) -> ValidatorType {
        unimplemented!("Implementation `GetValidatorType` for `DenyAll` has no meaning")
    }
}

impl Judge for DenyAll {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &NeedsPermissionBox,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        Err("All operations are denied.".to_owned().into())
    }

    /// Reimplementing this function to remove *validator type* checking cause it has no meaning
    fn judge(
        &self,
        authority: &AccountId,
        operation: &NeedsPermissionBox,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        self.judge_type_independent(authority, operation, wsv)
    }
}
