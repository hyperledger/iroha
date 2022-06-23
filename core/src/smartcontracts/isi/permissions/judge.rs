use super::*;

pub trait Judge<O: NeedsPermission> {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason>;

    fn judge(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        let expected_type = O::required_validator_type();
        if self.validator_type() != expected_type {
            // Technically we can return `ValidatorVerdict::Skip` or
            // `ValidatorVerdict::Deny` here, but error of that kind is
            // probably a programmer error, so we want to know about it as soon
            // as possible
            panic!(
                "Validator type mismatch: expected {}, got {}",
                expected_type,
                self.validator_type()
            );

            self.judge_type_independent(authority, operation, wsv)
        }
    }

    /// Get type of validator
    fn validator_type(&self) -> ValidatorType;
}

/// Every [`Judge`] is also a `Validator`
impl<J: Judge<O>, O: NeedsPermission> IsAllowed<O> for J {
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        self.judge(authority, operation, wsv).into()
    }

    fn validator_type(&self) -> ValidatorType {
        Judge::validator_type(&self)
    }
}

pub struct AtLeastOneAllow {
    pub(crate) validators: Vec<IsAllowedBoxed>,
}

impl<O: NeedsPermission> Judge<O> for AtLeastOneAllow {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &O,
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

    fn validator_type(&self) -> ValidatorType {
        // Since [`Self`] can be constructed only with TODO it's always panic-safe
        self.validators
            .first()
            .expect("Expected at least one validator for `AtLeastOneAllow` judge")
            .validator_type()
    }
}

pub struct NoDenies {
    pub(crate) validators: Vec<IsAllowedBoxed>,
}

impl<O: NeedsPermission> Judge<O> for NoDenies {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &O,
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

    fn validator_type(&self) -> ValidatorType {
        // Since [`Self`] can be constructed only with TODO it's always panic-safe
        self.validators
            .first()
            .expect("Expected at least one validator for `AtLeastOneAllow` judge")
            .validator_type()
    }
}

/// Allows all operations to be executed for all possible values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct AllowAll;

impl<O: NeedsPermission> Judge<O> for AllowAll {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        Ok(())
    }

    fn validator_type(&self) -> ValidatorType {
        O::required_validator_type()
    }
}

/// Disallows all operations to be executed for all possible
/// values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DenyAll;

impl<O: NeedsPermission> Judge<O> for DenyAll {
    fn judge_type_independent(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        Err("All operations are denied.".to_owned().into())
    }

    fn validator_type(&self) -> ValidatorType {
        O::required_validator_type()
    }
}
