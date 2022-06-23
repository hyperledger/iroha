use super::*;

pub trait Judge<O: NeedsPermission> {
    fn judge(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason>;
}

/// Every [`Judge`] is also a `Validator`
impl<T: Judge<O>, O: NeedsPermission> IsAllowed<O> for T {
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        self.judge(authority, operation, wsv).into()
    }
}

macro_rules! impl_judge {
    ($j:ty<$($o:ty),* $(,)?>) => {
        $(
            impl Judge<$o> for $t {
                fn judge(
                    &self,
                    authority: &AccountId,
                    operation: &$v,
                    wsv: &WorldStateView,
                ) -> std::result::Result<(), DenialReason> {
                    self.check_type(<$o as NeedsPermission>::required_validator_type())?;
                    T::judge(self, authority, operation, wsv)
                }
            }
        )*
    };
}

pub struct AtLeastOneAllow {
    pub(crate) validators: Vec<IsAllowedBoxed>,
}

impl AtLeastOneAllow {
    fn impl_judge<O: NeedsPermission>(
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

impl_judge!(AtLeastOneAllow<Instruction, Query, Expression>);

pub struct NoDenies {
    pub(crate) validators: Vec<IsAllowedBoxed>,
}

impl NoDenies {
    fn impl_judge<O: NeedsPermission>(
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

impl_judge!(NoDenies<Instruction, Query, Expression>);
