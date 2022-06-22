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

pub struct AtLeastOneAllow<O: NeedsPermission> {
    pub validators: Vec<Box<dyn IsAllowed<O> + Send + Sync>>,
}

impl<O: NeedsPermission> Judge<O> for AtLeastOneAllow<O> {
    fn judge(
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
}

pub struct NoDenies<O: NeedsPermission> {
    pub validators: Vec<Box<dyn IsAllowed<O> + Send + Sync>>,
}

impl<O: NeedsPermission> Judge<O> for NoDenies<O> {
    fn judge(
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
}
