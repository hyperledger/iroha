use super::*;

mod sealed {
    use crate::smartcontracts::permissions::NeedsPermission;

    pub trait Sealed {}

    impl<O: NeedsPermission> Sealed for super::AtLeastOneAllow<O> {}
    impl<O: NeedsPermission> Sealed for super::NoDenies<O> {}
    impl<O: NeedsPermission> Sealed for super::AllowAll<O> {}
    impl<O: NeedsPermission> Sealed for super::DenyAll<O> {}
}

// TODO: Do I really need `GetValidatorType` here?
pub trait Judge: GetValidatorType + std::fmt::Debug {
    type Operation: NeedsPermission;

    fn judge(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason>;
}

/// Every *sealed* [`Judge`] is also a `Validator`
///
/// [`sealed::Sealed`] is used to prevent conflicting trait implementations
/// for [`IsAllowedBoxed`].
/// *Sealed* makes it impossible to generate this implementation for anything
/// that is not listed in [`sealed`] module.
impl<O: NeedsPermission, J: Judge<Operation = O> + sealed::Sealed> IsAllowed for J {
    type Operation = O;

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
pub struct AtLeastOneAllow<O: NeedsPermission> {
    pub(crate) validators: Vec<IsOperationAllowedBoxed<O>>,
}

impl<O: NeedsPermission> GetValidatorType for AtLeastOneAllow<O> {
    fn get_validator_type(&self) -> ValidatorType {
        // Since [`Self`] can be constructed only with TODO it's always panic-safe
        let first = self
            .validators
            .first()
            .expect("Expected at least one validator for `AtLeastOneAllow` judge");

        first.get_validator_type()
    }
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

impl<O: NeedsPermission> GetValidatorType for NoDenies<O> {
    fn get_validator_type(&self) -> ValidatorType {
        // Since [`Self`] can be constructed only with
        // [`super::builder::WithJudge`] it's always panic-safe
        let first = self
            .validators
            .first()
            .expect("Expected at least one validator for `NoDenies` judge");

        first.get_validator_type()
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct AllowAll<O: NeedsPermission> {
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission> GetValidatorType for AllowAll<O> {
    fn get_validator_type(&self) -> ValidatorType {
        unimplemented!("Implementation `GetValidatorType` for `AllowAll` has no meaning")
    }
}

impl<O: NeedsPermission> Judge for AllowAll<O> {
    type Operation = O;

    fn judge(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
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
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DenyAll<O: NeedsPermission> {
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission> GetValidatorType for DenyAll<O> {
    fn get_validator_type(&self) -> ValidatorType {
        unimplemented!("Implementation `GetValidatorType` for `DenyAll` has no meaning")
    }
}

impl<O: NeedsPermission> Judge for DenyAll<O> {
    type Operation = O;

    fn judge(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> std::result::Result<(), DenialReason> {
        Err("All operations are denied.".to_owned().into())
    }
}
