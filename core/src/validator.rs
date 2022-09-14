//! Structures and impls related to *runtime* `Validator`s processing.

use dashmap::DashMap;
use iroha_data_model::{
    permission::validator::{
        DenialReason, Id, NeedsPermission as _, NeedsPermissionBox, Type, Validator,
    },
    Identifiable as _,
};

use super::wsv::WorldStateView;
use crate::smartcontracts::wasm;

/// Chain of *runtime* validators. Used to validate operations that require permissions.
///
/// Works similarly to the
/// [`Chain of responsibility`](https://en.wikipedia.org/wiki/Chain-of-responsibility_pattern).
/// The validation of an operation is forwarded to all
/// validators in the chain which have the required type.
/// The validation stops at the first
/// [`Deny`](iroha_data_model::permission::validator::Verdict::Deny) verdict.
#[derive(Debug, Default, Clone)]
pub struct Chain {
    all_validators: DashMap<Id, Validator>,
    concrete_type_validators: DashMap<Type, Vec<Id>>,
}

impl Chain {
    /// Construct new [`Chain`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Add new [`Validator`] to the [`Chain`].
    ///
    /// Return `true` if the validator was added
    /// and `false` if a validator with the same id already exists.
    pub fn add_validator(&self, validator: Validator) -> bool {
        use dashmap::mapref::entry::Entry::*;

        let id = validator.id().clone();
        match self.all_validators.entry(id.clone()) {
            Occupied(_) => false,
            Vacant(vacant) => {
                match self
                    .concrete_type_validators
                    .entry(*validator.validator_type())
                {
                    Occupied(mut occupied) => {
                        occupied.get_mut().push(id);
                    }
                    Vacant(concrete_type_vacant) => {
                        concrete_type_vacant.insert(vec![id]);
                    }
                }
                vacant.insert(validator);
                true
            }
        }
    }

    /// Remove [`Validator`] from the [`Chain`].
    ///
    /// Return `true` if the validator was removed
    /// and `false` if no validator with the given id was found.
    #[allow(clippy::expect_used)]
    pub fn remove_validator(&self, id: &Id) -> bool {
        match self.all_validators.get(id) {
            Some(entry) => {
                let type_ = entry.validator_type();
                self.all_validators
                    .remove(id)
                    .and_then(|_| self.concrete_type_validators.get_mut(type_))
                    .expect(
                        "Validator chain internal collections inconsistency error \
                         when removing a validator. This is a bug",
                    )
                    .retain(|validator_id| validator_id != id);
                true
            }
            None => false,
        }
    }

    /// Validate given `operation` with all [`Chain`] validators of required type.
    ///
    /// If no validator with required type is found, then return [`Ok`].
    ///
    /// # Errors
    ///
    /// Will abort the validation at first
    /// [`Deny`](iroha_data_model::permission::validator::Verdict::Deny) validator verdict and
    /// return an [`Err`](Result::Err).
    ///
    // TODO: Possibly we can use a separate validator thread
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub fn validate(
        &self,
        wsv: &WorldStateView,
        operation: impl Into<NeedsPermissionBox>,
    ) -> Result<(), DenialReason> {
        let operation = operation.into();
        let validators = match self
            .concrete_type_validators
            .get(&operation.required_validator_type())
        {
            Some(validators) => validators,
            None => return Ok(()),
        };

        for validator_id in validators.value() {
            let validator = self.all_validators.get(validator_id).expect(
                "Validator chain internal collections inconsistency error \
                 when validating an operation. This is a bug",
            );
            Self::execute_validator(validator.value(), wsv, operation.clone()).map_err(|err| {
                format!(
                    "Validator `{}` denied the operation `{operation}`: `{err}`",
                    validator_id,
                )
            })?
        }

        Ok(())
    }

    /// Get constant view to the [`Chain`] without interior mutability
    pub fn view(&self) -> ChainView {
        ChainView { chain: self }
    }

    fn execute_validator(
        validator: &Validator,
        wsv: &WorldStateView,
        operation: NeedsPermissionBox,
    ) -> Result<(), DenialReason> {
        let mut runtime = wasm::Runtime::from_configuration(wsv.config.wasm_runtime_config)
            .map_err(|err| format!("Can't create WASM runtime: {err}"))?;
        runtime
            .execute_permission_validator(
                wsv,
                validator.id().account_id.clone(),
                validator.wasm(),
                operation,
            )
            .map_err(|err| format!("Failure during validator execution: {err}"))?
            .into()
    }
}

/// Constant view to the [`Chain`].
///
/// Provides [`Chain`] const methods without interior mutability.
#[derive(Debug, Copy, Clone)]
pub struct ChainView<'chain> {
    chain: &'chain Chain,
}

impl<'chain> ChainView<'chain> {
    /// Wrapper around [`Self::validate()`].
    ///
    /// # Errors
    /// See [`Chain::validate()`].
    pub fn validate(
        self,
        wsv: &WorldStateView,
        operation: impl Into<NeedsPermissionBox>,
    ) -> Result<(), DenialReason> {
        self.chain.validate(wsv, operation)
    }
}
