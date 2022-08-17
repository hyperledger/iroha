//! Structures and impls related to *runtime* `Validator`s processing.

use dashmap::DashMap;
use iroha_data_model::{
    permission::validator::{DenialReason, Id, NeedsPermissionBox, Validator},
    Identifiable as _,
};

use super::wsv::WorldStateView;
use crate::smartcontracts::wasm;

/// Chain of *runtime* validators. Used to validate operations, which needs permissions.
///
/// Works pretty like [`Chain of responsibility`](https://en.wikipedia.org/wiki/Chain-of-responsibility_pattern).
/// Forwards validating operation to all validators in the chain,
/// stopping at the first [`Deny`](iroha_data_model::permission::validator::Verdict::Deny) verdict.
#[derive(Debug, Default, Clone)]
pub struct Chain {
    validators: DashMap<Id, Validator>,
}

impl Chain {
    /// Construct new [`Chain`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Add new [`Validator`] to the [`Chain`].
    ///
    /// Return `true` if validator was added
    /// and `false` if validator with the same id already exists.
    pub fn add_validator(&self, validator: Validator) -> bool {
        use dashmap::mapref::entry::Entry::*;

        match self.validators.entry(validator.id().clone()) {
            Occupied(_) => false,
            Vacant(vacant) => {
                vacant.insert(validator);
                true
            }
        }
    }

    /// Remove [`Validator`] from the [`Chain`].
    ///
    /// Return `true` if validator was removed
    /// and `false` if no validator with the given id was found.
    pub fn remove_validator(&self, id: &Id) -> bool {
        self.validators.remove(id).is_some()
    }

    /// Validate given `operation` with all validators in the [`Chain`].
    ///
    /// # Errors
    ///
    /// Will abort the validation at first
    /// [`Deny`](iroha_data_model::permission::validator::Verdict::Deny) validator verdict and
    /// return an [`Err`](Result::Err).
    pub fn validate(
        &self,
        wsv: &WorldStateView,
        operation: impl Into<NeedsPermissionBox>,
    ) -> Result<(), DenialReason> {
        let operation = operation.into();

        for id_and_validator in &self.validators {
            Self::execute_validator(id_and_validator.value(), wsv, operation.clone()).map_err(
                |err| {
                    format!(
                        "Validator `{}` denied the operation `{operation}`: `{err}`",
                        id_and_validator.key()
                    )
                },
            )?
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
    /// Wrapper around [`Chain::validate`].
    ///
    /// # Errors
    /// See [`Chain::validate`].
    pub fn validate(
        self,
        wsv: &WorldStateView,
        operation: impl Into<NeedsPermissionBox>,
    ) -> Result<(), DenialReason> {
        self.chain.validate(wsv, operation)
    }
}
