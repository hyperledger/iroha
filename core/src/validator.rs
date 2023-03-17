//! Structures and impls related to *runtime* `Validator`s processing.

use core::fmt::{self, Debug, Formatter};

use dashmap::DashMap;
use iroha_data_model::{
    permission::validator::{
        DenialReason, Id, NeedsPermission as _, NeedsPermissionBox, Type, Validator,
    },
    prelude::Account,
    Identifiable,
};
use iroha_logger::trace;
use iroha_primitives::must_use::MustUse;

use super::wsv::WorldStateView;
use crate::smartcontracts::wasm;

/// [`Chain`] error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// [`wasm`] module error.
    #[error("WASM error: {0}")]
    Wasm(#[from] wasm::Error),
    /// Validator denied the operation.
    #[error("Validator `{validator_id}` denied the operation `{operation}`: `{reason}`")]
    ValidatorDeny {
        /// Validator ID.
        validator_id: <Validator as Identifiable>::Id,
        /// Denial reason.
        reason: DenialReason,
        /// Denied operation.
        operation: NeedsPermissionBox,
    },
}

/// Result type for [`Chain`] operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Chain of *runtime* permission validators. Used to validate operations that require permissions.
///
/// Works similarly to the
/// [`Chain of responsibility`](https://en.wikipedia.org/wiki/Chain-of-responsibility_pattern).
/// The validation of an operation is forwarded to all
/// validators in the chain which have the required type.
/// The validation stops at the first
/// [`Deny`](iroha_data_model::permission::validator::Verdict::Deny) verdict.
#[derive(Clone)]
pub struct Chain {
    all_validators: DashMap<Id, LoadedValidator>,
    concrete_type_validators: DashMap<Type, Vec<Id>>,
    /// Engine for WASM [`Runtime`](wasm::Runtime) to execute validators.
    engine: wasmtime::Engine,
}

impl Debug for Chain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chain")
            .field("all_validators", &self.all_validators)
            .field("concrete_type_validators", &self.concrete_type_validators)
            .field("engine", &"<Engine is truncated>")
            .finish()
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self {
            all_validators: DashMap::default(),
            concrete_type_validators: DashMap::default(),
            engine: wasm::create_engine(),
        }
    }
}

/// [`Validator`] with [`Module`](wasmtime::Module) for execution.
///
/// Creating [`Module`] is expensive, so we do it once on [`add_validator()`](Chain::add_validator) step and reuse it on
/// [`validate()`](Chain::validate) step.
#[derive(Clone)]
struct LoadedValidator {
    id: Id,
    validator_type: Type,
    module: wasmtime::Module,
}

impl Debug for LoadedValidator {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedValidator")
            .field("id", &self.id)
            .field("validator_type", &self.validator_type)
            .field("module", &"<Module is truncated>")
            .finish()
    }
}

impl Chain {
    /// Construct new [`Chain`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Add new [`Validator`] to the [`Chain`].
    ///
    /// Returns `true` if the validator was added
    /// and `false` if a validator with the same id already exists.
    ///
    /// # Errors
    ///
    /// Fails if WASM module loading fails.
    pub fn add_validator(&self, validator: Validator) -> Result<MustUse<bool>> {
        use dashmap::mapref::entry::Entry::*;

        let id = validator.id.clone();
        let Vacant(vacant) = self.all_validators.entry(id.clone()) else {
            return Ok(MustUse(false));
        };

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

        let loaded_validator = LoadedValidator {
            id: validator.id,
            validator_type: validator.validator_type,
            module: wasm::load_module(&self.engine, validator.wasm)?,
        };

        vacant.insert(loaded_validator);
        Ok(MustUse(true))
    }

    /// Remove [`Validator`] from the [`Chain`].
    ///
    /// Return `true` if the validator was removed
    /// and `false` if no validator with the given id was found.
    #[allow(clippy::expect_used)]
    pub fn remove_validator(&self, id: &Id) -> bool {
        self.all_validators.get(id).map_or(false, |entry| {
            let type_ = &entry.validator_type;

            self.all_validators
                .remove(id)
                .and_then(|_| self.concrete_type_validators.get_mut(type_))
                .expect(
                    "Validator chain internal collections inconsistency error \
                         when removing a validator. This is a bug",
                )
                .retain(|validator_id| validator_id != id);
            true
        })
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
        authority: &<Account as Identifiable>::Id,
        operation: impl Into<NeedsPermissionBox>,
    ) -> Result<()> {
        let operation = operation.into();
        let Some(validators) = self
            .concrete_type_validators
            .get(&operation.required_validator_type()) else
        {
            return Ok(())
        };

        let runtime = wasm::RuntimeBuilder::new()
            .with_engine(self.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
            .with_configuration(wsv.config.wasm_runtime_config)
            .build()?;

        for validator_id in validators.value() {
            self.execute_validator(&runtime, wsv, authority, validator_id, &operation)?
        }

        Ok(())
    }

    /// Get constant view to the [`Chain`] without interior mutability
    pub fn view(&self) -> ChainView {
        ChainView { chain: self }
    }

    fn execute_validator(
        &self,
        runtime: &wasm::Runtime,
        wsv: &WorldStateView,
        authority: &<Account as Identifiable>::Id,
        validator_id: &iroha_data_model::permission::validator::Id,
        operation: &NeedsPermissionBox,
    ) -> Result<()> {
        let validator = self.all_validators.get(validator_id).expect(
            "Validator chain internal collections inconsistency error \
             when validating an operation. This is a bug",
        );

        trace!(%validator_id, "Running validator");
        let verdict = runtime.execute_permission_validator_module(
            wsv,
            authority,
            validator_id,
            &validator.module,
            operation,
        )?;

        Result::<(), DenialReason>::from(verdict).map_err(|reason| Error::ValidatorDeny {
            validator_id: validator_id.clone(),
            operation: operation.clone(),
            reason,
        })
    }
}

/// Constant view to the [`Chain`].
///
/// Provides [`Chain`] const methods without interior mutability.
#[derive(Debug, Copy, Clone)]
pub struct ChainView<'chain> {
    chain: &'chain Chain,
}

impl ChainView<'_> {
    /// Wrapper around [`Self::validate()`].
    ///
    /// # Errors
    /// See [`Chain::validate()`].
    pub fn validate(
        self,
        wsv: &WorldStateView,
        authority: &<Account as Identifiable>::Id,
        operation: impl Into<NeedsPermissionBox>,
    ) -> Result<()> {
        self.chain.validate(wsv, authority, operation)
    }
}
