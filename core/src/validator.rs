//! Structures and impls related to *runtime* `Validator`s processing.

use derive_more::DebugCustom;
#[cfg(test)]
use iroha_data_model::{
    isi::InstructionBox, transaction::Executable, validator::NeedsValidationBox,
};
use iroha_data_model::{prelude::Account, validator as data_model_validator, Identifiable};
use iroha_logger::trace;

use super::wsv::WorldStateView;
use crate::smartcontracts::wasm;

/// [`Chain`] error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// [`wasm`] module error.
    #[error("WASM error: {0}")]
    Wasm(#[from] wasm::Error),
    /// Validator denied the operation.
    #[error("Validator denied the operation `{operation}`: `{reason}`")]
    ValidatorDeny {
        /// Denial reason.
        reason: data_model_validator::DenialReason,
        /// Denied operation.
        operation: data_model_validator::NeedsValidationBox,
    },
}

/// Result type for [`Validator`] operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Validator that verifies the operation is valid.
///
/// Can be upgraded with [`Upgrade`](iroha_data_model::isi::Upgrade) instruction.
#[derive(DebugCustom, Clone)]
#[debug(
    fmt = "Validator {{ loaded_validator: {0:?}, engine: <Engine is truncated> }}",
    "&self.loaded_validator"
)]
pub struct Validator {
    /// Pre-loaded validator.
    /// Can be set with [`update()`](Validator::update).
    loaded_validator: LoadedValidator,
    /// Engine for WASM [`Runtime`](wasm::Runtime) to execute validators.
    engine: wasmtime::Engine,
}

impl Validator {
    /// Create new [`Validator`] from raw validator.
    ///
    /// # Errors
    ///
    /// Fails if failed to load wasm blob.
    pub fn new(raw_validator: data_model_validator::Validator) -> Result<Self> {
        let engine = wasm::create_engine();
        Ok(Self {
            loaded_validator: LoadedValidator::load(&engine, raw_validator)?,
            engine,
        })
    }

    /// Validate operation.
    ///
    /// # Errors
    ///
    /// - Failed to prepare runtime for WASM execution;
    /// - Failed to execute WASM blob;
    /// - Validator denied the operation
    pub fn validate(
        &self,
        wsv: &WorldStateView,
        authority: &<Account as Identifiable>::Id,
        operation: data_model_validator::NeedsValidationBox,
    ) -> Result<()> {
        let operation = operation;

        let runtime = wasm::RuntimeBuilder::new()
            .with_engine(self.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
            .with_configuration(wsv.config.wasm_runtime_config)
            .build()?;

        trace!("Running validator");
        let verdict = runtime.execute_validator_module(
            wsv,
            authority,
            &self.loaded_validator.module,
            &operation,
        )?;

        Result::<(), data_model_validator::DenialReason>::from(verdict).map_err(|reason| {
            Error::ValidatorDeny {
                operation: operation.clone(),
                reason,
            }
        })
    }
}

/// Mock of validator for unit tests of `iroha_core`.
///
/// We can't use real validator because WASM for it is produced in runtime from outside world.
#[cfg(test)]
#[derive(Default, Debug, Copy, Clone)]
pub struct MockValidator;

#[cfg(test)]
impl MockValidator {
    /// Mock for creating new validator from raw validator.
    ///
    /// # Errors
    ///
    /// Never fails with [`Err`].
    ///
    /// # Panics
    ///
    /// Will immediately panic, because you shouldn't call it in tests.
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(_raw_validator: data_model_validator::Validator) -> Result<Self> {
        panic!("You probably don't need this method in tests")
    }

    /// Mock for operation validation.
    /// Will just execute instructions if there are some.
    ///
    /// Without this step invalid transactions won't be marked as rejected in
    /// [`ChainedBlock::validate`].
    /// Real [`Validator`] assumes that internal WASM performs this.
    ///
    /// # Errors
    ///
    /// Never fails.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        clippy::trivially_copy_pass_by_ref,
        clippy::needless_pass_by_value
    )]
    pub fn validate(
        &self,
        wsv: &WorldStateView,
        authority: &<Account as Identifiable>::Id,
        operation: data_model_validator::NeedsValidationBox,
    ) -> Result<()> {
        match operation {
            NeedsValidationBox::Instruction(isi) => {
                Self::execute_instruction(wsv, authority.clone(), isi)
            }
            NeedsValidationBox::Transaction(tx) => {
                let Executable::Instructions(instructions) = tx.payload.instructions else {
                    return Ok(());
                };
                for isi in instructions {
                    Self::execute_instruction(wsv, authority.clone(), isi)?;
                }
                Ok(())
            }
            NeedsValidationBox::Query(_) => Ok(()),
        }
    }

    fn execute_instruction(
        wsv: &WorldStateView,
        authority: <Account as Identifiable>::Id,
        instruction: InstructionBox,
    ) -> Result<()> {
        use super::smartcontracts::Execute as _;

        instruction
            .clone()
            .execute(authority, wsv)
            .map_err(|err| Error::ValidatorDeny {
                reason: err.to_string(),
                operation: instruction.into(),
            })
    }
}

/// [`Validator`] with [`Module`](wasmtime::Module) for execution.
///
/// Creating [`Module`] is expensive, so we do it once on [`upgrade()`](Validator::upgrade)
/// step and reuse it on [`validate()`](Validator::validate) step.
#[derive(DebugCustom, Clone)]
#[debug(fmt = "LoadedValidator {{ module: <Module is truncated> }}")]
struct LoadedValidator {
    #[cfg_attr(test, allow(dead_code))]
    module: wasmtime::Module,
}

impl LoadedValidator {
    pub fn load(
        engine: &wasmtime::Engine,
        raw_validator: data_model_validator::Validator,
    ) -> Result<Self> {
        Ok(Self {
            module: wasm::load_module(engine, raw_validator.wasm)?,
        })
    }
}

/// Constant view to a [`Validator`] used by [`WorldStateView`].
///
/// Serves to the same purpose as [`RwLockReadGuard`](parking_lot::RwLockReadGuard),
/// but holds [`Option`] instead of [`Validator`].
/// That is required because [`WorldStateView`] may have uninitialized [`Validator`].
/// However we still want to provide direct access to [`Validator`] for users, so that they
/// don't have to deal with [`Option`].
///
/// # Panic
///
/// That said, [`new()`](Self::new) and [`deref()`](std::ops::Deref::deref) will panic if option is [`None`].
#[derive(Debug)]
pub struct View<'validator>(
    #[cfg(not(test))] parking_lot::RwLockReadGuard<'validator, Option<Validator>>,
    #[cfg(test)] parking_lot::RwLockReadGuard<'validator, Option<MockValidator>>,
);

#[cfg_attr(test, allow(single_use_lifetimes))]
impl<'validator> View<'validator> {
    /// Construct new [`View`].
    /// Make sure that Option is [`Some`] before calling this function.
    ///
    /// # Panic
    ///
    /// This function will panic if provided `rw_lock_guard` contains [`None`].
    pub(crate) fn new(
        #[cfg(not(test))] rw_lock_guard: parking_lot::RwLockReadGuard<
            'validator,
            Option<Validator>,
        >,
        #[cfg(test)] rw_lock_guard: parking_lot::RwLockReadGuard<'validator, Option<MockValidator>>,
    ) -> Self {
        assert!(
            rw_lock_guard.is_some(),
            "Validator must be initialized at that moment"
        );
        Self(rw_lock_guard)
    }
}

impl std::ops::Deref for View<'_> {
    #[cfg(not(test))]
    type Target = Validator;

    #[cfg(test)]
    type Target = MockValidator;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("Validator must be initialized at that moment")
    }
}
