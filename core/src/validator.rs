//! Structures and impls related to *runtime* `Validator`s processing.

use derive_more::DebugCustom;
use iroha_data_model::{
    account::AccountId,
    isi::InstructionBox,
    query::QueryBox,
    transaction::{Executable, VersionedSignedTransaction},
    validator as data_model_validator, ValidationFail,
};
use iroha_logger::trace;
use serde::{
    de::{DeserializeSeed, MapAccess, VariantAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};

use crate::{
    smartcontracts::{wasm, Execute as _},
    wsv::{WasmSeed, WorldStateView},
};

impl From<wasm::error::Error> for ValidationFail {
    fn from(err: wasm::error::Error) -> Self {
        match err {
            wasm::error::Error::ExportFnCall(call_error) => {
                use wasm::error::ExportFnCallError::*;

                match call_error {
                    ExecutionLimitsExceeded(_) => Self::TooComplex,
                    HostExecution(error) | Other(error) => Self::InternalError(error.to_string()),
                }
            }
            _ => Self::InternalError(err.to_string()),
        }
    }
}

/// Error used in [`migrate()`](Validator::migrate).
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// Error during WASM blob loading or runtime preparation.
    #[error("WASM error: {0}")]
    Wasm(#[from] wasm::error::Error),
    /// Error returned by entrypoint during execution.
    #[error("Entrypoint returned error: {0}")]
    EntrypointExecution(data_model_validator::MigrationError),
}

/// Validator that verifies that operation is valid and executes it.
///
/// Executing is done in order to verify dependent instructions in transaction.
/// So in fact it's more like an **Executor**, and it probably will be renamed soon.
///
/// Can be upgraded with [`Upgrade`](iroha_data_model::isi::Upgrade) instruction.
#[derive(Debug, Default, Clone, Serialize)]
pub enum Validator {
    /// Initial validator that allows all operations and performs no permission checking.
    #[default]
    Initial,
    /// User-provided validator with arbitrary logic.
    UserProvided(UserProvidedValidator),
}

/// Validator provided by user.
///
/// Used to not to leak private data to the user.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct UserProvidedValidator(LoadedValidator);

impl<'de> DeserializeSeed<'de> for WasmSeed<'_, Validator> {
    type Value = Validator;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValidatorVisitor<'l> {
            loader: &'l WasmSeed<'l, Validator>,
        }

        #[derive(Deserialize)]
        #[serde(variant_identifier)]
        enum Field {
            Initial,
            UserProvided,
        }

        impl<'de> Visitor<'de> for ValidatorVisitor<'_> {
            type Value = Validator;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an enum variant")
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::EnumAccess<'de>,
            {
                match data.variant()? {
                    ("Initial", variant) => {
                        variant.unit_variant()?;
                        Ok(Validator::Initial)
                    }
                    ("UserProvided", variant) => {
                        let loaded =
                            variant.newtype_variant_seed(self.loader.cast::<LoadedValidator>())?;
                        Ok(Validator::UserProvided(UserProvidedValidator(loaded)))
                    }
                    (other, _) => Err(serde::de::Error::unknown_variant(
                        other,
                        &["Initial", "UserProvided"],
                    )),
                }
            }
        }

        deserializer.deserialize_enum(
            "Validator",
            &["Initial", "UserProvided"],
            ValidatorVisitor { loader: &self },
        )
    }
}

impl Validator {
    /// Validate [`VersionedSignedTransaction`].
    ///
    /// # Errors
    ///
    /// - Failed to prepare runtime for WASM execution;
    /// - Failed to execute the entrypoint of the WASM blob;
    /// - Validator denied the operation.
    pub fn validate_transaction(
        &self,
        wsv: &mut WorldStateView,
        authority: &AccountId,
        transaction: VersionedSignedTransaction,
    ) -> Result<(), ValidationFail> {
        trace!("Running transaction validation");

        match self {
            Self::Initial => {
                let (_authority, Executable::Instructions(instructions)) = transaction.into()
                else {
                    return Ok(());
                };
                for isi in instructions {
                    isi.execute(authority, wsv)?
                }
                Ok(())
            }
            Self::UserProvided(UserProvidedValidator(loaded_validator)) => {
                let runtime =
                    wasm::RuntimeBuilder::<wasm::state::validator::ValidateTransaction>::new()
                    .with_engine(wsv.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
                    .with_configuration(wsv.config.wasm_runtime_config)
                    .build()?;

                runtime.execute_validator_validate_transaction(
                    wsv,
                    authority,
                    &loaded_validator.module,
                    transaction,
                )?
            }
        }
    }

    /// Validate [`InstructionBox`].
    ///
    /// # Errors
    ///
    /// - Failed to prepare runtime for WASM execution;
    /// - Failed to execute the entrypoint of the WASM blob;
    /// - Validator denied the operation.
    pub fn validate_instruction(
        &self,
        wsv: &mut WorldStateView,
        authority: &AccountId,
        instruction: InstructionBox,
    ) -> Result<(), ValidationFail> {
        trace!("Running instruction validation");

        match self {
            Self::Initial => instruction.execute(authority, wsv).map_err(Into::into),
            Self::UserProvided(UserProvidedValidator(loaded_validator)) => {
                let runtime =
                    wasm::RuntimeBuilder::<wasm::state::validator::ValidateInstruction>::new()
                    .with_engine(wsv.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
                    .with_configuration(wsv.config.wasm_runtime_config)
                    .build()?;

                runtime.execute_validator_validate_instruction(
                    wsv,
                    authority,
                    &loaded_validator.module,
                    instruction,
                )?
            }
        }
    }

    /// Validate [`QueryBox`].
    ///
    /// # Errors
    ///
    /// - Failed to prepare runtime for WASM execution;
    /// - Failed to execute the entrypoint of the WASM blob;
    /// - Validator denied the operation.
    pub fn validate_query(
        &self,
        wsv: &WorldStateView,
        authority: &AccountId,
        query: QueryBox,
    ) -> Result<(), ValidationFail> {
        trace!("Running query validation");

        match self {
            Self::Initial => Ok(()),
            Self::UserProvided(UserProvidedValidator(loaded_validator)) => {
                let runtime = wasm::RuntimeBuilder::<wasm::state::validator::ValidateQuery>::new()
                    .with_engine(wsv.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
                    .with_configuration(wsv.config.wasm_runtime_config)
                    .build()?;

                runtime.execute_validator_validate_query(
                    wsv,
                    authority,
                    &loaded_validator.module,
                    query,
                )?
            }
        }
    }

    /// Migrate validator to a new user-provided one.
    ///
    /// Execute `migrate()` entrypoint of the `raw_validator` and set `self` to
    /// [`UserProvided`](Validator::UserProvided) with `raw_validator`.
    ///
    /// # Errors
    ///
    /// - Failed to load `raw_validator`;
    /// - Failed to prepare runtime for WASM execution;
    /// - Failed to execute entrypoint of the WASM blob.
    pub fn migrate(
        &mut self,
        raw_validator: data_model_validator::Validator,
        wsv: &mut WorldStateView,
        authority: &AccountId,
    ) -> Result<(), MigrationError> {
        trace!("Running validator migration");

        let loaded_validator = LoadedValidator::load(&wsv.engine, raw_validator)?;

        let runtime = wasm::RuntimeBuilder::<wasm::state::validator::Migrate>::new()
            .with_engine(wsv.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
            .with_configuration(wsv.config.wasm_runtime_config)
            .build()?;

        runtime
            .execute_validator_migration(wsv, authority, &loaded_validator.module)?
            .map_err(MigrationError::EntrypointExecution)?;

        *self = Self::UserProvided(UserProvidedValidator(loaded_validator));
        Ok(())
    }
}

/// [`Validator`] with [`Module`](wasmtime::Module) for execution.
///
/// Creating a [`wasmtime::Module`] is expensive, so we do it once on [`migrate()`](Validator::migrate)
/// step and reuse it later on validating steps.
#[derive(DebugCustom, Clone, Serialize)]
#[debug(fmt = "LoadedValidator {{ module: <Module is truncated> }}")]
struct LoadedValidator {
    #[serde(skip)]
    module: wasmtime::Module,
    raw_validator: data_model_validator::Validator,
}

impl LoadedValidator {
    pub fn load(
        engine: &wasmtime::Engine,
        raw_validator: data_model_validator::Validator,
    ) -> Result<Self, wasm::error::Error> {
        Ok(Self {
            module: wasm::load_module(engine, &raw_validator.wasm)?,
            raw_validator,
        })
    }
}

impl<'de> DeserializeSeed<'de> for WasmSeed<'_, LoadedValidator> {
    type Value = LoadedValidator;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LoadedValidatorVisitor<'l> {
            loader: &'l WasmSeed<'l, LoadedValidator>,
        }

        impl<'de> Visitor<'de> for LoadedValidatorVisitor<'_> {
            type Value = LoadedValidator;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct LoadedValidator")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                while let Some(key) = map.next_key::<String>()? {
                    if key.as_str() == "raw_validator" {
                        let validator: data_model_validator::Validator = map.next_value()?;
                        return Ok(LoadedValidator::load(self.loader.engine, validator).unwrap());
                    }
                }
                Err(serde::de::Error::missing_field("raw_validator"))
            }
        }

        deserializer.deserialize_struct(
            "LoadedValidator",
            &["raw_validator"],
            LoadedValidatorVisitor { loader: &self },
        )
    }
}
