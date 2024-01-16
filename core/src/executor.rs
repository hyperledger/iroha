//! Structures and impls related to *runtime* `Executor`s processing.

use derive_more::DebugCustom;
use iroha_data_model::{
    account::AccountId,
    executor as data_model_executor,
    isi::InstructionBox,
    query::QueryBox,
    transaction::{Executable, SignedTransaction},
    ValidationFail,
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
                    HostExecution(error) | Other(error) => {
                        Self::InternalError(format!("{error:#}"))
                    }
                }
            }
            _ => Self::InternalError(format!("{err:#}")),
        }
    }
}

/// Error used in [`migrate()`](Executor::migrate).
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// Error during WASM blob loading or runtime preparation.
    #[error("WASM error: {0}")]
    Wasm(#[from] wasm::error::Error),
    /// Error returned by entrypoint during execution.
    #[error("Entrypoint returned error: {0}")]
    EntrypointExecution(data_model_executor::MigrationError),
}

/// Executor that verifies that operation is valid and executes it.
///
/// Executing is done in order to verify dependent instructions in transaction.
/// So in fact it's more like an **Executor**, and it probably will be renamed soon.
///
/// Can be upgraded with [`Upgrade`](iroha_data_model::isi::Upgrade) instruction.
#[derive(Debug, Default, Clone, Serialize)]
pub enum Executor {
    /// Initial executor that allows all operations and performs no permission checking.
    #[default]
    Initial,
    /// User-provided executor with arbitrary logic.
    UserProvided(UserProvidedExecutor),
}

/// Executor provided by user.
///
/// Used to not to leak private data to the user.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct UserProvidedExecutor(LoadedExecutor);

impl<'de> DeserializeSeed<'de> for WasmSeed<'_, Executor> {
    type Value = Executor;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ExecutorVisitor<'l> {
            loader: &'l WasmSeed<'l, Executor>,
        }

        #[derive(Deserialize)]
        #[serde(variant_identifier)]
        enum Field {
            Initial,
            UserProvided,
        }

        impl<'de> Visitor<'de> for ExecutorVisitor<'_> {
            type Value = Executor;

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
                        Ok(Executor::Initial)
                    }
                    ("UserProvided", variant) => {
                        let loaded =
                            variant.newtype_variant_seed(self.loader.cast::<LoadedExecutor>())?;
                        Ok(Executor::UserProvided(UserProvidedExecutor(loaded)))
                    }
                    (other, _) => Err(serde::de::Error::unknown_variant(
                        other,
                        &["Initial", "UserProvided"],
                    )),
                }
            }
        }

        deserializer.deserialize_enum(
            "Executor",
            &["Initial", "UserProvided"],
            ExecutorVisitor { loader: &self },
        )
    }
}

impl Executor {
    /// Validate [`SignedTransaction`].
    ///
    /// # Errors
    ///
    /// - Failed to prepare runtime for WASM execution;
    /// - Failed to execute the entrypoint of the WASM blob;
    /// - Executor denied the operation.
    pub fn validate_transaction(
        &self,
        wsv: &mut WorldStateView,
        authority: &AccountId,
        transaction: SignedTransaction,
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
            Self::UserProvided(UserProvidedExecutor(loaded_executor)) => {
                let runtime =
                    wasm::RuntimeBuilder::<wasm::state::executor::ValidateTransaction>::new()
                    .with_engine(wsv.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
                    .with_configuration(wsv.config.wasm_runtime)
                    .build()?;

                runtime.execute_executor_validate_transaction(
                    wsv,
                    authority,
                    &loaded_executor.module,
                    transaction,
                )?
            }
        }
    }

    /// Validate [`InstructionExpr`].
    ///
    /// # Errors
    ///
    /// - Failed to prepare runtime for WASM execution;
    /// - Failed to execute the entrypoint of the WASM blob;
    /// - Executor denied the operation.
    pub fn validate_instruction(
        &self,
        wsv: &mut WorldStateView,
        authority: &AccountId,
        instruction: InstructionBox,
    ) -> Result<(), ValidationFail> {
        trace!("Running instruction validation");

        match self {
            Self::Initial => instruction.execute(authority, wsv).map_err(Into::into),
            Self::UserProvided(UserProvidedExecutor(loaded_executor)) => {
                let runtime =
                    wasm::RuntimeBuilder::<wasm::state::executor::ValidateInstruction>::new()
                    .with_engine(wsv.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
                    .with_configuration(wsv.config.wasm_runtime)
                    .build()?;

                runtime.execute_executor_validate_instruction(
                    wsv,
                    authority,
                    &loaded_executor.module,
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
    /// - Executor denied the operation.
    pub fn validate_query(
        &self,
        wsv: &WorldStateView,
        authority: &AccountId,
        query: QueryBox,
    ) -> Result<(), ValidationFail> {
        trace!("Running query validation");

        match self {
            Self::Initial => Ok(()),
            Self::UserProvided(UserProvidedExecutor(loaded_executor)) => {
                let runtime = wasm::RuntimeBuilder::<wasm::state::executor::ValidateQuery>::new()
                    .with_engine(wsv.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
                    .with_configuration(wsv.config.wasm_runtime)
                    .build()?;

                runtime.execute_executor_validate_query(
                    wsv,
                    authority,
                    &loaded_executor.module,
                    query,
                )?
            }
        }
    }

    /// Migrate executor to a new user-provided one.
    ///
    /// Execute `migrate()` entrypoint of the `raw_executor` and set `self` to
    /// [`UserProvided`](Executor::UserProvided) with `raw_executor`.
    ///
    /// # Errors
    ///
    /// - Failed to load `raw_executor`;
    /// - Failed to prepare runtime for WASM execution;
    /// - Failed to execute entrypoint of the WASM blob.
    pub fn migrate(
        &mut self,
        raw_executor: data_model_executor::Executor,
        wsv: &mut WorldStateView,
        authority: &AccountId,
    ) -> Result<(), MigrationError> {
        trace!("Running executor migration");

        let loaded_executor = LoadedExecutor::load(&wsv.engine, raw_executor)?;

        let runtime = wasm::RuntimeBuilder::<wasm::state::executor::Migrate>::new()
            .with_engine(wsv.engine.clone()) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
            .with_configuration(wsv.config.wasm_runtime)
            .build()?;

        runtime
            .execute_executor_migration(wsv, authority, &loaded_executor.module)?
            .map_err(MigrationError::EntrypointExecution)?;

        *self = Self::UserProvided(UserProvidedExecutor(loaded_executor));
        Ok(())
    }
}

/// [`Executor`] with [`Module`](wasmtime::Module) for execution.
///
/// Creating a [`wasmtime::Module`] is expensive, so we do it once on [`migrate()`](Executor::migrate)
/// step and reuse it later on validating steps.
#[derive(DebugCustom, Clone, Serialize)]
#[debug(fmt = "LoadedExecutor {{ module: <Module is truncated> }}")]
struct LoadedExecutor {
    #[serde(skip)]
    module: wasmtime::Module,
    raw_executor: data_model_executor::Executor,
}

impl LoadedExecutor {
    pub fn load(
        engine: &wasmtime::Engine,
        raw_executor: data_model_executor::Executor,
    ) -> Result<Self, wasm::error::Error> {
        Ok(Self {
            module: wasm::load_module(engine, &raw_executor.wasm)?,
            raw_executor,
        })
    }
}

impl<'de> DeserializeSeed<'de> for WasmSeed<'_, LoadedExecutor> {
    type Value = LoadedExecutor;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LoadedExecutorVisitor<'l> {
            loader: &'l WasmSeed<'l, LoadedExecutor>,
        }

        impl<'de> Visitor<'de> for LoadedExecutorVisitor<'_> {
            type Value = LoadedExecutor;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct LoadedExecutor")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                while let Some(key) = map.next_key::<String>()? {
                    if key.as_str() == "raw_executor" {
                        let executor: data_model_executor::Executor = map.next_value()?;
                        return Ok(LoadedExecutor::load(self.loader.engine, executor).unwrap());
                    }
                }
                Err(serde::de::Error::missing_field("raw_executor"))
            }
        }

        deserializer.deserialize_struct(
            "LoadedExecutor",
            &["raw_executor"],
            LoadedExecutorVisitor { loader: &self },
        )
    }
}
