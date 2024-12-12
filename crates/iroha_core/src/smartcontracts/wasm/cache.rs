use iroha_data_model::parameter::SmartContractParameters;
use wasmtime::{Engine, Module, Store};

use crate::{
    prelude::WorldReadOnly,
    smartcontracts::{
        wasm,
        wasm::{state::executor::ExecuteTransaction, RuntimeFull},
    },
    state::StateTransaction,
};

/// Executor related things (linker initialization, module instantiation, memory free)
/// takes significant amount of time in case of single peer transactions handling.
/// (https://github.com/hyperledger-iroha/iroha/issues/3716#issuecomment-2348417005).
/// So this cache is used to share `Store` and `Instance` for different transaction validation.
#[derive(Default)]
pub struct WasmCache<'world, 'block, 'state> {
    cache: Option<RuntimeFull<ExecuteTransaction<'world, 'block, 'state>>>,
}

impl<'world, 'block, 'state> WasmCache<'world, 'block, 'state> {
    /// Constructor
    pub fn new() -> Self {
        Self { cache: None }
    }

    /// Hack to pass borrow checker. Should be used only when there is no data in `Store`.
    #[allow(unsafe_code)]
    pub fn change_lifetime<'l>(wasm_cache: &'l mut WasmCache) -> &'l mut Self {
        if let Some(cache) = wasm_cache.cache.as_ref() {
            assert!(cache.store.data().is_none());
        }
        // SAFETY: since we have ensured that `cache.store.data()` is `None`,
        // the lifetime parameters we are transmuting are not used by any references.
        unsafe { std::mem::transmute::<&mut WasmCache, &mut WasmCache>(wasm_cache) }
    }

    /// Returns cached saved runtime, or creates a new one.
    ///
    /// # Errors
    /// If failed to create runtime
    pub fn take_or_create_cached_runtime(
        &mut self,
        state_transaction: &StateTransaction<'_, '_>,
        module: &Module,
    ) -> Result<RuntimeFull<ExecuteTransaction<'world, 'block, 'state>>, wasm::Error> {
        let parameters = state_transaction.world.parameters().executor;
        if let Some(cached_runtime) = self.cache.take() {
            if cached_runtime.runtime.config == parameters {
                return Ok(cached_runtime);
            }
        }

        Self::create_runtime(state_transaction.engine.clone(), module, parameters)
    }

    fn create_runtime(
        engine: Engine,
        module: &'_ Module,
        parameters: SmartContractParameters,
    ) -> Result<RuntimeFull<ExecuteTransaction<'world, 'block, 'state>>, wasm::Error> {
        let runtime = wasm::RuntimeBuilder::<ExecuteTransaction>::new()
            .with_engine(engine)
            .with_config(parameters)
            .build()?;
        let mut store = Store::new(&runtime.engine, None);
        let instance = runtime.instantiate_module(module, &mut store)?;
        let runtime_full = RuntimeFull {
            runtime,
            store,
            instance,
        };
        Ok(runtime_full)
    }

    /// Saves runtime to be reused later.
    pub fn put_cached_runtime(
        &mut self,
        runtime: RuntimeFull<ExecuteTransaction<'world, 'block, 'state>>,
    ) {
        assert!(runtime.store.data().is_none());
        self.cache = Some(runtime);
    }
}
