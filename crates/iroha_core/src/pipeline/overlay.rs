//! One-shot transaction effects with ordered instructions, native emissions and authorization.
//!
//! Applying an overlay consumes its original effect owners. Emission graphs retain their
//! allocation custody through the transaction journal and cannot be cloned for replay.
#[cfg(any(test, feature = "iroha-core-tests"))]
use crate::smartcontracts::ivm::cache::{
    ExecutableProgramSummary, GenericProgramSummary, IvmCache,
};
use crate::{
    executor::{
        ContractEntrypointAuthorizationSnapshot, ensure_asset_definition_registration_allowed,
        extract_register_asset_definition,
    },
    smartcontracts::{
        code,
        isi::settlement::{
            admission_validate_atomic, admission_validate_dvp, admission_validate_fx_corridor,
            admission_validate_pvp,
        },
        ivm::{
            cache::ProgramSummary,
            host::{AmxBudgetViolation, QueryStateSource, QueuedEffectPayload},
        },
    },
    state::{StateReadOnly, StateTransaction, WorldReadOnly},
    streaming,
};
use core::str::FromStr;
use iroha_config::parameters::actual::QueryCursorMode;
use iroha_crypto::{Hash, streaming::TransportCapabilityResolutionSnapshot};
#[cfg(test)]
use iroha_data_model::block::BlockHeader;
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_data_model::isi::smart_contract_code::ActivateContractInstance;
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_data_model::transaction::executable::ContractInvocation;
use iroha_data_model::{
    errors::CanonicalErrorKind,
    executor::{IvmAdmissionError, ManifestCodeHashMismatchInfo},
    isi::{
        InstructionBox,
        settlement::{DvpIsi, PvpIsi, SettleAtomic, SettleFxCorridor, SettlementInstructionBox},
        smart_contract_code::{RegisterSmartContractBytes, RegisterSmartContractCode},
    },
    nexus::AxtRejectContext,
    prelude::{AccountId, ValidationFail},
    smart_contract::manifest::{ContractManifest, MANIFEST_METADATA_KEY},
    smart_contract::{ContractAddress, ContractArtifactId},
    transaction::{Executable, SignedTransaction, signed::TransactionPayload},
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::{name::Name, state_path::StatePath};
#[cfg(any(test, feature = "iroha-core-tests"))]
use ivm::host::IVMHost;
use ivm::{VMError as IvmError, analysis::ProgramAnalysisError};
use mv::storage::StorageReadOnly;
use norito::{codec::Encode as NoritoEncode, streaming::CapabilityFlags};
#[cfg(test)]
use sha2::{Digest as _, Sha256};
#[cfg(any(test, feature = "iroha-core-tests"))]
use std::mem;
#[cfg(all(test, feature = "telemetry"))]
use std::time::Instant;
use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    sync::{Arc, OnceLock},
};
#[cfg(test)]
use std::{
    collections::{BTreeSet, VecDeque},
    sync::{LazyLock, Mutex},
};
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StreamingOverlayMetadata {
    transport: Option<TransportCapabilityResolutionSnapshot>,
    negotiated: Option<CapabilityFlags>,
}
#[cfg(test)]
#[derive(Default)]
struct ProgramHashCache {
    map: BTreeMap<Hash, Hash>,
    order: VecDeque<Hash>,
    cap: usize,
}
#[cfg(test)]
impl ProgramHashCache {
    const DEFAULT_CAP: usize = 64;
    fn new(cap: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }
    fn get_or_insert(&mut self, code_hash: Hash, abi_hash: Hash) -> Hash {
        if let Some(stored) = self.map.get(&code_hash) {
            return *stored;
        }
        self.map.insert(code_hash, abi_hash);
        self.order.push_back(code_hash);
        if self.order.len() > self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.map.remove(&evicted);
            }
        }
        abi_hash
    }
}
#[cfg(test)]
static PROGRAM_HASH_CACHE: LazyLock<Mutex<ProgramHashCache>> =
    LazyLock::new(|| Mutex::new(ProgramHashCache::new(ProgramHashCache::DEFAULT_CAP)));
#[derive(Clone, Debug)]
struct ContractCallExecutionContext {
    entrypoint: Option<String>,
    entrypoint_pc: Option<u64>,
    argument_record: Option<ivm::PreparedArgumentRecord>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct OverlayLifecycleCompletion {
    contract_address: ContractAddress,
    pending: code::PendingContractLifecycle,
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn smart_contract_heap_limit(state: &impl StateReadOnly) -> u64 {
    state.world().parameters().smart_contract().memory().get()
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn configure_zk_lane_trace_collection(vm: &mut ivm::IVM, trace_enabled: bool) {
    vm.set_zk_trace_enabled(trace_enabled && vm.zk_mode_enabled());
}
fn validate_overlay_contract_runtime_context(
    world: &impl WorldReadOnly,
    context: &crate::executor::ContractRuntimeExecutionContext,
) -> Result<(), ValidationFail> {
    let live_subject = world
        .contract_subject_bindings()
        .get(&context.contract_address)
        .ok_or_else(|| {
            ValidationFail::NotPermitted(format!(
                "contract instance `{}` has no subject binding",
                context.contract_address
            ))
        })?;
    live_subject
        .validate_for(&context.contract_address)
        .map_err(ValidationFail::NotPermitted)?;
    if context.contract_subject != live_subject.subject {
        return Err(ValidationFail::NotPermitted(
            "prepared contract runtime context has an invalid subject binding".to_owned(),
        ));
    }
    if world
        .contract_instances()
        .get(&context.contract_address)
        .is_none()
    {
        return Err(ValidationFail::NotPermitted(format!(
            "contract instance `{}` is no longer active",
            context.contract_address
        )));
    }
    let live_alias = world
        .contract_alias_bindings()
        .get(&context.contract_address)
        .map(|binding| binding.alias.clone());
    if live_alias != context.contract_alias {
        return Err(ValidationFail::NotPermitted(format!(
            "contract instance `{}` changed alias binding while its effects were prepared",
            context.contract_address
        )));
    }
    if let Some(alias) = live_alias
        && world.contract_aliases().get(&alias) != Some(&context.contract_address)
    {
        return Err(ValidationFail::NotPermitted(format!(
            "contract instance `{}` has an inconsistent live alias binding",
            context.contract_address
        )));
    }
    Ok(())
}
enum ContractDispatchSource<'a> {
    Bytecode(&'a [u8]),
    #[cfg(any(test, feature = "iroha-core-tests"))]
    Prepared(&'a ivm::PreparedContract),
}
impl ContractDispatchSource<'_> {
    fn is_self_describing(&self) -> Result<bool, OverlayBuildError> {
        match self {
            Self::Bytecode(bytecode) => ivm::ProgramMetadata::parse(bytecode)
                .map(|parsed| parsed.contract_interface.is_some())
                .map_err(|err| {
                    OverlayBuildError::ContractCall(format!(
                        "invalid contract artifact for contract call dispatch: {err}"
                    ))
                }),
            #[cfg(any(test, feature = "iroha-core-tests"))]
            Self::Prepared(_) => Ok(true),
        }
    }
    fn callable_entrypoint(
        &self,
        selector: &str,
    ) -> Result<
        (
            u64,
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1,
            Option<ivm::EntrypointArgumentSchemaV1>,
        ),
        OverlayBuildError,
    > {
        match self {
            Self::Bytecode(bytecode) => {
                let parsed = ivm::ProgramMetadata::parse(bytecode).map_err(|err| {
                    OverlayBuildError::ContractCall(format!(
                        "invalid contract artifact for contract call dispatch: {err}"
                    ))
                })?;
                let prefix_len = parsed.prefix_len() as u64;
                let contract_interface = parsed.contract_interface.as_ref().ok_or_else(|| {
                    OverlayBuildError::ContractCall(
                        "contract call entrypoint metadata requires a self-describing contract artifact"
                            .to_owned(),
                    )
                })?;
                let descriptor = contract_interface
                    .entrypoints
                    .iter()
                    .find(|candidate| candidate.name == selector)
                    .ok_or_else(|| {
                        OverlayBuildError::ContractCall(format!(
                            "unknown contract entrypoint `{selector}`"
                        ))
                    })?;
                let permission =
                    crate::executor::raw_contract_entrypoint_authorization(descriptor, selector)
                        .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
                Ok((
                    prefix_len + descriptor.entry_pc,
                    permission,
                    descriptor.argument_schema.clone(),
                ))
            }
            #[cfg(any(test, feature = "iroha-core-tests"))]
            Self::Prepared(contract) => {
                let descriptor = contract.entrypoint_descriptor(selector).ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "unknown contract entrypoint `{selector}`"
                    ))
                })?;
                let entrypoint_pc = contract.entrypoint_pc(selector).ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract entrypoint `{selector}` has no validated program counter"
                    ))
                })?;
                let permission =
                    crate::executor::raw_contract_entrypoint_authorization(descriptor, selector)
                        .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
                Ok((
                    entrypoint_pc,
                    permission,
                    descriptor.argument_schema.clone(),
                ))
            }
        }
    }
}
fn parse_raw_contract_call_execution_context(
    metadata: &iroha_model_base::metadata::Metadata,
    bytecode: &[u8],
    gas_limit: u64,
) -> Result<Option<ContractCallExecutionContext>, OverlayBuildError> {
    parse_contract_call_execution_context_from_source(
        metadata,
        ContractDispatchSource::Bytecode(bytecode),
        gas_limit,
        None,
    )
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn parse_prepared_contract_call_execution_context(
    metadata: &Metadata,
    contract: &ivm::PreparedContract,
    gas_limit: u64,
    reused_argument_record: Option<&ivm::PreparedArgumentRecord>,
) -> Result<Option<ContractCallExecutionContext>, OverlayBuildError> {
    parse_contract_call_execution_context_from_source(
        metadata,
        ContractDispatchSource::Prepared(contract),
        gas_limit,
        reused_argument_record,
    )
}
fn reject_raw_contract_without_state(bytecode: &[u8]) -> Result<(), OverlayBuildError> {
    let parsed = ivm::ProgramMetadata::parse(bytecode).map_err(|error| {
        OverlayBuildError::ContractCall(format!(
            "invalid contract artifact for contract call dispatch: {error}"
        ))
    })?;
    if parsed.contract_interface.is_some() {
        return Err(OverlayBuildError::ContractCall(
            "raw-IVM contract entrypoint dispatch requires a full state view and live contract binding"
                .to_owned(),
        ));
    }
    Ok(())
}
fn parse_contract_call_execution_context_from_source(
    metadata: &Metadata,
    source: ContractDispatchSource<'_>,
    gas_limit: u64,
    reused_argument_record: Option<&ivm::PreparedArgumentRecord>,
) -> Result<Option<ContractCallExecutionContext>, OverlayBuildError> {
    let entrypoint = metadata
        .get("contract_entrypoint")
        .map(|raw| {
            raw.try_into_any_norito::<String>().map_err(|err| {
                OverlayBuildError::ContractCall(format!(
                    "invalid contract_entrypoint metadata: {err}"
                ))
            })
        })
        .transpose()?
        .map(|value| value.trim().to_owned());
    if entrypoint.as_deref().is_some_and(str::is_empty) {
        return Err(OverlayBuildError::ContractCall(
            "contract_entrypoint must not be empty".to_owned(),
        ));
    }
    let payload = metadata.get("contract_payload").cloned();
    if entrypoint.is_none() {
        if source.is_self_describing()? {
            return Err(OverlayBuildError::ContractCall(
                "self-describing contract calls require explicit contract_entrypoint metadata"
                    .to_owned(),
            ));
        }
        if payload.is_none() {
            return Ok(None);
        }
    }
    let (entrypoint_pc, argument_schema) = if let Some(selector) = entrypoint.as_deref() {
        let (entrypoint_pc, _entrypoint_authorization, argument_schema) =
            source.callable_entrypoint(selector)?;
        (Some(entrypoint_pc), argument_schema)
    } else {
        (None, None)
    };
    let canonical_record = crate::executor::encode_contract_argument_record(
        argument_schema.as_ref(),
        payload.as_ref(),
    )
    .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
    let argument_record = match (argument_schema.as_ref(), canonical_record) {
        (None, None) => None,
        (Some(schema), Some(record)) => {
            if let Some(reused) = reused_argument_record
                && reused
                    .is_bound_to(schema, &record)
                    .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?
            {
                // Reuse only the immutable decode plan. Every rebuilt VM still
                // precharges its complete decode/materialization cost below.
                Some(reused.clone())
            } else {
                Some(
                    ivm::prepare_argument_record_with_gas_limit(
                        schema,
                        Arc::<[u8]>::from(record),
                        gas_limit,
                    )
                    .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?,
                )
            }
        }
        _ => {
            return Err(OverlayBuildError::ContractCall(
                "contract argument schema and canonical record diverged".to_owned(),
            ));
        }
    };
    Ok(Some(ContractCallExecutionContext {
        entrypoint,
        entrypoint_pc,
        argument_record,
    }))
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn parse_prepared_contract_invocation_execution_context(
    invocation: &ContractInvocation,
    contract: &ivm::PreparedContract,
    gas_limit: u64,
    reused_argument_record: Option<&ivm::PreparedArgumentRecord>,
) -> Result<ContractCallExecutionContext, OverlayBuildError> {
    let selector = invocation.entrypoint.trim();
    if selector.is_empty() {
        return Err(OverlayBuildError::ContractCall(
            "contract entrypoint must not be empty".to_owned(),
        ));
    }
    let descriptor = contract.entrypoint_descriptor(selector).ok_or_else(|| {
        OverlayBuildError::ContractCall(format!("unknown contract entrypoint `{selector}`"))
    })?;
    let _permission =
        crate::executor::callable_contract_entrypoint_authorization(descriptor, selector)
            .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
    let entrypoint_pc = contract.entrypoint_pc(selector).ok_or_else(|| {
        OverlayBuildError::ContractCall(format!(
            "contract entrypoint `{selector}` has no validated program counter"
        ))
    })?;
    let argument_record = match (
        descriptor.argument_schema.as_ref(),
        invocation.arguments.as_deref(),
    ) {
        (None, None) => None,
        (None, Some(_)) => {
            return Err(OverlayBuildError::ContractCall(
                "zero-parameter entrypoint must not carry an argument record".to_owned(),
            ));
        }
        (Some(_), None) => {
            return Err(OverlayBuildError::ContractCall(
                "parameterized entrypoint requires an argument record".to_owned(),
            ));
        }
        (Some(schema), Some(arguments)) => {
            if let Some(reused) = reused_argument_record
                && reused
                    .is_bound_to(schema, arguments)
                    .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?
            {
                Some(reused.clone())
            } else {
                Some(
                    ivm::prepare_argument_record_with_gas_limit(
                        schema,
                        Arc::<[u8]>::from(arguments),
                        gas_limit,
                    )
                    .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?,
                )
            }
        }
    };
    Ok(ContractCallExecutionContext {
        entrypoint: Some(selector.to_owned()),
        entrypoint_pc: Some(entrypoint_pc),
        argument_record,
    })
}
#[cfg(test)]
fn authorize_and_prepare_raw_contract_dispatch<R: StateReadOnly>(
    state_ro: &R,
    tx: &TransactionPayload,
    summary: &ProgramSummary,
    gas_limit: u64,
) -> Result<
    (
        ContractCallExecutionContext,
        crate::executor::ContractRuntimeExecutionContext,
        ContractEntrypointAuthorizationSnapshot,
    ),
    OverlayBuildError,
> {
    let selector = crate::executor::requested_contract_entrypoint(&tx.metadata)
        .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?
        .ok_or_else(|| {
            OverlayBuildError::ContractCall(
                "self-describing raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                    .to_owned(),
            )
        })?;
    let identity = crate::executor::require_raw_contract_runtime_identity(
        state_ro.world(),
        summary.code_hash,
        &tx.metadata,
    )
    .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
    let authorization = crate::executor::authorize_prepared_raw_contract_selector(
        state_ro.world(),
        &tx.authority,
        summary.prepared_contract(),
        &selector,
        &identity,
    )
    .map_err(contract_registry_attempt_error)?;
    let contract_subject = code::fetch_bound_contract_subject(state_ro, &identity.contract_address)
        .ok_or_else(|| {
            OverlayBuildError::ContractCall(format!(
                "contract instance `{}` has no valid subject binding",
                identity.contract_address
            ))
        })?;
    let call_context = parse_prepared_contract_call_execution_context(
        &tx.metadata,
        summary.prepared_contract(),
        gas_limit,
        None,
    )?
    .ok_or_else(|| {
        OverlayBuildError::ContractCall(
            "raw-IVM contract dispatch did not materialize its selected entrypoint".to_owned(),
        )
    })?;
    let runtime_context = crate::executor::ContractRuntimeExecutionContext {
        contract_subject,
        contract_address: identity.contract_address,
        contract_alias: identity.contract_alias,
        entrypoint: selector,
    };
    Ok((call_context, runtime_context, authorization))
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn validate_bound_contract_manifest(
    manifest: &ContractManifest,
    summary: &ProgramSummary,
) -> Result<(), OverlayBuildError> {
    crate::smartcontracts::ivm::validate_manifest_hashes(
        manifest,
        summary.code_hash,
        summary.abi_hash,
    )
    .map_err(OverlayBuildError::HeaderPolicy)
}
fn map_program_analysis_error(err: ProgramAnalysisError) -> OverlayBuildError {
    match err {
        ProgramAnalysisError::Metadata(error)
            if crate::execution_attempt::ExecutionDeferred::from_vm_error(&error).is_some() =>
        {
            OverlayBuildError::IvmLoad(error)
        }
        ProgramAnalysisError::Metadata(_) => OverlayBuildError::IvmHeaderParse,
        ProgramAnalysisError::Decode(decode_err) => OverlayBuildError::IvmLoad(decode_err),
    }
}
fn reject_state_free_axt_syscalls(bytecode: &[u8]) -> Result<(), OverlayBuildError> {
    let syscalls =
        ivm::analysis::program_syscall_numbers(bytecode).map_err(map_program_analysis_error)?;
    if let Some(number) = syscalls
        .filter(|number| ivm::syscalls::is_axt_syscall(*number))
        .min()
    {
        return Err(OverlayBuildError::StateRequiredSyscall(number));
    }
    Ok(())
}
fn map_artifact_admission_error(error: ivm::ContractArtifactError) -> OverlayBuildError {
    if let Some(local) = error.local_vm_error() {
        return OverlayBuildError::IvmLoad(local);
    }
    OverlayBuildError::HeaderPolicy(IvmAdmissionError::BytecodeDecodingFailed(error.to_string()))
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn map_program_summary_error(error: ivm::VMError) -> OverlayBuildError {
    if crate::execution_attempt::ExecutionDeferred::from_vm_error(&error).is_some() {
        return OverlayBuildError::IvmLoad(error);
    }
    OverlayBuildError::HeaderPolicy(crate::smartcontracts::ivm::admission_reason_from_vm_error(
        error,
    ))
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn cached_amx_analysis(
    ivm_cache: &mut IvmCache,
    summary: &ProgramSummary,
    bytecode: &[u8],
) -> Result<ivm::analysis::ProgramAnalysis, OverlayBuildError> {
    ivm_cache
        .analyze_program(summary, bytecode)
        .map_err(map_program_analysis_error)
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn cached_generic_amx_analysis(
    ivm_cache: &mut IvmCache,
    summary: &GenericProgramSummary,
) -> Result<ivm::analysis::ProgramAnalysis, OverlayBuildError> {
    ivm_cache
        .analyze_generic_program(summary)
        .map_err(map_program_analysis_error)
}
#[cfg(test)]
#[cfg(feature = "telemetry")]
fn observe_overlay_stage_ms<R>(state_ro: &R, stage: &'static str, started_at: Instant)
where
    R: StateReadOnly,
{
    let aggregate_lane = state_ro.nexus().routing_policy.default_lane;
    state_ro.metrics().observe_pipeline_stage_ms(
        aggregate_lane,
        stage,
        started_at.elapsed().as_secs_f64() * 1_000.0,
    );
}
fn apply_contract_call_execution_context(
    vm: &mut ivm::IVM,
    context: Option<&ContractCallExecutionContext>,
) -> Result<(), OverlayBuildError> {
    if let Some(argument_record) = context.and_then(|context| context.argument_record.as_ref()) {
        argument_record
            .precharge_vm(vm)
            .map_err(OverlayBuildError::IvmRun)?;
    }
    if let Some(context) = context
        && let Some(entrypoint_pc) = context.entrypoint_pc
    {
        // Public by-call entrypoints are compiled as regular functions, not as
        // the artifact's top-level `main`. Seed RA with the end-of-code
        // sentinel so `return` exits execution instead of falling through to pc=0.
        vm.set_register(1, vm.memory.code_len());
        vm.set_program_counter(entrypoint_pc).map_err(|err| {
            OverlayBuildError::ContractCall(format!(
                "contract entrypoint `{}` resolved to invalid pc: {err}",
                context.entrypoint.as_deref().unwrap_or("main")
            ))
        })?;
    }
    Ok(())
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn begin_overlay_access_log<QS>(
    host: &mut crate::smartcontracts::ivm::host::CoreHostImpl<QS>,
    capture_access_log: bool,
) -> Result<(), OverlayBuildError>
where
    QS: crate::smartcontracts::ivm::host::QueryStateAccess + Default,
{
    if capture_access_log {
        host.begin_tx(&ivm::parallel::StateAccessSet::default())
            .map_err(OverlayBuildError::IvmRun)?;
    }
    Ok(())
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn finish_overlay_access_log<QS>(
    host: &mut crate::smartcontracts::ivm::host::CoreHostImpl<QS>,
    capture_access_log: bool,
) -> Result<Option<ivm::host::AccessLog>, OverlayBuildError>
where
    QS: crate::smartcontracts::ivm::host::QueryStateAccess + Default,
{
    if capture_access_log && host.access_logging_supported() {
        host.finish_tx()
            .map(Some)
            .map_err(OverlayBuildError::IvmRun)
    } else {
        Ok(None)
    }
}
fn default_pipeline_config() -> iroha_config::parameters::actual::Pipeline {
    use iroha_config::parameters::{actual, defaults};
    actual::Pipeline {
        dynamic_prepass: defaults::pipeline::DYNAMIC_PREPASS,
        access_set_cache_enabled: defaults::pipeline::ACCESS_SET_CACHE_ENABLED,
        parallel_overlay: defaults::pipeline::PARALLEL_OVERLAY,
        workers: defaults::pipeline::WORKERS,
        stateless_cache_cap: defaults::pipeline::STATELESS_CACHE_CAP,
        parallel_apply: defaults::pipeline::PARALLEL_APPLY,
        ready_queue_heap: defaults::pipeline::READY_QUEUE_HEAP,
        gpu_key_bucket: defaults::pipeline::GPU_KEY_BUCKET,
        debug_trace_scheduler_inputs: defaults::pipeline::DEBUG_TRACE_SCHEDULER_INPUTS,
        debug_trace_tx_eval: defaults::pipeline::DEBUG_TRACE_TX_EVAL,
        signature_batch_max_ed25519: defaults::pipeline::SIGNATURE_BATCH_MAX_ED25519,
        signature_batch_max_secp256k1: defaults::pipeline::SIGNATURE_BATCH_MAX_SECP256K1,
        signature_batch_max_pqc: defaults::pipeline::SIGNATURE_BATCH_MAX_PQC,
        signature_batch_max_bls: defaults::pipeline::SIGNATURE_BATCH_MAX_BLS,
        cache_size: defaults::pipeline::CACHE_SIZE,
        ivm_cache_max_decoded_ops: defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
        ivm_cache_max_bytes: defaults::pipeline::IVM_CACHE_MAX_BYTES,
        ivm_execution_max_bytes: defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ivm_prover_threads: defaults::pipeline::IVM_PROVER_THREADS,
        overlay_max_instructions: defaults::pipeline::OVERLAY_MAX_INSTRUCTIONS,
        overlay_max_bytes: defaults::pipeline::OVERLAY_MAX_BYTES,
        overlay_chunk_instructions: defaults::pipeline::OVERLAY_CHUNK_INSTRUCTIONS,
        gas: actual::Gas {
            tech_account_id: defaults::pipeline::GAS_TECH_ACCOUNT_ID.to_string(),
            accepted_assets: Vec::new(),
            units_per_gas: Vec::new(),
        },
        ivm_max_cycles_upper_bound: defaults::pipeline::IVM_MAX_CYCLES_UPPER_BOUND,
        ivm_max_decoded_instructions: defaults::pipeline::IVM_MAX_DECODED_INSTRUCTIONS,
        ivm_max_decoded_bytes: defaults::pipeline::IVM_MAX_DECODED_BYTES,
        quarantine_max_txs_per_block: defaults::pipeline::QUARANTINE_MAX_TXS_PER_BLOCK,
        quarantine_tx_max_cycles: defaults::pipeline::QUARANTINE_TX_MAX_CYCLES,
        query_default_cursor_mode: QueryCursorMode::Ephemeral,
        query_max_fetch_size: defaults::pipeline::QUERY_MAX_FETCH_SIZE,
        query_stored_min_gas_units: defaults::pipeline::QUERY_STORED_MIN_GAS_UNITS,
        amx_per_dataspace_budget_ms: defaults::pipeline::AMX_PER_DATASPACE_BUDGET_MS,
        amx_group_budget_ms: defaults::pipeline::AMX_GROUP_BUDGET_MS,
        amx_per_instruction_ns: defaults::pipeline::AMX_PER_INSTRUCTION_NS,
        amx_per_memory_access_ns: defaults::pipeline::AMX_PER_MEMORY_ACCESS_NS,
        amx_per_syscall_ns: defaults::pipeline::AMX_PER_SYSCALL_NS,
    }
}
pub(crate) fn resolve_streaming_metadata<R: StateReadOnly>(
    state_ro: &R,
    authority: &AccountId,
) -> StreamingOverlayMetadata {
    let mut metadata = StreamingOverlayMetadata::default();
    let handle = match streaming::global_handle() {
        Some(handle) => handle,
        None => return metadata,
    };
    let mut candidate_keys: Vec<iroha_crypto::PublicKey> = Vec::new();
    if let Some(single) = authority.controller().single_signatory() {
        candidate_keys.push(single.clone());
    } else if let Some(policy) = authority.controller().multisig_policy() {
        candidate_keys.extend(
            policy
                .members()
                .iter()
                .map(|member| member.public_key().clone()),
        );
    }
    if candidate_keys.is_empty() {
        return metadata;
    }
    let peers = state_ro.world().peers();
    for key in candidate_keys {
        if let Some(peer) = peers.iter().find(|peer| peer.public_key() == &key).cloned() {
            metadata.transport = handle
                .transport_capabilities(&peer)
                .map(|resolution| TransportCapabilityResolutionSnapshot::from(&resolution));
            metadata.negotiated = handle.negotiated_capabilities(&peer);
            if metadata.transport.is_some() || metadata.negotiated.is_some() {
                break;
            }
        }
    }
    metadata
}
pub(crate) fn apply_streaming_metadata<
    QS: Default + crate::smartcontracts::ivm::host::QueryStateAccess,
>(
    host: &mut crate::smartcontracts::ivm::host::CoreHostImpl<QS>,
    metadata: StreamingOverlayMetadata,
) {
    if let Some(snapshot) = metadata.transport {
        host.record_transport_caps_snapshot(snapshot);
    }
    if let Some(flags) = metadata.negotiated {
        host.record_negotiated_caps_snapshot(flags);
    }
}
fn require_ivm_gas_limit(
    fee_payment: &iroha_data_model::transaction::FeePaymentIntent,
) -> Result<u64, OverlayBuildError> {
    fee_payment.gas_limit().map(NonZeroU64::get).ok_or_else(|| {
        OverlayBuildError::GasLimit("missing gas limit in fee payment intent".to_owned())
    })
}
/// Reject a proved replay whose metered gas exceeds the transaction gas limit.
pub(crate) fn require_ivm_proved_gas_within_limit(
    tx: &SignedTransaction,
    gas_used: u64,
) -> Result<(), OverlayBuildError> {
    let gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
    if gas_used > gas_limit {
        return Err(OverlayBuildError::GasLimit(format!(
            "proved IVM replay used {gas_used} gas above transaction limit {gas_limit}"
        )));
    }
    Ok(())
}
#[cfg(test)]
const TEST_GAS_LIMIT: u64 = 50_000_000;
#[cfg(test)]
fn test_fee_payment() -> iroha_data_model::transaction::FeePaymentIntent {
    iroha_data_model::transaction::FeePaymentIntent::authority(
        Vec::new(),
        NonZeroU64::new(TEST_GAS_LIMIT),
    )
}
#[cfg(test)]
fn overlay_test_network_id(seed: &[u8]) -> iroha_data_model::NetworkId {
    iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(seed)),
    )
}
#[cfg(test)]
fn compute_program_hashes(
    meta: &ivm::ProgramMetadata,
    _header_len: usize,
    bytecode: &[u8],
) -> (Hash, Hash) {
    let code_hash = ivm::contract_code_hash(bytecode);
    debug_assert_eq!(meta.abi_version, 1, "only ABI v1 is supported");
    let policy = ivm::SyscallPolicy::AbiV1;
    let computed = Hash::prehashed(ivm::syscalls::compute_abi_hash(policy));
    let abi_hash = PROGRAM_HASH_CACHE
        .lock()
        .expect("program hash cache poisoned")
        .get_or_insert(code_hash, computed);
    (code_hash, abi_hash)
}
/// Apply mutable node policy to an already admitted IVM artifact.
///
/// Opcode and syscall validity belongs to artifact preparation. ABI V1 does not
/// feature-gate either surface, so this metadata-only check deliberately cannot
/// rewalk the program body on warm dispatch.
pub(crate) fn enforce_pre_execution_policy(
    ivm_max_cycles_upper_bound: NonZeroU64,
    meta: &ivm::ProgramMetadata,
) -> Result<(), OverlayBuildError> {
    crate::smartcontracts::ivm::validate_cycle_ceiling(meta, ivm_max_cycles_upper_bound)
        .map_err(OverlayBuildError::HeaderPolicy)?;
    Ok(())
}
fn contract_registry_attempt_error(
    error: crate::execution_attempt::ExecutionAttemptError<ValidationFail>,
) -> OverlayBuildError {
    match error {
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
            OverlayBuildError::ContractCall(error.to_string())
        }
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            OverlayBuildError::IvmRun(reason.into_vm_error())
        }
    }
}
pub(crate) fn validate_contract_binding<R: StateReadOnly>(
    state_ro: &R,
    tx: &TransactionPayload,
    summary: &ProgramSummary,
) -> Result<(), OverlayBuildError> {
    let code_hash = summary.code_hash;
    let abi_hash = summary.abi_hash;
    let runtime_identity = crate::executor::resolve_raw_contract_runtime_identity(
        state_ro.world(),
        code_hash,
        &tx.metadata,
    )
    .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
    let mut contract_address = runtime_identity.map(|identity| identity.contract_address);
    if contract_address.is_none() {
        contract_address = tx
            .metadata
            .get(&Name::from_str("gov_contract_address").expect("static name"))
            .map(|value| {
                value
                    .clone()
                    .try_into_any_norito::<String>()
                    .map_err(|error| {
                        OverlayBuildError::ContractCall(format!(
                            "invalid gov_contract_address metadata: {error}"
                        ))
                    })
            })
            .transpose()?
            .map(|raw| {
                raw.parse::<ContractAddress>().map_err(|error| {
                    OverlayBuildError::ContractCall(format!(
                        "invalid gov_contract_address metadata literal `{raw}`: {error}"
                    ))
                })
            })
            .transpose()?;
    }
    let artifact_id = routed_artifact_id(state_ro, tx, code_hash)?;
    if contract_address
        .as_ref()
        .is_some_and(|address| address.dataspace_id().ok() != Some(artifact_id.dataspace_id))
    {
        return Err(OverlayBuildError::ContractCall(
            "contract address differs from the exact native execution scope".into(),
        ));
    }
    let artifacts = code::fetch_artifacts(state_ro, &artifact_id, contract_address.as_ref())
        .map_err(contract_registry_attempt_error)?;
    let manifest_opt = artifacts.manifest.as_ref();
    // A stored V1 manifest is a complete consensus binding, not a collection
    // of optional constraints.
    if let Some(manifest) = manifest_opt {
        crate::smartcontracts::ivm::validate_manifest_hashes(manifest, code_hash, abi_hash)
            .map_err(OverlayBuildError::HeaderPolicy)?;
    }
    // If contract-address metadata is present, ensure the instance binding matches.
    if let Some(contract_address) = contract_address.as_ref() {
        let bound_hash = artifacts.bound_code_hash.ok_or_else(|| {
            OverlayBuildError::HeaderPolicy(IvmAdmissionError::BytecodeDecodingFailed(format!(
                "contract instance `{contract_address}` not found in WSV"
            )))
        })?;
        if bound_hash != code_hash {
            return Err(OverlayBuildError::HeaderPolicy(
                IvmAdmissionError::ManifestCodeHashMismatch(ManifestCodeHashMismatchInfo {
                    expected: bound_hash,
                    actual: code_hash,
                }),
            ));
        }
        manifest_opt.ok_or_else(|| {
            OverlayBuildError::HeaderPolicy(IvmAdmissionError::BytecodeDecodingFailed(
                "contract manifest missing for bound instance".into(),
            ))
        })?;
        let stored_bytecode = artifacts.code_bytes.as_deref().ok_or_else(|| {
            OverlayBuildError::HeaderPolicy(IvmAdmissionError::BytecodeDecodingFailed(format!(
                "contract bytecode for bound instance `{contract_address}` is missing from WSV"
            )))
        })?;
        let submitted_bytecode = match &tx.instructions {
            Executable::Ivm(bytecode) => Some(bytecode.as_ref()),
            Executable::IvmProved(proved) => Some(proved.bytecode.as_ref()),
            Executable::Instructions(_) | Executable::ContractCall(_) | Executable::Batch(_) => {
                None
            }
        };
        if submitted_bytecode.is_some_and(|bytecode| bytecode != stored_bytecode) {
            return Err(OverlayBuildError::HeaderPolicy(
                IvmAdmissionError::BytecodeDecodingFailed(format!(
                    "submitted contract bytecode does not exactly match the artifact stored for bound instance `{contract_address}`"
                )),
            ));
        }
    }
    Ok(())
}

/// Resolve registry ownership from the exact immutable native route, with no universal fallback.
pub(crate) fn routed_artifact_id<R: StateReadOnly>(
    state_ro: &R,
    tx: &TransactionPayload,
    code_hash: Hash,
) -> Result<ContractArtifactId, OverlayBuildError> {
    let height = u64::try_from(state_ro.height())
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or_else(|| {
            OverlayBuildError::ContractCall("artifact execution height overflows".into())
        })?;
    let snapshot = crate::sumeragi::lanes::routing::RoutingSnapshot::of(state_ro)
        .map_err(|reason| OverlayBuildError::IvmRun(reason.into_vm_error()))?;
    let route = snapshot
        .inputs(state_ro.world())
        .execution_route(tx, height)
        .map_err(|reason| OverlayBuildError::IvmRun(reason.into_vm_error()))?
        .ok_or_else(|| {
            OverlayBuildError::ContractCall(
                "artifact has no exact immutable native execution scope".into(),
            )
        })?;
    Ok(ContractArtifactId::new(route.dataspace_id, code_hash))
}
fn metadata_contract_manifest(
    metadata: &Metadata,
) -> Result<Option<ContractManifest>, OverlayBuildError> {
    metadata
        .get(&Name::from_str(MANIFEST_METADATA_KEY).expect("static manifest metadata key"))
        .map(|json| {
            json.clone()
                .try_into_any_norito::<ContractManifest>()
                .map_err(|_| OverlayBuildError::HeaderPolicy(IvmAdmissionError::ManifestMalformed))
        })
        .transpose()
}
fn queued_contract_bytes_match(
    queued: &[InstructionBox],
    artifact_id: &ContractArtifactId,
    bytecode: &[u8],
) -> bool {
    queued.iter().any(|instr| {
        instr
            .as_any()
            .downcast_ref::<RegisterSmartContractBytes>()
            .is_some_and(|bytes| {
                bytes.artifact_id() == artifact_id && bytes.code().as_slice() == bytecode
            })
    })
}
fn queued_manifest_matches(
    queued: &[InstructionBox],
    artifact_id: &ContractArtifactId,
    manifest: &ContractManifest,
) -> bool {
    queued.iter().any(|instr| {
        instr
            .as_any()
            .downcast_ref::<RegisterSmartContractCode>()
            .is_some_and(|registered| {
                registered.artifact_id() == artifact_id && registered.manifest() == manifest
            })
    })
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn append_verified_contract_metadata_registration<R: StateReadOnly>(
    state_ro: &R,
    tx: &SignedTransaction,
    summary: &ProgramSummary,
    bytecode: &[u8],
    queued: &mut Vec<InstructionBox>,
) -> Result<(), OverlayBuildError> {
    let Some(manifest) = metadata_contract_manifest(tx.metadata())? else {
        return Ok(());
    };
    let verified = ivm::verify_contract_artifact_with_memory_budget(
        bytecode,
        state_ro.prepared_contract_cache().execution_budget(),
    )
    .map_err(map_artifact_admission_error)?;
    if verified.code_hash != summary.code_hash {
        return Err(OverlayBuildError::HeaderPolicy(
            IvmAdmissionError::ManifestCodeHashMismatch(ManifestCodeHashMismatchInfo {
                expected: verified.code_hash,
                actual: summary.code_hash,
            }),
        ));
    }
    if !manifest.same_signed_content(&verified.manifest) {
        return Err(OverlayBuildError::HeaderPolicy(
            IvmAdmissionError::BytecodeDecodingFailed(
                "contract manifest metadata does not match embedded CNTR section".into(),
            ),
        ));
    }
    let code_hash = verified.code_hash;
    let artifact_id = routed_artifact_id(state_ro, tx.payload(), code_hash)?;
    let code_is_registered = state_ro.world().contract_code().get(&artifact_id).is_some()
        || queued_contract_bytes_match(queued, &artifact_id, bytecode);
    if !code_is_registered {
        queued.push(
            RegisterSmartContractBytes {
                artifact_id,
                code: bytecode.to_vec(),
            }
            .into(),
        );
    }
    let manifest_is_registered = state_ro
        .world()
        .contract_manifests()
        .get(&artifact_id)
        .is_some()
        || queued_manifest_matches(queued, &artifact_id, &manifest);
    if !manifest_is_registered {
        queued.push(
            RegisterSmartContractCode {
                artifact_id,
                manifest,
            }
            .into(),
        );
    }
    Ok(())
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn append_verified_contract_metadata_registration_to_queued<R: StateReadOnly>(
    state_ro: &R,
    tx: &SignedTransaction,
    summary: &ProgramSummary,
    bytecode: &[u8],
    queued: &mut Vec<crate::smartcontracts::ivm::host::QueuedEffect>,
    contract_runtime_context: Option<&crate::executor::ContractRuntimeExecutionContext>,
    entrypoint_authorization: &ContractEntrypointAuthorizationSnapshot,
) -> Result<(), OverlayBuildError> {
    let mut instructions = queued
        .iter()
        .filter_map(|queued| queued.instruction().cloned())
        .collect::<Vec<_>>();
    let original_len = instructions.len();
    append_verified_contract_metadata_registration(
        state_ro,
        tx,
        summary,
        bytecode,
        &mut instructions,
    )?;
    queued.extend(
        instructions
            .into_iter()
            .skip(original_len)
            .map(
                |instruction| crate::smartcontracts::ivm::host::QueuedEffect {
                    payload: crate::smartcontracts::ivm::host::QueuedEffectPayload::Instruction(
                        instruction,
                    ),
                    authority: contract_runtime_context.map_or_else(
                        || tx.authority().clone(),
                        |context| context.contract_subject.clone(),
                    ),
                    contract_runtime_context: contract_runtime_context.cloned(),
                    entrypoint_authorization: Some(entrypoint_authorization.clone()),
                },
            ),
    );
    Ok(())
}
fn append_verified_contract_metadata_registration_without_state(
    tx: &SignedTransaction,
    bytecode: &[u8],
    queued: &mut Vec<InstructionBox>,
) -> Result<(), OverlayBuildError> {
    let Some(manifest) = metadata_contract_manifest(tx.metadata())? else {
        return Ok(());
    };
    let verified = ivm::verify_contract_artifact(bytecode).map_err(map_artifact_admission_error)?;
    if !manifest.same_signed_content(&verified.manifest) {
        return Err(OverlayBuildError::HeaderPolicy(
            IvmAdmissionError::BytecodeDecodingFailed(
                "contract manifest metadata does not match embedded CNTR section".into(),
            ),
        ));
    }
    let code_hash = verified.code_hash;
    let address = crate::executor::requested_contract_address(tx.metadata())
        .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?
        .ok_or_else(|| {
            OverlayBuildError::ContractCall(
                "state-free artifact registration requires an explicit contract address".into(),
            )
        })?;
    let artifact_id = ContractArtifactId::for_address(&address, code_hash)
        .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
    if !queued_contract_bytes_match(queued, &artifact_id, bytecode) {
        queued.push(
            RegisterSmartContractBytes {
                artifact_id,
                code: bytecode.to_vec(),
            }
            .into(),
        );
    }
    if !queued_manifest_matches(queued, &artifact_id, &manifest) {
        queued.push(
            RegisterSmartContractCode {
                artifact_id,
                manifest,
            }
            .into(),
        );
    }
    Ok(())
}
#[cfg(any(test, feature = "iroha-core-tests"))]
pub(crate) fn prune_redundant_contract_ops<R: StateReadOnly>(
    state_ro: &R,
    queued: &mut Vec<InstructionBox>,
) {
    prune_redundant_contract_ops_with_metadata::<R, ()>(state_ro, queued, None);
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn prune_redundant_contract_ops_with_metadata<R, M>(
    state_ro: &R,
    queued: &mut Vec<InstructionBox>,
    metadata: Option<&mut Vec<M>>,
) where
    R: StateReadOnly,
{
    if queued.is_empty() {
        return;
    }
    if let Some(metadata) = metadata.as_ref() {
        let metadata_len = metadata.len();
        let queued_len = queued.len();
        debug_assert_eq!(
            metadata_len, queued_len,
            "overlay execution metadata must align with queued instructions",
        );
    }
    let mut manifest_cache: BTreeMap<ContractArtifactId, Option<ContractManifest>> =
        BTreeMap::new();
    let mut code_cache: BTreeMap<ContractArtifactId, Option<Vec<u8>>> = BTreeMap::new();
    let mut binding_cache: BTreeMap<ContractAddress, Option<Hash>> = BTreeMap::new();
    let retain: Vec<bool> = queued
        .iter()
        .map(|instr| {
            if let Some(reg) = instr.as_any().downcast_ref::<RegisterSmartContractCode>() {
                if reg.manifest().code_hash == Some(reg.artifact_id().code_hash) {
                    let existing = manifest_cache.entry(*reg.artifact_id()).or_insert_with(|| {
                        state_ro
                            .world()
                            .contract_manifests()
                            .get(reg.artifact_id())
                            .cloned()
                    });
                    if let Some(existing) = existing {
                        if existing == reg.manifest() {
                            return false;
                        }
                    }
                }
            } else if let Some(bytes) = instr.as_any().downcast_ref::<RegisterSmartContractBytes>()
            {
                let cached = code_cache.entry(*bytes.artifact_id()).or_insert_with(|| {
                    state_ro
                        .world()
                        .contract_code()
                        .get(bytes.artifact_id())
                        .cloned()
                });
                if cached
                    .as_ref()
                    .is_some_and(|existing| existing.as_slice() == bytes.code().as_slice())
                {
                    return false;
                }
            } else if let Some(activate) = instr.as_any().downcast_ref::<ActivateContractInstance>()
            {
                let key = activate.contract_address().clone();
                let bound = binding_cache
                    .entry(key.clone())
                    .or_insert_with(|| state_ro.world().contract_instances().get(&key).copied());
                if bound.is_some_and(|hash| hash == *activate.code_hash()) {
                    return false;
                }
            }
            true
        })
        .collect();
    if retain.iter().all(|keep| *keep) {
        return;
    }
    let prior = mem::take(queued);
    *queued = prior
        .into_iter()
        .zip(retain.iter().copied())
        .filter_map(|(instr, keep)| keep.then_some(instr))
        .collect();
    if let Some(metadata) = metadata {
        let prior = mem::take(metadata);
        *metadata = prior
            .into_iter()
            .zip(retain.into_iter())
            .filter_map(|(entry, keep)| keep.then_some(entry))
            .collect();
    }
}
#[derive(Debug, Clone)]
struct OverlayInstructionExecutionContext {
    authority: AccountId,
    contract_runtime_context: Option<crate::executor::ContractRuntimeExecutionContext>,
    entrypoint_authorization: Option<ContractEntrypointAuthorizationSnapshot>,
}
#[derive(Debug)]
struct OverlayEffect {
    payload: QueuedEffectPayload,
    execution_context: Option<OverlayInstructionExecutionContext>,
}
impl OverlayEffect {
    fn instruction(&self) -> Option<&InstructionBox> {
        match &self.payload {
            QueuedEffectPayload::Instruction(instruction) => Some(instruction),
            QueuedEffectPayload::Emission(_) => None,
        }
    }
    fn plain_instruction(instruction: InstructionBox) -> Self {
        Self {
            payload: QueuedEffectPayload::Instruction(instruction),
            execution_context: None,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum TxOverlaySource {
    #[default]
    Instructions,
    #[cfg(any(test, feature = "iroha-core-tests"))]
    ContractCall,
    Ivm,
    IvmProved,
}
impl TxOverlaySource {
    /// Whether this overlay was produced by a live contract/IVM execution at the block height.
    fn is_live_execution(self) -> bool {
        match self {
            #[cfg(any(test, feature = "iroha-core-tests"))]
            Self::ContractCall => true,
            Self::Ivm => true,
            Self::Instructions | Self::IvmProved => false,
        }
    }
}
/// Overlay of a transaction's intended operations.
#[derive(Debug, Default)]
pub struct TxOverlay {
    effects: Vec<OverlayEffect>,
    entrypoint_authorization: Option<ContractEntrypointAuthorizationSnapshot>,
    lifecycle_completion: Option<OverlayLifecycleCompletion>,
    ivm_gas_used: Option<u64>,
    completed_axt: Vec<ivm::axt::HostAxtState>,
    durable_state_overlay: BTreeMap<StatePath, Option<Vec<u8>>>,
    durable_state_authorizations:
        BTreeMap<StatePath, Option<ContractEntrypointAuthorizationSnapshot>>,
    source: TxOverlaySource,
    byte_size: OnceLock<usize>,
}
#[cfg(test)]
/// Overlay and prepared runtime inputs retained for scheduler regression tests.
#[derive(Debug)]
pub(crate) struct PreparedTxOverlay {
    /// Built transaction overlay.
    pub(crate) overlay: TxOverlay,
    /// Canonical argument plan retained across a selective live-state rebuild.
    pub(crate) prepared_argument_record: Option<ivm::PreparedArgumentRecord>,
    /// Immutable validated contract retained for access derivation without
    /// another artifact hash, parse, decode, or byte copy.
    pub(crate) prepared_contract: Option<ivm::PreparedContract>,
}
/// Conservative scheduler scope required by the reachable syscall surface.
///
/// Concrete host logs are useful for diagnostics and conflict precision, but they describe only the
/// block-start execution. If a predecessor changes a value used for control flow, selective
/// re-execution may choose a different target. This bytecode-derived fence keeps that target change
/// inside the DAG relation established before any overlay is applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum VmAccessFence {
    /// Every reachable syscall is VM-local.
    #[default]
    None,
    /// Reachable syscalls are limited to contract-owned durable state.
    State,
    /// Ledger, nested-contract, opaque, or unclassified access is reachable.
    Global,
}
impl VmAccessFence {
    /// Derive a fail-closed fixture fence from decoded bytecode rather than CNTR claims.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_program_analysis(analysis: &ivm::analysis::ProgramAnalysis) -> Self {
        Self::from_syscall_numbers(analysis.syscalls.iter().map(|usage| usage.number))
    }
    /// Classify a borrowed instruction scan without allocating an aggregate report.
    #[must_use]
    pub(crate) fn from_syscall_numbers(numbers: impl IntoIterator<Item = u32>) -> Self {
        let mut fence = Self::None;
        for number in numbers {
            match ivm::syscalls::syscall_access(number) {
                ivm::syscalls::SyscallAccess::None => {}
                ivm::syscalls::SyscallAccess::StateRead
                | ivm::syscalls::SyscallAccess::StateWrite => {
                    if fence == Self::None {
                        fence = Self::State;
                    }
                }
                ivm::syscalls::SyscallAccess::LedgerRead
                | ivm::syscalls::SyscallAccess::LedgerWrite
                | ivm::syscalls::SyscallAccess::Dynamic => return Self::Global,
            }
        }
        fence
    }
    #[cfg(test)]
    /// Return whether the bytecode can observe world state not represented by
    /// the durable-state read fingerprint.
    #[must_use]
    pub(crate) fn requires_live_rebuild(analysis: &ivm::analysis::ProgramAnalysis) -> bool {
        analysis.syscalls.iter().any(|syscall| {
            matches!(
                ivm::syscalls::syscall_access(syscall.number),
                ivm::syscalls::SyscallAccess::LedgerRead
                    | ivm::syscalls::SyscallAccess::LedgerWrite
                    | ivm::syscalls::SyscallAccess::Dynamic
            )
        })
    }
    /// Scheduler write key which serializes every access in the required scope.
    #[must_use]
    pub(crate) const fn scheduler_write_key(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::State => Some("state:*"),
            Self::Global => Some("*"),
        }
    }
}
#[cfg(test)]
/// Durable-state read snapshot retained for overlay invalidation regression tests.
///
/// The tests prepare an overlay, change predecessor state, and verify that stale
/// reads require a fresh VM run before applying a read-modify-write result.
#[derive(Clone, Debug)]
pub(crate) struct DurableStateReadSnapshot {
    /// `None` means an invalid/unrepresentable host key forced a fail-closed
    /// fingerprint of the complete durable-state map.
    prefixes: Option<Vec<StatePath>>,
    fingerprint: [u8; 32],
}
#[cfg(test)]
impl DurableStateReadSnapshot {
    /// Capture all exact values and descendants covered by the host read log.
    ///
    /// The host uses the same logical key for exact reads and prefix operations such as
    /// `STATE_SCAN`. Fingerprinting the whole prefix is conservative for exact reads and complete
    /// for both forms. Deployed contracts report the concrete contract-instance namespace; raw IVM
    /// execution reports the unscoped path it actually uses.
    pub(crate) fn capture<R>(
        tx: &SignedTransaction,
        access_log: Option<&ivm::host::AccessLog>,
        state_ro: &R,
    ) -> Option<Self>
    where
        R: StateReadOnly,
    {
        if !matches!(
            tx.instructions(),
            Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_)
        ) {
            return None;
        }
        let access_log = access_log?;
        if !access_log.durable_read_paths_complete {
            let fingerprint = durable_state_prefix_fingerprint(None, state_ro);
            return Some(Self {
                prefixes: None,
                fingerprint,
            });
        }
        if access_log.durable_read_paths.is_empty() {
            return None;
        }
        let mut prefixes = BTreeSet::new();
        for concrete_path in &access_log.durable_read_paths {
            let Ok(concrete_path) = StatePath::from_str(concrete_path) else {
                let fingerprint = durable_state_prefix_fingerprint(None, state_ro);
                return Some(Self {
                    prefixes: None,
                    fingerprint,
                });
            };
            prefixes.insert(concrete_path);
        }
        let prefixes = Some(prefixes.into_iter().collect::<Vec<_>>());
        let fingerprint = durable_state_prefix_fingerprint(prefixes.as_deref(), state_ro);
        Some(Self {
            prefixes,
            fingerprint,
        })
    }
    /// Return whether every observed durable-state prefix still has its block-preparation value.
    pub(crate) fn is_current<R>(&self, state_ro: &R) -> bool
    where
        R: StateReadOnly,
    {
        durable_state_prefix_fingerprint(self.prefixes.as_deref(), state_ro) == self.fingerprint
    }
}
#[cfg(test)]
fn durable_state_prefix_fingerprint<R>(prefixes: Option<&[StatePath]>, state_ro: &R) -> [u8; 32]
where
    R: StateReadOnly,
{
    fn frame(hasher: &mut Sha256, bytes: &[u8]) {
        let len = u64::try_from(bytes.len()).expect("slice length fits u64");
        hasher.update(len.to_le_bytes());
        hasher.update(bytes);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"iroha:durable-state-read-snapshot:v1");
    let state = state_ro.world().smart_contract_state();
    let Some(prefixes) = prefixes else {
        hasher.update(u64::MAX.to_le_bytes());
        for (path, value) in state.iter() {
            let path_raw: &str = path.as_ref();
            frame(&mut hasher, path_raw.as_bytes());
            frame(&mut hasher, value);
        }
        return hasher.finalize().into();
    };
    let prefix_count = u64::try_from(prefixes.len()).expect("prefix count fits u64");
    hasher.update(prefix_count.to_le_bytes());
    for prefix in prefixes {
        let prefix_raw: &str = prefix.as_ref();
        frame(&mut hasher, prefix_raw.as_bytes());
        if let Some(value) = state.get(prefix) {
            hasher.update([1]);
            frame(&mut hasher, prefix_raw.as_bytes());
            frame(&mut hasher, value);
        } else {
            hasher.update([0]);
        }
        // Start directly at `prefix/`. Other valid paths such as `prefix-`
        // can sort between `prefix` and `prefix/`; beginning at `prefix` and
        // breaking on the first non-match would therefore miss descendants.
        let descendant_prefix_raw = format!("{prefix_raw}/");
        let descendant_prefix = StatePath::from_str(&descendant_prefix_raw)
            .expect("a durable-state path with a slash suffix remains a valid StatePath");
        for (path, value) in state.range(descendant_prefix..) {
            let path_raw: &str = path.as_ref();
            if !path_raw.starts_with(&descendant_prefix_raw) {
                break;
            }
            hasher.update([1]);
            frame(&mut hasher, path_raw.as_bytes());
            frame(&mut hasher, value);
        }
        hasher.update([0]);
    }
    hasher.finalize().into()
}
#[cfg(test)]
impl PreparedTxOverlay {
    fn new(
        overlay: TxOverlay,
        _access_log: Option<ivm::host::AccessLog>,
        _access_fence: VmAccessFence,
        _force_live_rebuild: bool,
    ) -> Self {
        Self {
            overlay,
            prepared_argument_record: None,
            prepared_contract: None,
        }
    }
    fn with_prepared_argument_record(
        mut self,
        prepared_argument_record: Option<ivm::PreparedArgumentRecord>,
    ) -> Self {
        self.prepared_argument_record = prepared_argument_record;
        self
    }
    fn with_prepared_contract(mut self, contract: &ivm::PreparedContract) -> Self {
        self.prepared_contract = Some(contract.clone());
        self
    }
}
impl TxOverlay {
    fn validate_authorization_snapshot(
        world: &impl WorldReadOnly,
        authorization: &ContractEntrypointAuthorizationSnapshot,
        execution_height: Option<u64>,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        if let Some(execution_height) = execution_height {
            authorization.validate_at_height(world, execution_height)
        } else {
            authorization.validate(world)
        }
    }
    fn validate_authorization_snapshot_for_authority(
        world: &impl WorldReadOnly,
        authorization: &ContractEntrypointAuthorizationSnapshot,
        authority: &AccountId,
        execution_height: Option<u64>,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        if let Some(execution_height) = execution_height {
            authorization.validate_for_authority_at_height(world, authority, execution_height)
        } else {
            authorization.validate_for_authority(world, authority)
        }
    }
    /// Create an overlay from a list of instructions.
    pub fn from_instructions(instrs: Vec<InstructionBox>) -> Self {
        Self {
            effects: instrs
                .into_iter()
                .map(OverlayEffect::plain_instruction)
                .collect(),
            entrypoint_authorization: None,
            lifecycle_completion: None,
            ivm_gas_used: None,
            completed_axt: Vec::new(),
            durable_state_overlay: BTreeMap::new(),
            durable_state_authorizations: BTreeMap::new(),
            source: TxOverlaySource::Instructions,
            byte_size: OnceLock::new(),
        }
    }
    #[cfg(test)]
    fn from_ivm_proved_instructions(
        instrs: Vec<InstructionBox>,
        _authority: &AccountId,
        contract_runtime_context: crate::executor::ContractRuntimeExecutionContext,
        entrypoint_authorization: ContractEntrypointAuthorizationSnapshot,
    ) -> Self {
        let execution_contexts: Vec<_> = instrs
            .iter()
            .map(|_| OverlayInstructionExecutionContext {
                authority: contract_runtime_context.contract_subject.clone(),
                contract_runtime_context: Some(contract_runtime_context.clone()),
                entrypoint_authorization: Some(entrypoint_authorization.clone()),
            })
            .collect();
        Self {
            effects: instrs
                .into_iter()
                .zip(execution_contexts)
                .map(|(instruction, context)| OverlayEffect {
                    payload: QueuedEffectPayload::Instruction(instruction),
                    execution_context: Some(context),
                })
                .collect(),
            entrypoint_authorization: Some(entrypoint_authorization),
            lifecycle_completion: None,
            ivm_gas_used: None,
            completed_axt: Vec::new(),
            durable_state_overlay: BTreeMap::new(),
            durable_state_authorizations: BTreeMap::new(),
            source: TxOverlaySource::IvmProved,
            byte_size: OnceLock::new(),
        }
    }
    /// Create an overlay from IVM-produced artifacts including durable state writes.
    pub fn from_ivm_execution(
        instrs: Vec<InstructionBox>,
        ivm_gas_used: u64,
        durable_state_overlay: BTreeMap<StatePath, Option<Vec<u8>>>,
    ) -> Self {
        let durable_state_authorizations = durable_state_overlay
            .keys()
            .cloned()
            .map(|path| (path, None))
            .collect();
        Self {
            effects: instrs
                .into_iter()
                .map(OverlayEffect::plain_instruction)
                .collect(),
            entrypoint_authorization: None,
            lifecycle_completion: None,
            ivm_gas_used: Some(ivm_gas_used),
            completed_axt: Vec::new(),
            durable_state_overlay,
            durable_state_authorizations,
            source: TxOverlaySource::Ivm,
            byte_size: OnceLock::new(),
        }
    }
    #[cfg(test)]
    fn from_host_execution(
        instructions: Vec<InstructionBox>,
        execution_contexts: Vec<OverlayInstructionExecutionContext>,
        ivm_gas_used: u64,
        completed_axt: Vec<ivm::axt::HostAxtState>,
        durable_state_overlay: BTreeMap<StatePath, Option<Vec<u8>>>,
        durable_state_authorizations: BTreeMap<
            StatePath,
            Option<ContractEntrypointAuthorizationSnapshot>,
        >,
    ) -> Self {
        assert_eq!(instructions.len(), execution_contexts.len());
        let queued = instructions
            .into_iter()
            .zip(execution_contexts)
            .map(
                |(instruction, context)| crate::smartcontracts::ivm::host::QueuedEffect {
                    payload: QueuedEffectPayload::Instruction(instruction),
                    authority: context.authority,
                    contract_runtime_context: context.contract_runtime_context,
                    entrypoint_authorization: context.entrypoint_authorization,
                },
            )
            .collect();
        Self::from_queued_execution(
            queued,
            ivm_gas_used,
            completed_axt,
            durable_state_overlay,
            durable_state_authorizations,
            TxOverlaySource::ContractCall,
        )
    }
    #[cfg(test)]
    fn instruction_fixture(&self) -> Self {
        let effects = self
            .effects
            .iter()
            .map(|effect| OverlayEffect {
                payload: QueuedEffectPayload::Instruction(
                    effect
                        .instruction()
                        .expect(
                            "only instruction fixtures can be rebuilt without running their host",
                        )
                        .clone(),
                ),
                execution_context: effect.execution_context.clone(),
            })
            .collect();
        Self {
            effects,
            entrypoint_authorization: self.entrypoint_authorization.clone(),
            lifecycle_completion: self.lifecycle_completion.clone(),
            ivm_gas_used: self.ivm_gas_used,
            completed_axt: self.completed_axt.clone(),
            durable_state_overlay: self.durable_state_overlay.clone(),
            durable_state_authorizations: self.durable_state_authorizations.clone(),
            source: self.source,
            byte_size: OnceLock::new(),
        }
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    fn from_queued_execution(
        queued: Vec<crate::smartcontracts::ivm::host::QueuedEffect>,
        ivm_gas_used: u64,
        completed_axt: Vec<ivm::axt::HostAxtState>,
        durable_state_overlay: BTreeMap<StatePath, Option<Vec<u8>>>,
        durable_state_authorizations: BTreeMap<
            StatePath,
            Option<ContractEntrypointAuthorizationSnapshot>,
        >,
        source: TxOverlaySource,
    ) -> Self {
        let effects = queued
            .into_iter()
            .map(|queued| OverlayEffect {
                payload: queued.payload,
                execution_context: Some(OverlayInstructionExecutionContext {
                    authority: queued.authority,
                    contract_runtime_context: queued.contract_runtime_context,
                    entrypoint_authorization: queued.entrypoint_authorization,
                }),
            })
            .collect();
        Self {
            effects,
            entrypoint_authorization: None,
            lifecycle_completion: None,
            ivm_gas_used: Some(ivm_gas_used),
            completed_axt,
            durable_state_overlay,
            durable_state_authorizations,
            source,
            byte_size: OnceLock::new(),
        }
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    fn from_ivm_proved_execution(
        queued: Vec<crate::smartcontracts::ivm::host::QueuedEffect>,
        ivm_gas_used: u64,
        completed_axt: Vec<ivm::axt::HostAxtState>,
        durable_state_overlay: BTreeMap<StatePath, Option<Vec<u8>>>,
        durable_state_authorizations: BTreeMap<
            StatePath,
            Option<ContractEntrypointAuthorizationSnapshot>,
        >,
    ) -> Self {
        Self::from_queued_execution(
            queued,
            ivm_gas_used,
            completed_axt,
            durable_state_overlay,
            durable_state_authorizations,
            TxOverlaySource::IvmProved,
        )
    }
    /// Is this overlay empty?
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
            && self.completed_axt.is_empty()
            && self.durable_state_overlay.is_empty()
    }
    /// Number of instructions in this overlay.
    pub fn instruction_count(&self) -> usize {
        self.instructions().count()
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Whether this overlay carries durable smart-contract state changes.
    pub fn has_durable_state_changes(&self) -> bool {
        !self.completed_axt.is_empty() || !self.durable_state_overlay.is_empty()
    }
    /// Iterate over instructions in this overlay.
    pub fn instructions(&self) -> impl Iterator<Item = &InstructionBox> {
        self.effects.iter().filter_map(OverlayEffect::instruction)
    }
    /// Borrow the durable smart-contract state overlay accumulated during IVM execution.
    pub fn durable_state_overlay(&self) -> &BTreeMap<StatePath, Option<Vec<u8>>> {
        &self.durable_state_overlay
    }
    /// Return IVM gas used during overlay prepass, when the source executable was `Executable::Ivm`.
    pub fn ivm_gas_used(&self) -> Option<u64> {
        self.ivm_gas_used
    }
    /// Approximate byte size of this overlay when serialized via Norito TLV.
    pub fn byte_size(&self) -> usize {
        *self.byte_size.get_or_init(|| {
            self.effects
                .iter()
                .map(|effect| match &effect.payload {
                    QueuedEffectPayload::Instruction(instruction) => {
                        NoritoEncode::encode(instruction).len()
                    }
                    QueuedEffectPayload::Emission(emission) => {
                        norito::canonical_frame_len(&emission.value).unwrap_or(usize::MAX)
                    }
                })
                .fold(0usize, usize::saturating_add)
        })
    }
    /// Apply the overlay to the given state transaction via the runtime executor.
    /// Executes instructions in chunks to bound peak working memory.
    ///
    /// # Errors
    /// Returns an error if executing any instruction fails validation or the executor rejects it.
    pub fn apply(
        self,
        state_tx: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
    ) -> Result<(), ValidationFail> {
        self.apply_inner(state_tx, authority)
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Apply the overlay with a specific chunk size (number of instructions per chunk).
    ///
    /// # Errors
    /// Returns an error if executing any instruction fails validation or the executor rejects it.
    pub fn apply_with_chunk(
        self,
        state_tx: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        _chunk_size: usize,
    ) -> Result<(), ValidationFail> {
        self.apply_inner(state_tx, authority)
    }
    fn validate_execution_context(
        world: &impl WorldReadOnly,
        execution_context: &OverlayInstructionExecutionContext,
        execution_height: Option<u64>,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        match (
            execution_context.contract_runtime_context.as_ref(),
            execution_context.entrypoint_authorization.as_ref(),
        ) {
            (Some(runtime_context), Some(authorization)) => {
                validate_overlay_contract_runtime_context(world, runtime_context)?;
                if (
                    &runtime_context.contract_address,
                    &runtime_context.contract_alias,
                    &runtime_context.entrypoint,
                    &execution_context.authority,
                ) != (
                    &authorization.contract_address,
                    &authorization.contract_alias,
                    &authorization.entrypoint,
                    &runtime_context.contract_subject,
                ) {
                    return Err(ValidationFail::NotPermitted(
                        "prepared contract effect does not match its immutable authorization snapshot"
                            .to_owned(),
                    ).into());
                }
                Self::validate_authorization_snapshot(world, authorization, execution_height)
            }
            (Some(_), None) => Err(ValidationFail::NotPermitted(
                "prepared contract effect is missing its entrypoint authorization snapshot"
                    .to_owned(),
            )
            .into()),
            (None, Some(_)) => Err(ValidationFail::InternalError(
                "overlay entrypoint authorization has no runtime contract context".to_owned(),
            )
            .into()),
            (None, None) => Ok(()),
        }
    }
    fn durable_path_requires_authorization(path: &StatePath) -> bool {
        let path = path.as_ref();
        path.starts_with("sc/")
            || (path.starts_with(code::CONTRACT_LIFECYCLE_STATE_PREFIX)
                && path
                    .as_bytes()
                    .get(code::CONTRACT_LIFECYCLE_STATE_PREFIX.len())
                    == Some(&b'/'))
    }
    fn validate_durable_authorizations(
        &self,
        world: &impl WorldReadOnly,
        execution_height: Option<u64>,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        if self.durable_state_overlay.len() != self.durable_state_authorizations.len()
            || !self
                .durable_state_overlay
                .keys()
                .eq(self.durable_state_authorizations.keys())
        {
            return Err(ValidationFail::InternalError(
                "durable state overlay authorization keys are structurally inconsistent".to_owned(),
            )
            .into());
        }
        for (path, authorization) in &self.durable_state_authorizations {
            crate::smartcontracts::ivm::host::validate_reserve_durable_state_path(path)?;
            if (self.source == TxOverlaySource::IvmProved
                || Self::durable_path_requires_authorization(path))
                && authorization.is_none()
            {
                return Err(ValidationFail::NotPermitted(format!(
                    "scoped durable state path `{path}` is missing its contract authorization snapshot"
                )).into());
            }
            if let Some(authorization) = authorization {
                if !authorization.owns_durable_state_path(path) {
                    return Err(ValidationFail::NotPermitted(format!(
                        "durable state path `{path}` does not belong to its contract authorization snapshot"
                    )).into());
                }
                Self::validate_authorization_snapshot(world, authorization, execution_height)?;
            }
        }
        Ok(())
    }
    fn apply_inner(
        mut self,
        state_tx: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
    ) -> Result<(), ValidationFail> {
        (|| -> Result<(), ValidationFail> {
            let execution_height = self
                .source
                .is_live_execution()
                .then_some(state_tx.block_height());
            if self.source == TxOverlaySource::IvmProved {
                crate::validation_fee::enforce_ivm_proved_completed_axt_admission(
                    self.completed_axt.len(),
                    state_tx,
                )?;
            }
            let has_contract_effect = self.lifecycle_completion.is_some()
                || self.effects.iter().any(|effect| {
                    matches!(effect.payload, QueuedEffectPayload::Emission(_))
                        || effect.execution_context.as_ref().is_some_and(|context| {
                            context.contract_runtime_context.is_some()
                                || context.entrypoint_authorization.is_some()
                        })
                })
                || self
                    .durable_state_authorizations
                    .values()
                    .any(Option::is_some);
            if has_contract_effect && self.entrypoint_authorization.is_none() {
                return Err(ValidationFail::NotPermitted(
                    "contract overlay is missing its root authorization snapshot".to_owned(),
                ));
            }
            if let Some(completion) = self.lifecycle_completion.as_ref() {
                code::validate_contract_lifecycle_state_completion(
                    &state_tx.world,
                    &state_tx.execution_budget(),
                    &completion.contract_address,
                    completion.pending,
                    &self.durable_state_overlay,
                )
                .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
            }
            if let Some(authorization) = self.entrypoint_authorization.as_ref() {
                if !authorization.is_root() {
                    return Err(ValidationFail::NotPermitted(
                        "contract overlay root authorization contains a parent invocation"
                            .to_owned(),
                    ));
                }
                Self::validate_authorization_snapshot_for_authority(
                    &state_tx.world,
                    authorization,
                    authority,
                    execution_height,
                )
                .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
                let retains_root = self
                    .effects
                    .iter()
                    .filter_map(|effect| effect.execution_context.as_ref())
                    .filter_map(|context| context.entrypoint_authorization.as_ref())
                    .chain(
                        self.durable_state_authorizations
                            .values()
                            .filter_map(Option::as_ref),
                    )
                    .all(|effect| effect.descends_from(authorization));
                if !retains_root {
                    return Err(ValidationFail::NotPermitted(
                        "contract overlay effect does not retain the root invocation chain"
                            .to_owned(),
                    ));
                }
            }
            for execution_context in self
                .effects
                .iter()
                .filter_map(|effect| effect.execution_context.as_ref())
            {
                Self::validate_execution_context(
                    &state_tx.world,
                    execution_context,
                    execution_height,
                )
                .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
            }
            self.validate_durable_authorizations(&state_tx.world, execution_height)
                .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
            let executor = state_tx.world.executor.clone();
            let effects = std::mem::take(&mut self.effects);
            for effect in effects {
                if let Some(authorization) = self.entrypoint_authorization.as_ref() {
                    Self::validate_authorization_snapshot_for_authority(
                        &state_tx.world,
                        authorization,
                        authority,
                        execution_height,
                    )
                    .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
                }
                let execution_context = effect.execution_context.as_ref();
                if let Some(execution_context) = execution_context {
                    Self::validate_execution_context(
                        &state_tx.world,
                        execution_context,
                        execution_height,
                    )
                    .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
                }
                let effect_authority =
                    execution_context.map_or(authority, |context| &context.authority);
                match effect.payload {
                    QueuedEffectPayload::Emission(emission) => {
                        crate::smartcontracts::ivm::host::HostExecutionArtifacts::validate_emission_provenance(
                            &state_tx.world, &emission.value,
                            execution_context.and_then(|context| context.contract_runtime_context.as_ref()),
                            execution_context.and_then(|context| context.entrypoint_authorization.as_ref()),
                        )?;
                        state_tx.record_contract_emission(emission)?;
                    }
                    QueuedEffectPayload::Instruction(instruction) => {
                        let instr = &instruction;
                        if let Some(atomic) = instr.as_any().downcast_ref::<SettleAtomic>() {
                            admission_validate_atomic(effect_authority, state_tx, atomic)
                                .map_err(ValidationFail::from)?;
                        } else if let Some(dvp) = instr.as_any().downcast_ref::<DvpIsi>() {
                            admission_validate_dvp(effect_authority, state_tx, dvp)
                                .map_err(ValidationFail::from)?;
                        } else if let Some(pvp) = instr.as_any().downcast_ref::<PvpIsi>() {
                            admission_validate_pvp(effect_authority, state_tx, pvp)
                                .map_err(ValidationFail::from)?;
                        } else if let Some(fx) = instr.as_any().downcast_ref::<SettleFxCorridor>() {
                            admission_validate_fx_corridor(effect_authority, state_tx, fx)
                                .map_err(ValidationFail::from)?;
                        } else if let Some(settlement) =
                            instr.as_any().downcast_ref::<SettlementInstructionBox>()
                        {
                            match settlement {
                                SettlementInstructionBox::Atomic(atomic) => {
                                    admission_validate_atomic(effect_authority, state_tx, atomic)
                                        .map_err(ValidationFail::from)?;
                                }
                                SettlementInstructionBox::Dvp(dvp) => {
                                    admission_validate_dvp(effect_authority, state_tx, dvp)
                                        .map_err(ValidationFail::from)?;
                                }
                                SettlementInstructionBox::Pvp(pvp) => {
                                    admission_validate_pvp(effect_authority, state_tx, pvp)
                                        .map_err(ValidationFail::from)?;
                                }
                                SettlementInstructionBox::SettleFxCorridor(fx) => {
                                    admission_validate_fx_corridor(effect_authority, state_tx, fx)
                                        .map_err(ValidationFail::from)?;
                                }
                                SettlementInstructionBox::SetFxCorridorPolicy(_) => {}
                                SettlementInstructionBox::FundFxCorridorEscrow(_)
                                | SettlementInstructionBox::RefundFxCorridorEscrow(_) => {}
                            }
                        }
                        if let Some(reg) =
                            crate::executor::extract_register_dataspace_asset_definition(instr)
                        {
                            crate::smartcontracts::isi::domain::isi::ensure_dataspace_asset_definition_registration_allowed(
                            state_tx, effect_authority, &reg,
                        ).map_err(ValidationFail::InstructionFailed)?;
                        }
                        if let Some(reg_asset_definition) = extract_register_asset_definition(instr)
                        {
                            ensure_asset_definition_registration_allowed(
                                state_tx,
                                effect_authority,
                                &reg_asset_definition,
                            )?;
                        }
                        if let Some(execution_context) = execution_context {
                            executor.execute_borrowed_overlay_instruction(
                                state_tx,
                                &execution_context.authority,
                                instr,
                                execution_context.contract_runtime_context.as_ref(),
                            )?;
                        } else {
                            executor.execute_borrowed_overlay_instruction(
                                state_tx, authority, instr, None,
                            )?;
                        }
                    }
                }
                // The just-executed leaf may revoke its own permission or mutate its own live
                // binding. Revalidate both the selected root and this exact leaf immediately,
                // including after the final queued effect.
                if let Some(authorization) = self.entrypoint_authorization.as_ref() {
                    Self::validate_authorization_snapshot_for_authority(
                        &state_tx.world,
                        authorization,
                        authority,
                        execution_height,
                    )
                    .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
                }
                if let Some(execution_context) = execution_context {
                    Self::validate_execution_context(
                        &state_tx.world,
                        execution_context,
                        execution_height,
                    )
                    .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
                }
            }
            // Revalidate immediately before committing the lifecycle tombstone. Queued effects
            // can invoke helper contracts, so the pre-execution check alone cannot detect a
            // deactivate/reactivate ABA staged while hajimari or kaizen is running.
            if let Some(completion) = self.lifecycle_completion.as_ref() {
                code::validate_contract_lifecycle_state_completion(
                    &state_tx.world,
                    &state_tx.execution_budget(),
                    &completion.contract_address,
                    completion.pending,
                    &self.durable_state_overlay,
                )
                .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
            }
            // Queued instructions may revoke the selected permission or change the live contract
            // binding. Recheck after they finish so a stale authorization cannot guard durable
            // writes merely because it was valid at the start of overlay application.
            if let Some(authorization) = self.entrypoint_authorization.as_ref() {
                Self::validate_authorization_snapshot_for_authority(
                    &state_tx.world,
                    authorization,
                    authority,
                    execution_height,
                )
                .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
            }
            self.validate_durable_authorizations(&state_tx.world, execution_height)
                .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
            crate::smartcontracts::ivm::host::HostExecutionArtifacts::record_completed_axt_states(
                state_tx,
                std::mem::take(&mut self.completed_axt),
            )?;
            for (path, value) in &self.durable_state_overlay {
                if let Some(authorization) = self
                    .durable_state_authorizations
                    .get(path)
                    .and_then(Option::as_ref)
                {
                    Self::validate_authorization_snapshot(
                        &state_tx.world,
                        authorization,
                        execution_height,
                    )
                    .map_err(|error| state_tx.attempt_error_to_validation_fail(error))?;
                }
                if let Some(stored) = value {
                    state_tx
                        .world
                        .smart_contract_state
                        .insert(path.clone(), stored.clone());
                } else {
                    state_tx.world.smart_contract_state.remove(path.clone());
                }
            }
            Ok(())
        })()
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    fn with_entrypoint_authorization(
        mut self,
        authorization: Option<ContractEntrypointAuthorizationSnapshot>,
    ) -> Self {
        self.entrypoint_authorization = authorization;
        self
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    fn with_lifecycle_completion(
        mut self,
        contract_address: &ContractAddress,
        pending: Option<code::PendingContractLifecycle>,
    ) -> Self {
        self.lifecycle_completion = pending.map(|pending| OverlayLifecycleCompletion {
            contract_address: contract_address.clone(),
            pending,
        });
        self
    }
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn prune_redundant_queued_effects<R: StateReadOnly>(
    state: &R,
    mut queued: Vec<crate::smartcontracts::ivm::host::QueuedEffect>,
) -> Vec<crate::smartcontracts::ivm::host::QueuedEffect> {
    let mut instructions: Vec<_> = queued
        .iter()
        .filter_map(|effect| effect.instruction().cloned())
        .collect();
    let mut positions: Vec<_> = queued
        .iter()
        .enumerate()
        .filter_map(|(index, effect)| effect.instruction().map(|_| index))
        .collect();
    prune_redundant_contract_ops_with_metadata(state, &mut instructions, Some(&mut positions));
    let mut index = 0usize;
    queued.retain(|effect| {
        let retain = effect.instruction().is_none() || positions.binary_search(&index).is_ok();
        index += 1;
        retain
    });
    queued
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn tx_overlay_from_host_queued<R: StateReadOnly>(
    state_ro: &R,
    queued: Vec<crate::smartcontracts::ivm::host::QueuedEffect>,
    ivm_gas_used: u64,
    completed_axt: Vec<ivm::axt::HostAxtState>,
    durable_state_overlay: BTreeMap<StatePath, Option<Vec<u8>>>,
    durable_state_authorizations: BTreeMap<
        StatePath,
        Option<ContractEntrypointAuthorizationSnapshot>,
    >,
) -> TxOverlay {
    let queued = prune_redundant_queued_effects(state_ro, queued);
    TxOverlay::from_queued_execution(
        queued,
        ivm_gas_used,
        completed_axt,
        durable_state_overlay,
        durable_state_authorizations,
        TxOverlaySource::ContractCall,
    )
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn tx_overlay_from_ivm_proved_replay<R: StateReadOnly>(
    state_ro: &R,
    replay: IvmProvedReplay,
) -> TxOverlay {
    let IvmProvedReplay {
        queued: replay_queued,
        completed_axt,
        durable_state_overlay,
        durable_state_authorizations,
        #[cfg(test)]
            access_log: _,
        gas_used,
    } = replay;
    let queued = prune_redundant_queued_effects(state_ro, replay_queued);
    TxOverlay::from_ivm_proved_execution(
        queued,
        gas_used,
        completed_axt,
        durable_state_overlay,
        durable_state_authorizations,
    )
}
#[cfg(any(test, feature = "iroha-core-tests"))]
struct GenericOverlayExecution {
    overlay: TxOverlay,
    #[cfg(test)]
    access_log: Option<ivm::host::AccessLog>,
    #[cfg(test)]
    access_fence: VmAccessFence,
    #[cfg(test)]
    force_live_rebuild: bool,
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn validate_generic_program_context<R: StateReadOnly>(
    state_ro: &R,
    tx: &SignedTransaction,
    summary: &GenericProgramSummary,
) -> Result<(), OverlayBuildError> {
    crate::smartcontracts::ivm::validate_generic_execution_context(
        state_ro.world(),
        tx.metadata(),
        routed_artifact_id(state_ro, tx.payload(), summary.code_hash)?,
    )
    .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))
}
#[cfg(any(test, feature = "iroha-core-tests"))]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn execute_generic_program_overlay<R>(
    tx: &SignedTransaction,
    state_ro: &R,
    summary: &GenericProgramSummary,
    ivm_cache: &mut IvmCache,
    accounts: Arc<Vec<AccountId>>,
    streaming_meta: StreamingOverlayMetadata,
    zk_enabled: bool,
    max_cycles: Option<u64>,
    capture_access_log: bool,
) -> Result<GenericOverlayExecution, OverlayBuildError>
where
    R: StateReadOnly + QueryStateSource,
{
    validate_generic_program_context(state_ro, tx, summary)?;
    let meta = summary.metadata.clone();
    validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
    let wants_zk = meta.mode & ivm::ivm_mode::ZK != 0;
    if wants_zk && !zk_enabled {
        return Err(OverlayBuildError::HeaderPolicy(
            IvmAdmissionError::UnsupportedFeatureBits(ivm::ivm_mode::ZK),
        ));
    }
    let governed_cycles = crate::smartcontracts::ivm::validate_cycle_limits(
        &meta,
        state_ro.pipeline().ivm_max_cycles_upper_bound,
        state_ro.world().parameters().smart_contract().fuel(),
    )
    .map_err(OverlayBuildError::HeaderPolicy)?;
    enforce_pre_execution_policy(state_ro.pipeline().ivm_max_cycles_upper_bound, &meta)?;
    let tx_gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
    let amx_analysis = cached_generic_amx_analysis(ivm_cache, summary)?;
    #[cfg(test)]
    let access_fence = VmAccessFence::from_program_analysis(&amx_analysis);
    #[cfg(test)]
    let force_live_rebuild = VmAccessFence::requires_live_rebuild(&amx_analysis);
    let prepared_contract_cache = ivm_cache.prepared_contract_cache();
    let mut vm = ivm_cache
        .checkout_generic_runtime(summary, tx_gas_limit, smart_contract_heap_limit(state_ro))
        .map_err(OverlayBuildError::IvmLoad)?;
    let mut host = crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts(
        tx.authority().clone(),
        accounts,
    );
    host.set_output_limits_from_parameters(state_ro.world().parameters().smart_contract());
    host.set_generic_execution();
    host.set_prepared_contract_cache(prepared_contract_cache);
    host.set_amx_analysis(amx_analysis);
    let amx_limits =
        crate::smartcontracts::ivm::host::CoreHost::amx_limits_from_config(state_ro.pipeline());
    host.set_amx_limits(amx_limits);
    host.hydrate_axt_state(state_ro)?;
    host.set_public_inputs_from_parameters(state_ro.world().parameters());
    host.set_vrf_epoch_seeds_from_state(state_ro)
        .map_err(|error| {
            contract_registry_attempt_error(error.map_rejection(ValidationFail::InternalError))
        })?;
    host.set_query_state(state_ro);
    host.set_bound_contract_records_by_subject_snapshot(
        code::snapshot_bound_contract_records_by_subject(state_ro)
            .map_err(contract_registry_attempt_error)?,
    );
    apply_streaming_metadata(&mut host, streaming_meta);
    #[cfg(feature = "telemetry")]
    host.set_telemetry(state_ro.metrics().clone());
    host.set_crypto_config(state_ro.crypto());
    host.set_zk_config(state_ro.zk());
    host.set_chain_id(state_ro.chain_id());
    host.set_zk_snapshots_from_world(state_ro.world(), state_ro.zk())
        .map_err(OverlayBuildError::IvmRun)?;
    if capture_access_log {
        host = host.with_access_logging();
    }
    begin_overlay_access_log(&mut host, capture_access_log)?;
    let effective_cycles = max_cycles.map_or_else(
        || governed_cycles.get(),
        |cap| cap.min(governed_cycles.get()),
    );
    vm.set_max_cycles(effective_cycles);
    vm.set_gas_limit(tx_gas_limit);
    vm.set_zk_trace_enabled(false);
    run_vm_with_host(&mut vm, &mut host)?;
    let ivm_gas_used = tx_gas_limit.saturating_sub(vm.remaining_gas());
    let access_log = finish_overlay_access_log(&mut host, capture_access_log)?;
    #[cfg(not(test))]
    let _ = &access_log;
    let queued = host.drain_queued_effects_with_contract_runtime_context(None);
    let (durable_state_overlay, durable_state_authorizations) =
        host.drain_durable_state_overlay_with_authorizations();
    let completed_axt = host.drain_completed_axt_states();
    let overlay = tx_overlay_from_host_queued(
        state_ro,
        queued,
        ivm_gas_used,
        completed_axt,
        durable_state_overlay,
        durable_state_authorizations,
    );
    Ok(GenericOverlayExecution {
        overlay,
        #[cfg(test)]
        access_log,
        #[cfg(test)]
        access_fence,
        #[cfg(test)]
        force_live_rebuild,
    })
}
#[cfg(any(test, feature = "iroha-core-tests"))]
/// Build an overlay for a signed transaction without mutating state.
///
/// # Errors
/// Returns an error when the IVM header fails policy checks, loading fails, or VM execution fails.
pub fn build_overlay_for_transaction<R>(
    tx: &SignedTransaction,
    state_ro: &R,
) -> Result<TxOverlay, OverlayBuildError>
where
    R: StateReadOnly + QueryStateSource,
{
    let mut ivm_cache = crate::smartcontracts::ivm::cache::IvmCache::new();
    build_overlay_for_transaction_with_cache(tx, state_ro, &mut ivm_cache)
}
#[cfg(any(test, feature = "iroha-core-tests"))]
/// Build an overlay for a signed transaction using a caller-provided IVM cache.
///
/// # Errors
/// Returns an error when the IVM header fails policy checks, loading fails, or VM execution fails.
#[allow(clippy::too_many_lines)]
pub fn build_overlay_for_transaction_with_cache<R>(
    tx: &SignedTransaction,
    state_ro: &R,
    ivm_cache: &mut crate::smartcontracts::ivm::cache::IvmCache,
) -> Result<TxOverlay, OverlayBuildError>
where
    R: StateReadOnly + QueryStateSource,
{
    match tx.instructions() {
        Executable::Instructions(batch) => {
            // We already have fully-formed owned instructions; just clone boxes.
            let mut instrs: Vec<InstructionBox> = batch.iter().cloned().collect();
            prune_redundant_contract_ops(state_ro, &mut instrs);
            Ok(TxOverlay::from_instructions(instrs))
        }
        Executable::Batch(_) => Err(OverlayBuildError::ContractCall(
            "Executable::Batch must execute through the live scheduler barrier".to_owned(),
        )),
        Executable::ContractCall(call) => {
            let identity = code::fetch_bound_contract_identity(state_ro, &call.contract_address)
                .map_err(contract_registry_attempt_error)?
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract instance `{}` not found in WSV",
                        call.contract_address
                    ))
                })?;
            crate::executor::ensure_contract_invocation_code_hash(call, identity.code_hash)
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let code_hash = identity.code_hash;
            let artifact_id = ContractArtifactId::for_address(&call.contract_address, code_hash)
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let manifest = state_ro
                .world()
                .contract_manifests()
                .get(&artifact_id)
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract instance `{}` has no manifest",
                        call.contract_address
                    ))
                })?;
            let code_bytes = state_ro
                .world()
                .contract_code()
                .get(&artifact_id)
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract instance `{}` has no bytecode",
                        call.contract_address
                    ))
                })?;
            let summary = ivm_cache
                .summarize_program_with_hash(code_hash, code_bytes.as_ref())
                .map_err(map_program_summary_error)?;
            let gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
            let meta = summary.metadata.clone();
            validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
            let wants_zk = meta.mode & ivm::ivm_mode::ZK != 0;
            if wants_zk && !(state_ro.zk().pipa_r.enabled || state_ro.zk().stark.enabled) {
                return Err(OverlayBuildError::HeaderPolicy(
                    IvmAdmissionError::UnsupportedFeatureBits(ivm::ivm_mode::ZK),
                ));
            }
            enforce_pre_execution_policy(state_ro.pipeline().ivm_max_cycles_upper_bound, &meta)?;
            validate_bound_contract_manifest(manifest, &summary)?;
            let amx_analysis = cached_amx_analysis(ivm_cache, &summary, code_bytes.as_ref())?;
            let lifecycle_transition = crate::executor::validate_prepared_contract_lifecycle_call(
                state_ro.world(),
                &call.contract_address,
                summary.code_hash,
                summary.prepared_contract(),
                &call.entrypoint,
            )
            .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let entrypoint_authorization = crate::executor::authorize_prepared_contract_selector(
                state_ro.world(),
                tx.authority(),
                summary.prepared_contract(),
                &call.entrypoint,
                &identity,
            )
            .map_err(contract_registry_attempt_error)?;
            let contract_call_context = parse_prepared_contract_invocation_execution_context(
                call,
                summary.prepared_contract(),
                gas_limit,
                None,
            )?;
            let mut vm = summary
                .checkout_runtime(gas_limit, smart_contract_heap_limit(state_ro))
                .map_err(OverlayBuildError::IvmLoad)?;
            let contract_subject =
                code::fetch_bound_contract_subject(state_ro, &call.contract_address).ok_or_else(
                    || {
                        OverlayBuildError::ContractCall(format!(
                            "contract instance `{}` has no valid subject binding",
                            call.contract_address
                        ))
                    },
                )?;
            let contract_runtime_context = Some(crate::executor::ContractRuntimeExecutionContext {
                contract_subject,
                contract_address: call.contract_address.clone(),
                contract_alias: identity.contract_alias.clone(),
                entrypoint: contract_call_context
                    .entrypoint
                    .clone()
                    .expect("contract invocation parser must set entrypoint"),
            });
            let accounts = state_ro.accounts_snapshot();
            let streaming_meta = resolve_streaming_metadata(state_ro, tx.authority());
            let mut host =
                crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts_and_argument_record(
                    tx.authority().clone(),
                    Arc::clone(&accounts),
                    contract_call_context.argument_record.clone(),
                );
            host.set_output_limits_from_parameters(state_ro.world().parameters().smart_contract());
            host.set_prepared_contract_cache(summary.prepared_contract_cache());
            host.set_amx_analysis(amx_analysis);
            let amx_limits = crate::smartcontracts::ivm::host::CoreHost::amx_limits_from_config(
                state_ro.pipeline(),
            );
            host.set_amx_limits(amx_limits);
            host.hydrate_axt_state(state_ro)?;
            host.set_public_inputs_from_parameters(state_ro.world().parameters());
            host.set_vrf_epoch_seeds_from_state(state_ro)
                .map_err(|error| {
                    contract_registry_attempt_error(
                        error.map_rejection(ValidationFail::InternalError),
                    )
                })?;
            host.set_query_state(state_ro);
            host.set_contract_runtime_context(contract_runtime_context.clone());
            host.set_contract_entrypoint_authorization(Some(entrypoint_authorization.clone()));
            if let Some(pending) = lifecycle_transition {
                host.set_contract_lifecycle_transition(&call.contract_address, pending);
            }
            apply_streaming_metadata(&mut host, streaming_meta);
            #[cfg(feature = "telemetry")]
            host.set_telemetry(state_ro.metrics().clone());
            host.set_crypto_config(state_ro.crypto());
            host.set_zk_config(state_ro.zk());
            host.set_chain_id(state_ro.chain_id());
            host.set_zk_snapshots_from_world(state_ro.world(), state_ro.zk())
                .map_err(OverlayBuildError::IvmRun)?;
            vm.set_gas_limit(gas_limit);
            apply_contract_call_execution_context(&mut vm, Some(&contract_call_context))?;
            configure_zk_lane_trace_collection(&mut vm, state_ro.zk().trace.enabled);
            let returned_error = run_vm_with_host(&mut vm, &mut host)?;
            let lifecycle_transition = lifecycle_transition.filter(|_| !returned_error);
            let ivm_gas_used = gas_limit.saturating_sub(vm.remaining_gas());
            let transport_caps_snapshot = host.transport_caps_snapshot().copied();
            let negotiated_caps_snapshot = host.negotiated_caps_snapshot().copied();
            let queued = host.drain_queued_effects_with_contract_runtime_context(
                contract_runtime_context.clone(),
            );
            let (durable_state_overlay, durable_state_authorizations) =
                host.drain_durable_state_overlay_with_authorizations();
            let completed_axt = host.drain_completed_axt_states();
            if state_ro.zk().pipa_r.enabled && vm.zk_mode_enabled() {
                let _ = crate::pipeline::zk_lane::capture_and_submit(
                    &vm,
                    state_ro.prepared_contract_cache().execution_budget(),
                    Some(iroha_crypto::Hash::prehashed(*tx.hash().as_ref())),
                    summary.prepared_contract().shared_artifact(),
                    None,
                    transport_caps_snapshot,
                    negotiated_caps_snapshot,
                );
            }
            Ok(tx_overlay_from_host_queued(
                state_ro,
                queued,
                ivm_gas_used,
                completed_axt,
                durable_state_overlay,
                durable_state_authorizations,
            )
            .with_entrypoint_authorization(Some(entrypoint_authorization))
            .with_lifecycle_completion(&call.contract_address, lifecycle_transition))
        }
        Executable::Ivm(bytecode) => {
            // Validate header against node policy
            let admitted = ivm_cache
                .summarize_executable(bytecode.as_ref())
                .map_err(map_program_summary_error)?;
            let summary = match admitted {
                ExecutableProgramSummary::Contract(summary) => summary,
                ExecutableProgramSummary::Generic(summary) => {
                    let execution = execute_generic_program_overlay(
                        tx,
                        state_ro,
                        &summary,
                        ivm_cache,
                        state_ro.accounts_snapshot(),
                        resolve_streaming_metadata(state_ro, tx.authority()),
                        state_ro.zk().pipa_r.enabled || state_ro.zk().stark.enabled,
                        None,
                        false,
                    )?;
                    return Ok(execution.overlay);
                }
            };
            let gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
            let meta = summary.metadata.clone();
            validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
            // ABI gating is handled in validate_header_policy (v1-only release).
            let wants_zk = meta.mode & ivm::ivm_mode::ZK != 0;
            if wants_zk && !(state_ro.zk().pipa_r.enabled || state_ro.zk().stark.enabled) {
                return Err(OverlayBuildError::HeaderPolicy(
                    IvmAdmissionError::UnsupportedFeatureBits(ivm::ivm_mode::ZK),
                ));
            }
            enforce_pre_execution_policy(state_ro.pipeline().ivm_max_cycles_upper_bound, &meta)?;
            validate_contract_binding(state_ro, tx.payload(), &summary)?;
            let amx_analysis = cached_amx_analysis(ivm_cache, &summary, bytecode.as_ref())?;
            let selector = crate::executor::requested_contract_entrypoint(tx.metadata())
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(
                        "self-describing raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                            .to_owned(),
                    )
                })?;
            let identity = crate::executor::require_raw_contract_runtime_identity(
                state_ro.world(),
                summary.code_hash,
                tx.metadata(),
            )
            .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            code::ensure_contract_execution_allowed(
                state_ro.world(),
                &identity.contract_address,
                state_ro.block_height_hint().ok_or_else(|| {
                    OverlayBuildError::ContractCall(
                        "ordinary raw-IVM overlay preparation requires an execution block height"
                            .to_owned(),
                    )
                })?,
            )
            .map_err(OverlayBuildError::ContractCall)?;
            let entrypoint_authorization =
                crate::executor::authorize_prepared_raw_contract_selector(
                    state_ro.world(),
                    tx.authority(),
                    summary.prepared_contract(),
                    &selector,
                    &identity,
                )
                .map_err(contract_registry_attempt_error)?;
            let contract_call_context = parse_prepared_contract_call_execution_context(
                tx.metadata(),
                summary.prepared_contract(),
                gas_limit,
                None,
            )?;
            let contract_subject =
                code::fetch_bound_contract_subject(state_ro, &identity.contract_address)
                    .ok_or_else(|| {
                        OverlayBuildError::ContractCall(format!(
                            "contract instance `{}` has no valid subject binding",
                            identity.contract_address
                        ))
                    })?;
            let contract_runtime_context = Some(crate::executor::ContractRuntimeExecutionContext {
                contract_subject,
                contract_address: identity.contract_address.clone(),
                contract_alias: identity.contract_alias.clone(),
                entrypoint: selector,
            });
            let mut vm = summary
                .checkout_runtime(gas_limit, smart_contract_heap_limit(state_ro))
                .map_err(OverlayBuildError::IvmLoad)?;
            // Run CoreHost to collect queued ISIs
            // Snapshot of accounts for deterministic helpers
            let accounts = state_ro.accounts_snapshot();
            let streaming_meta = resolve_streaming_metadata(state_ro, tx.authority());
            let mut host = if let Some(context) = contract_call_context.as_ref() {
                crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts_and_argument_record(
                    tx.authority().clone(),
                    Arc::clone(&accounts),
                    context.argument_record.clone(),
                )
            } else {
                crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts(
                    tx.authority().clone(),
                    Arc::clone(&accounts),
                )
            };
            host.set_output_limits_from_parameters(state_ro.world().parameters().smart_contract());
            host.set_prepared_contract_cache(summary.prepared_contract_cache());
            host.set_amx_analysis(amx_analysis);
            let amx_limits = crate::smartcontracts::ivm::host::CoreHost::amx_limits_from_config(
                state_ro.pipeline(),
            );
            host.set_amx_limits(amx_limits);
            host.hydrate_axt_state(state_ro)?;
            host.set_public_inputs_from_parameters(state_ro.world().parameters());
            host.set_vrf_epoch_seeds_from_state(state_ro)
                .map_err(|error| {
                    contract_registry_attempt_error(
                        error.map_rejection(ValidationFail::InternalError),
                    )
                })?;
            host.set_query_state(state_ro);
            host.set_contract_runtime_context(contract_runtime_context.clone());
            host.set_contract_entrypoint_authorization(Some(entrypoint_authorization.clone()));
            host.set_bound_contract_records_by_subject_snapshot(
                code::snapshot_bound_contract_records_by_subject(state_ro)
                    .map_err(contract_registry_attempt_error)?,
            );
            apply_streaming_metadata(&mut host, streaming_meta);
            #[cfg(feature = "telemetry")]
            host.set_telemetry(state_ro.metrics().clone());
            host.set_crypto_config(state_ro.crypto());
            host.set_zk_config(state_ro.zk());
            host.set_chain_id(state_ro.chain_id());
            host.set_zk_snapshots_from_world(state_ro.world(), state_ro.zk())
                .map_err(OverlayBuildError::IvmRun)?;
            vm.set_gas_limit(gas_limit);
            apply_contract_call_execution_context(&mut vm, contract_call_context.as_ref())?;
            configure_zk_lane_trace_collection(&mut vm, state_ro.zk().trace.enabled);
            run_vm_with_host(&mut vm, &mut host)?;
            let ivm_gas_used = gas_limit.saturating_sub(vm.remaining_gas());
            let transport_caps_snapshot = host.transport_caps_snapshot().copied();
            let negotiated_caps_snapshot = host.negotiated_caps_snapshot().copied();
            let mut queued = host.drain_queued_effects_with_contract_runtime_context(
                contract_runtime_context.clone(),
            );
            let (durable_state_overlay, durable_state_authorizations) =
                host.drain_durable_state_overlay_with_authorizations();
            let completed_axt = host.drain_completed_axt_states();
            // Emit a ZK-lane job with the formal trace (non-forking background verification)
            if state_ro.zk().pipa_r.enabled && vm.zk_mode_enabled() {
                let _ = crate::pipeline::zk_lane::capture_and_submit(
                    &vm,
                    state_ro.prepared_contract_cache().execution_budget(),
                    Some(iroha_crypto::Hash::prehashed(*tx.hash().as_ref())),
                    summary.prepared_contract().shared_artifact(),
                    None,
                    transport_caps_snapshot,
                    negotiated_caps_snapshot,
                );
            }
            append_verified_contract_metadata_registration_to_queued(
                state_ro,
                tx,
                &summary,
                bytecode.as_ref(),
                &mut queued,
                contract_runtime_context.as_ref(),
                &entrypoint_authorization,
            )?;
            Ok(tx_overlay_from_host_queued(
                state_ro,
                queued,
                ivm_gas_used,
                completed_axt,
                durable_state_overlay,
                durable_state_authorizations,
            )
            .with_entrypoint_authorization(Some(entrypoint_authorization)))
        }
        Executable::IvmProved(proved) => {
            // Validate header against node policy (same checks as `Executable::Ivm`).
            let summary = ivm_cache
                .summarize_program(proved.bytecode.as_ref())
                .map_err(map_program_summary_error)?;
            let gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
            let meta = summary.metadata.clone();
            validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
            let wants_zk = meta.mode & ivm::ivm_mode::ZK != 0;
            if !wants_zk {
                return Err(OverlayBuildError::ZkProof(
                    "Executable::IvmProved requires IVM ZK mode bit (mode & ZK != 0)".to_owned(),
                ));
            }
            enforce_pre_execution_policy(state_ro.pipeline().ivm_max_cycles_upper_bound, &meta)?;
            validate_contract_binding(state_ro, tx.payload(), &summary)?;
            let selector = crate::executor::requested_contract_entrypoint(tx.metadata())
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(
                        "self-describing proved raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                            .to_owned(),
                    )
                })?;
            let identity = crate::executor::require_raw_contract_runtime_identity(
                state_ro.world(),
                summary.code_hash,
                tx.metadata(),
            )
            .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let entrypoint_authorization =
                crate::executor::authorize_prepared_raw_contract_selector(
                    state_ro.world(),
                    tx.authority(),
                    summary.prepared_contract(),
                    &selector,
                    &identity,
                )
                .map_err(contract_registry_attempt_error)?;
            // Proved executions do not support the implicit manifest registration append;
            // if a manifest is attached and missing from WSV, reject deterministically.
            enforce_manifest_is_pre_registered(state_ro, tx.payload(), summary.code_hash)?;
            let replay = verify_ivm_proved_execution(
                state_ro,
                tx,
                proved,
                &summary,
                None,
                &mut IvmProvedReplayWork::default(),
            )?;
            require_ivm_proved_gas_within_limit(tx, replay.gas_used)?;
            let _ = gas_limit; // still required for admission (fees), even when skipping VM.
            Ok(tx_overlay_from_ivm_proved_replay(state_ro, replay)
                .with_entrypoint_authorization(Some(entrypoint_authorization)))
        }
    }
}
/// Build an overlay for a transaction using a pre-captured accounts snapshot.
/// Build an overlay for a signed transaction, using a provided snapshot of accounts.
///
/// # Errors
/// Returns an error if the IVM header fails policy checks or running the VM fails.
pub fn build_overlay_for_transaction_with_accounts(
    tx: &SignedTransaction,
    accounts: &[AccountId],
) -> Result<TxOverlay, OverlayBuildError> {
    match tx.instructions() {
        Executable::Instructions(batch) => {
            let instrs: Vec<InstructionBox> = batch.iter().cloned().collect();
            Ok(TxOverlay::from_instructions(instrs))
        }
        Executable::Batch(_) => Err(OverlayBuildError::ContractCall(
            "Executable::Batch requires live state and cannot be flattened into an overlay"
                .to_owned(),
        )),
        Executable::ContractCall(_) => Err(OverlayBuildError::ContractCall(
            "Executable::ContractCall requires a full state view for overlay building".to_owned(),
        )),
        Executable::Ivm(bytecode) => {
            let parsed = ivm::ProgramMetadata::parse(bytecode.as_ref())
                .map_err(|_| OverlayBuildError::IvmHeaderParse)?;
            let meta = parsed.metadata;
            validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
            let wants_zk = meta.mode & ivm::ivm_mode::ZK != 0;
            if wants_zk {
                return Err(OverlayBuildError::HeaderPolicy(
                    IvmAdmissionError::UnsupportedFeatureBits(ivm::ivm_mode::ZK),
                ));
            }
            let pipeline = default_pipeline_config();
            enforce_pre_execution_policy(pipeline.ivm_max_cycles_upper_bound, &meta)?;
            let tx_gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
            reject_raw_contract_without_state(bytecode.as_ref())?;
            crate::smartcontracts::ivm::validate_generic_execution_metadata(tx.metadata())
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let mut vm = ivm::IVM::try_new(tx_gas_limit).map_err(OverlayBuildError::IvmLoad)?;
            let contract_call_context = parse_raw_contract_call_execution_context(
                tx.metadata(),
                bytecode.as_ref(),
                tx_gas_limit,
            )?;
            let mut host = if let Some(context) = contract_call_context.as_ref() {
                crate::smartcontracts::ivm::host::CoreHost::with_accounts_and_argument_record(
                    tx.authority().clone(),
                    Arc::new(accounts.to_vec()),
                    context.argument_record.clone(),
                )
            } else {
                crate::smartcontracts::ivm::host::CoreHost::with_accounts(
                    tx.authority().clone(),
                    Arc::new(accounts.to_vec()),
                )
            };
            host.set_state_free_generic_execution();
            apply_streaming_metadata(&mut host, StreamingOverlayMetadata::default());
            vm.set_host(host);
            vm.load_program(bytecode.as_ref())
                .map_err(OverlayBuildError::IvmLoad)?;
            reject_state_free_axt_syscalls(bytecode.as_ref())?;
            vm.set_gas_limit(tx_gas_limit);
            apply_contract_call_execution_context(&mut vm, contract_call_context.as_ref())?;
            run_vm(&mut vm)?;
            let ivm_gas_used = tx_gas_limit.saturating_sub(vm.remaining_gas());
            let (mut queued, durable_state_overlay) = if let Some(h) = vm.host_mut_any()
                && let Some(host) = h.downcast_mut::<crate::smartcontracts::ivm::host::CoreHost>()
            {
                (
                    host.drain_instructions(),
                    host.drain_durable_state_overlay(),
                )
            } else {
                (Vec::new(), BTreeMap::new())
            };
            append_verified_contract_metadata_registration_without_state(
                tx,
                bytecode.as_ref(),
                &mut queued,
            )?;
            Ok(TxOverlay::from_ivm_execution(
                queued,
                ivm_gas_used,
                durable_state_overlay,
            ))
        }
        Executable::IvmProved(_) => Err(OverlayBuildError::ZkProof(
            "Executable::IvmProved requires a full state view for proof verification".to_owned(),
        )),
    }
}
#[cfg(test)]
/// Build an overlay with optional same-run access evidence for scheduler regression tests.
///
/// # Errors
/// Returns an error if the IVM header fails policy checks or running the VM fails.
#[allow(clippy::too_many_lines)]
pub(crate) fn build_prepared_overlay_for_transaction_with_accounts_zk<R>(
    tx: &SignedTransaction,
    accounts: Arc<Vec<AccountId>>,
    state_ro: &R,
    zk_enabled: bool,
    header: &BlockHeader,
    streaming_meta: StreamingOverlayMetadata,
    ivm_cache: &mut IvmCache,
    capture_access_log: bool,
    reused_argument_record: Option<ivm::PreparedArgumentRecord>,
) -> Result<PreparedTxOverlay, OverlayBuildError>
where
    R: StateReadOnly + QueryStateSource,
{
    match tx.instructions() {
        Executable::Instructions(batch) => {
            let instrs: Vec<InstructionBox> = batch.iter().cloned().collect();
            Ok(PreparedTxOverlay::new(
                TxOverlay::from_instructions(instrs),
                None,
                VmAccessFence::None,
                false,
            ))
        }
        Executable::Batch(_) => Err(OverlayBuildError::ContractCall(
            "Executable::Batch must execute through the live scheduler barrier".to_owned(),
        )),
        Executable::ContractCall(call) => {
            #[cfg(feature = "telemetry")]
            let program_prepare_start = Instant::now();
            let identity = code::fetch_bound_contract_identity(state_ro, &call.contract_address)
                .map_err(contract_registry_attempt_error)?
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract instance `{}` not found in WSV",
                        call.contract_address
                    ))
                })?;
            crate::executor::ensure_contract_invocation_code_hash(call, identity.code_hash)
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let code_hash = identity.code_hash;
            let artifact_id = ContractArtifactId::for_address(&call.contract_address, code_hash)
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let manifest = state_ro
                .world()
                .contract_manifests()
                .get(&artifact_id)
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract instance `{}` has no manifest",
                        call.contract_address
                    ))
                })?;
            let code_bytes = state_ro
                .world()
                .contract_code()
                .get(&artifact_id)
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract instance `{}` has no bytecode",
                        call.contract_address
                    ))
                })?;
            let summary = ivm_cache
                .summarize_program_with_hash(code_hash, code_bytes.as_ref())
                .map_err(map_program_summary_error)?;
            let meta = summary.metadata.clone();
            validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
            let wants_zk = meta.mode & ivm::ivm_mode::ZK != 0;
            if wants_zk && !zk_enabled {
                return Err(OverlayBuildError::HeaderPolicy(
                    IvmAdmissionError::UnsupportedFeatureBits(ivm::ivm_mode::ZK),
                ));
            }
            enforce_pre_execution_policy(state_ro.pipeline().ivm_max_cycles_upper_bound, &meta)?;
            validate_bound_contract_manifest(manifest, &summary)?;
            let tx_gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
            let amx_analysis = cached_amx_analysis(ivm_cache, &summary, code_bytes.as_ref())?;
            let access_fence = VmAccessFence::from_program_analysis(&amx_analysis);
            let force_live_rebuild = VmAccessFence::requires_live_rebuild(&amx_analysis);
            let lifecycle_transition = crate::executor::validate_prepared_contract_lifecycle_call(
                state_ro.world(),
                &call.contract_address,
                summary.code_hash,
                summary.prepared_contract(),
                &call.entrypoint,
            )
            .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let entrypoint_authorization = crate::executor::authorize_prepared_contract_selector(
                state_ro.world(),
                tx.authority(),
                summary.prepared_contract(),
                &call.entrypoint,
                &identity,
            )
            .map_err(contract_registry_attempt_error)?;
            let contract_call_context = parse_prepared_contract_invocation_execution_context(
                call,
                summary.prepared_contract(),
                tx_gas_limit,
                reused_argument_record.as_ref(),
            )?;
            let mut vm = summary
                .checkout_runtime(tx_gas_limit, smart_contract_heap_limit(state_ro))
                .map_err(OverlayBuildError::IvmLoad)?;
            #[cfg(feature = "telemetry")]
            observe_overlay_stage_ms(state_ro, "overlay_program_prepare", program_prepare_start);
            let contract_subject =
                code::fetch_bound_contract_subject(state_ro, &call.contract_address).ok_or_else(
                    || {
                        OverlayBuildError::ContractCall(format!(
                            "contract instance `{}` has no valid subject binding",
                            call.contract_address
                        ))
                    },
                )?;
            let contract_runtime_context = Some(crate::executor::ContractRuntimeExecutionContext {
                contract_subject,
                contract_address: call.contract_address.clone(),
                contract_alias: identity.contract_alias.clone(),
                entrypoint: contract_call_context
                    .entrypoint
                    .clone()
                    .expect("contract invocation parser must set entrypoint"),
            });
            let mut host: crate::smartcontracts::ivm::host::CoreHostImpl<
                crate::smartcontracts::ivm::host::QueryStateSlot<_>,
            > = crate::smartcontracts::ivm::host::CoreHostImpl::<
                crate::smartcontracts::ivm::host::QueryStateSlot<_>,
            >::with_accounts_and_argument_record(
                tx.authority().clone(),
                Arc::clone(&accounts),
                contract_call_context.argument_record.clone(),
            );
            host.set_output_limits_from_parameters(state_ro.world().parameters().smart_contract());
            host.set_prepared_contract_cache(summary.prepared_contract_cache());
            host.set_amx_analysis(amx_analysis);
            #[cfg(feature = "telemetry")]
            let host_hydrate_start = Instant::now();
            let amx_limits = crate::smartcontracts::ivm::host::CoreHost::amx_limits_from_config(
                state_ro.pipeline(),
            );
            host.set_amx_limits(amx_limits);
            host.hydrate_axt_state(state_ro)?;
            host.set_public_inputs_from_parameters(state_ro.world().parameters());
            host.set_vrf_epoch_seeds_from_state(state_ro)
                .map_err(|error| {
                    contract_registry_attempt_error(
                        error.map_rejection(ValidationFail::InternalError),
                    )
                })?;
            host.set_query_state(state_ro);
            host.set_contract_runtime_context(contract_runtime_context.clone());
            host.set_contract_entrypoint_authorization(Some(entrypoint_authorization.clone()));
            apply_streaming_metadata(&mut host, streaming_meta);
            #[cfg(feature = "telemetry")]
            host.set_telemetry(state_ro.metrics().clone());
            host.set_crypto_config(state_ro.crypto());
            host.set_zk_config(state_ro.zk());
            host.set_chain_id(state_ro.chain_id());
            host.set_zk_snapshots_from_world(state_ro.world(), state_ro.zk())
                .map_err(OverlayBuildError::IvmRun)?;
            if capture_access_log {
                host = host.with_access_logging();
            }
            begin_overlay_access_log(&mut host, capture_access_log)?;
            if let Some(pending) = lifecycle_transition {
                host.set_contract_lifecycle_transition(&call.contract_address, pending);
            }
            vm.set_gas_limit(tx_gas_limit);
            apply_contract_call_execution_context(&mut vm, Some(&contract_call_context))?;
            configure_zk_lane_trace_collection(&mut vm, state_ro.zk().trace.enabled);
            #[cfg(feature = "telemetry")]
            observe_overlay_stage_ms(state_ro, "overlay_host_hydrate", host_hydrate_start);
            #[cfg(feature = "telemetry")]
            let vm_run_start = Instant::now();
            let returned_error = run_vm_with_host(&mut vm, &mut host)?;
            let lifecycle_transition = lifecycle_transition.filter(|_| !returned_error);
            #[cfg(feature = "telemetry")]
            observe_overlay_stage_ms(state_ro, "overlay_vm_run", vm_run_start);
            let ivm_gas_used = tx_gas_limit.saturating_sub(vm.remaining_gas());
            let access_log = finish_overlay_access_log(&mut host, capture_access_log)?;
            let transport_caps_snapshot = host.transport_caps_snapshot().copied();
            let negotiated_caps_snapshot = host.negotiated_caps_snapshot().copied();
            let queued = host.drain_queued_effects_with_contract_runtime_context(
                contract_runtime_context.clone(),
            );
            let (durable_state_overlay, durable_state_authorizations) =
                host.drain_durable_state_overlay_with_authorizations();
            let completed_axt = host.drain_completed_axt_states();
            if state_ro.zk().pipa_r.enabled && vm.zk_mode_enabled() {
                let _ = crate::pipeline::zk_lane::capture_and_submit(
                    &vm,
                    state_ro.prepared_contract_cache().execution_budget(),
                    Some(iroha_crypto::Hash::prehashed(*tx.hash().as_ref())),
                    summary.prepared_contract().shared_artifact(),
                    Some(header),
                    transport_caps_snapshot,
                    negotiated_caps_snapshot,
                );
            }
            Ok(PreparedTxOverlay::new(
                tx_overlay_from_host_queued(
                    state_ro,
                    queued,
                    ivm_gas_used,
                    completed_axt,
                    durable_state_overlay,
                    durable_state_authorizations,
                )
                .with_entrypoint_authorization(Some(entrypoint_authorization))
                .with_lifecycle_completion(&call.contract_address, lifecycle_transition),
                access_log,
                access_fence,
                force_live_rebuild,
            )
            .with_prepared_argument_record(contract_call_context.argument_record.clone())
            .with_prepared_contract(summary.prepared_contract()))
        }
        Executable::Ivm(bytecode) => {
            #[cfg(feature = "telemetry")]
            let program_prepare_start = Instant::now();
            let admitted = ivm_cache
                .summarize_executable(bytecode.as_ref())
                .map_err(map_program_summary_error)?;
            let summary = match admitted {
                ExecutableProgramSummary::Contract(summary) => summary,
                ExecutableProgramSummary::Generic(summary) => {
                    let execution = execute_generic_program_overlay(
                        tx,
                        state_ro,
                        &summary,
                        ivm_cache,
                        Arc::clone(&accounts),
                        streaming_meta,
                        zk_enabled,
                        None,
                        capture_access_log,
                    )?;
                    return Ok(PreparedTxOverlay::new(
                        execution.overlay,
                        execution.access_log,
                        execution.access_fence,
                        execution.force_live_rebuild,
                    ));
                }
            };
            let meta = summary.metadata.clone();
            validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
            let wants_zk = meta.mode & ivm::ivm_mode::ZK != 0;
            if wants_zk && !zk_enabled {
                return Err(OverlayBuildError::HeaderPolicy(
                    IvmAdmissionError::UnsupportedFeatureBits(ivm::ivm_mode::ZK),
                ));
            }
            enforce_pre_execution_policy(state_ro.pipeline().ivm_max_cycles_upper_bound, &meta)?;
            validate_contract_binding(state_ro, tx.payload(), &summary)?;
            let tx_gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
            let amx_analysis = cached_amx_analysis(ivm_cache, &summary, bytecode.as_ref())?;
            let access_fence = VmAccessFence::from_program_analysis(&amx_analysis);
            let force_live_rebuild = VmAccessFence::requires_live_rebuild(&amx_analysis);
            let selector = crate::executor::requested_contract_entrypoint(tx.metadata())
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(
                        "self-describing raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                            .to_owned(),
                    )
                })?;
            let identity = crate::executor::require_raw_contract_runtime_identity(
                state_ro.world(),
                summary.code_hash,
                tx.metadata(),
            )
            .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            code::ensure_contract_execution_allowed(
                state_ro.world(),
                &identity.contract_address,
                header.height().get(),
            )
            .map_err(OverlayBuildError::ContractCall)?;
            let entrypoint_authorization =
                crate::executor::authorize_prepared_raw_contract_selector(
                    state_ro.world(),
                    tx.authority(),
                    summary.prepared_contract(),
                    &selector,
                    &identity,
                )
                .map_err(contract_registry_attempt_error)?;
            let contract_call_context = parse_prepared_contract_call_execution_context(
                tx.metadata(),
                summary.prepared_contract(),
                tx_gas_limit,
                reused_argument_record.as_ref(),
            )?;
            let contract_subject =
                code::fetch_bound_contract_subject(state_ro, &identity.contract_address)
                    .ok_or_else(|| {
                        OverlayBuildError::ContractCall(format!(
                            "contract instance `{}` has no valid subject binding",
                            identity.contract_address
                        ))
                    })?;
            let contract_runtime_context = Some(crate::executor::ContractRuntimeExecutionContext {
                contract_subject,
                contract_address: identity.contract_address.clone(),
                contract_alias: identity.contract_alias.clone(),
                entrypoint: selector,
            });
            let mut vm = summary
                .checkout_runtime(tx_gas_limit, smart_contract_heap_limit(state_ro))
                .map_err(OverlayBuildError::IvmLoad)?;
            #[cfg(feature = "telemetry")]
            observe_overlay_stage_ms(state_ro, "overlay_program_prepare", program_prepare_start);
            let mut host = if let Some(context) = contract_call_context.as_ref() {
                crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts_and_argument_record(
                    tx.authority().clone(),
                    Arc::clone(&accounts),
                    context.argument_record.clone(),
                )
            } else {
                crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts(
                    tx.authority().clone(),
                    Arc::clone(&accounts),
                )
            };
            host.set_output_limits_from_parameters(state_ro.world().parameters().smart_contract());
            host.set_prepared_contract_cache(summary.prepared_contract_cache());
            host.set_amx_analysis(amx_analysis);
            #[cfg(feature = "telemetry")]
            let host_hydrate_start = Instant::now();
            let amx_limits = crate::smartcontracts::ivm::host::CoreHost::amx_limits_from_config(
                state_ro.pipeline(),
            );
            host.set_amx_limits(amx_limits);
            host.hydrate_axt_state(state_ro)?;
            host.set_public_inputs_from_parameters(state_ro.world().parameters());
            host.set_vrf_epoch_seeds_from_state(state_ro)
                .map_err(|error| {
                    contract_registry_attempt_error(
                        error.map_rejection(ValidationFail::InternalError),
                    )
                })?;
            host.set_query_state(state_ro);
            host.set_contract_runtime_context(contract_runtime_context.clone());
            host.set_contract_entrypoint_authorization(Some(entrypoint_authorization.clone()));
            host.set_bound_contract_records_by_subject_snapshot(
                code::snapshot_bound_contract_records_by_subject(state_ro)
                    .map_err(contract_registry_attempt_error)?,
            );
            apply_streaming_metadata(&mut host, streaming_meta);
            #[cfg(feature = "telemetry")]
            host.set_telemetry(state_ro.metrics().clone());
            host.set_crypto_config(state_ro.crypto());
            host.set_zk_config(state_ro.zk());
            host.set_chain_id(state_ro.chain_id());
            host.set_zk_snapshots_from_world(state_ro.world(), state_ro.zk())
                .map_err(OverlayBuildError::IvmRun)?;
            if capture_access_log {
                host = host.with_access_logging();
            }
            begin_overlay_access_log(&mut host, capture_access_log)?;
            vm.set_gas_limit(tx_gas_limit);
            apply_contract_call_execution_context(&mut vm, contract_call_context.as_ref())?;
            configure_zk_lane_trace_collection(&mut vm, state_ro.zk().trace.enabled);
            #[cfg(feature = "telemetry")]
            observe_overlay_stage_ms(state_ro, "overlay_host_hydrate", host_hydrate_start);
            #[cfg(feature = "telemetry")]
            let vm_run_start = Instant::now();
            run_vm_with_host(&mut vm, &mut host)?;
            #[cfg(feature = "telemetry")]
            observe_overlay_stage_ms(state_ro, "overlay_vm_run", vm_run_start);
            let ivm_gas_used = tx_gas_limit.saturating_sub(vm.remaining_gas());
            let access_log = finish_overlay_access_log(&mut host, capture_access_log)?;
            let transport_caps_snapshot = host.transport_caps_snapshot().copied();
            let negotiated_caps_snapshot = host.negotiated_caps_snapshot().copied();
            let mut queued = host.drain_queued_effects_with_contract_runtime_context(
                contract_runtime_context.clone(),
            );
            let (durable_state_overlay, durable_state_authorizations) =
                host.drain_durable_state_overlay_with_authorizations();
            let completed_axt = host.drain_completed_axt_states();
            if state_ro.zk().pipa_r.enabled && vm.zk_mode_enabled() {
                let _ = crate::pipeline::zk_lane::capture_and_submit(
                    &vm,
                    state_ro.prepared_contract_cache().execution_budget(),
                    Some(iroha_crypto::Hash::prehashed(*tx.hash().as_ref())),
                    summary.prepared_contract().shared_artifact(),
                    Some(header),
                    transport_caps_snapshot,
                    negotiated_caps_snapshot,
                );
            }
            append_verified_contract_metadata_registration_to_queued(
                state_ro,
                tx,
                &summary,
                bytecode.as_ref(),
                &mut queued,
                contract_runtime_context.as_ref(),
                &entrypoint_authorization,
            )?;
            Ok(PreparedTxOverlay::new(
                tx_overlay_from_host_queued(
                    state_ro,
                    queued,
                    ivm_gas_used,
                    completed_axt,
                    durable_state_overlay,
                    durable_state_authorizations,
                )
                .with_entrypoint_authorization(Some(entrypoint_authorization)),
                access_log,
                access_fence,
                force_live_rebuild,
            )
            .with_prepared_argument_record(
                contract_call_context
                    .as_ref()
                    .and_then(|context| context.argument_record.clone()),
            )
            .with_prepared_contract(summary.prepared_contract()))
        }
        Executable::IvmProved(proved) => {
            let summary = ivm_cache
                .summarize_program(proved.bytecode.as_ref())
                .map_err(map_program_summary_error)?;
            let meta = summary.metadata.clone();
            validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
            enforce_pre_execution_policy(state_ro.pipeline().ivm_max_cycles_upper_bound, &meta)?;
            validate_contract_binding(state_ro, tx.payload(), &summary)?;
            let selector = crate::executor::requested_contract_entrypoint(tx.metadata())
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(
                        "self-describing proved raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                            .to_owned(),
                    )
                })?;
            let identity = crate::executor::require_raw_contract_runtime_identity(
                state_ro.world(),
                summary.code_hash,
                tx.metadata(),
            )
            .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let entrypoint_authorization =
                crate::executor::authorize_prepared_raw_contract_selector(
                    state_ro.world(),
                    tx.authority(),
                    summary.prepared_contract(),
                    &selector,
                    &identity,
                )
                .map_err(contract_registry_attempt_error)?;
            let amx_analysis = cached_amx_analysis(ivm_cache, &summary, proved.bytecode.as_ref())?;
            let access_fence = VmAccessFence::from_program_analysis(&amx_analysis);
            let force_live_rebuild = VmAccessFence::requires_live_rebuild(&amx_analysis);
            enforce_manifest_is_pre_registered(state_ro, tx.payload(), summary.code_hash)?;
            let replay = verify_ivm_proved_execution(
                state_ro,
                tx,
                proved,
                &summary,
                None,
                &mut IvmProvedReplayWork::default(),
            )?;
            require_ivm_proved_gas_within_limit(tx, replay.gas_used)?;
            let access_log = replay.access_log.clone();
            Ok(PreparedTxOverlay::new(
                tx_overlay_from_ivm_proved_replay(state_ro, replay)
                    .with_entrypoint_authorization(Some(entrypoint_authorization)),
                access_log,
                access_fence,
                force_live_rebuild,
            )
            .with_prepared_contract(summary.prepared_contract()))
        }
    }
}
#[cfg(test)]
/// Build a reference overlay under quarantine limits for regression tests.
///
/// Applies per-transaction execution caps when running IVM bytecode to collect queued ISIs:
/// - `max_cycles_cap`: if non-zero, caps VM cycles to `min(header.max_cycles, max_cycles_cap, upper_bound_cap)`.
/// - `upper_bound_cap`: mandatory pipeline-wide upper bound on cycles.
///
/// Host wall-clock time is intentionally not an admission input: peers with different hardware
/// must accept or reject the same execution. Operators may still observe elapsed execution time
/// through telemetry, while consensus resource enforcement remains cycle- and gas-bounded.
///
/// # Errors
/// Returns an error if the IVM header fails policy checks or running the VM fails.
#[allow(clippy::too_many_lines)]
pub(crate) fn build_overlay_for_transaction_quarantine(
    tx: &SignedTransaction,
    accounts: Arc<Vec<AccountId>>,
    state_ro: &(impl StateReadOnly + QueryStateSource),
    max_cycles_cap: u64,
    upper_bound_cap: NonZeroU64,
    streaming_meta: StreamingOverlayMetadata,
    ivm_cache: &mut IvmCache,
    reused_argument_record: Option<ivm::PreparedArgumentRecord>,
) -> Result<PreparedTxOverlay, OverlayBuildError> {
    match tx.instructions() {
        Executable::Instructions(batch) => {
            // Built-in instruction batches do not use VM; return overlay directly.
            let instrs: Vec<InstructionBox> = batch.iter().cloned().collect();
            Ok(PreparedTxOverlay::new(
                TxOverlay::from_instructions(instrs),
                None,
                VmAccessFence::Global,
                true,
            ))
        }
        Executable::Batch(_) => Err(OverlayBuildError::ContractCall(
            "Executable::Batch is not supported in quarantine overlay building".to_owned(),
        )),
        Executable::ContractCall(call) => {
            let identity = code::fetch_bound_contract_identity(state_ro, &call.contract_address)
                .map_err(contract_registry_attempt_error)?
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract instance `{}` not found in WSV",
                        call.contract_address
                    ))
                })?;
            crate::executor::ensure_contract_invocation_code_hash(call, identity.code_hash)
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let code_hash = identity.code_hash;
            let artifact_id = ContractArtifactId::for_address(&call.contract_address, code_hash)
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let manifest = state_ro
                .world()
                .contract_manifests()
                .get(&artifact_id)
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract instance `{}` has no manifest",
                        call.contract_address
                    ))
                })?;
            let code_bytes = state_ro
                .world()
                .contract_code()
                .get(&artifact_id)
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(format!(
                        "contract instance `{}` has no bytecode",
                        call.contract_address
                    ))
                })?;
            let summary = ivm_cache
                .summarize_program_with_hash(code_hash, code_bytes.as_ref())
                .map_err(map_program_summary_error)?;
            let meta = summary.metadata.clone();
            validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
            if meta.mode & ivm::ivm_mode::ZK != 0 {
                return Err(OverlayBuildError::HeaderPolicy(
                    IvmAdmissionError::UnsupportedFeatureBits(ivm::ivm_mode::ZK),
                ));
            }
            enforce_pre_execution_policy(state_ro.pipeline().ivm_max_cycles_upper_bound, &meta)?;
            let tx_gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
            validate_bound_contract_manifest(manifest, &summary)?;
            let mut eff = meta.max_cycles.min(upper_bound_cap.get());
            if max_cycles_cap > 0 {
                eff = eff.min(max_cycles_cap);
            }
            let amx_analysis = cached_amx_analysis(ivm_cache, &summary, code_bytes.as_ref())?;
            let lifecycle_transition = crate::executor::validate_prepared_contract_lifecycle_call(
                state_ro.world(),
                &call.contract_address,
                summary.code_hash,
                summary.prepared_contract(),
                &call.entrypoint,
            )
            .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            let entrypoint_authorization = crate::executor::authorize_prepared_contract_selector(
                state_ro.world(),
                tx.authority(),
                summary.prepared_contract(),
                &call.entrypoint,
                &identity,
            )
            .map_err(contract_registry_attempt_error)?;
            let contract_call_context = parse_prepared_contract_invocation_execution_context(
                call,
                summary.prepared_contract(),
                tx_gas_limit,
                reused_argument_record.as_ref(),
            )?;
            let mut vm = summary
                .checkout_runtime(tx_gas_limit, smart_contract_heap_limit(state_ro))
                .map_err(OverlayBuildError::IvmLoad)?;
            let contract_subject =
                code::fetch_bound_contract_subject(state_ro, &call.contract_address).ok_or_else(
                    || {
                        OverlayBuildError::ContractCall(format!(
                            "contract instance `{}` has no valid subject binding",
                            call.contract_address
                        ))
                    },
                )?;
            let contract_runtime_context = Some(crate::executor::ContractRuntimeExecutionContext {
                contract_subject,
                contract_address: call.contract_address.clone(),
                contract_alias: identity.contract_alias.clone(),
                entrypoint: contract_call_context
                    .entrypoint
                    .clone()
                    .expect("contract invocation parser must set entrypoint"),
            });
            let mut host: crate::smartcontracts::ivm::host::CoreHostImpl<
                crate::smartcontracts::ivm::host::QueryStateSlot<_>,
            > = crate::smartcontracts::ivm::host::CoreHostImpl::<
                crate::smartcontracts::ivm::host::QueryStateSlot<_>,
            >::with_accounts_and_argument_record(
                tx.authority().clone(),
                Arc::clone(&accounts),
                contract_call_context.argument_record.clone(),
            );
            host.set_output_limits_from_parameters(state_ro.world().parameters().smart_contract());
            host.set_prepared_contract_cache(summary.prepared_contract_cache());
            host.set_amx_analysis(amx_analysis);
            let amx_limits = crate::smartcontracts::ivm::host::CoreHost::amx_limits_from_config(
                state_ro.pipeline(),
            );
            host.set_amx_limits(amx_limits);
            host.hydrate_axt_state(state_ro)?;
            host.set_public_inputs_from_parameters(state_ro.world().parameters());
            host.set_vrf_epoch_seeds_from_state(state_ro)
                .map_err(|error| {
                    contract_registry_attempt_error(
                        error.map_rejection(ValidationFail::InternalError),
                    )
                })?;
            host.set_query_state(state_ro);
            host.set_contract_runtime_context(contract_runtime_context.clone());
            host.set_contract_entrypoint_authorization(Some(entrypoint_authorization.clone()));
            if let Some(pending) = lifecycle_transition {
                host.set_contract_lifecycle_transition(&call.contract_address, pending);
            }
            apply_streaming_metadata(&mut host, streaming_meta);
            #[cfg(feature = "telemetry")]
            host.set_telemetry(state_ro.metrics().clone());
            host.set_crypto_config(state_ro.crypto());
            host.set_zk_config(state_ro.zk());
            host.set_chain_id(state_ro.chain_id());
            host.set_zk_snapshots_from_world(state_ro.world(), state_ro.zk())
                .map_err(OverlayBuildError::IvmRun)?;
            vm.set_max_cycles(eff);
            vm.set_gas_limit(tx_gas_limit);
            apply_contract_call_execution_context(&mut vm, Some(&contract_call_context))?;
            let returned_error = run_vm_with_host(&mut vm, &mut host)?;
            let lifecycle_transition = lifecycle_transition.filter(|_| !returned_error);
            let ivm_gas_used = tx_gas_limit.saturating_sub(vm.remaining_gas());
            let queued = host.drain_queued_effects_with_contract_runtime_context(
                contract_runtime_context.clone(),
            );
            let (durable_state_overlay, durable_state_authorizations) =
                host.drain_durable_state_overlay_with_authorizations();
            let completed_axt = host.drain_completed_axt_states();
            Ok(PreparedTxOverlay::new(
                tx_overlay_from_host_queued(
                    state_ro,
                    queued,
                    ivm_gas_used,
                    completed_axt,
                    durable_state_overlay,
                    durable_state_authorizations,
                )
                .with_entrypoint_authorization(Some(entrypoint_authorization))
                .with_lifecycle_completion(&call.contract_address, lifecycle_transition),
                None,
                VmAccessFence::Global,
                true,
            )
            .with_prepared_argument_record(contract_call_context.argument_record.clone())
            .with_prepared_contract(summary.prepared_contract()))
        }
        Executable::Ivm(bytecode) => {
            let admitted = ivm_cache
                .summarize_executable(bytecode.as_ref())
                .map_err(map_program_summary_error)?;
            let summary = match admitted {
                ExecutableProgramSummary::Contract(summary) => summary,
                ExecutableProgramSummary::Generic(summary) => {
                    let mut eff = summary.metadata.max_cycles.min(upper_bound_cap.get());
                    if max_cycles_cap > 0 {
                        eff = eff.min(max_cycles_cap);
                    }
                    let execution = execute_generic_program_overlay(
                        tx,
                        state_ro,
                        &summary,
                        ivm_cache,
                        Arc::clone(&accounts),
                        streaming_meta,
                        false,
                        Some(eff),
                        false,
                    )?;
                    return Ok(PreparedTxOverlay::new(
                        execution.overlay,
                        None,
                        VmAccessFence::Global,
                        true,
                    ));
                }
            };
            let meta = summary.metadata.clone();
            validate_header_policy(&meta).map_err(OverlayBuildError::HeaderPolicy)?;
            if meta.mode & ivm::ivm_mode::ZK != 0 {
                return Err(OverlayBuildError::HeaderPolicy(
                    IvmAdmissionError::UnsupportedFeatureBits(ivm::ivm_mode::ZK),
                ));
            }
            enforce_pre_execution_policy(state_ro.pipeline().ivm_max_cycles_upper_bound, &meta)?;
            validate_contract_binding(state_ro, tx.payload(), &summary)?;
            let tx_gas_limit = require_ivm_gas_limit(tx.fee_payment_intent())?;
            let mut eff = meta.max_cycles.min(upper_bound_cap.get());
            if max_cycles_cap > 0 {
                eff = eff.min(max_cycles_cap);
            }
            let amx_analysis = cached_amx_analysis(ivm_cache, &summary, bytecode.as_ref())?;
            let selector = crate::executor::requested_contract_entrypoint(tx.metadata())
                .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?
                .ok_or_else(|| {
                    OverlayBuildError::ContractCall(
                        "self-describing raw-IVM contract dispatch requires explicit contract_entrypoint metadata"
                            .to_owned(),
                    )
                })?;
            let identity = crate::executor::require_raw_contract_runtime_identity(
                state_ro.world(),
                summary.code_hash,
                tx.metadata(),
            )
            .map_err(|error| OverlayBuildError::ContractCall(error.to_string()))?;
            code::ensure_contract_execution_allowed(
                state_ro.world(),
                &identity.contract_address,
                state_ro
                    .block_height_hint()
                    .ok_or_else(|| {
                        OverlayBuildError::ContractCall(
                            "ordinary raw-IVM quarantine preparation requires an execution block height"
                                .to_owned(),
                        )
                    })?,
            )
            .map_err(OverlayBuildError::ContractCall)?;
            let entrypoint_authorization =
                crate::executor::authorize_prepared_raw_contract_selector(
                    state_ro.world(),
                    tx.authority(),
                    summary.prepared_contract(),
                    &selector,
                    &identity,
                )
                .map_err(contract_registry_attempt_error)?;
            let contract_call_context = parse_prepared_contract_call_execution_context(
                tx.metadata(),
                summary.prepared_contract(),
                tx_gas_limit,
                reused_argument_record.as_ref(),
            )?;
            let contract_subject =
                code::fetch_bound_contract_subject(state_ro, &identity.contract_address)
                    .ok_or_else(|| {
                        OverlayBuildError::ContractCall(format!(
                            "contract instance `{}` has no valid subject binding",
                            identity.contract_address
                        ))
                    })?;
            let contract_runtime_context = Some(crate::executor::ContractRuntimeExecutionContext {
                contract_subject,
                contract_address: identity.contract_address.clone(),
                contract_alias: identity.contract_alias.clone(),
                entrypoint: selector,
            });
            let mut vm = summary
                .checkout_runtime(tx_gas_limit, smart_contract_heap_limit(state_ro))
                .map_err(OverlayBuildError::IvmLoad)?;
            let mut host = if let Some(context) = contract_call_context.as_ref() {
                crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts_and_argument_record(
                    tx.authority().clone(),
                    Arc::clone(&accounts),
                    context.argument_record.clone(),
                )
            } else {
                crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts(
                    tx.authority().clone(),
                    Arc::clone(&accounts),
                )
            };
            host.set_output_limits_from_parameters(state_ro.world().parameters().smart_contract());
            host.set_prepared_contract_cache(summary.prepared_contract_cache());
            host.set_amx_analysis(amx_analysis);
            let amx_limits = crate::smartcontracts::ivm::host::CoreHost::amx_limits_from_config(
                state_ro.pipeline(),
            );
            host.set_amx_limits(amx_limits);
            host.hydrate_axt_state(state_ro)?;
            host.set_public_inputs_from_parameters(state_ro.world().parameters());
            host.set_vrf_epoch_seeds_from_state(state_ro)
                .map_err(|error| {
                    contract_registry_attempt_error(
                        error.map_rejection(ValidationFail::InternalError),
                    )
                })?;
            host.set_query_state(state_ro);
            host.set_contract_runtime_context(contract_runtime_context.clone());
            host.set_contract_entrypoint_authorization(Some(entrypoint_authorization.clone()));
            host.set_bound_contract_records_by_subject_snapshot(
                code::snapshot_bound_contract_records_by_subject(state_ro)
                    .map_err(contract_registry_attempt_error)?,
            );
            apply_streaming_metadata(&mut host, streaming_meta);
            #[cfg(feature = "telemetry")]
            host.set_telemetry(state_ro.metrics().clone());
            host.set_crypto_config(state_ro.crypto());
            host.set_zk_config(state_ro.zk());
            host.set_chain_id(state_ro.chain_id());
            host.set_zk_snapshots_from_world(state_ro.world(), state_ro.zk())
                .map_err(OverlayBuildError::IvmRun)?;
            vm.set_max_cycles(eff);
            vm.set_gas_limit(tx_gas_limit);
            apply_contract_call_execution_context(&mut vm, contract_call_context.as_ref())?;
            run_vm_with_host(&mut vm, &mut host)?;
            let ivm_gas_used = tx_gas_limit.saturating_sub(vm.remaining_gas());
            let queued = host.drain_queued_effects_with_contract_runtime_context(
                contract_runtime_context.clone(),
            );
            let (durable_state_overlay, durable_state_authorizations) =
                host.drain_durable_state_overlay_with_authorizations();
            let completed_axt = host.drain_completed_axt_states();
            Ok(PreparedTxOverlay::new(
                tx_overlay_from_host_queued(
                    state_ro,
                    queued,
                    ivm_gas_used,
                    completed_axt,
                    durable_state_overlay,
                    durable_state_authorizations,
                )
                .with_entrypoint_authorization(Some(entrypoint_authorization)),
                None,
                VmAccessFence::Global,
                true,
            )
            .with_prepared_argument_record(
                contract_call_context
                    .as_ref()
                    .and_then(|context| context.argument_record.clone()),
            )
            .with_prepared_contract(summary.prepared_contract()))
        }
        Executable::IvmProved(_) => Err(OverlayBuildError::ZkProof(
            "Executable::IvmProved is not supported in quarantine overlay building".to_owned(),
        )),
    }
}
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::state::State;
    use iroha_model_base::chain::ChainId;

    /// Component fixture with explicit committed global-root metadata.
    pub(crate) fn with_global_root(world: crate::state::World) -> crate::state::World {
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
            ))
            .expect("valid fixture parameters");
        parameters.commit();
        world
    }

    /// Apply the original signed genesis to its uniquely retained fixture State.
    pub(crate) fn state_after_genesis(world: crate::state::World) -> State {
        state_after_genesis_with_chain(world, ChainId::from("sumeragi-certified-test-chain"))
    }

    /// Apply original signed genesis while preserving the fixture's explicit chain identity.
    pub(super) fn state_after_genesis_with_chain(
        world: crate::state::World,
        chain_id: ChainId,
    ) -> State {
        use crate::sumeragi::{
            startup,
            test_chain::{CertifiedTestChain, TestChainConfig},
        };

        let mut config = TestChainConfig::new(world, 0);
        config.chain_id = chain_id;
        let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
        let consensus_mode = config.consensus_mode;
        let prepared =
            CertifiedTestChain::prepare(config).expect("prepare signed pipeline genesis");
        let state = Arc::try_unwrap(prepared.state)
            .unwrap_or_else(|_| panic!("unpublished pipeline State is unique"));
        startup::apply_genesis(
            &state,
            prepared.genesis.block().clone(),
            &genesis_account,
            consensus_mode.into(),
            None,
        )
        .expect("apply signed pipeline genesis");
        state
    }

    /// Prepare execution against an explicit block time, retaining the large
    /// staged world on the heap while the overlay runs.
    pub(super) fn execution_block(state: &State) -> Box<crate::state::StateBlock<'_>> {
        let height = u64::try_from(state.view().height()).expect("fixture height fits u64") + 1;
        Box::new(state.block(BlockHeader::new(
            height.try_into().expect("next fixture height is nonzero"),
            state.view().latest_block_hash(),
            None,
            0,
            0,
        )))
    }

    #[test]
    fn authenticated_fixture_execution_extends_original_genesis_parent() {
        let pristine = State::new(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let pristine_block = execution_block(&pristine);
        assert_eq!(pristine_block._curr_block.height().get(), 1);
        assert_eq!(pristine_block._curr_block.prev_block_hash(), None);
        drop(pristine_block);

        let state = state_after_genesis(crate::state::World::default());
        assert_eq!(
            state.chain_id,
            ChainId::from("sumeragi-certified-test-chain")
        );
        let custom_chain = ChainId::from("pipeline-fixture-chain");
        let custom =
            state_after_genesis_with_chain(crate::state::World::default(), custom_chain.clone());
        assert_eq!(custom.chain_id, custom_chain);
        assert_eq!(custom.committed_height(), 1);
        let view = state.view();
        assert_eq!(view.height(), 1);
        assert_eq!(
            crate::sumeragi::lanes::routing::committed_root_scope(view.world()),
            Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
        );
        let original_parent = view.latest_block_hash().expect("original genesis parent");
        drop(view);
        let next_block = execution_block(&state);
        assert_eq!(next_block._curr_block.height().get(), 2);
        assert_eq!(
            next_block._curr_block.prev_block_hash(),
            Some(original_parent)
        );
    }

    /// Seed a complete active lifecycle fixture, including its canonical subject and owner.
    pub(super) fn seed_active_contract(
        world: &mut crate::state::World,
        address: &ContractAddress,
        code_hash: Hash,
        owner: &AccountId,
    ) {
        let binding =
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(address, owner.clone())
                .with_active_code_hash(code_hash);
        for account in [owner, &binding.subject] {
            if world.accounts.view().get(account).is_none() {
                world.accounts.insert(
                    account.clone(),
                    iroha_data_model::account::AccountValue::new(
                        iroha_data_model::account::AccountDetails::default(),
                    ),
                );
            }
        }
        world.contract_instances.insert(address.clone(), code_hash);
        world
            .contract_subject_addresses
            .insert(binding.subject.clone(), address.clone());
        world
            .contract_subject_bindings
            .insert(address.clone(), binding);
    }
}
#[cfg(test)]
mod tests_overlay_manifest {
    use super::test_support::{execution_block, seed_active_contract};
    use super::*;
    use crate::state::State;
    use iroha_data_model::{IntoKeyValue, prelude::*};
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::json::Json;
    use iroha_test_samples::gen_account_in;
    use nonzero_ext::nonzero;
    fn build_wonderland_account(authority: &AccountId) -> iroha_data_model::account::Account {
        iroha_data_model::account::Account::new(authority.clone()).build(authority)
    }

    #[test]
    fn reserve_namespace_retained_overlay_refuses_before_writes() {
        let (authority, _) = gen_account_in("wonderland");
        let mut world = crate::state::World::new();
        let (id, account) = build_wonderland_account(&authority).into_key_value();
        world.accounts.insert(id, account);
        let state = test_support::state_after_genesis(world);
        let mut block = execution_block(&state);
        for text in ["sorafs_reserve_state_v1", "sorafs_reserve_unknown_record"] {
            for replacement in [Some(vec![8]), None] {
                let path: StatePath = text.parse().unwrap();
                let ordinary: StatePath = "ordinary_before_reserve".parse().unwrap();
                let original = vec![7];
                let mut tx = block.transaction();
                tx.world
                    .smart_contract_state
                    .insert(path.clone(), original.clone());
                // A retained overlay is data, never authority to replace native reserve state.
                let overlay = TxOverlay::from_ivm_execution(
                    Vec::new(),
                    0,
                    BTreeMap::from([
                        (ordinary.clone(), Some(vec![1])),
                        (path.clone(), replacement),
                    ]),
                );
                let error = overlay.apply(&mut tx, &authority).unwrap_err();
                assert!(
                    matches!(error, ValidationFail::NotPermitted(reason) if reason.contains("native reserve state"))
                );
                assert_eq!(tx.world.smart_contract_state.get(&path), Some(&original));
                assert!(tx.world.smart_contract_state.get(&ordinary).is_none());
            }
        }
        for replacement in [Some(vec![8]), None] {
            let path: StatePath = "sorafs_reservex_state_v1".parse().unwrap();
            let mut tx = block.transaction();
            tx.world.smart_contract_state.insert(path.clone(), vec![7]);
            let overlay = TxOverlay::from_ivm_execution(
                Vec::new(),
                0,
                BTreeMap::from([(path.clone(), replacement.clone())]),
            );
            overlay
                .apply(&mut tx, &authority)
                .expect("adjacent ordinary state remains writable");
            assert_eq!(
                tx.world.smart_contract_state.get(&path),
                replacement.as_ref()
            );
        }
    }

    fn analysis_with_syscalls(numbers: &[u32]) -> ivm::analysis::ProgramAnalysis {
        let mut program = ivm::ProgramMetadata::default().encode();
        for number in numbers {
            program.extend_from_slice(&ivm::encoding::wide::encode_syscallx(*number).to_le_bytes());
        }
        ivm::analysis::analyze_program(&program).expect("diagnostic syscall fixture")
    }
    #[test]
    fn vm_access_fence_fails_closed_by_reachable_syscall_class() {
        assert_eq!(
            VmAccessFence::from_program_analysis(&analysis_with_syscalls(&[])),
            VmAccessFence::None
        );
        assert_eq!(
            VmAccessFence::from_program_analysis(&analysis_with_syscalls(&[
                ivm::syscalls::SYSCALL_STATE_GET,
                ivm::syscalls::SYSCALL_STATE_SET,
            ])),
            VmAccessFence::State
        );
        assert!(!VmAccessFence::requires_live_rebuild(
            &analysis_with_syscalls(&[ivm::syscalls::SYSCALL_STATE_GET])
        ));
        assert!(VmAccessFence::requires_live_rebuild(
            &analysis_with_syscalls(&[ivm::syscalls::SYSCALL_CORE_QUERY_GET])
        ));
        assert!(VmAccessFence::requires_live_rebuild(
            &analysis_with_syscalls(&[ivm::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED])
        ));
        assert!(VmAccessFence::requires_live_rebuild(
            &analysis_with_syscalls(&[ivm::syscalls::SYSCALL_CALL_CONTRACT])
        ));
        for syscall in [
            ivm::syscalls::SYSCALL_CORE_QUERY_GET,
            ivm::syscalls::SYSCALL_CORE_QUERY_PAGE,
            ivm::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED,
            ivm::syscalls::SYSCALL_CALL_CONTRACT,
            0x00ff_fffe,
        ] {
            assert_eq!(
                VmAccessFence::from_program_analysis(&analysis_with_syscalls(&[syscall])),
                VmAccessFence::Global,
                "syscall 0x{syscall:06x} must serialize globally"
            );
        }
    }
    #[test]
    fn borrowed_syscall_classifier_preserves_fence_and_sorted_axt_error() {
        let numbers = [
            ivm::syscalls::SYSCALL_AXT_COMMIT,
            ivm::syscalls::SYSCALL_STATE_GET,
            ivm::syscalls::SYSCALL_AXT_BEGIN,
            ivm::syscalls::SYSCALL_AXT_COMMIT,
        ];
        let mut bytes = ivm::ProgramMetadata::default().encode();
        for number in numbers {
            bytes.extend_from_slice(&ivm::encoding::wide::encode_syscallx(number).to_le_bytes());
        }
        let analysis = ivm::analysis::analyze_program(&bytes).unwrap();
        assert_eq!(
            VmAccessFence::from_syscall_numbers(
                ivm::analysis::program_syscall_numbers(&bytes).unwrap()
            ),
            VmAccessFence::from_program_analysis(&analysis),
        );
        let expected = numbers
            .into_iter()
            .filter(|number| ivm::syscalls::is_axt_syscall(*number))
            .min()
            .unwrap();
        assert_eq!(
            reject_state_free_axt_syscalls(&bytes),
            Err(OverlayBuildError::StateRequiredSyscall(expected))
        );
        bytes.pop();
        assert!(matches!(
            reject_state_free_axt_syscalls(&bytes),
            Err(OverlayBuildError::IvmLoad(_))
        ));
    }
    #[test]
    fn overlay_error_retryability_excludes_state_invariant_failures() {
        assert!(
            OverlayBuildError::ContractCall("binding not found yet".to_owned())
                .may_change_with_live_state()
        );
        assert!(
            OverlayBuildError::IvmRun(ivm::VMError::PermissionDenied).may_change_with_live_state()
        );
        assert!(!OverlayBuildError::IvmHeaderParse.may_change_with_live_state());
        assert!(
            !OverlayBuildError::GasLimit("missing gas limit".to_owned())
                .may_change_with_live_state()
        );
        assert!(
            !OverlayBuildError::IvmLoad(ivm::VMError::InvalidMetadata).may_change_with_live_state()
        );
        assert!(
            !OverlayBuildError::StateRequiredSyscall(ivm::syscalls::SYSCALL_AXT_BEGIN)
                .may_change_with_live_state()
        );
        assert!(
            !OverlayBuildError::InvalidAxtPolicySnapshot(
                iroha_data_model::nexus::AxtPolicySnapshotValidationError::VersionMismatch {
                    expected: 0,
                    actual: 1,
                },
            )
            .may_change_with_live_state()
        );
        assert!(
            OverlayBuildError::IvmProvedReplay("state-dependent replay".to_owned())
                .may_change_with_live_state()
        );
        assert!(
            !OverlayBuildError::ZkProof("cryptographic failure".to_owned())
                .may_change_with_live_state()
        );
    }
    #[test]
    fn proved_replay_gas_must_fit_the_transaction_limit() {
        use iroha_data_model::prelude::{AccountId, Log, TransactionBuilder};
        let kp = iroha_crypto::KeyPair::try_random().expect("proved replay gas fixture key");
        let authority = AccountId::new(kp.public_key().clone());
        let signed = |fee| {
            TransactionBuilder::new(
                overlay_test_network_id(b"proved-replay-gas-limit"),
                authority.clone(),
                fee,
            )
            .with_instructions([Log::new(iroha_logger::Level::INFO, "gas".to_owned())])
            .sign(kp.private_key())
        };
        let bounded = signed(test_fee_payment());
        require_ivm_proved_gas_within_limit(&bounded, TEST_GAS_LIMIT)
            .expect("replay gas equal to the limit fits");
        assert!(matches!(
            require_ivm_proved_gas_within_limit(&bounded, TEST_GAS_LIMIT + 1),
            Err(OverlayBuildError::GasLimit(message)) if message.contains("above transaction limit")
        ));
        let unbounded = signed(iroha_data_model::transaction::FeePaymentIntent::authority(
            Vec::new(),
            None,
        ));
        assert!(matches!(
            require_ivm_proved_gas_within_limit(&unbounded, 1),
            Err(OverlayBuildError::GasLimit(message)) if message.contains("missing gas limit")
        ));
    }
    #[test]
    fn durable_state_read_snapshot_detects_value_and_descendant_changes() {
        fn state_with_entries(entries: &[(&str, &[u8])]) -> State {
            let mut world = crate::state::World::new();
            for (path, value) in entries {
                world.smart_contract_state_mut_for_testing().insert(
                    path.parse().expect("valid durable-state path"),
                    value.to_vec(),
                );
            }
            State::new_for_testing(
                test_support::with_global_root(world),
                crate::kura::Kura::blank_kura_for_testing(),
                crate::query::store::LiveQueryStore::start_test(),
            )
        }
        let (authority, keypair) = iroha_test_samples::gen_account_in("wonderland");
        let mut access_log = ivm::host::AccessLog::default();
        access_log.read_keys.insert("counter".to_owned());
        access_log
            .durable_read_paths
            .extend(["counter".to_owned(), "sc/nested/counter".to_owned()]);
        access_log.durable_read_paths_complete = true;
        let initial = state_with_entries(&[
            ("counter", b"one"),
            ("counter-lexical-interloper", b"same"),
            ("sc/nested/counter", b"nested-one"),
            ("unrelated", b"stable"),
        ]);
        let transaction =
            TransactionBuilder::new(initial.network_id, authority, test_fee_payment())
                .with_executable(Executable::Ivm(IvmBytecode::from_compiled(Vec::new())))
                .sign(keypair.private_key());
        let snapshot =
            DurableStateReadSnapshot::capture(&transaction, Some(&access_log), &initial.view())
                .expect("non-empty VM read log creates a snapshot");
        assert!(snapshot.is_current(&initial.view()));
        let unrelated = state_with_entries(&[
            ("counter", b"one"),
            ("counter-lexical-interloper", b"same"),
            ("sc/nested/counter", b"nested-one"),
            ("unrelated", b"changed"),
        ]);
        assert!(snapshot.is_current(&unrelated.view()));
        let changed_value = state_with_entries(&[("counter", b"two")]);
        assert!(!snapshot.is_current(&changed_value.view()));
        let changed_concrete_scope = state_with_entries(&[
            ("counter", b"one"),
            ("counter-lexical-interloper", b"same"),
            ("sc/nested/counter", b"nested-two"),
        ]);
        assert!(!snapshot.is_current(&changed_concrete_scope.view()));
        let changed_descendant = state_with_entries(&[
            ("counter", b"one"),
            ("counter-lexical-interloper", b"same"),
            ("counter/child", b"new"),
            ("sc/nested/counter", b"nested-one"),
        ]);
        assert!(!snapshot.is_current(&changed_descendant.view()));
    }
    #[test]
    fn durable_state_read_snapshot_fails_closed_for_invalid_host_key() {
        let (authority, keypair) = iroha_test_samples::gen_account_in("wonderland");
        let mut access_log = ivm::host::AccessLog::default();
        access_log
            .read_keys
            .insert("invalid state key with spaces".to_owned());
        let initial = {
            let mut world = crate::state::World::new();
            world
                .smart_contract_state_mut_for_testing()
                .insert("unrelated".parse().unwrap(), b"one".to_vec());
            State::new_for_testing(
                test_support::with_global_root(world),
                crate::kura::Kura::blank_kura_for_testing(),
                crate::query::store::LiveQueryStore::start_test(),
            )
        };
        let transaction =
            TransactionBuilder::new(initial.network_id, authority, test_fee_payment())
                .with_executable(Executable::Ivm(IvmBytecode::from_compiled(Vec::new())))
                .sign(keypair.private_key());
        let snapshot =
            DurableStateReadSnapshot::capture(&transaction, Some(&access_log), &initial.view())
                .expect("invalid VM read key still creates a fail-closed snapshot");
        let changed = {
            let mut world = crate::state::World::new();
            world
                .smart_contract_state_mut_for_testing()
                .insert("unrelated".parse().unwrap(), b"two".to_vec());
            State::new_for_testing(
                test_support::with_global_root(world),
                crate::kura::Kura::blank_kura_for_testing(),
                crate::query::store::LiveQueryStore::start_test(),
            )
        };
        assert!(
            !snapshot.is_current(&changed.view()),
            "an unrepresentable access key must conservatively observe the whole state map"
        );
    }
    #[test]
    fn durable_state_read_snapshot_fails_closed_for_partial_concrete_paths() {
        let (authority, keypair) = iroha_test_samples::gen_account_in("wonderland");
        let mut access_log = ivm::host::AccessLog::default();
        access_log
            .read_keys
            .extend(["alpha".to_owned(), "nested".to_owned()]);
        access_log.durable_read_paths.insert("alpha".to_owned());
        let make_state = |unrelated: &[u8]| {
            let mut world = crate::state::World::new();
            world
                .smart_contract_state_mut_for_testing()
                .insert("alpha".parse().unwrap(), b"stable".to_vec());
            world
                .smart_contract_state_mut_for_testing()
                .insert("unrelated".parse().unwrap(), unrelated.to_vec());
            State::new_for_testing(
                test_support::with_global_root(world),
                crate::kura::Kura::blank_kura_for_testing(),
                crate::query::store::LiveQueryStore::start_test(),
            )
        };
        let initial = make_state(b"one");
        let transaction =
            TransactionBuilder::new(initial.network_id, authority, test_fee_payment())
                .with_executable(Executable::Ivm(IvmBytecode::from_compiled(Vec::new())))
                .sign(keypair.private_key());
        let empty_incomplete_snapshot = DurableStateReadSnapshot::capture(
            &transaction,
            Some(&ivm::host::AccessLog::default()),
            &initial.view(),
        )
        .expect("an unattested empty log creates a fail-closed snapshot");
        assert!(
            !empty_incomplete_snapshot.is_current(&make_state(b"two").view()),
            "an empty custom-host log must not claim that no durable reads occurred"
        );
        let snapshot =
            DurableStateReadSnapshot::capture(&transaction, Some(&access_log), &initial.view())
                .expect("partial concrete log creates a fail-closed snapshot");
        assert!(snapshot.is_current(&initial.view()));
        assert!(
            !snapshot.is_current(&make_state(b"two").view()),
            "missing one logical read path must force a complete-map fingerprint"
        );
    }
    #[test]
    fn lifecycle_overlay_compare_and_consume_rejects_a_stale_second_apply_before_effects() {
        let (authority, _) = gen_account_in("wonderland");
        let domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let world = crate::state::World::with([domain], [account], []);
        let state = State::new_for_testing(
            test_support::with_global_root(world),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            71,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let code_hash = Hash::new(b"lifecycle-overlay-code");
        let pending = code::PendingContractLifecycle::Hajimari {
            transition_id: Hash::new(b"lifecycle-overlay-transition"),
            code_hash,
        };
        let marker = code::contract_lifecycle_state_key(&contract_address);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        {
            let mut seed = block.transaction();
            seed.world
                .contract_instances
                .insert(contract_address.clone(), code_hash);
            seed.world
                .contract_subject_addresses
                .insert(contract_address.subject_id(), contract_address.clone());
            seed.world.contract_subject_bindings.insert(
                contract_address.clone(),
                code::ContractSubjectBinding::new_direct(&contract_address, authority.clone())
                    .with_active_code_hash(code_hash),
            );
            code::set_pending_contract_lifecycle(&mut seed, &contract_address, Some(pending));
            seed.apply();
        }
        let mut first_writes = BTreeMap::new();
        first_writes.insert(marker.clone(), None);
        let authorization = ContractEntrypointAuthorizationSnapshot::new(
            authority.clone(),
            "hajimari".to_owned(),
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::RuntimeLifecycle,
            &code::BoundContractIdentity {
                lifecycle_revision: 1,
                contract_address: contract_address.clone(),
                contract_alias: None,
                contract_alias_binding: None,
                code_hash,
            },
        );
        let mut first = TxOverlay::from_ivm_execution(Vec::new(), 0, first_writes)
            .with_entrypoint_authorization(Some(authorization.clone()))
            .with_lifecycle_completion(&contract_address, Some(pending));
        first
            .durable_state_authorizations
            .insert(marker.clone(), Some(authorization.clone()));
        {
            let mut transaction = block.transaction();
            first
                .apply(&mut transaction, &authority)
                .expect("first lifecycle completion consumes the exact marker");
            transaction.apply();
        }
        assert!(block.world.smart_contract_state.get(&marker).is_none());
        let forbidden_effect: StatePath = "must-not-apply".parse().expect("state key");
        let mut stale_writes = BTreeMap::new();
        stale_writes.insert(marker.clone(), None);
        stale_writes.insert(forbidden_effect.clone(), Some(vec![0xA5]));
        let mut outdated = TxOverlay::from_ivm_execution(Vec::new(), 0, stale_writes)
            .with_entrypoint_authorization(Some(authorization.clone()))
            .with_lifecycle_completion(&contract_address, Some(pending));
        outdated
            .durable_state_authorizations
            .insert(marker, Some(authorization.clone()));
        outdated
            .durable_state_authorizations
            .insert(forbidden_effect.clone(), Some(authorization));
        let mut transaction = block.transaction();
        let error = outdated
            .apply(&mut transaction, &authority)
            .expect_err("a consumed lifecycle marker cannot be replayed");
        assert!(matches!(error, ValidationFail::NotPermitted(_)));
        assert!(
            transaction
                .world
                .smart_contract_state
                .get(&forbidden_effect)
                .is_none(),
            "live lifecycle validation must run before every prepared effect"
        );
    }
    #[test]
    fn deployed_hajimari_call_builds_and_atomically_consumes_its_pending_transition() {
        use iroha_data_model::{
            permission::{Permission, Permissions},
            transaction::executable::ContractInvocation,
        };
        let (authority, keypair) = gen_account_in("wonderland");
        let domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            72,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let metadata = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 4,
            abi_version: 1,
        };
        let interface = ivm::EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            callables: vec![crate::ivm_test_support::unit_callable(0)],
            seiyaku_name: "HajimariGuard".to_owned(),
            compiler_fingerprint: "iroha-core-lifecycle-overlay-test".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
                name: "hajimari".to_owned(),
                kind: iroha_data_model::smart_contract::manifest::EntryPointKind::Hajimari,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::RuntimeLifecycle,
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let mut artifact = metadata.encode();
        artifact.extend_from_slice(&interface.encode_section());
        artifact.extend_from_slice(&crate::ivm_test_support::unit_return());
        let verified = ivm::verify_contract_artifact(&artifact).expect("valid hajimari artifact");
        let code_hash = verified.code_hash;
        let manifest = verified.manifest;
        let mut world = crate::state::World::with([domain], [account], []);
        world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            artifact,
        );
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest,
        );
        seed_active_contract(&mut world, &contract_address, code_hash, &authority);
        let mut permissions = Permissions::new();
        assert!(permissions.insert(Permission::from(
            iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
                contract: contract_address.clone(),
                entrypoint: "hajimari".to_owned(),
            },
        )));
        world
            .account_permissions_mut_for_testing()
            .insert(authority.clone(), permissions);
        let state =
            test_support::state_after_genesis_with_chain(world, ChainId::from("hajimari-overlay"));
        let pending = code::PendingContractLifecycle::Hajimari {
            transition_id: Hash::new(b"hajimari-overlay-transition"),
            code_hash,
        };
        let marker = code::contract_lifecycle_state_key(&contract_address);
        {
            let mut block = state.block(BlockHeader::new(
                nonzero!(2_u64),
                state.view().latest_block_hash(),
                None,
                0,
                0,
            ));
            let mut transaction = block.transaction();
            code::set_pending_contract_lifecycle(
                &mut transaction,
                &contract_address,
                Some(pending),
            );
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("commit pending hajimari transition");
        }
        let tx_metadata = Metadata::default();
        let transaction =
            TransactionBuilder::new(state.network_id, authority.clone(), test_fee_payment())
                .with_metadata(tx_metadata)
                .with_executable(Executable::ContractCall(ContractInvocation {
                    contract_address: contract_address.clone(),
                    expected_code_hash: code_hash,
                    entrypoint: "hajimari".to_owned(),
                    arguments: None,
                }))
                .sign(keypair.private_key());
        let overlay = build_overlay_for_transaction(&transaction, &*execution_block(&state))
            .expect("the exact pending hajimari call must prepare");
        assert_eq!(
            overlay
                .lifecycle_completion
                .as_ref()
                .map(|completion| completion.pending),
            Some(pending)
        );
        assert_eq!(overlay.durable_state_overlay.get(&marker), Some(&None));
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            state.view().latest_block_hash(),
            None,
            0,
            0,
        ));
        let mut state_transaction = block.transaction();
        overlay
            .apply(&mut state_transaction, &authority)
            .expect("live hajimari transition remains valid at apply");
        state_transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit hajimari call");
        let view = state.view();
        assert!(view.world().smart_contract_state().get(&marker).is_none());
        assert!(
            code::validate_contract_lifecycle_call(
                view.world(),
                &contract_address,
                code_hash,
                iroha_data_model::smart_contract::manifest::EntryPointKind::Hajimari,
            )
            .is_err(),
            "hajimari/始まり must be single-use"
        );
    }
    fn minimal_contract_artifact_bytes(abi_version: u8, permission: Option<&str>) -> Vec<u8> {
        let meta = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 4,
            abi_version,
        };
        let interface = ivm::EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: permission.into_iter().map(|name| iroha_data_model::smart_contract::manifest::ContractPermissionDescriptorV1 { name: name.parse().unwrap(), scope: iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1::Instance }).collect(),
            callables: vec![crate::ivm_test_support::unit_callable(0)],
            seiyaku_name: "TestContract".to_owned(),
            compiler_fingerprint: "iroha-core-overlay-test".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
                name: "main".to_owned(),
                kind: iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization: permission.map_or(iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone, |name| iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(name.parse().unwrap())),
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: None,
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let mut artifact = meta.encode();
        artifact.extend_from_slice(&interface.encode_section());
        artifact.extend_from_slice(&crate::ivm_test_support::unit_return());
        artifact
    }
    fn minimal_contract_artifact_with_permission(
        abi_version: u8,
        permission: Option<&str>,
    ) -> (Vec<u8>, ContractManifest) {
        let artifact = minimal_contract_artifact_bytes(abi_version, permission);
        let verified =
            ivm::verify_contract_artifact(&artifact).expect("valid overlay test artifact");
        (artifact, verified.manifest)
    }
    fn minimal_contract_artifact(abi_version: u8) -> (Vec<u8>, ContractManifest) {
        minimal_contract_artifact_with_permission(abi_version, Some("CanInvoke"))
    }
    #[test]
    fn warm_pre_execution_policy_does_not_rewalk_opcodes() {
        let artifact = minimal_contract_artifact_bytes(1, Some("CanInvoke"));
        let code_hash = ivm::contract_code_hash(&artifact);
        let mut cache = IvmCache::with_capacity(2);
        cache
            .summarize_program_with_hash(code_hash, &artifact)
            .expect("cold artifact preparation");
        let cold_stats = cache.stats();
        // A trusted content-addressed hit needs no artifact bytes. The
        // pre-execution gate consumes only authenticated prepared metadata, so
        // it cannot add a second opcode walk to this warm dispatch.
        let summary = cache
            .summarize_program_with_hash(code_hash, &[])
            .expect("warm summary lookup without artifact bytes");
        assert!(
            enforce_pre_execution_policy(nonzero!(1_u64), &summary.metadata).is_err(),
            "a warm summary still rejects an insufficient live cycle ceiling"
        );
        enforce_pre_execution_policy(nonzero!(4_u64), &summary.metadata)
            .expect("prepared metadata remains within the live cycle ceiling");
        assert!(matches!(
            enforce_pre_execution_policy(nonzero!(3_u64), &summary.metadata),
            Err(OverlayBuildError::HeaderPolicy(
                IvmAdmissionError::MaxCyclesExceedsUpperBound(info)
            )) if info.max_cycles == 4 && info.upper_bound == 3
        ));
        let warm_stats = cache.stats();
        assert_eq!(warm_stats.metadata_hits, cold_stats.metadata_hits + 1);
        assert_eq!(warm_stats.artifact_hashes, cold_stats.artifact_hashes);
        assert_eq!(warm_stats.preparations, cold_stats.preparations);
    }
    fn minimal_generic_program() -> Vec<u8> {
        let mut program = ivm::ProgramMetadata {
            max_cycles: 100,
            ..ivm::ProgramMetadata::default()
        }
        .encode();
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        program
    }
    fn minimal_generic_program_with_syscall(syscall: u32) -> Vec<u8> {
        let mut program = ivm::ProgramMetadata {
            max_cycles: 100,
            ..ivm::ProgramMetadata::default()
        }
        .encode();
        program.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(syscall).expect("test syscall fits in the V1 encoding"),
            )
            .to_le_bytes(),
        );
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        program
    }
    fn state_free_generic_transaction(
        authority: AccountId,
        keypair: &iroha_crypto::KeyPair,
        program: Vec<u8>,
        metadata: Metadata,
    ) -> SignedTransaction {
        TransactionBuilder::new(
            overlay_test_network_id(b"state-free-generic-overlay"),
            authority,
            test_fee_payment(),
        )
        .with_metadata(metadata)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(keypair.private_key())
    }
    #[test]
    fn state_free_generic_overlay_enforces_contract_only_syscall_profile() {
        let (authority, keypair) = gen_account_in("wonderland");
        for syscall in [
            ivm::syscalls::SYSCALL_STATE_GET,
            ivm::syscalls::SYSCALL_STATE_SET,
            ivm::syscalls::SYSCALL_CALL_CONTRACT,
        ] {
            let metadata = Metadata::default();
            let transaction = state_free_generic_transaction(
                authority.clone(),
                &keypair,
                minimal_generic_program_with_syscall(syscall),
                metadata,
            );
            let error = build_overlay_for_transaction_with_accounts(&transaction, &[])
                .expect_err("state-free execution must apply the generic syscall profile");
            assert_eq!(
                error,
                OverlayBuildError::IvmLoad(ivm::VMError::GenericSyscallNotAllowed { syscall })
            );
        }
    }
    #[test]
    fn state_free_generic_overlay_rejects_every_axt_syscall_before_execution() {
        let (authority, keypair) = gen_account_in("wonderland");
        for syscall in [
            ivm::syscalls::SYSCALL_AXT_BEGIN,
            ivm::syscalls::SYSCALL_AXT_TOUCH,
            ivm::syscalls::SYSCALL_AXT_COMMIT,
            ivm::syscalls::SYSCALL_VERIFY_DS_PROOF,
        ] {
            let program = minimal_generic_program_with_syscall(syscall);
            assert!(
                matches!(
                    IvmCache::new().summarize_executable(&program),
                    Ok(ExecutableProgramSummary::Generic(_))
                ),
                "live-state generic ABI V1 admission must retain AXT syscall 0x{syscall:02x}"
            );
            let transaction = state_free_generic_transaction(
                authority.clone(),
                &keypair,
                program,
                Metadata::default(),
            );
            let error = build_overlay_for_transaction_with_accounts(&transaction, &[])
                .expect_err("state-free execution must reject the complete AXT surface");
            assert_eq!(error, OverlayBuildError::StateRequiredSyscall(syscall));
        }
    }
    #[test]
    fn state_free_generic_overlay_rejects_reserved_contract_metadata_before_execution() {
        let (authority, keypair) = gen_account_in("wonderland");
        for reserved_key in [
            "contract_entrypoint",
            "contract_payload",
            "contract_address",
        ] {
            let mut metadata = Metadata::default();
            metadata.insert(
                reserved_key.parse().expect("reserved metadata key"),
                Json::new("malformed-or-forged"),
            );
            let transaction = state_free_generic_transaction(
                authority.clone(),
                &keypair,
                minimal_generic_program(),
                metadata,
            );
            let error = build_overlay_for_transaction_with_accounts(&transaction, &[])
                .expect_err("generic execution must reject contract provenance metadata");
            assert!(
                matches!(
                    &error,
                    OverlayBuildError::ContractCall(message)
                        if message.contains("generic IVM programs cannot carry")
                            && message.contains(reserved_key)
                ),
                "unexpected rejection for `{reserved_key}`: {error:?}"
            );
        }
    }
    #[test]
    fn state_free_generic_overlay_still_accepts_stateless_programs() {
        let (authority, keypair) = gen_account_in("wonderland");
        let metadata = Metadata::default();
        let transaction = state_free_generic_transaction(
            authority,
            &keypair,
            minimal_generic_program(),
            metadata,
        );
        let overlay = build_overlay_for_transaction_with_accounts(&transaction, &[])
            .expect("stateless generic HALT must remain executable");
        assert_eq!(overlay.instruction_count(), 0);
        assert!(overlay.durable_state_overlay.is_empty());
    }
    #[test]
    fn full_state_overlay_executes_authenticated_generic_programs() {
        let (authority, keypair) = gen_account_in("wonderland");
        let domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let state = test_support::state_after_genesis_with_chain(
            crate::state::World::with([domain], [account], []),
            ChainId::from("generic-overlay"),
        );
        let metadata = Metadata::default();
        let transaction = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(
                minimal_generic_program(),
            )))
            .sign(keypair.private_key());
        let overlay = build_overlay_for_transaction(&transaction, &*execution_block(&state))
            .expect("generic HALT overlay");
        assert_eq!(overlay.instruction_count(), 0);
        assert!(overlay.ivm_gas_used().is_some());
    }
    #[test]
    fn generic_overlay_rejects_contract_dispatch_metadata() {
        let (authority, keypair) = gen_account_in("wonderland");
        let domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let state = test_support::state_after_genesis_with_chain(
            crate::state::World::with([domain], [account], []),
            ChainId::from("generic-overlay-metadata"),
        );
        let mut metadata = Metadata::default();
        metadata.insert(
            "contract_entrypoint".parse().expect("metadata key"),
            Json::new("main"),
        );
        let transaction = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(
                minimal_generic_program(),
            )))
            .sign(keypair.private_key());
        let error = build_overlay_for_transaction(&transaction, &*execution_block(&state))
            .expect_err("generic program must not impersonate a contract dispatch");
        assert!(matches!(
            error,
            OverlayBuildError::ContractCall(message)
                if message.contains("generic IVM programs cannot carry")
        ));
    }
    #[test]
    fn self_describing_raw_contract_requires_explicit_entrypoint_in_every_parser() {
        let (artifact, _) = minimal_contract_artifact_with_permission(1, Some("CanInvoke"));
        let metadata = Metadata::default();
        let bytecode_err =
            parse_raw_contract_call_execution_context(&metadata, &artifact, TEST_GAS_LIMIT)
                .expect_err("raw self-describing artifact must not fall through to pc zero");
        assert!(
            matches!(
                &bytecode_err,
                OverlayBuildError::ContractCall(message)
                    if message.contains("require explicit contract_entrypoint")
            ),
            "unexpected bytecode parser error: {bytecode_err:?}"
        );
        let mut cache = IvmCache::new();
        let summary = cache
            .summarize_program(&artifact)
            .expect("prepare self-describing artifact");
        let prepared_err = parse_prepared_contract_call_execution_context(
            &metadata,
            summary.prepared_contract(),
            TEST_GAS_LIMIT,
            None,
        )
        .expect_err("prepared self-describing artifact must not fall through to pc zero");
        assert!(
            matches!(
                &prepared_err,
                OverlayBuildError::ContractCall(message)
                    if message.contains("require explicit contract_entrypoint")
            ),
            "unexpected prepared parser error: {prepared_err:?}"
        );
    }
    #[test]
    fn selective_rebuild_reuses_the_prepared_argument_plan_without_redecoding() {
        let artifact = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                r"
seiyaku RebuildArguments { permission CanInspectRebuildArguments;
  kotoage fn inspect(int value) authorize(CanInspectRebuildArguments) -> int {
    return value;
  }
}
",
            )
            .expect("compile parameterized rebuild fixture");
        let prepared = ivm::prepare_contract(Arc::from(artifact))
            .expect("prepare parameterized rebuild fixture");
        let schema = prepared
            .entrypoint_descriptor("inspect")
            .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
            .expect("inspect argument schema");
        let arguments = ivm_abi::arguments::encode_argument_record_from_json(
            schema,
            &Json::from(norito::json!({ "value": "7" })),
        )
        .expect("encode canonical rebuild arguments");
        let arguments =
            iroha_data_model::transaction::executable::ContractArgumentRecord::try_new(arguments)
                .expect("bounded rebuild argument record");
        let (authority, _) = gen_account_in("wonderland");
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            91,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive rebuild contract address");
        let invocation = ContractInvocation {
            contract_address,
            expected_code_hash: Hash::new(b"rebuild-contract-code"),
            entrypoint: "inspect".to_owned(),
            arguments: Some(arguments),
        };
        ivm::reset_argument_record_decode_count();
        let first = parse_prepared_contract_invocation_execution_context(
            &invocation,
            &prepared,
            TEST_GAS_LIMIT,
            None,
        )
        .expect("prepare the initial argument plan");
        assert_eq!(ivm::argument_record_decode_count(), 1);
        let reused = first
            .argument_record
            .as_ref()
            .expect("prepared argument record");
        let rebuilt = {
            let alternate_flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            parse_prepared_contract_invocation_execution_context(
                &invocation,
                &prepared,
                TEST_GAS_LIMIT,
                Some(reused),
            )
            .expect("reuse the argument plan for a selective rebuild")
        };
        assert_eq!(
            ivm::argument_record_decode_count(),
            1,
            "the access-prepass/live-state rebuild boundary must not decode the signed payload twice"
        );
        assert_eq!(
            rebuilt
                .argument_record
                .as_ref()
                .expect("rebuilt argument record")
                .canonical_bytes(),
            reused.canonical_bytes()
        );
    }
    #[test]
    fn raw_rebuild_does_not_reuse_a_plan_for_different_signed_arguments() {
        let artifact = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                r"
seiyaku RawRebuildArguments { permission CanInspectRawRebuild;
  kotoage fn inspect(int value) authorize(CanInspectRawRebuild) {
    let _value = value;
  }
}
",
            )
            .expect("compile raw rebuild binding fixture");
        let prepared = ivm::prepare_contract(Arc::from(artifact))
            .expect("prepare raw rebuild binding fixture");
        let mut metadata = Metadata::default();
        metadata.insert(
            "contract_entrypoint".parse().expect("metadata key"),
            Json::new("inspect"),
        );
        metadata.insert(
            "contract_payload".parse().expect("metadata key"),
            Json::from(norito::json!({ "value": "7" })),
        );
        ivm::reset_argument_record_decode_count();
        let first = parse_prepared_contract_call_execution_context(
            &metadata,
            &prepared,
            TEST_GAS_LIMIT,
            None,
        )
        .expect("prepare the first raw argument plan")
        .expect("raw entrypoint context");
        let first = first
            .argument_record
            .expect("first raw prepared argument record");
        assert_eq!(ivm::argument_record_decode_count(), 1);
        let exact = {
            let alternate_flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            parse_prepared_contract_call_execution_context(
                &metadata,
                &prepared,
                TEST_GAS_LIMIT,
                Some(&first),
            )
            .expect("reuse exact raw arguments under an ambient Norito layout")
            .expect("exact raw entrypoint context")
            .argument_record
            .expect("exact raw prepared argument record")
        };
        assert_eq!(
            ivm::argument_record_decode_count(),
            1,
            "an ambient Norito layout must not force the exact raw plan to be decoded again"
        );
        assert_eq!(exact.canonical_bytes(), first.canonical_bytes());
        assert_eq!(exact.schema_bytes(), first.schema_bytes());
        metadata.insert(
            "contract_payload".parse().expect("metadata key"),
            Json::from(norito::json!({ "value": "8" })),
        );
        let changed = parse_prepared_contract_call_execution_context(
            &metadata,
            &prepared,
            TEST_GAS_LIMIT,
            Some(&first),
        )
        .expect("prepare changed signed raw arguments")
        .expect("changed raw entrypoint context")
        .argument_record
        .expect("changed raw prepared argument record");
        assert_eq!(
            ivm::argument_record_decode_count(),
            2,
            "a retained plan must never authenticate different signed argument bytes"
        );
        assert_ne!(changed.canonical_bytes(), first.canonical_bytes());
        assert_eq!(changed.schema_bytes(), first.schema_bytes());
    }
    fn parameterized_quarantine_fixture() -> (State, SignedTransaction, SignedTransaction) {
        use iroha_data_model::transaction::executable::ContractArgumentRecord;
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                r"
seiyaku QuarantineArguments { permission CanInspectQuarantine;
  kotoage fn inspect(int value) authorize(CanInspectQuarantine) {
    let _value = value;
  }
}
",
            )
            .expect("compile parameterized quarantine fixture");
        let verified = ivm::verify_contract_artifact(&program).expect("verify quarantine fixture");
        let prepared =
            ivm::prepare_contract(Arc::from(program.clone())).expect("prepare quarantine fixture");
        let schema = prepared
            .entrypoint_descriptor("inspect")
            .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
            .expect("inspect argument schema");
        let canonical_arguments = ivm_abi::arguments::encode_argument_record_from_json(
            schema,
            &Json::from(norito::json!({ "value": "7" })),
        )
        .expect("encode quarantine arguments");
        let bounded_arguments = ContractArgumentRecord::try_new(canonical_arguments)
            .expect("bounded quarantine arguments");
        let (authority, keypair) = gen_account_in("wonderland");
        let domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            95,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive quarantine contract address");
        let mut world = crate::state::World::with([domain], [account], []);
        world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, verified.code_hash),
            program.clone(),
        );
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, verified.code_hash),
            verified.manifest,
        );
        seed_active_contract(
            &mut world,
            &contract_address,
            verified.code_hash,
            &authority,
        );
        let mut permissions = iroha_data_model::permission::Permissions::new();
        assert!(
            permissions.insert(iroha_data_model::permission::Permission::new(
                "CanInspectQuarantine".to_owned(),
                Json::new(()),
            ))
        );
        world
            .account_permissions_mut_for_testing()
            .insert(authority.clone(), permissions);
        let chain_id = ChainId::from("parameterized-quarantine-overlay");
        let state = test_support::state_after_genesis_with_chain(world, chain_id.clone());
        let contract_call_metadata = Metadata::default();
        let contract_call =
            TransactionBuilder::new(state.network_id, authority.clone(), test_fee_payment())
                .with_metadata(contract_call_metadata)
                .with_executable(Executable::ContractCall(ContractInvocation {
                    contract_address: contract_address.clone(),
                    expected_code_hash: verified.code_hash,
                    entrypoint: "inspect".to_owned(),
                    arguments: Some(bounded_arguments),
                }))
                .sign(keypair.private_key());
        let mut raw_metadata = Metadata::default();
        raw_metadata.insert(
            "contract_entrypoint".parse().expect("metadata key"),
            Json::new("inspect"),
        );
        raw_metadata.insert(
            "contract_payload".parse().expect("metadata key"),
            Json::from(norito::json!({ "value": "7" })),
        );
        raw_metadata.insert(
            "contract_address".parse().expect("metadata key"),
            Json::new(contract_address.to_string()),
        );
        let raw_ivm = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(raw_metadata)
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
            .sign(keypair.private_key());
        (state, contract_call, raw_ivm)
    }
    fn assert_quarantine_rebuild_decodes_arguments_once(
        state: &State,
        transaction: &SignedTransaction,
    ) {
        let block = execution_block(state);
        let accounts = block.accounts_snapshot();
        let upper_bound = nonzero!(1_000_000_u64);
        let mut cache = IvmCache::new();
        ivm::reset_argument_record_decode_count();
        let prepared = build_overlay_for_transaction_quarantine(
            transaction,
            Arc::clone(&accounts),
            &*block,
            0,
            upper_bound,
            StreamingOverlayMetadata::default(),
            &mut cache,
            None,
        )
        .expect("prepare quarantined parameterized invocation");
        assert_eq!(
            ivm::argument_record_decode_count(),
            1,
            "quarantine preparation must decode the canonical signed record once"
        );
        let retained = prepared
            .prepared_argument_record
            .expect("quarantine must retain its validated argument plan");
        let rebuilt = build_overlay_for_transaction_quarantine(
            transaction,
            accounts,
            &*block,
            0,
            upper_bound,
            StreamingOverlayMetadata::default(),
            &mut cache,
            Some(retained.clone()),
        )
        .expect("rebuild quarantined invocation against live state");
        assert_eq!(
            ivm::argument_record_decode_count(),
            1,
            "the live-state rebuild must materialize, not decode, the retained argument plan"
        );
        let rebuilt = rebuilt
            .prepared_argument_record
            .expect("rebuilt quarantine overlay must keep its argument plan");
        assert_eq!(rebuilt.canonical_bytes(), retained.canonical_bytes());
        assert_eq!(rebuilt.schema_bytes(), retained.schema_bytes());
    }
    #[test]
    fn quarantined_contract_call_rebuild_decodes_arguments_exactly_once() {
        let (state, contract_call, _) = parameterized_quarantine_fixture();
        assert_quarantine_rebuild_decodes_arguments_once(&state, &contract_call);
    }
    #[test]
    fn quarantined_raw_ivm_rebuild_decodes_arguments_exactly_once() {
        let (state, _, raw_ivm) = parameterized_quarantine_fixture();
        assert_quarantine_rebuild_decodes_arguments_once(&state, &raw_ivm);
    }
    #[test]
    fn ordinary_raw_ivm_overlay_build_and_apply_reject_active_hold_before_argument_decode() {
        let (state, contract_call, raw_ivm) = parameterized_quarantine_fixture();
        let contract_address = match contract_call.instructions() {
            Executable::ContractCall(call) => call.contract_address.clone(),
            _ => unreachable!("fixture contract call executable"),
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let accounts = block.accounts_snapshot();
        let upper_bound = nonzero!(1_000_000_u64);
        let mut cache = IvmCache::new();
        let outdated = build_prepared_overlay_for_transaction_with_accounts_zk(
            &raw_ivm,
            Arc::clone(&accounts),
            &block,
            false,
            &header,
            StreamingOverlayMetadata::default(),
            &mut cache,
            false,
            None,
        )
        .expect("prepare an ordinary raw-IVM overlay before the hold");
        {
            let mut seed = block.transaction();
            let binding = seed
                .world
                .contract_subject_bindings
                .get_mut(&contract_address)
                .expect("fixture contract lifecycle binding");
            binding.lifecycle.emergency_hold =
                Some(iroha_data_model::smart_contract::ContractEmergencyHoldV1 {
                    incident_digest: [0xB1; 32],
                    proposal_content_id: [0xB2; 32],
                    governance_attempt_id: [0xB3; 32],
                    reason: "contain ordinary raw-IVM overlay execution".to_owned(),
                    imposed_at_height: 1,
                    expires_at_height: 2,
                });
            binding.lifecycle.revision = binding
                .lifecycle
                .revision
                .checked_add(1)
                .expect("test lifecycle revision advances");
            seed.apply();
        }
        let assert_held = |error: OverlayBuildError| {
            assert!(
                matches!(error, OverlayBuildError::ContractCall(ref message)
                    if message.contains("held by Parliament")),
                "unexpected raw-IVM overlay hold error: {error:?}"
            );
            assert_eq!(
                ivm::argument_record_decode_count(),
                0,
                "ordinary raw-IVM overlay hold checks must precede argument decoding"
            );
        };
        ivm::reset_argument_record_decode_count();
        assert_held(
            build_overlay_for_transaction_with_cache(&raw_ivm, &block, &mut cache)
                .expect_err("the simple raw-IVM overlay builder must reject the active hold"),
        );
        ivm::reset_argument_record_decode_count();
        assert_held(
            build_prepared_overlay_for_transaction_with_accounts_zk(
                &raw_ivm,
                Arc::clone(&accounts),
                &block,
                false,
                &header,
                StreamingOverlayMetadata::default(),
                &mut cache,
                false,
                None,
            )
            .expect_err("the production raw-IVM overlay builder must reject the active hold"),
        );
        ivm::reset_argument_record_decode_count();
        assert_held(
            build_overlay_for_transaction_quarantine(
                &raw_ivm,
                accounts,
                &block,
                0,
                upper_bound,
                StreamingOverlayMetadata::default(),
                &mut cache,
                None,
            )
            .expect_err("the quarantine raw-IVM overlay builder must reject the active hold"),
        );
        let mut apply_tx = block.transaction();
        let error = outdated
            .overlay
            .apply(&mut apply_tx, raw_ivm.authority())
            .expect_err("a hold imposed after preparation must invalidate the ordinary overlay");
        assert!(
            matches!(error, ValidationFail::NotPermitted(ref message)
                if message.contains("held by Parliament")),
            "unexpected stale ordinary raw-IVM overlay error: {error}"
        );
    }
    #[test]
    fn state_free_raw_builder_rejects_protected_entrypoint_before_argument_decode() {
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                r"
seiyaku ProtectedStateFreeOverlay { permission CanWriteStateFreeOverlay;
  kotoage fn write(int value) authorize(CanWriteStateFreeOverlay) {
    let _value = value;
  }
}
",
            )
            .expect("compile protected state-free overlay fixture");
        let (authority, keypair) = gen_account_in("wonderland");
        let mut metadata = Metadata::default();
        metadata.insert(
            "contract_entrypoint".parse().expect("metadata key"),
            Json::new("write"),
        );
        metadata.insert(
            "contract_payload".parse().expect("metadata key"),
            Json::from(norito::json!({ "value": "7" })),
        );
        let transaction = TransactionBuilder::new(
            overlay_test_network_id(b"protected-state-free-overlay"),
            authority,
            test_fee_payment(),
        )
        .with_metadata(metadata)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(keypair.private_key());
        ivm::reset_argument_record_decode_count();
        let error = build_overlay_for_transaction_with_accounts(&transaction, &[])
            .expect_err("state-free builder must reject protected entrypoints");
        assert!(
            matches!(
                &error,
                OverlayBuildError::ContractCall(message)
                    if message.contains("requires a full state view")
            ),
            "unexpected protected state-free overlay error: {error:?}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "state-free permission rejection must precede canonical record decoding"
        );
    }
    #[test]
    fn state_free_raw_builder_rejects_permissionless_entrypoint_before_argument_decode() {
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                r"
seiyaku PermissionlessStateFreeOverlay {
  view fn write(int value) authorize(anyone) -> int {
    return value;
  }
}
",
            )
            .expect("compile permissionless state-free overlay fixture");
        let (authority, keypair) = gen_account_in("wonderland");
        let mut metadata = Metadata::default();
        metadata.insert(
            "contract_entrypoint".parse().expect("metadata key"),
            Json::new("write"),
        );
        metadata.insert(
            "contract_payload".parse().expect("metadata key"),
            Json::from(norito::json!({ "value": "7" })),
        );
        let transaction = TransactionBuilder::new(
            overlay_test_network_id(b"permissionless-state-free-overlay"),
            authority,
            test_fee_payment(),
        )
        .with_metadata(metadata)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(keypair.private_key());
        ivm::reset_argument_record_decode_count();
        let error = build_overlay_for_transaction_with_accounts(&transaction, &[])
            .expect_err("state-free builder must reject every selected contract entrypoint");
        assert!(
            matches!(
                &error,
                OverlayBuildError::ContractCall(message)
                    if message.contains("full state view")
                        && message.contains("live contract binding")
            ),
            "unexpected permissionless state-free overlay error: {error:?}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "state-free identity rejection must precede canonical record decoding"
        );
    }
    #[test]
    fn parameterized_contract_call_denial_precedes_argument_record_decode() {
        use iroha_data_model::transaction::executable::{
            ContractArgumentRecord, ContractInvocation,
        };
        const REQUIRED_PERMISSION: &str = "CanWriteParameterizedOverlay";
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                r"
seiyaku ProtectedParameterizedOverlay { permission CanWriteParameterizedOverlay;
  kotoage fn write(int value) authorize(CanWriteParameterizedOverlay) {
    let _value = value;
  }
}
",
            )
            .expect("compile protected parameterized overlay fixture");
        let verified =
            ivm::verify_contract_artifact(&program).expect("verify parameterized overlay fixture");
        let prepared = ivm::prepare_contract(Arc::from(program.clone()))
            .expect("prepare parameterized overlay fixture");
        let schema = prepared
            .entrypoint_descriptor("write")
            .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
            .expect("write argument schema");
        let arguments = ivm_abi::arguments::encode_argument_record_from_json(
            schema,
            &Json::from(norito::json!({ "value": "7" })),
        )
        .expect("encode canonical parameterized arguments");
        let arguments = ContractArgumentRecord::try_new(arguments)
            .expect("bounded parameterized argument record");
        let (authority, keypair) = gen_account_in("wonderland");
        let domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            93,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive parameterized contract address");
        let code_hash = verified.code_hash;
        let mut world = crate::state::World::with([domain], [account], []);
        world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            program,
        );
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            verified.manifest,
        );
        seed_active_contract(&mut world, &contract_address, code_hash, &authority);
        let chain_id = ChainId::from("parameterized-authorization-overlay");
        let state = test_support::state_after_genesis_with_chain(world, chain_id.clone());
        let metadata = Metadata::default();
        let transaction = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::ContractCall(ContractInvocation {
                contract_address,
                expected_code_hash: code_hash,
                entrypoint: "write".to_owned(),
                arguments: Some(arguments),
            }))
            .sign(keypair.private_key());
        ivm::reset_argument_record_decode_count();
        let error = build_overlay_for_transaction(&transaction, &*execution_block(&state))
            .expect_err("missing permission must reject the parameterized call");
        assert!(
            matches!(
                &error,
                OverlayBuildError::ContractCall(message)
                    if message.contains(REQUIRED_PERMISSION) && message.contains("write")
            ),
            "unexpected parameterized authorization error: {error:?}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "ordinary ContractCall permission denial must precede canonical record decoding"
        );
    }
    #[test]
    fn protected_contract_call_is_checked_before_vm_and_again_before_overlay_apply() {
        use iroha_data_model::{
            permission::{Permission, Permissions},
            transaction::executable::{ContractArgumentRecord, ContractInvocation},
        };
        const REQUIRED_PERMISSION: &str = "CanInvokeContractEntrypoint";
        let (authority, keypair) = gen_account_in("wonderland");
        let (artifact, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r"
seiyaku GuardedOverlay { permission CanInvokeContractEntrypoint;
  kotoage fn main(int value) authorize(CanInvokeContractEntrypoint) {
    let _value = value;
  }
}
",
            )
            .expect("compile parameterized guarded overlay contract");
        let prepared = ivm::prepare_contract(Arc::from(artifact.clone()))
            .expect("prepare parameterized guarded overlay contract");
        let schema = prepared
            .entrypoint_descriptor("main")
            .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
            .expect("main argument schema");
        let arguments = ivm_abi::arguments::encode_argument_record_from_json(
            schema,
            &Json::from(norito::json!({ "value": "7" })),
        )
        .expect("encode guarded overlay arguments");
        let arguments =
            ContractArgumentRecord::try_new(arguments).expect("bounded guarded overlay arguments");
        let code_hash = manifest.code_hash.expect("verified code hash");
        let contract_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
            "guarded",
            Some("wonderland"),
            "universal",
        )
        .expect("valid contract alias");
        let make_state = |authorized: bool| {
            let domain = iroha_data_model::domain::Domain::new(
                DomainId::try_new("wonderland", "universal").expect("valid domain"),
            )
            .build(&authority);
            let account = build_wonderland_account(&authority);
            let world = crate::state::World::with([domain], [account], []);
            let mut state = test_support::state_after_genesis(world);
            let contract_address =
                ContractAddress::derive(&state.network_id, &authority, 92, DataSpaceId::UNIVERSAL)
                    .expect("derive guarded contract address from its signed network");
            let entrypoint_authorization = Permission::from(
                iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
                    contract: contract_address.clone(),
                    entrypoint: "main".to_owned(),
                },
            );
            let world = &mut state.world;
            world.contract_code.insert(
                ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
                artifact.clone(),
            );
            world.contract_manifests.insert(
                ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
                manifest.clone(),
            );
            seed_active_contract(world, &contract_address, code_hash, &authority);
            world
                .bind_contract_alias(&contract_address, contract_alias.clone(), None, None, 0)
                .expect("bind guarded contract alias");
            // The contract executes queued metadata writes as its own subject. The
            // ordinary account permission is independent of entrypoint admission.
            let mut contract_permissions = Permissions::new();
            assert!(contract_permissions.insert(Permission::from(
                iroha_executor_data_model::permission::account::CanModifyAccountMetadata {
                    account: authority.clone(),
                },
            )));
            // The queued revocation executes as the contract subject. Give that subject
            // the exact permission it may revoke so the negative control reaches the
            // subsequent caller-authorization recheck instead of failing issuer policy.
            assert!(contract_permissions.insert(entrypoint_authorization.clone()));
            world
                .account_permissions_mut_for_testing()
                .insert(contract_address.subject_id(), contract_permissions);
            if authorized {
                let mut permissions = Permissions::new();
                assert!(permissions.insert(entrypoint_authorization.clone()));
                world
                    .account_permissions_mut_for_testing()
                    .insert(authority.clone(), permissions);
            }
            (state, contract_address)
        };
        let (unauthorized_state, contract_address) = make_state(false);
        let entrypoint_authorization = Permission::from(
            iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
                contract: contract_address.clone(),
                entrypoint: "main".to_owned(),
            },
        );
        let metadata = iroha_model_base::metadata::Metadata::default();
        let transaction = TransactionBuilder::new(
            unauthorized_state.network_id,
            authority.clone(),
            test_fee_payment(),
        )
        .with_metadata(metadata)
        .with_executable(Executable::ContractCall(ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: code_hash,
            entrypoint: "main".to_owned(),
            arguments: Some(arguments),
        }))
        .sign(keypair.private_key());
        let denied =
            build_overlay_for_transaction(&transaction, &*execution_block(&unauthorized_state))
                .expect_err("missing named permission must reject before the VM runs");
        assert!(
            matches!(
                &denied,
                OverlayBuildError::ContractCall(message)
                    if message.contains(REQUIRED_PERMISSION) && message.contains("main")
            ),
            "unexpected authorization error: {denied:?}"
        );
        let (rebound_artifact, rebound_manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r"
seiyaku GuardedOverlayRebound { permission CanInvokeContractEntrypoint;
  kotoage fn main(int value) authorize(CanInvokeContractEntrypoint) {
    let _value = value + 1;
  }
}
",
            )
            .expect("compile parameterized rebound overlay contract");
        let rebound_code_hash = rebound_manifest.code_hash.expect("rebound code hash");
        assert_ne!(rebound_code_hash, code_hash);
        let mut rebound_state = make_state(true).0;
        rebound_state.world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, rebound_code_hash),
            rebound_artifact,
        );
        rebound_state.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, rebound_code_hash),
            rebound_manifest,
        );
        seed_active_contract(
            &mut rebound_state.world,
            &contract_address,
            rebound_code_hash,
            &authority,
        );
        ivm::reset_argument_record_decode_count();
        let rebound_error =
            build_overlay_for_transaction(&transaction, &*execution_block(&rebound_state))
                .expect_err("a signed call must not execute after its address is rebound");
        assert!(
            matches!(
                &rebound_error,
                OverlayBuildError::ContractCall(message)
                    if message.contains(&contract_address.to_string())
                        && message.contains(&code_hash.to_string())
                        && message.contains(&rebound_code_hash.to_string())
            ),
            "unexpected code-binding error: {rebound_error:?}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "code-hash drift must reject before argument decoding"
        );
        let authorized_state = make_state(true).0;
        let mut overlay =
            build_overlay_for_transaction(&transaction, &*execution_block(&authorized_state))
                .expect("granted caller may prepare the protected call");
        let contract_state_digest =
            hex::encode(Hash::new(contract_address.to_string().as_bytes()).as_ref());
        let guarded_path: StatePath = format!("sc/{contract_state_digest}/guarded/write")
            .parse()
            .expect("valid scoped contract state path");
        let queued_key: Name = "guarded_queued".parse().expect("valid metadata key");
        overlay.effects.push(OverlayEffect {
            payload: QueuedEffectPayload::Instruction(
                iroha_data_model::isi::SetKeyValue::account(
                    authority.clone(),
                    queued_key.clone(),
                    Json::new("queued"),
                )
                .into(),
            ),
            execution_context: Some(OverlayInstructionExecutionContext {
                authority: contract_address.subject_id(),
                contract_runtime_context: Some(crate::executor::ContractRuntimeExecutionContext {
                    contract_subject: contract_address.subject_id(),
                    contract_address: contract_address.clone(),
                    contract_alias: Some(contract_alias.clone()),
                    entrypoint: "main".to_owned(),
                }),
                entrypoint_authorization: overlay.entrypoint_authorization.clone(),
            }),
        });
        overlay
            .durable_state_overlay
            .insert(guarded_path.clone(), Some(vec![0xA5]));
        overlay.durable_state_authorizations.insert(
            guarded_path.clone(),
            overlay.entrypoint_authorization.clone(),
        );
        {
            let view = authorized_state.view();
            let root = overlay.entrypoint_authorization.as_ref().unwrap();
            root.validate(view.world())
                .expect("fixture retains actual live contract authority");
            validate_ivm_proved_durable_authorizations(
                view.world(),
                &overlay.durable_state_overlay,
                &overlay.durable_state_authorizations,
                root,
            )
            .expect("the original scoped contract path retains its exact authority");
            let native: StatePath = "sorafs_reserve_state_v1".parse().unwrap();
            for replacement in [Some(vec![8]), None] {
                let error = validate_ivm_proved_durable_authorizations(
                    view.world(),
                    &BTreeMap::from([(native.clone(), replacement)]),
                    &BTreeMap::from([(native.clone(), Some(root.clone()))]),
                    root,
                )
                .unwrap_err();
                assert!(matches!(error,
                    crate::execution_attempt::ExecutionAttemptError::Rejected(
                        ValidationFail::NotPermitted(reason)
                    ) if reason.contains("native reserve state")
                ));
            }
        }
        let proved_overlay = TxOverlay::from_ivm_proved_instructions(
            overlay.instructions().cloned().collect(),
            &authority,
            crate::executor::ContractRuntimeExecutionContext {
                contract_subject: contract_address.subject_id(),
                contract_address: contract_address.clone(),
                contract_alias: Some(contract_alias.clone()),
                entrypoint: "main".to_owned(),
            },
            overlay
                .entrypoint_authorization
                .clone()
                .expect("protected overlay authorization"),
        );
        let mut context_only_overlay = overlay.instruction_fixture();
        context_only_overlay.entrypoint_authorization = None;
        let mut missing_durable_authorization = overlay.instruction_fixture();
        missing_durable_authorization
            .durable_state_authorizations
            .remove(&guarded_path);
        let mut malformed_block = execution_block(&authorized_state);
        let mut malformed_transaction = malformed_block.transaction();
        let malformed_error = missing_durable_authorization
            .apply(&mut malformed_transaction, &authority)
            .expect_err("durable values and authorization snapshots must have identical keys");
        assert!(matches!(
            malformed_error,
            ValidationFail::InternalError(message)
                if message.contains("structurally inconsistent")
        ));
        assert!(
            malformed_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_none()
                && malformed_transaction
                    .world
                    .smart_contract_state
                    .get(&guarded_path)
                    .is_none(),
            "structurally malformed durable authorization must reject before all effects"
        );
        drop(malformed_transaction);
        drop(malformed_block);
        let mut revoked_block = execution_block(&unauthorized_state);
        let mut revoked_transaction = revoked_block.transaction();
        let error = overlay
            .instruction_fixture()
            .apply(&mut revoked_transaction, &authority)
            .expect_err("a revoked permission must invalidate the prepared overlay");
        assert!(matches!(error, ValidationFail::NotPermitted(_)));
        assert!(
            revoked_transaction
                .world
                .smart_contract_state
                .get(&guarded_path)
                .is_none(),
            "authorization must be checked before any durable write is applied"
        );
        assert!(
            revoked_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_none(),
            "authorization must be checked before any queued instruction is applied"
        );
        drop(revoked_transaction);
        drop(revoked_block);
        let mut revoked_proved_block = execution_block(&unauthorized_state);
        let mut revoked_proved_transaction = revoked_proved_block.transaction();
        proved_overlay
            .instruction_fixture()
            .apply(&mut revoked_proved_transaction, &authority)
            .expect_err("a revoked permission must invalidate a proved replay overlay");
        assert!(
            revoked_proved_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_none(),
            "proved replay authorization must run before any queued instruction"
        );
        drop(revoked_proved_transaction);
        drop(revoked_proved_block);
        let mut deactivated_proved_block = execution_block(&authorized_state);
        let mut deactivated_proved_transaction = deactivated_proved_block.transaction();
        deactivated_proved_transaction
            .world
            .contract_instances
            .remove(contract_address.clone());
        deactivated_proved_transaction
            .world
            .contract_subject_bindings
            .get_mut(&contract_address)
            .expect("retained deactivated lifecycle")
            .lifecycle
            .active_code_hash = None;
        proved_overlay
            .instruction_fixture()
            .apply(&mut deactivated_proved_transaction, &authority)
            .expect_err("a deactivated contract must invalidate a proved replay overlay");
        assert!(
            deactivated_proved_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_none(),
            "proved replay binding validation must run before any queued instruction"
        );
        drop(deactivated_proved_transaction);
        drop(deactivated_proved_block);
        let mut authorized_proved_block = execution_block(&authorized_state);
        let mut authorized_proved_transaction = authorized_proved_block.transaction();
        proved_overlay
            .instruction_fixture()
            .apply(&mut authorized_proved_transaction, &authority)
            .expect("live permission and binding must allow the proved replay overlay");
        assert!(
            authorized_proved_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_some(),
            "granted proved replay authorization must allow queued instructions"
        );
        drop(authorized_proved_transaction);
        drop(authorized_proved_block);
        let mut revoked_effect_block = execution_block(&authorized_state);
        let mut revoked_effect_transaction = revoked_effect_block.transaction();
        assert!(
            revoked_effect_transaction
                .world
                .account_permissions
                .get_mut(&contract_address.subject_id())
                .expect("contract effect permissions")
                .remove(&Permission::from(
                    iroha_executor_data_model::permission::account::CanModifyAccountMetadata {
                        account: authority.clone(),
                    },
                ))
        );
        let error = proved_overlay
            .instruction_fixture()
            .apply(&mut revoked_effect_transaction, &authority)
            .expect_err("live entrypoint permission cannot replace a revoked effect permission");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(message) if message == "authority cannot modify this metadata"
        ));
        assert!(
            revoked_effect_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_none()
                && revoked_effect_transaction
                    .world
                    .smart_contract_state
                    .get(&guarded_path)
                    .is_none(),
            "revoked subject effect permission must apply zero queued or durable effects"
        );
        drop(revoked_effect_transaction);
        drop(revoked_effect_block);
        let mut revoked_context_block = execution_block(&unauthorized_state);
        let mut revoked_context_transaction = revoked_context_block.transaction();
        context_only_overlay
            .apply(&mut revoked_context_transaction, &authority)
            .expect_err("queued contract effects must carry their own permission snapshot");
        assert!(
            revoked_context_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_none()
                && revoked_context_transaction
                    .world
                    .smart_contract_state
                    .get(&guarded_path)
                    .is_none(),
            "queued-context authorization must reject before every prepared effect"
        );
        drop(revoked_context_transaction);
        drop(revoked_context_block);
        let mut deactivated_block = execution_block(&authorized_state);
        let mut deactivated_transaction = deactivated_block.transaction();
        deactivated_transaction
            .world
            .contract_instances
            .remove(contract_address.clone());
        deactivated_transaction
            .world
            .contract_subject_bindings
            .get_mut(&contract_address)
            .expect("retained deactivated lifecycle")
            .lifecycle
            .active_code_hash = None;
        let error = overlay
            .instruction_fixture()
            .apply(&mut deactivated_transaction, &authority)
            .expect_err("deactivation must invalidate a prepared contract overlay");
        assert!(
            matches!(
                &error,
                ValidationFail::NotPermitted(message)
                    if message.contains("no longer active")
            ),
            "unexpected stale-binding error: {error:?}"
        );
        assert!(
            deactivated_transaction
                .world
                .smart_contract_state
                .get(&guarded_path)
                .is_none(),
            "binding must be checked before any durable write is applied"
        );
        assert!(
            deactivated_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_none(),
            "deactivation must be checked before any queued instruction is applied"
        );
        drop(deactivated_transaction);
        drop(deactivated_block);
        let mut rebound_block = execution_block(&authorized_state);
        let mut rebound_transaction = rebound_block.transaction();
        let changed_code_hash = Hash::new(b"changed-guarded-code");
        rebound_transaction
            .world
            .contract_instances
            .insert(contract_address.clone(), changed_code_hash);
        rebound_transaction
            .world
            .contract_subject_bindings
            .get_mut(&contract_address)
            .expect("retained rebound lifecycle")
            .lifecycle
            .active_code_hash = Some(changed_code_hash);
        rebound_transaction
            .world
            .contract_subject_bindings
            .get_mut(&contract_address)
            .unwrap()
            .lifecycle
            .retained_code_hash = Some(changed_code_hash);
        let error = overlay
            .instruction_fixture()
            .apply(&mut rebound_transaction, &authority)
            .expect_err("a changed code binding must invalidate a prepared contract overlay");
        assert!(
            matches!(
                &error,
                ValidationFail::NotPermitted(message)
                    if message.contains("changed code binding")
                        && message.contains(&contract_address.to_string())
                        && message.contains(&code_hash.to_string())
                        && message.contains(&changed_code_hash.to_string())
            ),
            "unexpected changed-code error: {error:?}"
        );
        assert!(
            rebound_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_none()
                && rebound_transaction
                    .world
                    .smart_contract_state
                    .get(&guarded_path)
                    .is_none(),
            "a changed code binding must apply zero prepared effects"
        );
        drop(rebound_transaction);
        drop(rebound_block);
        let mut realias_block = execution_block(&authorized_state);
        let mut realias_transaction = realias_block.transaction();
        let replacement_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
            "guarded2",
            Some("wonderland"),
            "universal",
        )
        .expect("valid replacement alias");
        realias_transaction
            .world
            .bind_contract_alias(&contract_address, replacement_alias, None, None, 1)
            .expect("replace guarded contract alias");
        let error = overlay
            .instruction_fixture()
            .apply(&mut realias_transaction, &authority)
            .expect_err("a changed alias binding must invalidate a prepared contract overlay");
        assert!(
            matches!(
                &error,
                ValidationFail::NotPermitted(message)
                    if message.contains("changed alias binding")
            ),
            "unexpected changed-alias error: {error:?}"
        );
        assert!(
            realias_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_none()
                && realias_transaction
                    .world
                    .smart_contract_state
                    .get(&guarded_path)
                    .is_none(),
            "a changed alias binding must apply zero prepared effects"
        );
        drop(realias_transaction);
        drop(realias_block);
        let mut revoking_overlay = overlay.instruction_fixture();
        revoking_overlay.effects = vec![OverlayEffect {
            payload: QueuedEffectPayload::Instruction(
                Revoke::account_permission(entrypoint_authorization, authority.clone()).into(),
            ),
            execution_context: overlay
                .effects
                .first()
                .expect("guarded effect")
                .execution_context
                .clone(),
        }];
        let mut revoking_block = execution_block(&authorized_state);
        let mut revoking_transaction = revoking_block.transaction();
        let error = revoking_overlay
            .apply(&mut revoking_transaction, &authority)
            .expect_err("queued permission revocation must invalidate later durable writes");
        assert!(
            matches!(
                &error,
                ValidationFail::NotPermitted(message)
                    if message.contains(REQUIRED_PERMISSION)
            ),
            "unexpected post-instruction authorization error: {error:?}"
        );
        assert!(
            revoking_transaction
                .world
                .smart_contract_state
                .get(&guarded_path)
                .is_none(),
            "authorization must be rechecked after queued instructions and before durable writes"
        );
        drop(revoking_transaction);
        drop(revoking_block);
        let mut authorized_block = execution_block(&authorized_state);
        let mut authorized_transaction = authorized_block.transaction();
        overlay
            .instruction_fixture()
            .apply(&mut authorized_transaction, &authority)
            .expect("live permission recheck should preserve the authorized path");
        assert_eq!(
            authorized_transaction
                .world
                .smart_contract_state
                .get(&guarded_path)
                .map(Vec::as_slice),
            Some([0xA5].as_slice())
        );
        assert!(
            authorized_transaction
                .world
                .account(&authority)
                .expect("authority account")
                .metadata()
                .get(&queued_key)
                .is_some(),
            "the granted live authorization must allow queued instructions"
        );
    }
    #[test]
    fn nested_overlay_effects_retain_and_revalidate_the_complete_authorization_chain() {
        use iroha_data_model::permission::{Permission, Permissions};
        const ROOT_PERMISSION: &str = "CanInvokeRoot";
        const CHILD_PERMISSION: &str = "CanInvokeContractEntrypoint";
        let (authority, _) = gen_account_in("wonderland");
        let root_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
            "root",
            Some("wonderland"),
            "universal",
        )
        .expect("root alias");
        let child_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
            "child",
            Some("wonderland"),
            "universal",
        )
        .expect("child alias");
        let root_code_hash = Hash::new(b"root-authorization-code");
        let child_code_hash = Hash::new(b"child-authorization-code");
        let make_state = |grant_root: bool, grant_child: bool, child_active: bool| {
            let domain = iroha_data_model::domain::Domain::new(
                DomainId::try_new("wonderland", "universal").expect("domain id"),
            )
            .build(&authority);
            let account = build_wonderland_account(&authority);
            let world = crate::state::World::with([domain], [account], []);
            let mut state = test_support::state_after_genesis(world);
            let root_address =
                ContractAddress::derive(&state.network_id, &authority, 82, DataSpaceId::UNIVERSAL)
                    .expect("derive root contract address from its signed network");
            let child_address =
                ContractAddress::derive(&state.network_id, &authority, 83, DataSpaceId::UNIVERSAL)
                    .expect("derive child contract address from its signed network");
            let root_contract_subject = root_address.subject_id();
            let child_contract_subject = child_address.subject_id();
            let child_entrypoint_authorization = Permission::from(
                iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
                    contract: child_address.clone(),
                    entrypoint: "child".to_owned(),
                },
            );
            let world = &mut state.world;
            for subject in [&root_contract_subject, &child_contract_subject] {
                let (id, account) = build_wonderland_account(subject).into_key_value();
                world.accounts.insert(id, account);
            }
            seed_active_contract(world, &root_address, root_code_hash, &authority);
            // The child owns its lifecycle so the self-deactivation case reaches
            // the post-instruction authorization check.
            if child_active {
                seed_active_contract(
                    world,
                    &child_address,
                    child_code_hash,
                    &child_contract_subject,
                );
            } else {
                world.contract_subject_bindings.insert(
                    child_address.clone(),
                    code::ContractSubjectBinding::new_direct(
                        &child_address,
                        child_contract_subject.clone(),
                    ),
                );
            }
            world
                .bind_contract_alias(&root_address, root_alias.clone(), None, None, 0)
                .expect("bind root alias");
            if child_active {
                world
                    .bind_contract_alias(&child_address, child_alias.clone(), None, None, 0)
                    .expect("bind child alias");
            }
            let mut root_permissions = Permissions::new();
            if grant_root {
                assert!(
                    root_permissions
                        .insert(Permission::new(ROOT_PERMISSION.to_owned(), Json::new(()),))
                );
            }
            let mut root_contract_permissions = Permissions::new();
            if grant_child {
                assert!(root_contract_permissions.insert(child_entrypoint_authorization.clone()));
            }
            let mut child_contract_permissions = Permissions::new();
            assert!(child_contract_permissions.insert(Permission::from(
                iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode,
            )));
            assert!(child_contract_permissions.insert(Permission::from(
                iroha_executor_data_model::permission::account::CanModifyAccountMetadata {
                    account: root_contract_subject.clone(),
                },
            )));
            world
                .account_permissions_mut_for_testing()
                .insert(authority.clone(), root_permissions);
            world
                .account_permissions_mut_for_testing()
                .insert(root_contract_subject.clone(), root_contract_permissions);
            world
                .account_permissions_mut_for_testing()
                .insert(child_contract_subject.clone(), child_contract_permissions);
            // Retain fixture states on the heap: this scenario exercises several
            // independent worlds, and their inline storage exhausted the default
            // test thread stack before authorization was reached.
            (Box::new(state), root_address, child_address)
        };
        let (authorized_state, root_address, child_address) = make_state(true, true, true);
        let root_contract_subject = root_address.subject_id();
        let child_contract_subject = child_address.subject_id();
        let child_entrypoint_authorization = Permission::from(
            iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
                contract: child_address.clone(),
                entrypoint: "child".to_owned(),
            },
        );
        let root_authorization = ContractEntrypointAuthorizationSnapshot::new(
            authority.clone(),
            "root".to_owned(),
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                ROOT_PERMISSION.parse().unwrap(),
            ),
            &code::BoundContractIdentity {
                lifecycle_revision: 1,
                contract_address: root_address.clone(),
                contract_alias: Some(root_alias.clone()),
                contract_alias_binding: Some(crate::state::ContractAliasBindingRecord {
                    alias: root_alias.clone(),
                    lease_expiry_ms: None,
                    grace_until_ms: None,
                    bound_at_ms: 0,
                }),
                code_hash: root_code_hash,
            },
        );
        let child_leaf = ContractEntrypointAuthorizationSnapshot::new(
            root_contract_subject.clone(),
            "child".to_owned(),
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                CHILD_PERMISSION.parse().unwrap(),
            ),
            &code::BoundContractIdentity {
                lifecycle_revision: 1,
                contract_address: child_address.clone(),
                contract_alias: Some(child_alias.clone()),
                contract_alias_binding: Some(crate::state::ContractAliasBindingRecord {
                    alias: child_alias.clone(),
                    lease_expiry_ms: None,
                    grace_until_ms: None,
                    bound_at_ms: 0,
                }),
                code_hash: child_code_hash,
            },
        );
        let child_authorization = child_leaf
            .clone()
            .with_parent(Some(root_authorization.clone()));
        let metadata_key: Name = "nested_authorization_applied"
            .parse()
            .expect("metadata key");
        let durable_path: StatePath = format!(
            "sc/{}/nested",
            hex::encode(Hash::new(child_address.to_string().as_bytes()).as_ref())
        )
        .parse()
        .expect("scoped durable path");
        let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
            root_contract_subject.clone(),
            metadata_key.clone(),
            Json::new("applied"),
        )
        .into();
        let build_overlay = |effect_authorization: ContractEntrypointAuthorizationSnapshot| {
            TxOverlay::from_host_execution(
                vec![instruction.clone()],
                vec![OverlayInstructionExecutionContext {
                    authority: child_contract_subject.clone(),
                    contract_runtime_context: Some(
                        crate::executor::ContractRuntimeExecutionContext {
                            contract_subject: child_address.subject_id(),
                            contract_address: child_address.clone(),
                            contract_alias: Some(child_alias.clone()),
                            entrypoint: "child".to_owned(),
                        },
                    ),
                    entrypoint_authorization: Some(effect_authorization.clone()),
                }],
                0,
                Vec::new(),
                BTreeMap::from([(durable_path.clone(), Some(vec![0xC1]))]),
                BTreeMap::from([(durable_path.clone(), Some(effect_authorization))]),
            )
            .with_entrypoint_authorization(Some(root_authorization.clone()))
        };
        let mut authorized_block = execution_block(&authorized_state);
        let mut authorized_tx = authorized_block.transaction();
        build_overlay(child_authorization.clone())
            .apply(&mut authorized_tx, &authority)
            .expect("complete live authorization chain permits nested effects");
        assert!(
            authorized_tx
                .world
                .account(&root_contract_subject)
                .expect("root contract account")
                .metadata()
                .get(&metadata_key)
                .is_some()
        );
        assert_eq!(
            authorized_tx
                .world
                .smart_contract_state
                .get(&durable_path)
                .map(Vec::as_slice),
            Some([0xC1].as_slice())
        );
        drop(authorized_tx);
        drop(authorized_block);
        let mut revoked_effect_block = execution_block(&authorized_state);
        let mut revoked_effect_tx = revoked_effect_block.transaction();
        assert!(
            revoked_effect_tx
                .world
                .account_permissions
                .get_mut(&child_contract_subject)
                .expect("child effect permissions")
                .remove(&Permission::from(
                    iroha_executor_data_model::permission::account::CanModifyAccountMetadata {
                        account: root_contract_subject.clone(),
                    },
                ))
        );
        let error = build_overlay(child_authorization.clone())
            .apply(&mut revoked_effect_tx, &authority)
            .expect_err("complete entrypoint chain cannot replace a revoked child effect grant");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(message) if message == "authority cannot modify this metadata"
        ));
        assert!(
            revoked_effect_tx
                .world
                .account(&root_contract_subject)
                .expect("root contract account")
                .metadata()
                .get(&metadata_key)
                .is_none()
                && revoked_effect_tx
                    .world
                    .smart_contract_state
                    .get(&durable_path)
                    .is_none(),
            "revoked child effect grant must apply zero queued or durable effects"
        );
        drop(revoked_effect_tx);
        drop(revoked_effect_block);
        for (label, grant_root, grant_child, child_active) in [
            ("revoked root", false, true, true),
            ("revoked child", true, false, true),
            ("deactivated child", true, true, false),
        ] {
            let state = make_state(grant_root, grant_child, child_active).0;
            let mut block = execution_block(&state);
            let mut tx = block.transaction();
            build_overlay(child_authorization.clone())
                .apply(&mut tx, &authority)
                .expect_err(label);
            assert!(
                tx.world
                    .account(&root_contract_subject)
                    .expect("root contract account")
                    .metadata()
                    .get(&metadata_key)
                    .is_none()
                    && tx.world.smart_contract_state.get(&durable_path).is_none(),
                "{label} must reject before every nested effect"
            );
        }
        let mut missing_parent_block = execution_block(&authorized_state);
        let mut missing_parent_tx = missing_parent_block.transaction();
        let error = build_overlay(child_leaf)
            .apply(&mut missing_parent_tx, &authority)
            .expect_err("detached child snapshot must not shed the root authorization");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(message) if message.contains("root invocation chain")
        ));
        assert!(
            missing_parent_tx
                .world
                .account(&root_contract_subject)
                .expect("root contract account")
                .metadata()
                .get(&metadata_key)
                .is_none()
                && missing_parent_tx
                    .world
                    .smart_contract_state
                    .get(&durable_path)
                    .is_none()
        );
        let forged_child = ContractEntrypointAuthorizationSnapshot::new(
            authority.clone(),
            "child".to_owned(),
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                CHILD_PERMISSION.parse().unwrap(),
            ),
            &code::BoundContractIdentity {
                lifecycle_revision: 1,
                contract_address: child_address.clone(),
                contract_alias: Some(child_alias.clone()),
                contract_alias_binding: Some(crate::state::ContractAliasBindingRecord {
                    alias: child_alias.clone(),
                    lease_expiry_ms: None,
                    grace_until_ms: None,
                    bound_at_ms: 0,
                }),
                code_hash: child_code_hash,
            },
        )
        .with_parent(Some(root_authorization.clone()));
        let forged_state = make_state(true, true, true).0;
        let mut forged_block = execution_block(&forged_state);
        let mut forged_tx = forged_block.transaction();
        let forged_overlay = TxOverlay::from_host_execution(
            vec![instruction.clone()],
            vec![OverlayInstructionExecutionContext {
                authority: child_contract_subject.clone(),
                contract_runtime_context: Some(crate::executor::ContractRuntimeExecutionContext {
                    contract_subject: child_address.subject_id(),
                    contract_address: child_address.clone(),
                    contract_alias: Some(child_alias.clone()),
                    entrypoint: "child".to_owned(),
                }),
                entrypoint_authorization: Some(forged_child),
            }],
            0,
            Vec::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .with_entrypoint_authorization(Some(root_authorization.clone()));
        let error = forged_overlay
            .apply(&mut forged_tx, &authority)
            .expect_err("nested caller must be the immediate parent contract subject");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(message)
                if message.contains("immediate parent contract")
        ));
        let build_single_effect_overlay = |instruction: InstructionBox| {
            TxOverlay::from_host_execution(
                vec![instruction],
                vec![OverlayInstructionExecutionContext {
                    authority: child_contract_subject.clone(),
                    contract_runtime_context: Some(
                        crate::executor::ContractRuntimeExecutionContext {
                            contract_subject: child_address.subject_id(),
                            contract_address: child_address.clone(),
                            contract_alias: Some(child_alias.clone()),
                            entrypoint: "child".to_owned(),
                        },
                    ),
                    entrypoint_authorization: Some(child_authorization.clone()),
                }],
                0,
                Vec::new(),
                BTreeMap::from([(durable_path.clone(), Some(vec![0xD1]))]),
                BTreeMap::from([(durable_path.clone(), Some(child_authorization.clone()))]),
            )
            .with_entrypoint_authorization(Some(root_authorization.clone()))
        };
        let self_revoking_state = make_state(true, true, true).0;
        let mut self_revoking_block = execution_block(&self_revoking_state);
        let mut self_revoking_tx = self_revoking_block.transaction();
        let error = build_single_effect_overlay(
            Revoke::account_permission(
                child_entrypoint_authorization.clone(),
                root_contract_subject.clone(),
            )
            .into(),
        )
        .apply(&mut self_revoking_tx, &authority)
        .expect_err("the final nested effect must not revoke its own selected permission");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(message) if message.contains(CHILD_PERMISSION)
        ));
        assert!(
            self_revoking_tx
                .world
                .smart_contract_state
                .get(&durable_path)
                .is_none(),
            "permission revocation must reject before the guarded durable write"
        );
        drop(self_revoking_tx);
        drop(self_revoking_block);
        let self_revoking_view = self_revoking_state.view();
        assert!(
            self_revoking_view
                .world
                .account_permissions()
                .get(&root_contract_subject)
                .is_some_and(|permissions| permissions.contains(&child_entrypoint_authorization)),
            "a rejected self-revocation must not persist outside its discarded transaction"
        );
        assert!(
            self_revoking_view
                .world
                .smart_contract_state()
                .get(&durable_path)
                .is_none(),
            "a rejected self-revocation must persist no guarded durable write"
        );
        let self_deactivating_state = make_state(true, true, true).0;
        let mut self_deactivating_block = execution_block(&self_deactivating_state);
        let mut self_deactivating_tx = self_deactivating_block.transaction();
        let error = build_single_effect_overlay(
            iroha_data_model::isi::smart_contract_code::DeactivateContractInstance {
                contract_address: child_address.clone(),
                expected_revision: 1,
                reason: Some("nested authorization regression".to_owned()),
            }
            .into(),
        )
        .apply(&mut self_deactivating_tx, &authority)
        .expect_err("the final nested effect must not deactivate its selected contract");
        assert!(matches!(
            error,
            ValidationFail::NotPermitted(message) if message.contains("no longer active")
        ));
        assert!(
            self_deactivating_tx
                .world
                .smart_contract_state
                .get(&durable_path)
                .is_none(),
            "contract deactivation must reject before the guarded durable write"
        );
        drop(self_deactivating_tx);
        drop(self_deactivating_block);
        let self_deactivating_view = self_deactivating_state.view();
        assert_eq!(
            self_deactivating_view
                .world
                .contract_instances()
                .get(&child_address),
            Some(&child_code_hash),
            "a rejected self-deactivation must not persist outside its discarded transaction"
        );
        assert!(
            self_deactivating_view
                .world
                .smart_contract_state()
                .get(&durable_path)
                .is_none(),
            "a rejected self-deactivation must persist no guarded durable write"
        );
    }
    #[test]
    fn artifact_admission_mapping_keeps_local_owner_and_deterministic_diagnostic() {
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let original = budget.try_reserve_bytes(1).unwrap_err();
        let error = map_artifact_admission_error(ivm::ContractArtifactError::preparation(
            "instruction admission",
            ivm::VMError::AllocationDeferred(original.clone()),
        ));
        assert!(
            matches!(error, OverlayBuildError::IvmLoad(ivm::VMError::AllocationDeferred(ref retained)) if retained == &original)
        );
        let invalid = ivm::ContractArtifactError::invalid("missing canonical instruction");
        let diagnostic = invalid.to_string();
        assert!(matches!(map_artifact_admission_error(invalid),
            OverlayBuildError::HeaderPolicy(IvmAdmissionError::BytecodeDecodingFailed(retained)) if retained == diagnostic));
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn policyless_transaction_entrypoint_artifact_is_rejected() {
        let artifact = minimal_contract_artifact_bytes(1, None);
        let error = ivm::verify_contract_artifact(&artifact)
            .expect_err("ABI V1 must reject a kotoage entrypoint without caller authorization");
        assert!(
            error.to_string().contains("missing caller authorization"),
            "unexpected policyless-artifact error: {error}"
        );
    }
    #[test]
    fn redundant_artifact_pruning_never_crosses_dataspaces() {
        let (program, manifest) = minimal_contract_artifact(1);
        let hash = manifest.code_hash.expect("verified artifact hash");
        let owned = ContractArtifactId::new(DataSpaceId::new(17), hash);
        let foreign = ContractArtifactId::new(DataSpaceId::new(u64::MAX), hash);
        let mut world = crate::state::World::default();
        world.contract_code.insert(owned, program.clone());
        world.contract_manifests.insert(owned, manifest.clone());
        let state = State::new(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let bytes = |artifact_id| {
            InstructionBox::from(RegisterSmartContractBytes {
                artifact_id,
                code: program.clone(),
            })
        };
        let registration = |artifact_id| {
            InstructionBox::from(RegisterSmartContractCode {
                artifact_id,
                manifest: manifest.clone(),
            })
        };
        let mut queued = vec![
            bytes(owned),
            bytes(foreign),
            registration(owned),
            registration(foreign),
        ];
        assert!(queued_contract_bytes_match(
            &[bytes(owned)],
            &owned,
            &program
        ));
        assert!(!queued_contract_bytes_match(
            &[bytes(owned)],
            &foreign,
            &program
        ));
        assert!(queued_manifest_matches(
            &[registration(owned)],
            &owned,
            &manifest
        ));
        assert!(!queued_manifest_matches(
            &[registration(owned)],
            &foreign,
            &manifest
        ));
        prune_redundant_contract_ops(&state.view(), &mut queued);
        assert_eq!(queued, vec![bytes(foreign), registration(foreign)]);
    }

    #[test]
    fn state_free_artifact_registration_requires_and_preserves_explicit_scope() {
        let (program, manifest) = minimal_contract_artifact(1);
        let hash = manifest.code_hash.expect("verified artifact hash");
        let (authority, pair) = gen_account_in("wonderland");
        let network = overlay_test_network_id(b"state-free artifact scope");
        let address = ContractAddress::derive(&network, &authority, 1, DataSpaceId::new(u64::MAX))
            .expect("full-width scoped address");
        let transaction = |address: Option<&ContractAddress>| {
            let mut metadata = Metadata::default();
            metadata.insert(
                MANIFEST_METADATA_KEY.parse().unwrap(),
                Json::new(manifest.clone()),
            );
            if let Some(address) = address {
                metadata.insert(
                    "contract_address".parse().unwrap(),
                    Json::new(address.to_string()),
                );
            }
            TransactionBuilder::new(network, authority.clone(), test_fee_payment())
                .with_metadata(metadata)
                .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program.clone())))
                .sign(pair.private_key())
        };
        let mut queued = Vec::new();
        assert!(
            append_verified_contract_metadata_registration_without_state(
                &transaction(None),
                &program,
                &mut queued
            )
            .is_err()
        );
        assert!(queued.is_empty());
        append_verified_contract_metadata_registration_without_state(
            &transaction(Some(&address)),
            &program,
            &mut queued,
        )
        .unwrap();
        let expected = ContractArtifactId::new(DataSpaceId::new(u64::MAX), hash);
        assert_eq!(queued.len(), 2);
        assert!(queued_contract_bytes_match(&queued, &expected, &program));
        assert!(queued_manifest_matches(&queued, &expected, &manifest));
    }

    #[test]
    fn raw_artifact_routing_requires_explicit_immutable_root_scope() {
        let (authority, pair) = gen_account_in("wonderland");
        let tx = TransactionBuilder::new(
            overlay_test_network_id(b"scope-routing"),
            authority,
            test_fee_payment(),
        )
        .with_instructions([Log::new(
            iroha_logger::Level::INFO,
            "scope routing".to_owned(),
        )])
        .sign(pair.private_key());
        let hash = Hash::new(b"scope routing artifact");
        let state = State::new(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        assert!(routed_artifact_id(&state.view(), tx.payload(), hash).is_err());
        let state = State::new(
            test_support::with_global_root(crate::state::World::default()),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        assert_eq!(
            routed_artifact_id(&state.view(), tx.payload(), hash).unwrap(),
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, hash)
        );
    }

    #[test]
    fn overlay_appends_manifest_only_when_missing() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        // Build state with a domain/account and optionally pre-seeded manifest
        let (authority_id, kp) = gen_account_in("wonderland");
        let domain: iroha_data_model::domain::Domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        )
        .build(&authority_id);
        let account = build_wonderland_account(&authority_id);
        let world = crate::state::World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query_handle = crate::query::store::LiveQueryStore::start_test();
        let state = State::new_with_chain(
            test_support::with_global_root(world),
            kura,
            query_handle,
            ChainId::from("chain"),
        );
        // Create a minimal contract artifact and attach its verified manifest to tx metadata.
        let (prog, verified_manifest) = minimal_contract_artifact(1);
        let code_hash = verified_manifest
            .code_hash
            .expect("verified manifest code hash");
        let manifest = verified_manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        let mut md = iroha_model_base::metadata::Metadata::default();
        md.insert(
            "contract_entrypoint".parse().expect("metadata key"),
            Json::new("main"),
        );
        md.insert(
            iroha_data_model::smart_contract::manifest::MANIFEST_METADATA_KEY
                .parse::<iroha_model_base::name::Name>()
                .unwrap(),
            Json::new(manifest.clone()),
        );
        let tx = iroha_data_model::transaction::TransactionBuilder::new(
            state.network_id,
            authority_id.clone(),
            test_fee_payment(),
        )
        .with_metadata(md)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog.clone())))
        .sign(kp.private_key());
        let mut cache = IvmCache::new();
        let summary = cache
            .summarize_program(&prog)
            .expect("prepare self-describing contract artifact");
        // Case 1: WSV doesn't have the artifact yet → append both registrations. Exercise the
        // append step directly: dispatching a self-describing artifact also requires a live
        // contract identity, which intentionally cannot exist before its artifact is registered.
        let mut registrations = Vec::new();
        append_verified_contract_metadata_registration(
            &state.view(),
            &tx,
            &summary,
            &prog,
            &mut registrations,
        )
        .expect("append missing contract registrations");
        assert_eq!(
            registrations.len(),
            2,
            "expected bytecode and manifest registration ISIs"
        );
        // Seed only the bytecode into WSV.
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        stx.world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            prog.clone(),
        );
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit registered contract bytecode");
        // Case 2: only the manifest is missing → append exactly its registration.
        let mut registrations = Vec::new();
        append_verified_contract_metadata_registration(
            &state.view(),
            &tx,
            &summary,
            &prog,
            &mut registrations,
        )
        .expect("append missing contract manifest");
        assert_eq!(registrations.len(), 1);
        assert!(
            registrations[0]
                .as_any()
                .downcast_ref::<RegisterSmartContractCode>()
                .is_some(),
            "the sole missing registration must be the manifest"
        );
        // Seed the manifest as well.
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        stx.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest.clone(),
        );
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit registered contract manifest");
        // Case 3: WSV already has both records → append no registration.
        let mut registrations = Vec::new();
        append_verified_contract_metadata_registration(
            &state.view(),
            &tx,
            &summary,
            &prog,
            &mut registrations,
        )
        .expect("skip existing contract registrations");
        assert!(
            registrations.is_empty(),
            "no registration when artifact records exist"
        );
    }
}
/// Validate IVM header policy and return a structured admission error.
pub(crate) fn validate_header_policy(meta: &ivm::ProgramMetadata) -> Result<(), IvmAdmissionError> {
    // Version: every first-release execution profile uses the sole 1.1 header.
    if meta.version_major != 1 || meta.version_minor != 1 {
        return Err(IvmAdmissionError::UnsupportedVersion(
            iroha_data_model::executor::UnsupportedVersionInfo {
                major: meta.version_major,
                minor: meta.version_minor,
            },
        ));
    }
    // Mode feature bits
    let known = ivm::ivm_mode::ZK | ivm::ivm_mode::VECTOR;
    if meta.mode & !known != 0 {
        return Err(IvmAdmissionError::UnsupportedFeatureBits(
            meta.mode & !known,
        ));
    }
    // ABI version: first release supports only v1.
    if meta.abi_version != 1 {
        return Err(IvmAdmissionError::UnsupportedAbiVersion(meta.abi_version));
    }
    // Vector length sanity
    if meta.vector_length != 0 && meta.vector_length > ivm::VECTOR_LENGTH_MAX {
        return Err(IvmAdmissionError::VectorLengthTooLarge(
            iroha_data_model::executor::VectorLengthTooLargeInfo {
                vector_length: meta.vector_length,
                max_allowed: ivm::VECTOR_LENGTH_MAX,
            },
        ));
    }
    if meta.max_cycles == 0 {
        return Err(IvmAdmissionError::MissingMaxCycles);
    }
    Ok(())
}
// (Chunking and limit enforcement driven by caller: see block.rs)
#[cfg(test)]
mod tests {
    use super::test_support::{execution_block, seed_active_contract};
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        Registrable,
        isi::smart_contract_code::RemoveSmartContractBytes,
        prelude::{IvmBytecode, TransactionBuilder},
    };
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::json::Json;
    use iroha_test_samples::gen_account_in;
    fn build_wonderland_account(authority: &AccountId) -> iroha_data_model::account::Account {
        iroha_data_model::account::Account::new(authority.clone()).build(authority)
    }
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("overlay fixture key generation should succeed")
    }
    #[test]
    fn zk_lane_trace_collection_requires_trace_and_zk_mode() {
        let mut vm = ivm::IVM::new(u64::MAX);

        configure_zk_lane_trace_collection(&mut vm, true);
        assert!(!vm.zk_trace_enabled());

        vm.set_zk_mode(true)
            .expect("private lifecycle cleanup succeeds");
        configure_zk_lane_trace_collection(&mut vm, false);
        assert!(!vm.zk_trace_enabled());

        configure_zk_lane_trace_collection(&mut vm, true);
        assert!(vm.zk_trace_enabled());
    }
    include!("overlay_admission_policy_tests.rs");
    #[test]
    fn ivm_proved_axt_only_replay_is_not_dropped() {
        use iroha_data_model::block::BlockHeader;
        use nonzero_ext::nonzero;
        let (descriptor, binding) = ivm::axt::AxtDescriptor::builder()
            .dataspace(iroha_model_base::topology::DataSpaceId::UNIVERSAL)
            .build_with_binding()
            .expect("AXT descriptor");
        let mut completed = ivm::axt::HostAxtState::new(descriptor, binding);
        completed
            .record_proof(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                Some(ivm::axt::ProofBlob {
                    payload: vec![1],
                    expiry_slot: None,
                }),
                None,
            )
            .expect("record AXT proof");
        completed.validate_commit().expect("completed AXT fixture");
        let state = crate::state::State::new_for_testing(
            test_support::with_global_root(crate::state::World::default()),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let overlay = tx_overlay_from_ivm_proved_replay(
            &state.view(),
            IvmProvedReplay {
                queued: Vec::new(),
                completed_axt: vec![completed],
                durable_state_overlay: BTreeMap::new(),
                durable_state_authorizations: BTreeMap::new(),
                access_log: None,
                gas_used: 1,
            },
        );
        assert!(
            !overlay.is_empty(),
            "AXT-only proved replay must not collapse into an empty overlay"
        );
        assert!(overlay.has_durable_state_changes());
        let authority = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut state_tx = block.transaction();
        overlay
            .apply(&mut state_tx, &authority)
            .expect("AXT-only proved replay applies without active fee policy");
        state_tx.apply();
        let envelopes = block.axt_envelopes();
        assert_eq!(envelopes.len(), 1, "verified AXT envelope must persist");
        assert_eq!(envelopes[0].binding.as_bytes(), &binding);
        assert_eq!(envelopes[0].commit_height, 1);
    }
    #[test]
    fn overlay_byte_size_cache_matches_norito_instruction_sum() {
        let instructions: Vec<InstructionBox> = vec![
            iroha_data_model::isi::Log::new(iroha_logger::Level::INFO, "cached-size-a".to_owned())
                .into(),
            iroha_data_model::isi::Log::new(iroha_logger::Level::INFO, "cached-size-b".to_owned())
                .into(),
        ];
        let expected = instructions
            .iter()
            .map(|instruction| NoritoEncode::encode(instruction).len())
            .sum();
        let overlay = TxOverlay::from_instructions(instructions);
        assert_eq!(overlay.byte_size(), expected);
        assert_eq!(overlay.byte_size.get(), Some(&expected));
        assert_eq!(overlay.byte_size(), expected);
    }
    #[test]
    fn overlay_rejects_ivm_without_fee_payment_gas_bound() {
        use iroha_data_model::{
            domain::Domain,
            prelude::{AccountId, IvmBytecode, TransactionBuilder},
        };
        let (program, _header_len, _meta) = sample_program();
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        let domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&authority);
        let account = build_wonderland_account(&authority);
        let world = crate::state::World::with([domain], [account], []);
        let state = test_support::state_after_genesis_with_chain(world, ChainId::from("chain"));
        let tx = TransactionBuilder::new(
            state.network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(kp.private_key());
        let err = build_overlay_for_transaction(&tx, &*execution_block(&state))
            .expect_err("overlay should require a typed fee-payment gas bound");
        assert!(matches!(
            err,
            OverlayBuildError::GasLimit(msg) if msg.contains("missing gas limit in fee payment intent")
        ));
    }
    #[test]
    fn overlay_rejects_ivm_proved_without_complete_execution_relation() {
        use iroha_data_model::{
            domain::Domain,
            prelude::{AccountId, IvmBytecode, TransactionBuilder},
            transaction::{Executable, IvmProved},
        };
        let (program, _header_len, _meta) = sample_program_zk_mode();
        let bytecode = IvmBytecode::from_compiled(program);
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        let domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&authority);
        let account = build_wonderland_account(&authority);
        let mut world = crate::state::World::with([domain], [account], []);
        let contract_address = bind_sample_raw_contract(&mut world, &authority, &bytecode, 101);
        let state = test_support::state_after_genesis(world);
        let mut metadata = iroha_model_base::metadata::Metadata::default();
        bind_sample_raw_metadata(&mut metadata, &contract_address);
        let tx = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::IvmProved(IvmProved {
                bytecode,
                overlay: Vec::<InstructionBox>::new().into(),
                events_commitment: Hash::new(b"events"),
                gas_policy_commitment: Hash::new(b"gas-policy"),
            }))
            .sign(kp.private_key());
        let error = build_overlay_for_transaction(&tx, &*execution_block(&state))
            .expect_err("binding-only proofs cannot establish IVM execution");
        assert!(matches!(
            error,
            OverlayBuildError::ZkProof(message)
                if message == "IvmProved requires the complete native STARK execution relation"
        ));
    }
    #[test]
    fn ivm_proved_replay_rejects_nested_or_mismatched_authorization_context() {
        let (authority, _) = gen_account_in("wonderland");
        let (other_authority, _) = gen_account_in("wonderland");
        let root_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            1,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive root contract address");
        let child_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            2,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive child contract address");
        let root_authorization = ContractEntrypointAuthorizationSnapshot::new(
            authority.clone(),
            "run".to_owned(),
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "RootPermission".parse().unwrap(),
            ),
            &code::BoundContractIdentity {
                lifecycle_revision: 1,
                contract_address: root_address.clone(),
                contract_alias: None,
                contract_alias_binding: None,
                code_hash: Hash::new(b"proved-root-code"),
            },
        );
        let root_context = crate::executor::ContractRuntimeExecutionContext {
            contract_address: root_address.clone(),
            contract_subject: root_address.subject_id(),
            contract_alias: None,
            entrypoint: "run".to_owned(),
        };
        let instruction: InstructionBox = iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "proved authorization invariant".to_owned(),
        )
        .into();
        let queued = |
            effect_authority: AccountId,
            contract_runtime_context: Option<crate::executor::ContractRuntimeExecutionContext>,
            entrypoint_authorization: Option<ContractEntrypointAuthorizationSnapshot>,
        | crate::smartcontracts::ivm::host::QueuedEffect {
            payload: crate::smartcontracts::ivm::host::QueuedEffectPayload::Instruction(instruction.clone()),
            authority: effect_authority,
            contract_runtime_context,
            entrypoint_authorization,
        };
        let exact = queued(
            root_context.contract_subject.clone(),
            Some(root_context.clone()),
            Some(root_authorization.clone()),
        );
        validate_ivm_proved_queued_authorization(
            &[exact],
            &authority,
            &root_context,
            &root_authorization,
        )
        .expect("exact top-level proved authorization must be retained");
        let child_authorization = ContractEntrypointAuthorizationSnapshot::new(
            root_address.subject_id(),
            "write".to_owned(),
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "ChildPermission".parse().unwrap(),
            ),
            &code::BoundContractIdentity {
                lifecycle_revision: 1,
                contract_address: child_address.clone(),
                contract_alias: None,
                contract_alias_binding: None,
                code_hash: Hash::new(b"proved-child-code"),
            },
        )
        .with_parent(Some(root_authorization.clone()));
        let child_context = crate::executor::ContractRuntimeExecutionContext {
            contract_subject: child_address.subject_id(),
            contract_address: child_address,
            contract_alias: None,
            entrypoint: "write".to_owned(),
        };
        let adversarial = [
            (
                "nested authorization",
                queued(
                    root_address.subject_id(),
                    Some(child_context),
                    Some(child_authorization),
                ),
            ),
            (
                "changed effect authority",
                queued(
                    other_authority,
                    Some(root_context.clone()),
                    Some(root_authorization.clone()),
                ),
            ),
            (
                "missing runtime context",
                queued(
                    root_context.contract_subject.clone(),
                    None,
                    Some(root_authorization.clone()),
                ),
            ),
            (
                "missing authorization snapshot",
                queued(
                    root_context.contract_subject.clone(),
                    Some(root_context.clone()),
                    None,
                ),
            ),
        ];
        for (label, queued) in adversarial {
            let error = validate_ivm_proved_queued_authorization(
                &[queued],
                &authority,
                &root_context,
                &root_authorization,
            )
            .expect_err(label);
            assert!(
                matches!(
                    &error,
                    OverlayBuildError::ZkProof(message)
                        if message.contains("only exact top-level authorization")
                            && message.contains("nested or mismatched contexts are forbidden")
                ),
                "unexpected {label} error: {error:?}"
            );
        }
        let nested_root = root_authorization
            .clone()
            .with_parent(Some(root_authorization.clone()));
        validate_ivm_proved_queued_authorization(&[], &authority, &root_context, &nested_root)
            .expect_err("proved replay root authorization must itself be top-level");
    }
    #[test]
    fn proved_contract_permission_denies_before_argument_decode_or_proof_validation() {
        let compiler = kotodama_lang::compiler::Compiler::new_with_options(
            kotodama_lang::compiler::CompilerOptions {
                force_zk: true,
                max_cycles: 10_000,
                ..kotodama_lang::compiler::CompilerOptions::default()
            },
        );
        let (program, manifest) = compiler
            .compile_source_with_manifest(
                r"
seiyaku ProtectedProved { permission CanWriteProved;
  kotoage fn write(int value) authorize(CanWriteProved) {
    let _value = value;
  }
}
",
            )
            .expect("compile protected ZK-mode contract");
        let (authority, keypair) = gen_account_in("wonderland");
        let domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            93,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("derive protected proved-call contract address");
        let code_hash = manifest.code_hash.expect("verified code hash");
        let mut world = crate::state::World::with([domain], [account], []);
        world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            program.clone(),
        );
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest,
        );
        seed_active_contract(&mut world, &contract_address, code_hash, &authority);
        let mut state = test_support::state_after_genesis_with_chain(
            world,
            ChainId::from("protected-proved-overlay"),
        );
        state
            .edit_zk_for_testing(|zk| zk.pipa_r.enabled = true)
            .expect("fixture ZK settings install");
        let mut metadata = Metadata::default();
        metadata.insert(
            "contract_entrypoint".parse().expect("metadata key"),
            Json::new("write"),
        );
        metadata.insert(
            "contract_payload".parse().expect("metadata key"),
            Json::from(norito::json!({ "value": "9" })),
        );
        metadata.insert(
            "contract_address".parse().expect("metadata key"),
            Json::new(contract_address.to_string()),
        );
        let transaction = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::IvmProved(
                iroha_data_model::transaction::IvmProved {
                    bytecode: IvmBytecode::from_compiled(program),
                    overlay: Vec::<InstructionBox>::new().into(),
                    events_commitment: Hash::new(b"unverified-events"),
                    gas_policy_commitment: Hash::new(b"unverified-gas"),
                },
            ))
            .sign(keypair.private_key());
        ivm::reset_argument_record_decode_count();
        let error = build_overlay_for_transaction(&transaction, &*execution_block(&state))
            .expect_err("missing permission must reject before inspecting the proof");
        assert!(
            matches!(
                &error,
                OverlayBuildError::ContractCall(message)
                    if message.contains("CanWriteProved")
            ),
            "permission denial must win over proof-validation errors: {error:?}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "denied proved-call arguments must remain undecoded"
        );
    }
    fn sample_program() -> (Vec<u8>, usize, ivm::ProgramMetadata) {
        let meta = ivm::ProgramMetadata {
            max_cycles: 4,
            version_minor: 1,
            ..ivm::ProgramMetadata::default()
        };
        let mut program = meta.encode();
        program.extend_from_slice(&sample_contract_interface(0).encode_section());
        program.extend_from_slice(&crate::ivm_test_support::unit_return());
        let parsed = ivm::ProgramMetadata::parse(&program).expect("parse sample program");
        (program, parsed.header_len, parsed.metadata)
    }
    fn sample_program_zk_mode() -> (Vec<u8>, usize, ivm::ProgramMetadata) {
        let meta = ivm::ProgramMetadata {
            max_cycles: 4,
            version_minor: 1,
            mode: ivm::ivm_mode::ZK,
            ..ivm::ProgramMetadata::default()
        };
        let mut program = meta.encode();
        program.extend_from_slice(
            &sample_contract_interface(ivm::CONTRACT_FEATURE_BIT_ZK).encode_section(),
        );
        program.extend_from_slice(&crate::ivm_test_support::unit_return());
        let parsed = ivm::ProgramMetadata::parse(&program).expect("parse sample program");
        (program, parsed.header_len, parsed.metadata)
    }
    fn sample_contract_interface(features_bitmap: u64) -> ivm::EmbeddedContractInterfaceV1 {
        ivm::EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: vec![iroha_data_model::smart_contract::manifest::ContractPermissionDescriptorV1 {name:"CanInvokeOverlayFixture".parse().unwrap(),scope:iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1::Instance}],
            callables: vec![crate::ivm_test_support::unit_callable(0)],
            seiyaku_name: "OverlayFixture".to_owned(),
            compiler_fingerprint: "iroha-core-overlay-tests".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
                name: "main".to_owned(),
                kind: iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission("CanInvokeOverlayFixture".parse().unwrap()),
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        }
    }
    fn bind_sample_raw_contract(
        world: &mut crate::state::World,
        authority: &AccountId,
        bytecode: &IvmBytecode,
        nonce: u64,
    ) -> ContractAddress {
        let verified = ivm::verify_contract_artifact(bytecode.as_ref())
            .expect("sample raw contract artifact must verify");
        let code_hash = verified.code_hash;
        let address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            authority,
            nonce,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive sample raw contract address");
        world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            bytecode.as_ref().to_vec(),
        );
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            verified.manifest,
        );
        seed_active_contract(world, &address, code_hash, authority);
        let mut permissions = iroha_data_model::permission::Permissions::new();
        assert!(
            permissions.insert(
                iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                    contract: address.clone(),
                    permission: "CanInvokeOverlayFixture".parse().unwrap(),
                }
                .into()
            )
        );
        world
            .account_permissions_mut_for_testing()
            .insert(authority.clone(), permissions);
        address
    }
    fn bind_sample_raw_metadata(metadata: &mut Metadata, address: &ContractAddress) {
        metadata.insert(
            "contract_entrypoint".parse().expect("metadata key"),
            Json::new("main"),
        );
        metadata.insert(
            "contract_address".parse().expect("metadata key"),
            Json::new(address.to_string()),
        );
    }
    fn norito_blob<T: norito::NoritoSerialize>(value: &T) -> Vec<u8> {
        norito::to_bytes(value).expect("norito encode payload with header")
    }
    fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
        v.extend_from_slice(&type_id.to_be_bytes());
        v.push(1u8);
        let payload_len =
            u32::try_from(payload.len()).expect("payload length must fit into u32 for TLV");
        v.extend_from_slice(&payload_len.to_be_bytes());
        v.extend_from_slice(payload);
        let hash = Hash::new(payload);
        v.extend_from_slice(hash.as_ref());
        v
    }
    fn program_with_literals(code: &[u8], literals: &[Vec<u8>]) -> Vec<u8> {
        let meta = ivm::ProgramMetadata {
            max_cycles: 10_000,
            ..Default::default()
        };
        let descriptor_bytes = literals
            .len()
            .checked_mul(core::mem::size_of::<u64>())
            .expect("literal descriptor table length fits");
        let data_offset = 16_usize
            .checked_add(descriptor_bytes)
            .expect("literal data offset fits");
        let data_len = literals
            .iter()
            .try_fold(0_usize, |len, literal| len.checked_add(literal.len()))
            .expect("literal data length fits");
        let post_pad = (4 - ((16 + descriptor_bytes + data_len) % 4)) % 4;
        let mut program = meta.encode();
        program.extend_from_slice(b"LTLB");
        program.extend_from_slice(
            &u32::try_from(literals.len())
                .expect("literal count fits")
                .to_le_bytes(),
        );
        program.extend_from_slice(
            &u32::try_from(post_pad)
                .expect("literal padding fits")
                .to_le_bytes(),
        );
        program.extend_from_slice(
            &u32::try_from(data_len)
                .expect("literal data length fits into u32")
                .to_le_bytes(),
        );
        let mut relative_offset = data_offset;
        for literal in literals {
            let descriptor = ivm::encode_literal_descriptor(
                ivm::LiteralKindV1::PointerTlv,
                u64::try_from(relative_offset).expect("literal offset fits in u64"),
            )
            .expect("literal descriptor offset is representable");
            program.extend_from_slice(&descriptor.to_le_bytes());
            relative_offset = relative_offset
                .checked_add(literal.len())
                .expect("literal offset fits");
        }
        for literal in literals {
            program.extend_from_slice(literal);
        }
        program.extend(std::iter::repeat_n(0_u8, post_pad));
        program.extend_from_slice(code);
        program
    }
    #[test]
    fn overlay_rejects_manifest_abi_mismatch_before_execution() {
        use iroha_data_model::prelude::{AccountId, TransactionBuilder};
        use iroha_model_base::metadata::Metadata;
        use iroha_primitives::json::Json;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, header_len, meta) = sample_program();
        let (code_hash, abi_hash) = super::compute_program_hashes(&meta, header_len, &program);
        let contract_address: ContractAddress =
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse()
                .expect("contract address");
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        // Inject a manifest with a mismatched abi_hash into WSV plus the instance binding.
        let mut world = crate::state::World::default();
        seed_active_contract(&mut world, &contract_address, code_hash, &authority);
        let mut wrong_bytes = [0u8; 32];
        wrong_bytes.copy_from_slice(abi_hash.as_ref());
        wrong_bytes[0] ^= 0xFF;
        let wrong_abi_hash = Hash::prehashed(wrong_bytes);
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            ContractManifest {
                events: Vec::new(),
                enum_types: Vec::new(),
                permissions: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(code_hash),
                abi_hash: Some(wrong_abi_hash),
                compiler_fingerprint: None,
                features_bitmap: None,
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            }
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest"),
        );
        let state = test_support::state_after_genesis(world);
        // Build a contract-call style transaction that references the instance.
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("contract_address").expect("static name"),
            Json::new(contract_address.to_string()),
        );
        let tx = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(
                iroha_data_model::prelude::IvmBytecode::from_compiled(program),
            ))
            .sign(kp.private_key());
        let res = build_overlay_for_transaction(&tx, &*execution_block(&state));
        assert!(matches!(
            res,
            Err(OverlayBuildError::HeaderPolicy(
                IvmAdmissionError::ManifestAbiHashMismatch(info)
            )) if info.expected == wrong_abi_hash && info.actual == abi_hash
        ));
    }
    #[test]
    fn raw_and_proved_ivm_reject_spoofed_contract_alias_metadata() {
        use iroha_data_model::{
            prelude::{AccountId, IvmBytecode, TransactionBuilder},
            transaction::IvmProved,
        };
        use iroha_model_base::metadata::Metadata;
        use iroha_primitives::json::Json;
        let compiler = kotodama_lang::compiler::Compiler::new_with_options(
            kotodama_lang::compiler::CompilerOptions {
                force_zk: true,
                max_cycles: 10_000,
                ..kotodama_lang::compiler::CompilerOptions::default()
            },
        );
        let (program, manifest) = compiler
            .compile_source_with_manifest(
                r"
seiyaku AliasBoundArguments { permission CanInvokeOverlayFixture;
  kotoage fn main(int value) authorize(CanInvokeOverlayFixture) {
    let _value = value;
  }
}
",
            )
            .expect("compile parameterized ZK alias-binding fixture");
        let parsed =
            ivm::ProgramMetadata::parse(&program).expect("parse parameterized alias fixture");
        let header_len = parsed.header_len;
        let meta = parsed.metadata;
        let (code_hash, abi_hash) = super::compute_program_hashes(&meta, header_len, &program);
        let bytecode = IvmBytecode::from_compiled(program);
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            9,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let active_alias: iroha_data_model::smart_contract::ContractAlias =
            "router::universal".parse().expect("active alias");
        let spoofed_alias = "benefit::universal";
        let domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let mut world = crate::state::World::with([domain], [account], []);
        seed_active_contract(&mut world, &contract_address, code_hash, &authority);
        world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            bytecode.as_ref().to_vec(),
        );
        assert_eq!(manifest.abi_hash, Some(abi_hash));
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest,
        );
        world
            .bind_contract_alias(&contract_address, active_alias.clone(), None, None, 0)
            .expect("bind canonical alias");
        let mut permissions = iroha_data_model::permission::Permissions::new();
        assert!(
            permissions.insert(iroha_data_model::permission::Permission::new(
                "CanInvokeOverlayFixture".to_owned(),
                Json::new(()),
            ))
        );
        world
            .account_permissions_mut_for_testing()
            .insert(authority.clone(), permissions);
        let mut state = test_support::state_after_genesis(world);
        state
            .edit_zk_for_testing(|zk| zk.pipa_r.enabled = true)
            .expect("fixture ZK settings install");
        let summary = IvmCache::new()
            .summarize_program(bytecode.as_ref())
            .expect("program summary");
        let assert_spoofed_alias_denied_without_decode = |label: &str, executable: Executable| {
            let mut metadata = Metadata::default();
            metadata.insert(
                "contract_address".parse().expect("metadata key"),
                Json::new(contract_address.to_string()),
            );
            metadata.insert(
                "contract_alias".parse().expect("metadata key"),
                Json::new(spoofed_alias),
            );
            metadata.insert(
                "contract_entrypoint".parse().expect("metadata key"),
                Json::new("main"),
            );
            metadata.insert(
                "contract_payload".parse().expect("metadata key"),
                Json::from(norito::json!({ "value": "7" })),
            );
            let tx =
                TransactionBuilder::new(state.network_id, authority.clone(), test_fee_payment())
                    .with_metadata(metadata)
                    .with_executable(executable)
                    .sign(kp.private_key());
            ivm::reset_argument_record_decode_count();
            let error = build_overlay_for_transaction(&tx, &*execution_block(&state))
                .expect_err("spoofed alias must fail before VM/proof execution");
            assert!(
                matches!(
                    error,
                    OverlayBuildError::ContractCall(ref message)
                        if message.contains("contract alias")
                            && message.contains(spoofed_alias)
                            && message.contains("is not bound in live state")
                ),
                "unexpected {label} spoofed-alias error: {error:?}"
            );
            assert_eq!(
                ivm::argument_record_decode_count(),
                0,
                "{label} spoofed-alias denial must precede argument decoding"
            );
            let mut canonical_metadata = Metadata::default();
            canonical_metadata.insert(
                "contract_address".parse().expect("metadata key"),
                Json::new(contract_address.to_string()),
            );
            canonical_metadata.insert(
                "contract_alias".parse().expect("metadata key"),
                Json::new(active_alias.to_string()),
            );
            canonical_metadata.insert(
                "contract_entrypoint".parse().expect("metadata key"),
                Json::new("main"),
            );
            canonical_metadata.insert(
                "contract_payload".parse().expect("metadata key"),
                Json::from(norito::json!({ "value": "7" })),
            );
            let canonical_tx =
                TransactionBuilder::new(state.network_id, authority.clone(), test_fee_payment())
                    .with_metadata(canonical_metadata)
                    .with_executable(tx.instructions().clone())
                    .sign(kp.private_key());
            ivm::reset_argument_record_decode_count();
            validate_contract_binding(&state.view(), canonical_tx.payload(), &summary)
                .expect("canonical alias must satisfy the live binding");
            authorize_and_prepare_raw_contract_dispatch(
                &state.view(),
                canonical_tx.payload(),
                &summary,
                TEST_GAS_LIMIT,
            )
            .expect("canonical alias control must reach argument preparation");
            assert_eq!(
                ivm::argument_record_decode_count(),
                1,
                "{label} canonical-alias control must prove the decoder is reachable"
            );
        };
        assert_spoofed_alias_denied_without_decode("raw IVM", Executable::Ivm(bytecode.clone()));
        assert_spoofed_alias_denied_without_decode(
            "proved IVM",
            Executable::IvmProved(IvmProved {
                bytecode,
                overlay: Vec::<InstructionBox>::new().into(),
                events_commitment: Hash::new(b"events"),
                gas_policy_commitment: Hash::new(b"gas"),
            }),
        );
    }
    #[test]
    fn raw_and_proved_ivm_reject_header_substitution_for_bound_contract() {
        use iroha_data_model::{
            prelude::{AccountId, IvmBytecode, TransactionBuilder},
            transaction::IvmProved,
        };
        use iroha_model_base::metadata::Metadata;
        use iroha_primitives::json::Json;
        use std::sync::Arc;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (stored_program, header_len, meta) = sample_program_zk_mode();
        let (code_hash, abi_hash) =
            super::compute_program_hashes(&meta, header_len, &stored_program);
        let stored_bytecode = IvmBytecode::from_compiled(stored_program.clone());
        let mut substituted_program = stored_program;
        substituted_program[8] ^= 0x01;
        let substituted_bytecode = IvmBytecode::from_compiled(substituted_program);
        let substituted_summary = IvmCache::new()
            .summarize_program(substituted_bytecode.as_ref())
            .expect("substituted program summary");
        assert_ne!(
            substituted_summary.code_hash, code_hash,
            "the canonical contract hash must authenticate the execution header"
        );
        assert_ne!(
            substituted_bytecode.as_ref(),
            stored_bytecode.as_ref(),
            "the negative control must alter the excluded IVM header"
        );
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            10,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let mut world = crate::state::World::default();
        seed_active_contract(&mut world, &contract_address, code_hash, &authority);
        world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            stored_bytecode.as_ref().to_vec(),
        );
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            ContractManifest {
                events: Vec::new(),
                enum_types: Vec::new(),
                permissions: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(code_hash),
                abi_hash: Some(abi_hash),
                compiler_fingerprint: None,
                features_bitmap: None,
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            }
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest"),
        );
        let kura = Arc::new(crate::kura::Kura::blank_kura_for_testing());
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = crate::state::State::new_for_testing(
            test_support::with_global_root(world),
            Arc::clone(&kura),
            query,
        );
        let executable_variants = [
            Executable::Ivm(substituted_bytecode.clone()),
            Executable::IvmProved(IvmProved {
                bytecode: substituted_bytecode,
                overlay: Vec::<InstructionBox>::new().into(),
                events_commitment: Hash::new(b"events"),
                gas_policy_commitment: Hash::new(b"gas"),
            }),
        ];
        for executable in executable_variants {
            let mut metadata = Metadata::default();
            metadata.insert(
                "contract_address".parse().expect("metadata key"),
                Json::new(contract_address.to_string()),
            );
            let tx =
                TransactionBuilder::new(state.network_id, authority.clone(), test_fee_payment())
                    .with_metadata(metadata)
                    .with_executable(executable)
                    .sign(kp.private_key());
            let error =
                validate_contract_binding(&state.view(), tx.payload(), &substituted_summary)
                    .expect_err("header-substituted artifact must fail before VM/proof execution");
            assert!(
                matches!(
                    error,
                    OverlayBuildError::ContractCall(ref message)
                        if message.contains("is bound to code")
                            && message.contains("not executing code")
                ),
                "unexpected bytecode-binding error: {error:?}"
            );
        }
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn overlay_rejects_axt_proof_without_policy_entry() {
        use iroha_data_model::{
            nexus::AxtRejectReason,
            prelude::{AccountId, IvmBytecode, TransactionBuilder},
            transaction::Executable,
        };
        use iroha_model_base::topology::DataSpaceId;
        use ivm::{axt, encoding, instruction, pointer_abi::PointerType, syscalls as ivm_sys};
        use std::sync::Arc;
        let dsid = DataSpaceId::new(7);
        let descriptor = axt::AxtDescriptor {
            dsids: vec![dsid],
            touches: Vec::new(),
        };
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        let descriptor_tlv = make_tlv(PointerType::AxtDescriptor as u16, &norito_blob(&descriptor));
        let dsid_tlv = make_tlv(PointerType::DataSpaceId as u16, &norito_blob(&dsid));
        let literals = [descriptor_tlv, dsid_tlv];
        let mut code = Vec::new();
        let mut emit = |word: u32| code.extend_from_slice(&word.to_le_bytes());
        for (index, register) in [40_u8, 41].into_iter().enumerate() {
            emit(encoding::wide::encode_literal(
                instruction::wide::memory::LDLIT,
                10,
                u16::try_from(index).expect("literal index fits in u16"),
            ));
            emit(encoding::wide::encode_sys(
                instruction::wide::system::SCALL,
                u8::try_from(ivm_sys::SYSCALL_INPUT_PUBLISH_TLV).expect("syscall fits in u8"),
            ));
            emit(encoding::wide::encode_rr(
                instruction::wide::arithmetic::ADD,
                register,
                10,
                0,
            ));
        }
        emit(encoding::wide::encode_rr(
            instruction::wide::arithmetic::ADD,
            10,
            40,
            0,
        ));
        emit(encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_AXT_BEGIN).expect("syscall fits in u8"),
        ));
        emit(encoding::wide::encode_rr(
            instruction::wide::arithmetic::ADD,
            10,
            41,
            0,
        ));
        emit(encoding::wide::encode_rr(
            instruction::wide::arithmetic::ADD,
            11,
            0,
            0,
        ));
        emit(encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_AXT_TOUCH).expect("syscall fits in u8"),
        ));
        emit(encoding::wide::encode_rr(
            instruction::wide::arithmetic::ADD,
            10,
            41,
            0,
        ));
        emit(encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_VERIFY_DS_PROOF).expect("syscall fits in u8"),
        ));
        emit(encoding::wide::encode_halt());
        let program = program_with_literals(&code, &literals);
        let kura = Arc::new(crate::kura::Kura::blank_kura_for_testing());
        let query = crate::query::store::LiveQueryStore::start_test();
        let world = crate::state::World::default();
        let state = crate::state::State::new_for_testing(
            test_support::with_global_root(world),
            Arc::clone(&kura),
            query,
        );
        assert!(
            state.view().axt_policy_snapshot().entries.is_empty(),
            "expected empty AXT policy snapshot"
        );
        let metadata = iroha_model_base::metadata::Metadata::default();
        let tx = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
            .sign(kp.private_key());
        let header = iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::new(1).expect("non-zero test block height"),
            None,
            None,
            1,
            0,
        );
        let block = state.block(header);
        let err = build_overlay_for_transaction(&tx, &block)
            .expect_err("overlay should reject AXT proof without policy entry");
        match err {
            OverlayBuildError::AxtReject(ctx) => {
                assert_eq!(ctx.reason, AxtRejectReason::MissingPolicy);
                assert_eq!(ctx.dataspace, Some(dsid));
                assert_eq!(ctx.lane, None);
            }
            other => panic!("expected AxtReject, got {other:?}"),
        }
    }
    #[test]
    fn overlay_rejects_contract_binding_code_hash_mismatch() {
        use iroha_data_model::prelude::{AccountId, TransactionBuilder};
        use iroha_model_base::metadata::Metadata;
        use iroha_primitives::json::Json;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, header_len, meta) = sample_program();
        let (code_hash, abi_hash) = super::compute_program_hashes(&meta, header_len, &program);
        let contract_address: ContractAddress =
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse()
                .expect("contract address");
        let wrong_binding = Hash::new(b"other-binding");
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        // Insert a manifest for the actual code, but bind the namespace to a different code hash.
        let mut world = crate::state::World::default();
        seed_active_contract(&mut world, &contract_address, wrong_binding, &authority);
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            ContractManifest {
                events: Vec::new(),
                enum_types: Vec::new(),
                permissions: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(code_hash),
                abi_hash: Some(abi_hash),
                compiler_fingerprint: None,
                features_bitmap: None,
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            }
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest"),
        );
        let state = test_support::state_after_genesis(world);
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("contract_address").expect("static name"),
            Json::new(contract_address.to_string()),
        );
        let tx = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(
                iroha_data_model::prelude::IvmBytecode::from_compiled(program),
            ))
            .sign(kp.private_key());
        let res = build_overlay_for_transaction(&tx, &*execution_block(&state));
        assert!(
            matches!(
                res,
                Err(OverlayBuildError::ContractCall(ref message))
                    if message.contains(&wrong_binding.to_string())
                        && message.contains(&code_hash.to_string())
                        && message.contains("is bound to code")
            ),
            "the live contract identity must reject the mismatched binding first: {res:?}"
        );
    }
    #[test]
    fn overlay_requires_manifest_for_bound_instance() {
        use iroha_data_model::prelude::{AccountId, TransactionBuilder};
        use iroha_model_base::metadata::Metadata;
        use iroha_primitives::json::Json;
        let (program, header_len, meta) = sample_program();
        let (code_hash, _abi_hash) = super::compute_program_hashes(&meta, header_len, &program);
        let contract_address: ContractAddress =
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse()
                .expect("contract address");
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        // Bind namespace to code hash but do not seed manifest in WSV.
        let mut world = crate::state::World::default();
        seed_active_contract(&mut world, &contract_address, code_hash, &authority);
        let state = test_support::state_after_genesis(world);
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("contract_address").expect("static name"),
            Json::new(contract_address.to_string()),
        );
        let tx = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(
                iroha_data_model::prelude::IvmBytecode::from_compiled(program),
            ))
            .sign(kp.private_key());
        let res = build_overlay_for_transaction(&tx, &*execution_block(&state));
        assert!(matches!(
            res,
            Err(OverlayBuildError::HeaderPolicy(
                IvmAdmissionError::BytecodeDecodingFailed(msg)
            )) if msg.contains("manifest missing")
        ));
    }
    #[test]
    fn overlay_requires_manifest_abi_for_bound_instance() {
        use iroha_data_model::prelude::{AccountId, TransactionBuilder};
        use iroha_model_base::metadata::Metadata;
        use iroha_primitives::json::Json;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, header_len, meta) = sample_program();
        let (code_hash, _abi_hash) = super::compute_program_hashes(&meta, header_len, &program);
        let contract_address: ContractAddress =
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse()
                .expect("contract address");
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        let mut world = crate::state::World::default();
        seed_active_contract(&mut world, &contract_address, code_hash, &authority);
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            ContractManifest {
                events: Vec::new(),
                enum_types: Vec::new(),
                permissions: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(code_hash),
                abi_hash: None,
                compiler_fingerprint: None,
                features_bitmap: None,
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            }
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest"),
        );
        let state = test_support::state_after_genesis(world);
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("contract_address").expect("static name"),
            Json::new(contract_address.to_string()),
        );
        let tx = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(
                iroha_data_model::prelude::IvmBytecode::from_compiled(program),
            ))
            .sign(kp.private_key());
        let res = build_overlay_for_transaction(&tx, &*execution_block(&state));
        assert!(matches!(
            res,
            Err(OverlayBuildError::HeaderPolicy(
                IvmAdmissionError::ManifestAbiHashMissing
            ))
        ));
        // Ensure ABI mismatch still reports the structured error when abi_hash is present.
        let mut world = crate::state::World::default();
        seed_active_contract(&mut world, &contract_address, code_hash, tx.authority());
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            ContractManifest {
                events: Vec::new(),
                enum_types: Vec::new(),
                permissions: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(code_hash),
                abi_hash: Some(Hash::prehashed([0u8; 32])),
                compiler_fingerprint: None,
                features_bitmap: None,
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            }
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest"),
        );
        let state = test_support::state_after_genesis(world);
        let res = build_overlay_for_transaction(&tx, &*execution_block(&state));
        assert!(matches!(
            res,
            Err(OverlayBuildError::HeaderPolicy(
                IvmAdmissionError::ManifestAbiHashMismatch(_)
            ))
        ));
    }
    #[test]
    fn pre_execution_policy_allows_scallx_opcode() {
        use iroha_data_model::prelude::{AccountId, TransactionBuilder};
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        let domain: iroha_data_model::domain::Domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let world = crate::state::World::with([domain], [account], []);
        let state = test_support::state_after_genesis_with_chain(world, ChainId::from("chain"));
        let meta = ivm::ProgramMetadata {
            max_cycles: 8,
            ..ivm::ProgramMetadata::default()
        };
        let mut program = meta.encode();
        program.extend_from_slice(
            &ivm::encoding::wide::encode_syscallx(ivm::syscalls::SYSCALL_DEBUG_PRINT).to_le_bytes(),
        );
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let metadata = iroha_model_base::metadata::Metadata::default();
        let tx = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(
                iroha_data_model::prelude::IvmBytecode::from_compiled(program),
            ))
            .sign(kp.private_key());
        let res = build_overlay_for_transaction(&tx, &*execution_block(&state));
        assert!(res.is_ok(), "SCALLX is part of the first-release ABI");
    }
    #[test]
    fn pre_execution_policy_ignores_literal_table() {
        use iroha_data_model::prelude::{AccountId, TransactionBuilder};
        let kp = checked_keypair();
        let authority = AccountId::new(kp.public_key().clone());
        let domain: iroha_data_model::domain::Domain = iroha_data_model::domain::Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        )
        .build(&authority);
        let account = build_wonderland_account(&authority);
        let world = crate::state::World::with([domain], [account], []);
        let state = test_support::state_after_genesis_with_chain(world, ChainId::from("chain"));
        // Authenticated pointer literal with a 0x62 payload byte to ensure
        // pre-execution opcode scans skip the complete literal section.
        let literal = make_tlv(
            ivm::pointer_abi::PointerType::NoritoBytes as u16,
            &norito_blob(&vec![0x62_u8]),
        );
        let program = program_with_literals(
            &ivm::encoding::wide::encode_halt().to_le_bytes(),
            &[literal],
        );
        let metadata = iroha_model_base::metadata::Metadata::default();
        let tx = TransactionBuilder::new(state.network_id, authority, test_fee_payment())
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(
                iroha_data_model::prelude::IvmBytecode::from_compiled(program),
            ))
            .sign(kp.private_key());
        let res = build_overlay_for_transaction(&tx, &*execution_block(&state));
        assert!(res.is_ok(), "literal table should not affect opcode scan");
    }
    #[test]
    fn redundant_contract_ops_are_pruned() {
        use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
        use iroha_data_model::smart_contract::manifest::ContractManifest;
        use std::sync::Arc;
        let (program, header_len, meta) = sample_program();
        let (code_hash, abi_hash) = super::compute_program_hashes(&meta, header_len, &program);
        let mut world = crate::state::World::default();
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: Some(abi_hash),
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        };
        world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest.clone(),
        );
        world.contract_code.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            program.clone(),
        );
        let contract_address: ContractAddress =
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse()
                .expect("contract address");
        seed_active_contract(
            &mut world,
            &contract_address,
            code_hash,
            &contract_address.subject_id(),
        );
        let kura = Arc::new(Kura::blank_kura_for_testing());
        let query = LiveQueryStore::start_test();
        let state = State::new_for_testing(
            test_support::with_global_root(world),
            Arc::clone(&kura),
            query,
        );
        let mut queued: Vec<InstructionBox> = vec![
            RegisterSmartContractBytes {
                artifact_id: ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
                code: program.clone(),
            }
            .into(),
            RegisterSmartContractCode {
                artifact_id: ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
                manifest: manifest.clone(),
            }
            .into(),
            ActivateContractInstance {
                contract_address,
                expected_revision: 1,
                code_hash,
            }
            .into(),
            RemoveSmartContractBytes {
                artifact_id: ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
                reason: None,
            }
            .into(),
        ];
        prune_redundant_contract_ops(&state.view(), &mut queued);
        assert_eq!(queued.len(), 1);
        assert!(
            queued[0]
                .as_any()
                .downcast_ref::<RemoveSmartContractBytes>()
                .is_some()
        );
    }
    #[test]
    fn sample_smart_contract_overlay_executes() {
        use iroha_data_model::{prelude::TransactionBuilder, transaction::Executable};
        use iroha_model_base::metadata::Metadata;
        use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
        use std::sync::Arc;
        let metadata = Metadata::default();
        let (program, _, _) = sample_program();
        let tx = TransactionBuilder::new(
            overlay_test_network_id(b"sample-smart-contract-overlay"),
            ALICE_ID.clone(),
            test_fee_payment(),
        )
        .with_metadata(metadata)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(ALICE_KEYPAIR.private_key());
        let accounts = vec![ALICE_ID.clone()];
        let bytes: Vec<u8> = match tx.instructions() {
            Executable::Ivm(code) => code.as_ref().to_vec(),
            _ => unreachable!("expected IVM executable"),
        };
        let parsed = ivm::ProgramMetadata::parse(&bytes).expect("metadata parses");
        let decoded = ivm::ivm_cache::global_get(&bytes[parsed.code_offset..])
            .expect("bytecode decodes before execution");
        let mut vm = ivm::IVM::new(TEST_GAS_LIMIT);
        let host = crate::smartcontracts::ivm::host::CoreHost::with_accounts(
            tx.authority().clone(),
            Arc::new(accounts),
        );
        vm.set_host(host);
        vm.load_program(&bytes).expect("program loads");
        vm.set_gas_limit(TEST_GAS_LIMIT);
        if let Err(err) = vm.run() {
            let code_bytes = vm.memory.read_code_bytes();
            let original_code = bytes[parsed.header_len..].to_vec();
            let diffs = code_bytes
                .iter()
                .zip(original_code.iter())
                .filter(|(a, b)| a != b)
                .count();
            let pc_usize = usize::try_from(vm.pc).ok();
            let word = pc_usize.and_then(|pc| {
                if pc + 4 <= code_bytes.len() {
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(&code_bytes[pc..pc + 4]);
                    Some(u32::from_le_bytes(buf))
                } else {
                    None
                }
            });
            let target_pc = vm.pc.saturating_sub(parsed.prefix_len() as u64);
            let has_decoded = decoded.iter().any(|op| op.pc == target_pc);
            let decoded_inst = decoded
                .iter()
                .find(|op| op.pc == target_pc)
                .map(|op| op.inst);
            let r10 = vm.registers.get(10);
            let r11 = vm.registers.get(11);
            let r12 = vm.registers.get(12);
            let dump_tlv = |addr: u64, vm: &ivm::IVM| -> Option<String> {
                let mut buf = vec![0u8; 48];
                vm.memory
                    .load_bytes(addr, &mut buf)
                    .ok()
                    .map(|()| hex::encode(buf))
            };
            panic!(
                "vm.run failed: {err:?} pc=0x{:x} gas_remaining={} word={word:#?} decoded_entry={has_decoded} inst={decoded_inst:#?} code_diffs={diffs} r10=0x{r10:x} r11=0x{r11:x} r12=0x{r12:x} tlv10={:?} tlv11={:?} tlv12={:?}",
                vm.pc,
                vm.gas_remaining,
                dump_tlv(r10, &vm),
                dump_tlv(r11, &vm),
                dump_tlv(r12, &vm)
            );
        }
    }
}
fn extract_amx_budget_violation(vm: &mut ivm::IVM) -> Option<AmxBudgetViolation> {
    let host_any = vm.host_mut_any()?;
    host_any
        .downcast_mut::<crate::smartcontracts::ivm::host::CoreHost>()
        .and_then(crate::smartcontracts::ivm::host::CoreHost::take_amx_budget_violation)
}
fn clear_axt_reject(vm: &mut ivm::IVM) {
    if let Some(host_any) = vm.host_mut_any() {
        if let Some(host) = host_any.downcast_mut::<crate::smartcontracts::ivm::host::CoreHost>() {
            host.clear_axt_reject();
        }
    }
}
fn extract_axt_reject(vm: &mut ivm::IVM) -> Option<AxtRejectContext> {
    let host_any = vm.host_mut_any()?;
    host_any
        .downcast_mut::<crate::smartcontracts::ivm::host::CoreHost>()
        .and_then(crate::smartcontracts::ivm::host::CoreHost::take_axt_reject)
}
fn run_vm(vm: &mut ivm::IVM) -> Result<(), OverlayBuildError> {
    clear_axt_reject(vm);
    match vm.run() {
        Ok(()) => Ok(()),
        Err(ivm::VMError::AmxBudgetExceeded {
            dataspace,
            stage,
            elapsed_ms,
            budget_ms,
        }) => {
            let violation = AmxBudgetViolation {
                dataspace,
                stage,
                elapsed_ms: u32::try_from(elapsed_ms.min(u64::from(u32::MAX)))
                    .expect("elapsed_ms clamped to u32::MAX"),
                budget_ms: u32::try_from(budget_ms.min(u64::from(u32::MAX)))
                    .expect("budget_ms clamped to u32::MAX"),
            };
            Err(OverlayBuildError::AmxBudgetViolation(violation))
        }
        Err(err) => {
            if matches!(
                err.as_unmetered(),
                ivm::VMError::HostOutputBudgetExceeded { .. }
            ) {
                return Err(OverlayBuildError::IvmRun(err));
            }
            if let Some(reject) = extract_axt_reject(vm) {
                return Err(OverlayBuildError::AxtReject(reject));
            }
            extract_amx_budget_violation(vm)
                .map(OverlayBuildError::AmxBudgetViolation)
                .map_or_else(|| Err(OverlayBuildError::IvmRun(err)), Err)
        }
    }
}
#[cfg(any(test, feature = "iroha-core-tests"))]
fn run_vm_with_host<QS: crate::smartcontracts::ivm::host::QueryStateAccess + Default>(
    vm: &mut ivm::IVM,
    host: &mut crate::smartcontracts::ivm::host::CoreHostImpl<QS>,
) -> Result<bool, OverlayBuildError> {
    host.clear_axt_reject();
    let result = vm.run_with_host(host);
    finish_vm_run_with_host(host, result)?;
    host.finish_contract_result(vm)
        .map_err(OverlayBuildError::IvmRun)
}

#[cfg(any(test, feature = "iroha-core-tests"))]
fn finish_vm_run_with_host<QS: crate::smartcontracts::ivm::host::QueryStateAccess + Default>(
    host: &mut crate::smartcontracts::ivm::host::CoreHostImpl<QS>,
    result: Result<(), ivm::VMError>,
) -> Result<(), OverlayBuildError> {
    match result {
        Ok(()) => Ok(()),
        Err(ivm::VMError::AmxBudgetExceeded {
            dataspace,
            stage,
            elapsed_ms,
            budget_ms,
        }) => {
            let violation = AmxBudgetViolation {
                dataspace,
                stage,
                elapsed_ms: u32::try_from(elapsed_ms.min(u64::from(u32::MAX)))
                    .expect("elapsed_ms clamped to u32::MAX"),
                budget_ms: u32::try_from(budget_ms.min(u64::from(u32::MAX)))
                    .expect("budget_ms clamped to u32::MAX"),
            };
            Err(OverlayBuildError::AmxBudgetViolation(violation))
        }
        Err(err) => {
            if matches!(
                err.as_unmetered(),
                ivm::VMError::HostOutputBudgetExceeded { .. }
            ) {
                return Err(OverlayBuildError::IvmRun(err));
            }
            if let Some(reject) = host.take_axt_reject() {
                return Err(OverlayBuildError::AxtReject(reject));
            }
            host.take_amx_budget_violation()
                .map(OverlayBuildError::AmxBudgetViolation)
                .map_or_else(|| Err(OverlayBuildError::IvmRun(err)), Err)
        }
    }
}
pub(crate) fn amx_timeout_message(violation: &AmxBudgetViolation) -> String {
    match violation.as_canonical() {
        CanonicalErrorKind::AmxTimeout(detail) => format!(
            "AMX_TIMEOUT dataspace={} stage={:?} elapsed_ms={} budget_ms={}",
            detail.dataspace.as_u64(),
            detail.stage,
            detail.elapsed_ms,
            detail.budget_ms
        ),
        _ => "AMX_TIMEOUT".to_owned(),
    }
}
/// Structured error type for overlay construction failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayBuildError {
    /// Failed to parse IVM header metadata.
    IvmHeaderParse,
    /// IVM header violated node policy (structured admission error).
    HeaderPolicy(IvmAdmissionError),
    /// Contract-call metadata was malformed or could not be applied.
    ContractCall(String),
    /// Missing or invalid gas bound in the typed fee-payment intent.
    GasLimit(String),
    /// Loading the program into the VM failed.
    IvmLoad(IvmError),
    /// Running the VM to collect queued ISIs failed.
    IvmRun(IvmError),
    /// A syscall requiring coherent live world state appeared in a state-free run.
    StateRequiredSyscall(u32),
    /// The replicated AXT policy snapshot is not canonical.
    InvalidAxtPolicySnapshot(iroha_data_model::nexus::AxtPolicySnapshotValidationError),
    /// AXT policy rejected the envelope with structured context.
    AxtReject(AxtRejectContext),
    /// AMX budget violation during overlay execution.
    AmxBudgetViolation(AmxBudgetViolation),
    /// Transaction classified into quarantine but exceeded per-block cap.
    QuarantineOverflow,
    /// ZK proof-related rejection (missing/invalid/unsupported).
    ZkProof(String),
    /// A cryptographically valid IVM proof no longer matches deterministic
    /// replay against the current state view.
    IvmProvedReplay(String),
    /// Local execution ownership failed; this is not a transaction rejection.
    ExecutionOwner(String),
}
impl OverlayBuildError {
    /// Return the typed local refusal before any consensus rejection mapping.
    pub(crate) fn execution_deferral(&self) -> Option<crate::execution_attempt::ExecutionDeferred> {
        match self {
            Self::IvmLoad(error) | Self::IvmRun(error) => {
                crate::execution_attempt::ExecutionDeferred::from_vm_error(error)
            }
            _ => None,
        }
    }
    #[cfg(test)]
    /// Return whether rebuilding against a later serial state may change the result. Structural,
    /// policy, gas, cryptographic-proof, and quarantine failures are invariant and must remain
    /// rejected without another execution attempt. A proved replay mismatch is state-dependent
    /// because an earlier transaction in the block can change the replayed trace.
    #[must_use]
    pub(crate) const fn may_change_with_live_state(&self) -> bool {
        matches!(
            self,
            Self::ContractCall(_) | Self::IvmRun(_) | Self::AxtReject(_) | Self::IvmProvedReplay(_)
        )
    }
}
impl core::fmt::Display for OverlayBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OverlayBuildError::IvmHeaderParse => write!(f, "IVM header parse error"),
            OverlayBuildError::HeaderPolicy(e) => write!(f, "header policy: {e:?}"),
            OverlayBuildError::ContractCall(msg) => write!(f, "{msg}"),
            OverlayBuildError::GasLimit(msg) => write!(f, "{msg}"),
            OverlayBuildError::IvmLoad(e) => write!(f, "ivm.load_program: {e}"),
            OverlayBuildError::IvmRun(e) => write!(f, "ivm.run: {e}"),
            OverlayBuildError::ExecutionOwner(message) => write!(f, "execution owner: {message}"),
            OverlayBuildError::StateRequiredSyscall(syscall) => write!(
                f,
                "IVM syscall 0x{syscall:06x} requires a coherent live state view"
            ),
            OverlayBuildError::InvalidAxtPolicySnapshot(e) => {
                write!(f, "invalid AXT policy snapshot: {e}")
            }
            OverlayBuildError::AxtReject(ctx) => write!(f, "axt_reject: {ctx}"),
            OverlayBuildError::AmxBudgetViolation(v) => write!(f, "{}", amx_timeout_message(v)),
            OverlayBuildError::QuarantineOverflow => write!(f, "quarantine overflow"),
            OverlayBuildError::ZkProof(msg) => write!(f, "zk_proof: {msg}"),
            OverlayBuildError::IvmProvedReplay(msg) => write!(f, "zk_proof: {msg}"),
        }
    }
}
impl From<iroha_data_model::nexus::AxtPolicySnapshotValidationError> for OverlayBuildError {
    fn from(error: iroha_data_model::nexus::AxtPolicySnapshotValidationError) -> Self {
        Self::InvalidAxtPolicySnapshot(error)
    }
}
pub(crate) fn enforce_manifest_is_pre_registered<R: StateReadOnly>(
    state_ro: &R,
    tx: &TransactionPayload,
    code_hash: Hash,
) -> Result<(), OverlayBuildError> {
    if metadata_contract_manifest(&tx.metadata)?.is_none() {
        return Ok(());
    }
    let artifact_id = routed_artifact_id(state_ro, tx, code_hash)?;
    if state_ro
        .world()
        .contract_manifests()
        .get(&artifact_id)
        .is_some()
    {
        return Ok(());
    }
    Err(OverlayBuildError::ZkProof(
        "manifest metadata present but contract manifest is not registered in WSV; proved executions do not support implicit manifest append"
            .to_owned(),
    ))
}
#[cfg(test)]
fn sha256_to_hash(bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    Hash::prehashed(arr)
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::pipeline::overlay::IvmTraceBundleV1")]
#[cfg(test)]
struct IvmTraceBundleV1 {
    register_trace: Vec<IvmRegisterStateV1>,
    constraints: Vec<IvmConstraintV1>,
    memory_log: Vec<IvmMemEventV1>,
    register_log: Vec<IvmRegEventV1>,
    step_log: Vec<IvmStepEntryV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::pipeline::overlay::IvmRegisterStateV1")]
#[derive(
    Debug, Clone, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[cfg(test)]
struct IvmRegisterStateV1 {
    pc: u64,
    gpr: Vec<u64>,
    tags: Vec<u8>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::pipeline::overlay::IvmConstraintV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
#[cfg(test)]
enum IvmConstraintV1 {
    Zero { reg: u16, cycle: u64 },
    Eq { reg1: u16, reg2: u16, cycle: u64 },
    Range { reg: u16, bits: u8, cycle: u64 },
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::pipeline::overlay::IvmMemEventV1")]
#[derive(
    Debug, Clone, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[cfg(test)]
enum IvmMemEventV1 {
    Load {
        addr: u64,
        value: u128,
        size: u8,
        path: Vec<[u8; 32]>,
        root: [u8; 32],
    },
    Store {
        addr: u64,
        value: u128,
        size: u8,
        path: Vec<[u8; 32]>,
        root: [u8; 32],
    },
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::pipeline::overlay::IvmRegEventV1")]
#[derive(
    Debug, Clone, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[cfg(test)]
enum IvmRegEventV1 {
    Read {
        index: u16,
        value: u64,
        tag: bool,
        path: [[u8; 32]; ivm::REGISTER_MERKLE_PATH_DEPTH],
        root: [u8; 32],
    },
    Write {
        index: u16,
        value: u64,
        tag: bool,
        path: [[u8; 32]; ivm::REGISTER_MERKLE_PATH_DEPTH],
        root: [u8; 32],
    },
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::pipeline::overlay::IvmStepEntryV1")]
#[derive(
    Debug, Clone, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[cfg(test)]
struct IvmStepEntryV1 {
    pc: u64,
    reg_root: [u8; 32],
    mem_root: [u8; 32],
}
#[cfg(test)]
fn expected_ivm_trace_hash(trace_bundle: &IvmTraceBundleV1) -> Result<Hash, OverlayBuildError> {
    let trace_bytes = norito::encode_canonical(trace_bundle)
        .map_err(|_| OverlayBuildError::ZkProof("failed to encode IVM trace bundle".to_owned()))?;
    Ok(sha256_to_hash(&trace_bytes))
}
#[cfg(test)]
fn validate_ivm_proved_queued_authorization(
    queued: &[crate::smartcontracts::ivm::host::QueuedEffect],
    authority: &AccountId,
    runtime_context: &crate::executor::ContractRuntimeExecutionContext,
    authorization: &ContractEntrypointAuthorizationSnapshot,
) -> Result<(), OverlayBuildError> {
    let invalid = !authorization.is_root()
        || authorization.authority != *authority
        || queued.iter().any(|queued| {
            queued.authority != runtime_context.contract_subject
                || queued.entrypoint_authorization.as_ref() != Some(authorization)
                || queued
                    .contract_runtime_context
                    .as_ref()
                    .is_none_or(|context| {
                        context.contract_subject != runtime_context.contract_subject
                            || context.contract_address != runtime_context.contract_address
                            || context.contract_alias != runtime_context.contract_alias
                            || context.entrypoint != runtime_context.entrypoint
                    })
        });
    if invalid {
        return Err(OverlayBuildError::ZkProof(
            "Executable::IvmProved ABI V1 can preserve only exact top-level authorization for queued host writes; nested or mismatched contexts are forbidden"
                .to_owned(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_ivm_proved_durable_authorizations(
    world: &impl WorldReadOnly,
    durable_state_overlay: &BTreeMap<StatePath, Option<Vec<u8>>>,
    durable_state_authorizations: &BTreeMap<
        StatePath,
        Option<ContractEntrypointAuthorizationSnapshot>,
    >,
    root_authorization: &ContractEntrypointAuthorizationSnapshot,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
    if durable_state_overlay.len() != durable_state_authorizations.len()
        || !durable_state_overlay
            .keys()
            .eq(durable_state_authorizations.keys())
    {
        return Err(ValidationFail::InternalError(
            "Executable::IvmProved replay produced structurally inconsistent durable-state authorization metadata"
                .to_owned(),
        ).into());
    }
    for (path, authorization) in durable_state_authorizations {
        crate::smartcontracts::ivm::host::validate_reserve_durable_state_path(path)?;
        let authorization = authorization.as_ref().ok_or_else(|| {
            ValidationFail::NotPermitted(format!(
                "Executable::IvmProved durable state path `{path}` is missing its contract authorization snapshot"
            ))
        })?;
        if !authorization.descends_from(root_authorization) {
            return Err(ValidationFail::NotPermitted(format!(
                "Executable::IvmProved durable state path `{path}` does not retain the root invocation chain"
            )).into());
        }
        if !authorization.owns_durable_state_path(path) {
            return Err(ValidationFail::NotPermitted(format!(
                "Executable::IvmProved durable state path `{path}` does not belong to its contract authorization snapshot"
            )).into());
        }
        authorization.validate(world)?;
    }
    Ok(())
}
#[derive(Debug)]
pub(crate) struct IvmProvedReplay {
    pub(crate) queued: Vec<crate::smartcontracts::ivm::host::QueuedEffect>,
    pub(crate) completed_axt: Vec<ivm::axt::HostAxtState>,
    pub(crate) durable_state_overlay: BTreeMap<StatePath, Option<Vec<u8>>>,
    pub(crate) durable_state_authorizations:
        BTreeMap<StatePath, Option<ContractEntrypointAuthorizationSnapshot>>,
    #[cfg(test)]
    pub(crate) access_log: Option<ivm::host::AccessLog>,
    pub(crate) gas_used: u64,
}

/// Sole observation of actual replay work, retained even when verification fails.
/// Claimed overlay/proof counters never populate this record.
#[derive(Default)]
pub(crate) struct IvmProvedReplayWork {
    started: bool,
    gas_used: Option<u64>,
}

impl IvmProvedReplayWork {
    /// Actual run gas; absent when validation refused before VM execution began.
    pub(crate) fn gas_used(&self) -> Result<Option<u64>, &'static str> {
        if self.started && self.gas_used.is_none() {
            return Err("replay execution did not close its work record");
        }
        Ok(self.gas_used)
    }
}
pub(crate) fn verify_ivm_proved_execution<R>(
    _state_ro: &R,
    _tx: &SignedTransaction,
    _proved: &iroha_data_model::transaction::IvmProved,
    _summary: &ProgramSummary,
    _cycle_budget: Option<&ivm::VmCycleBudget>,
    _work: &mut IvmProvedReplayWork,
) -> Result<IvmProvedReplay, OverlayBuildError>
where
    R: StateReadOnly + QueryStateSource,
{
    // TODO: Admit IvmProved only after the complete native STARK relation,
    // State-owned finalized anchor, and local private prover are connected.
    // The retired Halo2 and STARK binding circuits prove only public values;
    // replay cannot turn either into an execution proof.
    Err(OverlayBuildError::ZkProof(
        "IvmProved requires the complete native STARK execution relation".to_owned(),
    ))
}

#[cfg(test)]
mod trace_frame_identity_tests {
    use super::*;

    #[test]
    fn ivm_trace_frame_owner_binds_trace_hash_and_rejects_substitution() {
        let mut trace = IvmTraceBundleV1 {
            register_trace: vec![IvmRegisterStateV1 {
                pc: 4,
                gpr: vec![0, 7],
                tags: vec![0, 0],
            }],
            constraints: vec![IvmConstraintV1::Range {
                reg: 1,
                bits: 8,
                cycle: 1,
            }],
            memory_log: Vec::new(),
            register_log: Vec::new(),
            step_log: Vec::new(),
        };
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &trace,
            "iroha_core::pipeline::overlay::IvmTraceBundleV1",
        );
        let frame = norito::encode_canonical(&trace).expect("trace frame");
        let digest = expected_ivm_trace_hash(&trace).expect("production trace commitment");
        assert_eq!(digest, sha256_to_hash(&frame));
        trace.register_trace[0].gpr[1] += 1;
        assert_ne!(
            expected_ivm_trace_hash(&trace).expect("changed trace commitment"),
            digest
        );
    }
}

#[cfg(test)]
#[path = "overlay_atomic_settlement_tests.rs"]
mod atomic_settlement_overlay_tests;
