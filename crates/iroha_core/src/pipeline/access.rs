//! Access-set derivation for transactions and instructions.
//!
//! Produces deterministic read/write key sets to feed the conflict-aware
//! scheduler described in `new_pipeline.md`.
use iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1;
mod dynamic_execution;

use core::fmt::Write as _;
use iroha_allocation::AllocationBudget;
use iroha_crypto::Hash as IrohaHash;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};
// ZK ISIs live in the data model; import the module for pattern matches
use crate::{
    execution_attempt::ExecutionAttemptError,
    executor::transaction_gas_limit,
    smartcontracts::triggers::set::{ExecutableRef, SetReadOnly},
    smartcontracts::{code, ivm::host::QueryStateSource},
    state::{StateReadOnly, WorldReadOnly},
};
use iroha_data_model::isi::ExecuteTrigger;
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    isi::{
        BurnBox, GrantBox, InstructionBox, Log, MintBox, RegisterBox, RemoveKeyValueBox, RevokeBox,
        SetKeyValueBox, TransferBox, UnregisterBox, zk,
    },
    nft::NftId,
    permission,
    prelude::*,
    role::RoleId,
    rwa::RwaId,
    smart_contract::ContractArtifactId,
    smart_contract::manifest::{
        ContractManifest, DynamicAccessHint, EntrypointDescriptor, MANIFEST_METADATA_KEY,
    },
    state::{
        AccountMetadataKey, AccountRoleKey, AssetDefinitionMetadataKey, AssetMetadataKey,
        CanonicalStateKey, DomainMetadataKey, NftMetadataKey, RwaMetadataKey,
        StateAccessSetAdvisory, TriggerMetadataKey, TxQueueKey,
    },
    transaction::{SignedTransaction, TransactionEntrypoint, executable::ContractInvocation},
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::LaneId;
use ivm::host::IVMHost;
use mv::storage::StorageReadOnly; // bring trait into scope for .get()
use parking_lot::RwLock;
/// Canonical string key used for conflict detection (Norito-like ordering).
///
/// Keys are generated deterministically from data model identifiers such as
/// `AccountId`, `DomainId`, `AssetDefinitionId`, `AssetId`, `NftId`, and `RwaId`.
pub type AccessKey = String;
const AUTHORITY_ACCOUNT_KEY: &str = "account:$authority";
/// Synthetic scheduler epoch covering every change that can affect a named
/// entrypoint permission check (direct grants, role bindings, and role grants).
const AUTHORIZATION_EPOCH_KEY: &str = "authorization:*";
const ACCOUNT_WILDCARD_KEY: &str = "account:*";
const DOMAIN_WILDCARD_KEY: &str = "domain:*";
const ASSET_WILDCARD_KEY: &str = "asset:*";
const ASSET_DEF_WILDCARD_KEY: &str = "asset_def:*";
const NEXUS_ACTIVE_LANE_CATALOG_KEY: &str = "nexus.active_lane_catalog";
/// Access set with separate read and write collections.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AccessSet {
    /// Set of keys read by a transaction or instruction batch.
    pub read_keys: BTreeSet<AccessKey>,
    /// Set of keys written by a transaction or instruction batch.
    pub write_keys: BTreeSet<AccessKey>,
}
impl AccessSet {
    /// Create an empty access set.
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a single read key.
    pub fn add_read(&mut self, k: AccessKey) {
        self.read_keys.insert(k);
    }
    /// Add a single write key.
    pub fn add_write(&mut self, k: AccessKey) {
        self.write_keys.insert(k);
    }
    /// Merge another access set into this one.
    pub fn union_with(&mut self, other: AccessSet) {
        self.read_keys.extend(other.read_keys);
        self.write_keys.extend(other.write_keys);
    }
    /// Conservative set that conflicts with everything (serializes the tx).
    pub fn global() -> Self {
        let mut s = Self::new();
        s.add_write("*".to_string());
        s
    }
}
/// Origin of an IVM access set used by the scheduler.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum AccessSetSource {
    /// Derived from manifest-level `access_set_hints`.
    ManifestHints,
    /// Derived from entrypoint-level hints on the manifest.
    EntrypointHints,
    /// Derived from a dynamic prepass that merged ISI targets and state access logs.
    PrepassMerge,
    /// Conservative fallback (global conflicts).
    ConservativeFallback,
}
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct AccessSetCacheKey {
    artifact_id: ContractArtifactId,
    entrypoint: Option<String>,
}
struct AccessSetCacheEntry {
    manifest_hash: IrohaHash,
    set: AccessSet,
}
fn access_set_cache() -> &'static RwLock<BTreeMap<AccessSetCacheKey, AccessSetCacheEntry>> {
    static ACCESS_SET_CACHE: OnceLock<RwLock<BTreeMap<AccessSetCacheKey, AccessSetCacheEntry>>> =
        OnceLock::new();
    ACCESS_SET_CACHE.get_or_init(|| RwLock::new(BTreeMap::new()))
}
fn access_set_cache_get(key: &AccessSetCacheKey, manifest_hash: &IrohaHash) -> Option<AccessSet> {
    let cache = access_set_cache();
    {
        let guard = cache.read();
        if let Some(entry) = guard.get(key) {
            if entry.manifest_hash == *manifest_hash {
                return Some(entry.set.clone());
            }
        } else {
            return None;
        }
    }
    let mut guard = cache.write();
    if let Some(entry) = guard.get(key) {
        if entry.manifest_hash == *manifest_hash {
            return Some(entry.set.clone());
        }
        guard.remove(key);
    }
    None
}
fn access_set_cache_put(key: AccessSetCacheKey, manifest_hash: IrohaHash, set: AccessSet) {
    let mut guard = access_set_cache().write();
    guard.insert(key, AccessSetCacheEntry { manifest_hash, set });
}
#[cfg(test)]
fn access_set_cache_clear() {
    access_set_cache().write().clear();
}
fn manifest_signature_hash(
    manifest: &ContractManifest,
    budget: &AllocationBudget,
) -> Result<IrohaHash, norito::core::BoundedEncodeError> {
    use norito::core::{BoundedEncodeError, DecodeBudgetContext};

    // This optional planner borrows the original manifest and streams into a
    // stack hasher. Its only new native allocation is the cumulative counter,
    // paid by the exact State execution pool supplied by the caller. The pool
    // limit also bounds streamed frame bytes; it does not certify source custody.
    let max_frame_bytes = budget.limit_bytes();
    let context = DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(
            max_frame_bytes,
            max_frame_bytes,
            max_frame_bytes,
            max_frame_bytes,
            256,
        ),
        budget,
    )
    .map_err(BoundedEncodeError::Serialization)?;
    // TODO: Norito's owned-context constructor retains typed AllocationFailed
    // but erases the original pool refusal/release observation. Do not infer an
    // execution rejection or a complete allocation certificate from this hash.
    let mut encoding = Ok(());
    let hash = IrohaHash::new_from_writer(|writer| {
        encoding = manifest
            .signature_payload()
            .write_canonical(&context, max_frame_bytes, writer);
        if encoding.is_err() {
            // Keep the original native error outside the I/O callback instead
            // of boxing it, and prevent a partial digest from being finalized.
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        Ok(())
    });
    encoding?;
    hash.map_err(|error| BoundedEncodeError::Serialization(error.into()))
}
fn prepared_contract_for_access<R>(
    state_ro: &R,
    artifact_id: ContractArtifactId,
) -> Option<ivm::PreparedContract>
where
    R: StateReadOnly,
{
    let cache = state_ro.prepared_contract_cache();
    // A warm content cache never substitutes for custody in this exact dataspace.
    // Planning alone may fall back to the global dependency barrier on an incomplete read.
    // It produces no execution verdict or negative registry entry; the live executor repeats
    // original scope/authorization admission before any effect or fee can be published.
    code::with_code_bytes(state_ro, &artifact_id, |bytecode| {
        cache.get_or_prepare(artifact_id.code_hash, bytecode)
    })
    .ok()??
    .ok()
    .map(|contract| contract.as_ref().clone())
}
fn manifest_from_metadata(tx: &SignedTransaction) -> Option<ContractManifest> {
    let key: Name = MANIFEST_METADATA_KEY.parse().ok()?;
    tx.metadata()
        .get(&key)
        .and_then(|json| json.clone().try_into_any_norito::<ContractManifest>().ok())
}
#[derive(Clone, Debug)]
struct ContractCallExecutionContext {
    entrypoint: Option<String>,
    entrypoint_pc: Option<u64>,
    entrypoint_authorization: EntrypointAuthorizationV1,
    argument_record: Option<ivm::PreparedArgumentRecord>,
    authorization: Option<crate::executor::ContractEntrypointAuthorizationSnapshot>,
}
fn requested_contract_entrypoint(metadata: &Metadata) -> Option<String> {
    metadata
        .get("contract_entrypoint")
        .and_then(|raw| raw.clone().try_into_any_norito::<String>().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}
fn add_embedded_entrypoint_authorization_read(
    set: &mut AccessSet,
    bytecode: &[u8],
    metadata: &Metadata,
) -> bool {
    let Some(selector) = requested_contract_entrypoint(metadata) else {
        return true;
    };
    let Ok(parsed) = ivm::ProgramMetadata::parse(bytecode) else {
        return false;
    };
    let Some(interface) = parsed.contract_interface.as_ref() else {
        return false;
    };
    let Some(descriptor) = interface
        .entrypoints
        .iter()
        .find(|candidate| candidate.name == selector)
    else {
        return false;
    };
    let Ok(permission) =
        crate::executor::raw_contract_entrypoint_authorization(descriptor, &selector)
    else {
        return false;
    };
    if permission != EntrypointAuthorizationV1::Anyone {
        set.add_read(AUTHORIZATION_EPOCH_KEY.to_owned());
    }
    true
}
fn add_prepared_entrypoint_authorization_read(
    set: &mut AccessSet,
    contract: &ivm::PreparedContract,
    metadata: &Metadata,
) -> bool {
    let Some(selector) = requested_contract_entrypoint(metadata) else {
        return true;
    };
    let Some(descriptor) = contract.entrypoint_descriptor(&selector) else {
        return false;
    };
    let Ok(permission) =
        crate::executor::raw_contract_entrypoint_authorization(descriptor, &selector)
    else {
        return false;
    };
    if permission != EntrypointAuthorizationV1::Anyone {
        set.add_read(AUTHORIZATION_EPOCH_KEY.to_owned());
    }
    true
}
fn resolve_callable_contract_entrypoint(
    bytecode: &[u8],
    selector: &str,
    interface_required_message: &'static str,
    raw_ivm: bool,
) -> Result<
    (
        u64,
        EntrypointAuthorizationV1,
        Option<ivm::EntrypointArgumentSchemaV1>,
    ),
    ExecutionAttemptError<String>,
> {
    let parsed = ivm::ProgramMetadata::parse(bytecode).map_err(|error| {
        dynamic_execution::vm_error(
            "invalid contract artifact for contract call dispatch",
            error,
        )
    })?;
    let prefix_len = parsed.prefix_len() as u64;
    let contract_interface = parsed
        .contract_interface
        .as_ref()
        .ok_or_else(|| interface_required_message.to_owned())?;
    let descriptor = contract_interface
        .entrypoints
        .iter()
        .find(|candidate| candidate.name == selector)
        .ok_or_else(|| format!("unknown contract entrypoint `{selector}`"))?;
    let permission = if raw_ivm {
        crate::executor::raw_contract_entrypoint_authorization(descriptor, selector)
    } else {
        crate::executor::callable_contract_entrypoint_authorization(descriptor, selector)
    }
    .map_err(|error| error.to_string())?;
    Ok((
        prefix_len + descriptor.entry_pc,
        permission,
        descriptor.argument_schema.clone(),
    ))
}
fn is_self_describing_contract(bytecode: &[u8]) -> Result<bool, ExecutionAttemptError<String>> {
    ivm::ProgramMetadata::parse(bytecode)
        .map(|parsed| parsed.contract_interface.is_some())
        .map_err(|error| dynamic_execution::vm_error("ivm.metadata", error))
}
fn parse_contract_call_execution_context(
    metadata: &Metadata,
    bytecode: &[u8],
    gas_limit: u64,
    authorization: Option<crate::executor::ContractEntrypointAuthorizationSnapshot>,
) -> Result<Option<ContractCallExecutionContext>, ExecutionAttemptError<String>> {
    let entrypoint = requested_contract_entrypoint(metadata);
    let payload = metadata.get("contract_payload").cloned();
    let (entrypoint, entrypoint_pc, entrypoint_authorization, argument_schema) = if let Some(
        selector,
    ) =
        entrypoint.as_deref()
    {
        let (entrypoint_pc, entrypoint_authorization, argument_schema) =
            resolve_callable_contract_entrypoint(
                bytecode,
                selector,
                "contract call entrypoint metadata requires a self-describing contract artifact",
                true,
            )?;
        let selected = authorization.as_ref().ok_or_else(|| {
            "raw-IVM contract entrypoint prepass requires an authorized live contract binding"
                .to_owned()
        })?;
        if selected.entrypoint != selector || selected.authorization != entrypoint_authorization {
            return Err(
                ("raw-IVM contract entrypoint authorization changed before argument preparation"
                    .to_owned())
                .into(),
            );
        }
        (
            Some(selector.to_owned()),
            Some(entrypoint_pc),
            entrypoint_authorization,
            argument_schema,
        )
    } else if is_self_describing_contract(bytecode)? {
        return Err(
            ("self-describing contract calls require explicit contract_entrypoint metadata"
                .to_owned())
            .into(),
        );
    } else if payload.is_none() {
        return Ok(None);
    } else {
        (None, None, EntrypointAuthorizationV1::Anyone, None)
    };
    let canonical_record = crate::executor::encode_contract_argument_record(
        argument_schema.as_ref(),
        payload.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    let argument_record = match (argument_schema.as_ref(), canonical_record) {
        (None, None) => None,
        (Some(schema), Some(record)) => Some(
            ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(record), gas_limit)
                .map_err(|error| dynamic_execution::vm_error("ivm.arguments", error))?,
        ),
        _ => {
            return Err("contract argument schema and canonical record diverged"
                .to_owned()
                .into());
        }
    };
    Ok(Some(ContractCallExecutionContext {
        entrypoint,
        entrypoint_pc,
        entrypoint_authorization,
        argument_record,
        authorization,
    }))
}
fn parse_prepared_contract_call_execution_context(
    metadata: &Metadata,
    contract: &ivm::PreparedContract,
    gas_limit: u64,
    authorization: Option<crate::executor::ContractEntrypointAuthorizationSnapshot>,
) -> Result<Option<ContractCallExecutionContext>, ExecutionAttemptError<String>> {
    let entrypoint = requested_contract_entrypoint(metadata);
    let payload = metadata.get("contract_payload").cloned();
    let (entrypoint, entrypoint_pc, entrypoint_authorization, argument_schema) =
        if let Some(selector) = entrypoint.as_deref() {
            let descriptor = contract
                .entrypoint_descriptor(selector)
                .ok_or_else(|| format!("unknown contract entrypoint `{selector}`"))?;
            let entrypoint_pc = contract.entrypoint_pc(selector).ok_or_else(|| {
                format!("contract entrypoint `{selector}` has no validated program counter")
            })?;
            let entrypoint_authorization =
                crate::executor::raw_contract_entrypoint_authorization(descriptor, selector)
                    .map_err(|error| error.to_string())?;
            let selected = authorization.as_ref().ok_or_else(|| {
                "raw-IVM contract entrypoint prepass requires an authorized live contract binding"
                    .to_owned()
            })?;
            if selected.entrypoint != selector || selected.authorization != entrypoint_authorization
            {
                return Err((
                    "raw-IVM contract entrypoint authorization changed before argument preparation"
                        .to_owned()).into());
            }
            (
                Some(selector.to_owned()),
                Some(entrypoint_pc),
                entrypoint_authorization,
                descriptor.argument_schema.clone(),
            )
        } else {
            return Err(
                ("self-describing contract calls require explicit contract_entrypoint metadata"
                    .to_owned())
                .into(),
            );
        };
    let canonical_record = crate::executor::encode_contract_argument_record(
        argument_schema.as_ref(),
        payload.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    let argument_record = match (argument_schema.as_ref(), canonical_record) {
        (None, None) => None,
        (Some(schema), Some(record)) => Some(
            ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(record), gas_limit)
                .map_err(|error| dynamic_execution::vm_error("ivm.arguments", error))?,
        ),
        _ => {
            return Err("contract argument schema and canonical record diverged"
                .to_owned()
                .into());
        }
    };
    Ok(Some(ContractCallExecutionContext {
        entrypoint,
        entrypoint_pc,
        entrypoint_authorization,
        argument_record,
        authorization,
    }))
}
fn parse_contract_invocation_execution_context(
    invocation: &ContractInvocation,
    contract: &ivm::PreparedContract,
    gas_limit: u64,
    authorization: crate::executor::ContractEntrypointAuthorizationSnapshot,
) -> Result<ContractCallExecutionContext, ExecutionAttemptError<String>> {
    let selector = invocation.entrypoint.trim();
    if selector.is_empty() {
        return Err(("contract entrypoint must not be empty".to_owned()).into());
    }
    let descriptor = contract
        .entrypoint_descriptor(selector)
        .ok_or_else(|| format!("unknown contract entrypoint `{selector}`"))?;
    let entrypoint_pc = contract.entrypoint_pc(selector).ok_or_else(|| {
        format!("contract entrypoint `{selector}` has no validated program counter")
    })?;
    let entrypoint_authorization =
        crate::executor::callable_contract_entrypoint_authorization(descriptor, selector)
            .map_err(|error| error.to_string())?;
    let argument_schema = descriptor.argument_schema.clone();
    if authorization.entrypoint != selector
        || authorization.authorization != entrypoint_authorization
    {
        return Err(
            ("deployed contract entrypoint authorization changed before argument preparation"
                .to_owned())
            .into(),
        );
    }
    let argument_record = match (argument_schema.as_ref(), invocation.arguments.as_deref()) {
        (None, None) => None,
        (None, Some(_)) => {
            return Err(
                ("zero-parameter entrypoint must not carry an argument record".to_owned()).into(),
            );
        }
        (Some(_), None) => {
            return Err(("parameterized entrypoint requires an argument record".to_owned()).into());
        }
        (Some(schema), Some(arguments)) => Some(
            ivm::prepare_argument_record_with_gas_limit(
                schema,
                Arc::<[u8]>::from(arguments),
                gas_limit,
            )
            .map_err(|error| dynamic_execution::vm_error("ivm.arguments", error))?,
        ),
    };
    Ok(ContractCallExecutionContext {
        entrypoint: Some(selector.to_owned()),
        entrypoint_pc: Some(entrypoint_pc),
        entrypoint_authorization,
        argument_record,
        authorization: Some(authorization),
    })
}
fn apply_contract_call_execution_context(
    vm: &mut ivm::IVM,
    context: Option<&ContractCallExecutionContext>,
) -> Result<(), String> {
    if let Some(context) = context
        && let Some(entrypoint_pc) = context.entrypoint_pc
    {
        // Match runtime contract-call semantics during access derivation so
        // non-`main` entrypoints can return cleanly to the VM end-of-stream.
        vm.set_register(1, vm.memory.code_len());
        vm.set_program_counter(entrypoint_pc).map_err(|err| {
            format!(
                "contract entrypoint `{}` resolved to invalid pc: {err}",
                context.entrypoint.as_deref().unwrap_or("<unspecified>")
            )
        })?;
    }
    Ok(())
}
fn manifest_access_set(
    manifest: &ContractManifest,
    artifact_id: ContractArtifactId,
    contract: &ivm::PreparedContract,
    cache_enabled: bool,
    requested_entrypoint: Option<&str>,
    budget: &AllocationBudget,
) -> Option<(AccessSet, AccessSetSource)> {
    if contract.code_hash() != artifact_id.code_hash {
        return None;
    }
    // A refused hash cannot authorize a cached exact hint. The enclosing
    // planner keeps its existing conservative dependency barrier, without a
    // negative cache entry or a manufactured transaction rejection.
    let manifest_hash = if cache_enabled {
        Some(manifest_signature_hash(manifest, budget).ok()?)
    } else {
        None
    };
    let mut selected_entrypoint_name = None;
    let mut authorization_read_required = false;
    if let Some(entrypoints) = manifest.entrypoints.as_deref() {
        let entrypoint = select_entrypoint(entrypoints, requested_entrypoint)?;
        selected_entrypoint_name = Some(entrypoint.name.clone());
        authorization_read_required = entrypoint_requires_authorization_read(entrypoint);
        if !entrypoint_access_hints_are_complete(entrypoint) {
            return None;
        }
        let key = AccessSetCacheKey {
            artifact_id,
            entrypoint: Some(entrypoint.name.clone()),
        };
        if let Some(hash) = manifest_hash.as_ref() {
            if let Some(mut set) = access_set_cache_get(&key, hash) {
                if authorization_read_required {
                    set.add_read(AUTHORIZATION_EPOCH_KEY.to_owned());
                }
                return Some((set, AccessSetSource::EntrypointHints));
            }
        }
        if let Some(set) = entrypoint_access_set_if_safe(contract, entrypoint, budget) {
            if let Some(hash) = manifest_hash.as_ref() {
                access_set_cache_put(key, hash.clone(), set.clone());
            }
            return Some((set, AccessSetSource::EntrypointHints));
        }
        // Entrypoint metadata is the most precise description available. If it is
        // incomplete or otherwise unsafe, do not mask that failure by falling back
        // to the contract-wide hints: those may contain the same under-approximation.
        if !entrypoint.read_keys.is_empty() || !entrypoint.write_keys.is_empty() {
            return None;
        }
        // A complete, explicitly empty entrypoint set may use the wider static
        // contract hints as a conservative over-approximation.
    }
    if let Some(hints) = manifest.access_set_hints.as_ref() {
        if !hints.dynamic_reads.is_empty() || !hints.dynamic_writes.is_empty() {
            return None;
        }
        let key = AccessSetCacheKey {
            artifact_id,
            entrypoint: selected_entrypoint_name,
        };
        if let Some(hash) = manifest_hash.as_ref() {
            if let Some(mut set) = access_set_cache_get(&key, hash) {
                if authorization_read_required {
                    set.add_read(AUTHORIZATION_EPOCH_KEY.to_owned());
                }
                return Some((set, AccessSetSource::ManifestHints));
            }
        }
        if let Some(mut set) = manifest_hint_access_set_if_safe(contract, hints, budget) {
            if authorization_read_required {
                set.add_read(AUTHORIZATION_EPOCH_KEY.to_owned());
            }
            if let Some(hash) = manifest_hash.as_ref() {
                access_set_cache_put(key, hash.clone(), set.clone());
            }
            return Some((set, AccessSetSource::ManifestHints));
        }
    }
    None
}
/// Derivation strategy for IVM executables.
#[derive(Debug, Copy, Clone)]
pub enum IvmStrategy {
    /// Attempt a dynamic prepass by executing the program with a read-only host and
    /// deriving keys from the queued ISIs. Fallback to conservative on error.
    DynamicThenConservative,
    /// Always conservative (serializes contracts).
    Conservative,
}
/// Derive access set for a signed transaction.
///
/// - ISI batches are analyzed statically by inspecting instruction targets.
/// - IVM contracts: when `ivm_strategy` is `DynamicThenConservative` and `state_view` is provided,
///   a read-only prepass is performed to derive keys from queued ISIs; otherwise conservative.
pub fn derive_for_transaction<R>(
    tx: &SignedTransaction,
    state_ro: Option<&R>,
    ivm_strategy: IvmStrategy,
) -> AccessSet
where
    R: StateReadOnly + QueryStateSource,
{
    derive_for_transaction_with_source(tx, state_ro, ivm_strategy).0
}
/// Derive access set for a signed transaction and report the IVM source, if any.
pub(crate) fn derive_for_transaction_with_source<R>(
    tx: &SignedTransaction,
    state_ro: Option<&R>,
    ivm_strategy: IvmStrategy,
) -> (AccessSet, Option<AccessSetSource>)
where
    R: StateReadOnly + QueryStateSource,
{
    derive_for_transaction_with_source_and_prepared(tx, state_ro, ivm_strategy, None)
}
fn derive_for_transaction_with_source_and_prepared<R>(
    tx: &SignedTransaction,
    state_ro: Option<&R>,
    ivm_strategy: IvmStrategy,
    prepared_contract: Option<&ivm::PreparedContract>,
) -> (AccessSet, Option<AccessSetSource>)
where
    R: StateReadOnly + QueryStateSource,
{
    match tx.instructions() {
        Executable::Instructions(batch) => with_stateful_admission_keys(
            tx,
            derive_from_isi_batch_with_state(batch.as_ref(), state_ro),
            None,
        ),
        // Mixed batches execute against the live state at a singleton DAG barrier. Precise
        // ordered access derivation is intentionally deferred until the live-batch executor can
        // expose one access journal spanning native ISIs and every contract call.
        Executable::Batch(_) => with_stateful_admission_keys(
            tx,
            AccessSet::global(),
            Some(AccessSetSource::ConservativeFallback),
        ),
        Executable::ContractCall(call) => {
            if let Some(view) = state_ro
                && let Ok(Some(identity)) =
                    code::fetch_bound_contract_identity(view, &call.contract_address)
                && identity.code_hash == call.expected_code_hash
                && let Ok(artifact_id) =
                    ContractArtifactId::for_address(&call.contract_address, identity.code_hash)
                && view.world().contract_code().get(&artifact_id).is_some()
                && let Some(contract) = prepared_contract
                    .filter(|contract| contract.code_hash() == identity.code_hash)
                    .cloned()
                    .or_else(|| prepared_contract_for_access(view, artifact_id))
                && let Some(manifest) = view.world().contract_manifests().get(&artifact_id)
            {
                if let Some((set, source)) = manifest_access_set(
                    manifest,
                    artifact_id,
                    &contract,
                    view.pipeline().access_set_cache_enabled,
                    Some(call.entrypoint.as_str()),
                    view.prepared_contract_cache().execution_budget(),
                ) {
                    return with_stateful_admission_keys(tx, set, Some(source));
                }
                if matches!(ivm_strategy, IvmStrategy::DynamicThenConservative) {
                    let mut set = tx_gas_limit(tx)
                        .map_err(crate::execution_attempt::ExecutionAttemptError::Rejected)
                        .and_then(|gas_limit| {
                            if contract.code_hash() != identity.code_hash {
                                return Err(
                                    "deployed contract bytecode no longer matches its live binding"
                                        .to_owned()
                                        .into(),
                                );
                            }
                            let authorization =
                                crate::executor::authorize_prepared_contract_selector(
                                    view.world(),
                                    tx.authority(),
                                    &contract,
                                    &call.entrypoint,
                                    &identity,
                                )
                                .map_err(|error| error.to_string())?;
                            let context = parse_contract_invocation_execution_context(
                                call,
                                &contract,
                                gas_limit,
                                authorization,
                            )?;
                            derive_from_prepared_ivm_dynamic_with_context(
                                &contract,
                                tx.authority(),
                                Some(context),
                                view,
                                gas_limit,
                            )
                        })
                        .unwrap_or_else(|_| AccessSet::global());
                    let fenced = apply_prepared_ivm_access_fence(&contract, &mut set);
                    let source = if fenced || is_conservative_global(&set) {
                        AccessSetSource::ConservativeFallback
                    } else {
                        AccessSetSource::PrepassMerge
                    };
                    return with_stateful_admission_keys(tx, set, Some(source));
                }
            }
            with_stateful_admission_keys(
                tx,
                AccessSet::global(),
                Some(AccessSetSource::ConservativeFallback),
            )
        }
        Executable::IvmProved(proved) => {
            let mut set = derive_from_isi_batch_with_state(proved.overlay.as_ref(), state_ro);
            let authorization_ok = if let Some(contract) = prepared_contract {
                add_prepared_entrypoint_authorization_read(&mut set, contract, tx.metadata())
            } else {
                add_embedded_entrypoint_authorization_read(
                    &mut set,
                    proved.bytecode.as_ref(),
                    tx.metadata(),
                )
            };
            if !authorization_ok {
                set = AccessSet::global();
            }
            let fenced = if let Some(contract) = prepared_contract {
                apply_prepared_ivm_access_fence(contract, &mut set)
            } else {
                apply_unverified_ivm_access_fence(proved.bytecode.as_ref(), &mut set)
            };
            let source = (fenced || is_conservative_global(&set))
                .then_some(AccessSetSource::ConservativeFallback);
            with_stateful_admission_keys(tx, set, source)
        }
        Executable::Ivm(bytecode) => {
            let bytecode_ref = bytecode.as_ref();
            let requested_entrypoint = requested_contract_entrypoint(tx.metadata());
            // Prepared overlays retain this exact immutable contract. Cold State
            // callers prepare from their original pool; state-free inspection
            // retains the conservative dependency barrier below.
            let prepared = prepared_contract.cloned().or_else(|| {
                state_ro.and_then(|state| {
                    state
                        .prepared_contract_cache()
                        .get_or_prepare(ivm::contract_code_hash(bytecode_ref), bytecode_ref)
                        .ok()
                })
            });
            if let Some(contract) = prepared.as_ref() {
                debug_assert_eq!(contract.artifact(), bytecode_ref);
                let code_hash = contract.code_hash();
                let artifact_id = state_ro.and_then(|view| {
                    super::overlay::routed_artifact_id(view, tx.payload(), code_hash).ok()
                });
                // 1) Try static hints from the exact routed registry entry.
                if let Some(view) = state_ro {
                    if let Some(artifact_id) = artifact_id
                        && let Some(manifest) = view.world().contract_manifests().get(&artifact_id)
                    {
                        if let Some((set, source)) = manifest_access_set(
                            manifest,
                            artifact_id,
                            contract,
                            view.pipeline().access_set_cache_enabled,
                            requested_entrypoint.as_deref(),
                            view.prepared_contract_cache().execution_budget(),
                        ) {
                            return with_stateful_admission_keys(tx, set, Some(source));
                        }
                    }
                }
                // 1b) Fallback to manifest provided in transaction metadata.
                if let Some(view) = state_ro
                    && let Some(manifest) = manifest_from_metadata(tx)
                    && let Some(artifact_id) = artifact_id
                {
                    if manifest.code_hash == Some(code_hash)
                        && manifest_matches_prepared_contract(contract, &manifest)
                    {
                        if let Some((set, source)) = manifest_access_set(
                            &manifest,
                            artifact_id,
                            contract,
                            false,
                            requested_entrypoint.as_deref(),
                            view.prepared_contract_cache().execution_budget(),
                        ) {
                            return with_stateful_admission_keys(tx, set, Some(source));
                        }
                    }
                }
            }
            // 2) Otherwise, use dynamic prepass if enabled with view, else conservative
            let (set, source) = match (ivm_strategy, state_ro) {
                (IvmStrategy::DynamicThenConservative, Some(view)) => {
                    let mut set = tx_gas_limit(tx)
                        .map_err(crate::execution_attempt::ExecutionAttemptError::Rejected)
                        .and_then(|gas_limit| {
                            let artifact_id = super::overlay::routed_artifact_id(
                                view,
                                tx.payload(),
                                ivm::contract_code_hash(bytecode_ref),
                            )
                            .map_err(|error| error.to_string())?;
                            if let Some(contract) = prepared.as_ref() {
                                derive_from_prepared_ivm_dynamic(
                                    contract,
                                    tx.authority(),
                                    tx.metadata(),
                                    view,
                                    gas_limit,
                                    artifact_id,
                                )
                            } else {
                                derive_from_ivm_dynamic(
                                    bytecode_ref,
                                    tx.authority(),
                                    tx.metadata(),
                                    view,
                                    gas_limit,
                                    artifact_id,
                                )
                            }
                        })
                        .unwrap_or_else(|_| AccessSet::global());
                    let fenced = if let Some(contract) = prepared.as_ref() {
                        apply_prepared_ivm_access_fence(contract, &mut set)
                    } else {
                        apply_unverified_ivm_access_fence(bytecode_ref, &mut set)
                    };
                    let source = if fenced || is_conservative_global(&set) {
                        AccessSetSource::ConservativeFallback
                    } else {
                        AccessSetSource::PrepassMerge
                    };
                    (set, Some(source))
                }
                _ => (
                    AccessSet::global(),
                    Some(AccessSetSource::ConservativeFallback),
                ),
            };
            with_stateful_admission_keys(tx, set, source)
        }
    }
}
#[cfg(test)]
/// Derive access from a prepared overlay for scheduler regression tests.
pub(crate) fn derive_for_prepared_overlay_with_source<R>(
    tx: &SignedTransaction,
    state_ro: &R,
    overlay: &crate::pipeline::overlay::TxOverlay,
    prepared_contract: Option<&ivm::PreparedContract>,
    access_log: Option<&ivm::host::AccessLog>,
    dynamic_prepass: bool,
) -> (AccessSet, Option<AccessSetSource>)
where
    R: StateReadOnly + QueryStateSource,
{
    match tx.instructions() {
        Executable::Instructions(_) => with_stateful_admission_keys(
            tx,
            derive_from_overlay_artifacts(overlay, None, Some(state_ro), false),
            None,
        ),
        Executable::Batch(_) => with_stateful_admission_keys(
            tx,
            AccessSet::global(),
            Some(AccessSetSource::ConservativeFallback),
        ),
        Executable::IvmProved(proved) => {
            let mut set = derive_from_overlay_artifacts(overlay, None, Some(state_ro), false);
            let authorization_ok = if let Some(contract) = prepared_contract {
                add_prepared_entrypoint_authorization_read(&mut set, contract, tx.metadata())
            } else {
                add_embedded_entrypoint_authorization_read(
                    &mut set,
                    proved.bytecode.as_ref(),
                    tx.metadata(),
                )
            };
            if !authorization_ok {
                set = AccessSet::global();
            }
            let fenced = if let Some(contract) = prepared_contract {
                apply_prepared_ivm_access_fence(contract, &mut set)
            } else {
                apply_unverified_ivm_access_fence(proved.bytecode.as_ref(), &mut set)
            };
            let source = (fenced || is_conservative_global(&set))
                .then_some(AccessSetSource::ConservativeFallback);
            with_stateful_admission_keys(tx, set, source)
        }
        Executable::ContractCall(_) | Executable::Ivm(_) => {
            let (hint_set, hint_source) = derive_for_transaction_with_source_and_prepared(
                tx,
                Some(state_ro),
                IvmStrategy::Conservative,
                prepared_contract,
            );
            if matches!(
                hint_source,
                Some(AccessSetSource::ManifestHints | AccessSetSource::EntrypointHints)
            ) {
                return (hint_set, hint_source);
            }
            if !dynamic_prepass {
                return (hint_set, hint_source);
            }
            let set = derive_from_overlay_artifacts(overlay, access_log, Some(state_ro), true);
            let source = if is_conservative_global(&set) {
                AccessSetSource::ConservativeFallback
            } else {
                AccessSetSource::PrepassMerge
            };
            with_stateful_admission_keys(tx, set, Some(source))
        }
    }
}
#[cfg(test)]
fn derive_from_overlay_artifacts<R>(
    overlay: &crate::pipeline::overlay::TxOverlay,
    access_log: Option<&ivm::host::AccessLog>,
    state_ro: Option<&R>,
    conservative_if_empty: bool,
) -> AccessSet
where
    R: StateReadOnly + QueryStateSource,
{
    let mut set = AccessSet::new();
    let max_depth = state_ro
        .map(|state| {
            u16::from(
                state
                    .world()
                    .parameters()
                    .smart_contract()
                    .execution_depth(),
            )
        })
        .unwrap_or(0);
    let mut visited_triggers = BTreeSet::new();
    for isi in overlay.instructions() {
        set.union_with(derive_from_instruction(
            isi,
            state_ro,
            &mut visited_triggers,
            0,
            max_depth,
        ));
    }
    if let Some(log) = access_log {
        merge_access_log(&mut set, log);
    }
    for path in overlay.durable_state_overlay().keys() {
        set.add_write(access_key_from_state_log(&path.to_string()));
    }
    if conservative_if_empty && set.read_keys.is_empty() && set.write_keys.is_empty() {
        AccessSet::global()
    } else {
        set
    }
}
fn is_conservative_global(set: &AccessSet) -> bool {
    set.read_keys.is_empty() && set.write_keys.len() == 1 && set.write_keys.contains("*")
}
fn apply_unverified_ivm_access_fence(bytecode: &[u8], set: &mut AccessSet) -> bool {
    let fence = ivm::analysis::program_syscall_numbers(bytecode).map_or(
        crate::pipeline::overlay::VmAccessFence::Global,
        crate::pipeline::overlay::VmAccessFence::from_syscall_numbers,
    );
    if let Some(key) = fence.scheduler_write_key() {
        set.add_write(key.to_owned());
        true
    } else {
        false
    }
}
fn apply_prepared_ivm_access_fence(contract: &ivm::PreparedContract, set: &mut AccessSet) -> bool {
    let fence = crate::pipeline::overlay::VmAccessFence::from_syscall_numbers(
        ivm::analysis::prepared_syscall_numbers(contract),
    );
    if let Some(key) = fence.scheduler_write_key() {
        set.add_write(key.to_owned());
        true
    } else {
        false
    }
}
fn manifest_matches_prepared_contract(
    contract: &ivm::PreparedContract,
    manifest: &ContractManifest,
) -> bool {
    manifest.same_signed_content(contract.manifest())
}
fn key_tx_sequence(account: &AccountId) -> AccessKey {
    format!("tx.sequence:{account}")
}
fn key_bridge_proof_hash(proof_hash: &[u8; 32]) -> AccessKey {
    let mut out = "bridge.proof:".to_owned();
    for byte in proof_hash {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
fn key_bridge_backend(backend: &str) -> AccessKey {
    format!("bridge.backend:{backend}")
}
fn bridge_proof_hash(proof: &iroha_data_model::bridge::BridgeProof) -> Option<[u8; 32]> {
    let backend = proof.backend_label();
    let encoded = norito::to_bytes(proof).ok()?;
    Some(crate::zk::hash_proof(
        &iroha_data_model::proof::ProofBox::new(backend, encoded),
    ))
}
fn derive_submit_bridge_proof_access(
    submit: &iroha_data_model::isi::bridge::SubmitBridgeProof,
) -> AccessSet {
    let Some(proof_hash) = bridge_proof_hash(&submit.proof) else {
        return AccessSet::global();
    };
    let mut set = AccessSet::new();
    set.add_write(key_bridge_proof_hash(&proof_hash));
    set.add_write(key_bridge_backend(&submit.proof.backend_label()));
    set
}
fn derive_record_bridge_receipt_access(
    record: &iroha_data_model::isi::bridge::RecordBridgeReceipt,
) -> AccessSet {
    let mut set = AccessSet::new();
    set.add_read(NEXUS_ACTIVE_LANE_CATALOG_KEY.to_owned());
    set.add_write(key_bridge_proof_hash(&record.receipt.proof_hash));
    set
}
fn with_stateful_admission_keys(
    tx: &SignedTransaction,
    mut set: AccessSet,
    source: Option<AccessSetSource>,
) -> (AccessSet, Option<AccessSetSource>) {
    expand_authority_placeholders(&mut set, tx.authority());
    set.add_read(key_account(tx.authority()));
    set.add_write(key_tx_sequence(tx.authority()));
    match crate::tx::faucet_claim_consumption_marker(tx) {
        Ok(Some((path, _))) => {
            set.add_write(access_key_from_state_log(&path.to_string()));
        }
        Ok(None) => {}
        Err(_) => return (AccessSet::global(), source),
    }
    if let Executable::ContractCall(invocation) = tx.instructions() {
        set.add_read(format!("contract.instance:{}", invocation.contract_address));
        let lifecycle_marker =
            code::contract_lifecycle_state_key(&invocation.contract_address).to_string();
        let lifecycle_key = access_key_from_state_log(&lifecycle_marker);
        set.add_read(lifecycle_key.clone());
        if matches!(
            invocation.entrypoint.as_str(),
            "hajimari" | "始まり" | "kaizen" | "改善"
        ) {
            set.add_write(lifecycle_key);
        }
    }
    (set, source)
}
fn expand_authority_placeholders(set: &mut AccessSet, authority: &AccountId) {
    set.read_keys = set
        .read_keys
        .iter()
        .map(|key| expand_authority_placeholder_key(key, authority))
        .collect();
    set.write_keys = set
        .write_keys
        .iter()
        .map(|key| expand_authority_placeholder_key(key, authority))
        .collect();
}
fn expand_authority_placeholder_key(key: &str, authority: &AccountId) -> String {
    if key == AUTHORITY_ACCOUNT_KEY {
        return key_account(authority);
    }
    if let Some(rest) = key.strip_prefix("asset:")
        && let Some(definition_raw) = rest.strip_suffix(":$authority")
        && let Ok(definition) = AssetDefinitionId::parse_address_literal(definition_raw)
    {
        return key_asset(&AssetId::of(definition, authority.clone()));
    }
    if let Some(key_raw) = key.strip_prefix("account.detail:$authority:")
        && let Ok(name) = key_raw.parse::<Name>()
    {
        return key_account_detail(authority, &name);
    }
    if let Some(role_raw) = key.strip_prefix("role.binding:$authority:")
        && let Ok(role) = role_raw.parse::<RoleId>()
    {
        return key_role_binding(authority, &role);
    }
    if let Some(permission) = key.strip_prefix("perm.account:$authority:")
        && !permission.is_empty()
    {
        return format!("perm.account:{authority}:{permission}");
    }
    key.to_owned()
}
fn is_authority_placeholder_key(key: &str) -> bool {
    if key == AUTHORITY_ACCOUNT_KEY {
        return true;
    }
    if let Some(rest) = key.strip_prefix("asset:")
        && let Some(definition_raw) = rest.strip_suffix(":$authority")
    {
        return AssetDefinitionId::parse_address_literal(definition_raw).is_ok();
    }
    if let Some(key_raw) = key.strip_prefix("account.detail:$authority:") {
        return key_raw.parse::<Name>().is_ok();
    }
    if let Some(role_raw) = key.strip_prefix("role.binding:$authority:") {
        return role_raw.parse::<RoleId>().is_ok();
    }
    if let Some(permission) = key.strip_prefix("perm.account:$authority:") {
        return !permission.is_empty();
    }
    false
}
fn entrypoint_access_set_if_safe(
    contract: &ivm::PreparedContract,
    entrypoint: &EntrypointDescriptor,
    budget: &AllocationBudget,
) -> Option<AccessSet> {
    if !entrypoint_access_hints_are_complete(entrypoint) {
        return None;
    }
    let mut set = hint_access_set_with_dynamic_if_safe(
        contract,
        &entrypoint.read_keys,
        &entrypoint.write_keys,
        &[],
        &[],
        Some(&entrypoint.name),
        budget,
    )?;
    if entrypoint_requires_authorization_read(entrypoint) {
        set.add_read(AUTHORIZATION_EPOCH_KEY.to_owned());
    }
    Some(set)
}
fn entrypoint_requires_authorization_read(entrypoint: &EntrypointDescriptor) -> bool {
    entrypoint.authorization != EntrypointAuthorizationV1::Anyone
        || matches!(
            entrypoint.kind,
            iroha_data_model::smart_contract::manifest::EntryPointKind::Hajimari
                | iroha_data_model::smart_contract::manifest::EntryPointKind::Kaizen
        )
}
fn entrypoint_access_hints_are_complete(entrypoint: &EntrypointDescriptor) -> bool {
    entrypoint.access_hints_complete == Some(true) && entrypoint.access_hints_skipped.is_empty()
}
#[cfg(test)]
fn static_state_test_budget() -> AllocationBudget {
    AllocationBudget::new(64 * 1024 * 1024)
}
#[cfg(test)]
fn hint_access_set_if_safe(
    bytecode: &[u8],
    read_keys: &[String],
    write_keys: &[String],
) -> Option<AccessSet> {
    let prepared = ivm::prepare_contract(Arc::<[u8]>::from(bytecode)).ok()?;
    hint_access_set_with_dynamic_if_safe(
        &prepared,
        read_keys,
        write_keys,
        &[],
        &[],
        None,
        &static_state_test_budget(),
    )
}
#[cfg(test)]
fn entrypoint_access_set_from_bytecode_if_safe(
    bytecode: &[u8],
    entrypoint: &EntrypointDescriptor,
) -> Option<AccessSet> {
    let prepared = ivm::prepare_contract(Arc::<[u8]>::from(bytecode)).ok()?;
    entrypoint_access_set_if_safe(&prepared, entrypoint, &static_state_test_budget())
}
#[cfg(test)]
fn manifest_hint_access_set_from_bytecode_if_safe(
    bytecode: &[u8],
    hints: &iroha_data_model::smart_contract::manifest::AccessSetHints,
) -> Option<AccessSet> {
    let prepared = ivm::prepare_contract(Arc::<[u8]>::from(bytecode)).ok()?;
    manifest_hint_access_set_if_safe(&prepared, hints, &static_state_test_budget())
}
#[cfg(test)]
fn manifest_access_set_from_bytecode(
    manifest: &ContractManifest,
    code_hash: IrohaHash,
    bytecode: &[u8],
    cache_enabled: bool,
    requested_entrypoint: Option<&str>,
) -> Option<(AccessSet, AccessSetSource)> {
    let prepared = ivm::prepare_contract(Arc::<[u8]>::from(bytecode)).ok()?;
    manifest_access_set(
        manifest,
        ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        &prepared,
        cache_enabled,
        requested_entrypoint,
        &static_state_test_budget(),
    )
}
fn manifest_hint_access_set_if_safe(
    contract: &ivm::PreparedContract,
    hints: &iroha_data_model::smart_contract::manifest::AccessSetHints,
    budget: &AllocationBudget,
) -> Option<AccessSet> {
    // Dynamic hints currently identify only a base key and do not carry enough
    // information to prove that every concrete state key conflicts with it.
    // Keep them advisory until that relationship is represented explicitly.
    if !hints.dynamic_reads.is_empty() || !hints.dynamic_writes.is_empty() {
        return None;
    }
    hint_access_set_with_dynamic_if_safe(
        contract,
        &hints.read_keys,
        &hints.write_keys,
        &hints.dynamic_reads,
        &hints.dynamic_writes,
        None,
        budget,
    )
}
fn hint_access_set_with_dynamic_if_safe(
    contract: &ivm::PreparedContract,
    read_keys: &[String],
    write_keys: &[String],
    dynamic_reads: &[DynamicAccessHint],
    dynamic_writes: &[DynamicAccessHint],
    entrypoint: Option<&str>,
    budget: &AllocationBudget,
) -> Option<AccessSet> {
    let set = access_set_from_hint_keys(read_keys, write_keys, dynamic_reads, dynamic_writes)?;
    let global_read = read_keys.iter().any(|key| key == "*");
    let global_write = write_keys.iter().any(|key| key == "*");
    if global_write {
        return Some(set);
    }
    let state_read_wildcard = read_keys.iter().any(|key| key == "state:*")
        || write_keys.iter().any(|key| key == "state:*");
    let state_write_wildcard = write_keys.iter().any(|key| key == "state:*");
    // This is an optional scheduling optimization. A local workspace refusal
    // declines the hint; its caller retains the existing conservative fence.
    // Shape/selector absence stays distinct inside the canonical analyzer.
    let static_state =
        ivm::analysis::analyze_prepared_static_state_accesses(contract, entrypoint, budget).ok()?;
    if let Some(static_state) = static_state.as_ref() {
        let read_claims_cover = |key: &str| {
            global_read
                || state_read_wildcard
                || read_keys
                    .iter()
                    .chain(write_keys)
                    .any(|claim| state_claim_covers_key(claim, key))
        };
        let write_claims_cover = |key: &str| {
            global_write
                || state_write_wildcard
                || write_keys
                    .iter()
                    .any(|claim| state_claim_covers_key(claim, key))
        };
        let exact_claims_cover = static_state.complete
            && static_state
                .read_keys
                .iter()
                .all(|key| read_claims_cover(key))
            && static_state
                .write_keys
                .iter()
                .all(|key| write_claims_cover(key));
        let conservative_claims_cover =
            (!static_state.has_state_reads || state_read_wildcard || global_read)
                && (!static_state.has_state_writes || state_write_wildcard || global_write);
        if !(global_write || exact_claims_cover || conservative_claims_cover) {
            return None;
        }
    }
    for number in ivm::analysis::prepared_syscall_numbers(contract) {
        use ivm::syscalls::SyscallAccess;
        let covered = match ivm::syscalls::syscall_access(number) {
            SyscallAccess::None => true,
            SyscallAccess::StateRead => {
                static_state.is_some() || state_read_wildcard || global_read
            }
            SyscallAccess::StateWrite => {
                static_state.is_some() || state_write_wildcard || global_write
            }
            SyscallAccess::LedgerRead => global_read,
            SyscallAccess::LedgerWrite | SyscallAccess::Dynamic => false,
        };
        if !covered {
            return None;
        }
    }
    Some(set)
}
fn state_claim_covers_key(claim: &str, key: &str) -> bool {
    if claim == key || claim == "state:*" {
        return true;
    }
    let Some(base) = claim
        .strip_prefix("state:")
        .and_then(|rest| rest.strip_suffix("[*]"))
    else {
        return false;
    };
    key.strip_prefix("state:").is_some_and(|rest| {
        rest == base
            || rest
                .strip_prefix(base)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}
fn select_entrypoint<'a>(
    entrypoints: &'a [EntrypointDescriptor],
    requested_entrypoint: Option<&str>,
) -> Option<&'a EntrypointDescriptor> {
    if entrypoints.is_empty() {
        return None;
    }
    if let Some(requested) = requested_entrypoint {
        return entrypoints.iter().find(|entry| entry.name == requested);
    }
    None
}
/// Normalize manifest/entrypoint hint keys into canonical WSV keys plus state keys.
#[allow(clippy::too_many_lines)]
fn access_set_from_hint_keys(
    read_keys: &[String],
    write_keys: &[String],
    dynamic_reads: &[DynamicAccessHint],
    dynamic_writes: &[DynamicAccessHint],
) -> Option<AccessSet> {
    let mut advisory = StateAccessSetAdvisory::default();
    let mut state_reads: BTreeSet<String> = BTreeSet::new();
    let mut state_writes: BTreeSet<String> = BTreeSet::new();
    let ingest = |raw: &str,
                  canonical: &mut Vec<CanonicalStateKey>,
                  state_keys: &mut BTreeSet<String>|
     -> Option<()> {
        if raw == "*" {
            state_keys.insert(raw.to_owned());
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("state:") {
            if rest.is_empty() {
                return None;
            }
            state_keys.insert(raw.to_owned());
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("zk:election:") {
            if !iroha_data_model::governance::is_valid_governance_selector_v1(rest) {
                return None;
            }
            state_keys.insert(raw.to_owned());
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("zk_asset:") {
            AssetDefinitionId::parse_address_literal(rest).ok()?;
            state_keys.insert(raw.to_owned());
            return Some(());
        }
        if is_authority_placeholder_key(raw) {
            state_keys.insert(raw.to_owned());
            return Some(());
        }
        if raw == ACCOUNT_WILDCARD_KEY || raw == DOMAIN_WILDCARD_KEY {
            state_keys.insert(raw.to_owned());
            return Some(());
        }
        if raw == ASSET_WILDCARD_KEY || raw == ASSET_DEF_WILDCARD_KEY {
            state_keys.insert(raw.to_owned());
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("account.detail:") {
            let mut parsed: Option<AccountMetadataKey> = None;
            for split in [rest.split_once(':'), rest.rsplit_once(':')] {
                let Some((id_raw, key_raw)) = split else {
                    continue;
                };
                let Ok(key) = key_raw.parse::<Name>() else {
                    continue;
                };
                match AccountId::parse_encoded(id_raw) {
                    Ok(id) => {
                        parsed = Some(AccountMetadataKey { id, key });
                        break;
                    }
                    Err(_) => continue,
                }
            }
            match parsed {
                Some(key) => {
                    canonical.push(CanonicalStateKey::AccountMetadata(key));
                }
                None => return None,
            }
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("domain.detail:") {
            let (id, key) = rest.split_once(':')?;
            let id = DomainId::parse_fully_qualified(id).ok()?;
            let key: Name = key.parse().ok()?;
            canonical.push(CanonicalStateKey::DomainMetadata(DomainMetadataKey {
                id,
                key,
            }));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("asset_def.detail:") {
            let (id, key) = rest.split_once(':')?;
            let id = AssetDefinitionId::parse_address_literal(id).ok()?;
            let key: Name = key.parse().ok()?;
            canonical.push(CanonicalStateKey::AssetDefinitionMetadata(
                AssetDefinitionMetadataKey { id, key },
            ));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("asset.detail:") {
            let mut parsed: Option<AssetMetadataKey> = None;
            for split in [rest.split_once(':'), rest.rsplit_once(':')] {
                let Some((id_raw, key_raw)) = split else {
                    continue;
                };
                let Ok(key) = key_raw.parse::<Name>() else {
                    continue;
                };
                match AssetId::parse_literal(id_raw) {
                    Ok(id) => {
                        parsed = Some(AssetMetadataKey { id, key });
                        break;
                    }
                    Err(_) => continue,
                }
            }
            match parsed {
                Some(key) => {
                    canonical.push(CanonicalStateKey::AssetMetadata(key));
                }
                None => return None,
            }
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("nft.detail:") {
            let (id, key) = rest.split_once(':')?;
            let id: NftId = id.parse().ok()?;
            let key: Name = key.parse().ok()?;
            canonical.push(CanonicalStateKey::NftMetadata(NftMetadataKey { id, key }));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("rwa.detail:") {
            let (id, key) = rest.split_once(':')?;
            let id: RwaId = id.parse().ok()?;
            let key: Name = key.parse().ok()?;
            canonical.push(CanonicalStateKey::RwaMetadata(RwaMetadataKey { id, key }));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("trigger.detail:") {
            let (id, key) = rest.split_once(':')?;
            let id: TriggerId = id.parse().ok()?;
            let key: Name = key.parse().ok()?;
            canonical.push(CanonicalStateKey::TriggerMetadata(TriggerMetadataKey {
                id,
                key,
            }));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("role.binding:") {
            let mut parsed: Option<AccountRoleKey> = None;
            for split in [rest.split_once(':'), rest.rsplit_once(':')] {
                let Some((account_raw, role_raw)) = split else {
                    continue;
                };
                let Ok(role) = role_raw.parse::<RoleId>() else {
                    continue;
                };
                match AccountId::parse_encoded(account_raw) {
                    Ok(account) => {
                        parsed = Some(AccountRoleKey { account, role });
                        break;
                    }
                    Err(_) => continue,
                }
            }
            match parsed {
                Some(key) => {
                    canonical.push(CanonicalStateKey::AccountRole(key));
                }
                None => return None,
            }
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("account:") {
            match AccountId::parse_encoded(rest) {
                Ok(id) => canonical.push(CanonicalStateKey::Account(id)),
                Err(_) => return None,
            }
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("domain:") {
            let id = DomainId::parse_fully_qualified(rest).ok()?;
            canonical.push(CanonicalStateKey::Domain(id));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("asset_def:") {
            if let Ok(id) = AssetDefinitionId::parse_address_literal(rest) {
                canonical.push(CanonicalStateKey::AssetDefinition(id));
            } else {
                return None;
            }
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("asset:") {
            match AssetId::parse_literal(rest) {
                Ok(id) => canonical.push(CanonicalStateKey::Asset(id)),
                Err(_) => return None,
            }
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("nft:") {
            let id: NftId = rest.parse().ok()?;
            canonical.push(CanonicalStateKey::Nft(id));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("rwa:") {
            let id: RwaId = rest.parse().ok()?;
            canonical.push(CanonicalStateKey::Rwa(id));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("trigger:") {
            let id: TriggerId = rest.parse().ok()?;
            canonical.push(CanonicalStateKey::Trigger(id));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("role:") {
            let id: RoleId = rest.parse().ok()?;
            canonical.push(CanonicalStateKey::Role(id));
            return Some(());
        }
        if let Some(rest) = raw.strip_prefix("txqueue:") {
            let hash: iroha_crypto::HashOf<TransactionEntrypoint> = rest.parse().ok()?;
            canonical.push(CanonicalStateKey::TxQueue(TxQueueKey { hash }));
            return Some(());
        }
        None
    };
    for key in read_keys {
        ingest(key, &mut advisory.reads, &mut state_reads)?;
    }
    for key in write_keys {
        ingest(key, &mut advisory.writes, &mut state_writes)?;
    }
    for hint in dynamic_reads {
        ingest_dynamic_hint(hint, &mut state_reads)?;
    }
    for hint in dynamic_writes {
        ingest_dynamic_hint(hint, &mut state_writes)?;
        ingest_dynamic_hint(hint, &mut state_reads)?;
    }
    advisory.canonicalize();
    let render = |key: &CanonicalStateKey| -> AccessKey {
        match key {
            CanonicalStateKey::Domain(id) => format!("domain:{id}"),
            CanonicalStateKey::Account(id) => format!("account:{id}"),
            CanonicalStateKey::Asset(id) => format!("asset:{id}"),
            CanonicalStateKey::AssetDefinition(id) => format!("asset_def:{id}"),
            CanonicalStateKey::Nft(id) => format!("nft:{id}"),
            CanonicalStateKey::Rwa(id) => format!("rwa:{id}"),
            CanonicalStateKey::Trigger(id) => format!("trigger:{id}"),
            CanonicalStateKey::Role(id) => format!("role:{id}"),
            CanonicalStateKey::AccountPermissions(id) => format!("perm.account:{id}"),
            CanonicalStateKey::AccountRole(key) => {
                format!("role.binding:{}:{}", key.account, key.role)
            }
            CanonicalStateKey::TxQueue(key) => format!("txqueue:{}", key.hash),
            CanonicalStateKey::DomainMetadata(key) => {
                format!("domain.detail:{}:{}", key.id, key.key)
            }
            CanonicalStateKey::AccountMetadata(key) => {
                format!("account.detail:{}:{}", key.id, key.key)
            }
            CanonicalStateKey::AssetDefinitionMetadata(key) => {
                format!("asset_def.detail:{}:{}", key.id, key.key)
            }
            CanonicalStateKey::AssetMetadata(key) => format!("asset.detail:{}:{}", key.id, key.key),
            CanonicalStateKey::NftMetadata(key) => format!("nft.detail:{}:{}", key.id, key.key),
            CanonicalStateKey::RwaMetadata(key) => format!("rwa.detail:{}:{}", key.id, key.key),
            CanonicalStateKey::TriggerMetadata(key) => {
                format!("trigger.detail:{}:{}", key.id, key.key)
            }
        }
    };
    let mut set = AccessSet::new();
    for key in advisory.reads {
        set.add_read(render(&key));
    }
    for key in advisory.writes {
        set.add_write(render(&key));
    }
    for key in state_reads {
        set.add_read(key);
    }
    for key in state_writes {
        set.add_write(key);
    }
    Some(set)
}
fn ingest_dynamic_hint(hint: &DynamicAccessHint, state_keys: &mut BTreeSet<String>) -> Option<()> {
    ivm::access_hints::validate_dynamic_access_hint_v1(hint).ok()?;
    state_keys.insert(hint.base_key.clone());
    Some(())
}
fn derive_from_isi_batch_with_state<R>(batch: &[InstructionBox], state_ro: Option<&R>) -> AccessSet
where
    R: StateReadOnly + QueryStateSource,
{
    if let Some(set) = derive_simple_asset_transfer_batch(batch) {
        return set;
    }
    let mut set = AccessSet::new();
    let max_depth = state_ro
        .map(|view| u16::from(view.world().parameters().smart_contract().execution_depth()))
        .unwrap_or(0);
    let mut visited_triggers = BTreeSet::new();
    for instr in batch {
        set.union_with(derive_from_instruction(
            instr,
            state_ro,
            &mut visited_triggers,
            0,
            max_depth,
        ));
    }
    set
}
fn derive_simple_asset_transfer_batch(batch: &[InstructionBox]) -> Option<AccessSet> {
    for instr in batch {
        let transfer = instr.as_any().downcast_ref::<TransferBox>()?;
        let TransferBox::Asset(_) = transfer else {
            return None;
        };
    }
    // User asset transfer admission reads dynamic alias, policy, escrow, and routing state.
    // Until those keys have first-class scheduler categories, the only complete declaration is
    // the scheduler's designed conservative fence.
    Some(AccessSet::global())
}
#[allow(clippy::too_many_lines)]
fn derive_from_instruction<R>(
    instr: &InstructionBox,
    state_ro: Option<&R>,
    visited_triggers: &mut BTreeSet<TriggerId>,
    depth: u16,
    max_depth: u16,
) -> AccessSet
where
    R: StateReadOnly + QueryStateSource,
{
    let mut set = AccessSet::new();
    let any = instr.as_any();
    // Logging is side-effect-free; keep it conflict-free.
    if any.downcast_ref::<Log>().is_some() {
        return set;
    }
    if let Some(submit) = any.downcast_ref::<iroha_data_model::isi::bridge::SubmitBridgeProof>() {
        return derive_submit_bridge_proof_access(submit);
    }
    if let Some(record) = any.downcast_ref::<iroha_data_model::isi::bridge::RecordBridgeReceipt>() {
        return derive_record_bridge_receipt_access(record);
    }
    // Transfers
    if let Some(tb) = any.downcast_ref::<TransferBox>() {
        match tb {
            TransferBox::Asset(t) => {
                let _ = t;
                set = AccessSet::global();
            }
            TransferBox::Domain(t) => {
                add_domain_rw(&mut set, &t.object);
                add_account_r(&mut set, &t.source);
                add_account_r(&mut set, &t.destination);
            }
            TransferBox::AssetDefinition(t) => {
                add_asset_def_rw(&mut set, &t.object, state_ro);
                add_account_r(&mut set, &t.source);
                add_account_r(&mut set, &t.destination);
            }
            TransferBox::Nft(t) => {
                add_nft_rw(&mut set, &t.object);
                add_account_r(&mut set, &t.source);
                add_account_r(&mut set, &t.destination);
            }
        }
        return set;
    }
    if let Some(rb) = any.downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>() {
        use iroha_data_model::isi::rwa::RwaInstructionBox;
        match rb {
            RwaInstructionBox::Register(r) => {
                add_domain_rw(&mut set, r.rwa.domain());
            }
            RwaInstructionBox::Transfer(t) => {
                add_rwa_rw(&mut set, t.rwa());
                add_account_r(&mut set, t.source());
                add_account_r(&mut set, t.destination());
            }
            RwaInstructionBox::Merge(m) => {
                for parent in m.parents() {
                    add_rwa_rw(&mut set, parent.rwa());
                }
            }
            RwaInstructionBox::Redeem(r) => add_rwa_rw(&mut set, r.rwa()),
            RwaInstructionBox::Freeze(r) => add_rwa_rw(&mut set, r.rwa()),
            RwaInstructionBox::Unfreeze(r) => add_rwa_rw(&mut set, r.rwa()),
            RwaInstructionBox::Hold(r) => add_rwa_rw(&mut set, r.rwa()),
            RwaInstructionBox::Release(r) => add_rwa_rw(&mut set, r.rwa()),
            RwaInstructionBox::ForceTransfer(r) => {
                add_rwa_rw(&mut set, r.rwa());
                add_account_r(&mut set, r.destination());
            }
            RwaInstructionBox::SetControls(r) => add_rwa_rw(&mut set, r.rwa()),
            RwaInstructionBox::SetKeyValue(r) => add_rwa_detail_rw(&mut set, &r.object, &r.key),
            RwaInstructionBox::RemoveKeyValue(r) => add_rwa_detail_rw(&mut set, &r.object, &r.key),
        }
        return set;
    }
    // Mint
    if let Some(mb) = any.downcast_ref::<MintBox>() {
        match mb {
            MintBox::Asset(m) => {
                let _ = m;
                set = AccessSet::global();
            }
            MintBox::TriggerRepetitions(m) => {
                add_trigger_rw(&mut set, &m.destination);
            }
        }
        return set;
    }
    // Burn
    if let Some(bb) = any.downcast_ref::<BurnBox>() {
        match bb {
            BurnBox::Asset(b) => {
                let _ = b;
                set = AccessSet::global();
            }
            BurnBox::TriggerRepetitions(b) => {
                add_trigger_rw(&mut set, &b.destination);
            }
        }
        return set;
    }
    // Set / Remove key-values
    if let Some(sb) = any.downcast_ref::<SetKeyValueBox>() {
        match sb {
            SetKeyValueBox::Account(s) => {
                add_account_detail_rw(&mut set, &s.object, &s.key);
            }
            SetKeyValueBox::Domain(s) => {
                add_domain_detail_rw(&mut set, &s.object, &s.key);
            }
            SetKeyValueBox::AssetDefinition(s) => {
                add_asset_def_detail_rw(&mut set, &s.object, &s.key, state_ro);
            }
            SetKeyValueBox::Nft(s) => {
                add_nft_detail_rw(&mut set, &s.object, &s.key);
            }
            SetKeyValueBox::Trigger(s) => {
                set.add_read(key_trigger(&s.object));
                set.add_write(format!("trigger.detail:{}:{}", &s.object, &s.key));
            }
        }
        return set;
    }
    if let Some(rb) = any.downcast_ref::<RemoveKeyValueBox>() {
        match rb {
            RemoveKeyValueBox::Account(r) => {
                add_account_detail_rw(&mut set, &r.object, &r.key);
            }
            RemoveKeyValueBox::Domain(r) => {
                add_domain_detail_rw(&mut set, &r.object, &r.key);
            }
            RemoveKeyValueBox::AssetDefinition(r) => {
                add_asset_def_detail_rw(&mut set, &r.object, &r.key, state_ro);
            }
            RemoveKeyValueBox::Nft(r) => {
                add_nft_detail_rw(&mut set, &r.object, &r.key);
            }
            RemoveKeyValueBox::Trigger(r) => {
                set.add_read(key_trigger(&r.object));
                set.add_write(format!("trigger.detail:{}:{}", &r.object, &r.key));
            }
        }
        return set;
    }
    // Register / Unregister
    if let Some(rb) = any.downcast_ref::<RegisterBox>() {
        match rb {
            RegisterBox::Domain(r) => add_domain_rw(&mut set, &r.object.id().clone()),
            RegisterBox::Account(r) => add_account_rw(&mut set, r.object.id()),
            RegisterBox::AssetDefinition(r) => {
                add_asset_def_rw(&mut set, r.object.id(), state_ro);
                // The signed owner domain is independent of the optional
                // routing alias and is read when registration is authorized.
                if let Some(domain) = r.object.owning_domain.as_ref() {
                    add_domain_r(&mut set, domain);
                }
                if let Some(alias) = r.object.alias.as_ref()
                    && let Some(domain_name) = alias.domain_segment()
                    && let Ok(domain) = DomainId::try_new(domain_name, alias.dataspace_segment())
                {
                    add_domain_r(&mut set, &domain);
                }
            }
            RegisterBox::Nft(r) => add_nft_rw(&mut set, r.object.id()),
            RegisterBox::Peer(_) => set = AccessSet::global(),
            RegisterBox::Trigger(r) => add_trigger_rw(&mut set, r.object.id()),
            RegisterBox::Role(r) => {
                add_role_rw(&mut set, r.object.id());
                set.add_write(AUTHORIZATION_EPOCH_KEY.to_owned());
            }
        }
        return set;
    }
    // ZK Voting
    if let Some(instr) = any.downcast_ref::<zk::CreateElection>() {
        // Single election record write
        set.add_write(format!("zk:election:{}", instr.election_id()));
        return set;
    }
    if let Some(instr) = any.downcast_ref::<zk::SubmitBallot>() {
        // The executor replaces the whole election record, including its ordered corpus.
        set.add_write(format!("zk:election:{}", instr.election_id()));
        return set;
    }
    if let Some(instr) = any.downcast_ref::<zk::FinalizeElection>() {
        // Finalization also replaces that same election record.
        set.add_write(format!("zk:election:{}", instr.election_id()));
        return set;
    }
    if let Some(ub) = any.downcast_ref::<UnregisterBox>() {
        match ub {
            UnregisterBox::Domain(_) => set = AccessSet::global(),
            UnregisterBox::Account(u) => add_account_rw(&mut set, &u.object),
            UnregisterBox::AssetDefinition(u) => {
                add_asset_def_rw(&mut set, &u.object, state_ro);
            }
            UnregisterBox::Nft(u) => add_nft_rw(&mut set, &u.object),
            UnregisterBox::Peer(_) => set = AccessSet::global(),
            UnregisterBox::Trigger(u) => add_trigger_rw(&mut set, &u.object),
            UnregisterBox::Role(u) => {
                add_role_rw(&mut set, &u.object);
                set.add_write(AUTHORIZATION_EPOCH_KEY.to_owned());
            }
        }
        return set;
    }
    // Grant
    if let Some(gb) = any.downcast_ref::<GrantBox>() {
        set.add_write(AUTHORIZATION_EPOCH_KEY.to_owned());
        match gb {
            GrantBox::Permission(g) => {
                add_account_rw(&mut set, &g.destination);
                set.add_write(key_perm_account(&g.destination, &g.object));
            }
            GrantBox::Role(g) => {
                add_account_rw(&mut set, &g.destination);
                set.add_read(key_role(&g.object));
                set.add_write(key_role_binding(&g.destination, &g.object));
            }
            GrantBox::RolePermission(g) => {
                add_role_rw(&mut set, &g.destination);
                set.add_write(key_perm_role(&g.destination, &g.object));
            }
        }
        return set;
    }
    // Revoke
    if let Some(rb) = any.downcast_ref::<RevokeBox>() {
        set.add_write(AUTHORIZATION_EPOCH_KEY.to_owned());
        match rb {
            RevokeBox::Permission(r) => {
                add_account_rw(&mut set, &r.destination);
                set.add_write(key_perm_account(&r.destination, &r.object));
            }
            RevokeBox::Role(r) => {
                add_account_rw(&mut set, &r.destination);
                set.add_read(key_role(&r.object));
                set.add_write(key_role_binding(&r.destination, &r.object));
            }
            RevokeBox::RolePermission(r) => {
                add_role_rw(&mut set, &r.destination);
                set.add_write(key_perm_role(&r.destination, &r.object));
            }
        }
        return set;
    }
    // Execute trigger
    if let Some(exe) = any.downcast_ref::<ExecuteTrigger>() {
        // Executing a trigger can mutate its own action (e.g., via Mint::trigger_repetitions or metadata updates),
        // so treat it as a full trigger write to avoid under-reporting conflicts.
        add_trigger_rw(&mut set, &exe.trigger);
        if let Some(view) = state_ro {
            let can_recurse = depth < max_depth && !visited_triggers.contains(&exe.trigger);
            if can_recurse {
                visited_triggers.insert(exe.trigger.clone());
                // Access planning mirrors execution with a counter wider than
                // the `u8` configured limit. `depth < max_depth` proves this
                // successor is representable without wrapping.
                set.union_with(derive_from_trigger_executable(
                    &exe.trigger,
                    view,
                    visited_triggers,
                    depth + 1,
                    max_depth,
                ));
            }
        }
        return set;
    }
    if let Some(act) =
        any.downcast_ref::<iroha_data_model::isi::staking::ActivatePublicLaneValidator>()
    {
        add_public_lane_validator_rw(&mut set, act.lane_id, &act.validator);
        return set;
    }
    if let Some(exit) =
        any.downcast_ref::<iroha_data_model::isi::staking::ExitPublicLaneValidator>()
    {
        add_public_lane_validator_rw(&mut set, exit.lane_id, &exit.validator);
        return set;
    }
    // Fallback: unknown instruction kind — be conservative.
    AccessSet::global()
}
fn derive_from_trigger_executable<R>(
    trigger_id: &TriggerId,
    state_ro: &R,
    visited_triggers: &mut BTreeSet<TriggerId>,
    depth: u16,
    max_depth: u16,
) -> AccessSet
where
    R: StateReadOnly + QueryStateSource,
{
    let mut set = AccessSet::new();
    let triggers = state_ro.world().triggers();
    let Some((executable, metadata)) = triggers.inspect_by_id(trigger_id, |action| {
        (action.executable().clone(), action.metadata().clone())
    }) else {
        return set;
    };
    match executable {
        ExecutableRef::Instructions(instructions) => {
            for instr in instructions.as_ref() {
                set.union_with(derive_from_instruction(
                    instr,
                    Some(state_ro),
                    visited_triggers,
                    depth,
                    max_depth,
                ));
            }
        }
        ExecutableRef::Batch(_) => set.union_with(AccessSet::global()),
        ExecutableRef::ContractCall(invocation) => {
            if let Ok(Some(identity)) =
                code::fetch_bound_contract_identity(state_ro, &invocation.contract_address)
                && identity.code_hash == invocation.expected_code_hash
                && let Ok(artifact_id) = ContractArtifactId::for_address(
                    &invocation.contract_address,
                    identity.code_hash,
                )
                && let Some(contract) = prepared_contract_for_access(state_ro, artifact_id)
                && let Some(manifest) = state_ro.world().contract_manifests().get(&artifact_id)
                && let Some((hinted, _source)) = manifest_access_set(
                    manifest,
                    artifact_id,
                    &contract,
                    state_ro.pipeline().access_set_cache_enabled,
                    Some(invocation.entrypoint.as_str()),
                    state_ro.prepared_contract_cache().execution_budget(),
                )
            {
                set.union_with(hinted);
            } else {
                set.union_with(AccessSet::global());
            }
        }
        ExecutableRef::Ivm(hash) => {
            let Some((code, code_hash)) = triggers.get_original_contract_with_code_hash(&hash)
            else {
                set.union_with(AccessSet::global());
                return set;
            };
            let requested_entrypoint = requested_contract_entrypoint(&metadata);
            if let Some(address) = crate::executor::requested_contract_address(&metadata)
                .ok()
                .flatten()
                && let Ok(artifact_id) = ContractArtifactId::for_address(&address, code_hash)
                && let Some(hinted) = derive_access_from_ivm_trigger(
                    code,
                    artifact_id,
                    requested_entrypoint.as_deref(),
                    state_ro,
                )
            {
                set.union_with(hinted);
            } else {
                set.union_with(AccessSet::global());
            }
        }
    }
    set
}
fn derive_access_from_ivm_trigger<R>(
    bytecode: &iroha_data_model::transaction::IvmBytecode,
    artifact_id: ContractArtifactId,
    requested_entrypoint: Option<&str>,
    state_ro: &R,
) -> Option<AccessSet>
where
    R: StateReadOnly + QueryStateSource,
{
    let bytecode_ref = bytecode.as_ref();
    let manifest = state_ro.world().contract_manifests().get(&artifact_id)?;
    let cache = state_ro.prepared_contract_cache();
    let contract = cache
        .get_or_prepare(artifact_id.code_hash, bytecode_ref)
        .ok()?;
    manifest_access_set(
        manifest,
        artifact_id,
        &contract,
        state_ro.pipeline().access_set_cache_enabled,
        requested_entrypoint,
        cache.execution_budget(),
    )
    .map(|(set, _source)| set)
}
fn key_account(id: &AccountId) -> AccessKey {
    format!("account:{id}")
}
fn key_account_detail(id: &AccountId, key: &Name) -> AccessKey {
    let mut s = String::new();
    let _ = write!(s, "account.detail:{id}:{key}");
    s
}
fn key_domain(id: &DomainId) -> AccessKey {
    format!("domain:{id}")
}
fn key_domain_detail(id: &DomainId, key: &Name) -> AccessKey {
    format!("domain.detail:{id}:{key}")
}
fn key_asset_def(id: &AssetDefinitionId) -> AccessKey {
    format!("asset_def:{id}")
}
fn key_asset_def_detail(id: &AssetDefinitionId, key: &Name) -> AccessKey {
    format!("asset_def.detail:{id}:{key}")
}
fn key_asset(id: &AssetId) -> AccessKey {
    format!("asset:{id}")
}
fn key_nft(id: &NftId) -> AccessKey {
    format!("nft:{id}")
}
fn key_nft_detail(id: &NftId, key: &Name) -> AccessKey {
    format!("nft.detail:{id}:{key}")
}
fn key_rwa(id: &RwaId) -> AccessKey {
    format!("rwa:{id}")
}
fn key_rwa_detail(id: &RwaId, key: &Name) -> AccessKey {
    format!("rwa.detail:{id}:{key}")
}
fn add_account_r(set: &mut AccessSet, id: &AccountId) {
    set.add_read(ACCOUNT_WILDCARD_KEY.to_owned());
    set.add_read(key_account(id));
}
fn add_domain_r(set: &mut AccessSet, id: &DomainId) {
    set.add_read(DOMAIN_WILDCARD_KEY.to_owned());
    set.add_read(key_domain(id));
}
fn add_account_rw(set: &mut AccessSet, id: &AccountId) {
    set.add_read(ACCOUNT_WILDCARD_KEY.to_owned());
    set.add_write(ACCOUNT_WILDCARD_KEY.to_owned());
    let k = key_account(id);
    set.add_read(k.clone());
    set.add_write(k);
}
fn add_account_detail_rw(set: &mut AccessSet, id: &AccountId, key: &Name) {
    set.add_read(key_account(id));
    let d = key_account_detail(id, key);
    set.add_read(d.clone());
    set.add_write(d);
}
fn add_domain_rw(set: &mut AccessSet, id: &DomainId) {
    set.add_read(DOMAIN_WILDCARD_KEY.to_owned());
    set.add_write(DOMAIN_WILDCARD_KEY.to_owned());
    let k = key_domain(id);
    set.add_read(k.clone());
    set.add_write(k);
}
fn add_domain_detail_rw(set: &mut AccessSet, id: &DomainId, key: &Name) {
    add_domain_r(set, id);
    let d = key_domain_detail(id, key);
    set.add_read(d.clone());
    set.add_write(d);
}
fn add_asset_definition_domain_r<R>(
    set: &mut AccessSet,
    id: &AssetDefinitionId,
    state_ro: Option<&R>,
) where
    R: StateReadOnly,
{
    let authoritative =
        state_ro.and_then(|state| state.world().asset_definition_domains().get(id).cloned());
    if let Some(domain) = authoritative {
        add_domain_r(set, &domain);
    } else {
        // Opaque identifiers without a state view cannot prove an exact owning domain. Reading
        // the category fence conflicts with every domain mutation instead of under-declaring.
        set.add_read(DOMAIN_WILDCARD_KEY.to_owned());
    }
}
fn add_asset_def_rw<R>(set: &mut AccessSet, id: &AssetDefinitionId, state_ro: Option<&R>)
where
    R: StateReadOnly,
{
    set.add_read(ASSET_DEF_WILDCARD_KEY.to_owned());
    set.add_write(ASSET_DEF_WILDCARD_KEY.to_owned());
    add_asset_definition_domain_r(set, id, state_ro);
    let k = key_asset_def(id);
    set.add_read(k.clone());
    set.add_write(k);
}
fn add_asset_def_detail_rw<R>(
    set: &mut AccessSet,
    id: &AssetDefinitionId,
    key: &Name,
    state_ro: Option<&R>,
) where
    R: StateReadOnly,
{
    add_asset_definition_domain_r(set, id, state_ro);
    set.add_read(key_asset_def(id));
    let d = key_asset_def_detail(id, key);
    set.add_read(d.clone());
    set.add_write(d);
}
fn add_nft_rw(set: &mut AccessSet, id: &NftId) {
    let k = key_nft(id);
    set.add_read(k.clone());
    set.add_write(k);
}
fn add_nft_detail_rw(set: &mut AccessSet, id: &NftId, key: &Name) {
    set.add_read(key_nft(id));
    let d = key_nft_detail(id, key);
    set.add_read(d.clone());
    set.add_write(d);
}
fn add_rwa_rw(set: &mut AccessSet, id: &RwaId) {
    let k = key_rwa(id);
    set.add_read(k.clone());
    set.add_write(k);
}
fn add_rwa_detail_rw(set: &mut AccessSet, id: &RwaId, key: &Name) {
    set.add_read(key_rwa(id));
    let d = key_rwa_detail(id, key);
    set.add_read(d.clone());
    set.add_write(d);
}
fn key_role(id: &RoleId) -> AccessKey {
    format!("role:{id}")
}
fn key_role_binding(account: &AccountId, role: &RoleId) -> AccessKey {
    format!("role.binding:{account}:{role}")
}
fn key_perm_account(account: &AccountId, perm: &permission::Permission) -> AccessKey {
    format!("perm.account:{}:{}", account, perm.name())
}
fn key_perm_role(role: &RoleId, perm: &permission::Permission) -> AccessKey {
    format!("perm.role:{}:{}", role, perm.name())
}
fn add_role_rw(set: &mut AccessSet, id: &RoleId) {
    let k = key_role(id);
    set.add_read(k.clone());
    set.add_write(k);
}
fn key_trigger(id: &TriggerId) -> AccessKey {
    format!("trigger:{id}")
}
fn key_trigger_repetitions(id: &TriggerId) -> AccessKey {
    format!("trigger.repetitions:{id}")
}
fn key_public_lane_validator(lane: LaneId, validator: &AccountId) -> AccessKey {
    format!("nexus.validator:{lane}:{validator}")
}
fn add_public_lane_validator_rw(set: &mut AccessSet, lane: LaneId, validator: &AccountId) {
    let k = key_public_lane_validator(lane, validator);
    set.add_read(k.clone());
    set.add_write(k);
}
fn add_trigger_rw(set: &mut AccessSet, id: &TriggerId) {
    let key = key_trigger(id);
    set.add_read(key.clone());
    set.add_write(key);
    set.add_write(key_trigger_repetitions(id));
}
fn tx_gas_limit(tx: &SignedTransaction) -> Result<u64, String> {
    transaction_gas_limit(tx).ok_or_else(|| "missing gas limit in fee payment intent".to_owned())
}
fn derive_from_ivm_dynamic<R>(
    bytecode: &[u8],
    authority: &AccountId,
    metadata: &Metadata,
    state_ro: &R,
    gas_limit: u64,
    artifact_id: ContractArtifactId,
) -> Result<AccessSet, crate::execution_attempt::ExecutionAttemptError<String>>
where
    R: StateReadOnly + QueryStateSource,
{
    let selector = crate::executor::requested_contract_entrypoint(metadata)
        .map_err(|error| error.to_string())?;
    let authorization = if let Some(selector) = selector.as_deref() {
        let code_hash = ivm::contract_code_hash(bytecode);
        let identity = crate::executor::require_raw_contract_runtime_identity(
            state_ro.world(),
            code_hash,
            metadata,
        )
        .map_err(|error| error.to_string())?;
        let prepared = dynamic_execution::prepare(&state_ro.prepared_contract_cache(), bytecode)?;
        if prepared.code_hash() != identity.code_hash {
            return Err(
                ("raw contract bytecode no longer matches its live binding".to_owned()).into(),
            );
        }
        Some(
            crate::executor::authorize_prepared_raw_contract_selector(
                state_ro.world(),
                authority,
                &prepared,
                selector,
                &identity,
            )
            .map_err(|error| error.to_string())?,
        )
    } else {
        crate::smartcontracts::ivm::validate_generic_execution_context(
            state_ro.world(),
            metadata,
            artifact_id,
        )
        .map_err(|error| error.to_string())?;
        None
    };
    let contract_call_context =
        parse_contract_call_execution_context(metadata, bytecode, gas_limit, authorization)?;
    derive_from_ivm_dynamic_with_context(
        bytecode,
        authority,
        contract_call_context,
        state_ro,
        gas_limit,
    )
}
fn derive_from_prepared_ivm_dynamic<R>(
    contract: &ivm::PreparedContract,
    authority: &AccountId,
    metadata: &Metadata,
    state_ro: &R,
    gas_limit: u64,
    artifact_id: ContractArtifactId,
) -> Result<AccessSet, crate::execution_attempt::ExecutionAttemptError<String>>
where
    R: StateReadOnly + QueryStateSource,
{
    let selector = crate::executor::requested_contract_entrypoint(metadata)
        .map_err(|error| error.to_string())?;
    let authorization = if let Some(selector) = selector.as_deref() {
        let identity = crate::executor::require_raw_contract_runtime_identity(
            state_ro.world(),
            contract.code_hash(),
            metadata,
        )
        .map_err(|error| error.to_string())?;
        Some(
            crate::executor::authorize_prepared_raw_contract_selector(
                state_ro.world(),
                authority,
                contract,
                selector,
                &identity,
            )
            .map_err(|error| error.to_string())?,
        )
    } else {
        crate::smartcontracts::ivm::validate_generic_execution_context(
            state_ro.world(),
            metadata,
            artifact_id,
        )
        .map_err(|error| error.to_string())?;
        None
    };
    let contract_call_context = parse_prepared_contract_call_execution_context(
        metadata,
        contract,
        gas_limit,
        authorization,
    )?;
    derive_from_prepared_ivm_dynamic_with_context(
        contract,
        authority,
        contract_call_context,
        state_ro,
        gas_limit,
    )
}
#[derive(Clone, Copy)]
enum DynamicIvmProgram<'a> {
    Raw(&'a [u8]),
    Prepared(&'a ivm::PreparedContract),
}
fn derive_from_ivm_dynamic_with_context<R>(
    bytecode: &[u8],
    authority: &AccountId,
    contract_call_context: Option<ContractCallExecutionContext>,
    state_ro: &R,
    gas_limit: u64,
) -> Result<AccessSet, crate::execution_attempt::ExecutionAttemptError<String>>
where
    R: StateReadOnly + QueryStateSource,
{
    derive_from_ivm_dynamic_with_source(
        DynamicIvmProgram::Raw(bytecode),
        authority,
        contract_call_context,
        state_ro,
        gas_limit,
    )
}
fn derive_from_prepared_ivm_dynamic_with_context<R>(
    contract: &ivm::PreparedContract,
    authority: &AccountId,
    contract_call_context: Option<ContractCallExecutionContext>,
    state_ro: &R,
    gas_limit: u64,
) -> Result<AccessSet, crate::execution_attempt::ExecutionAttemptError<String>>
where
    R: StateReadOnly + QueryStateSource,
{
    derive_from_ivm_dynamic_with_source(
        DynamicIvmProgram::Prepared(contract),
        authority,
        contract_call_context,
        state_ro,
        gas_limit,
    )
}
fn derive_from_ivm_dynamic_with_source<R>(
    program: DynamicIvmProgram<'_>,
    authority: &AccountId,
    contract_call_context: Option<ContractCallExecutionContext>,
    state_ro: &R,
    gas_limit: u64,
) -> Result<AccessSet, crate::execution_attempt::ExecutionAttemptError<String>>
where
    R: StateReadOnly + QueryStateSource,
{
    // Execute VM with CoreHost to collect queued ISIs; do not apply.
    if let DynamicIvmProgram::Raw(bytecode) = program {
        ivm::ProgramMetadata::parse(bytecode)
            .map_err(|error| dynamic_execution::vm_error("ivm.metadata", error))?;
    }
    if let Some(context) = contract_call_context.as_ref() {
        match (&context.entrypoint, &context.authorization) {
            (Some(entrypoint), Some(authorization)) => {
                if authorization.entrypoint != *entrypoint
                    || authorization.authorization != context.entrypoint_authorization
                {
                    return Err(
                        ("contract prepass authorization does not match the selected entrypoint"
                            .to_owned())
                        .into(),
                    );
                }
                authorization
                    .validate_for_authority(state_ro.world(), authority)
                    .map_err(|error| error.to_string())?;
            }
            (Some(_), None) => {
                return Err(
                    ("contract entrypoint prepass requires an authorized live contract binding"
                        .to_owned())
                    .into(),
                );
            }
            (None, Some(_)) => {
                return Err(
                    ("generic IVM prepass must not carry contract entrypoint authorization"
                        .to_owned())
                    .into(),
                );
            }
            (None, None) => {}
        }
    }
    let cache = state_ro.prepared_contract_cache();
    let mut vm = dynamic_execution::new_vm(&cache, gas_limit)?;
    let heap_limit = state_ro
        .world()
        .parameters()
        .smart_contract()
        .memory()
        .get();
    vm.memory
        .set_heap_max_limit(heap_limit)
        .map_err(|error| dynamic_execution::vm_error("ivm.heap_limit", error))?;
    // Supply accounts snapshot for vendor helpers to become deterministic.
    let accounts = state_ro.accounts_snapshot();
    let mut host = if let Some(context) = contract_call_context.as_ref() {
        crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts_and_argument_record(
            authority.clone(),
            Arc::clone(&accounts),
            context.argument_record.clone(),
        )
    } else {
        crate::smartcontracts::ivm::host::CoreHostImpl::with_accounts(
            authority.clone(),
            Arc::clone(&accounts),
        )
    }
    .with_access_logging();
    host.set_output_limits_from_parameters(state_ro.world().parameters().smart_contract());
    host.set_prepared_contract_cache(cache);
    host.hydrate_axt_state(state_ro)
        .map_err(|e| format!("ivm.axt_state: {e}"))?;
    #[cfg(feature = "telemetry")]
    host.set_telemetry(state_ro.metrics().clone());
    host.set_crypto_config(state_ro.crypto());
    host.set_zk_config(state_ro.zk());
    host.set_public_inputs_from_parameters(state_ro.world().parameters());
    host.set_vrf_epoch_seeds_from_state(state_ro)?;
    host.set_query_state(state_ro);
    host.set_chain_id(state_ro.chain_id());
    if let Some(authorization) = contract_call_context
        .as_ref()
        .and_then(|context| context.authorization.as_ref())
    {
        let contract_subject = crate::smartcontracts::code::bound_contract_subject_from_world(
            state_ro.world(),
            &authorization.contract_address,
        )
        .ok_or_else(|| {
            format!(
                "contract instance `{}` has no valid subject binding",
                authorization.contract_address
            )
        })?;
        host.bind_contract_runtime_context(contract_subject, authorization.clone());
    } else {
        host.set_generic_execution();
    }
    host.set_zk_snapshots_from_world(state_ro.world(), state_ro.zk())
        .map_err(|error| dynamic_execution::vm_error("ivm.zk_snapshots", error))?;
    host.begin_tx(&ivm::parallel::StateAccessSet::default())
        .map_err(|error| dynamic_execution::vm_error("ivm.begin_tx", error))?;
    match program {
        DynamicIvmProgram::Raw(bytecode) => vm
            .load_program(bytecode)
            .map_err(|error| dynamic_execution::vm_error("ivm.load_program", error))?,
        DynamicIvmProgram::Prepared(contract) => vm
            .load_prepared(contract)
            .map_err(|error| dynamic_execution::vm_error("ivm.load_prepared", error))?,
    }
    vm.set_gas_limit(gas_limit);
    apply_contract_call_execution_context(&mut vm, contract_call_context.as_ref())
        .map_err(|e| format!("ivm.contract_call: {e}"))?;
    vm.run_with_host(&mut host)
        .and_then(|()| host.finish_contract_result(&vm).map(|_| ()))
        .map_err(|error| dynamic_execution::vm_error("ivm.run", error))?;
    let mut set = AccessSet::new();
    let mut access_log: Option<ivm::host::AccessLog> = None;
    let max_depth = u16::from(
        state_ro
            .world()
            .parameters()
            .smart_contract()
            .execution_depth(),
    );
    let mut visited_triggers = BTreeSet::new();
    for isi in host.drain_instructions() {
        set.union_with(derive_from_instruction(
            &isi,
            Some(state_ro),
            &mut visited_triggers,
            0,
            max_depth,
        ));
    }
    if host.access_logging_supported() {
        access_log = Some(
            host.finish_tx()
                .map_err(|error| dynamic_execution::vm_error("ivm.finish_tx", error))?,
        );
    }
    if let Some(log) = access_log {
        merge_access_log(&mut set, &log);
    }
    if contract_call_context.as_ref().is_some_and(|context| {
        context.entrypoint_authorization != EntrypointAuthorizationV1::Anyone
    }) {
        set.add_read(AUTHORIZATION_EPOCH_KEY.to_owned());
    }
    if set.read_keys.is_empty() && set.write_keys.is_empty() {
        // No syscalls or only helper syscalls: be conservative.
        return Ok(AccessSet::global());
    }
    Ok(set)
}
fn merge_access_log(set: &mut AccessSet, log: &ivm::host::AccessLog) {
    for key in &log.read_keys {
        set.add_read(access_key_from_state_log(key));
    }
    for key in &log.write_keys {
        set.add_write(access_key_from_state_log(key));
    }
}
fn access_key_from_state_log(key: &str) -> AccessKey {
    if key.starts_with("state:") {
        key.to_owned()
    } else {
        format!("state:{key}")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::Execute;
    use crate::state::{State, World};
    use iroha_data_model::{
        isi::Log,
        level::Level,
        transaction::{
            Executable, ExecutableBatchItem, IvmBytecode, PREPARED_FAUCET_OPERATION,
            TransactionBuilder,
        },
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::state_path::StatePath;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::json::Json;
    const LITERAL_SECTION_MAGIC: [u8; 4] = *b"LTLB";
    const TEST_GAS_LIMIT: u64 = 50_000_000;
    fn test_network_id() -> iroha_data_model::NetworkId {
        iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"pipeline-access-test-genesis"),
        ))
    }
    fn wonderland_domain_id() -> DomainId {
        DomainId::try_new("wonderland", "universal").expect("static domain id")
    }
    fn new_wonderland_account(account_id: &AccountId) -> iroha_data_model::account::NewAccount {
        Account::new(account_id.clone())
    }
    fn build_wonderland_account(account_id: &AccountId) -> Account {
        new_wonderland_account(account_id).build(account_id)
    }
    fn bridge_proof_fixture(seed: u8) -> iroha_data_model::bridge::BridgeProof {
        iroha_data_model::bridge::BridgeProof {
            range: iroha_data_model::bridge::BridgeProofRange {
                start_height: 20 + u64::from(seed),
                end_height: 20 + u64::from(seed),
            },
            payload: iroha_data_model::bridge::BridgeProofPayload::TransparentZk(
                iroha_data_model::bridge::BridgeTransparentProof {
                    verifier_manifest_hash: [0xB0 | (seed & 0x0F); 32],
                    proof: iroha_data_model::proof::ProofBox::new(
                        format!("halo2/mock/{seed}").into(),
                        vec![0xCA, 0xFE, seed],
                    ),
                    recursion_depth: Some(1),
                },
            ),
        }
    }
    fn bridge_receipt_fixture(proof_hash: [u8; 32]) -> iroha_data_model::bridge::BridgeReceipt {
        iroha_data_model::bridge::BridgeReceipt {
            lane: LaneId::SINGLE,
            direction: b"mint".to_vec(),
            source_tx: [0x11; 32],
            dest_tx: None,
            proof_hash,
            amount: 1_u64.into(),
            asset_id: b"wBTC#btc".to_vec(),
            recipient: b"alice@main".to_vec(),
        }
    }
    fn fixture_callable(code: &[u8], pc: u64) -> ivm::call::EmbeddedCallableV1 {
        use ivm::instruction::wide;
        let mut callable = crate::ivm_test_support::unit_callable(pc);
        if let Some(bytes) = code.get(pc as usize..pc as usize + 4) {
            let word = u32::from_le_bytes(bytes.try_into().expect("instruction word"));
            if wide::opcode(word) == wide::arithmetic::ADDI
                && wide::rd(word) == 31
                && wide::rs1(word) == 31
                && wide::imm8(word) < 0
            {
                callable.frame_bytes = u32::from(wide::imm8(word).unsigned_abs());
            }
        }
        callable
    }
    fn literal_clobber_call_program(long_call: bool, fresh_literal: bool) -> Vec<u8> {
        use ivm::{encoding::wide as enc, instruction::wide};
        // r16 is caller-clobbered. Descriptor staging does not erase its literal,
        // so provenance must be invalidated specifically at the direct call.
        let mut words = vec![
            enc::encode_ri(wide::arithmetic::ADDI, 31, 31, -32),
            enc::encode_store(wide::memory::STORE64, 31, 1, 0),
            enc::encode_store(wide::memory::STORE64, 31, 12, 8),
            enc::encode_literal(wide::memory::LDLIT, 16, 0),
            enc::encode_ri(wide::arithmetic::ADDI, 10, 0, 0),
            enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 0),
            enc::encode_ri(wide::arithmetic::ADDI, 12, 31, 16),
            enc::encode_ri(wide::arithmetic::ADDI, 13, 0, 1),
            0,
            if fresh_literal {
                enc::encode_literal(wide::memory::LDLIT, 10, 0)
            } else {
                enc::encode_ri(wide::arithmetic::ADDI, 10, 16, 0)
            },
            enc::encode_syscallx(ivm::syscalls::SYSCALL_STATE_SET),
            enc::encode_load(wide::memory::LOAD64, 12, 31, 8),
            enc::encode_store(wide::memory::STORE64, 12, 0, 0),
            enc::encode_ri(wide::arithmetic::ADDI, 10, 12, 0),
            enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 1),
            enc::encode_load(wide::memory::LOAD64, 1, 31, 0),
            enc::encode_ri(wide::arithmetic::ADDI, 31, 31, 32),
            enc::encode_rr(wide::control::JALR, 0, 1, 0),
            enc::encode_literal(wide::memory::LDLIT, 16, 1),
        ];
        words[8] = if long_call {
            enc::encode_offset24(wide::control::JALS, 10)
        } else {
            enc::encode_jump(wide::control::JAL, 1, 10)
        };
        let mut code = words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        code.extend_from_slice(&crate::ivm_test_support::unit_return());
        code
    }
    fn test_contract_artifact(
        code: Vec<u8>,
        access_set_hints: Option<iroha_data_model::smart_contract::manifest::AccessSetHints>,
        entrypoints: Vec<EntrypointDescriptor>,
    ) -> (Vec<u8>, IrohaHash, ContractManifest) {
        test_contract_artifact_with_literals(code, access_set_hints, entrypoints, &[])
    }
    fn test_contract_artifact_with_literals(
        code: Vec<u8>,
        access_set_hints: Option<iroha_data_model::smart_contract::manifest::AccessSetHints>,
        entrypoints: Vec<EntrypointDescriptor>,
        literals: &[Vec<u8>],
    ) -> (Vec<u8>, IrohaHash, ContractManifest) {
        let meta = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 10_000,
            abi_version: 1,
        };
        let embedded_entrypoints = entrypoints
            .iter()
            .map(|entrypoint| ivm::EmbeddedEntrypointDescriptor {
                name: entrypoint.name.clone(),
                kind: entrypoint.kind,
                params: entrypoint.params.clone(),
                argument_schema: entrypoint.argument_schema.clone(),
                return_type: entrypoint.return_type.clone(),
                return_schema: entrypoint.return_schema.clone(),
                authorization: entrypoint.authorization.clone(),
                read_keys: entrypoint.read_keys.clone(),
                write_keys: entrypoint.write_keys.clone(),
                access_hints_complete: entrypoint.access_hints_complete,
                access_hints_skipped: entrypoint.access_hints_skipped.clone(),
                triggers: entrypoint.triggers.clone(),
                entry_pc: 0,
            })
            .collect();
        let mut callables = std::collections::BTreeMap::new();
        callables.insert(0, fixture_callable(&code, 0));
        for (index, bytes) in code.chunks_exact(4).enumerate() {
            use ivm::instruction::wide;
            let word = u32::from_le_bytes(bytes.try_into().expect("instruction word"));
            let offset = match wide::opcode(word) {
                wide::control::JALS => i64::from(wide::imm24(word)),
                wide::control::JAL if wide::rd(word) == 1 => i64::from(wide::imm16(word)),
                _ => continue,
            };
            let target = (index as u64 * 4)
                .checked_add_signed(offset * 4)
                .expect("call target");
            callables.insert(target, fixture_callable(&code, target));
        }
        let interface = ivm::EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: entrypoints.iter().filter_map(|entry| match &entry.authorization {
                EntrypointAuthorizationV1::Permission(name) => Some(name.clone()),
                _ => None,
            }).collect::<std::collections::BTreeSet<_>>().into_iter().map(|name|
                iroha_data_model::smart_contract::manifest::ContractPermissionDescriptorV1 {
                    name,
                    scope: iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1::Instance,
                }
            ).collect(),
            callables: callables.into_values().collect(),
            seiyaku_name: "TestContract".to_owned(),
            compiler_fingerprint: "access-test".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints,
            kotoba: Vec::new(),
            entrypoints: embedded_entrypoints,
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let mut artifact = meta.encode();
        let interface = interface.encode_section();
        artifact.extend_from_slice(&interface);
        if !literals.is_empty() {
            let descriptor_bytes = literals
                .len()
                .checked_mul(core::mem::size_of::<u64>())
                .expect("test literal descriptor length");
            let literal_data_len = literals
                .iter()
                .try_fold(0_usize, |total, literal| total.checked_add(literal.len()))
                .expect("test literal data length");
            let prefix_without_padding = interface
                .len()
                .checked_add(16)
                .and_then(|len| len.checked_add(descriptor_bytes))
                .and_then(|len| len.checked_add(literal_data_len))
                .expect("test literal prefix length");
            let post_padding = (4 - (prefix_without_padding % 4)) % 4;
            artifact.extend_from_slice(&LITERAL_SECTION_MAGIC);
            artifact.extend_from_slice(
                &u32::try_from(literals.len())
                    .expect("test literal count")
                    .to_le_bytes(),
            );
            artifact.extend_from_slice(
                &u32::try_from(post_padding)
                    .expect("test literal padding")
                    .to_le_bytes(),
            );
            artifact.extend_from_slice(
                &u32::try_from(literal_data_len)
                    .expect("test literal data length")
                    .to_le_bytes(),
            );
            let mut relative_offset = 16_usize
                .checked_add(descriptor_bytes)
                .expect("test literal data offset");
            for literal in literals {
                let descriptor = ivm::encode_literal_descriptor(
                    ivm::LiteralKindV1::PointerTlv,
                    u64::try_from(relative_offset).expect("test literal offset"),
                )
                .expect("test literal descriptor");
                artifact.extend_from_slice(&descriptor.to_le_bytes());
                relative_offset = relative_offset
                    .checked_add(literal.len())
                    .expect("next test literal offset");
            }
            for literal in literals {
                artifact.extend_from_slice(literal);
            }
            artifact.extend(std::iter::repeat_n(0, post_padding));
        }
        artifact.extend_from_slice(&code);
        let verified = ivm::verify_contract_artifact(&artifact).expect("valid test artifact");
        (artifact, verified.code_hash, verified.manifest)
    }
    fn default_test_entrypoint() -> EntrypointDescriptor {
        EntrypointDescriptor {
            name: "main".to_owned(),
            kind: iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: EntrypointAuthorizationV1::Permission("ExecuteContract".parse().unwrap()),
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
        }
    }
    #[test]
    fn select_entrypoint_requires_an_explicit_selector() {
        let mut main = default_test_entrypoint();
        main.read_keys = vec!["state:main".to_owned()];
        let mut run = default_test_entrypoint();
        run.name = "run".to_owned();
        run.read_keys = vec!["state:run".to_owned()];
        let mut hajimari = default_test_entrypoint();
        hajimari.name = "hajimari".to_owned();
        hajimari.kind = iroha_data_model::smart_contract::manifest::EntryPointKind::Hajimari;
        hajimari.read_keys = vec!["state:hajimari".to_owned()];
        let mut view_main = default_test_entrypoint();
        view_main.kind = iroha_data_model::smart_contract::manifest::EntryPointKind::View;
        let entrypoints = vec![run.clone(), hajimari.clone(), main.clone()];
        assert!(select_entrypoint(&entrypoints, None).is_none());
        assert_eq!(
            select_entrypoint(&entrypoints, Some("run")).map(|entrypoint| entrypoint.name.as_str()),
            Some("run")
        );
        let non_main_entrypoints = vec![run, hajimari];
        assert!(select_entrypoint(&non_main_entrypoints, None).is_none());
        assert!(select_entrypoint(&[view_main], None).is_none());
    }
    #[test]
    fn duplicate_faucet_claims_share_one_scheduler_write_key() {
        let (authority, keypair) = iroha_test_samples::gen_account_in("wonderland");
        let (destination, _) = iroha_test_samples::gen_account_in("destination");
        let definition_id = AssetDefinitionId::derive_from_components(
            wonderland_domain_id(),
            "faucet".parse().expect("faucet asset name"),
        );
        let source_asset_id = AssetId::new(definition_id, authority.clone());
        let marked = |instruction: InstructionBox| {
            let mut metadata = Metadata::default();
            metadata.insert(
                iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY
                    .parse()
                    .expect("marker version key"),
                Json::new(iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_V1),
            );
            metadata.insert(
                iroha_data_model::transaction::PREPARED_OPERATION_METADATA_KEY
                    .parse()
                    .expect("operation key"),
                Json::new(PREPARED_FAUCET_OPERATION.to_owned()),
            );
            metadata.insert(
                iroha_data_model::transaction::PREPARED_SEMANTIC_HASH_METADATA_KEY
                    .parse()
                    .expect("semantic key"),
                Json::new("ab".repeat(iroha_crypto::Hash::LENGTH)),
            );
            TransactionBuilder::new(
                test_network_id(),
                authority.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_metadata(metadata)
            .with_instructions([instruction])
            .sign(keypair.private_key())
        };
        let first = marked(
            Transfer::asset_quantity(source_asset_id.clone(), 1_u32, destination.clone()).into(),
        );
        let second =
            marked(Transfer::asset_quantity(source_asset_id, 2_u32, destination.clone()).into());
        assert_ne!(first.hash(), second.hash());
        let marker_key = crate::tx::faucet_claim_consumption_marker(&first)
            .expect("valid marker")
            .expect("present marker")
            .0;
        let expected = access_key_from_state_log(&marker_key.to_string());
        for transaction in [&first, &second] {
            let (set, _) = with_stateful_admission_keys(transaction, AccessSet::new(), None);
            assert!(
                set.write_keys.contains(&expected),
                "same authority and semantic claim must serialize through one marker key"
            );
        }

        let malformed = marked(Log::new(Level::INFO, "not a faucet transfer".to_owned()).into());
        let (set, _) = with_stateful_admission_keys(&malformed, AccessSet::new(), None);
        assert_eq!(
            set,
            AccessSet::global(),
            "invalid marker shapes must fail closed in scheduler admission"
        );
    }
    #[test]
    fn lifecycle_calls_write_the_instance_marker_scheduler_key() {
        let (authority, keypair) = iroha_test_samples::gen_account_in("wonderland");
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &test_network_id(),
            &authority,
            91,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let marker_key = access_key_from_state_log(
            crate::smartcontracts::code::contract_lifecycle_state_key(&contract_address).as_ref(),
        );
        for (entrypoint, writes_marker) in [
            ("run", false),
            ("hajimari", true),
            ("始まり", true),
            ("kaizen", true),
            ("改善", true),
        ] {
            let transaction = TransactionBuilder::new(
                test_network_id(),
                authority.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_executable(Executable::ContractCall(ContractInvocation {
                contract_address: contract_address.clone(),
                expected_code_hash: iroha_crypto::Hash::new(entrypoint.as_bytes()),
                entrypoint: entrypoint.to_owned(),
                arguments: None,
            }))
            .sign(keypair.private_key());
            let (set, _) = with_stateful_admission_keys(&transaction, AccessSet::new(), None);
            assert!(set.read_keys.contains(&marker_key));
            assert_eq!(
                set.write_keys.contains(&marker_key),
                writes_marker,
                "unexpected lifecycle marker mode for `{entrypoint}`"
            );
        }
    }
    #[test]
    fn mixed_executable_batch_forces_a_global_scheduler_barrier() {
        let (authority, keypair) = iroha_test_samples::gen_account_in("wonderland");
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &test_network_id(),
            &authority,
            92,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let transaction = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(InstructionBox::from(Log::new(
                    Level::INFO,
                    "before call".to_owned(),
                ))),
                ExecutableBatchItem::ContractCall(ContractInvocation {
                    contract_address,
                    expected_code_hash: iroha_crypto::Hash::new(b"mixed-batch"),
                    entrypoint: "main".to_owned(),
                    arguments: None,
                }),
            ]
            .into(),
        ))
        .sign(keypair.private_key());
        let (set, source) = derive_for_transaction_with_source::<crate::state::StateView<'_>>(
            &transaction,
            None,
            IvmStrategy::Conservative,
        );
        assert!(set.write_keys.contains("*"));
        assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
    }
    fn generic_state_get_test_program() -> Vec<u8> {
        let mut program = ivm::ProgramMetadata::default().encode();
        program.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_STATE_GET)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        program
    }
    fn state_get_test_program() -> Vec<u8> {
        let mut code = Vec::new();
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_STATE_GET)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&crate::ivm_test_support::unit_return());
        let mut entrypoint = default_test_entrypoint();
        entrypoint.read_keys = vec!["state:*".to_owned()];
        test_contract_artifact(code, None, vec![entrypoint]).0
    }
    fn generic_prepass_test_state(authority: &AccountId) -> State {
        let domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(authority);
        let account = build_wonderland_account(authority);
        State::new(
            crate::pipeline::overlay::test_support::with_global_root(World::with(
                [domain],
                [account],
                [],
            )),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        )
    }
    fn prepass_test_header() -> iroha_data_model::block::BlockHeader {
        // Execution uses its block's authenticated timestamp, including the
        // valid zero timestamp; a pre-genesis committed view has no anchor.
        iroha_data_model::block::BlockHeader::new(
            core::num::NonZeroU64::new(1).expect("genesis height"),
            None,
            None,
            0,
            0,
        )
    }
    #[test]
    fn dynamic_generic_prepass_enforces_contract_only_syscall_profile() {
        let (alice, _) = iroha_test_samples::gen_account_in("wonderland");
        let state = generic_prepass_test_state(&alice);
        let block = state.block(prepass_test_header());
        let metadata = Metadata::default();
        let error = derive_from_ivm_dynamic(
            &generic_state_get_test_program(),
            &alice,
            &metadata,
            &block,
            TEST_GAS_LIMIT,
            ContractArtifactId::new(
                DataSpaceId::UNIVERSAL,
                ivm::contract_code_hash(&generic_state_get_test_program()),
            ),
        )
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .expect_err("generic prepass must reject contract-owned durable-state access");
        assert!(
            error.contains("not allowed in a generic IVM program"),
            "unexpected generic prepass rejection: {error}"
        );
    }
    #[test]
    fn dynamic_generic_prepass_rejects_reserved_metadata_before_vm_execution() {
        let (alice, _) = iroha_test_samples::gen_account_in("wonderland");
        let state = generic_prepass_test_state(&alice);
        let mut halt = ivm::ProgramMetadata::default().encode();
        halt.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        for reserved_key in ["contract_payload", "contract_address", "contract_alias"] {
            let mut metadata = Metadata::default();
            metadata.insert(
                reserved_key.parse().expect("reserved metadata key"),
                iroha_primitives::json::Json::new("forged"),
            );
            let error = derive_from_ivm_dynamic(
                &halt,
                &alice,
                &metadata,
                &state.view(),
                TEST_GAS_LIMIT,
                ContractArtifactId::new(DataSpaceId::UNIVERSAL, ivm::contract_code_hash(&halt)),
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("generic prepass must reject contract provenance metadata");
            assert!(
                error.contains("generic IVM programs cannot carry") && error.contains(reserved_key),
                "unexpected rejection for `{reserved_key}`: {error}"
            );
        }
    }
    #[test]
    fn dynamic_generic_prepass_still_accepts_stateless_programs() {
        let (alice, _) = iroha_test_samples::gen_account_in("wonderland");
        let state = generic_prepass_test_state(&alice);
        let block = state.block(prepass_test_header());
        let mut halt = ivm::ProgramMetadata::default().encode();
        halt.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let set = derive_from_ivm_dynamic(
            &halt,
            &alice,
            &Metadata::default(),
            &block,
            TEST_GAS_LIMIT,
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, ivm::contract_code_hash(&halt)),
        )
        .expect("stateless generic prepass must remain executable");
        assert!(set.write_keys.contains("*"));
    }
    #[test]
    fn entrypoint_hints_require_explicit_complete_unskipped_attestation() {
        let program = state_get_test_program();
        let mut entrypoint = default_test_entrypoint();
        entrypoint.read_keys = vec!["state:alpha".to_owned()];
        entrypoint.write_keys = vec!["state:beta".to_owned()];
        assert!(
            entrypoint_access_set_from_bytecode_if_safe(&program, &entrypoint).is_none(),
            "exact CNTR keys are not a bytecode proof of the runtime state path"
        );
        entrypoint.read_keys = vec!["state:*".to_owned()];
        entrypoint.write_keys.clear();
        assert!(entrypoint_access_set_from_bytecode_if_safe(&program, &entrypoint).is_some());
        for completion in [None, Some(false)] {
            entrypoint.access_hints_complete = completion;
            assert!(entrypoint_access_set_from_bytecode_if_safe(&program, &entrypoint).is_none());
        }
        entrypoint.access_hints_complete = Some(true);
        entrypoint.access_hints_skipped = vec!["dynamic state path".to_owned()];
        assert!(entrypoint_access_set_from_bytecode_if_safe(&program, &entrypoint).is_none());
    }
    #[test]
    fn verified_empty_entrypoint_access_is_distinct_from_missing_or_incomplete_metadata() {
        let program = test_contract_artifact(
            crate::ivm_test_support::unit_return().to_vec(),
            None,
            vec![default_test_entrypoint()],
        )
        .0;
        let mut entrypoint = default_test_entrypoint();
        entrypoint.authorization = EntrypointAuthorizationV1::Anyone;
        let empty = entrypoint_access_set_from_bytecode_if_safe(&program, &entrypoint)
            .expect("complete empty hints over effect-free bytecode are verified");
        assert!(empty.read_keys.is_empty());
        assert!(empty.write_keys.is_empty());
        for completion in [None, Some(false)] {
            entrypoint.access_hints_complete = completion;
            assert!(
                entrypoint_access_set_from_bytecode_if_safe(&program, &entrypoint).is_none(),
                "missing or incomplete metadata must not certify an empty access set"
            );
        }
        entrypoint.access_hints_complete = Some(true);
        entrypoint.access_hints_skipped = vec!["unresolved access".to_owned()];
        assert!(entrypoint_access_set_from_bytecode_if_safe(&program, &entrypoint).is_none());
        entrypoint.access_hints_skipped.clear();
        assert!(
            entrypoint_access_set_from_bytecode_if_safe(&state_get_test_program(), &entrypoint,)
                .is_none(),
            "an empty claim must not hide a bytecode-derived state access"
        );
    }
    #[test]
    fn state_hint_coverage_distinguishes_exact_and_wildcard_keys() {
        assert!(state_claim_covers_key(
            "state:Counters/01",
            "state:Counters/01"
        ));
        assert!(!state_claim_covers_key(
            "state:Counters/01",
            "state:Counters/02"
        ));
        assert!(state_claim_covers_key(
            "state:Counters[*]",
            "state:Counters/02"
        ));
        assert!(!state_claim_covers_key(
            "state:Other[*]",
            "state:Counters/02"
        ));
        assert!(state_claim_covers_key("state:*", "state:Counters/02"));
    }
    #[test]
    fn protected_entrypoint_reads_the_authorization_scheduler_epoch() {
        let program = test_contract_artifact(
            crate::ivm_test_support::unit_return().to_vec(),
            None,
            vec![default_test_entrypoint()],
        )
        .0;
        let mut entrypoint = default_test_entrypoint();
        entrypoint.authorization =
            EntrypointAuthorizationV1::Permission("CanRunGuardedEntrypoint".parse().unwrap());
        entrypoint.read_keys = vec!["state:guard".to_owned()];
        let set = entrypoint_access_set_from_bytecode_if_safe(&program, &entrypoint)
            .expect("a complete local entrypoint has a static access set");
        assert!(
            set.read_keys.contains(AUTHORIZATION_EPOCH_KEY),
            "permission checks must conflict with every grant, revoke, and role mutation"
        );
    }
    #[test]
    fn dynamic_raw_contract_prepass_rejects_identityless_dispatch_before_argument_decode() {
        let (alice, _) = iroha_test_samples::gen_account_in("wonderland");
        let domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(World::with(
                [domain],
                [account],
                [],
            )),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let entrypoint = default_test_entrypoint();
        let code = crate::ivm_test_support::unit_return().to_vec();
        let (artifact, _, _) = test_contract_artifact(code, None, vec![entrypoint]);
        let mut metadata = Metadata::default();
        metadata.insert(
            "contract_entrypoint".parse().unwrap(),
            iroha_primitives::json::Json::new("main"),
        );
        metadata.insert(
            "contract_payload".parse().unwrap(),
            iroha_primitives::json::Json::new(1_u64),
        );
        ivm::reset_argument_record_decode_count();
        let error = derive_from_ivm_dynamic(
            &artifact,
            &alice,
            &metadata,
            &state.view(),
            TEST_GAS_LIMIT,
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, ivm::contract_code_hash(&artifact)),
        )
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .expect_err("selected raw contract entrypoints require a live instance identity");
        assert!(
            error.contains("requires a live contract_address or contract_alias binding"),
            "unexpected prepass rejection: {error}"
        );
        assert_eq!(
            ivm::argument_record_decode_count(),
            0,
            "authorization must fail before canonical argument decoding"
        );
    }
    #[test]
    fn incomplete_entrypoint_hints_do_not_fall_through_to_contract_hints() {
        use iroha_data_model::smart_contract::manifest::AccessSetHints;
        let program = state_get_test_program();
        let code_hash = ivm::contract_code_hash(&program);
        let contract_hints = AccessSetHints {
            read_keys: vec!["state:contract-read".to_owned()],
            write_keys: vec!["state:contract-write".to_owned()],
            dynamic_reads: Vec::new(),
            dynamic_writes: Vec::new(),
        };
        for (completion, skipped) in [
            (None, Vec::new()),
            (Some(false), Vec::new()),
            (Some(true), vec!["dynamic state path".to_owned()]),
        ] {
            let mut entrypoint = default_test_entrypoint();
            entrypoint.read_keys = vec!["state:entry-read".to_owned()];
            entrypoint.write_keys = vec!["state:entry-write".to_owned()];
            entrypoint.access_hints_complete = completion;
            entrypoint.access_hints_skipped = skipped;
            let manifest = ContractManifest {
                events: Vec::new(),
                enum_types: Vec::new(),
                permissions: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(code_hash),
                abi_hash: None,
                compiler_fingerprint: None,
                features_bitmap: None,
                access_set_hints: Some(contract_hints.clone()),
                entrypoints: Some(vec![entrypoint]),
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            };
            assert!(
                manifest_access_set_from_bytecode(
                    &manifest,
                    code_hash,
                    &program,
                    false,
                    Some("main")
                )
                .is_none()
            );
        }
    }
    #[test]
    fn dynamic_manifest_hints_are_not_scheduler_authoritative() {
        use iroha_data_model::smart_contract::manifest::{AccessSetHints, DynamicAccessHint};
        let program = state_get_test_program();
        let code_hash = ivm::contract_code_hash(&program);
        for dynamic_hint in [
            DynamicAccessHint {
                base_key: "state:Orders".to_owned(),
                key_type: "int".to_owned(),
                bound_kind: "take".to_owned(),
                max_keys: 1,
            },
            DynamicAccessHint {
                base_key: "state:Orders".to_owned(),
                key_type: "int".to_owned(),
                bound_kind: "page".to_owned(),
                max_keys: 64,
            },
            DynamicAccessHint {
                base_key: "state:Victim".to_owned(),
                key_type: "forged-key-type".to_owned(),
                bound_kind: "forged-exact-bound".to_owned(),
                max_keys: 1,
            },
            DynamicAccessHint {
                base_key: "state:Unrelated/forged-child".to_owned(),
                key_type: String::new(),
                bound_kind: String::new(),
                max_keys: u32::MAX,
            },
        ] {
            for hints in [
                AccessSetHints {
                    read_keys: Vec::new(),
                    write_keys: Vec::new(),
                    dynamic_reads: vec![dynamic_hint.clone()],
                    dynamic_writes: Vec::new(),
                },
                AccessSetHints {
                    read_keys: Vec::new(),
                    write_keys: Vec::new(),
                    dynamic_reads: Vec::new(),
                    dynamic_writes: vec![dynamic_hint.clone()],
                },
            ] {
                assert!(manifest_hint_access_set_from_bytecode_if_safe(&program, &hints).is_none());
                let manifest = ContractManifest {
                    events: Vec::new(),
                    enum_types: Vec::new(),
                    permissions: Vec::new(),
                    seiyaku_name: Some("DynamicHintsAreAdvisory".to_owned()),
                    code_hash: Some(code_hash),
                    abi_hash: None,
                    compiler_fingerprint: Some("malicious-cntr".to_owned()),
                    features_bitmap: Some(0),
                    access_set_hints: Some(hints),
                    entrypoints: None,
                    states: None,
                    kotoba: None,
                    error_messages: None,
                    error_types: None,
                    provenance: None,
                };
                assert!(
                    manifest_access_set_from_bytecode(&manifest, code_hash, &program, false, None)
                        .is_none(),
                    "dynamic base/key/bound claims must never become a scheduler access set"
                );
            }
        }
    }
    #[test]
    fn compiler_static_state_map_keys_are_bytecode_verified_and_exact() {
        let source = r#"
seiyaku StaticAccessCounter { permission CanWrite;
  state StateMap<int, int> Counters;

  kotoage fn write_one() authorize(CanWrite) { Counters[1] = 10; }
  kotoage fn write_two() authorize(CanWrite) { Counters[2] = 20; }
  kotoage fn write_one_again() authorize(CanWrite) { Counters[1] = 30; }
}
"#;
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile static-access contract");
        let code_hash = ivm::contract_code_hash(&program);
        let entrypoints = manifest
            .entrypoints
            .as_deref()
            .expect("compiler manifest entrypoints");
        let derive = |name: &str| {
            let descriptor = entrypoints
                .iter()
                .find(|entrypoint| entrypoint.name == name)
                .unwrap_or_else(|| panic!("missing `{name}` entrypoint"));
            assert_eq!(descriptor.access_hints_complete, Some(true));
            assert!(descriptor.access_hints_skipped.is_empty());
            assert_eq!(descriptor.write_keys.len(), 1);
            assert!(descriptor.write_keys[0].starts_with("state:Counters/"));
            assert_ne!(descriptor.write_keys[0], "state:Counters");
            assert_ne!(descriptor.write_keys[0], "state:*");
            manifest_access_set_from_bytecode(&manifest, code_hash, &program, false, Some(name))
                .unwrap_or_else(|| {
                    let prepared = ivm::prepare_contract(Arc::<[u8]>::from(program.clone()))
                        .expect("prepare static-access contract for failure diagnostics");
                    let analysis = ivm::analysis::analyze_prepared_static_state_accesses(
                        &prepared,
                        Some(name),
                        &static_state_test_budget(),
                    );
                    panic!("static bytecode proof rejected `{name}`: {analysis:?}")
                })
                .0
        };
        let one = derive("write_one");
        let two = derive("write_two");
        let one_again = derive("write_one_again");
        let one_key = one
            .write_keys
            .iter()
            .find(|key| key.starts_with("state:Counters/"))
            .expect("first exact StateMap key");
        let two_key = two
            .write_keys
            .iter()
            .find(|key| key.starts_with("state:Counters/"))
            .expect("second exact StateMap key");
        let one_again_key = one_again
            .write_keys
            .iter()
            .find(|key| key.starts_with("state:Counters/"))
            .expect("repeated exact StateMap key");
        assert_ne!(one_key, two_key, "distinct static keys were collapsed");
        assert_eq!(one_key, one_again_key, "the same key must canonicalize");
        for set in [&one, &two, &one_again] {
            assert!(!set.write_keys.contains("state:*"));
            assert!(!set.write_keys.contains("state:Counters"));
        }
    }
    #[test]
    fn repeated_prepared_manifest_access_does_not_reprepare_the_artifact() {
        use crate::smartcontracts::ivm::cache::IvmCache;
        let source = r#"
seiyaku WarmAccessCounter { permission CanWrite;
  state StateMap<int, int> Counters;

  kotoage fn write_one() authorize(CanWrite) { Counters[1] = 10; }
}
"#;
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile warm-access contract");
        let mut cache = IvmCache::with_capacity(2);
        let summary = cache
            .summarize_program(&program)
            .expect("prepare warm-access contract once");
        let artifact_allocation = summary.prepared_contract().artifact().as_ptr();
        let cache_before = cache.stats();
        let prepared_cache = cache.prepared_contract_cache();
        let prepared_before = prepared_cache.stats();
        let first = manifest_access_set(
            &manifest,
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, summary.code_hash),
            summary.prepared_contract(),
            false,
            Some("write_one"),
            prepared_cache.execution_budget(),
        )
        .expect("first prepared access derivation");
        let second = manifest_access_set(
            &manifest,
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, summary.code_hash),
            summary.prepared_contract(),
            false,
            Some("write_one"),
            prepared_cache.execution_budget(),
        )
        .expect("second prepared access derivation");
        assert_eq!(first, second);
        assert_eq!(
            summary.prepared_contract().artifact().as_ptr(),
            artifact_allocation,
            "access derivation must keep borrowing the shared artifact image"
        );
        assert_eq!(
            cache.stats(),
            cache_before,
            "prepared access derivation must not hash, parse, decode, load, or build a runtime template"
        );
        assert_eq!(
            prepared_cache.stats(),
            prepared_before,
            "prepared access derivation must not touch the artifact or runtime caches"
        );
    }
    #[test]
    fn helper_hidden_static_state_access_retains_state_wildcard_fence() {
        let source = r#"
seiyaku HelperStaticAccess { permission CanWrite;
  state StateMap<int, int> Counters;

  fn hidden_write() { Counters[1] = 10; }
  kotoage fn direct_write() authorize(CanWrite) { Counters[1] = 20; }
  kotoage fn helper_write() authorize(CanWrite) { hidden_write(); }
  // Two live callers retain the actual private helper edge under single-use inlining.
  kotoage fn second_helper_write() authorize(CanWrite) { hidden_write(); }
}
"#;
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile helper-static contract");
        let code_hash = ivm::contract_code_hash(&program);
        assert!(
            manifest_access_set_from_bytecode(
                &manifest,
                code_hash,
                &program,
                false,
                Some("direct_write"),
            )
            .is_some(),
            "direct literal access should retain its exact key"
        );
        assert!(
            manifest_access_set_from_bytecode(
                &manifest,
                code_hash,
                &program,
                false,
                Some("helper_write"),
            )
            .is_none(),
            "helper-hidden access must not be narrowed by transitive CNTR hints"
        );
        let mut fallback = AccessSet::new();
        assert!(apply_unverified_ivm_access_fence(&program, &mut fallback));
        assert!(fallback.write_keys.contains("state:*"));
        assert!(!fallback.write_keys.contains("*"));
    }
    #[test]
    fn helper_call_clobber_cannot_reuse_pre_call_literal_state_provenance() {
        let claimed_path: StatePath = "claimed".parse().expect("claimed state path");
        let runtime_path: StatePath = "runtime".parse().expect("runtime state path");
        let literals = [
            make_tlv(
                ivm::PointerType::NoritoBytes as u16,
                &norito::to_bytes(&claimed_path).expect("encode claimed path"),
            ),
            make_tlv(
                ivm::PointerType::NoritoBytes as u16,
                &norito::to_bytes(&runtime_path).expect("encode runtime path"),
            ),
        ];
        for (label, long_call) in [("JALS", true), ("JAL r1", false)] {
            let code = literal_clobber_call_program(long_call, false);
            let mut entrypoint = default_test_entrypoint();
            entrypoint.write_keys = vec!["state:claimed".to_owned()];
            let (program, code_hash, manifest) =
                test_contract_artifact_with_literals(code, None, vec![entrypoint], &literals);
            assert!(
                manifest_access_set_from_bytecode(
                    &manifest,
                    code_hash,
                    &program,
                    false,
                    Some("main"),
                )
                .is_none(),
                "{label} retained pre-call literal provenance and trusted a forged exact key"
            );
            let mut fallback = AccessSet::new();
            assert!(apply_unverified_ivm_access_fence(&program, &mut fallback));
            assert!(fallback.write_keys.contains("state:*"));
            assert!(!fallback.write_keys.contains("*"));
        }
    }
    #[test]
    fn fresh_authenticated_literal_after_helper_recovers_exact_state_provenance() {
        let claimed_path: StatePath = "claimed".parse().expect("claimed state path");
        let runtime_path: StatePath = "runtime".parse().expect("runtime state path");
        let literals = [
            make_tlv(
                ivm::PointerType::NoritoBytes as u16,
                &norito::to_bytes(&claimed_path).expect("encode claimed path"),
            ),
            make_tlv(
                ivm::PointerType::NoritoBytes as u16,
                &norito::to_bytes(&runtime_path).expect("encode runtime path"),
            ),
        ];
        for (label, long_call) in [("JALS", true), ("JAL r1", false)] {
            let code = literal_clobber_call_program(long_call, true);
            let mut entrypoint = default_test_entrypoint();
            entrypoint.write_keys = vec!["state:claimed".to_owned()];
            let (program, code_hash, manifest) =
                test_contract_artifact_with_literals(code, None, vec![entrypoint], &literals);
            let (set, _) = manifest_access_set_from_bytecode(
                &manifest,
                code_hash,
                &program,
                false,
                Some("main"),
            )
            .unwrap_or_else(|| {
                panic!("{label} failed to recover exact provenance after a fresh literal")
            });
            assert!(set.write_keys.contains("state:claimed"));
            assert!(!set.write_keys.contains("state:runtime"));
            assert!(!set.write_keys.contains("state:*"));
            assert!(!set.write_keys.contains("*"));
        }
    }
    #[test]
    fn compiler_dynamic_state_writes_and_helper_writes_fall_back_to_global() {
        let source = r#"
seiyaku DynamicAccessCounter { permission CanEnactGovernance;
  state StateMap<int, int> Counters;

  fn bump_hidden(int key, int delta) {
    let current = Counters.get(key).unwrap_or(0);
    Counters[key] = current + delta;
  }

  kotoage fn bump_direct(int key, int delta) authorize(CanEnactGovernance) {
    let current = Counters.get(key).unwrap_or(0);
    Counters[key] = current + delta;
  }

  kotoage fn bump_via_helper(int key, int delta) authorize(CanEnactGovernance) {
    bump_hidden(key: key, delta: delta);
  }
}
"#;
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile dynamic-access contract");
        let code_hash = ivm::contract_code_hash(&program);
        let entrypoints = manifest
            .entrypoints
            .as_deref()
            .expect("compiler manifest entrypoints");
        for entrypoint_name in ["bump_direct", "bump_via_helper"] {
            let mut forged = manifest.clone();
            let forged_entrypoint = forged
                .entrypoints
                .as_mut()
                .and_then(|entrypoints| {
                    entrypoints
                        .iter_mut()
                        .find(|entrypoint| entrypoint.name == entrypoint_name)
                })
                .expect("forged entrypoint");
            forged_entrypoint.read_keys = vec!["state:Counters/forged".to_owned()];
            forged_entrypoint.write_keys = vec!["state:Counters/forged".to_owned()];
            forged_entrypoint.access_hints_complete = Some(true);
            forged_entrypoint.access_hints_skipped.clear();
            assert!(
                manifest_access_set_from_bytecode(
                    &forged,
                    code_hash,
                    &program,
                    false,
                    Some(entrypoint_name),
                )
                .is_none(),
                "forged exact hints narrowed dynamic `{entrypoint_name}` bytecode"
            );
        }
        for entrypoint_name in ["bump_direct", "bump_via_helper"] {
            let entrypoint = entrypoints
                .iter()
                .find(|entrypoint| entrypoint.name == entrypoint_name)
                .unwrap_or_else(|| panic!("missing `{entrypoint_name}` entrypoint"));
            assert_eq!(entrypoint.access_hints_complete, Some(false));
            assert_eq!(
                entrypoint.access_hints_skipped,
                vec!["dynamic state path is not compiler-resolved".to_owned()]
            );
            assert!(entrypoint.read_keys.contains(&"state:*".to_owned()));
            assert!(entrypoint.write_keys.contains(&"state:*".to_owned()));
            assert!(
                manifest_access_set_from_bytecode(
                    &manifest,
                    code_hash,
                    &program,
                    false,
                    Some(entrypoint_name),
                )
                .is_none(),
                "dynamic StateMap base hints must not be trusted as exact scheduler keys"
            );
        }
        let (alice, key_pair) = iroha_test_samples::gen_account_in("wonderland");
        for entrypoint_name in ["bump_direct", "bump_via_helper"] {
            let mut metadata = Metadata::default();
            metadata.insert(
                MANIFEST_METADATA_KEY
                    .parse()
                    .expect("manifest metadata key"),
                iroha_primitives::json::Json::new(manifest.clone()),
            );
            metadata.insert(
                "contract_entrypoint"
                    .parse()
                    .expect("contract entrypoint metadata key"),
                iroha_primitives::json::Json::new(entrypoint_name.to_owned()),
            );
            let transaction = TransactionBuilder::new(
                test_network_id(),
                alice.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(
                    Vec::new(),
                    core::num::NonZeroU64::new(TEST_GAS_LIMIT),
                ),
            )
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program.clone())))
            .sign(key_pair.private_key());
            let (set, source) = derive_for_transaction_with_source::<crate::state::StateView<'_>>(
                &transaction,
                None,
                IvmStrategy::Conservative,
            );
            assert!(set.write_keys.contains("*"));
            assert!(!set.write_keys.contains("state:Counters"));
            assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
        }
    }
    fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
        v.extend_from_slice(&type_id.to_be_bytes());
        v.push(1u8); // version
        let payload_len =
            u32::try_from(payload.len()).expect("payload length must fit into u32 for TLV");
        v.extend_from_slice(&payload_len.to_be_bytes());
        v.extend_from_slice(payload);
        let h: [u8; 32] = IrohaHash::new(payload).into();
        v.extend_from_slice(&h);
        v
    }
    #[test]
    fn isi_access_transfer_and_mint() {
        let (alice, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
        let (bob, _) = iroha_test_samples::gen_account_in("wonderland");
        let ad: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "coin".parse().unwrap(),
            );
        let src = AssetId::of(ad.clone(), alice.clone());
        let isis: Vec<iroha_data_model::isi::InstructionBox> = vec![
            Mint::asset_quantity(10u32, src.clone()).into(),
            Transfer::asset_quantity(src.clone(), 5u32, bob.clone()).into(),
        ];
        let exec = Executable::from_iter(isis);
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(exec)
        .sign(alice_keypair.private_key());
        let set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            None,
            IvmStrategy::Conservative,
        );
        assert!(set.write_keys.contains("*"));
    }
    #[test]
    fn simple_asset_transfer_batch_fast_path_matches_generic_walker() {
        let (alice, _) = iroha_test_samples::gen_account_in("wonderland");
        let (bob, _) = iroha_test_samples::gen_account_in("wonderland");
        let (carol, _) = iroha_test_samples::gen_account_in("wonderland");
        let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
        let alice_asset = AssetId::of(asset_definition.clone(), alice.clone());
        let bob_asset = AssetId::of(asset_definition, bob.clone());
        let batch: Vec<InstructionBox> = vec![
            Transfer::asset_quantity(alice_asset, 5_u32, bob).into(),
            Transfer::asset_quantity(bob_asset, 2_u32, carol).into(),
        ];
        let fast = derive_simple_asset_transfer_batch(&batch)
            .expect("simple asset transfers should use the fast path");
        let mut generic = AccessSet::new();
        let mut visited_triggers = BTreeSet::new();
        for instruction in &batch {
            generic.union_with(derive_from_instruction(
                instruction,
                None::<&crate::state::StateView<'_>>,
                &mut visited_triggers,
                0,
                0,
            ));
        }
        assert_eq!(fast, generic);
        assert!(fast.write_keys.contains("*"));
        assert!(
            derive_simple_asset_transfer_batch(&[Log::new(Level::INFO, "noop".into()).into()])
                .is_none()
        );
    }
    #[test]
    fn log_instruction_has_no_access_keys() {
        let (alice, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "hello".to_owned())])
        .sign(alice_keypair.private_key());
        let authority = tx.authority().clone();
        let set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            None,
            IvmStrategy::Conservative,
        );
        assert_eq!(set.read_keys, [format!("account:{authority}")].into());
        assert_eq!(set.write_keys, [format!("tx.sequence:{authority}")].into());
    }
    #[test]
    fn submit_bridge_proof_access_uses_canonical_proof_hash() {
        let proof = bridge_proof_fixture(5);
        let expected_hash = bridge_proof_hash(&proof).expect("fixture proof should encode");
        let instruction =
            InstructionBox::from(iroha_data_model::isi::bridge::SubmitBridgeProof::new(proof));
        let mut visited_triggers = BTreeSet::new();
        let set = derive_from_instruction(
            &instruction,
            None::<&crate::state::StateView<'_>>,
            &mut visited_triggers,
            0,
            0,
        );
        assert!(set.read_keys.is_empty());
        assert_eq!(
            set.write_keys,
            BTreeSet::from([
                key_bridge_proof_hash(&expected_hash),
                key_bridge_backend(&bridge_proof_fixture(5).backend_label())
            ])
        );
    }
    #[test]
    fn bridge_receipt_access_conflicts_with_submitted_proof_hash() {
        let proof = bridge_proof_fixture(6);
        let proof_hash = bridge_proof_hash(&proof).expect("fixture proof should encode");
        let submit =
            InstructionBox::from(iroha_data_model::isi::bridge::SubmitBridgeProof::new(proof));
        let receipt =
            InstructionBox::from(iroha_data_model::isi::bridge::RecordBridgeReceipt::new(
                bridge_receipt_fixture(proof_hash),
            ));
        let expected_key = key_bridge_proof_hash(&proof_hash);
        let mut visited_triggers = BTreeSet::new();
        let submit_set = derive_from_instruction(
            &submit,
            None::<&crate::state::StateView<'_>>,
            &mut visited_triggers,
            0,
            0,
        );
        assert!(!submit_set.read_keys.contains(NEXUS_ACTIVE_LANE_CATALOG_KEY));
        assert!(submit_set.write_keys.contains(&expected_key));
        let mut visited_triggers = BTreeSet::new();
        let receipt_set = derive_from_instruction(
            &receipt,
            None::<&crate::state::StateView<'_>>,
            &mut visited_triggers,
            0,
            0,
        );
        assert!(
            receipt_set
                .read_keys
                .contains(NEXUS_ACTIVE_LANE_CATALOG_KEY)
        );
        assert!(receipt_set.write_keys.contains(&expected_key));
    }
    #[test]
    fn register_access_includes_domain_reads() {
        let (alice, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
        let domain_id = wonderland_domain_id();
        let account = new_wonderland_account(&alice);
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "coin".parse().unwrap(),
            );
        let asset_def = AssetDefinition::numeric(
            asset_def_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        );
        let isis: Vec<iroha_data_model::isi::InstructionBox> = vec![
            Register::account(account).into(),
            Register::asset_definition(asset_def).into(),
        ];
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::from_iter(isis))
        .sign(alice_keypair.private_key());
        let set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            None,
            IvmStrategy::Conservative,
        );
        let k_domain = key_domain(&domain_id);
        let k_account = key_account(&alice);
        let k_asset_def = key_asset_def(&asset_def_id);
        assert!(set.read_keys.contains(&k_domain));
        assert!(set.read_keys.contains(&k_account));
        assert!(set.write_keys.contains(&k_account));
        assert!(set.read_keys.contains(&k_asset_def));
        assert!(set.write_keys.contains(&k_asset_def));
    }
    #[test]
    fn register_asset_definition_reads_explicit_owner_and_alias_route_independently() {
        let owner_domain = DomainId::try_new("owner", "universal").expect("owner domain");
        let alias_domain = DomainId::try_new("route", "universal").expect("alias domain");
        let id_domain = wonderland_domain_id();
        let definition_id = AssetDefinitionId::derive_from_components(
            id_domain.clone(),
            "coin".parse().expect("asset name"),
        );
        for (owner, alias) in [(false, false), (true, false), (false, true), (true, true)] {
            let definition = AssetDefinition::numeric(
                definition_id.clone(),
                "coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                owner.then(|| owner_domain.clone()),
            )
            .with_alias(alias.then(|| "coin#route.universal".parse().expect("asset alias")));
            let instruction = Register::asset_definition(definition).into();
            let set = derive_from_instruction(
                &instruction,
                None::<&crate::state::StateView<'_>>,
                &mut BTreeSet::new(),
                0,
                0,
            );
            assert_eq!(set.read_keys.contains(&key_domain(&owner_domain)), owner);
            assert_eq!(set.read_keys.contains(&key_domain(&alias_domain)), alias);
            assert!(
                !set.read_keys.contains(&key_domain(&id_domain)),
                "opaque asset identifiers do not establish domain ownership"
            );
        }
    }
    #[test]
    fn ivm_access_dynamic_prepass_set_account_detail_sentinel() {
        // World and state for view
        let (alice, kp) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let world = World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(world),
            kura,
            query,
        );
        let view = state.block(prepass_test_header());
        // Program: GET_AUTHORITY; INPUT_PUBLISH_TLV (key/value); SET_ACCOUNT_DETAIL; HALT
        let key: Name = "cursor".parse().expect("key name");
        let key_payload = norito::to_bytes(&key).expect("encode key");
        let value_json = iroha_primitives::json::Json::new(1u64);
        let value_payload = norito::to_bytes(&value_json).expect("encode value");
        let key_tlv = make_tlv(ivm::PointerType::Name as u16, &key_payload);
        let value_tlv = make_tlv(ivm::PointerType::Json as u16, &value_payload);
        let mut code = Vec::new();
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_GET_AUTHORITY)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(
            &kotodama_lang::compiler::encode_addi(13, 10, 0)
                .expect("encode addi")
                .to_le_bytes(),
        ); // save account ptr
        code.extend_from_slice(
            &ivm::encoding::wide::encode_literal(ivm::instruction::wide::memory::LDLIT, 10, 0)
                .to_le_bytes(),
        );
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_INPUT_PUBLISH_TLV)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(
            &kotodama_lang::compiler::encode_addi(11, 10, 0)
                .expect("encode addi")
                .to_le_bytes(),
        ); // r11 = key ptr
        code.extend_from_slice(
            &ivm::encoding::wide::encode_literal(ivm::instruction::wide::memory::LDLIT, 10, 1)
                .to_le_bytes(),
        );
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_INPUT_PUBLISH_TLV)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(
            &kotodama_lang::compiler::encode_addi(12, 10, 0)
                .expect("encode addi")
                .to_le_bytes(),
        ); // r12 = value ptr
        code.extend_from_slice(
            &kotodama_lang::compiler::encode_addi(10, 13, 0)
                .expect("encode addi")
                .to_le_bytes(),
        ); // r10 = account ptr
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_SET_ACCOUNT_DETAIL)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let meta = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 10_000,
            abi_version: 1,
        };
        let literals = [&key_tlv, &value_tlv];
        let descriptor_bytes = literals.len() * core::mem::size_of::<u64>();
        let literal_data_len = literals.iter().map(|literal| literal.len()).sum::<usize>();
        let post_pad = (4 - ((16 + descriptor_bytes + literal_data_len) % 4)) % 4;
        let mut prog = meta.encode();
        prog.extend_from_slice(&LITERAL_SECTION_MAGIC);
        prog.extend_from_slice(
            &u32::try_from(literals.len())
                .expect("literal count fits")
                .to_le_bytes(),
        );
        prog.extend_from_slice(
            &u32::try_from(post_pad)
                .expect("literal padding fits")
                .to_le_bytes(),
        );
        prog.extend_from_slice(
            &u32::try_from(literal_data_len)
                .expect("literal data length fits")
                .to_le_bytes(),
        );
        let mut relative_offset = 16 + descriptor_bytes;
        for literal in &literals {
            let descriptor = ivm::encode_literal_descriptor(
                ivm::LiteralKindV1::PointerTlv,
                u64::try_from(relative_offset).expect("literal offset fits"),
            )
            .expect("literal descriptor offset is representable");
            prog.extend_from_slice(&descriptor.to_le_bytes());
            relative_offset += literal.len();
        }
        for literal in literals {
            prog.extend_from_slice(literal);
        }
        prog.extend(std::iter::repeat_n(0_u8, post_pad));
        prog.extend_from_slice(&code);
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                core::num::NonZeroU64::new(TEST_GAS_LIMIT),
            ),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let Executable::Ivm(bytecode) = tx.instructions() else {
            panic!("fixture executable is raw IVM");
        };
        let prepass = derive_from_ivm_dynamic(
            bytecode.as_ref(),
            &alice,
            tx.metadata(),
            &view,
            TEST_GAS_LIMIT,
            ContractArtifactId::new(
                DataSpaceId::UNIVERSAL,
                ivm::contract_code_hash(bytecode.as_ref()),
            ),
        )
        .expect("account-detail prepass must execute the current pointer-ownership fixture");
        let k = key_account_detail(&alice, &"cursor".parse().unwrap());
        assert!(prepass.read_keys.contains(&k) && prepass.write_keys.contains(&k));
        let (set, source) = derive_for_transaction_with_source(
            &tx,
            Some(&view),
            IvmStrategy::DynamicThenConservative,
        );
        // Expect an account.detail access for the authority under key "cursor".
        assert!(set.read_keys.contains(&k) && set.write_keys.contains(&k));
        assert!(
            set.write_keys.contains("*"),
            "a concrete prepass target cannot prove that a ledger-write target is stable after re-execution"
        );
        assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
    }
    #[test]
    fn ivm_access_dynamic_prepass_honors_governed_heap_limit() {
        let (alice, _) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(World::with(
                [domain],
                [account],
                [],
            )),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        {
            let mut parameters = state.world.parameters.block();
            parameters.set_parameter(iroha_data_model::parameter::Parameter::SmartContract(
                iroha_data_model::parameter::SmartContractParameter::Memory(
                    core::num::NonZeroU64::new(64).expect("test heap limit is non-zero"),
                ),
            ));
            parameters.commit();
        }
        let view = state.block(prepass_test_header());
        let mut program = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 10_000,
            abi_version: 1,
        }
        .encode();
        program.extend_from_slice(
            &kotodama_lang::compiler::encode_addi(10, 0, 72)
                .expect("encode allocation size")
                .to_le_bytes(),
        );
        program.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_ALLOC)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let error =
            derive_from_ivm_dynamic_with_context(&program, &alice, None, &view, TEST_GAS_LIMIT)
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("access planning must use the live smart-contract heap ceiling");
        assert!(
            error.to_ascii_lowercase().contains("out of memory"),
            "unexpected governed-heap failure: {error}"
        );
    }
    #[test]
    fn ivm_access_dynamic_prepass_requires_gas_limit() {
        let (alice, kp) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let world = World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(world),
            kura,
            query,
        );
        let view = state.view();
        let mut code = Vec::new();
        for rd in [10_u8, 11, 12] {
            code.extend_from_slice(
                &ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, rd, 0, 0)
                    .to_le_bytes(),
            );
        }
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_SET_ACCOUNT_DETAIL)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let meta = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 10_000,
            abi_version: 1,
        };
        let mut prog = meta.encode();
        prog.extend_from_slice(&LITERAL_SECTION_MAGIC);
        prog.extend_from_slice(&0u32.to_le_bytes()); // literal entries
        prog.extend_from_slice(&0u32.to_le_bytes()); // post-pad bytes
        prog.extend_from_slice(&0u32.to_le_bytes()); // literal size
        prog.extend_from_slice(&code);
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let authority = tx.authority().clone();
        let (set, source) = derive_for_transaction_with_source(
            &tx,
            Some(&view),
            IvmStrategy::DynamicThenConservative,
        );
        assert!(set.write_keys.contains("*"));
        assert!(set.read_keys.contains(&format!("account:{authority}")));
        assert!(
            set.write_keys.contains(&format!("tx.sequence:{authority}")),
            "stateful admission sequence key must serialize same-authority transactions"
        );
        assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
    }
    #[test]
    fn access_log_state_keys_are_prefixed() {
        let mut log = ivm::host::AccessLog::default();
        log.read_keys.insert("counter".to_owned());
        log.read_keys.insert("state:already".to_owned());
        log.write_keys.insert("items/1".to_owned());
        let mut set = AccessSet::new();
        merge_access_log(&mut set, &log);
        assert!(set.read_keys.contains("state:counter"));
        assert!(set.read_keys.contains("state:already"));
        assert!(set.write_keys.contains("state:items/1"));
    }
    #[test]
    fn bytecode_access_fence_serializes_state_and_nested_targets_conservatively() {
        use iroha_data_model::transaction::IvmProved;
        fn program_with_syscall(number: u32) -> Vec<u8> {
            let mut program = ivm::ProgramMetadata::default().encode();
            program.extend_from_slice(
                &ivm::encoding::wide::encode_sys(
                    ivm::instruction::wide::system::SCALL,
                    u8::try_from(number).expect("test syscall fits in the encoded immediate"),
                )
                .to_le_bytes(),
            );
            program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
            program
        }
        let mut state_set = AccessSet::new();
        state_set.add_write("state:Map/01".to_owned());
        assert!(apply_unverified_ivm_access_fence(
            &program_with_syscall(ivm::syscalls::SYSCALL_STATE_SET),
            &mut state_set,
        ));
        assert!(state_set.write_keys.contains("state:*"));
        assert!(!state_set.write_keys.contains("*"));
        let mut nested_set = AccessSet::new();
        nested_set.add_write("state:Map/01".to_owned());
        assert!(apply_unverified_ivm_access_fence(
            &program_with_syscall(ivm::syscalls::SYSCALL_CALL_CONTRACT),
            &mut nested_set,
        ));
        assert!(nested_set.write_keys.contains("*"));
        let nested_program = program_with_syscall(ivm::syscalls::SYSCALL_CALL_CONTRACT);
        let (authority, key_pair) = iroha_test_samples::gen_account_in("wonderland");
        let proved = IvmProved {
            bytecode: IvmBytecode::from_compiled(nested_program),
            overlay: Vec::<InstructionBox>::new().into(),
            events_commitment: IrohaHash::new(b"proved-events"),
            gas_policy_commitment: IrohaHash::new(b"proved-gas-policy"),
        };
        let transaction = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::IvmProved(proved))
        .sign(key_pair.private_key());
        let (proved_set, source) = derive_for_transaction_with_source::<crate::state::StateView<'_>>(
            &transaction,
            None,
            IvmStrategy::Conservative,
        );
        assert!(
            proved_set.write_keys.contains("*"),
            "proved overlays must retain the bytecode-derived nested-call fence"
        );
        assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(World::default()),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let empty_overlay = crate::pipeline::overlay::TxOverlay::from_instructions(Vec::new());
        let (prepared_set, prepared_source) = derive_for_prepared_overlay_with_source(
            &transaction,
            &state.view(),
            &empty_overlay,
            None,
            None,
            false,
        );
        assert!(prepared_set.write_keys.contains("*"));
        assert_eq!(prepared_source, Some(AccessSetSource::ConservativeFallback));
    }
    #[test]
    fn state_scan_and_retired_key_enumeration_keep_conservative_fences() {
        for (syscall, expected) in [
            (ivm::syscalls::SYSCALL_STATE_SCAN, "state:*"),
            (0x01_0030, "*"),
        ] {
            let mut program = ivm::ProgramMetadata::default().encode();
            program.extend_from_slice(&ivm::encoding::wide::encode_syscallx(syscall).to_le_bytes());
            program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
            let mut set = AccessSet::new();
            assert!(apply_unverified_ivm_access_fence(&program, &mut set));
            assert_eq!(set.write_keys, BTreeSet::from([expected.to_owned()]));
        }
    }
    #[test]
    fn syscall_access_registry_fails_closed_for_unknown_numbers() {
        use ivm::syscalls::SyscallAccess;
        assert_eq!(
            ivm::syscalls::syscall_access(ivm::syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT),
            SyscallAccess::None
        );
        assert_eq!(
            ivm::syscalls::syscall_access(ivm::syscalls::SYSCALL_STATE_GET),
            SyscallAccess::StateRead
        );
        assert_eq!(
            ivm::syscalls::syscall_access(ivm::syscalls::SYSCALL_STATE_SCAN),
            SyscallAccess::StateRead
        );
        assert_eq!(
            ivm::syscalls::syscall_access(0x01_0030),
            SyscallAccess::Dynamic
        );
        assert_eq!(
            ivm::syscalls::syscall_access(ivm::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED),
            SyscallAccess::LedgerWrite
        );
        assert_eq!(
            ivm::syscalls::syscall_access(0x00ff_fffe),
            SyscallAccess::Dynamic
        );
    }
    #[test]
    fn helper_hidden_privileged_and_dynamic_syscalls_force_global_serialization() {
        use ivm::instruction::wide;
        for (label, syscall) in [
            ("ledger write", ivm::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED),
            ("dynamic nested call", ivm::syscalls::SYSCALL_CALL_CONTRACT),
        ] {
            let code = [
                ivm::encoding::wide::encode_offset24(wide::control::JALS, 2),
                ivm::encoding::wide::encode_halt(),
                ivm::encoding::wide::encode_syscallx(syscall),
                ivm::encoding::wide::encode_rr(wide::control::JALR, 0, 1, 0),
            ];
            let mut program = ivm::ProgramMetadata::default().encode();
            program.extend(code.into_iter().flat_map(u32::to_le_bytes));
            assert!(
                hint_access_set_if_safe(
                    &program,
                    &["state:forged-read".to_owned()],
                    &["state:forged-write".to_owned()],
                )
                .is_none(),
                "{label} hidden behind a helper trusted forged exact CNTR keys"
            );
            let mut dynamic_prepass_claim = AccessSet::new();
            dynamic_prepass_claim.add_read("state:forged-read".to_owned());
            assert!(
                apply_unverified_ivm_access_fence(&program, &mut dynamic_prepass_claim),
                "{label} did not activate the bytecode-derived access fence"
            );
            assert!(
                dynamic_prepass_claim.write_keys.contains("*"),
                "{label} did not force global serialization"
            );
        }
    }
    #[test]
    fn access_set_hints_accept_state_and_canonical_keys() {
        let alice = iroha_test_samples::ALICE_ID.clone();
        let reads = vec![
            "state:alpha".to_owned(),
            format!("account:{alice}"),
            format!("account.detail:{alice}:cursor"),
        ];
        let writes = vec![
            "state:beta".to_owned(),
            "asset_def:62Fk4FPcMuLvW5QjDGNF2a4jAmjM".to_owned(),
        ];
        let set = access_set_from_hint_keys(&reads, &writes, &[], &[])
            .expect("expected valid access set hints");
        assert!(set.read_keys.contains("state:alpha"));
        assert!(set.read_keys.contains(&format!("account:{alice}")));
        assert!(
            set.read_keys
                .contains(&format!("account.detail:{alice}:cursor"))
        );
        assert!(set.write_keys.contains("state:beta"));
        assert!(
            set.write_keys
                .contains("asset_def:62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        );
    }
    #[test]
    fn access_set_hints_accept_zk_state_keys() {
        let asset_def = AssetDefinitionId::parse_address_literal("6pEP9RjNoZ7beWkT3pLfKoM1dyfi")
            .expect("asset definition");
        let reads = vec![format!("zk_asset:{asset_def}")];
        let writes = vec!["zk:election:election-1".to_owned()];
        let set = access_set_from_hint_keys(&reads, &writes, &[], &[])
            .expect("expected zk access set hints to normalize");
        assert!(set.read_keys.contains(&format!("zk_asset:{asset_def}")));
        assert!(set.write_keys.contains("zk:election:election-1"));
        for retired in [
            "zk:election:election-1:accepted_ballots",
            "zk:election:election-1:tally",
        ] {
            assert!(access_set_from_hint_keys(&[], &[retired.to_owned()], &[], &[]).is_none());
        }
    }
    #[test]
    fn election_instructions_conflict_on_one_whole_record_key() {
        let backend = "halo2/ipa";
        let proof = iroha_data_model::proof::ProofAttachment::new_ref(
            backend.into(),
            iroha_data_model::proof::ProofBox::new(backend.into(), vec![1]),
            iroha_data_model::proof::VerifyingKeyId::new(backend, "ballot-v1"),
        );
        let instructions: [InstructionBox; 3] = [
            zk::CreateElection {
                election_id: "election-1".to_owned(),
                options: 2,
                eligible_root: [0; 32],
                start_ts: 1,
                end_ts: 2,
                vk_ballot: iroha_data_model::proof::VerifyingKeyId::new(backend, "ballot-v1"),
                vk_tally: iroha_data_model::proof::VerifyingKeyId::new(backend, "tally-v1"),
                domain_tag: "election-1".to_owned(),
            }
            .into(),
            zk::SubmitBallot {
                election_id: "election-1".to_owned(),
                ciphertext: vec![2],
                ballot_proof: proof.clone(),
                nullifier: [3; 32],
            }
            .into(),
            zk::FinalizeElection {
                election_id: "election-1".to_owned(),
                tally: vec![0, 0],
                tally_proof: proof,
            }
            .into(),
        ];
        for instruction in &instructions {
            let set = derive_from_instruction::<crate::state::StateView<'_>>(
                instruction,
                None,
                &mut BTreeSet::new(),
                0,
                1,
            );
            assert_eq!(
                set.write_keys,
                BTreeSet::from(["zk:election:election-1".to_owned()]),
            );
        }
    }
    #[test]
    fn access_set_hints_accept_and_expand_authority_placeholders() {
        let authority = iroha_test_samples::ALICE_ID.clone();
        let mut set = AccessSet {
            read_keys: [
                AUTHORITY_ACCOUNT_KEY.to_owned(),
                "asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM:$authority".to_owned(),
                "account.detail:$authority:cursor".to_owned(),
            ]
            .into(),
            write_keys: [
                "role.binding:$authority:minter".to_owned(),
                "perm.account:$authority:BenefitSpend".to_owned(),
            ]
            .into(),
        };
        expand_authority_placeholders(&mut set, &authority);
        let asset_def =
            AssetDefinitionId::parse_address_literal("62Fk4FPcMuLvW5QjDGNF2a4jAmjM").unwrap();
        let asset = AssetId::of(asset_def, authority.clone());
        assert!(set.read_keys.contains(&format!("account:{authority}")));
        assert!(set.read_keys.contains(&format!("asset:{asset}")));
        assert!(
            set.read_keys
                .contains(&format!("account.detail:{authority}:cursor"))
        );
        assert!(
            set.write_keys
                .contains(&format!("role.binding:{authority}:minter"))
        );
        assert!(
            set.write_keys
                .contains(&format!("perm.account:{authority}:BenefitSpend"))
        );
        let reads = vec![AUTHORITY_ACCOUNT_KEY.to_owned()];
        let writes = vec!["role.binding:$authority:minter".to_owned()];
        assert!(access_set_from_hint_keys(&reads, &writes, &[], &[]).is_some());
    }
    #[test]
    fn access_set_hints_accept_dynamic_state_hints() {
        let dynamic_reads = vec![
            iroha_data_model::smart_contract::manifest::DynamicAccessHint {
                base_key: "state:Orders".to_owned(),
                key_type: "int".to_owned(),
                bound_kind: "page".to_owned(),
                max_keys: 64,
            },
        ];
        let set = access_set_from_hint_keys(&[], &[], &dynamic_reads, &[])
            .expect("expected dynamic read hint to normalize");
        assert!(set.read_keys.contains("state:Orders"));
        assert!(!set.write_keys.contains("state:Orders"));
        let dynamic_writes = vec![
            iroha_data_model::smart_contract::manifest::DynamicAccessHint {
                base_key: "state:Balances".to_owned(),
                key_type: "int".to_owned(),
                bound_kind: "take".to_owned(),
                max_keys: 64,
            },
        ];
        let set = access_set_from_hint_keys(&[], &[], &[], &dynamic_writes)
            .expect("expected dynamic write hint to normalize");
        assert!(set.read_keys.contains("state:Balances"));
        assert!(set.write_keys.contains("state:Balances"));
    }
    #[test]
    fn access_set_hints_accept_coarse_dynamic_account_key() {
        let reads = vec![ACCOUNT_WILDCARD_KEY.to_owned()];
        let set = access_set_from_hint_keys(&reads, &[], &[], &[])
            .expect("expected account wildcard hint to normalize");
        assert!(set.read_keys.contains(ACCOUNT_WILDCARD_KEY));
        assert!(!set.write_keys.contains(ACCOUNT_WILDCARD_KEY));
        let writes = vec![ACCOUNT_WILDCARD_KEY.to_owned()];
        let set = access_set_from_hint_keys(&[], &writes, &[], &[])
            .expect("expected account wildcard write hint to normalize");
        assert!(set.write_keys.contains(ACCOUNT_WILDCARD_KEY));
    }
    #[test]
    fn access_set_hints_accept_coarse_dynamic_asset_keys() {
        let reads = vec![
            ASSET_WILDCARD_KEY.to_owned(),
            ASSET_DEF_WILDCARD_KEY.to_owned(),
        ];
        let writes = reads.clone();
        let set = access_set_from_hint_keys(&reads, &writes, &[], &[])
            .expect("expected asset wildcard hints to normalize");
        assert!(set.read_keys.contains(ASSET_WILDCARD_KEY));
        assert!(set.write_keys.contains(ASSET_WILDCARD_KEY));
        assert!(set.read_keys.contains(ASSET_DEF_WILDCARD_KEY));
        assert!(set.write_keys.contains(ASSET_DEF_WILDCARD_KEY));
    }
    #[test]
    fn access_set_hints_reject_invalid_dynamic_state_hints() {
        use iroha_data_model::smart_contract::manifest::DynamicAccessHint;
        let valid = DynamicAccessHint {
            base_key: "state:Orders".to_owned(),
            key_type: "int".to_owned(),
            bound_kind: "page".to_owned(),
            max_keys: 1,
        };
        assert!(access_set_from_hint_keys(&[], &[], &[valid.clone()], &[]).is_some());
        assert!(access_set_from_hint_keys(&[], &[], &[], &[valid.clone()]).is_some());
        let invalid = [
            DynamicAccessHint {
                max_keys: 0,
                ..valid.clone()
            },
            DynamicAccessHint {
                max_keys: 65,
                ..valid.clone()
            },
            DynamicAccessHint {
                base_key: "state:*".to_owned(),
                ..valid.clone()
            },
            DynamicAccessHint {
                base_key: "state:Orders/child".to_owned(),
                ..valid.clone()
            },
            DynamicAccessHint {
                base_key: "state:".to_owned(),
                ..valid.clone()
            },
            DynamicAccessHint {
                base_key: "state:state".to_owned(),
                ..valid.clone()
            },
            DynamicAccessHint {
                base_key: "state:int".to_owned(),
                ..valid.clone()
            },
            DynamicAccessHint {
                base_key: "state:__kotodama_link_private".to_owned(),
                ..valid.clone()
            },
            DynamicAccessHint {
                key_type: "Numeric".to_owned(),
                ..valid.clone()
            },
            DynamicAccessHint {
                bound_kind: "bounded".to_owned(),
                ..valid.clone()
            },
            DynamicAccessHint {
                bound_kind: "range".to_owned(),
                ..valid.clone()
            },
        ];
        for hint in invalid {
            assert!(
                access_set_from_hint_keys(&[], &[], &[hint.clone()], &[]).is_none(),
                "invalid dynamic read hint must reject: {hint:?}"
            );
            assert!(
                access_set_from_hint_keys(&[], &[], &[], &[hint.clone()]).is_none(),
                "invalid dynamic write hint must reject: {hint:?}"
            );
        }
        let upper_bound = vec![DynamicAccessHint {
            base_key: "state:Orders".to_owned(),
            key_type: "int".to_owned(),
            bound_kind: "take".to_owned(),
            max_keys: ivm::access_hints::DYNAMIC_ACCESS_HINT_MAX_KEYS_V1,
        }];
        assert!(access_set_from_hint_keys(&[], &[], &upper_bound, &[]).is_some());
    }
    #[test]
    fn access_set_hints_reject_unknown_keys() {
        let reads = vec!["perm.account:historical-scoped-literal:can_transfer".to_owned()];
        assert!(access_set_from_hint_keys(&reads, &[], &[], &[]).is_none());
    }
    #[test]
    fn access_set_hints_accept_wildcards() {
        let reads = vec!["*".to_owned()];
        let set = access_set_from_hint_keys(&reads, &[], &[], &[]).expect("global wildcard hint");
        assert!(set.read_keys.contains("*"));
        let writes = vec!["state:*".to_owned()];
        let set = access_set_from_hint_keys(&[], &writes, &[], &[]).expect("state wildcard hint");
        assert!(set.write_keys.contains("state:*"));
    }
    #[test]
    fn ivm_access_uses_manifest_hints_when_present() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::{
            asset::{AssetDefinitionId, AssetId},
            smart_contract::manifest::{AccessSetHints, MANIFEST_METADATA_KEY},
        };
        use iroha_primitives::json::Json;
        use nonzero_ext::nonzero;
        // World/state setup with one account to own the manifest
        let (alice, kp) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let world = World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(world),
            kura,
            query,
        );
        // Insert manifest with access-set hints into WSV
        let asset_def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::of(asset_def, alice.clone());
        let hints = AccessSetHints {
            read_keys: vec![format!("account:{alice}")],
            write_keys: vec![format!("asset:{asset_id}")],
            dynamic_reads: Vec::new(),
            dynamic_writes: Vec::new(),
        };
        let code = crate::ivm_test_support::unit_return().to_vec();
        let mut entrypoint = default_test_entrypoint();
        entrypoint.read_keys = hints.read_keys.clone();
        entrypoint.write_keys = hints.write_keys.clone();
        let (prog, code_hash, manifest) =
            test_contract_artifact(code, Some(hints.clone()), vec![entrypoint]);
        let manifest = manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        let mut stx = st_block.transaction();
        stx.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest.clone(),
        );
        stx.apply();
        let _ = st_block.commit_world_overlay_for_testing();
        // Build a tx carrying this program; add manifest copy into metadata as well (optional)
        let mut md = iroha_model_base::metadata::Metadata::default();
        md.insert(MANIFEST_METADATA_KEY.parse().unwrap(), Json::new(manifest));
        md.insert("contract_entrypoint".parse().unwrap(), Json::new("main"));
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(md)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let (set, source) = derive_for_transaction_with_source(
            &tx,
            Some(&state.view()),
            IvmStrategy::DynamicThenConservative,
        );
        // Expect keys exactly from hints
        assert!(set.read_keys.contains(&hints.read_keys[0]));
        assert!(set.write_keys.contains(&hints.write_keys[0]));
        assert_eq!(source, Some(AccessSetSource::EntrypointHints));
    }
    #[test]
    fn ivm_access_uses_manifest_hints_from_metadata_when_missing_in_wsv() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::{
            asset::{AssetDefinitionId, AssetId},
            smart_contract::manifest::{AccessSetHints, MANIFEST_METADATA_KEY},
        };
        use iroha_primitives::json::Json;
        access_set_cache_clear();
        let (alice, kp) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let world = World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(world),
            kura,
            query,
        );
        let asset_def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::of(asset_def, alice.clone());
        let hints = AccessSetHints {
            read_keys: vec![format!("account:{alice}")],
            write_keys: vec![format!("asset:{asset_id}")],
            dynamic_reads: Vec::new(),
            dynamic_writes: Vec::new(),
        };
        let code = crate::ivm_test_support::unit_return().to_vec();
        let mut entrypoint = default_test_entrypoint();
        entrypoint.read_keys = hints.read_keys.clone();
        entrypoint.write_keys = hints.write_keys.clone();
        let (prog, _code_hash, manifest) =
            test_contract_artifact(code, Some(hints.clone()), vec![entrypoint]);
        let manifest = manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        let mut md = iroha_model_base::metadata::Metadata::default();
        md.insert(MANIFEST_METADATA_KEY.parse().unwrap(), Json::new(manifest));
        md.insert("contract_entrypoint".parse().unwrap(), Json::new("main"));
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(md)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let (set, source) = derive_for_transaction_with_source(
            &tx,
            Some(&state.view()),
            IvmStrategy::DynamicThenConservative,
        );
        assert!(set.read_keys.contains(&hints.read_keys[0]));
        assert!(set.write_keys.contains(&hints.write_keys[0]));
        assert_eq!(source, Some(AccessSetSource::EntrypointHints));
    }
    #[test]
    fn artifact_custody_is_checked_before_shared_preparation_cache() {
        let (program, hash, _) = test_contract_artifact(
            crate::ivm_test_support::unit_return().to_vec(),
            None,
            vec![default_test_entrypoint()],
        );
        let owned = ContractArtifactId::new(DataSpaceId::new(17), hash);
        let foreign = ContractArtifactId::new(DataSpaceId::new(u64::MAX), hash);
        let mut world = World::default();
        world.contract_code.insert(owned, program);
        let state = crate::pipeline::overlay::test_support::state_after_genesis(world);
        let view = state.view();
        assert!(prepared_contract_for_access(&view, owned).is_some());
        assert!(
            prepared_contract_for_access(&view, foreign).is_none(),
            "a warm equal-hash artifact never grants registry custody in another dataspace"
        );
        assert!(prepared_contract_for_access(&view, owned).is_some());
    }

    #[test]
    fn access_set_cache_separates_equal_hashes_in_different_dataspaces() {
        let hash = IrohaHash::new(b"scoped access-cache fixture");
        let owned = AccessSetCacheKey {
            artifact_id: ContractArtifactId::new(DataSpaceId::new(17), hash),
            entrypoint: Some("scope_isolation_fixture".to_owned()),
        };
        let foreign = AccessSetCacheKey {
            artifact_id: ContractArtifactId::new(DataSpaceId::new(u64::MAX), hash),
            entrypoint: owned.entrypoint.clone(),
        };
        let signature = IrohaHash::new(b"same signed manifest");
        let mut owned_set = AccessSet::new();
        owned_set.add_read("state:owned".to_owned());
        let mut foreign_set = AccessSet::new();
        foreign_set.add_read("state:foreign".to_owned());
        let mut cache = access_set_cache().write();
        cache.insert(
            owned.clone(),
            AccessSetCacheEntry {
                manifest_hash: signature,
                set: owned_set.clone(),
            },
        );
        assert!(!cache.contains_key(&foreign));
        cache.insert(
            foreign.clone(),
            AccessSetCacheEntry {
                manifest_hash: signature,
                set: foreign_set.clone(),
            },
        );
        assert_eq!(cache.get(&owned).unwrap().set, owned_set);
        assert_eq!(cache.get(&foreign).unwrap().set, foreign_set);
        cache.remove(&owned);
        cache.remove(&foreign);
    }

    #[test]
    fn access_set_cache_invalidates_on_manifest_update() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::smart_contract::manifest::AccessSetHints;
        use nonzero_ext::nonzero;
        access_set_cache_clear();
        let (alice, kp) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let world = World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(world),
            kura,
            query,
        );
        let (prog, code_hash, _) = test_contract_artifact(
            crate::ivm_test_support::unit_return().to_vec(),
            None,
            vec![default_test_entrypoint()],
        );
        let hints_a = AccessSetHints {
            read_keys: vec!["state:alpha".to_owned()],
            write_keys: Vec::new(),
            dynamic_reads: Vec::new(),
            dynamic_writes: Vec::new(),
        };
        let manifest_a = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: None,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: Some(hints_a.clone()),
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
        .expect("sign bounded fixture manifest");
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        let mut stx = st_block.transaction();
        stx.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest_a,
        );
        stx.apply();
        let _ = st_block.commit_world_overlay_for_testing();
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let set_a = derive_for_transaction(&tx, Some(&state.view()), IvmStrategy::Conservative);
        assert!(set_a.read_keys.contains("state:alpha"));
        assert!(!set_a.read_keys.contains("state:beta"));
        let hints_b = AccessSetHints {
            read_keys: vec!["state:beta".to_owned()],
            write_keys: Vec::new(),
            dynamic_reads: Vec::new(),
            dynamic_writes: Vec::new(),
        };
        let manifest_b = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: None,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: Some(hints_b.clone()),
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
        .expect("sign bounded fixture manifest");
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        let mut stx = st_block.transaction();
        stx.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest_b,
        );
        stx.apply();
        let _ = st_block.commit_world_overlay_for_testing();
        let set_b = derive_for_transaction(&tx, Some(&state.view()), IvmStrategy::Conservative);
        assert!(set_b.read_keys.contains("state:beta"));
        assert!(!set_b.read_keys.contains("state:alpha"));
    }
    #[test]
    fn ivm_access_falls_back_when_manifest_hints_invalid() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::smart_contract::manifest::AccessSetHints;
        use nonzero_ext::nonzero;
        let (alice, kp) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let world = World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(world),
            kura,
            query,
        );
        let mut prog = ivm::ProgramMetadata::default().encode();
        prog.extend_from_slice(&[0x01, 0x00]); // dummy body
        ivm::ProgramMetadata::parse(&prog).expect("header parse");
        let code_hash = ivm::contract_code_hash(&prog);
        let hints = AccessSetHints {
            read_keys: vec!["perm.account:historical-scoped-literal:can_transfer".to_owned()],
            write_keys: Vec::new(),
            dynamic_reads: Vec::new(),
            dynamic_writes: Vec::new(),
        };
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: None,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: Some(hints),
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
        .expect("sign bounded fixture manifest");
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        let mut stx = st_block.transaction();
        stx.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest,
        );
        stx.apply();
        let _ = st_block.commit_world_overlay_for_testing();
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let (set, source) =
            derive_for_transaction_with_source(&tx, Some(&state.view()), IvmStrategy::Conservative);
        assert!(set.write_keys.contains("*"));
        assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
    }
    #[test]
    fn ivm_access_rejects_unproven_exact_state_entrypoint_hints() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::smart_contract::manifest::{
            AccessSetHints, ContractManifest, EntryPointKind, EntrypointDescriptor,
        };
        use nonzero_ext::nonzero;
        let (alice, kp) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let world = World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(world),
            kura,
            query,
        );
        let mut code = Vec::new();
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_STATE_GET)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let mut prog = ivm::ProgramMetadata::default().encode();
        prog.extend_from_slice(&code);
        ivm::ProgramMetadata::parse(&prog).expect("header parse");
        let code_hash = ivm::contract_code_hash(&prog);
        let entrypoints = vec![
            EntrypointDescriptor {
                name: "main".to_owned(),
                kind: EntryPointKind::Kotoage,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization: EntrypointAuthorizationV1::Permission("ExecuteContract".parse().unwrap()),
                read_keys: vec!["state:alpha".to_owned()],
                write_keys: vec!["state:beta".to_owned()],
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
            },
            EntrypointDescriptor {
                name: "run".to_owned(),
                kind: EntryPointKind::Kotoage,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization: EntrypointAuthorizationV1::Permission("ExecuteContract".parse().unwrap()),
                read_keys: vec!["state:run-read".to_owned()],
                write_keys: vec!["state:run-write".to_owned()],
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
            },
        ];
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: None,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: Some(AccessSetHints {
                read_keys: vec!["state:manifest-read".to_owned()],
                write_keys: vec!["state:manifest-write".to_owned()],
                dynamic_reads: Vec::new(),
                dynamic_writes: Vec::new(),
            }),
            entrypoints: Some(entrypoints),
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
        .expect("sign bounded fixture manifest");
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        let mut stx = st_block.transaction();
        stx.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest.clone(),
        );
        stx.apply();
        let _ = st_block.commit_world_overlay_for_testing();
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let (set, source) =
            derive_for_transaction_with_source(&tx, Some(&state.view()), IvmStrategy::Conservative);
        assert!(set.write_keys.contains("*"));
        assert!(!set.read_keys.contains("state:alpha"));
        assert!(!set.write_keys.contains("state:beta"));
        assert!(!set.read_keys.contains("state:manifest-read"));
        assert!(!set.write_keys.contains("state:manifest-write"));
        assert!(!set.read_keys.contains("state:run-read"));
        assert!(!set.write_keys.contains("state:run-write"));
        assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
    }
    #[test]
    fn ivm_access_skips_entrypoint_hints_for_unsafe_syscalls() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::smart_contract::manifest::{
            ContractManifest, EntryPointKind, EntrypointDescriptor,
        };
        use nonzero_ext::nonzero;
        let (alice, kp) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let world = World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(world),
            kura,
            query,
        );
        let mut code = Vec::new();
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let mut prog = ivm::ProgramMetadata::default().encode();
        prog.extend_from_slice(&code);
        ivm::ProgramMetadata::parse(&prog).expect("header parse");
        let code_hash = ivm::contract_code_hash(&prog);
        let entrypoints = vec![EntrypointDescriptor {
            name: "main".to_owned(),
            kind: EntryPointKind::Kotoage,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: EntrypointAuthorizationV1::Permission("ExecuteContract".parse().unwrap()),
            read_keys: vec!["state:alpha".to_owned()],
            write_keys: vec!["state:beta".to_owned()],
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
        }];
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: None,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: Some(entrypoints),
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
        .expect("sign bounded fixture manifest");
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        let mut stx = st_block.transaction();
        stx.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest.clone(),
        );
        stx.apply();
        let _ = st_block.commit_world_overlay_for_testing();
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let (set, source) =
            derive_for_transaction_with_source(&tx, Some(&state.view()), IvmStrategy::Conservative);
        assert!(set.write_keys.contains("*"));
        assert!(!set.read_keys.contains("state:alpha"));
        assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
    }
    #[test]
    fn ivm_access_rejects_unproven_exact_ledger_entrypoint_hints() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::{
            asset::id::{AssetDefinitionId, AssetId},
            smart_contract::manifest::{ContractManifest, EntryPointKind, EntrypointDescriptor},
        };
        use nonzero_ext::nonzero;
        let (alice, kp) = iroha_test_samples::gen_account_in("wonderland");
        let domain: Domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice);
        let account = build_wonderland_account(&alice);
        let world = World::with([domain], [account], []);
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(world),
            kura,
            query,
        );
        let mut code = Vec::new();
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED)
                    .expect("syscall identifier fits in 8 bits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let mut prog = ivm::ProgramMetadata::default().encode();
        prog.extend_from_slice(&code);
        ivm::ProgramMetadata::parse(&prog).expect("header parse");
        let code_hash = ivm::contract_code_hash(&prog);
        let asset_def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::of(asset_def, alice.clone());
        let entrypoints = vec![EntrypointDescriptor {
            name: "main".to_owned(),
            kind: EntryPointKind::Kotoage,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: EntrypointAuthorizationV1::Permission("ExecuteContract".parse().unwrap()),
            read_keys: vec![format!("account:{alice}")],
            write_keys: vec![format!("asset:{asset_id}")],
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
        }];
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: None,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: Some(entrypoints),
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
        .expect("sign bounded fixture manifest");
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        let mut stx = st_block.transaction();
        stx.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest.clone(),
        );
        stx.apply();
        let _ = st_block.commit_world_overlay_for_testing();
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let (set, source) =
            derive_for_transaction_with_source(&tx, Some(&state.view()), IvmStrategy::Conservative);
        assert!(set.write_keys.contains("*"));
        assert!(!set.write_keys.contains(&format!("asset:{asset_id}")));
        assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
    }
    #[test]
    fn grant_revoke_role_and_permission_have_static_keys() {
        use iroha_data_model::permission::Permission;
        let (alice, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
        let role_id: RoleId = "auditor".parse().unwrap();
        let perm = Permission::new(
            "CanMintAssetToAccount".to_string(),
            norito::json!({
                "asset_definition": "coin#wonderland",
                "account": (alice.to_string()),
            }),
        );
        // Build ISI batch with grant/revoke combinations
        let isis: Vec<InstructionBox> = vec![
            Grant::account_role(role_id.clone(), alice.clone()).into(),
            Revoke::account_role(role_id.clone(), alice.clone()).into(),
            Grant::account_permission(perm.clone(), alice.clone()).into(),
            Revoke::account_permission(perm.clone(), alice.clone()).into(),
            Grant::role_permission(perm.clone(), role_id.clone()).into(),
            Revoke::role_permission(perm.clone(), role_id.clone()).into(),
        ];
        let exec = Executable::from_iter(isis);
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(exec)
        .sign(alice_keypair.private_key());
        let set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            None,
            IvmStrategy::Conservative,
        );
        // Expect role registry touched and account-role binding keys written
        assert!(set.read_keys.contains(&format!("role:{}", &role_id)));
        assert!(
            set.write_keys
                .contains(&format!("role.binding:{}:{}", &alice, &role_id))
        );
        // Expect permission keys touched for account and role
        assert!(
            set.write_keys
                .contains(&format!("perm.account:{}:{}", &alice, perm.name()))
        );
        assert!(
            set.write_keys
                .contains(&format!("perm.role:{}:{}", &role_id, perm.name()))
        );
        assert!(
            set.write_keys.contains(AUTHORIZATION_EPOCH_KEY),
            "permission and role mutations must order protected contract calls"
        );
    }
    #[test]
    fn execute_trigger_keys_cover_definition_and_repetitions() {
        let (alice, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
        let trig: TriggerId = "t0".parse().unwrap();
        let isi: InstructionBox = ExecuteTrigger::new(trig.clone()).into();
        let exec = Executable::from_iter([isi]);
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(exec)
        .sign(alice_keypair.private_key());
        let set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            None,
            IvmStrategy::Conservative,
        );
        assert!(set.read_keys.contains(&format!("trigger:{}", &trig)));
        assert!(set.write_keys.contains(&format!("trigger:{}", &trig)));
        assert!(
            set.write_keys
                .contains(&format!("trigger.repetitions:{}", &trig))
        );
    }
    #[test]
    fn execute_trigger_includes_access_from_trigger_instructions() {
        use nonzero_ext::nonzero;
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(World::default()),
            kura,
            query,
        );
        let alice = iroha_test_samples::ALICE_ID.clone();
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        {
            let mut stx = st_block.transaction();
            let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&alice, &mut stx)
                .unwrap();
            Register::account(new_wonderland_account(&alice))
                .execute(&alice, &mut stx)
                .unwrap();
            let asset_def_id: AssetDefinitionId =
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "rose".parse().unwrap(),
                );
            Register::asset_definition({
                let __asset_definition_id = asset_def_id.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "rose".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&alice, &mut stx)
            .unwrap();
            let asset_id = AssetId::of(asset_def_id.clone(), alice.clone());
            let trigger_id: TriggerId = "mint_asset_trigger".parse().unwrap();
            let trigger = Trigger::new(
                trigger_id.clone(),
                Action::new(
                    vec![InstructionBox::from(Mint::asset_quantity(
                        1_u32,
                        asset_id.clone(),
                    ))],
                    Repeats::Exactly(1),
                    alice.clone(),
                    iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id.clone())
                        .under_authority(alice.clone()),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            );
            Register::trigger(trigger)
                .execute(&alice, &mut stx)
                .unwrap();
            stx.apply();
        }
        st_block.commit_world_overlay_for_testing().unwrap();
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(ExecuteTrigger::new(
            "mint_asset_trigger".parse().unwrap(),
        ))])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
        let set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            Some(&state.view()),
            IvmStrategy::Conservative,
        );
        assert!(
            set.write_keys.contains("*"),
            "the trigger must retain the mint's global fence for dynamic asset policy and routing reads"
        );
        let trigger_id = "mint_asset_trigger".parse().expect("trigger id");
        assert!(set.read_keys.contains(&key_trigger(&trigger_id)));
        assert!(set.write_keys.contains(&key_trigger(&trigger_id)));
        assert!(
            set.write_keys
                .contains(&key_trigger_repetitions(&trigger_id))
        );
    }
    #[test]
    fn execute_trigger_includes_trigger_metadata_keys() {
        use nonzero_ext::nonzero;
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(World::default()),
            kura,
            query,
        );
        let alice = iroha_test_samples::ALICE_ID.clone();
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        {
            let mut stx = st_block.transaction();
            Register::domain(Domain::new(
                DomainId::try_new("wonderland", "universal").unwrap(),
            ))
            .execute(&alice, &mut stx)
            .unwrap();
            Register::account(new_wonderland_account(&alice))
                .execute(&alice, &mut stx)
                .unwrap();
            let trigger_id: TriggerId = "meta_trigger".parse().unwrap();
            let key: Name = "flag".parse().unwrap();
            let trigger = Trigger::new(
                trigger_id.clone(),
                Action::new(
                    vec![InstructionBox::from(SetKeyValue::trigger(
                        trigger_id.clone(),
                        key.clone(),
                        iroha_primitives::json::Json::from(norito::json!("ok")),
                    ))],
                    Repeats::Exactly(1),
                    alice.clone(),
                    iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id.clone())
                        .under_authority(alice.clone()),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            );
            Register::trigger(trigger)
                .execute(&alice, &mut stx)
                .unwrap();
            stx.apply();
        }
        st_block.commit_world_overlay_for_testing().unwrap();
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(ExecuteTrigger::new(
            "meta_trigger".parse().unwrap(),
        ))])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
        let set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            Some(&state.view()),
            IvmStrategy::Conservative,
        );
        let detail_key = format!("trigger.detail:{}:{}", "meta_trigger", "flag");
        assert!(set.write_keys.contains(&detail_key));
    }
    #[test]
    fn execute_trigger_uses_retained_entrypoint_hints_without_repreparing() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::smart_contract::manifest::AccessSetHints;
        use nonzero_ext::nonzero;
        access_set_cache_clear();
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(World::default()),
            kura,
            query,
        );
        let alice = iroha_test_samples::ALICE_ID.clone();
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        let (code_hash, trigger_id, hints) = {
            let mut stx = st_block.transaction();
            Register::domain(Domain::new(
                DomainId::try_new("wonderland", "universal").unwrap(),
            ))
            .execute(&alice, &mut stx)
            .unwrap();
            Register::account(new_wonderland_account(&alice))
                .execute(&alice, &mut stx)
                .unwrap();
            let hints = AccessSetHints {
                read_keys: vec!["state:trigger_hint_read".to_owned()],
                write_keys: vec![format!("state:trigger_hint")],
                dynamic_reads: Vec::new(),
                dynamic_writes: Vec::new(),
            };
            let code = crate::ivm_test_support::unit_return().to_vec();
            let mut entrypoint = default_test_entrypoint();
            entrypoint.read_keys = hints.read_keys.clone();
            entrypoint.write_keys = hints.write_keys.clone();
            let (prog, code_hash, manifest) =
                test_contract_artifact(code, Some(hints.clone()), vec![entrypoint]);
            let manifest = manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &iroha_test_samples::ALICE_KEYPAIR,
                )
                .expect("sign bounded fixture manifest");
            stx.world.contract_manifests.insert(
                ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
                manifest,
            );
            let trigger_id: TriggerId = "ivm_trigger".parse().unwrap();
            let mut trigger_metadata = Metadata::default();
            trigger_metadata.insert(
                "contract_entrypoint".parse().expect("entrypoint key"),
                iroha_primitives::json::Json::new("main"),
            );
            let address = iroha_data_model::smart_contract::ContractAddress::derive(
                &test_network_id(),
                &alice,
                96,
                DataSpaceId::UNIVERSAL,
            )
            .expect("explicit universal trigger address");
            trigger_metadata.insert(
                "contract_address".parse().expect("address key"),
                iroha_primitives::json::Json::new(address.to_string()),
            );
            let trigger = Trigger::new(
                trigger_id.clone(),
                Action::new(
                    Executable::Ivm(IvmBytecode::from_compiled(prog)),
                    Repeats::Exactly(1),
                    alice.clone(),
                    iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id.clone())
                        .under_authority(alice.clone()),
                )
                .expect("trigger action fixture satisfies validation invariants")
                .with_metadata(trigger_metadata),
            );
            Register::trigger(trigger)
                .execute(&alice, &mut stx)
                .unwrap();
            stx.apply();
            (code_hash, trigger_id, hints)
        };
        st_block.commit_world_overlay_for_testing().unwrap();
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(ExecuteTrigger::new(
            trigger_id.clone(),
        ))])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
        let set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            Some(&state.view()),
            IvmStrategy::Conservative,
        );
        let prepared_cache = state.view().prepared_contract_cache();
        let prepared_after_first = prepared_cache.stats();
        let warm_set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            Some(&state.view()),
            IvmStrategy::Conservative,
        );
        let prepared_after_second = prepared_cache.stats();
        assert!(set.read_keys.contains(&format!("account:{alice}")));
        assert!(set.read_keys.contains(&format!("trigger:{trigger_id}")));
        assert!(
            set.write_keys
                .contains(&format!("trigger.repetitions:{trigger_id}"))
        );
        assert!(set.write_keys.contains(&format!("trigger:{trigger_id}")));
        assert!(set.write_keys.contains(&format!("tx.sequence:{alice}")));
        assert!(set.read_keys.contains(&hints.read_keys[0]));
        assert!(set.write_keys.contains(&hints.write_keys[0]));
        assert_eq!(warm_set, set);
        assert_eq!(
            prepared_after_second.hits,
            prepared_after_first.hits + 1,
            "warm trigger access should resolve solely by its retained deployable hash"
        );
        assert_eq!(
            prepared_after_second.preparations, prepared_after_first.preparations,
            "warm trigger access must not parse, hash, validate, or predecode again"
        );
        assert_eq!(
            prepared_after_second.runtime_template_builds,
            prepared_after_first.runtime_template_builds,
            "scheduler access derivation must not build a runtime template"
        );
        assert!(
            state
                .view()
                .world()
                .contract_manifests()
                .get(&ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash))
                .is_some()
        );
    }
    #[test]
    fn execute_trigger_without_selector_does_not_use_entrypoint_hints() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        use iroha_data_model::smart_contract::manifest::AccessSetHints;
        use nonzero_ext::nonzero;
        access_set_cache_clear();
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::new(
            crate::pipeline::overlay::test_support::with_global_root(World::default()),
            kura,
            query,
        );
        let alice = iroha_test_samples::ALICE_ID.clone();
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut st_block = state.block(header);
        let (code_hash, trigger_id, hints) = {
            let mut stx = st_block.transaction();
            Register::domain(Domain::new(
                DomainId::try_new("wonderland", "universal").unwrap(),
            ))
            .execute(&alice, &mut stx)
            .unwrap();
            Register::account(new_wonderland_account(&alice))
                .execute(&alice, &mut stx)
                .unwrap();
            let hints = AccessSetHints {
                read_keys: vec!["state:trigger_hint_read".to_owned()],
                write_keys: vec!["state:trigger_hint".to_owned()],
                dynamic_reads: Vec::new(),
                dynamic_writes: Vec::new(),
            };
            let code = crate::ivm_test_support::unit_return().to_vec();
            let mut entrypoint = default_test_entrypoint();
            entrypoint.read_keys = hints.read_keys.clone();
            entrypoint.write_keys = hints.write_keys.clone();
            let (prog, code_hash, manifest) =
                test_contract_artifact(code, Some(hints.clone()), vec![entrypoint]);
            let manifest = manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &iroha_test_samples::ALICE_KEYPAIR,
                )
                .expect("sign bounded fixture manifest");
            stx.world.contract_manifests.insert(
                ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
                manifest,
            );
            let trigger_id: TriggerId = "ivm_trigger_without_selector".parse().unwrap();
            let trigger = Trigger::new(
                trigger_id.clone(),
                Action::new(
                    Executable::Ivm(IvmBytecode::from_compiled(prog)),
                    Repeats::Exactly(1),
                    alice.clone(),
                    iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id.clone())
                        .under_authority(alice.clone()),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            );
            Register::trigger(trigger)
                .execute(&alice, &mut stx)
                .unwrap();
            stx.apply();
            (code_hash, trigger_id, hints)
        };
        st_block.commit_world_overlay_for_testing().unwrap();
        let tx = TransactionBuilder::new(
            test_network_id(),
            alice.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(ExecuteTrigger::new(
            trigger_id.clone(),
        ))])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
        let set = derive_for_transaction::<crate::state::StateView<'_>>(
            &tx,
            Some(&state.view()),
            IvmStrategy::Conservative,
        );
        assert!(set.read_keys.contains(&format!("account:{alice}")));
        assert!(set.read_keys.contains(&format!("trigger:{trigger_id}")));
        assert!(set.write_keys.contains("*"));
        assert!(!set.read_keys.contains(&hints.read_keys[0]));
        assert!(!set.write_keys.contains(&hints.write_keys[0]));
        assert!(
            state
                .view()
                .world()
                .contract_manifests()
                .get(&ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash))
                .is_some()
        );
    }
    include!("access_register_trigger_test.rs");
}

#[cfg(test)]
#[path = "access/static_state_memory_tests.rs"]
mod static_state_memory_tests;

#[cfg(test)]
#[path = "access/manifest_signature_hash_tests.rs"]
mod manifest_signature_hash_tests;
