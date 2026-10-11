//! Host interface trait for handling syscalls, with default dummy implementations.
//!
//! The default host provides a minimal but functional set of syscalls used by
//! the tests. It supports heap allocation and retrieval of private inputs so
//! that zero‑knowledge programs can run without a custom environment.
//!
//! The host also exposes basic hardware feature discovery and Merkle-proof
//! helpers used by some tests.
use crate::{
    SyscallPolicy,
    axt::{self, ProofBlob, TouchManifest},
    error::VMError,
    gas,
    ivm::IVM,
    memory::Memory,
    parallel::{StateAccessSet, StateKey, StateUpdate},
    pointer_abi::{self, PointerType},
    syscall_metering::SyscallMetering,
    syscalls,
};
use iroha_crypto::{
    Sm2PublicKey, Sm2Signature, Sm3Digest, Sm4Key,
    blake2::{
        Blake2bVar,
        digest::{Update as Blake2Update, VariableOutput},
    },
};
use iroha_data_model::{
    isi::transfer::TransferAssetBatch,
    nexus::{AxtPolicySnapshot, AxtPolicySnapshotValidationError},
    zk::{OpenVerifyEnvelope, OpenVerifyEnvelopeBounds, OpenVerifyEnvelopeValidationError},
};
use iroha_model_base::topology::DataSpaceId;
use iroha_model_base::{name::Name, state_path::StatePath};
#[cfg(test)]
use iroha_primitives::numeric::{Numeric, Quantity};
use iroha_primitives::{
    json::Json,
    numeric_abi::{MAX_QUANTITY_FRAME_BYTES_V1, QuantityValueV1},
};
use ivm_abi::{
    codec::{
        decode_canonical_norito, decode_canonical_norito_with_limits, encode_canonical_norito,
    },
    private_input::{
        MAX_PRIVATE_INPUT_RECORD_BYTES_V1, MAX_PRIVATE_INPUT_TRANSPORT_BYTES_V1,
        MAX_PRIVATE_INPUTS_V1, PrivateInputKindV1, PrivateInputRecordV1,
    },
};
use norito::{
    core::{Header, SerializePayload},
    decode_from_bytes,
};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3_hash::{Digest as Sha3Digest, Keccak256, Sha3_256};
use std::{
    any::Any,
    collections::{BTreeMap, HashSet},
    num::NonZeroU16,
};
/// Validate a signed nominal error descriptor and request the exact application rejection.
pub(crate) fn request_nominal_contract_abort(
    vm: &mut IVM,
    resolve: impl Fn(&IVM, u64) -> u64,
) -> Result<u64, VMError> {
    if (12..=15).any(|register| vm.register(register) != 0) {
        return Err(VMError::NoritoInvalid);
    }
    let code = u32::try_from(vm.register(11)).map_err(|_| VMError::NoritoInvalid)?;
    let tlv = vm.validate_tlv(resolve(vm, vm.register(10)))?;
    if tlv.type_id != PointerType::NoritoBytes || tlv.payload.len() > 64 * 1024 {
        return Err(VMError::NoritoInvalid);
    }
    let descriptor_len = tlv.payload.len();
    let descriptor: iroha_data_model::smart_contract::manifest::ContractErrorTypeDescriptor =
        decode_canonical_norito(tlv.payload)?;
    if !descriptor.validate()
        || descriptor.variant(code).is_none()
        || !vm
            .contract_interface()
            .is_some_and(|interface| interface.error_types.contains(&descriptor))
    {
        return Err(VMError::NoritoInvalid);
    }
    let contract = vm
        .contract_interface()
        .ok_or(VMError::NoritoInvalid)?
        .seiyaku_name
        .clone();
    let name = descriptor
        .variant(code)
        .ok_or(VMError::NoritoInvalid)?
        .name
        .clone();
    let message = contract_abort_message(vm, &descriptor.identity, code).map(str::to_owned);
    let gas = contract_abort_gas(descriptor_len, message.as_deref());
    vm.request_contract_abort(
        contract,
        name,
        descriptor.identity.clone(),
        descriptor.schema_hash(),
        code,
        message,
    );
    Ok(gas)
}
fn contract_abort_message<'a>(vm: &'a IVM, identity: &str, code: u32) -> Option<&'a str> {
    let messages = &vm.contract_interface()?.error_messages;
    let index = messages
        .binary_search_by(|entry| (entry.error_type.as_str(), entry.code).cmp(&(identity, code)))
        .ok()?;
    Some(messages[index].message.as_str())
}
fn contract_abort_gas(descriptor_bytes: usize, message: Option<&str>) -> u64 {
    DEBUG_GAS
        .saturating_add(u64::try_from(descriptor_bytes).unwrap_or(u64::MAX))
        .saturating_add(message.map_or(0, |text| text.len() as u64))
}
/// Runtime record of logical state touches performed by a host during a transaction.
#[derive(Clone, Default, Debug)]
pub struct AccessLog {
    pub read_keys: HashSet<StateKey>,
    pub write_keys: HashSet<StateKey>,
    /// Concrete durable-state paths observed by the host, including any contract-instance scope.
    pub durable_read_paths: HashSet<StateKey>,
    /// Whether `durable_read_paths` completely covers every durable read.
    ///
    /// The default is deliberately false so custom hosts and manually built
    /// logs fail closed until they explicitly provide this guarantee.
    pub durable_read_paths_complete: bool,
    pub reg_tags: HashSet<usize>,
    pub state_writes: Vec<StateUpdate>,
}
/// Resource limits for generic proof envelopes and verification batches.
///
/// Limits never select an engine or grant proof authority. The standalone host
/// has no authenticated verifier registry and rejects every proof relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkVerifyLimits {
    /// Maximum envelopes in one batch syscall.
    pub max_verify_batch: u32,
    /// Maximum bytes in one canonical outer proof envelope.
    pub max_envelope_bytes: usize,
    /// Maximum bytes in its inner proof payload.
    pub max_proof_bytes: usize,
}
impl Default for ZkVerifyLimits {
    fn default() -> Self {
        Self {
            max_verify_batch: 16,
            max_envelope_bytes: 256 * 1024,
            max_proof_bytes: 192 * 1024,
        }
    }
}
pub const ERR_DISABLED: u64 = 1;
pub const ERR_BACKEND: u64 = 2;
pub const ERR_CURVE: u64 = 3;
pub const ERR_K: u64 = 4;
pub const ERR_DECODE: u64 = 5;
pub const ERR_VERIFY: u64 = 6;
pub const ERR_BATCH: u64 = 7;
pub const ERR_ENVELOPE_SIZE: u64 = 8;
pub const ERR_PROOF_LEN: u64 = 10;
pub const ERR_VK_MISSING: u64 = 11;
pub const ERR_VK_MISMATCH: u64 = 12;
pub const ERR_VK_INACTIVE: u64 = 13;
pub const ERR_NAMESPACE: u64 = 14;
pub const LABEL_VOTE_BALLOT: &str = "zk_verify_ballot/v2";
pub const LABEL_VOTE_TALLY: &str = "zk_verify_tally/v2";
pub const LABEL_BATCH: &str = "zk_verify_batch/v2";
/// Per-host counters used to prove the ZK reserve/decode/backend/allocation ordering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ZkExecutionCounters {
    /// Canonical envelope or batch decode attempts made after gas reservation.
    pub canonical_decodes: u64,
    /// Backend verifier invocations made after exact-cost preflight.
    pub backend_invocations: u64,
    /// Guest-visible batch response allocations made after verification.
    pub response_allocations: u64,
}
/// Per-host counters used to prove VRF reserve/decode/backend/allocation ordering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VrfExecutionCounters {
    /// Canonical single-request or batch decode attempts made after gas reservation.
    pub canonical_decodes: u64,
    /// Pairing verifier invocations made after exact-cost preflight.
    pub backend_invocations: u64,
    /// Successful guest-visible response allocations.
    pub response_allocations: u64,
}
const PUBLIC_INPUT_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const PUBLIC_INPUT_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
#[cfg(test)]
const COMMIT_OUTPUT_GAS: u64 = gas::HOST_COMMIT_OUTPUT_GAS;
const DEBUG_GAS: u64 = gas::HOST_DEBUG_GAS_BASE;
const GET_PRIVATE_INPUT_GAS: u64 = gas::HOST_PRIVATE_INPUT_GAS;
const PRIVATE_NUMERIC_VALCOM_GAS: u64 = gas::HOST_PRIVATE_NUMERIC_VALCOM_GAS;
const GROW_HEAP_GAS_BASE: u64 = gas::GROW_HEAP_GAS_BASE;
const GROW_HEAP_GAS_PER_PAGE: u64 = gas::GROW_HEAP_GAS_PER_PAGE;
const GROW_HEAP_PAGE_BYTES: u64 = gas::GROW_HEAP_PAGE_BYTES;
const AXT_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const AXT_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const HASH_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const HASH_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const INPUT_PUBLISH_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const INPUT_PUBLISH_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const MERKLE_PATH_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const MERKLE_PATH_GAS_PER_NODE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const MUTATION_GAS: u64 = gas::HOST_BYTE_GAS_BASE;
const MUTATION_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const POINTER_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const POINTER_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const SIGNATURE_VERIFY_GAS_BASE: u64 = gas::HOST_VERIFY_GAS_BASE;
const SIGNATURE_VERIFY_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const SM4_GAS_BASE: u64 = gas::HOST_VERIFY_GAS_BASE;
const SM4_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
/// Minimum gas charged before a host may inspect durable or ledger state.
///
/// Preparation rejects a smaller budget before the host is invoked. Stateful scans then spend one
/// additional gas unit per examined item and stop as soon as the pre-debited reserve is exhausted.
pub const STATE_QUERY_GAS_BASE: u64 = gas::STATE_QUERY_GAS_BASE;
/// Validate and return a durable-state path's canonical pointer payload size.
///
/// # Errors
///
/// Returns an ABI or memory error for an invalid pointer and
/// [`VMError::NoritoInvalid`] when the V1 path bound is exceeded.
pub fn quote_state_path_payload_len_at(vm: &IVM, address: u64) -> Result<usize, VMError> {
    let path_len = quote_tlv_payload_len_at(vm, address, PointerType::NoritoBytes)?;
    if path_len > syscalls::STATE_MAX_PATH_FRAME_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    Ok(path_len)
}
/// Return the framed Norito payload length used by a `StateMap` base `Name`.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] when the canonical length overflows.
pub fn state_path_name_payload_len(name: &Name) -> Result<usize, VMError> {
    state_path_text_payload_len(name.as_ref(), core::mem::align_of::<Name>())
}
/// Return the framed Norito payload length used by a durable-state `StatePath`.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] when the canonical length overflows.
pub fn state_path_payload_len(path: &StatePath) -> Result<usize, VMError> {
    state_path_text_payload_len(path.as_ref(), core::mem::align_of::<StatePath>())
}
fn state_path_text_payload_len(path: &str, align: usize) -> Result<usize, VMError> {
    let encoded = state_key_encoded_len_from_text(path)?;
    let padding = if align <= 1 {
        0
    } else {
        let remainder = Header::SIZE % align;
        if remainder == 0 { 0 } else { align - remainder }
    };
    Header::SIZE
        .checked_add(padding)
        .and_then(|bytes| bytes.checked_add(encoded))
        .ok_or(VMError::NoritoInvalid)
}
/// Validate canonical durable-state path text without applying `Name`'s
/// business-identifier length bound.
///
/// Stored-key scanners use this before counting or skipping an entry, so an
/// oversized preloaded key cannot evade validation through pagination.
pub fn validate_state_path_text(path: &str) -> Result<(), VMError> {
    let path: StatePath = path.parse().map_err(|_| VMError::NoritoInvalid)?;
    validate_state_path(&path)
}
/// Validate a canonical durable-state path against the V1 text and canonical-frame bounds.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] when the path exceeds the V1 bound.
pub fn validate_state_path(path: &StatePath) -> Result<(), VMError> {
    if path.as_ref().len() > syscalls::STATE_MAX_PATH_BYTES
        || state_path_payload_len(path)? > syscalls::STATE_MAX_PATH_FRAME_BYTES
    {
        return Err(VMError::NoritoInvalid);
    }
    Ok(())
}
/// Validate a V1 durable-state value payload length.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] when the value exceeds the V1 bound.
pub fn validate_state_value_payload_len(value_len: usize) -> Result<(), VMError> {
    if value_len > syscalls::STATE_MAX_VALUE_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    Ok(())
}
/// Exact gas for a bounded path-only durable-state operation.
#[must_use]
pub fn state_path_gas(path_len: usize) -> u64 {
    STATE_QUERY_GAS_BASE.saturating_add(u64::try_from(path_len).unwrap_or(u64::MAX))
}
/// Exact gas for a bounded durable-state value operation.
#[must_use]
pub fn state_value_gas(path_len: usize, value_len: usize) -> u64 {
    state_path_gas(path_len).saturating_add(u64::try_from(value_len).unwrap_or(u64::MAX))
}
const SYSVAR_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const SYSVAR_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const TLV_EQ_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const TLV_EQ_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const TLV_LEN_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const TLV_LEN_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const VERIFY_GAS_BASE: u64 = gas::HOST_VERIFY_GAS_BASE;
const VERIFY_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
pub(crate) fn debug_log_gas(payload_len: usize) -> u64 {
    DEBUG_GAS.saturating_add(u64::try_from(payload_len).unwrap_or(u64::MAX))
}
pub(crate) const TLV_ENVELOPE_OVERHEAD: usize = 7 + iroha_crypto::Hash::LENGTH;
/// Build the injective V1 durable-map path for canonical Norito key bytes.
pub fn canonical_state_map_path(base: &Name, key: &[u8]) -> Result<StatePath, VMError> {
    if base.as_ref().len() > syscalls::STATE_MAP_MAX_BASE_BYTES
        || state_path_name_payload_len(base)? > syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES
        || key.is_empty()
        || key.len() > syscalls::STATE_MAP_MAX_KEY_BYTES
    {
        return Err(VMError::NoritoInvalid);
    }
    let base = base.as_ref();
    let mut path = String::with_capacity(base.len() + 1 + key.len().saturating_mul(2));
    path.push_str(base);
    path.push('/');
    path.push_str(&hex::encode(key));
    let path: StatePath = path.parse().map_err(|_| VMError::NoritoInvalid)?;
    validate_state_path(&path)?;
    Ok(path)
}
fn declared_state_map_key_type<'a>(
    vm: &'a IVM,
    base: &Name,
) -> Result<&'a crate::metadata::EmbeddedStateType, VMError> {
    let interface = vm.contract_interface().ok_or(VMError::NoritoInvalid)?;
    let mut matches = interface
        .states
        .iter()
        .filter(|state| state.name == base.as_ref());
    let state = matches.next().ok_or(VMError::NoritoInvalid)?;
    if matches.next().is_some() {
        return Err(VMError::NoritoInvalid);
    }
    match &state.ty {
        crate::metadata::EmbeddedStateType::StateMap { key, .. } => Ok(key),
        _ => Err(VMError::NoritoInvalid),
    }
}
/// Require `base` to name exactly one declared top-level `StateMap`.
pub(crate) fn validate_declared_state_map_base(vm: &IVM, base: &Name) -> Result<(), VMError> {
    declared_state_map_key_type(vm, base).map(drop)
}
#[path = "host/state_map_key.rs"]
mod state_map_key;
pub(crate) use state_map_key::state_map_key_schema;

/// Bind every scalar or tuple map key to its exact canonical StateValueRecordV1 schema.
pub(crate) fn validate_declared_state_map_key(
    vm: &IVM,
    base: &Name,
    key: &[u8],
) -> Result<(), VMError> {
    state_map_key::validate_key_record(vm, declared_state_map_key_type(vm, base)?, key)
}
/// Build a map path only after binding the canonical key to its CNTR type.
pub(crate) fn canonical_typed_state_map_path(
    vm: &IVM,
    base: &Name,
    key: &[u8],
) -> Result<StatePath, VMError> {
    validate_declared_state_map_key(vm, base, key)?;
    canonical_state_map_path(base, key)
}
enum DeclaredStatePath<'a> {
    Value(&'a crate::metadata::EmbeddedStateType),
    MapBase,
}
fn resolve_declared_state_path<'a>(
    vm: &'a IVM,
    path: &StatePath,
) -> Result<Option<DeclaredStatePath<'a>>, VMError> {
    let Some(interface) = vm.contract_interface() else {
        return Ok(None);
    };
    let (base, suffix) = path
        .as_ref()
        .split_once('/')
        .map_or((path.as_ref(), None), |(base, suffix)| (base, Some(suffix)));
    let mut matches = interface.states.iter().filter(|state| state.name == base);
    let state = matches.next().ok_or(VMError::NoritoInvalid)?;
    if matches.next().is_some() {
        return Err(VMError::NoritoInvalid);
    }
    match (&state.ty, suffix) {
        (crate::metadata::EmbeddedStateType::StateMap { .. }, None) => {
            Ok(Some(DeclaredStatePath::MapBase))
        }
        (crate::metadata::EmbeddedStateType::StateMap { value, .. }, Some(suffix)) => {
            if suffix.is_empty()
                || suffix.len() % 2 != 0
                || suffix.contains('/')
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(VMError::NoritoInvalid);
            }
            let key = hex::decode(suffix).map_err(|_| VMError::NoritoInvalid)?;
            let base: Name = base.parse().map_err(|_| VMError::NoritoInvalid)?;
            if canonical_state_map_path(&base, &key)?.as_ref() != path.as_ref() {
                return Err(VMError::NoritoInvalid);
            }
            validate_declared_state_map_key(vm, &base, &key)?;
            Ok(Some(DeclaredStatePath::Value(value)))
        }
        (ty, None) => Ok(Some(DeclaredStatePath::Value(ty))),
        (_, Some(_)) => Err(VMError::NoritoInvalid),
    }
}
/// Bind one value operation to the loaded CNTR durable-state declaration.
///
/// The VM rejects every durable-state syscall from generic programs before host dispatch. For
/// self-describing contracts, the first path segment must name exactly one declared scalar or one
/// canonical `StateMap` entry. The bare map base is a collection prefix and is therefore invalid
/// for value operations.
pub fn validate_declared_state_path(vm: &IVM, path: &StatePath) -> Result<(), VMError> {
    match resolve_declared_state_path(vm, path)? {
        Some(DeclaredStatePath::MapBase) => Err(VMError::NoritoInvalid),
        Some(DeclaredStatePath::Value(_)) | None => Ok(()),
    }
}
/// Bind a scan/count prefix to the loaded CNTR durable-state declaration.
///
/// Unlike value operations, scans may address the bare base of a declared `StateMap`. Generic
/// programs never reach this host-side check because the VM rejects their durable-state syscalls
/// before quoting or dispatch, while malformed or undeclared typed paths still fail closed.
pub fn validate_declared_state_scan_path(vm: &IVM, path: &StatePath) -> Result<(), VMError> {
    resolve_declared_state_path(vm, path).map(drop)
}
/// Validate a `STATE_SET` payload against the exact type declared by CNTR.
///
/// Compiler-emitted durable values are canonical `StateValueRecordV1`
/// payloads bound to the canonical schema hash. This check prevents callers
/// from writing a well-formed record for a different scalar or aggregate type.
pub fn validate_declared_state_value_payload(
    vm: &IVM,
    path: &StatePath,
    payload: &[u8],
) -> Result<(), VMError> {
    let Some(declared) = resolve_declared_state_path(vm, path)? else {
        return Ok(());
    };
    let DeclaredStatePath::Value(ty) = declared else {
        return Err(VMError::NoritoInvalid);
    };
    let schema = crate::state_value_runtime::schema_for_embedded_state_type(ty)?;
    crate::state_value_runtime::validate_state_value_record(vm, &schema, payload)
}
/// Validate a persisted value against a complete admitted V1 state type without executing code.
///
/// Lifecycle completion uses the same canonical record, pointer and schema checks as `STATE_SET`.
/// A map declaration is not a scalar value and is rejected.
///
/// # Errors
/// Rejects invalid types, malformed records, noncanonical payloads and schema mismatches.
pub fn validate_persisted_state_value_payload(
    ty: &crate::metadata::EmbeddedStateType,
    payload: &[u8],
) -> Result<(), VMError> {
    let schema = crate::state_value_runtime::schema_for_embedded_state_type(ty)?;
    crate::state_value_runtime::validate_state_value_record_for_policy(
        crate::SyscallPolicy::AbiV1,
        &schema,
        payload,
    )
}
/// Validate header-only `StateMap` path inputs and return their gas lengths.
///
/// `base_payload_len` is the framed canonical `Name` payload length from the pointer ABI, while
/// `key_payload_len` is the raw canonical key payload. The returned output length is conservative
/// and includes framing slack; the decoded execution path repeats the semantic base/key checks and
/// validates the final canonical `StatePath` against [`syscalls::STATE_MAX_PATH_BYTES`].
pub(crate) fn quote_canonical_state_map_path_lengths(
    base_payload_len: usize,
    key_payload_len: usize,
) -> Result<(usize, usize), VMError> {
    if base_payload_len > syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES
        || key_payload_len == 0
        || key_payload_len > syscalls::STATE_MAP_MAX_KEY_BYTES
    {
        return Err(VMError::NoritoInvalid);
    }
    let output_text_bound = syscalls::STATE_MAP_MAX_BASE_BYTES
        .checked_add(1)
        .and_then(|len| len.checked_add(key_payload_len.checked_mul(2)?))
        .ok_or(VMError::NoritoInvalid)?;
    if output_text_bound > syscalls::STATE_MAX_PATH_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    let output_bound = output_text_bound
        .checked_add(
            syscalls::STATE_MAX_PATH_FRAME_BYTES.saturating_sub(syscalls::STATE_MAX_PATH_BYTES),
        )
        .ok_or(VMError::NoritoInvalid)?;
    let input_len = base_payload_len
        .checked_add(key_payload_len)
        .ok_or(VMError::NoritoInvalid)?;
    Ok((input_len, output_bound))
}
/// Decode one canonical key from a `STATE_SCAN` page and validate its map path.
pub(crate) fn canonical_state_map_key_at(
    page_payload: &[u8],
    base: &Name,
    index: u64,
) -> Result<Option<Vec<u8>>, VMError> {
    if page_payload.len() > syscalls::STATE_MAP_MAX_PAGE_BYTES
        || base.as_ref().len() > syscalls::STATE_MAP_MAX_BASE_BYTES
        || state_path_name_payload_len(base)? > syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES
    {
        return Err(VMError::NoritoInvalid);
    }
    let default_limits = ivm_abi::codec::canonical_norito_decode_limits(page_payload.len());
    let item_limit = usize::try_from(syscalls::STATE_SCAN_MAX_ITEMS_V1).unwrap_or(usize::MAX);
    let page_limits = norito::core::DecodeLimits::new(
        default_limits.max_sequence_elements().min(item_limit),
        default_limits.max_field_bytes(),
        default_limits.max_total_elements(),
        default_limits.max_total_allocated_bytes(),
        default_limits.max_nesting_depth(),
    );
    let paths: Vec<StatePath> = decode_canonical_norito_with_limits(page_payload, page_limits)
        .map_err(|_| VMError::DecodeError)?;
    let mut previous: Option<&StatePath> = None;
    for path in &paths {
        validate_state_path(path)?;
        if previous.is_some_and(|previous| previous >= path) {
            return Err(VMError::NoritoInvalid);
        }
        previous = Some(path);
        let suffix = path
            .as_ref()
            .strip_prefix(base.as_ref())
            .and_then(|suffix| suffix.strip_prefix('/'))
            .ok_or(VMError::NoritoInvalid)?;
        if suffix.is_empty()
            || suffix.len() > syscalls::STATE_MAP_MAX_KEY_BYTES.saturating_mul(2)
            || suffix.len() % 2 != 0
            || suffix.contains('/')
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(VMError::NoritoInvalid);
        }
    }
    let index = usize::try_from(index).unwrap_or(usize::MAX);
    let Some(path) = paths.get(index) else {
        return Ok(None);
    };
    let suffix = path
        .as_ref()
        .strip_prefix(base.as_ref())
        .and_then(|suffix| suffix.strip_prefix('/'))
        .ok_or(VMError::NoritoInvalid)?;
    if suffix.is_empty()
        || suffix.len() % 2 != 0
        || suffix.contains('/')
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(VMError::NoritoInvalid);
    }
    let key = hex::decode(suffix).map_err(|_| VMError::NoritoInvalid)?;
    if key.len() > syscalls::STATE_MAP_MAX_KEY_BYTES
        || canonical_state_map_path(base, &key)?.as_ref() != path.as_ref()
    {
        return Err(VMError::NoritoInvalid);
    }
    Ok(Some(key))
}
fn parse_tlv_header(vm: &IVM, header: &[u8]) -> Result<(PointerType, usize), VMError> {
    let raw_type = u16::from_be_bytes([header[0], header[1]]);
    let pointer_type = PointerType::from_u16(raw_type).ok_or(VMError::NoritoInvalid)?;
    if header[2] != 1 {
        return Err(VMError::NoritoInvalid);
    }
    if !pointer_abi::is_type_allowed_for_policy(vm.syscall_policy(), pointer_type) {
        return Err(VMError::AbiTypeNotAllowed {
            abi: vm.abi_version(),
            type_id: raw_type,
        });
    }
    let payload_len = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    Ok((pointer_type, payload_len))
}
fn quote_tlv_header_at(vm: &IVM, address: u64) -> Result<(PointerType, usize), VMError> {
    vm.ensure_owned_public_tlv_range(address, 7)?;
    parse_tlv_header(vm, vm.memory.inspect_region(address, 7)?)
}
fn read_tlv_header_at(vm: &IVM, address: u64) -> Result<(PointerType, usize), VMError> {
    vm.ensure_owned_public_tlv_range(address, 7)?;
    parse_tlv_header(vm, vm.memory.load_region(address, 7)?)
}
fn validate_quoted_tlv_range(vm: &IVM, address: u64, payload_len: usize) -> Result<(), VMError> {
    let total = 7usize
        .checked_add(payload_len)
        .and_then(|len| len.checked_add(iroha_crypto::Hash::LENGTH))
        .ok_or(VMError::NoritoInvalid)?;
    let total = u64::try_from(total).map_err(|_| VMError::NoritoInvalid)?;
    vm.ensure_owned_tlv_range(address, total)?;
    vm.memory.inspect_region(address, total)?;
    Ok(())
}
fn quote_bounded_tlv_payload_len_at(
    vm: &IVM,
    address: u64,
    expected: PointerType,
    maximum_payload_len: usize,
) -> Result<usize, VMError> {
    // The cap is checked from the provenance-checked fixed header before the
    // complete declared range is inspected or its digest is authenticated.
    // Fixed/byte-linear syscalls can therefore reject oversized envelopes
    // without performing attacker-controlled payload work first.
    let (actual, payload_len) = quote_tlv_header_at(vm, address)?;
    if actual != expected || payload_len > maximum_payload_len {
        return Err(VMError::NoritoInvalid);
    }
    validate_quoted_tlv_range(vm, address, payload_len)?;
    Ok(payload_len)
}
fn read_bounded_tlv_payload_len_at(
    vm: &IVM,
    address: u64,
    expected: PointerType,
    maximum_payload_len: usize,
) -> Result<usize, VMError> {
    let (actual, payload_len) = read_tlv_header_at(vm, address)?;
    if actual != expected || payload_len > maximum_payload_len {
        return Err(VMError::NoritoInvalid);
    }
    validate_quoted_tlv_range(vm, address, payload_len)?;
    Ok(payload_len)
}
/// Inspect a TLV header for gas quoting without decoding, hashing, or allocating.
///
/// # Errors
///
/// Returns an error when the envelope header, bounds, pointer type, or ABI policy is invalid.
pub fn quote_any_tlv_at(vm: &IVM, address: u64) -> Result<(PointerType, usize), VMError> {
    let (pointer_type, payload_len) = quote_tlv_header_at(vm, address)?;
    validate_quoted_tlv_range(vm, address, payload_len)?;
    Ok((pointer_type, payload_len))
}
/// Inspect a typed TLV header for gas quoting without decoding, hashing, or allocating.
///
/// # Errors
///
/// Returns an error when the envelope is invalid or does not have `expected` pointer type.
pub fn quote_tlv_payload_len_at(
    vm: &IVM,
    address: u64,
    expected: PointerType,
) -> Result<usize, VMError> {
    let (actual, payload_len) = quote_any_tlv_at(vm, address)?;
    if actual != expected {
        return Err(VMError::NoritoInvalid);
    }
    Ok(payload_len)
}
/// Header-only quote for one encoded ZK batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkBatchGasQuote {
    /// Complete encoded batch archive length.
    pub payload_bytes: usize,
    /// Best-effort untrusted count used to reserve gas.
    pub quoted_proof_count: usize,
    /// Conservative schedule cost debited before host execution.
    pub gas: u64,
}
/// Inspect one ZK envelope TLV and compute its conservative pre-decode quote.
///
/// # Errors
///
/// Returns an error when the TLV is invalid or exceeds the schedule's hard payload cap.
pub fn quote_zk_single_at(
    vm: &IVM,
    address: u64,
    schedule: gas::ZkGasScheduleV1,
) -> Result<(usize, u64), VMError> {
    let payload_bytes = quote_tlv_payload_len_at(vm, address, PointerType::NoritoBytes)?;
    if u64::try_from(payload_bytes).unwrap_or(u64::MAX) > schedule.max_payload_bytes {
        return Err(VMError::NoritoInvalid);
    }
    Ok((
        payload_bytes,
        schedule.conservative_single_gas(payload_bytes),
    ))
}
/// Inspect a ZK batch TLV and compute a conservative pre-decode quote.
///
/// Only the fixed archive header, bounded alignment padding, and top-level count are inspected.
/// Schema, flags, and checksums are intentionally left to execution after the quote is debited.
/// Malformed headers fall back to one proof, while counts above the V1 cap are clamped to `cap +
/// 1`; neither case can reach decoding or backend verification.
///
/// # Errors
///
/// Returns an error when the TLV is invalid or exceeds the schedule's hard payload cap.
pub fn quote_zk_batch_at(
    vm: &IVM,
    address: u64,
    schedule: gas::ZkGasScheduleV1,
) -> Result<ZkBatchGasQuote, VMError> {
    const COMPRESSION_OFFSET: usize = 22;
    const LENGTH_OFFSET: usize = COMPRESSION_OFFSET + 1;
    const LENGTH_END: usize = LENGTH_OFFSET + 8;
    const MAX_ALIGNMENT_PADDING: usize = 64;
    let payload_len = quote_tlv_payload_len_at(vm, address, PointerType::NoritoBytes)?;
    if u64::try_from(payload_len).unwrap_or(u64::MAX) > schedule.max_payload_bytes {
        return Err(VMError::NoritoInvalid);
    }
    let quoted_proof_count = (|| -> Option<usize> {
        if payload_len < norito::core::Header::SIZE + 8 {
            return None;
        }
        let payload_address = address.checked_add(7)?;
        let header = vm
            .memory
            .inspect_region(payload_address, norito::core::Header::SIZE as u64)
            .ok()?;
        let encoded_payload_len = usize::try_from(u64::from_le_bytes(
            header.get(LENGTH_OFFSET..LENGTH_END)?.try_into().ok()?,
        ))
        .ok()?;
        let archive_tail_len = payload_len.checked_sub(norito::core::Header::SIZE)?;
        let padding_len = archive_tail_len.checked_sub(encoded_payload_len)?;
        if padding_len > MAX_ALIGNMENT_PADDING || encoded_payload_len < 8 {
            return None;
        }
        let count_address = payload_address
            .checked_add(norito::core::Header::SIZE as u64)?
            .checked_add(u64::try_from(padding_len).ok()?)?;
        let count = u64::from_le_bytes(
            vm.memory
                .inspect_region(count_address, 8)
                .ok()?
                .try_into()
                .ok()?,
        );
        usize::try_from(count).ok()
    })()
    .unwrap_or(1)
    .max(1)
    .min(
        usize::try_from(schedule.max_batch_proofs)
            .unwrap_or(usize::MAX)
            .saturating_add(1),
    );
    Ok(ZkBatchGasQuote {
        payload_bytes: payload_len,
        quoted_proof_count,
        gas: schedule.conservative_batch_gas(quoted_proof_count, payload_len),
    })
}
/// Decode the sole ABI-v1 public ZK envelope schema canonically.
///
/// # Errors
///
/// Returns [`ERR_DECODE`] for invalid headers, flags, schema, checksum, or payloads.
pub fn decode_canonical_zk_envelope(payload: &[u8]) -> Result<OpenVerifyEnvelope, u64> {
    // Pointer-ABI payloads begin seven bytes into their TLV envelope, so a
    // valid nested Norito frame is not necessarily aligned for the zero-copy
    // `from_bytes` path. The canonical slice decoder validates the same
    // header, schema, flags, padding, and checksum while safely realigning
    // when required.
    decode_canonical_norito(payload).map_err(|_| ERR_DECODE)
}
/// Decode the sole ABI-v1 public ZK batch schema with a bounded item count.
///
/// # Errors
///
/// Returns [`ERR_DECODE`] for invalid headers, flags, schema, checksum, an
/// empty batch, or malformed elements, and [`ERR_BATCH`] above `max_items`.
pub fn decode_canonical_zk_batch(
    payload: &[u8],
    max_items: usize,
) -> Result<Vec<OpenVerifyEnvelope>, u64> {
    type Batch = Vec<OpenVerifyEnvelope>;
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let _payload_context = norito::core::PayloadCtxGuard::enter(payload);
    // Validate the complete frame without requiring the TLV payload address
    // itself to satisfy `Batch` payload-storage alignment. Inspect the bounded
    // top-level count before materializing any elements.
    let view = norito::core::from_bytes_view(payload).map_err(|_| ERR_DECODE)?;
    if view.schema() != norito::schema::identity::frame_hash::<Batch>() {
        return Err(ERR_DECODE);
    }
    let alignment = norito::core::archived_payload_align::<Batch>();
    let expected_padding = if alignment <= 1 {
        0
    } else {
        (alignment - Header::SIZE % alignment) % alignment
    };
    let actual_padding = payload
        .len()
        .checked_sub(Header::SIZE)
        .and_then(|tail| tail.checked_sub(view.as_bytes().len()))
        .ok_or(ERR_DECODE)?;
    if actual_padding != expected_padding {
        return Err(ERR_DECODE);
    }
    let (count, _) = norito::core::read_seq_len_slice(view.as_bytes()).map_err(|_| ERR_DECODE)?;
    if count == 0 {
        return Err(ERR_DECODE);
    }
    if count > max_items {
        return Err(ERR_BATCH);
    }
    let batch: Batch = decode_canonical_norito(payload).map_err(|_| ERR_DECODE)?;
    if batch.len() != count {
        return Err(ERR_DECODE);
    }
    Ok(batch)
}
/// Map canonical data-model envelope validation failures to stable ABI statuses.
#[must_use]
pub const fn map_open_verify_validation_error(error: OpenVerifyEnvelopeValidationError) -> u64 {
    match error {
        OpenVerifyEnvelopeValidationError::ZeroVerifierKeyHash => ERR_VK_MISSING,
        OpenVerifyEnvelopeValidationError::NonEmptyAux => ERR_VK_MISMATCH,
        OpenVerifyEnvelopeValidationError::ProofBytesTooLarge { .. } => ERR_PROOF_LEN,
        OpenVerifyEnvelopeValidationError::PublicInputsTooLarge { .. }
        | OpenVerifyEnvelopeValidationError::CircuitIdTooLarge { .. }
        | OpenVerifyEnvelopeValidationError::AuxTooLarge { .. } => ERR_ENVELOPE_SIZE,
        OpenVerifyEnvelopeValidationError::EmptyCircuitId
        | OpenVerifyEnvelopeValidationError::InvalidCircuitId
        | OpenVerifyEnvelopeValidationError::ReservedPrivacyProtocolCircuitId
        | OpenVerifyEnvelopeValidationError::EmptyPublicInputs
        | OpenVerifyEnvelopeValidationError::AllZeroPublicInputs
        | OpenVerifyEnvelopeValidationError::EmptyProofBytes
        | OpenVerifyEnvelopeValidationError::AllZeroProofBytes => ERR_DECODE,
    }
}
/// Security-relevant host work class used by ABI-v1 syscall metering.
///
/// This is deliberately separate from a compiler builtin's source-level gas
/// class. It describes which runtime resource must be affordable before the
/// host performs work or exposes a side effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSyscallGasClass {
    /// VM-local or immutable-context work with an input/output-derived bound.
    VmLocal,
    /// Guest-memory allocation whose size is known from public registers.
    Allocation,
    /// Contract-owned durable-state read.
    DurableStateRead,
    /// Contract-owned durable-state write.
    DurableStateWrite,
    /// Ledger/world-state query.
    LedgerRead,
    /// Ledger/world-state mutation or queued instruction.
    LedgerWrite,
    /// Nested, opaque, or externally routed work.
    Dynamic,
}
/// Default quote strategy required for a host syscall class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSyscallQuoteStrategy {
    /// The host derives a deterministic upper bound from public VM inputs.
    InputOutputBounded,
    /// The allocation extent itself determines the exact quote.
    AllocationExtent,
    /// Escrow all currently available gas and enforce bounded post-debit work.
    ReserveAvailable,
}
/// Stable prepare/execute gas formula assigned to one ABI syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSyscallGasFormula {
    /// Phase-by-phase exact-number validation and logical-limb arithmetic.
    NumericStaged,
    /// Fixed or byte-linear VM-local helper with public inputs.
    ByteLinear,
    /// Cryptographic verification with the canonical verification base.
    VerifyByteLinear,
    /// V1 VRF verification charged by canonical bytes and examined items.
    VrfVerifyV1,
    /// V1 ZK verification charged per proof, public input, and encoded byte.
    ZkVerifyV1,
    /// Schema codec with the canonical schema base.
    SchemaByteLinear,
    /// Allocation extent divided into canonical ABI words.
    AllocationExtent,
    /// Heap growth in canonical logical pages.
    GrowHeapPages,
    /// Commit only the append-only output prefix, charging every copied byte.
    CommitOutput,
    /// Durable-state read reserving available gas before charging the exact value length.
    StateGet,
    /// Durable-state path-only operation.
    StatePath,
    /// Durable-state path plus value bytes.
    StateValue,
    /// Bounded live keyset scan with a schema-bound continuation.
    StateScan,
    /// Ordered durable-state count scan.
    StateCount,
    /// Escrow the available bounded budget before host-dependent work.
    ReserveAvailable,
    /// V1 ledger query charged by request kind, visited/skipped items, and bytes.
    LedgerQueryV1,
    /// Conservative pointer-input and complete-output-region envelope.
    ConservativeEnvelope,
}
/// Canonical gas-parameter family consumed by a syscall formula.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSyscallGasParameters {
    /// Exact-number envelope, logical-limb, and decimal-scale constants.
    Numeric,
    /// Common byte-linear host constants.
    HostByte,
    /// Verification base and byte rate.
    HostVerify,
    /// V1 VRF base, item/byte rates, formula version, and hard caps.
    VrfVerifyV1,
    /// V1 ZK rates, public-input unit, batch-output layout, and hard caps.
    ZkVerifyV1,
    /// Schema codec base and byte rate.
    HostSchema,
    /// Allocation base and word size.
    Allocation,
    /// Heap-growth base, page rate, and page size.
    GrowHeap,
    /// Output-commit base and per-byte rate.
    HostCommit,
    /// Durable-state base, byte/item rates, and ABI state caps.
    DurableState,
    /// Conservative base, input multiplier, and output-region multiplier.
    Conservative,
    /// V1 ledger-query bases, item/sort rates, byte rate, and formula version.
    LedgerQueryV1,
}
/// Exhaustive ABI-v1 host metering metadata for one syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSyscallMeteringSpec {
    /// Canonical syscall number.
    pub number: u32,
    /// Debit lifecycle used by the VM for this syscall.
    pub metering: SyscallMetering,
    /// Security-relevant runtime work class.
    pub gas_class: HostSyscallGasClass,
    /// Fail-closed default quote strategy.
    pub quote_strategy: HostSyscallQuoteStrategy,
    /// Exact consensus formula selected for preparation.
    pub formula: HostSyscallGasFormula,
    /// Canonical parameter family consumed by [`Self::formula`].
    pub parameters: HostSyscallGasParameters,
    /// Minimum reserve required before host-state work may begin.
    pub minimum_gas: u64,
}
/// Return the explicitly registered gas formula for one ABI-v1 syscall.
///
/// This registry deliberately does not derive a formula from the access class: access and metering
/// are independent security claims. Adding a syscall to the ABI therefore requires updating both
/// registries, otherwise preparation fails closed with [`VMError::UnknownSyscall`].
#[must_use]
pub const fn registered_host_syscall_gas_formula(number: u32) -> Option<HostSyscallGasFormula> {
    if syscalls::is_numeric_v1_syscall(number) {
        return Some(HostSyscallGasFormula::NumericStaged);
    }
    if matches!(number, syscalls::SYSCALL_ALLOC) {
        return Some(HostSyscallGasFormula::AllocationExtent);
    }
    if matches!(number, syscalls::SYSCALL_GROW_HEAP) {
        return Some(HostSyscallGasFormula::GrowHeapPages);
    }
    if matches!(number, syscalls::SYSCALL_COMMIT_OUTPUT) {
        return Some(HostSyscallGasFormula::CommitOutput);
    }
    if matches!(number, syscalls::SYSCALL_STATE_GET) {
        return Some(HostSyscallGasFormula::StateGet);
    }
    if matches!(number, syscalls::SYSCALL_STATE_SET) {
        return Some(HostSyscallGasFormula::StateValue);
    }
    if matches!(
        number,
        syscalls::SYSCALL_STATE_DEL | syscalls::SYSCALL_STATE_HAS | syscalls::SYSCALL_STATE_LEN
    ) {
        return Some(HostSyscallGasFormula::StatePath);
    }
    if matches!(number, syscalls::SYSCALL_STATE_SCAN) {
        return Some(HostSyscallGasFormula::StateScan);
    }
    if matches!(number, syscalls::SYSCALL_STATE_COUNT) {
        return Some(HostSyscallGasFormula::StateCount);
    }
    if matches!(
        number,
        syscalls::SYSCALL_VERIFY_PROOF
            | syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT
            | syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY
            | syscalls::SYSCALL_ZK_VERIFY_BATCH
    ) {
        return Some(HostSyscallGasFormula::ZkVerifyV1);
    }
    if matches!(number, syscalls::SYSCALL_VERIFY_SIGNATURE) {
        return Some(HostSyscallGasFormula::VerifyByteLinear);
    }
    if matches!(
        number,
        syscalls::SYSCALL_VRF_VERIFY | syscalls::SYSCALL_VRF_VERIFY_BATCH
    ) {
        return Some(HostSyscallGasFormula::VrfVerifyV1);
    }
    if matches!(
        number,
        syscalls::SYSCALL_SCHEMA_ENCODE
            | syscalls::SYSCALL_SCHEMA_DECODE
            | syscalls::SYSCALL_SCHEMA_INFO
    ) {
        return Some(HostSyscallGasFormula::SchemaByteLinear);
    }
    if matches!(
        number,
        syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY
            | syscalls::SYSCALL_QUERY_EXECUTE_NORITO
            | syscalls::SYSCALL_CORE_QUERY_GET
            | syscalls::SYSCALL_CORE_QUERY_PAGE
            | syscalls::SYSCALL_QUERY_GET_PARAMETER
            | syscalls::SYSCALL_QUERY_GET_CONTRACT_MANIFEST
            | syscalls::SYSCALL_QUERY_GET_CONTRACT_INSTANCE
            | syscalls::SYSCALL_GET_ACCOUNT_BALANCE
            | syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS
    ) {
        return Some(HostSyscallGasFormula::LedgerQueryV1);
    }
    if matches!(
        number,
        syscalls::SYSCALL_JSON_BUILD
            | syscalls::SYSCALL_VALUE_ENCODE
            | syscalls::SYSCALL_BLOB_CONCAT
            | syscalls::SYSCALL_UTF8_VALIDATE
            | syscalls::SYSCALL_VALUE_TO_STRING
            | syscalls::SYSCALL_STATE_VALUE_ENCODE
            | syscalls::SYSCALL_STATE_VALUE_DECODE
            | syscalls::SYSCALL_GET_PUBLIC_INPUT
            | syscalls::SYSCALL_VRF_EPOCH_SEED
            | syscalls::SYSCALL_ZK_ROOTS_GET
            | syscalls::SYSCALL_ZK_VOTE_GET_TALLY
            | syscalls::SYSCALL_SORACLOUD_READ_COMMITTED_STATE
            | syscalls::SYSCALL_SORACLOUD_READ_CONFIG
            | syscalls::SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE
            | syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION
            | syscalls::SYSCALL_CALL_CONTRACT
            | syscalls::SYSCALL_EMIT_CONTRACT_EVENT
            | syscalls::SYSCALL_CREATE_NFTS_FOR_ALL_USERS
            | syscalls::SYSCALL_SET_SMARTCONTRACT_EXECUTION_DEPTH
    ) {
        return Some(HostSyscallGasFormula::ReserveAvailable);
    }
    if matches!(
        number,
        syscalls::SYSCALL_REGISTER_DOMAIN
            | syscalls::SYSCALL_UNREGISTER_DOMAIN
            | syscalls::SYSCALL_TRANSFER_DOMAIN
            | syscalls::SYSCALL_REGISTER_PEER
            | syscalls::SYSCALL_UNREGISTER_PEER
            | syscalls::SYSCALL_REGISTER_ACCOUNT
            | syscalls::SYSCALL_UNREGISTER_ACCOUNT
            | syscalls::SYSCALL_ADD_SIGNATORY
            | syscalls::SYSCALL_REMOVE_SIGNATORY
            | syscalls::SYSCALL_SET_ACCOUNT_QUORUM
            | syscalls::SYSCALL_SET_ACCOUNT_DETAIL
            | syscalls::SYSCALL_REGISTER_ASSET
            | syscalls::SYSCALL_UNREGISTER_ASSET
            | syscalls::SYSCALL_MINT_ASSET
            | syscalls::SYSCALL_BURN_ASSET
            | syscalls::SYSCALL_TRANSFER_V1
            | syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN
            | syscalls::SYSCALL_TRANSFER_V1_BATCH_END
            | syscalls::SYSCALL_TRANSFER_V1_BATCH_APPLY
            | syscalls::SYSCALL_TRANSFER_ASSET_SCOPED
            | syscalls::SYSCALL_NFT_MINT_ASSET
            | syscalls::SYSCALL_NFT_TRANSFER_ASSET
            | syscalls::SYSCALL_NFT_SET_METADATA
            | syscalls::SYSCALL_NFT_BURN_ASSET
            | syscalls::SYSCALL_CREATE_ROLE
            | syscalls::SYSCALL_DELETE_ROLE
            | syscalls::SYSCALL_GRANT_ROLE
            | syscalls::SYSCALL_REVOKE_ROLE
            | syscalls::SYSCALL_GRANT_PERMISSION
            | syscalls::SYSCALL_REVOKE_PERMISSION
            | syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION
            | syscalls::SYSCALL_REVOKE_CONTRACT_PERMISSION
            | syscalls::SYSCALL_CREATE_TRIGGER
            | syscalls::SYSCALL_REMOVE_TRIGGER
            | syscalls::SYSCALL_SET_TRIGGER_ENABLED
            | syscalls::SYSCALL_REGISTER_SMART_CONTRACT_CODE
            | syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES
            | syscalls::SYSCALL_ACTIVATE_CONTRACT_INSTANCE
            | syscalls::SYSCALL_DEACTIVATE_CONTRACT_INSTANCE
            | syscalls::SYSCALL_REMOVE_SMART_CONTRACT_BYTES
            | syscalls::SYSCALL_AXT_BEGIN
            | syscalls::SYSCALL_AXT_TOUCH
            | syscalls::SYSCALL_AXT_COMMIT
            | syscalls::SYSCALL_VERIFY_DS_PROOF
            | syscalls::SYSCALL_AXT_STAGE_ANCHORED_SPEND
            | syscalls::SYSCALL_ESCROW_OPEN_OFFER
            | syscalls::SYSCALL_ESCROW_ACCEPT
            | syscalls::SYSCALL_ESCROW_MARK_PAYMENT_SENT
            | syscalls::SYSCALL_ESCROW_RELEASE
            | syscalls::SYSCALL_ESCROW_CANCEL
            | syscalls::SYSCALL_ESCROW_OPEN_DISPUTE
            | syscalls::SYSCALL_ESCROW_RESOLVE_DISPUTE
            | syscalls::SYSCALL_SUBSCRIPTION_BILL
            | syscalls::SYSCALL_SUBSCRIPTION_RECORD_USAGE
            | syscalls::SYSCALL_SORACLOUD_EMIT_STATE_MUTATION
            | syscalls::SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE
            | syscalls::SYSCALL_SORACLOUD_APPEND_JOURNAL
            | syscalls::SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT
            | syscalls::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY
            | syscalls::SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT
            | syscalls::SYSCALL_SET_ASSET_HOLDING_LIMIT
            | syscalls::SYSCALL_ACCOUNT_RECOVERY_PROPOSE
            | syscalls::SYSCALL_ACCOUNT_RECOVERY_APPROVE
            | syscalls::SYSCALL_ACCOUNT_RECOVERY_CANCEL
            | syscalls::SYSCALL_ACCOUNT_RECOVERY_FINALIZE
    ) {
        return Some(HostSyscallGasFormula::ConservativeEnvelope);
    }
    if matches!(
        number,
        syscalls::SYSCALL_EXIT
            | syscalls::SYSCALL_ABORT
            | syscalls::SYSCALL_CONTRACT_ABORT
            | syscalls::SYSCALL_DEBUG_PRINT
            | syscalls::SYSCALL_DEBUG_LOG
            | syscalls::SYSCALL_GET_PRIVATE_INPUT
            | syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM
            | syscalls::SYSCALL_INPUT_PUBLISH_TLV
            | syscalls::SYSCALL_SM3_HASH
            | syscalls::SYSCALL_SM2_VERIFY
            | syscalls::SYSCALL_SM4_GCM_SEAL
            | syscalls::SYSCALL_SM4_GCM_OPEN
            | syscalls::SYSCALL_SM4_CCM_SEAL
            | syscalls::SYSCALL_SM4_CCM_OPEN
            | syscalls::SYSCALL_SHA256_HASH
            | syscalls::SYSCALL_SHA3_HASH
            | syscalls::SYSCALL_BLAKE2B256_HASH
            | syscalls::SYSCALL_KECCAK256_HASH
            | syscalls::SYSCALL_IROHA_HASH
            | syscalls::SYSCALL_EXECUTION_SUMMARY
            | syscalls::SYSCALL_GET_MERKLE_PATH
            | syscalls::SYSCALL_GET_MERKLE_COMPACT
            | syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT
            | syscalls::SYSCALL_JSON_ENCODE
            | syscalls::SYSCALL_JSON_DECODE
            | syscalls::SYSCALL_TLV_LEN
            | syscalls::SYSCALL_JSON_GET_JSON
            | syscalls::SYSCALL_JSON_GET_NAME
            | syscalls::SYSCALL_JSON_GET_ACCOUNT_ID
            | syscalls::SYSCALL_JSON_GET_NFT_ID
            | syscalls::SYSCALL_JSON_GET_BLOB_HEX
            | syscalls::SYSCALL_JSON_GET_ASSET_DEFINITION_ID
            | syscalls::SYSCALL_JSON_GET_INT
            | syscalls::SYSCALL_JSON_GET_DECIMAL
            | syscalls::SYSCALL_JSON_GET_QUANTITY
            | syscalls::SYSCALL_JSON_GET_STRING
            | syscalls::SYSCALL_JSON_GET_BOOL
            | syscalls::SYSCALL_JSON_OBJECT
            | syscalls::SYSCALL_JSON_SET_I64
            | syscalls::SYSCALL_JSON_SET_ACCOUNT_ID
            | syscalls::SYSCALL_NAME_DECODE
            | syscalls::SYSCALL_BUILD_PATH_KEY_NORITO
            | syscalls::SYSCALL_STATE_PATH_FROM_NAME
            | syscalls::SYSCALL_POINTER_TO_NORITO
            | syscalls::SYSCALL_POINTER_FROM_NORITO
            | syscalls::SYSCALL_TLV_EQ
            | syscalls::SYSCALL_GET_AUTHORITY
            | syscalls::SYSCALL_CURRENT_TIME_MS
            | syscalls::SYSCALL_SYSVAR_CHAIN_ID
            | syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT
            | syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS
            | syscalls::SYSCALL_SYSVAR_AUTHORITY
            | syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS
            | syscalls::SYSCALL_SYSVAR_CONTRACT_SUBJECT
            | syscalls::SYSCALL_SYSVAR_ENTRYPOINT
            | syscalls::SYSCALL_NORMALIZE_NORITO_BYTES
            | syscalls::SYSCALL_DECODE_ARGUMENT_RECORD
            | syscalls::SYSCALL_STATE_MAP_KEY_AT
    ) {
        return Some(HostSyscallGasFormula::ByteLinear);
    }
    None
}
/// Return the registered metering metadata for an allowed syscall.
///
/// The access registry has no fallback. Consequently, adding a number to the
/// allowed ABI surface without classifying it makes preparation return
/// `UnknownSyscall` instead of silently selecting a generic quote.
#[must_use]
pub fn host_syscall_metering_spec(
    policy: SyscallPolicy,
    number: u32,
) -> Option<HostSyscallMeteringSpec> {
    if !syscalls::is_syscall_allowed(policy, number) {
        return None;
    }
    let access = syscalls::registered_syscall_access(number)?;
    let formula = registered_host_syscall_gas_formula(number)?;
    let metering = if matches!(formula, HostSyscallGasFormula::NumericStaged) {
        SyscallMetering::Staged
    } else {
        SyscallMetering::Reserved
    };
    let parameters = match formula {
        HostSyscallGasFormula::NumericStaged => HostSyscallGasParameters::Numeric,
        HostSyscallGasFormula::VerifyByteLinear => HostSyscallGasParameters::HostVerify,
        HostSyscallGasFormula::VrfVerifyV1 => HostSyscallGasParameters::VrfVerifyV1,
        HostSyscallGasFormula::ZkVerifyV1 => HostSyscallGasParameters::ZkVerifyV1,
        HostSyscallGasFormula::SchemaByteLinear => HostSyscallGasParameters::HostSchema,
        HostSyscallGasFormula::AllocationExtent => HostSyscallGasParameters::Allocation,
        HostSyscallGasFormula::GrowHeapPages => HostSyscallGasParameters::GrowHeap,
        HostSyscallGasFormula::CommitOutput => HostSyscallGasParameters::HostCommit,
        HostSyscallGasFormula::StateGet
        | HostSyscallGasFormula::StatePath
        | HostSyscallGasFormula::StateValue
        | HostSyscallGasFormula::StateScan
        | HostSyscallGasFormula::StateCount => HostSyscallGasParameters::DurableState,
        HostSyscallGasFormula::LedgerQueryV1 => HostSyscallGasParameters::LedgerQueryV1,
        HostSyscallGasFormula::ConservativeEnvelope => HostSyscallGasParameters::Conservative,
        HostSyscallGasFormula::ByteLinear | HostSyscallGasFormula::ReserveAvailable => {
            HostSyscallGasParameters::HostByte
        }
    };
    let quote_strategy = match formula {
        HostSyscallGasFormula::AllocationExtent | HostSyscallGasFormula::GrowHeapPages => {
            HostSyscallQuoteStrategy::AllocationExtent
        }
        HostSyscallGasFormula::ReserveAvailable
        | HostSyscallGasFormula::StateGet
        | HostSyscallGasFormula::LedgerQueryV1
        | HostSyscallGasFormula::StateScan
        | HostSyscallGasFormula::StateCount => HostSyscallQuoteStrategy::ReserveAvailable,
        _ => HostSyscallQuoteStrategy::InputOutputBounded,
    };
    let minimum_gas = match parameters {
        HostSyscallGasParameters::Numeric => crate::numeric_gas::NUMERIC_ENTRY_GAS,
        HostSyscallGasParameters::HostVerify => gas::HOST_VERIFY_GAS_BASE,
        HostSyscallGasParameters::VrfVerifyV1 => gas::vrf_verify_gas(1, 0),
        HostSyscallGasParameters::ZkVerifyV1 => gas::HOST_ZK_VERIFY_GAS_PER_PROOF,
        HostSyscallGasParameters::HostSchema => gas::HOST_SCHEMA_GAS_BASE,
        HostSyscallGasParameters::Allocation => gas::ALLOCATION_GAS_BASE,
        HostSyscallGasParameters::GrowHeap => gas::GROW_HEAP_GAS_BASE,
        HostSyscallGasParameters::HostCommit => gas::HOST_COMMIT_OUTPUT_GAS,
        HostSyscallGasParameters::DurableState => STATE_QUERY_GAS_BASE,
        HostSyscallGasParameters::LedgerQueryV1 => gas::LEDGER_QUERY_GAS_BASE_SINGULAR,
        HostSyscallGasParameters::Conservative => gas::CONSERVATIVE_SYSCALL_GAS_BASE,
        HostSyscallGasParameters::HostByte => match formula {
            HostSyscallGasFormula::ReserveAvailable => gas::HOST_BYTE_GAS_BASE,
            _ => 0,
        },
    };
    let gas_class = if matches!(
        formula,
        HostSyscallGasFormula::AllocationExtent | HostSyscallGasFormula::GrowHeapPages
    ) {
        HostSyscallGasClass::Allocation
    } else {
        match access {
            syscalls::SyscallAccess::None => HostSyscallGasClass::VmLocal,
            syscalls::SyscallAccess::StateRead => HostSyscallGasClass::DurableStateRead,
            syscalls::SyscallAccess::StateWrite => HostSyscallGasClass::DurableStateWrite,
            syscalls::SyscallAccess::LedgerRead => HostSyscallGasClass::LedgerRead,
            syscalls::SyscallAccess::LedgerWrite => HostSyscallGasClass::LedgerWrite,
            syscalls::SyscallAccess::Dynamic => HostSyscallGasClass::Dynamic,
        }
    };
    Some(HostSyscallMeteringSpec {
        number,
        metering,
        gas_class,
        quote_strategy,
        formula,
        parameters,
        minimum_gas,
    })
}
/// Return the complete, sorted ABI-v1 host metering registry.
///
/// An allowed syscall missing explicit access metadata is intentionally absent.
/// Production preparation rejects that number, and the exhaustive release test
/// requires this registry's numbers to equal [`syscalls::abi_syscall_list`].
pub fn abi_v1_host_syscall_metering_registry() -> &'static [HostSyscallMeteringSpec] {
    static REGISTRY: std::sync::OnceLock<Box<[HostSyscallMeteringSpec]>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        syscalls::abi_syscall_list()
            .iter()
            .filter_map(|&number| host_syscall_metering_spec(SyscallPolicy::AbiV1, number))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    })
}
/// Require registered metering metadata for an allowed host syscall.
///
/// # Errors
///
/// Returns [`VMError::UnknownSyscall`] for a disallowed or unclassified number.
pub fn require_host_syscall_metering_spec(
    policy: SyscallPolicy,
    number: u32,
) -> Result<HostSyscallMeteringSpec, VMError> {
    host_syscall_metering_spec(policy, number).ok_or(VMError::UnknownSyscall(number))
}
/// Conservative deterministic gas bound for host implementations whose exact
/// response size is unavailable during syscall preparation.
///
/// The bound scales all pointer-ABI payloads in the syscall argument registers
/// and reserves the complete host-output regions. Hosts should prefer a tighter
/// syscall-specific quote whenever they can compute one without side effects.
#[must_use]
pub fn conservative_syscall_gas_quote(number: u32, vm: &IVM) -> u64 {
    let mut argument_bytes = 0_u64;
    for &register in crate::ivm::syscall_public_input_registers(number) {
        let pointer = vm.register(register);
        if pointer == 0 {
            continue;
        }
        let payload_len = quote_any_tlv_at(vm, pointer)
            .ok()
            .map_or(0, |(_, payload_len)| {
                u64::try_from(payload_len).unwrap_or(u64::MAX)
            });
        argument_bytes = argument_bytes.saturating_add(payload_len);
    }
    let response_bytes = Memory::INPUT_SIZE.saturating_add(Memory::OUTPUT_SIZE);
    gas::CONSERVATIVE_SYSCALL_GAS_BASE
        .saturating_add(gas::CONSERVATIVE_SYSCALL_INPUT_MULTIPLIER.saturating_mul(argument_bytes))
        .saturating_add(
            gas::CONSERVATIVE_SYSCALL_RESPONSE_MULTIPLIER.saturating_mul(response_bytes),
        )
}
/// Reserve all gas currently available to a syscall whose exact cost depends on host state.
///
/// The host must call [`preflight_reserved_syscall_gas`] with the exact cost after reading its
/// state and before making any guest-visible allocation or mutation. Reserving a non-zero amount
/// also distinguishes VM-dispatched calls from direct host calls in tests and tooling.
pub fn reserve_available_syscall_gas(vm: &IVM) -> Result<u64, VMError> {
    reserve_available_syscall_gas_at_least(vm, 1)
}
/// Reserve all currently available syscall gas after enforcing a minimum.
///
/// The minimum is checked during side-effect-free preparation. This prevents a
/// caller from triggering even a single host-state lookup or scan with a
/// reserve smaller than the class's deterministic base charge.
pub fn reserve_available_syscall_gas_at_least(vm: &IVM, minimum: u64) -> Result<u64, VMError> {
    let available = vm.remaining_gas();
    if available < minimum {
        Err(VMError::OutOfGas)
    } else {
        Ok(available)
    }
}
/// Check an exact state-dependent syscall cost against the gas reserved before host execution.
///
/// Direct host calls have no reserve and remain supported for low-level tests. A VM-dispatched
/// call that cannot cover the exact cost consumes its full reserve and traps before the caller
/// performs guest-visible work.
pub fn preflight_reserved_syscall_gas(vm: &IVM, actual: u64) -> Result<(), VMError> {
    let reserved = vm.syscall_reserved_gas();
    if reserved != 0 && actual > reserved {
        return Err(VMError::metered(reserved, VMError::OutOfGas));
    }
    Ok(())
}
/// Charge one key comparison against a state scan's reserved work budget.
///
/// `charged_before` includes the encoded prefix and every previously examined
/// key's one-unit visit charge plus UTF-8 byte length. Call this before parsing,
/// cloning, or comparing the next key beyond the iterator's ordered-bound check.
///
/// # Errors
///
/// Returns a metered [`VMError::OutOfGas`] before the next key is materialized
/// when its deterministic work charge exceeds the pre-debited reserve.
pub fn preflight_reserved_state_scan_work(
    vm: &IVM,
    charged_before: u64,
    next_key_len: usize,
) -> Result<(), VMError> {
    preflight_reserved_state_scan_work_with_tail(vm, charged_before, next_key_len, 0)
}
/// Charge one key comparison while preserving gas for later response work.
///
/// `reserved_tail_gas` is the cumulative response or allocation bound that every successful scan
/// must leave untouched. `STATE_SCAN` starts with its empty framed page and grows the tail by each
/// selected key's exact canonical encoded length before cloning or parsing that key.
///
/// # Errors
///
/// Returns a metered [`VMError::OutOfGas`] before the next key is materialized
/// when scan work plus the reserved tail exceeds the pre-debited quote.
pub fn preflight_reserved_state_scan_work_with_tail(
    vm: &IVM,
    charged_before: u64,
    next_key_len: usize,
    reserved_tail_gas: u64,
) -> Result<(), VMError> {
    let reserved = vm.syscall_reserved_gas();
    if reserved == 0 {
        return Ok(());
    }
    let next =
        gas::STATE_SCAN_ITEM_GAS.saturating_add(u64::try_from(next_key_len).unwrap_or(u64::MAX));
    let actual = STATE_QUERY_GAS_BASE
        .saturating_add(charged_before)
        .saturating_add(next)
        .saturating_add(reserved_tail_gas);
    preflight_reserved_syscall_gas(vm, actual)
}
/// Return a conservative framed-Norito byte bound for one `STATE_SCAN` page.
///
/// The calculation borrows the selected paths and performs no serialization or allocation. It
/// covers both plain sequences (one length prefix per element) and packed sequences (an `n + 1`
/// offset table), plus the Norito header and alignment padding.
fn state_scan_page_payload_bound_from_parts(
    item_count: usize,
    encoded_elements: usize,
) -> Result<usize, VMError> {
    if item_count > usize::try_from(syscalls::STATE_SCAN_MAX_ITEMS_V1).unwrap_or(usize::MAX) {
        return Err(VMError::NoritoInvalid);
    }
    let offset_table = item_count
        .checked_add(1)
        .and_then(|entries| entries.checked_mul(core::mem::size_of::<u64>()))
        .ok_or(VMError::NoritoInvalid)?;
    let payload = core::mem::size_of::<u64>()
        .checked_add(offset_table)
        .and_then(|bytes| bytes.checked_add(encoded_elements))
        .ok_or(VMError::NoritoInvalid)?;
    let align = core::mem::align_of::<Vec<StatePath>>();
    let padding = if align <= 1 {
        0
    } else {
        let remainder = Header::SIZE % align;
        if remainder == 0 { 0 } else { align - remainder }
    };
    let framed = Header::SIZE
        .checked_add(padding)
        .and_then(|bytes| bytes.checked_add(payload))
        .ok_or(VMError::NoritoInvalid)?;
    if framed > syscalls::STATE_MAP_MAX_PAGE_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    Ok(framed)
}
fn state_key_encoded_len_from_text(key: &str) -> Result<usize, VMError> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    <&str as SerializePayload>::encoded_len_exact(&key).ok_or(VMError::NoritoInvalid)
}
/// Compute the exact encoded-element total and framed page bound after adding
/// one canonical durable-state key to a selected page.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] when length arithmetic overflows or the
/// resulting canonical page would exceed the V1 page bound.
pub fn state_scan_response_tail_after_item(
    selected_before: usize,
    encoded_elements_before: usize,
    key: &str,
) -> Result<(usize, usize), VMError> {
    let encoded_elements = encoded_elements_before
        .checked_add(state_key_encoded_len_from_text(key)?)
        .ok_or(VMError::NoritoInvalid)?;
    let selected = selected_before
        .checked_add(1)
        .ok_or(VMError::NoritoInvalid)?;
    let response = state_scan_page_payload_bound_from_parts(selected, encoded_elements)?;
    Ok((encoded_elements, response))
}
/// Deterministic gas for one contiguous heap allocation.
///
/// Charging by eight-byte ABI words makes bounded collection capacity visible
/// to metering without depending on the host allocator or hardware page size.
#[must_use]
pub(crate) const fn allocation_gas(bytes: u64) -> u64 {
    gas::ALLOCATION_GAS_BASE.saturating_add(
        bytes.saturating_add(gas::ALLOCATION_GAS_WORD_BYTES - 1) / gas::ALLOCATION_GAS_WORD_BYTES,
    )
}
/// Return whether a syscall belongs to the optional ShangMi family.
#[must_use]
pub(crate) const fn is_sm_syscall(number: u32) -> bool {
    matches!(
        number,
        syscalls::SYSCALL_SM3_HASH
            | syscalls::SYSCALL_SM2_VERIFY
            | syscalls::SYSCALL_SM4_GCM_SEAL
            | syscalls::SYSCALL_SM4_GCM_OPEN
            | syscalls::SYSCALL_SM4_CCM_SEAL
            | syscalls::SYSCALL_SM4_CCM_OPEN
    )
}
/// Compute exact, side-effect-free gas quotes for VM-local helper syscalls
/// shared by the standalone, core, and world-state hosts.
///
/// `None` means the syscall's gas depends on host-owned state or on an output
/// whose encoded size must be estimated by that host.
pub(crate) fn common_syscall_gas_quote(number: u32, vm: &IVM) -> Result<Option<u64>, VMError> {
    let blob_len = |register: usize| -> Result<usize, VMError> {
        quote_tlv_payload_len_at(
            vm,
            DefaultHost::resolve_code_tlv_addr(vm, vm.register(register)),
            PointerType::Blob,
        )
    };
    let quote = match number {
        syscalls::SYSCALL_DEBUG_PRINT | syscalls::SYSCALL_EXIT | syscalls::SYSCALL_ABORT => {
            DEBUG_GAS
        }
        syscalls::SYSCALL_CONTRACT_ABORT => {
            let len = quote_tlv_payload_len_at(
                vm,
                DefaultHost::resolve_code_tlv_addr(vm, vm.register(10)),
                PointerType::NoritoBytes,
            )?;
            if len > 64 * 1024 {
                return Err(VMError::NoritoInvalid);
            }
            let tlv = vm.validate_tlv(DefaultHost::resolve_code_tlv_addr(vm, vm.register(10)))?;
            let descriptor: iroha_data_model::smart_contract::manifest::ContractErrorTypeDescriptor =
                decode_canonical_norito(tlv.payload)?;
            let code = u32::try_from(vm.register(11)).map_err(|_| VMError::NoritoInvalid)?;
            contract_abort_gas(len, contract_abort_message(vm, &descriptor.identity, code))
        }
        syscalls::SYSCALL_DEBUG_LOG => {
            let pointer = vm.register(10);
            if pointer == 0 {
                DEBUG_GAS
            } else {
                let (pointer_type, payload_len) =
                    quote_any_tlv_at(vm, DefaultHost::resolve_code_tlv_addr(vm, pointer))?;
                if !matches!(
                    pointer_type,
                    PointerType::Blob | PointerType::NoritoBytes | PointerType::Json
                ) {
                    return Err(VMError::NoritoInvalid);
                }
                debug_log_gas(payload_len)
            }
        }
        syscalls::SYSCALL_ALLOC => allocation_gas(vm.register(10)),
        syscalls::SYSCALL_POINTER_TO_NORITO => {
            let pointer = vm.register(10);
            if pointer == 0 {
                return Err(VMError::NoritoInvalid);
            }
            let (_, payload_len) =
                quote_any_tlv_at(vm, DefaultHost::resolve_code_tlv_addr(vm, pointer))?;
            DefaultHost::pointer_gas(TLV_ENVELOPE_OVERHEAD.saturating_add(payload_len))
        }
        syscalls::SYSCALL_POINTER_FROM_NORITO => {
            let pointer = vm.register(10);
            if pointer == 0 {
                DefaultHost::pointer_gas(0)
            } else {
                let (pointer_type, payload_len) =
                    quote_any_tlv_at(vm, DefaultHost::resolve_code_tlv_addr(vm, pointer))?;
                if pointer_type != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                DefaultHost::pointer_gas(payload_len)
            }
        }
        syscalls::SYSCALL_TLV_EQ => {
            let left_pointer = vm.register(10);
            let right_pointer = vm.register(11);
            let left_len = if left_pointer == 0 {
                0
            } else {
                quote_any_tlv_at(vm, left_pointer)?.1
            };
            let right_len = if right_pointer == 0 || right_pointer == left_pointer {
                0
            } else {
                quote_any_tlv_at(vm, right_pointer)?.1
            };
            DefaultHost::tlv_eq_gas(left_len, right_len)
        }
        syscalls::SYSCALL_TLV_LEN => {
            let pointer = vm.register(10);
            if pointer == 0 {
                DefaultHost::tlv_len_gas(0)
            } else {
                let (_, payload_len) =
                    quote_any_tlv_at(vm, DefaultHost::resolve_code_tlv_addr(vm, pointer))?;
                DefaultHost::tlv_len_gas(payload_len)
            }
        }
        syscalls::SYSCALL_DECODE_ARGUMENT_RECORD => {
            crate::argument_record::decode_argument_record_gas_quote(vm)?
        }
        syscalls::SYSCALL_VALUE_ENCODE
        | syscalls::SYSCALL_BLOB_CONCAT
        | syscalls::SYSCALL_UTF8_VALIDATE
        | syscalls::SYSCALL_VALUE_TO_STRING
        | syscalls::SYSCALL_STATE_VALUE_ENCODE
        | syscalls::SYSCALL_STATE_VALUE_DECODE => reserve_available_syscall_gas(vm)?,
        syscalls::SYSCALL_STATE_PATH_FROM_NAME => {
            let input = quote_tlv_payload_len_at(
                vm,
                DefaultHost::resolve_code_tlv_addr(vm, vm.register(10)),
                PointerType::Name,
            )?;
            if input > syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES {
                return Err(VMError::NoritoInvalid);
            }
            DefaultHost::path_gas(input, syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES)
        }
        syscalls::SYSCALL_SM3_HASH
        | syscalls::SYSCALL_SHA256_HASH
        | syscalls::SYSCALL_SHA3_HASH
        | syscalls::SYSCALL_BLAKE2B256_HASH
        | syscalls::SYSCALL_KECCAK256_HASH
        | syscalls::SYSCALL_IROHA_HASH => DefaultHost::hash_syscall_gas(blob_len(10)?),
        syscalls::SYSCALL_SM2_VERIFY => {
            let message_len = blob_len(10)?;
            let signature_len = blob_len(11)?;
            let public_key_len = blob_len(12)?;
            let distid_len = if vm.register(13) == 0 {
                0
            } else {
                blob_len(13)?
            };
            DefaultHost::verify_gas(
                message_len
                    .saturating_add(signature_len)
                    .saturating_add(public_key_len)
                    .saturating_add(distid_len),
            )
        }
        syscalls::SYSCALL_SM4_GCM_SEAL
        | syscalls::SYSCALL_SM4_GCM_OPEN
        | syscalls::SYSCALL_SM4_CCM_SEAL
        | syscalls::SYSCALL_SM4_CCM_OPEN => {
            blob_len(10)?;
            blob_len(11)?;
            let aad_len = if vm.register(12) == 0 {
                0
            } else {
                blob_len(12)?
            };
            DefaultHost::sm4_gas(aad_len, blob_len(13)?)
        }
        syscalls::SYSCALL_INPUT_PUBLISH_TLV => {
            let pointer = vm.register(10);
            if pointer == 0 {
                DefaultHost::input_publish_gas(0)
            } else {
                let (_, payload_len) =
                    quote_any_tlv_at(vm, DefaultHost::resolve_code_tlv_addr(vm, pointer))?;
                DefaultHost::input_publish_gas(TLV_ENVELOPE_OVERHEAD.saturating_add(payload_len))
            }
        }
        syscalls::SYSCALL_NORMALIZE_NORITO_BYTES => {
            vm.ensure_public_register(10)?;
            let pointer = vm.register(10);
            if pointer == 0 {
                return Err(VMError::NoritoInvalid);
            }
            let (pointer_type, payload_len) = quote_any_tlv_at(vm, pointer)?;
            if !matches!(pointer_type, PointerType::Blob | PointerType::NoritoBytes) {
                return Err(VMError::NoritoInvalid);
            }
            DefaultHost::pointer_gas(payload_len)
        }
        _ => return Ok(None),
    };
    Ok(Some(quote))
}
/// Canonicalize a public byte carrier as a fresh host-owned `NoritoBytes` TLV.
///
/// The payload is copied verbatim; only the pointer-ABI type tag and envelope
/// digest are produced anew. Keeping this implementation shared makes the
/// standalone, codec, mock-WSV, and production hosts byte-for-byte identical.
pub(crate) fn normalize_norito_bytes(vm: &mut IVM) -> Result<u64, VMError> {
    vm.ensure_public_register(10)?;
    let pointer = vm.register(10);
    if pointer == 0 {
        return Err(VMError::NoritoInvalid);
    }
    let payload = {
        let tlv = vm.validate_tlv(pointer)?;
        if !matches!(tlv.type_id, PointerType::Blob | PointerType::NoritoBytes) {
            return Err(VMError::NoritoInvalid);
        }
        tlv.payload.to_vec()
    };
    let gas = DefaultHost::pointer_gas(payload.len());
    let normalized = DefaultHost::alloc_norito_bytes_tlv(vm, &payload)?;
    vm.set_register(10, normalized);
    Ok(gas)
}
/// Trait for IVM host environment to handle syscalls (SCALL).
pub trait IVMHost {
    /// Return the authoritative, schema-bound prepared public arguments for this invocation.
    /// Hosts without a preparation owner use the canonical metered public-input route.
    fn prepared_entrypoint_arguments(&self) -> Option<crate::PreparedArgumentRecord> {
        None
    }
    /// Return a deterministic upper bound for the syscall's additional gas.
    ///
    /// Preparation must be side-effect-free. For [`SyscallMetering::Reserved`] calls the VM debits
    /// this quote before invoking [`Self::syscall`] and refunds the unused portion afterwards. The
    /// VM does not invoke this method for registered staged syscalls.
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError>;
    /// Handle a syscall invoked by the VM. `number` is the syscall ID and the
    /// mutable reference to the VM gives access to registers and memory.
    ///
    /// A reserved handler returns the actual additional gas cost, which must not exceed
    /// [`Self::prepare_syscall`]. Metered errors report their actual cost through
    /// [`VMError::Metered`]; an unmetered error consumes the complete prepared quote so potentially
    /// completed host work is never refunded implicitly.
    ///
    /// A staged handler calls [`IVM::charge_syscall_stage`] before each phase and
    /// returns zero. Returning non-zero actual gas or a [`VMError::Metered`]
    /// wrapper from a staged handler is a metering-mode violation.
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError>;
    /// Whether this host accepts `number` for a program running under `policy`.
    ///
    /// This policy check must be side-effect-free because it runs before gas is
    /// reserved for the syscall.
    ///
    /// The default is the canonical public ABI surface. Tooling hosts may explicitly opt in to
    /// host-private syscalls without changing the ABI hash or weakening production admission.
    fn allows_syscall(&self, policy: SyscallPolicy, number: u32) -> bool {
        syscalls::is_syscall_allowed(policy, number)
    }
    /// Downcast support for hosts with extra methods/state.
    fn as_any(&mut self) -> &mut dyn Any
    where
        Self: 'static;
    /// Hint that a transaction is about to start. Hosts can reset per-tx state here.
    /// Returning an error aborts the transaction before execution begins.
    fn begin_tx(&mut self, _declared: &StateAccessSet) -> Result<(), VMError> {
        Ok(())
    }
    /// Report the actual logical state accesses performed during the last transaction.
    /// Errors propagate to the caller and trigger a host rollback via `restore()`.
    fn finish_tx(&mut self) -> Result<AccessLog, VMError> {
        Ok(AccessLog::default())
    }
    /// Optional transactional checkpoint. Transactional callers (for example the
    /// Kotodama test driver) restore this snapshot when a transaction fails so
    /// host side effects do not leak. `None` means the host cannot prove rollback.
    fn checkpoint(&self) -> Option<Box<dyn Any + Send>> {
        None
    }
    /// Restore a previously taken checkpoint.
    ///
    /// An error means rollback could not be completed durably; callers must not
    /// execute another transaction with the affected host.
    fn restore(&mut self, _snapshot: &dyn Any) -> Result<(), VMError> {
        Err(VMError::HostUnavailable)
    }
    /// Indicate whether this host reports logical state accesses via `finish_tx`.
    fn access_logging_supported(&self) -> bool {
        false
    }
}
// Compile-time signature guards keep the host lifecycle and syscall quote
// contracts uniform across downstream implementations.
type PrepareSyscallSignatureGuard =
    for<'a, 'b> fn(&'a dyn IVMHost, u32, &'b IVM) -> Result<u64, VMError>;
type AllowsSyscallSignatureGuard = for<'a> fn(&'a dyn IVMHost, SyscallPolicy, u32) -> bool;
type BeginTxSignatureGuard =
    for<'a, 'b> fn(&'a mut dyn IVMHost, &'b StateAccessSet) -> Result<(), VMError>;
type FinishTxSignatureGuard = for<'a> fn(&'a mut dyn IVMHost) -> Result<AccessLog, VMError>;
type RestoreSignatureGuard =
    for<'a, 'b> fn(&'a mut dyn IVMHost, &'b dyn Any) -> Result<(), VMError>;
fn prepare_syscall_signature_guard(
    host: &dyn IVMHost,
    number: u32,
    vm: &IVM,
) -> Result<u64, VMError> {
    IVMHost::prepare_syscall(host, number, vm)
}
fn allows_syscall_signature_guard(host: &dyn IVMHost, policy: SyscallPolicy, number: u32) -> bool {
    IVMHost::allows_syscall(host, policy, number)
}
fn begin_tx_signature_guard(
    host: &mut dyn IVMHost,
    declared: &StateAccessSet,
) -> Result<(), VMError> {
    IVMHost::begin_tx(host, declared)
}
fn finish_tx_signature_guard(host: &mut dyn IVMHost) -> Result<AccessLog, VMError> {
    IVMHost::finish_tx(host)
}
fn restore_signature_guard(host: &mut dyn IVMHost, snapshot: &dyn Any) -> Result<(), VMError> {
    IVMHost::restore(host, snapshot)
}
const _: PrepareSyscallSignatureGuard = prepare_syscall_signature_guard;
const _: AllowsSyscallSignatureGuard = allows_syscall_signature_guard;
const _: BeginTxSignatureGuard = begin_tx_signature_guard;
const _: FinishTxSignatureGuard = finish_tx_signature_guard;
const _: RestoreSignatureGuard = restore_signature_guard;
/// A basic host implementation used in tests. It supports heap allocation and
/// reading private inputs.
#[derive(Clone, Default)]
struct DefaultHostNestedCallJournal;
/// Lightweight rollback token for the subset of [`DefaultHost`] operations
/// forwarded by the production Iroha host during a nested contract call.
///
/// Immutable inputs, durable state, verifying keys, and configuration are not copied. The bounded
/// committed-output buffer is checkpointed directly. The production adapter's forwarded subset does
/// not mutate this host's durable state or access log.
pub struct DefaultHostForwardedCallCheckpoint {
    journal_depth: usize,
    pub_output: Vec<u8>,
}
#[derive(Clone)]
pub struct DefaultHost {
    state_instance: String,
    private_inputs: Vec<Vec<u8>>,
    public_inputs: BTreeMap<Name, Vec<u8>>,
    state: BTreeMap<StatePath, Vec<u8>>,
    pub_output: Vec<u8>,
    zk_cfg: ZkVerifyLimits,
    zk_gas_schedule: gas::ZkGasScheduleV1,
    zk_execution_counters: ZkExecutionCounters,
    vrf_execution_counters: VrfExecutionCounters,
    network_id: Option<iroha_data_model::NetworkId>,
    chain_id: Option<Vec<u8>>,
    axt_state: Option<axt::HostAxtState>,
    axt_policy: std::sync::Arc<dyn axt::AxtPolicy>,
    fastpq_batch_active: bool,
    fastpq_batch_has_entries: bool,
    sm_enabled: bool,
    current_time_ms: u64,
    current_block_height: u64,
    access_log: AccessLog,
    nested_call_journals: Vec<DefaultHostNestedCallJournal>,
}
impl DefaultHost {
    /// Bind this isolated development host to a deterministic contract instance.
    /// Persist and reuse the same binding with a local state overlay; distinct
    /// instances must use distinct bindings. Production hosts derive it from
    /// the authenticated contract address.
    pub fn set_state_instance(&mut self, instance: String) -> Result<(), VMError> {
        if instance.is_empty() || instance.len() > 1024 {
            return Err(VMError::NoritoInvalid);
        }
        self.state_instance = instance;
        Ok(())
    }
    pub fn new() -> Self {
        DefaultHost {
            state_instance: "local".to_owned(),
            private_inputs: Vec::new(),
            public_inputs: BTreeMap::new(),
            state: BTreeMap::new(),
            pub_output: Vec::new(),
            zk_cfg: ZkVerifyLimits::default(),
            zk_gas_schedule: gas::ZkGasScheduleV1::default(),
            zk_execution_counters: ZkExecutionCounters::default(),
            vrf_execution_counters: VrfExecutionCounters::default(),
            network_id: None,
            chain_id: None,
            axt_state: None,
            axt_policy: std::sync::Arc::new(axt::AllowAllAxtPolicy),
            fastpq_batch_active: false,
            fastpq_batch_has_entries: false,
            sm_enabled: false,
            current_time_ms: 0,
            current_block_height: 0,
            access_log: AccessLog::default(),
            nested_call_journals: Vec::new(),
        }
    }
    /// Provide typed private inputs retrieved by `SYSCALL_GET_PRIVATE_INPUT`.
    ///
    /// # Errors
    /// Rejects more than the deterministic V1 input bound or a record whose
    /// canonical outer Norito encoding exceeds its hard byte bound.
    pub fn with_private_inputs(inputs: Vec<PrivateInputRecordV1>) -> Result<Self, VMError> {
        if inputs.len() > MAX_PRIVATE_INPUTS_V1 {
            return Err(VMError::NoritoInvalid);
        }
        let private_inputs = inputs
            .iter()
            .map(crate::private_input::encode_record)
            .collect::<Result<Vec<_>, _>>()?;
        Self::with_encoded_private_inputs(private_inputs)
    }
    /// Provide bounded, untrusted encoded private-input records from transport.
    ///
    /// Records are deliberately not decoded here. Runtime execution validates the selected record
    /// only after the fixed quote has been debited. Count, per-record, and aggregate byte limits
    /// are enforced before this host retains any of the supplied buffers.
    ///
    /// # Errors
    /// Returns [`VMError::NoritoInvalid`] when any V1 transport bound is
    /// exceeded. Malformed but bounded records remain a metered runtime error.
    pub fn with_encoded_private_inputs(inputs: Vec<Vec<u8>>) -> Result<Self, VMError> {
        if inputs.len() > MAX_PRIVATE_INPUTS_V1 {
            return Err(VMError::NoritoInvalid);
        }
        let mut aggregate_bytes = 0_usize;
        for record in &inputs {
            if record.len() > MAX_PRIVATE_INPUT_RECORD_BYTES_V1 {
                return Err(VMError::NoritoInvalid);
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(record.len())
                .ok_or(VMError::NoritoInvalid)?;
            if aggregate_bytes > MAX_PRIVATE_INPUT_TRANSPORT_BYTES_V1 {
                return Err(VMError::NoritoInvalid);
            }
        }
        let mut host = Self::new();
        host.private_inputs = inputs;
        Ok(host)
    }
    /// Install arbitrary encoded records without transport admission checks.
    ///
    /// This exists only for unit tests proving runtime decoding remains
    /// fail-closed when an in-process fixture bypasses normal construction.
    #[cfg(test)]
    fn with_encoded_private_inputs_unchecked(inputs: Vec<Vec<u8>>) -> Self {
        let mut host = Self::new();
        host.private_inputs = inputs;
        host
    }
    /// Begin a rollback scope for operations forwarded by the production host.
    ///
    /// The matching commit or rollback method must be called in LIFO order.
    #[must_use]
    pub fn begin_forwarded_call(&mut self) -> DefaultHostForwardedCallCheckpoint {
        let checkpoint = DefaultHostForwardedCallCheckpoint {
            journal_depth: self.nested_call_journals.len(),
            pub_output: self.pub_output.clone(),
        };
        self.nested_call_journals.push(Default::default());
        checkpoint
    }
    /// Commit a nested-call rollback scope without copying host state.
    ///
    /// Returns `false` when `checkpoint` is not the innermost active scope.
    pub fn commit_forwarded_call(
        &mut self,
        checkpoint: DefaultHostForwardedCallCheckpoint,
    ) -> bool {
        if self.nested_call_journals.len() != checkpoint.journal_depth.saturating_add(1) {
            return false;
        }
        self.nested_call_journals.pop();
        true
    }
    /// Roll back operations forwarded during a nested-call scope.
    ///
    /// Returns `false` when `checkpoint` is not the innermost active scope.
    pub fn rollback_forwarded_call(
        &mut self,
        checkpoint: DefaultHostForwardedCallCheckpoint,
    ) -> bool {
        if self.nested_call_journals.len() != checkpoint.journal_depth.saturating_add(1) {
            return false;
        }
        self.nested_call_journals
            .pop()
            .expect("nested call journal depth checked");
        self.pub_output = checkpoint.pub_output;
        true
    }
    /// Configure proof envelope and batch limits for this host.
    pub fn with_zk_verify_limits(mut self, cfg: ZkVerifyLimits) -> Self {
        self.zk_cfg = cfg;
        self
    }
    /// Replace proof limits without discarding other host state.
    pub fn set_zk_verify_limits(&mut self, cfg: ZkVerifyLimits) {
        self.zk_cfg = cfg;
    }
    /// Configure the immutable ZK syscall gas snapshot for this host.
    #[must_use]
    pub const fn with_zk_gas_schedule(mut self, schedule: gas::ZkGasScheduleV1) -> Self {
        self.zk_gas_schedule = schedule;
        self
    }
    /// Replace the immutable ZK syscall gas snapshot.
    pub fn set_zk_gas_schedule(&mut self, schedule: gas::ZkGasScheduleV1) {
        self.zk_gas_schedule = schedule;
    }
    /// Return the immutable ZK syscall gas snapshot.
    #[must_use]
    pub const fn zk_gas_schedule(&self) -> gas::ZkGasScheduleV1 {
        self.zk_gas_schedule
    }
    /// Return the current ZK execution-order counters.
    #[must_use]
    pub const fn zk_execution_counters(&self) -> ZkExecutionCounters {
        self.zk_execution_counters
    }
    /// Return the current VRF execution-order counters.
    #[must_use]
    pub const fn vrf_execution_counters(&self) -> VrfExecutionCounters {
        self.vrf_execution_counters
    }
    /// Provide public inputs retrievable via `SYSCALL_GET_PUBLIC_INPUT`.
    pub fn with_public_inputs(mut self, inputs: BTreeMap<Name, Vec<u8>>) -> Self {
        self.public_inputs = inputs;
        self
    }
    /// Replace the public input map used by `SYSCALL_GET_PUBLIC_INPUT`.
    pub fn set_public_inputs(&mut self, inputs: BTreeMap<Name, Vec<u8>>) {
        self.public_inputs = inputs;
    }
    /// Return the current proof envelope and batch limits.
    pub fn zk_verify_limits(&self) -> ZkVerifyLimits {
        self.zk_cfg
    }
    /// Install an AXT policy sourced from a data-model snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AxtPolicySnapshotValidationError`] when the snapshot is not
    /// canonically ordered or its version does not bind its exact entries.
    pub fn with_axt_policy_from_snapshot(
        mut self,
        snapshot: &AxtPolicySnapshot,
    ) -> Result<Self, AxtPolicySnapshotValidationError> {
        self.axt_policy = std::sync::Arc::new(axt::SnapshotAxtPolicy::new(snapshot)?);
        Ok(self)
    }
    /// Set the display chain label returned by `SYSVAR_CHAIN_ID`.
    pub fn with_chain_id(mut self, chain_id: Vec<u8>) -> Self {
        self.chain_id = Some(chain_id);
        self
    }
    /// Set the host-owned exact network identity used for VRF prehash binding.
    ///
    /// VRF verification fails closed when this context is absent and rejects
    /// envelopes whose claimed network identity does not match it.
    pub fn with_network_id(mut self, network_id: iroha_data_model::NetworkId) -> Self {
        self.network_id = Some(network_id);
        self
    }
    /// Mutably set the display chain label without moving the host.
    pub fn set_chain_id_bytes(&mut self, chain_id: Vec<u8>) {
        self.chain_id = Some(chain_id);
    }
    /// Mutably set the host-owned exact network identity without moving the host.
    pub fn set_network_id(&mut self, network_id: iroha_data_model::NetworkId) {
        self.network_id = Some(network_id);
    }
    /// Enable or disable SM helper syscalls for this host.
    pub fn with_sm_enabled(mut self, enabled: bool) -> Self {
        self.sm_enabled = enabled;
        self
    }
    /// Toggle SM helper support at runtime.
    pub fn set_sm_enabled(&mut self, enabled: bool) {
        self.sm_enabled = enabled;
    }
    /// Set the deterministic block time returned by time syscalls.
    pub fn set_current_time_ms(&mut self, time_ms: u64) {
        self.current_time_ms = time_ms;
    }
    /// Set the deterministic block height returned by sysvar syscalls.
    pub fn set_current_block_height(&mut self, block_height: u64) {
        self.current_block_height = block_height;
    }
    fn validate_zk_open_envelope(&self, envelope: &OpenVerifyEnvelope) -> Result<(), u64> {
        envelope
            .validate_with_bounds(OpenVerifyEnvelopeBounds {
                max_proof_bytes: self.zk_cfg.max_proof_bytes,
                ..OpenVerifyEnvelopeBounds::default()
            })
            .map_err(map_open_verify_validation_error)?;
        // The standalone host deliberately has no chain verifier-key registry.
        // Production verification is provided only by CoreHost after binding
        // the canonical envelope to an active registered key.
        Err(ERR_BACKEND)
    }
    fn begin_fastpq_batch(&mut self) -> Result<u64, VMError> {
        if self.fastpq_batch_active {
            return Err(VMError::metered(
                gas::G_FASTPQ_BATCH,
                VMError::PermissionDenied,
            ));
        }
        self.fastpq_batch_active = true;
        self.fastpq_batch_has_entries = false;
        Ok(gas::G_FASTPQ_BATCH)
    }
    fn push_fastpq_batch_entry(&mut self, vm: &IVM) -> Result<u64, VMError> {
        if !self.fastpq_batch_active {
            return Err(VMError::PermissionDenied);
        }
        let quantity_len = Self::expect_quantity(vm, 13)?;
        Self::expect_tlv(vm, 10, PointerType::AccountId)?;
        Self::expect_tlv(vm, 11, PointerType::AccountId)?;
        Self::expect_tlv(vm, 12, PointerType::AssetDefinitionId)?;
        let gas = Self::mutation_gas(quantity_len);
        self.fastpq_batch_has_entries = true;
        Ok(gas)
    }
    fn finish_fastpq_batch(&mut self) -> Result<u64, VMError> {
        if !self.fastpq_batch_active {
            return Err(VMError::metered(
                gas::G_FASTPQ_BATCH,
                VMError::PermissionDenied,
            ));
        }
        self.fastpq_batch_active = false;
        if !self.fastpq_batch_has_entries {
            return Err(VMError::metered(gas::G_FASTPQ_BATCH, VMError::DecodeError));
        }
        self.fastpq_batch_has_entries = false;
        Ok(gas::G_FASTPQ_BATCH)
    }
    fn apply_fastpq_batch(&mut self, vm: &IVM) -> Result<u64, VMError> {
        if self.fastpq_batch_active {
            return Err(VMError::PermissionDenied);
        }
        let gas = Self::fastpq_batch_apply_gas_quote(vm)?;
        preflight_reserved_syscall_gas(vm, gas)?;
        Ok(gas)
    }
    fn fastpq_batch_apply_gas_quote(vm: &IVM) -> Result<u64, VMError> {
        let ptr = vm.register(10);
        let tlv = vm.validate_tlv(ptr)?;
        if tlv.type_id != PointerType::NoritoBytes {
            return Err(VMError::NoritoInvalid);
        }
        let batch: TransferAssetBatch =
            decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
        if batch.entries().is_empty() {
            return Err(VMError::DecodeError);
        }
        Ok(MUTATION_GAS.saturating_mul(u64::try_from(batch.entries().len()).unwrap_or(u64::MAX)))
    }
    fn unsupported_syscall_error(number: u32) -> VMError {
        if syscalls::abi_syscall_list().binary_search(&number).is_ok() {
            VMError::metered_not_implemented(MUTATION_GAS, number)
        } else {
            VMError::UnknownSyscall(number)
        }
    }
    /// Retrieve and clear the output committed by the last program run.
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pub_output)
    }
    /// Validate a TLV pointer in register `reg` has the expected `PointerType`.
    fn expect_tlv<'a>(
        vm: &'a IVM,
        reg: usize,
        ty: PointerType,
    ) -> Result<pointer_abi::Tlv<'a>, VMError> {
        let tlv = Self::decode_any_tlv(vm, vm.register(reg))?;
        if tlv.type_id as u16 != ty as u16 {
            return Err(VMError::NoritoInvalid);
        }
        let policy = vm.syscall_policy();
        if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
            return Err(VMError::AbiTypeNotAllowed {
                abi: vm.abi_version(),
                type_id: tlv.type_id as u16,
            });
        }
        Ok(tlv)
    }
    fn expect_quantity(vm: &IVM, reg: usize) -> Result<usize, VMError> {
        let pointer = Self::resolve_code_tlv_addr(vm, vm.register(reg));
        let payload_len = read_bounded_tlv_payload_len_at(
            vm,
            pointer,
            PointerType::Quantity,
            MAX_QUANTITY_FRAME_BYTES_V1,
        )?;
        // VM-dispatched mutation calls must afford the complete bounded frame
        // before hashing or canonical decoding begins. Direct host calls have
        // no reserve and remain available to low-level tests and tooling.
        preflight_reserved_syscall_gas(vm, Self::mutation_gas(payload_len))?;
        let tlv = Self::expect_tlv(vm, reg, PointerType::Quantity)?;
        QuantityValueV1::decode_frame(tlv.payload).map_err(|_| VMError::DecodeError)?;
        debug_assert_eq!(tlv.payload.len(), payload_len);
        Ok(payload_len)
    }
    fn resolve_literal_pointer(vm: &IVM, address: u64) -> Option<u64> {
        vm.is_validated_literal_pointer(address).then_some(address)
    }
    fn resolve_code_tlv_addr(vm: &IVM, addr: u64) -> u64 {
        let input_lo = Memory::INPUT_START;
        let input_hi = Memory::INPUT_START + Memory::INPUT_SIZE;
        if addr >= input_lo && addr < input_hi {
            return addr;
        }
        Self::resolve_literal_pointer(vm, addr).unwrap_or(addr)
    }
    fn decode_any_tlv<'a>(vm: &'a IVM, ptr: u64) -> Result<pointer_abi::Tlv<'a>, VMError> {
        let resolved = Self::resolve_code_tlv_addr(vm, ptr);
        if crate::dev_env::decode_trace_enabled() {
            eprintln!("[DefaultHost] decode_any_tlv ptr=0x{ptr:08x} resolved=0x{resolved:08x}");
        }
        vm.validate_tlv(resolved)
    }
    fn alloc_blob_tlv(vm: &mut IVM, payload: &[u8]) -> Result<u64, VMError> {
        use iroha_crypto::Hash;
        let mut out = Vec::with_capacity(7 + payload.len() + 32);
        out.extend_from_slice(&(PointerType::Blob as u16).to_be_bytes());
        out.push(1);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        let h: [u8; 32] = Hash::new(payload).into();
        out.extend_from_slice(&h);
        vm.alloc_host_tlv(&out)
    }
    fn alloc_norito_bytes_tlv(vm: &mut IVM, payload: &[u8]) -> Result<u64, VMError> {
        use iroha_crypto::Hash;
        let mut out = Vec::with_capacity(7 + payload.len() + 32);
        out.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
        out.push(1);
        let len = u32::try_from(payload.len()).map_err(|_| VMError::NoritoInvalid)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        let h: [u8; 32] = Hash::new(payload).into();
        out.extend_from_slice(&h);
        vm.alloc_host_tlv(&out)
    }
    fn blake2b256(payload: &[u8]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        let mut hasher =
            Blake2bVar::new(32).expect("32-byte Blake2b output size must be supported");
        hasher.update(payload);
        hasher
            .finalize_variable(&mut digest)
            .expect("fixed Blake2b output buffer has the requested length");
        digest
    }
    fn hash_syscall_gas(payload_len: usize) -> u64 {
        let bytes = u64::try_from(payload_len).unwrap_or(u64::MAX);
        HASH_GAS_BASE.saturating_add(HASH_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn axt_gas(payload_len: usize) -> u64 {
        let bytes = u64::try_from(payload_len).unwrap_or(u64::MAX);
        AXT_GAS_BASE.saturating_add(AXT_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn axt_commit_gas(state: &axt::HostAxtState) -> u64 {
        let entries = state.touches().len().saturating_add(state.proofs().len());
        Self::axt_gas(entries)
    }
    fn pointer_gas(payload_len: usize) -> u64 {
        let bytes = u64::try_from(payload_len).unwrap_or(u64::MAX);
        POINTER_GAS_BASE.saturating_add(POINTER_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn sm4_gas(aad_len: usize, data_len: usize) -> u64 {
        let bytes = u64::try_from(aad_len)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(data_len).unwrap_or(u64::MAX));
        SM4_GAS_BASE.saturating_add(SM4_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn verify_gas(input_len: usize) -> u64 {
        let bytes = u64::try_from(input_len).unwrap_or(u64::MAX);
        VERIFY_GAS_BASE.saturating_add(VERIFY_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn vrf_verify_gas(examined_items: usize, input_len: usize) -> u64 {
        gas::vrf_verify_gas(
            u64::try_from(examined_items).unwrap_or(u64::MAX),
            u64::try_from(input_len).unwrap_or(u64::MAX),
        )
    }
    fn sysvar_gas(payload_len: usize) -> u64 {
        let bytes = u64::try_from(payload_len).unwrap_or(u64::MAX);
        SYSVAR_GAS_BASE.saturating_add(SYSVAR_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn state_query_gas(payload_len: usize) -> u64 {
        STATE_QUERY_GAS_BASE.saturating_add(u64::try_from(payload_len).unwrap_or(u64::MAX))
    }
    fn path_gas(input_len: usize, output_len: usize) -> u64 {
        STATE_QUERY_GAS_BASE
            .saturating_add(u64::try_from(input_len).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(output_len).unwrap_or(u64::MAX))
    }
    fn tlv_eq_gas(left_len: usize, right_len: usize) -> u64 {
        let bytes = u64::try_from(left_len)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(right_len).unwrap_or(u64::MAX));
        TLV_EQ_GAS_BASE.saturating_add(TLV_EQ_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn tlv_len_gas(payload_len: usize) -> u64 {
        let bytes = u64::try_from(payload_len).unwrap_or(u64::MAX);
        TLV_LEN_GAS_BASE.saturating_add(TLV_LEN_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn input_publish_gas(envelope_len: usize) -> u64 {
        let bytes = u64::try_from(envelope_len).unwrap_or(u64::MAX);
        INPUT_PUBLISH_GAS_BASE.saturating_add(INPUT_PUBLISH_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn grow_heap_gas(additional: u64) -> u64 {
        let pages = if additional == 0 {
            0
        } else {
            additional
                .saturating_add(GROW_HEAP_PAGE_BYTES - 1)
                .saturating_div(GROW_HEAP_PAGE_BYTES)
        };
        GROW_HEAP_GAS_BASE.saturating_add(GROW_HEAP_GAS_PER_PAGE.saturating_mul(pages))
    }
    fn merkle_path_gas(depth: usize) -> u64 {
        let nodes = u64::try_from(depth).unwrap_or(u64::MAX);
        MERKLE_PATH_GAS_BASE.saturating_add(MERKLE_PATH_GAS_PER_NODE.saturating_mul(nodes))
    }
    fn complete_tree_depth(leaf_count: usize) -> usize {
        usize::try_from(usize::BITS - leaf_count.max(1).saturating_sub(1).leading_zeros())
            .unwrap_or(usize::MAX)
    }
    fn memory_merkle_path_depth(vm: &IVM) -> usize {
        let byte_len = vm.memory.stack_top().saturating_add(Memory::STACK_SLOP);
        let leaf_count = usize::try_from(byte_len)
            .unwrap_or(usize::MAX)
            .div_ceil(32)
            .max(1);
        Self::complete_tree_depth(leaf_count)
    }
    fn compact_merkle_depth(full_depth: usize, requested: u64) -> usize {
        if requested == 0 {
            full_depth
        } else {
            full_depth.min(usize::try_from(requested).unwrap_or(usize::MAX).min(32))
        }
    }
    fn execution_summary_gas_quote(vm: &IVM) -> Result<u64, VMError> {
        let payload_len = crate::execution_summary::ExecutionSummary::encoded_len_v1()
            .map_err(|_| VMError::NoritoInvalid)?;
        Ok(128_u64
            .saturating_add(vm.execution_summary_event_count().saturating_mul(2))
            .saturating_add(u64::try_from(payload_len).unwrap_or(u64::MAX)))
    }
    fn signature_verify_gas(
        message_len: usize,
        signature_len: usize,
        public_key_len: usize,
    ) -> u64 {
        let bytes = u64::try_from(message_len)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(signature_len).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(public_key_len).unwrap_or(u64::MAX));
        SIGNATURE_VERIFY_GAS_BASE
            .saturating_add(SIGNATURE_VERIFY_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn sm4_ccm_tag_len(raw: u64) -> Option<usize> {
        let normalized = match raw {
            0 => 16,
            4 | 6 | 8 | 10 | 12 | 14 | 16 => raw,
            _ => return None,
        };
        usize::try_from(normalized).ok()
    }
    fn decode_signature_inputs(vm: &IVM) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), VMError> {
        let message_tlv = vm.validate_tlv(vm.register(10))?;
        if message_tlv.type_id != PointerType::Blob {
            return Err(VMError::NoritoInvalid);
        }
        let message = message_tlv.payload.to_vec();
        let decode_blob = |register: usize| -> Result<Vec<u8>, VMError> {
            let tlv = vm.validate_tlv(vm.register(register))?;
            if tlv.type_id != PointerType::Blob {
                return Err(VMError::NoritoInvalid);
            }
            Ok(tlv.payload.to_vec())
        };
        Ok((message, decode_blob(11)?, decode_blob(12)?))
    }
    fn signature_verify_gas_quote(vm: &IVM) -> Result<u64, VMError> {
        let message_len = quote_tlv_payload_len_at(vm, vm.register(10), PointerType::Blob)?;
        let signature_len = quote_tlv_payload_len_at(vm, vm.register(11), PointerType::Blob)?;
        let public_key_len = quote_tlv_payload_len_at(vm, vm.register(12), PointerType::Blob)?;
        Ok(Self::signature_verify_gas(
            message_len,
            signature_len,
            public_key_len,
        ))
    }
    fn mutation_gas(payload_len: usize) -> u64 {
        let bytes = u64::try_from(payload_len).unwrap_or(u64::MAX);
        MUTATION_GAS.saturating_add(MUTATION_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn decode_state_path_tlv(vm: &IVM, reg: usize) -> Result<(StatePath, usize), VMError> {
        let tlv = Self::expect_tlv(vm, reg, PointerType::NoritoBytes)?;
        if tlv.payload.len() > syscalls::STATE_MAX_PATH_FRAME_BYTES {
            return Err(VMError::NoritoInvalid);
        }
        let path: StatePath =
            decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
        validate_state_path(&path)?;
        validate_declared_state_path(vm, &path)?;
        Ok((path, tlv.payload.len()))
    }
    fn decode_state_scan_path_tlv(vm: &IVM, reg: usize) -> Result<(StatePath, usize), VMError> {
        let tlv = Self::expect_tlv(vm, reg, PointerType::NoritoBytes)?;
        if tlv.payload.len() > syscalls::STATE_MAX_PATH_FRAME_BYTES {
            return Err(VMError::NoritoInvalid);
        }
        let path: StatePath =
            decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
        validate_state_path(&path)?;
        validate_declared_state_scan_path(vm, &path)?;
        Ok((path, tlv.payload.len()))
    }
    fn state_key_matches_prefix(key: &StatePath, prefix: &StatePath) -> bool {
        let key = key.as_ref();
        let prefix = prefix.as_ref();
        key == prefix
            || key
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
    fn state_count_with_prefix(
        &self,
        vm: &IVM,
        prefix: &StatePath,
        path_len: usize,
    ) -> Result<(u64, u64), VMError> {
        let prefix_text = prefix.as_ref();
        let mut total = 0_u64;
        let mut scan_work_gas = u64::try_from(path_len).unwrap_or(u64::MAX);
        for (key, _) in self.state.range::<str, _>((
            std::ops::Bound::Included(prefix_text),
            std::ops::Bound::Unbounded,
        )) {
            if !key.as_ref().starts_with(prefix_text) {
                break;
            }
            preflight_reserved_state_scan_work(vm, scan_work_gas, key.as_ref().len())?;
            validate_state_path(key)?;
            scan_work_gas = scan_work_gas
                .saturating_add(1)
                .saturating_add(u64::try_from(key.as_ref().len()).unwrap_or(u64::MAX));
            if Self::state_key_matches_prefix(key, prefix) {
                total = total.saturating_add(1);
            }
        }
        Ok((total, scan_work_gas))
    }
    /// Override the default allow-all AXT policy (test/dependency injection).
    pub fn with_axt_policy(mut self, policy: std::sync::Arc<dyn axt::AxtPolicy>) -> Self {
        self.axt_policy = policy;
        self
    }
    fn handle_axt_begin(&mut self, vm: &mut IVM) -> Result<u64, VMError> {
        let ptr = vm.register(10);
        let tlv = vm.validate_tlv(ptr)?;
        if tlv.type_id != PointerType::AxtDescriptor {
            return Err(VMError::NoritoInvalid);
        }
        let gas = Self::axt_gas(tlv.payload.len());
        let descriptor: axt::AxtDescriptor = decode_canonical_norito(tlv.payload)?;
        axt::validate_descriptor(&descriptor)?;
        let binding = axt::compute_binding(&descriptor).map_err(|_| VMError::NoritoInvalid)?;
        self.axt_state = Some(axt::HostAxtState::new(descriptor, binding));
        Ok(gas)
    }
    fn handle_axt_touch(&mut self, vm: &mut IVM) -> Result<u64, VMError> {
        let state = self.axt_state.as_mut().ok_or(VMError::PermissionDenied)?;
        let ds_ptr = vm.register(10);
        let ds_tlv = vm.validate_tlv(ds_ptr)?;
        if ds_tlv.type_id != PointerType::DataSpaceId {
            return Err(VMError::NoritoInvalid);
        }
        let mut gas_len = ds_tlv.payload.len();
        let dsid: DataSpaceId = decode_canonical_norito(ds_tlv.payload)?;
        if !state.expected_dsids().contains(&dsid) {
            return Err(VMError::PermissionDenied);
        }
        let manifest_ptr = vm.register(11);
        let manifest = if manifest_ptr == 0 {
            TouchManifest {
                read: Vec::new(),
                write: Vec::new(),
            }
        } else {
            let manifest_tlv = vm.validate_tlv(manifest_ptr)?;
            if manifest_tlv.type_id != PointerType::NoritoBytes {
                return Err(VMError::NoritoInvalid);
            }
            gas_len = gas_len.saturating_add(manifest_tlv.payload.len());
            decode_canonical_norito(manifest_tlv.payload)?
        };
        axt::validate_touch_manifest(&manifest)?;
        let gas = Self::axt_gas(gas_len);
        preflight_reserved_syscall_gas(vm, gas)?;
        self.axt_policy.allow_touch(dsid, &manifest)?;
        state.record_touch(dsid, manifest)?;
        Ok(gas)
    }
    fn handle_axt_verify_ds_proof(&mut self, vm: &mut IVM) -> Result<u64, VMError> {
        let state = self.axt_state.as_mut().ok_or(VMError::PermissionDenied)?;
        let ds_ptr = vm.register(10);
        let ds_tlv = vm.validate_tlv(ds_ptr)?;
        if ds_tlv.type_id != PointerType::DataSpaceId {
            return Err(VMError::NoritoInvalid);
        }
        let dsid: DataSpaceId = decode_canonical_norito(ds_tlv.payload)?;
        if !state.expected_dsids().contains(&dsid) {
            return Err(VMError::PermissionDenied);
        }
        let proof_ptr = vm.register(11);
        if proof_ptr == 0 {
            let gas = Self::verify_gas(0);
            preflight_reserved_syscall_gas(vm, gas)?;
            state.record_proof(dsid, None, None)?;
            return Ok(gas);
        }
        let proof_tlv = vm.validate_tlv(proof_ptr)?;
        if proof_tlv.type_id != PointerType::ProofBlob {
            return Err(VMError::NoritoInvalid);
        }
        let proof: ProofBlob = decode_canonical_norito(proof_tlv.payload)?;
        axt::validate_proof_blob(&proof)?;
        let envelope = decode_canonical_norito::<axt::AxtProofEnvelope>(&proof.payload)?;
        axt::preflight_fastpq_v1_proof_envelope(&envelope, dsid)?;
        // The standalone host does not link the FastPQ verifier. Shape preflight
        // is diagnostic only, so proof-consuming AXT calls fail closed here.
        Err(VMError::PermissionDenied)
    }
    fn handle_axt_commit(&mut self, vm: &IVM) -> Result<u64, VMError> {
        let gas = self
            .axt_state
            .as_ref()
            .map(Self::axt_commit_gas)
            .ok_or(VMError::PermissionDenied)?;
        preflight_reserved_syscall_gas(vm, gas)?;
        let state = self
            .axt_state
            .take()
            .expect("axt_state checked before gas preflight");
        match Self::validate_axt_commit(&state) {
            Ok(()) => Ok(gas),
            Err(err) => {
                self.axt_state = Some(state);
                Err(err)
            }
        }
    }
    fn validate_axt_commit(state: &axt::HostAxtState) -> Result<(), VMError> {
        state.validate_commit()
    }
}
impl Default for DefaultHost {
    fn default() -> Self {
        Self::new()
    }
}
impl IVMHost for DefaultHost {
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
        let metering = require_host_syscall_metering_spec(vm.syscall_policy(), number)?;
        if metering.metering == SyscallMetering::Staged {
            return Ok(0);
        }
        if is_sm_syscall(number) && !self.sm_enabled {
            // Disabled ShangMi helpers fail before doing metered work.
            return Ok(0);
        }
        if let Some(quote) = common_syscall_gas_quote(number, vm)? {
            return Ok(quote);
        }
        if let Some(quote) = crate::core_host::CoreHost::codec_gas_quote(number, vm)? {
            return Ok(quote);
        }
        if let Some(quote) = crate::core_host::CoreHost::schema_gas_quote(number, vm)? {
            return Ok(quote);
        }
        if crate::syscalls::is_json_getter_syscall(number) {
            let json = quote_tlv_payload_len_at(
                vm,
                Self::resolve_code_tlv_addr(vm, vm.register(10)),
                PointerType::Json,
            )?;
            let key = quote_tlv_payload_len_at(
                vm,
                Self::resolve_code_tlv_addr(vm, vm.register(11)),
                PointerType::Name,
            )?;
            if json > gas::HOST_CODEC_MAX_INPUT_BYTES || key > gas::HOST_CODEC_MAX_INPUT_BYTES {
                return Err(VMError::NoritoInvalid);
            }
            let maximum_output = gas::HOST_CODEC_MAX_OUTPUT_BYTES;
            let output = maximum_output.saturating_add(16);
            return Ok(crate::json::typed_getter_gas(
                json.saturating_add(key),
                output,
            ));
        }
        let tlv_len = |register: usize| -> Result<usize, VMError> {
            let pointer = vm.register(register);
            quote_any_tlv_at(vm, pointer).map(|(_, payload_len)| payload_len)
        };
        let quote = match number {
            crate::syscalls::SYSCALL_VRF_EPOCH_SEED => {
                vm.ensure_public_register(10)?;
                crate::vrf::epoch_seed_gas(false)
            }
            crate::syscalls::SYSCALL_BUILD_PATH_KEY_NORITO => {
                let base_len = quote_tlv_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(10)),
                    PointerType::Name,
                )?;
                let key_len = quote_tlv_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(11)),
                    PointerType::NoritoBytes,
                )?;
                let (input_len, output_bound) =
                    quote_canonical_state_map_path_lengths(base_len, key_len)?;
                Self::path_gas(input_len, output_bound)
            }
            crate::syscalls::SYSCALL_STATE_MAP_KEY_AT => {
                let page_len =
                    quote_tlv_payload_len_at(vm, vm.register(10), PointerType::NoritoBytes)?;
                let base_len = quote_tlv_payload_len_at(vm, vm.register(11), PointerType::Name)?;
                if page_len > syscalls::STATE_MAP_MAX_PAGE_BYTES
                    || base_len > syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES
                {
                    return Err(VMError::NoritoInvalid);
                }
                Self::path_gas(
                    page_len.saturating_add(base_len),
                    syscalls::STATE_MAP_MAX_KEY_BYTES,
                )
            }
            crate::syscalls::SYSCALL_CURRENT_TIME_MS
            | crate::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS
            | crate::syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT
            | crate::syscalls::SYSCALL_SYSVAR_AUTHORITY
            | crate::syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS
            | crate::syscalls::SYSCALL_SYSVAR_ENTRYPOINT => Self::sysvar_gas(0),
            crate::syscalls::SYSCALL_SYSVAR_CHAIN_ID => {
                Self::sysvar_gas(self.chain_id.as_ref().map_or(0, Vec::len))
            }
            crate::syscalls::SYSCALL_QUERY_EXECUTE_NORITO
            | crate::syscalls::SYSCALL_CORE_QUERY_GET
            | crate::syscalls::SYSCALL_CORE_QUERY_PAGE
            | crate::syscalls::SYSCALL_QUERY_GET_PARAMETER
            | crate::syscalls::SYSCALL_QUERY_GET_CONTRACT_MANIFEST
            | crate::syscalls::SYSCALL_QUERY_GET_CONTRACT_INSTANCE => STATE_QUERY_GAS_BASE,
            crate::syscalls::SYSCALL_JSON_BUILD => {
                reserve_available_syscall_gas_at_least(vm, STATE_QUERY_GAS_BASE)?
            }
            crate::syscalls::SYSCALL_STATE_GET => {
                let path_len = quote_state_path_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(10)),
                )?;
                reserve_available_syscall_gas_at_least(vm, state_path_gas(path_len))?
            }
            crate::syscalls::SYSCALL_STATE_LEN => {
                let path_len = quote_state_path_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(10)),
                )?;
                state_path_gas(path_len)
            }
            crate::syscalls::SYSCALL_STATE_COUNT => {
                let path_len = quote_state_path_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(10)),
                )?;
                reserve_available_syscall_gas_at_least(vm, state_path_gas(path_len))?
            }
            crate::syscalls::SYSCALL_STATE_SCAN => {
                reserve_available_syscall_gas_at_least(vm, crate::state_scan::prepare_minimum(vm)?)?
            }
            crate::syscalls::SYSCALL_STATE_SET => {
                let path_len = quote_state_path_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(10)),
                )?;
                let value_len = quote_tlv_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(11)),
                    PointerType::NoritoBytes,
                )?;
                validate_state_value_payload_len(value_len)?;
                state_value_gas(path_len, value_len)
            }
            crate::syscalls::SYSCALL_STATE_DEL | crate::syscalls::SYSCALL_STATE_HAS => {
                let path_len = quote_state_path_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(10)),
                )?;
                state_path_gas(path_len)
            }
            crate::syscalls::SYSCALL_GROW_HEAP => Self::grow_heap_gas(vm.register(10)),
            crate::syscalls::SYSCALL_GET_PRIVATE_INPUT => GET_PRIVATE_INPUT_GAS,
            crate::syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM => PRIVATE_NUMERIC_VALCOM_GAS,
            crate::syscalls::SYSCALL_GET_PUBLIC_INPUT => {
                reserve_available_syscall_gas_at_least(vm, PUBLIC_INPUT_GAS_BASE)?
            }
            crate::syscalls::SYSCALL_COMMIT_OUTPUT => gas::commit_output_gas(vm.output_used_len()),
            crate::syscalls::SYSCALL_EXECUTION_SUMMARY => Self::execution_summary_gas_quote(vm)?,
            crate::syscalls::SYSCALL_VERIFY_PROOF => {
                let payload_len = tlv_len(10)?;
                if payload_len > gas::HOST_ZK_VERIFY_MAX_PAYLOAD_BYTES {
                    return Err(VMError::NoritoInvalid);
                }
                gas::zk_verify_gas(payload_len)
            }
            crate::syscalls::SYSCALL_VERIFY_SIGNATURE => Self::signature_verify_gas_quote(vm)?,
            crate::syscalls::SYSCALL_VRF_VERIFY => {
                let payload_len = quote_bounded_tlv_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(10)),
                    PointerType::NoritoBytes,
                    crate::vrf::MAX_VRF_VERIFY_PAYLOAD_BYTES_V1,
                )?;
                Self::vrf_verify_gas(1, payload_len)
            }
            crate::syscalls::SYSCALL_VRF_VERIFY_BATCH => {
                let payload_len = quote_bounded_tlv_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(10)),
                    PointerType::NoritoBytes,
                    crate::vrf::MAX_VRF_VERIFY_PAYLOAD_BYTES_V1,
                )?;
                Self::vrf_verify_gas(crate::vrf::MAX_VRF_VERIFY_BATCH_ITEMS_V1, payload_len)
            }
            crate::syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT
            | crate::syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY => {
                quote_zk_single_at(vm, vm.register(10), self.zk_gas_schedule)?.1
            }
            crate::syscalls::SYSCALL_ZK_VERIFY_BATCH => {
                quote_zk_batch_at(vm, vm.register(10), self.zk_gas_schedule)?.gas
            }
            crate::syscalls::SYSCALL_ADD_SIGNATORY
            | crate::syscalls::SYSCALL_REMOVE_SIGNATORY
            | crate::syscalls::SYSCALL_SET_ACCOUNT_QUORUM
            | crate::syscalls::SYSCALL_NFT_MINT_ASSET
            | crate::syscalls::SYSCALL_NFT_TRANSFER_ASSET
            | crate::syscalls::SYSCALL_NFT_SET_METADATA
            | crate::syscalls::SYSCALL_NFT_BURN_ASSET => Self::mutation_gas(0),
            crate::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED => {
                let quantity_len = quote_bounded_tlv_payload_len_at(
                    vm,
                    Self::resolve_code_tlv_addr(vm, vm.register(13)),
                    PointerType::Quantity,
                    MAX_QUANTITY_FRAME_BYTES_V1,
                )?;
                Self::mutation_gas(quantity_len)
            }
            crate::syscalls::SYSCALL_SET_ACCOUNT_DETAIL => Self::mutation_gas(tlv_len(12)?),
            crate::syscalls::SYSCALL_TRANSFER_V1 => {
                reserve_available_syscall_gas_at_least(vm, metering.minimum_gas)?
            }
            crate::syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN
            | crate::syscalls::SYSCALL_TRANSFER_V1_BATCH_END => gas::G_FASTPQ_BATCH,
            crate::syscalls::SYSCALL_TRANSFER_V1_BATCH_APPLY => {
                reserve_available_syscall_gas_at_least(vm, metering.minimum_gas)?
            }
            crate::syscalls::SYSCALL_GET_MERKLE_PATH => {
                let address = vm.register(10);
                let max_address = vm.memory.stack_top().saturating_add(Memory::STACK_SLOP);
                if address >= max_address {
                    return Err(VMError::MemoryOutOfBounds);
                }
                Self::merkle_path_gas(Self::memory_merkle_path_depth(vm))
            }
            crate::syscalls::SYSCALL_GET_MERKLE_COMPACT => {
                let address = vm.register(10);
                let max_address = vm.memory.stack_top().saturating_add(Memory::STACK_SLOP);
                if address >= max_address {
                    return Err(VMError::MemoryOutOfBounds);
                }
                let depth =
                    Self::compact_merkle_depth(Self::memory_merkle_path_depth(vm), vm.register(12));
                Self::merkle_path_gas(depth)
            }
            crate::syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT => {
                let index =
                    usize::try_from(vm.register(10)).map_err(|_| VMError::RegisterOutOfBounds)?;
                if index >= crate::parallel::REGISTER_COUNT {
                    return Err(VMError::RegisterOutOfBounds);
                }
                let full_depth = Self::complete_tree_depth(crate::parallel::REGISTER_COUNT);
                Self::merkle_path_gas(Self::compact_merkle_depth(full_depth, vm.register(12)))
            }
            crate::syscalls::SYSCALL_ZK_ROOTS_GET | crate::syscalls::SYSCALL_ZK_VOTE_GET_TALLY => {
                let request_len =
                    quote_tlv_payload_len_at(vm, vm.register(10), PointerType::NoritoBytes)?;
                let maximum_response = usize::try_from(Memory::INPUT_SIZE).unwrap_or(usize::MAX);
                Self::state_query_gas(request_len.saturating_add(maximum_response))
            }
            crate::syscalls::SYSCALL_AXT_BEGIN => {
                let payload_len =
                    quote_tlv_payload_len_at(vm, vm.register(10), PointerType::AxtDescriptor)?;
                Self::axt_gas(payload_len)
            }
            crate::syscalls::SYSCALL_AXT_TOUCH
            | crate::syscalls::SYSCALL_AXT_COMMIT
            | crate::syscalls::SYSCALL_VERIFY_DS_PROOF
            | crate::syscalls::SYSCALL_AXT_STAGE_ANCHORED_SPEND => {
                reserve_available_syscall_gas_at_least(vm, metering.minimum_gas)?
            }
            _ => {
                if metering.quote_strategy == HostSyscallQuoteStrategy::ReserveAvailable {
                    reserve_available_syscall_gas_at_least(vm, metering.minimum_gas)?
                } else {
                    MUTATION_GAS
                }
            }
        };
        Ok(quote)
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        require_host_syscall_metering_spec(vm.syscall_policy(), number)?;
        if crate::syscalls::is_numeric_v1_syscall(number) {
            return crate::numeric_v1::execute(number, vm);
        }
        if crate::syscalls::is_json_getter_syscall(number) {
            let cost = crate::json::typed_getter(vm, number, Self::resolve_code_tlv_addr)?;
            return Ok(crate::json::typed_getter_gas(
                cost.input_bytes,
                cost.output_bytes,
            ));
        }
        if number == crate::syscalls::SYSCALL_JSON_BUILD {
            return crate::json::build_json(vm, Self::resolve_code_tlv_addr);
        }
        match number {
            crate::syscalls::SYSCALL_DEBUG_PRINT => {
                let value = vm.register(10);
                if cfg!(any(test, debug_assertions)) {
                    eprintln!("[IVM] debug_print r10={value}");
                }
                Ok(DEBUG_GAS)
            }
            crate::syscalls::SYSCALL_EXIT => {
                let status = vm.register(10);
                vm.request_exit();
                vm.set_register(10, status);
                Ok(DEBUG_GAS)
            }
            crate::syscalls::SYSCALL_ABORT => {
                vm.request_abort();
                Ok(DEBUG_GAS)
            }
            crate::syscalls::SYSCALL_CONTRACT_ABORT => {
                request_nominal_contract_abort(vm, Self::resolve_code_tlv_addr)
            }
            crate::syscalls::SYSCALL_CURRENT_TIME_MS
            | crate::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS => {
                vm.set_register(10, self.current_time_ms);
                Ok(Self::sysvar_gas(0))
            }
            crate::syscalls::SYSCALL_SYSVAR_CHAIN_ID => {
                let Some(chain_id) = self.chain_id.as_ref() else {
                    vm.set_register(10, 0);
                    return Ok(Self::sysvar_gas(0));
                };
                let ptr = Self::alloc_blob_tlv(vm, chain_id)?;
                vm.set_register(10, ptr);
                Ok(Self::sysvar_gas(chain_id.len()))
            }
            crate::syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT => {
                vm.set_register(10, self.current_block_height);
                Ok(Self::sysvar_gas(0))
            }
            crate::syscalls::SYSCALL_SYSVAR_AUTHORITY => {
                vm.set_register(10, 0);
                Ok(Self::sysvar_gas(0))
            }
            crate::syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS
            | crate::syscalls::SYSCALL_SYSVAR_ENTRYPOINT => {
                vm.set_register(10, 0);
                Ok(Self::sysvar_gas(0))
            }
            crate::syscalls::SYSCALL_VRF_EPOCH_SEED => {
                vm.ensure_public_register(10)?;
                Err(VMError::metered_not_implemented(
                    crate::vrf::epoch_seed_gas(false),
                    number,
                ))
            }
            crate::syscalls::SYSCALL_QUERY_EXECUTE_NORITO
            | crate::syscalls::SYSCALL_CORE_QUERY_GET
            | crate::syscalls::SYSCALL_CORE_QUERY_PAGE
            | crate::syscalls::SYSCALL_QUERY_GET_PARAMETER
            | crate::syscalls::SYSCALL_QUERY_GET_CONTRACT_MANIFEST
            | crate::syscalls::SYSCALL_QUERY_GET_CONTRACT_INSTANCE => Err(
                VMError::metered_not_implemented(STATE_QUERY_GAS_BASE, number),
            ),
            crate::syscalls::SYSCALL_BUILD_PATH_KEY_NORITO => {
                let base_tlv = Self::expect_tlv(vm, 10, PointerType::Name)?;
                let key_tlv = Self::expect_tlv(vm, 11, PointerType::NoritoBytes)?;
                let input_len = base_tlv.payload.len().saturating_add(key_tlv.payload.len());
                let base: Name =
                    decode_canonical_norito(base_tlv.payload).map_err(|_| VMError::DecodeError)?;
                let path = canonical_typed_state_map_path(vm, &base, key_tlv.payload)?;
                let body = encode_canonical_norito(&path)?;
                let pointer = Self::alloc_norito_bytes_tlv(vm, &body)?;
                vm.set_register(10, pointer);
                Ok(Self::path_gas(input_len, body.len()))
            }
            crate::syscalls::SYSCALL_STATE_PATH_FROM_NAME => {
                let name_tlv = Self::expect_tlv(vm, 10, PointerType::Name)?;
                if name_tlv.payload.len() > syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES {
                    return Err(VMError::NoritoInvalid);
                }
                let input_len = name_tlv.payload.len();
                let name: Name =
                    decode_canonical_norito(name_tlv.payload).map_err(|_| VMError::DecodeError)?;
                let path = StatePath::from(name);
                validate_state_path(&path)?;
                let body = encode_canonical_norito(&path)?;
                let pointer = Self::alloc_norito_bytes_tlv(vm, &body)?;
                vm.set_register(10, pointer);
                Ok(Self::path_gas(input_len, body.len()))
            }
            crate::syscalls::SYSCALL_STATE_GET => {
                let (path, path_len) = Self::decode_state_path_tlv(vm, 10)?;
                if let Some(value) = self.state.get(&path) {
                    validate_state_value_payload_len(value.len())?;
                    let gas = state_value_gas(path_len, value.len());
                    preflight_reserved_syscall_gas(vm, gas)?;
                    validate_declared_state_value_payload(vm, &path, value)?;
                    let value = value.clone();
                    self.access_log.read_keys.insert(path.as_ref().to_string());
                    let ptr = Self::alloc_norito_bytes_tlv(vm, &value)?;
                    vm.set_register(10, ptr);
                    Ok(gas)
                } else {
                    let gas = state_path_gas(path_len);
                    preflight_reserved_syscall_gas(vm, gas)?;
                    self.access_log.read_keys.insert(path.as_ref().to_string());
                    vm.set_register(10, 0);
                    Ok(gas)
                }
            }
            crate::syscalls::SYSCALL_STATE_SET => {
                let (path, path_len) = Self::decode_state_path_tlv(vm, 10)?;
                let value = {
                    let tlv = Self::expect_tlv(vm, 11, PointerType::NoritoBytes)?;
                    validate_state_value_payload_len(tlv.payload.len())?;
                    validate_declared_state_value_payload(vm, &path, tlv.payload)?;
                    tlv.payload.to_vec()
                };
                let value_len = value.len();
                self.access_log.write_keys.insert(path.as_ref().to_string());
                self.state.insert(path, value);
                Ok(state_value_gas(path_len, value_len))
            }
            crate::syscalls::SYSCALL_STATE_DEL => {
                let (path, path_len) = Self::decode_state_path_tlv(vm, 10)?;
                self.access_log.write_keys.insert(path.as_ref().to_string());
                self.state.remove(&path);
                Ok(state_path_gas(path_len))
            }
            crate::syscalls::SYSCALL_STATE_SCAN => {
                let request =
                    crate::state_scan::StateScanRequest::decode(vm, &self.state_instance)?;
                let map = request.map().clone();
                let prefix = format!("{}/", map.as_ref());
                let after = request.after().cloned();
                let lower = after
                    .as_ref()
                    .map_or(std::ops::Bound::Included(prefix.as_str()), |key| {
                        std::ops::Bound::Excluded(key.as_ref())
                    });
                let mut page = crate::state_scan::StateScanPage::new(request);
                for key in self
                    .state
                    .range::<str, _>((lower, std::ops::Bound::Unbounded))
                    .map(|(key, _)| key)
                    .take_while(|key| key.as_ref().starts_with(&prefix))
                {
                    if page
                        .examine(vm, key.as_ref(), key.as_ref().len(), true)?
                        .is_break()
                    {
                        break;
                    }
                }
                let gas = page.publish(vm)?;
                self.access_log.read_keys.insert(map.as_ref().to_owned());
                Ok(gas)
            }
            crate::syscalls::SYSCALL_STATE_MAP_KEY_AT => {
                let page = Self::decode_any_tlv(vm, vm.register(10))?;
                let base_tlv = Self::decode_any_tlv(vm, vm.register(11))?;
                if page.type_id != PointerType::NoritoBytes || base_tlv.type_id != PointerType::Name
                {
                    return Err(VMError::NoritoInvalid);
                }
                let base: Name =
                    decode_canonical_norito(base_tlv.payload).map_err(|_| VMError::DecodeError)?;
                validate_declared_state_map_base(vm, &base)?;
                let key = canonical_state_map_key_at(page.payload, &base, vm.register(12))?;
                if let Some(key) = key.as_deref() {
                    validate_declared_state_map_key(vm, &base, key)?;
                }
                let gas = Self::path_gas(
                    page.payload.len().saturating_add(base_tlv.payload.len()),
                    key.as_ref().map_or(0, Vec::len),
                );
                if let Some(key) = key {
                    let pointer = Self::alloc_norito_bytes_tlv(vm, &key)?;
                    vm.set_register(10, pointer);
                } else {
                    vm.set_register(10, 0);
                }
                Ok(gas)
            }
            crate::syscalls::SYSCALL_STATE_HAS => {
                let (path, path_len) = Self::decode_state_path_tlv(vm, 10)?;
                let present = self.state.contains_key(&path);
                self.access_log.read_keys.insert(path.as_ref().to_string());
                vm.set_register(10, u64::from(present));
                Ok(state_path_gas(path_len))
            }
            crate::syscalls::SYSCALL_STATE_LEN => {
                let (path, path_len) = Self::decode_state_path_tlv(vm, 10)?;
                if let Some(value) = self.state.get(&path) {
                    validate_state_value_payload_len(value.len())?;
                    let gas = state_path_gas(path_len);
                    preflight_reserved_syscall_gas(vm, gas)?;
                    self.access_log.read_keys.insert(path.as_ref().to_string());
                    vm.set_register(10, u64::try_from(value.len()).unwrap_or(u64::MAX));
                    vm.set_register(11, 1);
                    Ok(gas)
                } else {
                    let gas = state_path_gas(path_len);
                    preflight_reserved_syscall_gas(vm, gas)?;
                    self.access_log.read_keys.insert(path.as_ref().to_string());
                    vm.set_register(10, 0);
                    vm.set_register(11, 0);
                    Ok(gas)
                }
            }
            crate::syscalls::SYSCALL_STATE_COUNT => {
                let (prefix, path_len) = Self::decode_state_scan_path_tlv(vm, 10)?;
                let (total, scan_work_gas) = self.state_count_with_prefix(vm, &prefix, path_len)?;
                let gas = STATE_QUERY_GAS_BASE.saturating_add(scan_work_gas);
                preflight_reserved_syscall_gas(vm, gas)?;
                self.access_log
                    .read_keys
                    .insert(prefix.as_ref().to_string());
                vm.set_register(10, total);
                Ok(gas)
            }
            crate::syscalls::SYSCALL_POINTER_TO_NORITO => {
                let ptr = vm.register(10);
                if ptr == 0 {
                    return Err(VMError::NoritoInvalid);
                }
                let tlv = Self::decode_any_tlv(vm, ptr)?;
                crate::numeric_tlv::validate_numeric_frame_if_needed(tlv.type_id, tlv.payload)?;
                let mut body =
                    Vec::with_capacity(2 + 1 + 4 + tlv.payload.len() + iroha_crypto::Hash::LENGTH);
                body.extend_from_slice(&tlv.type_id_raw().to_be_bytes());
                body.push(tlv.version);
                let len = u32::try_from(tlv.payload.len()).map_err(|_| VMError::NoritoInvalid)?;
                body.extend_from_slice(&len.to_be_bytes());
                body.extend_from_slice(tlv.payload);
                let hash: [u8; iroha_crypto::Hash::LENGTH] =
                    iroha_crypto::Hash::new(tlv.payload).into();
                body.extend_from_slice(&hash);
                let out = Self::alloc_norito_bytes_tlv(vm, &body)?;
                vm.set_register(10, out);
                Ok(Self::pointer_gas(body.len()))
            }
            crate::syscalls::SYSCALL_POINTER_FROM_NORITO => {
                let ptr = vm.register(10);
                if ptr == 0 {
                    if [
                        PointerType::Int,
                        PointerType::Decimal,
                        PointerType::Quantity,
                    ]
                    .into_iter()
                    .any(|kind| vm.register(11) == u64::from(kind as u16))
                    {
                        return Err(VMError::NoritoInvalid);
                    }
                    vm.set_register(10, 0);
                    return Ok(Self::pointer_gas(0));
                }
                let tlv = Self::decode_any_tlv(vm, ptr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let encoded_len = tlv.payload.len();
                let (inner_type, inner_version, inner_payload) = {
                    let inner = pointer_abi::validate_tlv_bytes(tlv.payload)
                        .map_err(|_| VMError::NoritoInvalid)?;
                    (inner.type_id, inner.version, inner.payload.to_vec())
                };
                let expected =
                    u16::try_from(vm.register(11)).map_err(|_| VMError::NoritoInvalid)?;
                if expected != 0 && expected != inner_type as u16 {
                    return Err(VMError::NoritoInvalid);
                }
                if !pointer_abi::is_type_allowed_for_policy(vm.syscall_policy(), inner_type) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: inner_type as u16,
                    });
                }
                crate::numeric_tlv::validate_numeric_frame_if_needed(inner_type, &inner_payload)?;
                let mut out = Vec::with_capacity(
                    2 + 1 + 4 + inner_payload.len() + iroha_crypto::Hash::LENGTH,
                );
                out.extend_from_slice(&(inner_type as u16).to_be_bytes());
                out.push(inner_version);
                let len = u32::try_from(inner_payload.len()).map_err(|_| VMError::NoritoInvalid)?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&inner_payload);
                let hash: [u8; iroha_crypto::Hash::LENGTH] =
                    iroha_crypto::Hash::new(&inner_payload).into();
                out.extend_from_slice(&hash);
                let out_ptr = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, out_ptr);
                Ok(Self::pointer_gas(encoded_len))
            }
            crate::syscalls::SYSCALL_TLV_EQ => {
                let ptr1 = vm.register(10);
                let ptr2 = vm.register(11);
                if ptr1 == 0 && ptr2 == 0 {
                    vm.set_register(10, 1);
                    return Ok(Self::tlv_eq_gas(0, 0));
                }
                if ptr1 == 0 {
                    let right_len = vm.validate_tlv(ptr2)?.payload.len();
                    vm.set_register(10, 0);
                    return Ok(Self::tlv_eq_gas(0, right_len));
                }
                let tlv1 = vm.validate_tlv(ptr1)?;
                let left_len = tlv1.payload.len();
                if ptr2 == 0 {
                    vm.set_register(10, 0);
                    return Ok(Self::tlv_eq_gas(left_len, 0));
                }
                if ptr1 == ptr2 {
                    vm.set_register(10, 1);
                    return Ok(Self::tlv_eq_gas(left_len, 0));
                }
                let tlv2 = vm.validate_tlv(ptr2)?;
                let right_len = tlv2.payload.len();
                let eq = tlv1.type_id == tlv2.type_id
                    && tlv1.version == tlv2.version
                    && tlv1.payload == tlv2.payload;
                vm.set_register(10, u64::from(eq));
                Ok(Self::tlv_eq_gas(left_len, right_len))
            }
            crate::syscalls::SYSCALL_TLV_LEN => {
                let ptr = vm.register(10);
                if ptr == 0 {
                    vm.set_register(10, 0);
                    return Ok(Self::tlv_len_gas(0));
                }
                let tlv = Self::decode_any_tlv(vm, ptr)?;
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: tlv.type_id as u16,
                    });
                }
                let payload_len = tlv.payload.len();
                vm.set_register(10, u64::try_from(payload_len).unwrap_or(u64::MAX));
                Ok(Self::tlv_len_gas(payload_len))
            }
            crate::syscalls::SYSCALL_DECODE_ARGUMENT_RECORD => {
                crate::argument_record::decode_argument_record(vm)
            }
            crate::syscalls::SYSCALL_VALUE_ENCODE
            | crate::syscalls::SYSCALL_BLOB_CONCAT
            | crate::syscalls::SYSCALL_UTF8_VALIDATE
            | crate::syscalls::SYSCALL_VALUE_TO_STRING => {
                crate::value_utilities::execute(number, vm)
            }
            crate::syscalls::SYSCALL_STATE_VALUE_ENCODE => {
                crate::state_value_runtime::encode_state_value(
                    vm,
                    crate::core_host::CoreHost::resolve_code_tlv_addr,
                )
            }
            crate::syscalls::SYSCALL_STATE_VALUE_DECODE => {
                crate::state_value_runtime::decode_state_value(
                    vm,
                    crate::core_host::CoreHost::resolve_code_tlv_addr,
                )
            }
            crate::syscalls::SYSCALL_NORMALIZE_NORITO_BYTES => normalize_norito_bytes(vm),
            crate::syscalls::SYSCALL_DEBUG_LOG => {
                let ptr = vm.register(10);
                if ptr == 0 {
                    return Ok(DEBUG_GAS);
                }
                let tlv = Self::decode_any_tlv(vm, ptr)?;
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: tlv.type_id as u16,
                    });
                }
                match tlv.type_id {
                    PointerType::Blob | PointerType::NoritoBytes | PointerType::Json => {
                        if cfg!(any(test, debug_assertions)) {
                            let msg = if tlv.type_id == PointerType::Json {
                                decode_from_bytes::<Json>(tlv.payload)
                                    .map(|json| json.to_string())
                                    .unwrap_or_else(|_| {
                                        core::str::from_utf8(tlv.payload)
                                            .unwrap_or("<non-utf8>")
                                            .to_string()
                                    })
                            } else {
                                core::str::from_utf8(tlv.payload)
                                    .unwrap_or("<non-utf8>")
                                    .to_string()
                            };
                            eprintln!("[IVM] {msg}");
                        }
                        Ok(debug_log_gas(tlv.payload.len()))
                    }
                    _ => Err(VMError::NoritoInvalid),
                }
            }
            // Basic pointer‑ABI validations to mirror core host behavior in tests
            crate::syscalls::SYSCALL_ADD_SIGNATORY => {
                // r10=&AccountId, r11=&Json
                Self::expect_tlv(vm, 10, PointerType::AccountId)?;
                Self::expect_tlv(vm, 11, PointerType::Json)?;
                Ok(Self::mutation_gas(0))
            }
            crate::syscalls::SYSCALL_REMOVE_SIGNATORY => {
                // r10=&AccountId, r11=&Json
                Self::expect_tlv(vm, 10, PointerType::AccountId)?;
                Self::expect_tlv(vm, 11, PointerType::Json)?;
                Ok(Self::mutation_gas(0))
            }
            crate::syscalls::SYSCALL_SET_ACCOUNT_QUORUM => {
                // r10=&AccountId, r11=quorum:u64
                Self::expect_tlv(vm, 10, PointerType::AccountId)?;
                let quorum_raw = vm.register(11);
                let quorum_u16 = u16::try_from(quorum_raw).map_err(|_| VMError::DecodeError)?;
                NonZeroU16::new(quorum_u16).ok_or(VMError::DecodeError)?;
                Ok(Self::mutation_gas(0))
            }
            crate::syscalls::SYSCALL_SET_ACCOUNT_DETAIL => {
                // r10=&AccountId, r11=&Name, r12=&Json
                Self::expect_tlv(vm, 10, PointerType::AccountId)?;
                Self::expect_tlv(vm, 11, PointerType::Name)?;
                let value = Self::expect_tlv(vm, 12, PointerType::Json)?;
                Ok(Self::mutation_gas(value.payload.len()))
            }
            crate::syscalls::SYSCALL_NFT_MINT_ASSET => {
                // r10=&NftId, r11=&AccountId
                Self::expect_tlv(vm, 10, PointerType::NftId)?;
                Self::expect_tlv(vm, 11, PointerType::AccountId)?;
                Ok(Self::mutation_gas(0))
            }
            crate::syscalls::SYSCALL_NFT_TRANSFER_ASSET => {
                // r10=&AccountId(from), r11=&NftId, r12=&AccountId(to)
                Self::expect_tlv(vm, 10, PointerType::AccountId)?;
                Self::expect_tlv(vm, 11, PointerType::NftId)?;
                Self::expect_tlv(vm, 12, PointerType::AccountId)?;
                Ok(Self::mutation_gas(0))
            }
            crate::syscalls::SYSCALL_TRANSFER_V1 => {
                if self.fastpq_batch_active {
                    self.push_fastpq_batch_entry(vm)
                } else {
                    Err(crate::VMError::PermissionDenied)
                }
            }
            crate::syscalls::SYSCALL_TRANSFER_ASSET_SCOPED => {
                // r10=&AccountId(from), r11=&AccountId(to), r12=&AssetDefinitionId,
                // r13=&Quantity, r14=&DataSpaceId
                let quantity_len = Self::expect_quantity(vm, 13)?;
                Self::expect_tlv(vm, 10, PointerType::AccountId)?;
                Self::expect_tlv(vm, 11, PointerType::AccountId)?;
                Self::expect_tlv(vm, 12, PointerType::AssetDefinitionId)?;
                Self::expect_tlv(vm, 14, PointerType::DataSpaceId)?;
                Ok(Self::mutation_gas(quantity_len))
            }
            crate::syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN => self.begin_fastpq_batch(),
            crate::syscalls::SYSCALL_TRANSFER_V1_BATCH_END => self.finish_fastpq_batch(),
            crate::syscalls::SYSCALL_TRANSFER_V1_BATCH_APPLY => self.apply_fastpq_batch(vm),
            crate::syscalls::SYSCALL_NFT_SET_METADATA => {
                // r10=&NftId, r11=&Name, r12=&Json
                Self::expect_tlv(vm, 10, PointerType::NftId)?;
                Self::expect_tlv(vm, 11, PointerType::Name)?;
                Self::expect_tlv(vm, 12, PointerType::Json)?;
                Ok(Self::mutation_gas(0))
            }
            crate::syscalls::SYSCALL_NFT_BURN_ASSET => {
                // r10=&NftId
                Self::expect_tlv(vm, 10, PointerType::NftId)?;
                Ok(Self::mutation_gas(0))
            }
            crate::syscalls::SYSCALL_ALLOC => {
                // Allocate `x10` bytes on the VM heap and return the pointer in `x10`.
                let size = vm.register(10);
                let addr = vm.alloc_heap(size)?;
                vm.set_register(10, addr);
                Ok(allocation_gas(size))
            }
            crate::syscalls::SYSCALL_VRF_VERIFY => {
                // Envelope-based syscall: r10 = &NoritoBytes(VrfVerifyRequest)
                // Return: r10 = &Blob(32 bytes) on success; r11 = status code (0=ok, >0 = error)
                use crate::vrf::VrfVerifyRequest;
                // Status codes specific to VRF_VERIFY
                const OK: u64 = 0;
                const ERR_TYPE: u64 = 1; // wrong TLV type
                const ERR_DECODE: u64 = 2; // Norito decode error
                const ERR_VARIANT: u64 = 3; // unknown variant
                const ERR_PK: u64 = 4; // bad pk encoding/length
                const ERR_PROOF: u64 = 5; // bad proof encoding/length
                const ERR_VERIFY: u64 = 6; // pairing check failed
                const ERR_NETWORK: u64 = 8; // network_id mismatch
                let ptr = vm.register(10);
                let (pointer_type, payload_len) = read_tlv_header_at(vm, ptr)?;
                let decode_gas = Self::vrf_verify_gas(0, payload_len);
                preflight_reserved_syscall_gas(vm, decode_gas)?;
                if payload_len > crate::vrf::MAX_VRF_VERIFY_PAYLOAD_BYTES_V1 {
                    return Err(VMError::metered(decode_gas, VMError::NoritoInvalid));
                }
                validate_quoted_tlv_range(vm, ptr, payload_len)
                    .map_err(|error| VMError::metered(decode_gas, error))?;
                let tlv = vm
                    .validate_tlv(ptr)
                    .map_err(|error| VMError::metered(decode_gas, error))?;
                if pointer_type != PointerType::NoritoBytes {
                    vm.set_register(10, 0);
                    vm.set_register(11, ERR_TYPE);
                    return Ok(decode_gas);
                }
                self.vrf_execution_counters.canonical_decodes = self
                    .vrf_execution_counters
                    .canonical_decodes
                    .saturating_add(1);
                let req: VrfVerifyRequest = match decode_canonical_norito_with_limits(
                    tlv.payload,
                    crate::vrf::VRF_VERIFY_DECODE_LIMITS_V1,
                ) {
                    Ok(v) => v,
                    Err(_) => {
                        vm.set_register(10, 0);
                        vm.set_register(11, ERR_DECODE);
                        return Ok(decode_gas);
                    }
                };
                let actual = Self::vrf_verify_gas(1, payload_len);
                preflight_reserved_syscall_gas(vm, actual)?;
                // VRF domains are host-owned consensus context. A guest-supplied
                // network identifier is only a claimed binding and can never
                // substitute for an absent host configuration.
                let Some(network_id) = self.network_id.as_ref() else {
                    vm.set_register(10, 0);
                    vm.set_register(11, ERR_NETWORK);
                    return Ok(actual);
                };
                if req.network_id != *network_id {
                    vm.set_register(10, 0);
                    vm.set_register(11, ERR_NETWORK);
                    return Ok(actual);
                }
                let network_bytes = network_id.as_bytes();
                let mut in_buf = Vec::with_capacity(
                    b"iroha:vrf:v1:input|".len() + network_bytes.len() + 1 + req.input.len(),
                );
                in_buf.extend_from_slice(b"iroha:vrf:v1:input|");
                in_buf.extend_from_slice(network_bytes);
                in_buf.push(b'|');
                in_buf.extend_from_slice(&req.input);
                let msg: [u8; 32] = iroha_crypto::Hash::new(&in_buf).into();
                // BLS helpers using blstrs
                use blstrs::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective};
                use group::{Curve, Group as _, prime::PrimeCurveAffine};
                use pairing::{MillerLoopResult as _, MultiMillerLoop as _};
                fn to_g1(bytes: &[u8]) -> Option<G1Affine> {
                    if bytes.len() != 48 {
                        return None;
                    }
                    if bytes.iter().all(|&byte| byte == 0) {
                        return None;
                    }
                    let mut arr = [0u8; 48];
                    arr.copy_from_slice(bytes);
                    let point = G1Affine::from_compressed(&arr).into_option()?;
                    if bool::from(point.is_identity()) {
                        return None;
                    }
                    if point.to_compressed() != arr {
                        None
                    } else {
                        Some(point)
                    }
                }
                fn to_g2(bytes: &[u8]) -> Option<G2Affine> {
                    if bytes.len() != 96 {
                        return None;
                    }
                    if bytes.iter().all(|&byte| byte == 0) {
                        return None;
                    }
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(bytes);
                    let point = G2Affine::from_compressed(&arr).into_option()?;
                    if bool::from(point.is_identity()) {
                        return None;
                    }
                    if point.to_compressed() != arr {
                        None
                    } else {
                        Some(point)
                    }
                }
                fn hash_to_g2(msg: &[u8]) -> G2Affine {
                    const DST: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1";
                    let mut buf = Vec::with_capacity(msg.len());
                    buf.extend_from_slice(msg);
                    G2Projective::hash_to_curve(&buf, DST, &[]).to_affine()
                }
                fn hash_to_g1(msg: &[u8]) -> G1Affine {
                    const DST: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1";
                    let mut buf = Vec::with_capacity(msg.len());
                    buf.extend_from_slice(msg);
                    G1Projective::hash_to_curve(&buf, DST, &[]).to_affine()
                }
                // Verify and produce y
                let ok: bool = match req.variant {
                    // 1 = SigInG2 (Normal): pk in G1 (48), proof in G2 (96)
                    1 => {
                        let Some(pk) = to_g1(&req.pk) else {
                            vm.set_register(10, 0);
                            vm.set_register(11, ERR_PK);
                            return Ok(actual);
                        };
                        let Some(sig) = to_g2(&req.proof) else {
                            vm.set_register(10, 0);
                            vm.set_register(11, ERR_PROOF);
                            return Ok(actual);
                        };
                        self.vrf_execution_counters.backend_invocations = self
                            .vrf_execution_counters
                            .backend_invocations
                            .saturating_add(1);
                        let h = hash_to_g2(&msg);
                        let terms: [(&G1Affine, &G2Prepared); 2] = [
                            (&G1Affine::generator(), &G2Prepared::from(sig)),
                            (&(-G1Projective::from(pk)).to_affine(), &G2Prepared::from(h)),
                        ];
                        let gt = Bls12::multi_miller_loop(&terms).final_exponentiation();
                        gt.is_identity().into()
                    }
                    // 2 = SigInG1 (Small): pk in G2 (96), proof in G1 (48)
                    2 => {
                        let Some(pk) = to_g2(&req.pk) else {
                            vm.set_register(10, 0);
                            vm.set_register(11, ERR_PK);
                            return Ok(actual);
                        };
                        let Some(sig) = to_g1(&req.proof) else {
                            vm.set_register(10, 0);
                            vm.set_register(11, ERR_PROOF);
                            return Ok(actual);
                        };
                        self.vrf_execution_counters.backend_invocations = self
                            .vrf_execution_counters
                            .backend_invocations
                            .saturating_add(1);
                        let h = hash_to_g1(&msg);
                        let terms: [(&G1Affine, &G2Prepared); 2] = [
                            (&sig, &G2Prepared::from(G2Affine::generator())),
                            (&(-G1Projective::from(h)).to_affine(), &G2Prepared::from(pk)),
                        ];
                        let gt = Bls12::multi_miller_loop(&terms).final_exponentiation();
                        gt.is_identity().into()
                    }
                    _ => {
                        vm.set_register(10, 0);
                        vm.set_register(11, ERR_VARIANT);
                        return Ok(actual);
                    }
                };
                if !ok {
                    vm.set_register(10, 0);
                    vm.set_register(11, ERR_VERIFY);
                    return Ok(actual);
                }
                // Derive output y = Hash(b"iroha:vrf:v1:output" || proof)
                let mut out_buf =
                    Vec::with_capacity(b"iroha:vrf:v1:output".len() + req.proof.len());
                out_buf.extend_from_slice(b"iroha:vrf:v1:output");
                out_buf.extend_from_slice(&req.proof);
                let y: [u8; 32] = iroha_crypto::Hash::new(&out_buf).into();
                // Build a host-owned Blob TLV and return its public pointer.
                let mut tlv = Vec::with_capacity(7 + 32 + 32);
                tlv.extend_from_slice(&(PointerType::Blob as u16).to_be_bytes());
                tlv.push(1);
                tlv.extend_from_slice(&(32u32).to_be_bytes());
                tlv.extend_from_slice(&y);
                let h: [u8; 32] = iroha_crypto::Hash::new(y).into();
                tlv.extend_from_slice(&h);
                let pointer = vm
                    .alloc_host_tlv(&tlv)
                    .map_err(|error| VMError::metered(actual, error))?;
                self.vrf_execution_counters.response_allocations = self
                    .vrf_execution_counters
                    .response_allocations
                    .saturating_add(1);
                vm.set_register(10, pointer);
                vm.set_register(11, OK);
                Ok(actual)
            }
            crate::syscalls::SYSCALL_VRF_VERIFY_BATCH => {
                // r10 = &NoritoBytes(VrfVerifyBatchRequest { items: [VrfVerifyRequest] })
                use crate::vrf::VrfVerifyBatchRequest;
                const OK: u64 = 0;
                const ERR_TYPE: u64 = 1;
                const ERR_DECODE: u64 = 2;
                const ERR_VARIANT: u64 = 3;
                const ERR_PK: u64 = 4;
                const ERR_PROOF: u64 = 5;
                const ERR_VERIFY: u64 = 6;
                const ERR_NETWORK: u64 = 8;
                const ERR_BATCH: u64 = 9;
                let ptr = vm.register(10);
                let (pointer_type, payload_len) = read_tlv_header_at(vm, ptr)?;
                let decode_gas = Self::vrf_verify_gas(0, payload_len);
                preflight_reserved_syscall_gas(vm, decode_gas)?;
                if payload_len > crate::vrf::MAX_VRF_VERIFY_PAYLOAD_BYTES_V1 {
                    return Err(VMError::metered(decode_gas, VMError::NoritoInvalid));
                }
                validate_quoted_tlv_range(vm, ptr, payload_len)
                    .map_err(|error| VMError::metered(decode_gas, error))?;
                let tlv = vm
                    .validate_tlv(ptr)
                    .map_err(|error| VMError::metered(decode_gas, error))?;
                if pointer_type != PointerType::NoritoBytes {
                    vm.set_register(10, 0);
                    vm.set_register(11, ERR_TYPE);
                    vm.set_register(12, u64::MAX);
                    return Ok(decode_gas);
                }
                self.vrf_execution_counters.canonical_decodes = self
                    .vrf_execution_counters
                    .canonical_decodes
                    .saturating_add(1);
                let req: VrfVerifyBatchRequest = match decode_canonical_norito_with_limits(
                    tlv.payload,
                    crate::vrf::VRF_VERIFY_DECODE_LIMITS_V1,
                ) {
                    Ok(v) => v,
                    Err(_) => {
                        vm.set_register(10, 0);
                        vm.set_register(11, ERR_DECODE);
                        vm.set_register(12, u64::MAX);
                        return Ok(decode_gas);
                    }
                };
                if req.items.is_empty()
                    || req.items.len() > crate::vrf::MAX_VRF_VERIFY_BATCH_ITEMS_V1
                {
                    vm.set_register(10, 0);
                    vm.set_register(11, ERR_BATCH);
                    vm.set_register(12, u64::MAX);
                    return Ok(decode_gas);
                }
                let success_gas = Self::vrf_verify_gas(req.items.len(), payload_len);
                preflight_reserved_syscall_gas(vm, success_gas)?;
                // Shared helpers
                use blstrs::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective};
                use group::{Curve, Group as _, prime::PrimeCurveAffine};
                use pairing::{MillerLoopResult as _, MultiMillerLoop as _};
                fn to_g1(bytes: &[u8]) -> Option<G1Affine> {
                    if bytes.len() != 48 {
                        return None;
                    }
                    if bytes.iter().all(|&byte| byte == 0) {
                        return None;
                    }
                    let mut arr = [0u8; 48];
                    arr.copy_from_slice(bytes);
                    let point = G1Affine::from_compressed(&arr).into_option()?;
                    if bool::from(point.is_identity()) {
                        return None;
                    }
                    if point.to_compressed() != arr {
                        None
                    } else {
                        Some(point)
                    }
                }
                fn to_g2(bytes: &[u8]) -> Option<G2Affine> {
                    if bytes.len() != 96 {
                        return None;
                    }
                    if bytes.iter().all(|&byte| byte == 0) {
                        return None;
                    }
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(bytes);
                    let point = G2Affine::from_compressed(&arr).into_option()?;
                    if bool::from(point.is_identity()) {
                        return None;
                    }
                    if point.to_compressed() != arr {
                        None
                    } else {
                        Some(point)
                    }
                }
                fn hash_to_g2(msg: &[u8]) -> G2Affine {
                    const DST: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1";
                    let mut buf = Vec::with_capacity(msg.len());
                    buf.extend_from_slice(msg);
                    G2Projective::hash_to_curve(&buf, DST, &[]).to_affine()
                }
                fn hash_to_g1(msg: &[u8]) -> G1Affine {
                    const DST: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1";
                    let mut buf = Vec::with_capacity(msg.len());
                    buf.extend_from_slice(msg);
                    G1Projective::hash_to_curve(&buf, DST, &[]).to_affine()
                }
                let mut outputs: Vec<[u8; 32]> = Vec::with_capacity(req.items.len());
                for (idx, it) in req.items.iter().enumerate() {
                    let examined_gas = Self::vrf_verify_gas(idx.saturating_add(1), payload_len);
                    let Some(network_id) = self.network_id.as_ref() else {
                        vm.set_register(10, 0);
                        vm.set_register(11, ERR_NETWORK);
                        vm.set_register(12, idx as u64);
                        return Ok(examined_gas);
                    };
                    if it.network_id != *network_id {
                        vm.set_register(10, 0);
                        vm.set_register(11, ERR_NETWORK);
                        vm.set_register(12, idx as u64);
                        return Ok(examined_gas);
                    }
                    let network_bytes = network_id.as_bytes();
                    let mut in_buf = Vec::with_capacity(
                        b"iroha:vrf:v1:input|".len() + network_bytes.len() + 1 + it.input.len(),
                    );
                    in_buf.extend_from_slice(b"iroha:vrf:v1:input|");
                    in_buf.extend_from_slice(network_bytes);
                    in_buf.push(b'|');
                    in_buf.extend_from_slice(&it.input);
                    let msg: [u8; 32] = iroha_crypto::Hash::new(&in_buf).into();
                    let ok: bool = match it.variant {
                        1 => {
                            let Some(pk) = to_g1(&it.pk) else {
                                vm.set_register(10, 0);
                                vm.set_register(11, ERR_PK);
                                vm.set_register(12, idx as u64);
                                return Ok(examined_gas);
                            };
                            let Some(sig) = to_g2(&it.proof) else {
                                vm.set_register(10, 0);
                                vm.set_register(11, ERR_PROOF);
                                vm.set_register(12, idx as u64);
                                return Ok(examined_gas);
                            };
                            self.vrf_execution_counters.backend_invocations = self
                                .vrf_execution_counters
                                .backend_invocations
                                .saturating_add(1);
                            let h = hash_to_g2(&msg);
                            let terms: [(&G1Affine, &G2Prepared); 2] = [
                                (&G1Affine::generator(), &G2Prepared::from(sig)),
                                (&(-G1Projective::from(pk)).to_affine(), &G2Prepared::from(h)),
                            ];
                            let gt = Bls12::multi_miller_loop(&terms).final_exponentiation();
                            gt.is_identity().into()
                        }
                        2 => {
                            let Some(pk) = to_g2(&it.pk) else {
                                vm.set_register(10, 0);
                                vm.set_register(11, ERR_PK);
                                vm.set_register(12, idx as u64);
                                return Ok(examined_gas);
                            };
                            let Some(sig) = to_g1(&it.proof) else {
                                vm.set_register(10, 0);
                                vm.set_register(11, ERR_PROOF);
                                vm.set_register(12, idx as u64);
                                return Ok(examined_gas);
                            };
                            self.vrf_execution_counters.backend_invocations = self
                                .vrf_execution_counters
                                .backend_invocations
                                .saturating_add(1);
                            let h = hash_to_g1(&msg);
                            let terms: [(&G1Affine, &G2Prepared); 2] = [
                                (&sig, &G2Prepared::from(G2Affine::generator())),
                                (&(-G1Projective::from(h)).to_affine(), &G2Prepared::from(pk)),
                            ];
                            let gt = Bls12::multi_miller_loop(&terms).final_exponentiation();
                            gt.is_identity().into()
                        }
                        _ => {
                            vm.set_register(10, 0);
                            vm.set_register(11, ERR_VARIANT);
                            vm.set_register(12, idx as u64);
                            return Ok(examined_gas);
                        }
                    };
                    if !ok {
                        vm.set_register(10, 0);
                        vm.set_register(11, ERR_VERIFY);
                        vm.set_register(12, idx as u64);
                        return Ok(examined_gas);
                    }
                    // Compute y
                    let mut out_buf =
                        Vec::with_capacity(b"iroha:vrf:v1:output".len() + it.proof.len());
                    out_buf.extend_from_slice(b"iroha:vrf:v1:output");
                    out_buf.extend_from_slice(&it.proof);
                    let y: [u8; 32] = iroha_crypto::Hash::new(&out_buf).into();
                    outputs.push(y);
                }
                // Encode outputs Vec<[u8;32]> as NoritoBytes and return pointer
                let body = encode_canonical_norito(&outputs)
                    .map_err(|error| VMError::metered(success_gas, error))?;
                let mut out = Vec::with_capacity(7 + body.len() + 32);
                out.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
                out.push(1);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                let h: [u8; 32] = iroha_crypto::Hash::new(&body).into();
                out.extend_from_slice(&h);
                let pointer = vm
                    .alloc_host_tlv(&out)
                    .map_err(|error| VMError::metered(success_gas, error))?;
                self.vrf_execution_counters.response_allocations = self
                    .vrf_execution_counters
                    .response_allocations
                    .saturating_add(1);
                vm.set_register(10, pointer);
                vm.set_register(11, OK);
                vm.set_register(12, u64::MAX);
                Ok(success_gas)
            }
            crate::syscalls::SYSCALL_GROW_HEAP => {
                // Increase heap limit by `x10` bytes.
                let size = vm.register(10);
                let new_limit = vm.grow_heap(size)?;
                vm.set_register(10, new_limit);
                Ok(Self::grow_heap_gas(size))
            }
            crate::syscalls::SYSCALL_GET_PRIVATE_INPUT => {
                // Decode only after the VM has debited the fixed maximum quote.
                let expected =
                    PrivateInputKindV1::from_tag(vm.register(11)).ok_or(VMError::NoritoInvalid)?;
                let raw = usize::try_from(vm.register(10))
                    .ok()
                    .and_then(|index| self.private_inputs.get(index))
                    .ok_or(VMError::PermissionDenied)?;
                let value = crate::private_input::decode_record(raw, expected)?;
                debug_assert_eq!(value.kind, expected);
                let pointer = vm.alloc_host_private_tlv(&value.envelope)?;
                vm.set_register(10, pointer);
                Ok(GET_PRIVATE_INPUT_GAS)
            }
            crate::syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM => {
                use iroha_primitives::numeric_abi::MAX_QUANTITY_ENVELOPE_BYTES_V1;
                // The two complete opaque inputs are snapshotted and validated
                // before any public result allocation occurs.
                let value =
                    vm.snapshot_private_tlv(vm.register(10), MAX_QUANTITY_ENVELOPE_BYTES_V1)?;
                let blind =
                    vm.snapshot_private_tlv(vm.register(11), MAX_QUANTITY_ENVELOPE_BYTES_V1)?;
                let value_kind = crate::private_input::validate_private_numeric_envelope(&value)?;
                let blind_kind = crate::private_input::validate_private_numeric_envelope(&blind)?;
                let commitment =
                    crate::private_input::valcom(value_kind, &value, blind_kind, &blind)?;
                let output = ivm_abi::numeric_tlv::encode_int(&commitment)?;
                let pointer = vm.alloc_host_tlv(&output)?;
                vm.set_register(10, pointer);
                Ok(PRIVATE_NUMERIC_VALCOM_GAS)
            }
            crate::syscalls::SYSCALL_GET_PUBLIC_INPUT => {
                // Load a named public input provided by the host.
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::Name {
                    return Err(VMError::NoritoInvalid);
                }
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: tlv.type_id as u16,
                    });
                }
                let name: Name = decode_canonical_norito(tlv.payload)?;
                let Some(bytes) = self.public_inputs.get(&name) else {
                    return Err(VMError::PermissionDenied);
                };
                let tlv = pointer_abi::validate_tlv_bytes(bytes)?;
                if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: tlv.type_id as u16,
                    });
                }
                let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                let gas = PUBLIC_INPUT_GAS_BASE
                    .saturating_add(PUBLIC_INPUT_GAS_PER_BYTE.saturating_mul(len));
                preflight_reserved_syscall_gas(vm, gas)?;
                let dst = vm.alloc_host_tlv(bytes)?;
                vm.set_register(10, dst);
                Ok(gas)
            }
            crate::syscalls::SYSCALL_COMMIT_OUTPUT => {
                // Commit only the append-only written prefix. Quoting and
                // preflight happen before the copy, so repeated empty commits
                // remain constant-time and full commits pay for every byte.
                let output_len = vm.output_used_len();
                let gas = gas::commit_output_gas(output_len);
                preflight_reserved_syscall_gas(vm, gas)?;
                self.pub_output = vm.read_output_used().to_vec();
                Ok(gas)
            }
            crate::syscalls::SYSCALL_EXECUTION_SUMMARY => {
                let summary = vm.execution_summary();
                let payload = encode_canonical_norito(&summary)?;
                let ptr = Self::alloc_norito_bytes_tlv(vm, &payload)?;
                vm.set_register(10, ptr);
                vm.set_register(11, 0);
                let event_count = summary
                    .pc_trace_len
                    .saturating_add(summary.delta_trace_len)
                    .saturating_add(summary.register_trace_len)
                    .saturating_add(summary.constraint_len)
                    .saturating_add(summary.memory_log_len)
                    .saturating_add(summary.register_log_len)
                    .saturating_add(summary.step_log_len);
                let payload_len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
                Ok(128_u64
                    .saturating_add(event_count.saturating_mul(2))
                    .saturating_add(payload_len))
            }
            crate::syscalls::SYSCALL_VERIFY_PROOF => {
                // Execution proof verification is implemented at the node layer (CoreHost),
                // not inside the standalone IVM host.
                Err(VMError::metered_not_implemented(VERIFY_GAS_BASE, number))
            }
            crate::syscalls::SYSCALL_VERIFY_SIGNATURE => {
                // r10 = &message TLV, r11 = &Blob signature TLV, r12 = &Blob public key TLV, r13 = scheme code
                let (msg, sig, pk) = Self::decode_signature_inputs(vm)?;
                let gas = Self::signature_verify_gas(msg.len(), sig.len(), pk.len());
                let Ok(scheme_code) = u8::try_from(vm.register(13)) else {
                    vm.set_register(10, 0);
                    return Ok(gas);
                };
                let scheme = match scheme_code {
                    1 => crate::signature::SignatureScheme::Ed25519,
                    2 => crate::signature::SignatureScheme::Secp256k1,
                    3 => crate::signature::SignatureScheme::MlDsa,
                    _ => {
                        vm.set_register(10, 0);
                        return Ok(gas);
                    }
                };
                let ok = crate::signature::verify_signature(scheme, &msg, &sig, &pk);
                vm.set_register(10, if ok { 1 } else { 0 });
                Ok(gas)
            }
            crate::syscalls::SYSCALL_SM3_HASH => {
                if !self.sm_enabled {
                    return Err(VMError::PermissionDenied);
                }
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::Blob {
                    return Err(VMError::NoritoInvalid);
                }
                let payload_len = tlv.payload.len();
                let digest = Sm3Digest::hash(tlv.payload);
                let bytes = digest.as_bytes();
                let addr = DefaultHost::alloc_blob_tlv(vm, bytes)?;
                vm.set_register(10, addr);
                Ok(Self::hash_syscall_gas(payload_len))
            }
            crate::syscalls::SYSCALL_SHA256_HASH => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::Blob {
                    return Err(VMError::NoritoInvalid);
                }
                let payload_len = tlv.payload.len();
                let digest = <Sha256 as Sha2Digest>::digest(tlv.payload);
                let addr = DefaultHost::alloc_blob_tlv(vm, digest.as_slice())?;
                vm.set_register(10, addr);
                Ok(Self::hash_syscall_gas(payload_len))
            }
            crate::syscalls::SYSCALL_SHA3_HASH => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::Blob {
                    return Err(VMError::NoritoInvalid);
                }
                let payload_len = tlv.payload.len();
                let digest = <Sha3_256 as Sha3Digest>::digest(tlv.payload);
                let addr = DefaultHost::alloc_blob_tlv(vm, digest.as_slice())?;
                vm.set_register(10, addr);
                Ok(Self::hash_syscall_gas(payload_len))
            }
            crate::syscalls::SYSCALL_BLAKE2B256_HASH => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::Blob {
                    return Err(VMError::NoritoInvalid);
                }
                let payload_len = tlv.payload.len();
                let digest = Self::blake2b256(tlv.payload);
                let addr = DefaultHost::alloc_blob_tlv(vm, &digest)?;
                vm.set_register(10, addr);
                Ok(Self::hash_syscall_gas(payload_len))
            }
            crate::syscalls::SYSCALL_KECCAK256_HASH => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::Blob {
                    return Err(VMError::NoritoInvalid);
                }
                let payload_len = tlv.payload.len();
                let digest = <Keccak256 as Sha3Digest>::digest(tlv.payload);
                let addr = DefaultHost::alloc_blob_tlv(vm, digest.as_slice())?;
                vm.set_register(10, addr);
                Ok(Self::hash_syscall_gas(payload_len))
            }
            crate::syscalls::SYSCALL_IROHA_HASH => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::Blob {
                    return Err(VMError::NoritoInvalid);
                }
                let payload_len = tlv.payload.len();
                let digest: [u8; iroha_crypto::Hash::LENGTH] =
                    iroha_crypto::Hash::new(tlv.payload).into();
                let addr = DefaultHost::alloc_blob_tlv(vm, &digest)?;
                vm.set_register(10, addr);
                Ok(Self::hash_syscall_gas(payload_len))
            }
            crate::syscalls::SYSCALL_SM2_VERIFY => {
                if !self.sm_enabled {
                    return Err(VMError::PermissionDenied);
                }
                let msg_tlv = vm.validate_tlv(vm.register(10))?;
                let sig_tlv = vm.validate_tlv(vm.register(11))?;
                let pk_tlv = vm.validate_tlv(vm.register(12))?;
                if msg_tlv.type_id != PointerType::Blob
                    || sig_tlv.type_id != PointerType::Blob
                    || pk_tlv.type_id != PointerType::Blob
                {
                    return Err(VMError::NoritoInvalid);
                }
                let distid_ptr = vm.register(13);
                let mut input_len = msg_tlv
                    .payload
                    .len()
                    .saturating_add(sig_tlv.payload.len())
                    .saturating_add(pk_tlv.payload.len());
                let distid = if distid_ptr != 0 {
                    let distid_tlv = vm.validate_tlv(distid_ptr)?;
                    if distid_tlv.type_id != PointerType::Blob {
                        return Err(VMError::NoritoInvalid);
                    }
                    input_len = input_len.saturating_add(distid_tlv.payload.len());
                    std::str::from_utf8(distid_tlv.payload)
                        .map(|s| s.to_owned())
                        .map_err(|_| VMError::NoritoInvalid)?
                } else {
                    Sm2PublicKey::default_distid()
                };
                let gas = Self::verify_gas(input_len);
                let msg = msg_tlv.payload;
                let sig_bytes = sig_tlv.payload;
                if sig_bytes.len() != Sm2Signature::LENGTH {
                    vm.set_register(10, 0);
                    return Ok(gas);
                }
                let mut sig_buf = [0u8; Sm2Signature::LENGTH];
                sig_buf.copy_from_slice(sig_bytes);
                let signature = match Sm2Signature::from_bytes(&sig_buf) {
                    Ok(sig) => sig,
                    Err(_) => {
                        vm.set_register(10, 0);
                        return Ok(gas);
                    }
                };
                let public_key = match Sm2PublicKey::from_sec1_bytes(&distid, pk_tlv.payload) {
                    Ok(pk) => pk,
                    Err(_) => {
                        vm.set_register(10, 0);
                        return Ok(gas);
                    }
                };
                let ok = public_key.verify(msg, &signature).is_ok();
                vm.set_register(10, if ok { 1 } else { 0 });
                Ok(gas)
            }
            crate::syscalls::SYSCALL_SM4_GCM_SEAL => {
                if !self.sm_enabled {
                    return Err(VMError::PermissionDenied);
                }
                let key_tlv = vm.validate_tlv(vm.register(10))?;
                let nonce_tlv = vm.validate_tlv(vm.register(11))?;
                let aad_opt = if vm.register(12) == 0 {
                    None
                } else {
                    Some(vm.validate_tlv(vm.register(12))?)
                };
                let pt_tlv = vm.validate_tlv(vm.register(13))?;
                if key_tlv.type_id != PointerType::Blob
                    || nonce_tlv.type_id != PointerType::Blob
                    || pt_tlv.type_id != PointerType::Blob
                {
                    return Err(VMError::NoritoInvalid);
                }
                if let Some(ref aad_tlv) = aad_opt
                    && aad_tlv.type_id != PointerType::Blob
                {
                    return Err(VMError::NoritoInvalid);
                }
                let aad_len = aad_opt.as_ref().map(|tlv| tlv.payload.len()).unwrap_or(0);
                let gas = Self::sm4_gas(aad_len, pt_tlv.payload.len());
                if key_tlv.payload.len() != 16 {
                    vm.set_register(10, 0);
                    return Ok(gas);
                }
                let mut key_bytes = [0u8; 16];
                key_bytes.copy_from_slice(key_tlv.payload);
                let key = Sm4Key::new(key_bytes);
                if nonce_tlv.payload.len() != 12 {
                    vm.set_register(10, 0);
                    return Ok(gas);
                }
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(nonce_tlv.payload);
                let aad = aad_opt.as_ref().map(|tlv| tlv.payload).unwrap_or(&[]);
                match key.encrypt_gcm(&nonce, aad, pt_tlv.payload) {
                    Ok((cipher, tag)) => {
                        let mut payload = cipher;
                        payload.extend_from_slice(&tag);
                        let addr = DefaultHost::alloc_blob_tlv(vm, &payload)?;
                        vm.set_register(10, addr);
                    }
                    Err(_) => {
                        vm.set_register(10, 0);
                    }
                }
                Ok(gas)
            }
            crate::syscalls::SYSCALL_SM4_GCM_OPEN => {
                if !self.sm_enabled {
                    return Err(VMError::PermissionDenied);
                }
                let key_tlv = vm.validate_tlv(vm.register(10))?;
                let nonce_tlv = vm.validate_tlv(vm.register(11))?;
                let aad_opt = if vm.register(12) == 0 {
                    None
                } else {
                    Some(vm.validate_tlv(vm.register(12))?)
                };
                let ct_tlv = vm.validate_tlv(vm.register(13))?;
                if key_tlv.type_id != PointerType::Blob
                    || nonce_tlv.type_id != PointerType::Blob
                    || ct_tlv.type_id != PointerType::Blob
                {
                    return Err(VMError::NoritoInvalid);
                }
                if let Some(ref aad_tlv) = aad_opt
                    && aad_tlv.type_id != PointerType::Blob
                {
                    return Err(VMError::NoritoInvalid);
                }
                let aad_len = aad_opt.as_ref().map(|tlv| tlv.payload.len()).unwrap_or(0);
                let gas = Self::sm4_gas(aad_len, ct_tlv.payload.len());
                if key_tlv.payload.len() != 16 {
                    vm.set_register(10, 0);
                    return Ok(gas);
                }
                let mut key_bytes = [0u8; 16];
                key_bytes.copy_from_slice(key_tlv.payload);
                let key = Sm4Key::new(key_bytes);
                if nonce_tlv.payload.len() != 12 {
                    vm.set_register(10, 0);
                    return Ok(gas);
                }
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(nonce_tlv.payload);
                let aad = aad_opt.as_ref().map(|tlv| tlv.payload).unwrap_or(&[]);
                if ct_tlv.payload.len() < 16 {
                    vm.set_register(10, 0);
                    return Ok(gas);
                }
                let split = ct_tlv.payload.len() - 16;
                let (cipher_bytes, tag_bytes) = ct_tlv.payload.split_at(split);
                let mut tag = [0u8; 16];
                tag.copy_from_slice(tag_bytes);
                match key.decrypt_gcm(&nonce, aad, cipher_bytes, &tag) {
                    Ok(plaintext) => {
                        let addr = DefaultHost::alloc_blob_tlv(vm, &plaintext)?;
                        vm.set_register(10, addr);
                    }
                    Err(_) => {
                        vm.set_register(10, 0);
                    }
                }
                Ok(gas)
            }
            crate::syscalls::SYSCALL_SM4_CCM_SEAL => {
                if !self.sm_enabled {
                    return Err(VMError::PermissionDenied);
                }
                let key_tlv = vm.validate_tlv(vm.register(10))?;
                let nonce_tlv = vm.validate_tlv(vm.register(11))?;
                let aad_opt = if vm.register(12) == 0 {
                    None
                } else {
                    Some(vm.validate_tlv(vm.register(12))?)
                };
                let pt_tlv = vm.validate_tlv(vm.register(13))?;
                let tag_len_raw = vm.register(14);
                if key_tlv.type_id != PointerType::Blob
                    || nonce_tlv.type_id != PointerType::Blob
                    || pt_tlv.type_id != PointerType::Blob
                {
                    return Err(VMError::NoritoInvalid);
                }
                if let Some(ref aad_tlv) = aad_opt
                    && aad_tlv.type_id != PointerType::Blob
                {
                    return Err(VMError::NoritoInvalid);
                }
                let aad_len = aad_opt.as_ref().map(|tlv| tlv.payload.len()).unwrap_or(0);
                let gas = Self::sm4_gas(aad_len, pt_tlv.payload.len());
                let Some(tag_len) = Self::sm4_ccm_tag_len(tag_len_raw) else {
                    vm.set_register(10, 0);
                    return Ok(gas);
                };
                if key_tlv.payload.len() != 16 {
                    vm.set_register(10, 0);
                    return Ok(gas);
                }
                let mut key_bytes = [0u8; 16];
                key_bytes.copy_from_slice(key_tlv.payload);
                let key = Sm4Key::new(key_bytes);
                let aad = aad_opt.as_ref().map(|tlv| tlv.payload).unwrap_or(&[]);
                match key.encrypt_ccm(nonce_tlv.payload, aad, pt_tlv.payload, tag_len) {
                    Ok((mut cipher, tag)) => {
                        cipher.extend_from_slice(&tag);
                        let addr = DefaultHost::alloc_blob_tlv(vm, &cipher)?;
                        vm.set_register(10, addr);
                    }
                    Err(_) => {
                        vm.set_register(10, 0);
                    }
                }
                Ok(gas)
            }
            crate::syscalls::SYSCALL_SM4_CCM_OPEN => {
                if !self.sm_enabled {
                    return Err(VMError::PermissionDenied);
                }
                let key_tlv = vm.validate_tlv(vm.register(10))?;
                let nonce_tlv = vm.validate_tlv(vm.register(11))?;
                let aad_opt = if vm.register(12) == 0 {
                    None
                } else {
                    Some(vm.validate_tlv(vm.register(12))?)
                };
                let ct_tlv = vm.validate_tlv(vm.register(13))?;
                let tag_len_raw = vm.register(14);
                if key_tlv.type_id != PointerType::Blob
                    || nonce_tlv.type_id != PointerType::Blob
                    || ct_tlv.type_id != PointerType::Blob
                {
                    return Err(VMError::NoritoInvalid);
                }
                if let Some(ref aad_tlv) = aad_opt
                    && aad_tlv.type_id != PointerType::Blob
                {
                    return Err(VMError::NoritoInvalid);
                }
                let aad_len = aad_opt.as_ref().map(|tlv| tlv.payload.len()).unwrap_or(0);
                let gas = Self::sm4_gas(aad_len, ct_tlv.payload.len());
                let Some(tag_len) = Self::sm4_ccm_tag_len(tag_len_raw) else {
                    vm.set_register(10, 0);
                    return Ok(gas);
                };
                if key_tlv.payload.len() != 16 {
                    vm.set_register(10, 0);
                    return Ok(gas);
                }
                let mut key_bytes = [0u8; 16];
                key_bytes.copy_from_slice(key_tlv.payload);
                let key = Sm4Key::new(key_bytes);
                let aad = aad_opt.as_ref().map(|tlv| tlv.payload).unwrap_or(&[]);
                if ct_tlv.payload.len() < tag_len {
                    vm.set_register(10, 0);
                    return Ok(gas);
                }
                let split = ct_tlv.payload.len() - tag_len;
                let (cipher_bytes, tag_bytes) = ct_tlv.payload.split_at(split);
                match key.decrypt_ccm(nonce_tlv.payload, aad, cipher_bytes, tag_bytes) {
                    Ok(plaintext) => {
                        let addr = DefaultHost::alloc_blob_tlv(vm, &plaintext)?;
                        vm.set_register(10, addr);
                    }
                    Err(_) => {
                        vm.set_register(10, 0);
                    }
                }
                Ok(gas)
            }
            crate::syscalls::SYSCALL_INPUT_PUBLISH_TLV => {
                // Validate host-owned public TLVs in place. Immutable code literals are
                // materialized into the host arena so downstream pointer consumers can
                // retain the returned pointer after literal resolution.
                let src = vm.register(10);
                if src == 0 {
                    vm.set_register(10, 0);
                    return Ok(Self::input_publish_gas(0));
                }
                if src >= crate::memory::Memory::HEAP_START {
                    let tlv = vm.validate_tlv(src)?;
                    let envelope_len = 7usize.saturating_add(tlv.payload.len()).saturating_add(32);
                    return Ok(Self::input_publish_gas(envelope_len));
                }
                let resolved =
                    Self::resolve_literal_pointer(vm, src).ok_or(VMError::NoritoInvalid)?;
                let bytes_vec = vm.clone_tlv(resolved)?;
                let total = bytes_vec.len();
                let dst = vm.alloc_host_tlv(&bytes_vec)?;
                vm.set_register(10, dst);
                Ok(Self::input_publish_gas(total))
            }
            crate::syscalls::SYSCALL_GET_MERKLE_PATH => {
                let addr = vm.register(10);
                let max_addr = vm
                    .memory
                    .stack_top()
                    .saturating_add(crate::Memory::STACK_SLOP);
                if addr >= max_addr {
                    return Err(VMError::MemoryOutOfBounds);
                }
                let dest = vm.register(11);
                let root_out = vm.register(12);
                let (root, path) = vm.memory.merkle_root_and_path(addr)?;
                for (i, node) in path.iter().enumerate() {
                    vm.memory.store_bytes(dest + (i as u64) * 32, node)?;
                }
                if root_out != 0 {
                    vm.memory.store_bytes(root_out, root.as_ref())?;
                }
                vm.set_register(10, path.len() as u64);
                Ok(Self::merkle_path_gas(path.len()))
            }
            crate::syscalls::SYSCALL_GET_MERKLE_COMPACT => {
                let addr = vm.register(10);
                let max_addr = vm
                    .memory
                    .stack_top()
                    .saturating_add(crate::Memory::STACK_SLOP);
                if addr >= max_addr {
                    return Err(VMError::MemoryOutOfBounds);
                }
                let dest = vm.register(11);
                let depth_cap_raw = vm.register(12);
                let depth_cap = if depth_cap_raw == 0 {
                    None
                } else {
                    Some(usize::try_from(depth_cap_raw.min(32)).expect("depth cap fits usize"))
                };
                let root_out = vm.register(13);
                let (proof, root) = vm.memory.merkle_compact(addr, depth_cap)?;
                let depth = proof.depth() as usize;
                vm.memory.store_bytes(dest, &[proof.depth()])?;
                vm.memory
                    .store_bytes(dest + 1, &proof.dirs().to_le_bytes())?;
                let count = depth as u32;
                vm.memory.store_bytes(dest + 1 + 4, &count.to_le_bytes())?;
                let mut off = dest + 1 + 4 + 4;
                for sibling in proof.siblings() {
                    let bytes = sibling.map(|hash| *hash.as_ref()).unwrap_or([0u8; 32]);
                    vm.memory.store_bytes(off, &bytes)?;
                    off += 32;
                }
                if root_out != 0 {
                    vm.memory.store_bytes(root_out, root.as_ref())?;
                }
                vm.set_register(10, depth as u64);
                Ok(Self::merkle_path_gas(depth))
            }
            crate::syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT => {
                let idx_raw = vm.register(10);
                let idx = usize::try_from(idx_raw).map_err(|_| VMError::RegisterOutOfBounds)?;
                if idx >= crate::parallel::REGISTER_COUNT {
                    return Err(VMError::RegisterOutOfBounds);
                }
                let dest = vm.register(11);
                let depth_cap_raw = vm.register(12);
                let depth_cap = if depth_cap_raw == 0 {
                    None
                } else {
                    Some(usize::try_from(depth_cap_raw.min(32)).expect("depth cap fits usize"))
                };
                let root_out = vm.register(13);
                let (proof, root) = vm.registers.merkle_compact(idx, depth_cap)?;
                let depth = proof.depth() as usize;
                vm.memory.store_bytes(dest, &[proof.depth()])?;
                vm.memory
                    .store_bytes(dest + 1, &proof.dirs().to_le_bytes())?;
                let count = depth as u32;
                vm.memory.store_bytes(dest + 1 + 4, &count.to_le_bytes())?;
                let mut off = dest + 1 + 4 + 4;
                for sibling in proof.siblings() {
                    let bytes = sibling.map(|hash| *hash.as_ref()).unwrap_or([0u8; 32]);
                    vm.memory.store_bytes(off, &bytes)?;
                    off += 32;
                }
                if root_out != 0 {
                    vm.memory.store_bytes(root_out, root.as_ref())?;
                }
                vm.set_register(10, depth as u64);
                Ok(Self::merkle_path_gas(depth))
            }
            // --- ZK verify/state-read helpers ---
            crate::syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT
            | crate::syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let payload_len = tlv.payload.len();
                if u64::try_from(payload_len).unwrap_or(u64::MAX)
                    > self.zk_gas_schedule.max_payload_bytes
                {
                    return Err(VMError::NoritoInvalid);
                }
                let conservative = self.zk_gas_schedule.conservative_single_gas(payload_len);
                preflight_reserved_syscall_gas(vm, conservative)?;
                if payload_len > self.zk_cfg.max_envelope_bytes {
                    vm.set_register(10, 0);
                    vm.set_register(11, ERR_ENVELOPE_SIZE);
                    return Ok(conservative);
                }
                self.zk_execution_counters.canonical_decodes = self
                    .zk_execution_counters
                    .canonical_decodes
                    .saturating_add(1);
                let envelope = match decode_canonical_zk_envelope(tlv.payload) {
                    Ok(envelope) => envelope,
                    Err(status) => {
                        vm.set_register(10, 0);
                        vm.set_register(11, status);
                        return Ok(conservative);
                    }
                };
                let actual = self
                    .zk_gas_schedule
                    .actual_single_gas(payload_len, envelope.public_inputs.len());
                preflight_reserved_syscall_gas(vm, actual)?;
                let status = self.validate_zk_open_envelope(&envelope).err();
                vm.set_register(10, u64::from(status.is_none()));
                vm.set_register(11, status.unwrap_or(0));
                Ok(actual)
            }
            crate::syscalls::SYSCALL_ZK_ROOTS_GET | crate::syscalls::SYSCALL_ZK_VOTE_GET_TALLY => {
                // Expect a NoritoBytes TLV pointer in r10 (request). DefaultHost has
                // no ledger state, so it writes an empty deterministic response into
                // INPUT and returns a pointer.
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let input_len = tlv.payload.len();
                if number == crate::syscalls::SYSCALL_ZK_ROOTS_GET {
                    // Decode request
                    let _req: crate::zk_verify::RootsGetRequest =
                        decode_canonical_norito(tlv.payload)?;
                    // DefaultHost response (empty roots)
                    let resp = crate::zk_verify::RootsGetResponse {
                        latest: [0u8; 32],
                        roots: Vec::new(),
                        height: 0,
                    };
                    let body = encode_canonical_norito(&resp)?;
                    // Build a host-owned TLV and return its public pointer.
                    let mut out = Vec::with_capacity(7 + body.len() + 32);
                    out.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
                    out.push(1);
                    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                    out.extend_from_slice(&body);
                    let h: [u8; 32] = iroha_crypto::Hash::new(&body).into();
                    out.extend_from_slice(&h);
                    let p = vm.alloc_host_tlv(&out)?;
                    vm.set_register(10, p);
                    Ok(Self::state_query_gas(input_len.saturating_add(body.len())))
                } else {
                    // Vote tally read
                    let req: crate::zk_verify::VoteGetTallyRequest =
                        decode_canonical_norito(tlv.payload)?;
                    if !req.is_valid_v1() {
                        return Err(VMError::NoritoInvalid);
                    }
                    let resp = crate::zk_verify::VoteGetTallyResponse {
                        finalized: false,
                        tally: Vec::new(),
                    };
                    let body = encode_canonical_norito(&resp)?;
                    let mut out = Vec::with_capacity(7 + body.len() + 32);
                    out.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
                    out.push(1);
                    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                    out.extend_from_slice(&body);
                    let h: [u8; 32] = iroha_crypto::Hash::new(&body).into();
                    out.extend_from_slice(&h);
                    let p = vm.alloc_host_tlv(&out)?;
                    vm.set_register(10, p);
                    Ok(Self::state_query_gas(input_len.saturating_add(body.len())))
                }
            }
            crate::syscalls::SYSCALL_ZK_VERIFY_BATCH => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                if u64::try_from(tlv.payload.len()).unwrap_or(u64::MAX)
                    > self.zk_gas_schedule.max_payload_bytes
                {
                    return Err(VMError::NoritoInvalid);
                }
                let quote = quote_zk_batch_at(vm, ptr, self.zk_gas_schedule)?;
                preflight_reserved_syscall_gas(vm, quote.gas)?;
                let max_items = usize::try_from(self.zk_cfg.max_verify_batch)
                    .unwrap_or(usize::MAX)
                    .min(
                        usize::try_from(self.zk_gas_schedule.max_batch_proofs)
                            .unwrap_or(usize::MAX),
                    );
                self.zk_execution_counters.canonical_decodes = self
                    .zk_execution_counters
                    .canonical_decodes
                    .saturating_add(1);
                let envelopes = match decode_canonical_zk_batch(tlv.payload, max_items) {
                    Ok(envelopes) => envelopes,
                    Err(status) => {
                        vm.set_register(10, 0);
                        vm.set_register(11, status);
                        vm.set_register(12, u64::MAX);
                        return Ok(quote.gas);
                    }
                };
                let public_input_count = envelopes.iter().fold(0_u64, |total, envelope| {
                    total.saturating_add(
                        self.zk_gas_schedule
                            .public_input_count(envelope.public_inputs.len()),
                    )
                });
                let actual = self.zk_gas_schedule.actual_batch_gas(
                    envelopes.len(),
                    tlv.payload.len(),
                    public_input_count,
                );
                preflight_reserved_syscall_gas(vm, actual)?;
                let mut first_error = None;
                let mut first_error_index = u64::MAX;
                for (index, envelope) in envelopes.iter().enumerate() {
                    if let Err(status) = self.validate_zk_open_envelope(envelope)
                        && first_error.is_none()
                    {
                        first_error = Some(status);
                        first_error_index = u64::try_from(index).unwrap_or(u64::MAX);
                    }
                }
                // ABI V1 status bytes are boolean (`1 = verified`, `0 = not
                // verified`). DefaultHost has no verifier backend, so every
                // canonical item fails closed and the first failure is index 0.
                let statuses = vec![0_u8; envelopes.len()];
                let body = encode_canonical_norito(&statuses)
                    .map_err(|_| VMError::metered(actual, VMError::NoritoInvalid))?;
                let encoded_output_bytes = TLV_ENVELOPE_OVERHEAD.saturating_add(body.len());
                if u64::try_from(encoded_output_bytes).unwrap_or(u64::MAX)
                    != self.zk_gas_schedule.batch_output_bytes(envelopes.len())
                {
                    return Err(VMError::metered(actual, VMError::NoritoInvalid));
                }
                let output = Self::alloc_norito_bytes_tlv(vm, &body)?;
                self.zk_execution_counters.response_allocations = self
                    .zk_execution_counters
                    .response_allocations
                    .saturating_add(1);
                vm.set_register(10, output);
                vm.set_register(11, first_error.unwrap_or(ERR_BACKEND));
                vm.set_register(
                    12,
                    if first_error.is_some() {
                        first_error_index
                    } else {
                        0
                    },
                );
                Ok(actual)
            }
            syscalls::SYSCALL_AXT_BEGIN => self.handle_axt_begin(vm),
            syscalls::SYSCALL_AXT_TOUCH => self.handle_axt_touch(vm),
            syscalls::SYSCALL_AXT_COMMIT => self.handle_axt_commit(vm),
            syscalls::SYSCALL_VERIFY_DS_PROOF => self.handle_axt_verify_ds_proof(vm),
            syscalls::SYSCALL_AXT_STAGE_ANCHORED_SPEND => Err(VMError::PermissionDenied),
            _ => Err(Self::unsupported_syscall_error(number)),
        }
    }
    /// Downcast support for hosts with extra methods/state.
    fn as_any(&mut self) -> &mut dyn Any
    where
        Self: 'static,
    {
        self
    }
    fn begin_tx(&mut self, _declared: &StateAccessSet) -> Result<(), VMError> {
        self.access_log.read_keys.clear();
        self.access_log.write_keys.clear();
        self.access_log.reg_tags.clear();
        self.access_log.state_writes.clear();
        Ok(())
    }
    fn finish_tx(&mut self) -> Result<AccessLog, VMError> {
        Ok(self.access_log.clone())
    }
    fn checkpoint(&self) -> Option<Box<dyn Any + Send>> {
        Some(Box::new(self.clone()))
    }
    fn restore(&mut self, snapshot: &dyn Any) -> Result<(), VMError> {
        if let Some(saved) = snapshot.downcast_ref::<DefaultHost>() {
            *self = saved.clone();
            Ok(())
        } else {
            Err(VMError::HostUnavailable)
        }
    }
    fn access_logging_supported(&self) -> bool {
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProgramMetadata;
    use crate::pointer_abi::PointerType;
    use iroha_data_model::privacy::PrivacyProtocolIdV1;
    use iroha_data_model::zk::BackendTag;
    use iroha_model_base::name::MAX_NAME_BYTES;
    #[test]
    fn persisted_state_validation_requires_exact_schema_and_canonical_record() {
        use ivm_abi::state_value::{
            StateValueAtomV1, StateValueRecordV1, state_value_schema_for_embedded_type_v1,
            state_value_schema_hash_v1,
        };
        let ty = crate::metadata::EmbeddedStateType::Bool;
        let schema = state_value_schema_for_embedded_type_v1(&ty).unwrap();
        let record = StateValueRecordV1 {
            schema_hash: state_value_schema_hash_v1(
                &crate::codec::encode_canonical_norito(&schema).unwrap(),
            ),
            atoms: vec![StateValueAtomV1::Bool(true)],
        };
        let encoded = crate::codec::encode_canonical_norito(&record).unwrap();
        assert!(validate_persisted_state_value_payload(&ty, &encoded).is_ok());
        assert!(
            validate_persisted_state_value_payload(
                &crate::metadata::EmbeddedStateType::Unit,
                &encoded
            )
            .is_err()
        );
        assert!(validate_persisted_state_value_payload(&ty, b"true").is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(validate_persisted_state_value_payload(&ty, &trailing).is_err());
    }
    fn test_tlv(kind: PointerType, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
        out.extend_from_slice(&(kind as u16).to_be_bytes());
        out.push(1);
        out.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("test payload length")
                .to_be_bytes(),
        );
        out.extend_from_slice(payload);
        let hash: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new(payload).into();
        out.extend_from_slice(&hash);
        out
    }
    #[test]
    fn encoded_private_input_transport_rejects_unbounded_state_before_retention() {
        let too_many = vec![Vec::new(); MAX_PRIVATE_INPUTS_V1 + 1];
        assert!(matches!(
            DefaultHost::with_encoded_private_inputs(too_many),
            Err(VMError::NoritoInvalid)
        ));
        let too_large = vec![vec![0_u8; MAX_PRIVATE_INPUT_RECORD_BYTES_V1 + 1]];
        assert!(matches!(
            DefaultHost::with_encoded_private_inputs(too_large),
            Err(VMError::NoritoInvalid)
        ));
        let bounded_but_malformed = vec![vec![0xA5; MAX_PRIVATE_INPUT_RECORD_BYTES_V1]];
        let host = DefaultHost::with_encoded_private_inputs(bounded_but_malformed)
            .expect("bounded bytes are decoded only after runtime metering");
        assert_eq!(host.private_inputs.len(), 1);
        assert_eq!(
            host.private_inputs[0].len(),
            MAX_PRIVATE_INPUT_RECORD_BYTES_V1
        );
    }
    #[test]
    fn unchecked_private_input_injector_is_test_only() {
        let oversized = vec![vec![0_u8; MAX_PRIVATE_INPUT_RECORD_BYTES_V1 + 1]];
        let host = DefaultHost::with_encoded_private_inputs_unchecked(oversized);
        assert_eq!(
            host.private_inputs[0].len(),
            MAX_PRIVATE_INPUT_RECORD_BYTES_V1 + 1
        );
    }
    #[test]
    fn default_host_rejects_noncanonical_axt_policy_snapshot_without_panicking() {
        let snapshot = AxtPolicySnapshot {
            version: 1,
            entries: Vec::new(),
        };
        assert!(matches!(
            DefaultHost::new().with_axt_policy_from_snapshot(&snapshot),
            Err(AxtPolicySnapshotValidationError::VersionMismatch {
                expected: 0,
                actual: 1,
            })
        ));
    }
    fn dummy_zk_batch_envelope() -> OpenVerifyEnvelope {
        OpenVerifyEnvelope::new(
            BackendTag::NativePipaRPasta,
            "test-circuit-v1",
            [0x11; 32],
            vec![0x22; 64],
            vec![0x33; 96],
        )
    }
    fn test_network_id(marker: u8) -> iroha_data_model::NetworkId {
        iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([marker; iroha_crypto::Hash::LENGTH]),
        ))
    }
    fn valid_vrf_request(
        network_id: iroha_data_model::NetworkId,
        input: &[u8],
    ) -> crate::vrf::VrfVerifyRequest {
        use blstrs::{G1Projective, G2Projective, Scalar};
        use group::{Curve as _, Group as _};
        let secret = Scalar::from(7_u64);
        let public_key = (G1Projective::generator() * secret)
            .to_affine()
            .to_compressed();
        let network_bytes = network_id.as_bytes();
        let mut preimage = Vec::with_capacity(
            b"iroha:vrf:v1:input|".len() + network_bytes.len() + 1 + input.len(),
        );
        preimage.extend_from_slice(b"iroha:vrf:v1:input|");
        preimage.extend_from_slice(network_bytes);
        preimage.push(b'|');
        preimage.extend_from_slice(input);
        let message: [u8; 32] = iroha_crypto::Hash::new(&preimage).into();
        const DST: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1";
        let proof = (G2Projective::hash_to_curve(&message, DST, &[]) * secret)
            .to_affine()
            .to_compressed();
        crate::vrf::VrfVerifyRequest {
            variant: 1,
            pk: public_key.to_vec(),
            proof: proof.to_vec(),
            network_id,
            input: input.to_vec(),
        }
    }
    fn run_vm_dispatched_vrf_batch(payload: &[u8]) -> (IVM, DefaultHost, u64) {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let scall = crate::encoding::wide::encode_sys(
            crate::instruction::wide::system::SCALL,
            u8::try_from(syscalls::SYSCALL_VRF_VERIFY_BATCH).expect("syscall fits"),
        );
        let mut code = Vec::new();
        code.extend_from_slice(&scall.to_le_bytes());
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_code(&code).expect("load VRF batch test program");
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, payload))
            .expect("allocate VRF batch");
        vm.set_register(10, pointer);
        vm.set_register(11, u64::MAX);
        vm.set_register(12, u64::MAX);
        let mut host = DefaultHost::new().with_network_id(test_network_id(0x71));
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_VRF_VERIFY_BATCH, &vm)
            .expect("quote VRF batch without decoding");
        let instruction_gas = gas::cost_of(scall).expect("SCALL is scheduled");
        vm.set_gas_limit(instruction_gas.saturating_add(quote));
        vm.run_with_host(&mut host)
            .expect("VRF status paths do not trap");
        (vm, host, quote)
    }
    fn run_vm_dispatched_zk_batch(payload: &[u8]) -> (IVM, DefaultHost, u64) {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let scall = crate::encoding::wide::encode_sys(
            crate::instruction::wide::system::SCALL,
            u8::try_from(syscalls::SYSCALL_ZK_VERIFY_BATCH).expect("syscall fits"),
        );
        let mut code = Vec::new();
        code.extend_from_slice(&scall.to_le_bytes());
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_code(&code).expect("load ZK batch test program");
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, payload))
            .expect("allocate ZK batch");
        vm.set_register(10, pointer);
        vm.set_register(11, u64::MAX);
        vm.set_register(12, u64::MAX);
        let mut host = DefaultHost::new();
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &vm)
            .expect("quote ZK batch without decoding");
        let instruction_gas = gas::cost_of(scall).expect("SCALL is scheduled");
        vm.set_gas_limit(instruction_gas.saturating_add(quote));
        vm.run_with_host(&mut host)
            .expect("ZK status paths do not trap");
        (vm, host, quote)
    }
    #[test]
    fn downcast_default_host() {
        let mut host: Box<dyn IVMHost + Send + Sync> = Box::new(DefaultHost::new());
        assert!(host.as_any().downcast_mut::<DefaultHost>().is_some());
    }
    #[test]
    fn default_host_public_input_result_spills_to_owned_heap() {
        let mut vm = IVM::new(u64::MAX);
        vm.alloc_input_tlv(&vec![0; Memory::INPUT_SIZE as usize])
            .expect("fill INPUT exactly");
        let name: Name = "payload".parse().expect("public input name");
        let name_payload = norito::to_bytes(&name).expect("encode public input name");
        let name_pointer = vm
            .alloc_host_tlv(&test_tlv(PointerType::Name, &name_payload))
            .expect("spill public input name to HEAP");
        let expected = test_tlv(PointerType::Blob, b"heap-backed-public-input");
        let mut inputs = BTreeMap::new();
        inputs.insert(name, expected);
        let mut host = DefaultHost::new().with_public_inputs(inputs);
        vm.set_register(10, name_pointer);
        host.syscall(syscalls::SYSCALL_GET_PUBLIC_INPUT, &mut vm)
            .expect("materialize public input after INPUT exhaustion");
        let output_pointer = vm.register(10);
        assert!((Memory::HEAP_START..Memory::INPUT_START).contains(&output_pointer));
        let output = vm
            .validate_tlv(output_pointer)
            .expect("validate HEAP result");
        assert_eq!(output.type_id, PointerType::Blob);
        assert_eq!(output.payload, b"heap-backed-public-input");
    }
    #[test]
    fn default_host_large_public_input_dispatch_stays_within_reserved_quote() {
        let name: Name = "large_payload".parse().expect("public input name");
        let payload = vec![0x6b; (Memory::INPUT_SIZE as usize) * 2];
        let expected = test_tlv(PointerType::Blob, &payload);
        let mut inputs = BTreeMap::new();
        inputs.insert(name.clone(), expected);
        let mut host = DefaultHost::new().with_public_inputs(inputs);
        let mut vm = IVM::new(1_000_000);
        let code = [
            crate::encoding::wide::encode_sys(
                crate::instruction::wide::system::SCALL,
                u8::try_from(syscalls::SYSCALL_GET_PUBLIC_INPUT).expect("syscall fits"),
            )
            .to_le_bytes(),
            crate::encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat();
        vm.load_code(&code).expect("load public-input program");
        let name_payload = norito::to_bytes(&name).expect("encode public input name");
        let name_pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::Name, &name_payload))
            .expect("allocate input name");
        vm.set_register(10, name_pointer);
        vm.run_with_host(&mut host)
            .expect("dispatcher must reconcile the heap-sized result quote");
        let output_pointer = vm.register(10);
        assert!((Memory::HEAP_START..Memory::INPUT_START).contains(&output_pointer));
        let output = vm
            .validate_tlv(output_pointer)
            .expect("validate heap-backed public input");
        assert_eq!(output.type_id, PointerType::Blob);
        assert_eq!(output.payload, payload);
    }
    #[test]
    fn nested_call_rollback_restores_committed_output() {
        let mut host = DefaultHost::new();
        host.pub_output = vec![1, 2, 3];
        let checkpoint = host.begin_forwarded_call();
        host.pub_output = vec![9; 1024];
        assert!(host.rollback_forwarded_call(checkpoint));
        assert_eq!(host.pub_output, [1, 2, 3]);
    }
    #[test]
    fn conservative_quote_ignores_registers_outside_the_syscall_signature() {
        let mut vm = IVM::new(u64::MAX);
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, &[0x5A; 256]))
            .expect("allocate quote fixture");
        let syscall = syscalls::SYSCALL_REGISTER_DOMAIN;
        let baseline = conservative_syscall_gas_quote(syscall, &vm);
        vm.set_register(15, pointer);
        vm.registers.set_tag(15, true);
        assert_eq!(
            conservative_syscall_gas_quote(syscall, &vm),
            baseline,
            "an unrelated secret register must not influence public gas"
        );
        vm.set_register(10, pointer);
        assert!(
            conservative_syscall_gas_quote(syscall, &vm) > baseline,
            "the documented r10 argument must remain part of the quote"
        );
    }
    fn maximum_bounded_state_map_fixture(fill: u8) -> (Name, Vec<u8>) {
        let base: Name = "b"
            .repeat(syscalls::STATE_MAP_MAX_BASE_BYTES)
            .parse()
            .expect("maximum map base");
        let key = vec![fill; syscalls::STATE_MAP_MAX_KEY_BYTES];
        let path = canonical_state_map_path(&base, &key).expect("maximum bounded map path");
        assert_eq!(
            path.as_ref().len(),
            syscalls::STATE_MAP_MAX_BASE_BYTES + 1 + 2 * syscalls::STATE_MAP_MAX_KEY_BYTES
        );
        assert_eq!(
            state_path_payload_len(&path).expect("framed path length"),
            norito::to_bytes(&path).expect("encode maximum path").len()
        );
        (base, key)
    }
    #[test]
    fn maximum_state_map_base_and_key_fit_final_framed_path() {
        let (base, key) = maximum_bounded_state_map_fixture(0xa5);
        let base_len = state_path_name_payload_len(&base).expect("base length");
        assert!(base_len <= syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES);
        let path = canonical_state_map_path(&base, &key).expect("maximum canonical map path");
        let path_len = state_path_payload_len(&path).expect("path length");
        assert!(path_len <= syscalls::STATE_MAX_PATH_FRAME_BYTES);
        let (_, output_bound) =
            quote_canonical_state_map_path_lengths(base_len, key.len()).expect("header quote");
        assert!(output_bound >= path_len);
        let (_, configured_output_bound) = quote_canonical_state_map_path_lengths(
            syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES,
            syscalls::STATE_MAP_MAX_KEY_BYTES,
        )
        .expect("configured maximum header lengths");
        assert!(configured_output_bound <= syscalls::STATE_MAX_PATH_FRAME_BYTES);
        assert_eq!(
            canonical_state_map_path(&base, &[0u8; syscalls::STATE_MAP_MAX_KEY_BYTES + 1]),
            Err(VMError::NoritoInvalid)
        );
        assert_eq!(
            quote_canonical_state_map_path_lengths(syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES + 1, 1),
            Err(VMError::NoritoInvalid)
        );
        assert!("b".repeat(MAX_NAME_BYTES + 1).parse::<Name>().is_err());
        assert!(
            "p".repeat(syscalls::STATE_MAX_PATH_BYTES + 1)
                .parse::<StatePath>()
                .is_err()
        );
    }
    #[test]
    fn state_scan_page_bound_covers_admissible_pages_and_rejects_item_overflow() {
        let maximum_items = usize::try_from(syscalls::STATE_SCAN_MAX_ITEMS_V1)
            .expect("the V1 state-key page limit must fit usize");
        for count in [0_usize, 1, maximum_items] {
            let keys: Vec<StatePath> = (0..count)
                .map(|index| {
                    let prefix = format!("k{index:02}/");
                    format!("{prefix}{}", "a".repeat(8 * 1024 - prefix.len()))
                        .parse()
                        .expect("bounded page path")
                })
                .collect();
            let encoded = norito::to_bytes(&keys).expect("encode bounded state-key page");
            let elements = keys
                .iter()
                .map(|key| {
                    state_key_encoded_len_from_text(key.as_ref()).expect("encoded key length")
                })
                .sum();
            let quote =
                state_scan_page_payload_bound_from_parts(count, elements).expect("bounded page");
            assert!(
                quote >= encoded.len(),
                "page bound underquoted {count} large state paths"
            );
            assert!(encoded.len() <= syscalls::STATE_MAP_MAX_PAGE_BYTES);
        }
        assert_eq!(
            state_scan_page_payload_bound_from_parts(maximum_items + 1, 0),
            Err(VMError::NoritoInvalid)
        );
    }
    #[test]
    fn state_path_and_page_bounds_ignore_ambient_layout() {
        let path: StatePath = "state/ambient_layout_probe"
            .parse()
            .expect("valid state path");
        let canonical_name = encode_canonical_norito(&path).expect("encode canonical state path");
        let canonical_path_len =
            state_path_payload_len(&path).expect("canonical state path length");
        let canonical_tail = state_scan_response_tail_after_item(0, 0, path.as_ref())
            .expect("canonical state-key page tail");
        assert_eq!(canonical_path_len, canonical_name.len());
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let alternate_name = norito::to_bytes(&path).expect("encode alternate-layout state path");
        assert_ne!(
            alternate_name, canonical_name,
            "fixture must distinguish the ambient layout from canonical V1"
        );
        assert_eq!(
            state_path_payload_len(&path),
            Ok(canonical_path_len),
            "path admission and gas must use canonical V1 lengths"
        );
        assert_eq!(
            state_scan_response_tail_after_item(0, 0, path.as_ref()),
            Ok(canonical_tail),
            "page selection and response bounds must use canonical V1 lengths"
        );
    }
    #[test]
    fn maximum_state_map_page_is_accepted_by_key_decoder() {
        let (base, maximum_key) = maximum_bounded_state_map_fixture(0xa5);
        let mut expected_last = Vec::new();
        let mut paths = Vec::new();
        for index in 0..syscalls::STATE_SCAN_MAX_ITEMS_V1 {
            let mut key = maximum_key.clone();
            let last = key.len() - 1;
            key[last] = u8::try_from(index).expect("bounded index");
            if index + 1 == syscalls::STATE_SCAN_MAX_ITEMS_V1 {
                expected_last = key.clone();
            }
            paths.push(canonical_state_map_path(&base, &key).expect("bounded map path"));
        }
        let page = norito::to_bytes(&paths).expect("encode maximum map page");
        assert!(page.len() <= syscalls::STATE_MAP_MAX_PAGE_BYTES);
        let elements = paths
            .iter()
            .map(|key| state_key_encoded_len_from_text(key.as_ref()).expect("encoded key length"))
            .sum();
        state_scan_page_payload_bound_from_parts(paths.len(), elements)
            .expect("quote maximum map page");
        assert_eq!(
            canonical_state_map_key_at(
                &page,
                &base,
                syscalls::STATE_SCAN_MAX_ITEMS_V1.saturating_sub(1),
            )
            .expect("decode last key"),
            Some(expected_last)
        );
    }
    #[test]
    fn state_map_key_decoder_rejects_pages_not_produced_by_ordered_base_scan() {
        let base: Name = "orders".parse().expect("map base");
        let other: Name = "payments".parse().expect("foreign map base");
        let first = canonical_state_map_path(&base, &[0x01]).expect("first map path");
        let second = canonical_state_map_path(&base, &[0x02]).expect("second map path");
        let foreign = canonical_state_map_path(&other, &[0x03]).expect("foreign map path");
        for paths in [
            vec![second.clone(), first.clone()],
            vec![first.clone(), first.clone()],
            vec![first.clone(), foreign],
        ] {
            let page = encode_canonical_norito(&paths).expect("encode adversarial page");
            assert_eq!(
                canonical_state_map_key_at(&page, &base, u64::MAX),
                Err(VMError::NoritoInvalid),
                "the complete page must be validated even when the index is out of range"
            );
        }
    }
    #[test]
    fn state_map_key_decoder_rejects_oversized_sequence_during_bounded_decode() {
        let base: Name = "orders".parse().expect("map base");
        let paths = (0..=syscalls::STATE_SCAN_MAX_ITEMS_V1)
            .map(|index| {
                canonical_state_map_path(&base, &index.to_le_bytes())
                    .expect("canonical bounded map path")
            })
            .collect::<Vec<_>>();
        let page = encode_canonical_norito(&paths).expect("encode oversized map page");
        assert_eq!(
            canonical_state_map_key_at(&page, &base, 0),
            Err(VMError::DecodeError),
            "the top-level sequence limit must reject before Vec<StatePath> materialization"
        );
    }
    #[test]
    fn debug_log_quote_and_execution_charge_payload_bytes() {
        let mut vm = IVM::new(u64::MAX);
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, &[b'x'; 256]))
            .expect("allocate debug log fixture");
        vm.set_register(10, pointer);
        let mut host = DefaultHost::new();
        let quoted = host
            .prepare_syscall(syscalls::SYSCALL_DEBUG_LOG, &vm)
            .expect("quote debug log");
        let actual = host
            .syscall(syscalls::SYSCALL_DEBUG_LOG, &mut vm)
            .expect("execute debug log");
        assert_eq!(quoted, actual);
        assert_eq!(actual, debug_log_gas(256));
    }
    #[test]
    fn default_host_accepts_only_the_canonical_envelope_schema() {
        let host = DefaultHost::new();
        let envelope = dummy_zk_batch_envelope();
        assert_eq!(host.validate_zk_open_envelope(&envelope), Err(ERR_BACKEND));
        let legacy = norito::to_bytes(&42_u64).expect("encode non-envelope archive");
        assert_eq!(decode_canonical_zk_envelope(&legacy), Err(ERR_DECODE));
        let canonical =
            encode_canonical_norito(&envelope).expect("encode canonical data-model envelope");
        assert!(decode_canonical_zk_envelope(&canonical).is_ok());
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&envelope).expect("encode alternate-layout data-model envelope")
        };
        assert_ne!(alternate, canonical);
        assert!(
            norito::decode_from_bytes::<OpenVerifyEnvelope>(&alternate).is_ok(),
            "ordinary Norito decoding must accept the advertised alternate layout"
        );
        assert_eq!(decode_canonical_zk_envelope(&alternate), Err(ERR_DECODE));
    }
    #[test]
    fn default_host_rejects_every_reserved_privacy_circuit_label_before_dispatch() {
        let host = DefaultHost::new();
        for label in PrivacyProtocolIdV1::ALL.map(PrivacyProtocolIdV1::canonical_label) {
            for circuit_id in [
                label.to_owned(),
                format!("halo2/ipa::{label}"),
                format!("generic/namespace/{label}"),
            ] {
                let mut envelope = dummy_zk_batch_envelope();
                envelope.circuit_id = circuit_id.clone();
                assert_eq!(
                    host.validate_zk_open_envelope(&envelope),
                    Err(ERR_DECODE),
                    "reserved circuit id {circuit_id:?}"
                );
            }
            for near_miss in [format!("generic-{label}"), format!("{label}-generic")] {
                let mut envelope = dummy_zk_batch_envelope();
                envelope.circuit_id = near_miss.clone();
                assert_eq!(
                    host.validate_zk_open_envelope(&envelope),
                    Err(ERR_BACKEND),
                    "portable near miss {near_miss:?} must pass shape validation"
                );
            }
        }
    }
    #[test]
    fn time_syscalls_use_configured_deterministic_value() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        assert_eq!(
            host.syscall(syscalls::SYSCALL_CURRENT_TIME_MS, &mut vm),
            Ok(DefaultHost::sysvar_gas(0))
        );
        assert_eq!(vm.register(10), 0);
        host.set_current_time_ms(42);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS, &mut vm),
            Ok(DefaultHost::sysvar_gas(0))
        );
        assert_eq!(vm.register(10), 42);
    }
    #[test]
    fn block_height_syscall_uses_configured_deterministic_value() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        assert_eq!(
            host.syscall(syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT, &mut vm),
            Ok(DefaultHost::sysvar_gas(0))
        );
        assert_eq!(vm.register(10), 0);
        host.set_current_block_height(77);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT, &mut vm),
            Ok(DefaultHost::sysvar_gas(0))
        );
        assert_eq!(vm.register(10), 77);
    }
    #[test]
    fn chain_id_sysvar_charges_returned_bytes() {
        crate::set_banner_enabled(false);
        let chain_id = b"chain-A".to_vec();
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new().with_chain_id(chain_id.clone());
        assert_eq!(
            host.syscall(syscalls::SYSCALL_SYSVAR_CHAIN_ID, &mut vm),
            Ok(DefaultHost::sysvar_gas(chain_id.len()))
        );
        let tlv = vm.validate_tlv(vm.register(10)).expect("chain tlv");
        assert_eq!(tlv.type_id, PointerType::Blob);
        assert_eq!(tlv.payload, chain_id.as_slice());
    }
    #[test]
    fn default_host_vrf_verify_status_paths_charge_bytes_and_examined_items() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let network_id = test_network_id(0x71);
        let mut host = DefaultHost::new().with_network_id(network_id);
        let wrong_type_payload = b"{\"not\":\"vrf\"}";
        let wrong_type_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, wrong_type_payload))
            .expect("alloc wrong type");
        vm.set_register(10, wrong_type_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_VRF_VERIFY, &mut vm),
            Ok(DefaultHost::vrf_verify_gas(0, wrong_type_payload.len()))
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 1);
        let malformed = [0xff];
        let malformed_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &malformed))
            .expect("alloc malformed request");
        vm.set_register(10, malformed_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_VRF_VERIFY, &mut vm),
            Ok(DefaultHost::vrf_verify_gas(0, malformed.len()))
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 2);
        let bad_pk = crate::vrf::VrfVerifyRequest {
            variant: 1,
            pk: vec![1],
            proof: vec![2; 96],
            network_id,
            input: b"message".to_vec(),
        };
        let body = norito::to_bytes(&bad_pk).expect("encode vrf request");
        let bad_pk_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &body))
            .expect("alloc bad pk request");
        vm.set_register(10, bad_pk_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_VRF_VERIFY, &mut vm),
            Ok(DefaultHost::vrf_verify_gas(1, body.len()))
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 4);
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters {
                canonical_decodes: 2,
                backend_invocations: 0,
                response_allocations: 0,
            }
        );
    }
    #[test]
    fn default_host_vrf_batch_empty_request_is_rejected_without_output() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let request = crate::vrf::VrfVerifyBatchRequest { items: Vec::new() };
        let body = encode_canonical_norito(&request).expect("encode canonical VRF batch request");
        let ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &body))
            .expect("alloc batch request");
        let ambient_probe = vec!["first".to_owned(), "second".to_owned()];
        let canonical_probe =
            encode_canonical_norito(&ambient_probe).expect("encode canonical ambient probe");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_before =
            norito::to_bytes(&ambient_probe).expect("encode alternate-layout ambient probe");
        assert_ne!(ambient_before, canonical_probe);
        vm.set_register(10, ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_VRF_VERIFY_BATCH, &mut vm),
            Ok(DefaultHost::vrf_verify_gas(0, body.len()))
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 9);
        assert_eq!(vm.register(12), u64::MAX);
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters {
                canonical_decodes: 1,
                backend_invocations: 0,
                response_allocations: 0,
            }
        );
        assert_eq!(
            norito::to_bytes(&ambient_probe).expect("encode ambient probe after syscall"),
            ambient_before,
            "host canonical decode and encode must restore the ambient layout"
        );
    }
    #[test]
    fn default_host_vrf_verification_rejects_absent_host_network_context() {
        crate::set_banner_enabled(false);
        let request = crate::vrf::VrfVerifyRequest {
            variant: 1,
            pk: vec![1; 48],
            proof: vec![2; 96],
            network_id: test_network_id(0x72),
            input: b"message".to_vec(),
        };
        let body = encode_canonical_norito(&request).expect("encode canonical VRF request");
        let mut vm = IVM::new(u64::MAX);
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &body))
            .expect("allocate VRF request");
        vm.set_register(10, pointer);
        let mut host = DefaultHost::new();
        assert_eq!(
            host.syscall(syscalls::SYSCALL_VRF_VERIFY, &mut vm),
            Ok(DefaultHost::vrf_verify_gas(1, body.len()))
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 8);
        let batch = crate::vrf::VrfVerifyBatchRequest {
            items: vec![request],
        };
        let batch_body =
            encode_canonical_norito(&batch).expect("encode canonical VRF batch request");
        let batch_pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &batch_body))
            .expect("allocate VRF batch request");
        vm.set_register(10, batch_pointer);
        vm.set_register(11, u64::MAX);
        vm.set_register(12, u64::MAX);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_VRF_VERIFY_BATCH, &mut vm),
            Ok(DefaultHost::vrf_verify_gas(1, batch_body.len()))
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 8);
        assert_eq!(vm.register(12), 0);
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters {
                canonical_decodes: 2,
                backend_invocations: 0,
                response_allocations: 0,
            }
        );
    }
    #[test]
    fn vm_dispatched_vrf_batch_count_boundaries_have_stable_refunds() {
        let invalid = crate::vrf::VrfVerifyRequest {
            variant: 0,
            pk: Vec::new(),
            proof: Vec::new(),
            network_id: test_network_id(0x71),
            input: Vec::new(),
        };
        for count in [0_usize, crate::vrf::MAX_VRF_VERIFY_BATCH_ITEMS_V1 + 1] {
            let payload = encode_canonical_norito(&crate::vrf::VrfVerifyBatchRequest {
                items: vec![invalid.clone(); count],
            })
            .expect("encode rejected VRF batch");
            let (vm, host, quote) = run_vm_dispatched_vrf_batch(&payload);
            assert_eq!(
                quote,
                DefaultHost::vrf_verify_gas(
                    crate::vrf::MAX_VRF_VERIFY_BATCH_ITEMS_V1,
                    payload.len()
                )
            );
            assert_eq!(vm.register(10), 0);
            assert_eq!(vm.register(11), 9);
            assert_eq!(vm.register(12), u64::MAX);
            assert_eq!(
                vm.remaining_gas(),
                quote - DefaultHost::vrf_verify_gas(0, payload.len())
            );
            assert_eq!(
                host.vrf_execution_counters(),
                VrfExecutionCounters {
                    canonical_decodes: 1,
                    backend_invocations: 0,
                    response_allocations: 0,
                }
            );
        }
        for count in [1_usize, crate::vrf::MAX_VRF_VERIFY_BATCH_ITEMS_V1] {
            let payload = encode_canonical_norito(&crate::vrf::VrfVerifyBatchRequest {
                items: vec![invalid.clone(); count],
            })
            .expect("encode admitted VRF batch");
            let (vm, host, quote) = run_vm_dispatched_vrf_batch(&payload);
            assert_eq!(vm.register(10), 0);
            assert_eq!(
                vm.register(11),
                3,
                "count {count} must pass batch admission"
            );
            assert_eq!(vm.register(12), 0);
            assert_eq!(
                vm.remaining_gas(),
                quote - DefaultHost::vrf_verify_gas(1, payload.len())
            );
            assert_eq!(
                host.vrf_execution_counters(),
                VrfExecutionCounters {
                    canonical_decodes: 1,
                    backend_invocations: 0,
                    response_allocations: 0,
                }
            );
        }
    }
    #[test]
    fn vm_dispatched_vrf_batch_rejects_alternate_layout_and_restores_ambient_flags() {
        let request = crate::vrf::VrfVerifyBatchRequest {
            items: vec![crate::vrf::VrfVerifyRequest {
                variant: 0,
                pk: Vec::new(),
                proof: Vec::new(),
                network_id: test_network_id(0x71),
                input: Vec::new(),
            }],
        };
        let canonical = encode_canonical_norito(&request).expect("encode canonical VRF batch");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&request).expect("encode alternate-layout VRF batch")
        };
        assert_ne!(alternate, canonical);
        assert!(
            norito::decode_from_bytes::<crate::vrf::VrfVerifyBatchRequest>(&alternate).is_ok(),
            "ordinary Norito must accept its advertised alternate layout"
        );
        let ambient_probe = vec!["first".to_owned(), "second".to_owned()];
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_before =
            norito::to_bytes(&ambient_probe).expect("encode ambient VRF layout probe");
        let (vm, host, quote) = run_vm_dispatched_vrf_batch(&alternate);
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 2);
        assert_eq!(vm.register(12), u64::MAX);
        assert_eq!(
            vm.remaining_gas(),
            quote - DefaultHost::vrf_verify_gas(0, alternate.len())
        );
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters {
                canonical_decodes: 1,
                backend_invocations: 0,
                response_allocations: 0,
            }
        );
        assert_eq!(
            norito::to_bytes(&ambient_probe).expect("encode ambient probe after VRF syscall"),
            ambient_before
        );
    }
    #[test]
    fn vm_dispatched_vrf_batch_rejects_forged_vector_length_before_backend_or_output() {
        const FORGED_LENGTH: u64 = 1 << 40;
        let request = crate::vrf::VrfVerifyBatchRequest { items: Vec::new() };
        let mut bare = Vec::new();
        {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::core::serialize_to_buffer(&request, &mut bare)
                .expect("encode bare canonical VRF batch");
        }
        assert!(
            bare.ends_with(&0_u64.to_le_bytes()),
            "empty batch must end in its zero sequence count"
        );
        let count_offset = bare.len() - core::mem::size_of::<u64>();
        bare[count_offset..].copy_from_slice(&FORGED_LENGTH.to_le_bytes());
        let forged =
            norito::core::frame_bare_with_header_flags::<crate::vrf::VrfVerifyBatchRequest>(
                &bare,
                norito::core::default_encode_flags(),
            )
            .expect("frame forged VRF batch with a valid checksum");
        let (vm, host, quote) = run_vm_dispatched_vrf_batch(&forged);
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 2);
        assert_eq!(vm.register(12), u64::MAX);
        assert_eq!(
            vm.remaining_gas(),
            quote - DefaultHost::vrf_verify_gas(0, forged.len())
        );
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters {
                canonical_decodes: 1,
                backend_invocations: 0,
                response_allocations: 0,
            }
        );
    }
    #[test]
    fn vm_dispatched_vrf_batch_refunds_unexamined_items() {
        let valid = valid_vrf_request(test_network_id(0x71), b"valid");
        let invalid = crate::vrf::VrfVerifyRequest {
            variant: 0,
            pk: Vec::new(),
            proof: Vec::new(),
            network_id: test_network_id(0x71),
            input: b"invalid".to_vec(),
        };
        let payload = encode_canonical_norito(&crate::vrf::VrfVerifyBatchRequest {
            items: vec![valid, invalid],
        })
        .expect("encode VRF batch with second-item failure");
        let (vm, host, quote) = run_vm_dispatched_vrf_batch(&payload);
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 3);
        assert_eq!(vm.register(12), 1);
        assert_eq!(
            vm.remaining_gas(),
            quote - DefaultHost::vrf_verify_gas(2, payload.len())
        );
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters {
                canonical_decodes: 1,
                backend_invocations: 1,
                response_allocations: 0,
            }
        );
    }
    #[test]
    fn vm_dispatched_vrf_batch_success_refunds_reserved_tail() {
        let payload = encode_canonical_norito(&crate::vrf::VrfVerifyBatchRequest {
            items: vec![valid_vrf_request(test_network_id(0x71), b"success")],
        })
        .expect("encode successful VRF batch");
        let (vm, host, quote) = run_vm_dispatched_vrf_batch(&payload);
        assert_eq!(vm.register(11), 0);
        assert_eq!(vm.register(12), u64::MAX);
        let output = vm.validate_tlv(vm.register(10)).expect("VRF output");
        assert_eq!(output.type_id, PointerType::NoritoBytes);
        assert_eq!(
            norito::decode_from_bytes::<Vec<[u8; 32]>>(output.payload)
                .expect("decode VRF outputs")
                .len(),
            1
        );
        assert_eq!(
            vm.remaining_gas(),
            quote - DefaultHost::vrf_verify_gas(1, payload.len())
        );
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters {
                canonical_decodes: 1,
                backend_invocations: 1,
                response_allocations: 1,
            }
        );
    }
    #[test]
    fn vrf_prepare_rejects_wrong_type_and_oversized_payload_without_decode() {
        let mut vm = IVM::new(u64::MAX);
        let wrong_type = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, b"wrong type"))
            .expect("allocate wrong-type VRF request");
        vm.set_register(10, wrong_type);
        let host = DefaultHost::new();
        assert_eq!(
            host.prepare_syscall(syscalls::SYSCALL_VRF_VERIFY_BATCH, &vm),
            Err(VMError::NoritoInvalid)
        );
        let oversized = vec![0_u8; crate::vrf::MAX_VRF_VERIFY_PAYLOAD_BYTES_V1 + 1];
        let envelope = test_tlv(PointerType::NoritoBytes, &oversized);
        let pointer = vm
            .alloc_heap(u64::try_from(envelope.len()).expect("oversized envelope length fits"))
            .expect("allocate oversized envelope");
        vm.store_bytes(pointer, &envelope)
            .expect("store oversized envelope");
        vm.set_register(10, pointer);
        assert_eq!(
            host.prepare_syscall(syscalls::SYSCALL_VRF_VERIFY_BATCH, &vm),
            Err(VMError::NoritoInvalid)
        );
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters::default()
        );
    }
    #[test]
    fn unaffordable_vrf_batch_stops_before_decode_or_backend_work() {
        let payload = encode_canonical_norito(&crate::vrf::VrfVerifyBatchRequest {
            items: vec![valid_vrf_request(test_network_id(0x71), b"unaffordable")],
        })
        .expect("encode VRF batch");
        let mut vm = IVM::new(u64::MAX);
        let scall = crate::encoding::wide::encode_sys(
            crate::instruction::wide::system::SCALL,
            u8::try_from(syscalls::SYSCALL_VRF_VERIFY_BATCH).expect("syscall fits"),
        );
        let mut code = Vec::new();
        code.extend_from_slice(&scall.to_le_bytes());
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_code(&code).expect("load VRF batch program");
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &payload))
            .expect("allocate VRF batch");
        vm.set_register(10, pointer);
        vm.set_register(11, 0xfeed);
        vm.set_register(12, 0xbeef);
        let mut host = DefaultHost::new();
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_VRF_VERIFY_BATCH, &vm)
            .expect("quote VRF batch");
        vm.set_gas_limit(quote);
        assert_eq!(vm.run_with_host(&mut host), Err(VMError::OutOfGas));
        assert_eq!(vm.register(10), pointer);
        assert_eq!(vm.register(11), 0xfeed);
        assert_eq!(vm.register(12), 0xbeef);
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters::default()
        );
    }
    #[test]
    fn vrf_batch_allocation_failure_reports_metered_work_without_publication() {
        let payload = encode_canonical_norito(&crate::vrf::VrfVerifyBatchRequest {
            items: vec![valid_vrf_request(test_network_id(0x71), b"allocation")],
        })
        .expect("encode successful VRF batch");
        let input = test_tlv(PointerType::NoritoBytes, &payload);
        let mut vm = IVM::new(u64::MAX);
        let pointer = vm
            .alloc_input_tlv(&input)
            .expect("allocate canonical VRF batch");
        let aligned_used = input.len().next_multiple_of(8);
        let remaining = usize::try_from(Memory::INPUT_SIZE)
            .expect("INPUT size fits usize")
            .saturating_sub(aligned_used);
        vm.alloc_input_tlv(&vec![0_u8; remaining])
            .expect("fill the remaining INPUT allocator");
        vm.memory
            .set_heap_limit(0)
            .expect("disable heap spill allocation");
        vm.set_register(10, pointer);
        vm.set_register(11, 0xfeed);
        vm.set_register(12, 0xbeef);
        let mut host = DefaultHost::new().with_network_id(test_network_id(0x71));
        let actual = DefaultHost::vrf_verify_gas(1, payload.len());
        let error = host
            .syscall(syscalls::SYSCALL_VRF_VERIFY_BATCH, &mut vm)
            .expect_err("response allocation must fail");
        assert_eq!(error.split_metered(), (Some(actual), VMError::OutOfMemory));
        assert_eq!(vm.register(10), pointer);
        assert_eq!(vm.register(11), 0xfeed);
        assert_eq!(vm.register(12), 0xbeef);
        assert_eq!(
            host.vrf_execution_counters(),
            VrfExecutionCounters {
                canonical_decodes: 1,
                backend_invocations: 1,
                response_allocations: 0,
            }
        );
    }
    #[test]
    fn default_host_zk_verify_status_paths_charge_payload_bytes() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let malformed = [0xff, 0x00, 0x01];
        let ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &malformed))
            .expect("alloc malformed envelope");
        vm.set_register(10, ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT, &mut vm),
            Ok(gas::zk_verify_gas(malformed.len()))
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), ERR_DECODE);
        let canonical = norito::to_bytes(&dummy_zk_batch_envelope())
            .expect("encode canonical data-model envelope");
        let canonical_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &canonical))
            .expect("allocate canonical envelope");
        vm.set_register(10, canonical_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT, &mut vm),
            Ok(host
                .zk_gas_schedule()
                .actual_single_gas(canonical.len(), 64))
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), ERR_BACKEND);
        let batch_payload = b"batch-envelope";
        let batch_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, batch_payload))
            .expect("alloc batch envelope");
        vm.set_register(10, batch_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &mut vm),
            Ok(host
                .zk_gas_schedule()
                .conservative_batch_gas(1, batch_payload.len()))
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), ERR_DECODE);
        assert_eq!(
            host.zk_execution_counters(),
            ZkExecutionCounters {
                canonical_decodes: 3,
                backend_invocations: 0,
                response_allocations: 0,
            }
        );
    }
    #[test]
    fn zk_batch_prepare_quotes_every_declared_proof_including_rejected_count() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let host = DefaultHost::new();
        let payload = norito::to_bytes(&vec![
            dummy_zk_batch_envelope(),
            dummy_zk_batch_envelope(),
            dummy_zk_batch_envelope(),
        ])
        .expect("encode bounded ZK batch");
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &payload))
            .expect("allocate bounded ZK batch");
        vm.set_register(10, pointer);
        assert_eq!(
            host.prepare_syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &vm),
            Ok(gas::zk_verify_batch_gas(3, payload.len()))
        );
        let oversized = norito::to_bytes(
            &std::iter::repeat_with(dummy_zk_batch_envelope)
                .take(gas::HOST_ZK_VERIFY_MAX_BATCH_PROOFS + 1)
                .collect::<Vec<_>>(),
        )
        .expect("encode oversized ZK batch");
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &oversized))
            .expect("allocate oversized ZK batch");
        vm.set_register(10, pointer);
        assert_eq!(
            host.prepare_syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &vm),
            Ok(gas::zk_verify_batch_gas(
                gas::HOST_ZK_VERIFY_MAX_BATCH_PROOFS + 1,
                oversized.len()
            ))
        );
    }
    #[test]
    fn vm_dispatched_zk_batch_malformed_header_paths_are_metered_before_decode() {
        let canonical =
            norito::to_bytes(&vec![dummy_zk_batch_envelope()]).expect("encode canonical ZK batch");
        assert!(canonical.len() > norito::core::Header::SIZE);
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let ambient_probe = vec!["first".to_owned(), "second".to_owned()];
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            let ambient_before =
                norito::to_bytes(&ambient_probe).expect("encode ambient batch probe");
            assert!(decode_canonical_zk_batch(&canonical, 16).is_ok());
            assert_eq!(
                norito::to_bytes(&ambient_probe).expect("encode ambient probe after batch decode"),
                ambient_before,
                "canonical batch decoding must restore the ambient layout"
            );
        }
        let alternate_layout = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&vec![dummy_zk_batch_envelope()])
                .expect("encode alternate-layout ZK batch")
        };
        assert_ne!(alternate_layout, canonical);
        assert!(
            norito::decode_from_bytes::<Vec<OpenVerifyEnvelope>>(&alternate_layout).is_ok(),
            "ordinary Norito decoding must accept the advertised alternate layout"
        );
        assert!(matches!(
            decode_canonical_zk_batch(&alternate_layout, 16),
            Err(ERR_DECODE)
        ));
        let mut wrong_schema = canonical.clone();
        wrong_schema[6] ^= 1; // schema starts after magic + major + minor
        let mut wrong_flags = canonical.clone();
        wrong_flags[norito::core::Header::SIZE - 1] = 0x80;
        let mut wrong_checksum = canonical;
        wrong_checksum[31] ^= 1; // CRC64 follows the encoded payload length
        for (label, payload) in [
            ("schema", wrong_schema),
            ("flags", wrong_flags),
            ("checksum", wrong_checksum),
            ("alternate layout", alternate_layout),
        ] {
            let (vm, host, quote) = run_vm_dispatched_zk_batch(&payload);
            assert_eq!(
                quote,
                host.zk_gas_schedule()
                    .conservative_batch_gas(1, payload.len()),
                "{label}"
            );
            assert_eq!(vm.register(10), 0, "{label}");
            assert_eq!(vm.register(11), ERR_DECODE, "{label}");
            assert_eq!(vm.register(12), u64::MAX, "{label}");
            assert_eq!(vm.remaining_gas(), 0, "{label}");
            assert_eq!(
                host.zk_execution_counters(),
                ZkExecutionCounters {
                    canonical_decodes: 1,
                    backend_invocations: 0,
                    response_allocations: 0,
                },
                "{label}"
            );
        }
    }
    #[test]
    fn vm_dispatched_zk_batch_count_boundaries_have_stable_status_and_work() {
        for count in [0_usize, 17] {
            let payload = norito::to_bytes(
                &(0..count)
                    .map(|_| dummy_zk_batch_envelope())
                    .collect::<Vec<_>>(),
            )
            .expect("encode boundary ZK batch");
            let (vm, host, quote) = run_vm_dispatched_zk_batch(&payload);
            let quoted_count = count.max(1);
            assert_eq!(
                quote,
                host.zk_gas_schedule()
                    .conservative_batch_gas(quoted_count, payload.len())
            );
            assert_eq!(vm.register(10), 0);
            assert_eq!(
                vm.register(11),
                if count == 0 { ERR_DECODE } else { ERR_BATCH }
            );
            assert_eq!(vm.register(12), u64::MAX);
            assert_eq!(vm.remaining_gas(), 0);
            assert_eq!(
                host.zk_execution_counters(),
                ZkExecutionCounters {
                    canonical_decodes: 1,
                    backend_invocations: 0,
                    response_allocations: 0,
                }
            );
        }
        for count in [1_usize, 16] {
            let payload = norito::to_bytes(
                &(0..count)
                    .map(|_| dummy_zk_batch_envelope())
                    .collect::<Vec<_>>(),
            )
            .expect("encode admitted ZK batch");
            let (vm, host, quote) = run_vm_dispatched_zk_batch(&payload);
            let actual = host.zk_gas_schedule().actual_batch_gas(
                count,
                payload.len(),
                u64::try_from(count).expect("bounded count") * 2,
            );
            assert_eq!(vm.remaining_gas(), quote - actual);
            assert_eq!(vm.register(11), ERR_BACKEND);
            assert_eq!(vm.register(12), 0);
            let output = vm.validate_tlv(vm.register(10)).expect("batch output");
            assert_eq!(output.type_id, PointerType::NoritoBytes);
            let statuses: Vec<u8> =
                norito::decode_from_bytes(output.payload).expect("decode statuses");
            assert_eq!(statuses, vec![0; count]);
            assert_eq!(
                u64::try_from(TLV_ENVELOPE_OVERHEAD + output.payload.len())
                    .expect("bounded output"),
                host.zk_gas_schedule().batch_output_bytes(count)
            );
            assert_eq!(
                host.zk_execution_counters(),
                ZkExecutionCounters {
                    canonical_decodes: 1,
                    backend_invocations: 0,
                    response_allocations: 1,
                }
            );
        }
    }
    #[test]
    fn zk_batch_allocation_failure_does_not_count_a_guest_visible_response() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let payload =
            norito::to_bytes(&vec![dummy_zk_batch_envelope()]).expect("encode canonical ZK batch");
        let input = test_tlv(PointerType::NoritoBytes, &payload);
        let pointer = vm
            .alloc_input_tlv(&input)
            .expect("allocate canonical ZK batch");
        let aligned_used = input.len().next_multiple_of(8);
        let remaining = usize::try_from(Memory::INPUT_SIZE)
            .expect("INPUT size fits usize")
            .saturating_sub(aligned_used);
        vm.alloc_input_tlv(&vec![0_u8; remaining])
            .expect("fill the remaining INPUT allocator");
        vm.memory
            .set_heap_limit(0)
            .expect("disable heap spill allocation");
        vm.set_register(10, pointer);
        let mut host = DefaultHost::new();
        assert_eq!(
            host.syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &mut vm),
            Err(VMError::OutOfMemory)
        );
        assert_eq!(
            host.zk_execution_counters(),
            ZkExecutionCounters {
                canonical_decodes: 1,
                backend_invocations: 0,
                response_allocations: 0,
            }
        );
    }
    #[test]
    fn unaffordable_zk_batch_stops_before_decode_or_backend_work() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut code = Vec::new();
        code.extend_from_slice(
            &crate::encoding::wide::encode_sys(
                crate::instruction::wide::system::SCALL,
                u8::try_from(syscalls::SYSCALL_ZK_VERIFY_BATCH).expect("syscall fits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_code(&code).expect("load ZK batch test program");
        let payload = norito::to_bytes(&vec![dummy_zk_batch_envelope(), dummy_zk_batch_envelope()])
            .expect("encode ZK batch");
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &payload))
            .expect("allocate ZK batch");
        vm.set_register(10, pointer);
        vm.set_register(11, 0xfeed);
        vm.set_register(12, 0xbeef);
        let mut host = DefaultHost::new();
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &vm)
            .expect("quote bounded ZK batch");
        vm.set_gas_limit(quote);
        assert_eq!(vm.run_with_host(&mut host), Err(VMError::OutOfGas));
        assert_eq!(vm.register(10), pointer);
        assert_eq!(vm.register(11), 0xfeed);
        assert_eq!(vm.register(12), 0xbeef);
        assert_eq!(host.zk_execution_counters(), ZkExecutionCounters::default());
    }
    #[test]
    fn forged_batch_count_cannot_buy_more_backend_work_than_was_quoted() {
        crate::set_banner_enabled(false);
        let mut payload = norito::to_bytes(&vec![
            dummy_zk_batch_envelope(),
            dummy_zk_batch_envelope(),
            dummy_zk_batch_envelope(),
        ])
        .expect("encode ZK batch");
        let count_offset = {
            let view = norito::core::from_bytes_view(&payload).expect("inspect ZK batch");
            view.as_bytes().as_ptr() as usize - payload.as_ptr() as usize
        };
        payload[count_offset..count_offset + 8].copy_from_slice(&1_u64.to_le_bytes());
        let mut vm = IVM::new(u64::MAX);
        let mut code = Vec::new();
        code.extend_from_slice(
            &crate::encoding::wide::encode_sys(
                crate::instruction::wide::system::SCALL,
                u8::try_from(syscalls::SYSCALL_ZK_VERIFY_BATCH).expect("syscall fits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_code(&code).expect("load forged-count test program");
        let pointer = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &payload))
            .expect("allocate forged-count batch");
        vm.set_register(10, pointer);
        let mut host = DefaultHost::new();
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &vm)
            .expect("quote declared count without decoding");
        assert_eq!(quote, gas::zk_verify_batch_gas(1, payload.len()));
        vm.set_gas_limit(quote.saturating_add(16));
        vm.run_with_host(&mut host)
            .expect("invalid Norito checksum is a metered decode status");
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), ERR_DECODE);
        assert_eq!(
            host.zk_execution_counters(),
            ZkExecutionCounters {
                canonical_decodes: 1,
                backend_invocations: 0,
                response_allocations: 0,
            }
        );
    }
    #[test]
    fn default_host_zk_read_helpers_charge_request_and_response_bytes() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let roots_req = crate::zk_verify::RootsGetRequest {
            asset_id: "rose#garden".to_string(),
            max: 8,
        };
        let roots_payload = norito::to_bytes(&roots_req).expect("encode roots request");
        let roots_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &roots_payload))
            .expect("alloc roots request");
        vm.set_register(10, roots_ptr);
        let roots_quote = host
            .prepare_syscall(syscalls::SYSCALL_ZK_ROOTS_GET, &vm)
            .expect("quote roots get");
        let roots_gas = host
            .syscall(syscalls::SYSCALL_ZK_ROOTS_GET, &mut vm)
            .expect("roots get");
        assert!(roots_gas <= roots_quote);
        let roots_out = vm.validate_tlv(vm.register(10)).expect("roots tlv");
        assert_eq!(roots_out.type_id, PointerType::NoritoBytes);
        assert_eq!(
            roots_gas,
            DefaultHost::state_query_gas(
                roots_payload.len().saturating_add(roots_out.payload.len())
            )
        );
        let tally_req = crate::zk_verify::VoteGetTallyRequest {
            election_id: "election".to_string(),
        };
        let tally_payload = norito::to_bytes(&tally_req).expect("encode tally request");
        let tally_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &tally_payload))
            .expect("alloc tally request");
        vm.set_register(10, tally_ptr);
        let tally_quote = host
            .prepare_syscall(syscalls::SYSCALL_ZK_VOTE_GET_TALLY, &vm)
            .expect("quote vote tally");
        let tally_gas = host
            .syscall(syscalls::SYSCALL_ZK_VOTE_GET_TALLY, &mut vm)
            .expect("vote tally");
        assert!(tally_gas <= tally_quote);
        let tally_out = vm.validate_tlv(vm.register(10)).expect("tally tlv");
        assert_eq!(tally_out.type_id, PointerType::NoritoBytes);
        assert_eq!(
            tally_gas,
            DefaultHost::state_query_gas(
                tally_payload.len().saturating_add(tally_out.payload.len())
            )
        );
    }
    #[test]
    fn default_host_vote_tally_rejects_noncanonical_selector_without_response() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let request = crate::zk_verify::VoteGetTallyRequest {
            election_id: ".hidden".to_owned(),
        };
        let payload = norito::to_bytes(&request).expect("encode tally request");
        let request_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &payload))
            .expect("allocate tally request");
        vm.set_register(10, request_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_ZK_VOTE_GET_TALLY, &mut vm),
            Err(VMError::NoritoInvalid)
        );
        assert_eq!(
            vm.register(10),
            request_ptr,
            "failed tally queries must not publish a response pointer"
        );
    }
    #[test]
    fn default_host_state_has_len_and_count_roundtrip() {
        fn tlv(kind: PointerType, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
            out.extend_from_slice(&(kind as u16).to_be_bytes());
            out.push(1);
            out.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("test payload length")
                    .to_be_bytes(),
            );
            out.extend_from_slice(payload);
            let hash: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new(payload).into();
            out.extend_from_slice(&hash);
            out
        }
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let key: StatePath = "orders/1".parse().expect("state key");
        let prefix: StatePath = "orders".parse().expect("state prefix");
        let key_payload = norito::to_bytes(&key).expect("encode key");
        let prefix_payload = norito::to_bytes(&prefix).expect("encode prefix");
        let key_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::NoritoBytes, &key_payload))
            .expect("alloc key");
        let prefix_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::NoritoBytes, &prefix_payload))
            .expect("alloc prefix");
        let value_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::NoritoBytes, b"value"))
            .expect("alloc value");
        vm.set_register(10, key_ptr);
        vm.set_register(11, value_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_STATE_SET, &mut vm),
            Ok(state_value_gas(key_payload.len(), b"value".len()))
        );
        vm.set_register(10, key_ptr);
        host.syscall(syscalls::SYSCALL_STATE_HAS, &mut vm)
            .expect("STATE_HAS");
        assert_eq!(vm.register(10), 1);
        vm.set_register(10, key_ptr);
        host.syscall(syscalls::SYSCALL_STATE_LEN, &mut vm)
            .expect("STATE_LEN");
        assert_eq!(vm.register(10), 5);
        assert_eq!(vm.register(11), 1);
        vm.set_register(10, prefix_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_STATE_COUNT, &mut vm),
            Ok(STATE_QUERY_GAS_BASE
                + u64::try_from(prefix_payload.len()).expect("path length fits")
                + u64::try_from(1 + key.as_ref().len()).expect("scan length fits"))
        );
        assert_eq!(vm.register(10), 1);
        vm.set_register(10, key_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_STATE_DEL, &mut vm),
            Ok(state_path_gas(key_payload.len()))
        );
        vm.set_register(10, key_ptr);
        host.syscall(syscalls::SYSCALL_STATE_HAS, &mut vm)
            .expect("STATE_HAS absent");
        assert_eq!(vm.register(10), 0);
    }
    #[test]
    fn state_path_from_name_is_explicit_and_state_rejects_name_carrier() {
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let name: Name = "orders".parse().expect("canonical Name");
        let name_payload = norito::to_bytes(&name).expect("encode Name");
        let name_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::Name, &name_payload))
            .expect("allocate Name");
        vm.set_register(10, name_ptr);
        let gas = host
            .syscall(syscalls::SYSCALL_STATE_PATH_FROM_NAME, &mut vm)
            .expect("convert Name to StatePath");
        let output = vm
            .validate_tlv(vm.register(10))
            .expect("validate StatePath output");
        assert_eq!(output.type_id, PointerType::NoritoBytes);
        let path: StatePath = norito::decode_from_bytes(output.payload).expect("decode StatePath");
        assert_eq!(path.as_ref(), name.as_ref());
        assert_eq!(
            gas,
            DefaultHost::path_gas(name_payload.len(), output.payload.len())
        );
        vm.set_register(10, name_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_STATE_HAS, &mut vm),
            Err(VMError::NoritoInvalid),
            "durable-state operations must not accept Name as a compatibility carrier"
        );
        assert_eq!(vm.register(10), name_ptr);
    }
    #[test]
    fn host_state_dependent_prepare_reserves_without_observing_state() {
        let mut vm = IVM::new(4_000_000);
        let path: StatePath = "orders".parse().expect("state path");
        let path = norito::to_bytes(&path).expect("encode state path");
        let path = vm
            .alloc_input_tlv(&test_tlv(PointerType::NoritoBytes, &path))
            .expect("allocate state path");
        vm.set_register(10, path);
        vm.set_register(12, syscalls::STATE_SCAN_MAX_ITEMS_V1);
        let empty = DefaultHost::new();
        let mut populated = DefaultHost::new();
        populated
            .state
            .insert("orders/1".parse().expect("state key"), vec![0u8; 128]);
        populated.public_inputs.insert(
            "public".parse().expect("public input name"),
            test_tlv(PointerType::Blob, &[0u8; 128]),
        );
        populated.fastpq_batch_active = true;
        let available = vm.remaining_gas();
        for syscall in [
            syscalls::SYSCALL_STATE_COUNT,
            syscalls::SYSCALL_GET_PUBLIC_INPUT,
            syscalls::SYSCALL_TRANSFER_V1,
            syscalls::SYSCALL_TRANSFER_V1_BATCH_APPLY,
            syscalls::SYSCALL_AXT_TOUCH,
            syscalls::SYSCALL_VERIFY_DS_PROOF,
            syscalls::SYSCALL_AXT_COMMIT,
        ] {
            assert_eq!(empty.prepare_syscall(syscall, &vm), Ok(available));
            assert_eq!(populated.prepare_syscall(syscall, &vm), Ok(available));
        }
        let path_len = quote_state_path_payload_len_at(&vm, path).expect("quote state path");
        assert_eq!(
            empty.prepare_syscall(syscalls::SYSCALL_STATE_GET, &vm),
            Ok(available)
        );
        assert_eq!(
            populated.prepare_syscall(syscalls::SYSCALL_STATE_GET, &vm),
            Ok(available)
        );
        assert_eq!(
            empty.prepare_syscall(syscalls::SYSCALL_STATE_LEN, &vm),
            Ok(state_path_gas(path_len))
        );
        assert_eq!(
            populated.prepare_syscall(syscalls::SYSCALL_STATE_LEN, &vm),
            Ok(state_path_gas(path_len))
        );
        assert_eq!(
            reserve_available_syscall_gas(&IVM::new(0)),
            Err(VMError::OutOfGas)
        );
    }
    #[test]
    fn default_host_pointer_helpers_roundtrip_and_charge_gas() {
        fn tlv(kind: PointerType, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
            out.extend_from_slice(&(kind as u16).to_be_bytes());
            out.push(1);
            out.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("test payload length")
                    .to_be_bytes(),
            );
            out.extend_from_slice(payload);
            let hash: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new(payload).into();
            out.extend_from_slice(&hash);
            out
        }
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let payload = b"deterministic";
        let ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, payload))
            .expect("alloc blob");
        let envelope_len = 2 + 1 + 4 + payload.len() + iroha_crypto::Hash::LENGTH;
        vm.set_register(10, ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_POINTER_TO_NORITO, &mut vm),
            Ok(DefaultHost::pointer_gas(envelope_len))
        );
        let wrapped_ptr = vm.register(10);
        let wrapped = vm.validate_tlv(wrapped_ptr).expect("wrapped tlv");
        assert_eq!(wrapped.type_id, PointerType::NoritoBytes);
        assert_eq!(wrapped.payload.len(), envelope_len);
        vm.set_register(10, wrapped_ptr);
        vm.set_register(11, PointerType::Blob as u64);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm),
            Ok(DefaultHost::pointer_gas(envelope_len))
        );
        let roundtrip = vm.validate_tlv(vm.register(10)).expect("roundtrip tlv");
        assert_eq!(roundtrip.type_id, PointerType::Blob);
        assert_eq!(roundtrip.payload, payload);
        let blob_carrier = tlv(PointerType::Blob, &tlv(PointerType::Blob, payload));
        let blob_carrier_ptr = vm
            .alloc_input_tlv(&blob_carrier)
            .expect("alloc blob carrier");
        vm.set_register(10, blob_carrier_ptr);
        vm.set_register(11, PointerType::Blob as u64);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm),
            Err(VMError::NoritoInvalid)
        );
        assert_eq!(vm.register(10), blob_carrier_ptr);
    }
    #[test]
    fn default_host_int_pointer_codec_validates_signed_512_frames() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let value = iroha_primitives::bigint::BigInt::from_twos_bytes(&[0x7f; 64])
            .expect("wide signed integer");
        let inner = ivm_abi::numeric_tlv::encode_int(&value).expect("canonical Int pointer");
        let source = vm.alloc_input_tlv(&inner).expect("allocate Int");
        vm.set_register(10, source);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_POINTER_TO_NORITO, &mut vm),
            Ok(DefaultHost::pointer_gas(inner.len()))
        );
        let wrapped = vm.register(10);
        assert_eq!(
            vm.validate_tlv(wrapped).expect("wrapped Int").payload,
            inner
        );
        vm.set_register(10, wrapped);
        vm.set_register(11, u64::from(PointerType::Int as u16));
        assert_eq!(
            host.syscall(syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm),
            Ok(DefaultHost::pointer_gas(inner.len()))
        );
        let restored = vm.validate_tlv(vm.register(10)).expect("restored Int");
        assert_eq!(
            crate::numeric_tlv::decode_int_bytes(&test_tlv(PointerType::Int, restored.payload)),
            Ok(value)
        );

        let malformed = test_tlv(PointerType::Int, b"17");
        let malformed_ptr = vm
            .alloc_input_tlv(&malformed)
            .expect("allocate malformed Int");
        vm.set_register(10, malformed_ptr);
        assert!(matches!(
            host.syscall(syscalls::SYSCALL_POINTER_TO_NORITO, &mut vm),
            Err(VMError::PointerAbiFault(_))
        ));
        assert_eq!(vm.register(10), malformed_ptr);
        let wrapped_malformed = test_tlv(PointerType::NoritoBytes, &malformed);
        let wrapped_ptr = vm
            .alloc_input_tlv(&wrapped_malformed)
            .expect("allocate wrapped malformed Int");
        vm.set_register(10, wrapped_ptr);
        vm.set_register(11, u64::from(PointerType::Int as u16));
        assert!(matches!(
            host.syscall(syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm),
            Err(VMError::PointerAbiFault(_))
        ));
        assert_eq!(vm.register(10), wrapped_ptr);
        for kind in [
            PointerType::Int,
            PointerType::Decimal,
            PointerType::Quantity,
        ] {
            vm.set_register(10, 0);
            vm.set_register(11, u64::from(kind as u16));
            assert_eq!(
                host.syscall(syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm),
                Err(VMError::NoritoInvalid),
                "numeric {kind:?} cannot decode from null"
            );
            assert_eq!(vm.register(10), 0);
        }
    }
    #[test]
    fn common_helper_quotes_are_exact_at_length_boundaries() {
        crate::set_banner_enabled(false);
        for payload_len in [0, 1, 127, 128, 255, 256, 4095] {
            let mut vm = IVM::new(u64::MAX);
            let mut host = DefaultHost::new();
            let payload = vec![0x5a; payload_len];
            let pointer = vm
                .alloc_input_tlv(&test_tlv(PointerType::Blob, &payload))
                .expect("allocate boundary TLV");
            vm.set_register(10, pointer);
            let registers_before = (vm.register(10), vm.register(11));
            vm.memory.clear_tracking();
            let quote = host
                .prepare_syscall(syscalls::SYSCALL_POINTER_TO_NORITO, &vm)
                .expect("quote pointer conversion");
            assert_eq!(
                (vm.register(10), vm.register(11)),
                registers_before,
                "preparation must not mutate registers"
            );
            assert!(
                vm.memory
                    .try_read_log_snapshot()
                    .expect("allocate read-log snapshot")
                    .is_empty(),
                "preparation must not mutate memory access tracking"
            );
            assert_eq!(
                host.syscall(syscalls::SYSCALL_POINTER_TO_NORITO, &mut vm)
                    .expect("convert pointer"),
                quote
            );
        }
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let left = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, b"left"))
            .expect("allocate left TLV");
        vm.set_register(10, left);
        vm.set_register(11, Memory::OUTPUT_START);
        let error = host
            .prepare_syscall(syscalls::SYSCALL_TLV_EQ, &vm)
            .expect_err("invalid right pointer must fail strict pointer-ABI preparation");
        assert!(matches!(
            error,
            VMError::NoritoInvalid | VMError::MemoryAccessViolation { .. }
        ));
        assert!(host.syscall(syscalls::SYSCALL_TLV_EQ, &mut vm).is_err());
        vm.set_register(10, Memory::OUTPUT_START);
        vm.set_register(11, Memory::OUTPUT_START);
        assert!(
            host.prepare_syscall(syscalls::SYSCALL_TLV_EQ, &vm).is_err(),
            "equal raw addresses must not bypass pointer-ABI validation"
        );
        assert!(host.syscall(syscalls::SYSCALL_TLV_EQ, &mut vm).is_err());
        vm.set_register(10, 0);
        vm.set_register(11, Memory::OUTPUT_START);
        assert!(
            host.prepare_syscall(syscalls::SYSCALL_TLV_EQ, &vm).is_err(),
            "null comparison must still validate the non-null operand"
        );
        assert!(host.syscall(syscalls::SYSCALL_TLV_EQ, &mut vm).is_err());
    }
    #[test]
    fn crypto_quotes_use_processed_lengths_and_saturate() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let json = Json::from(norito::json!({
            "z": [true, false],
            "a": "canonicalized",
        }));
        let json_payload = norito::to_bytes(&json).expect("encode JSON envelope");
        let message = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, &json_payload))
            .expect("allocate message");
        let signature = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, b"signature"))
            .expect("allocate signature");
        let public_key = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, b"public-key"))
            .expect("allocate public key");
        vm.set_register(10, message);
        vm.set_register(11, signature);
        vm.set_register(12, public_key);
        vm.set_register(13, u64::MAX);
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_VERIFY_SIGNATURE, &vm)
            .expect("quote signature verification");
        let actual = host
            .syscall(syscalls::SYSCALL_VERIFY_SIGNATURE, &mut vm)
            .expect("unsupported scheme still reports processed gas");
        assert!(actual <= quote);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new().with_sm_enabled(true);
        for (register, payload) in [
            (10, Vec::new()),
            (11, Vec::new()),
            (12, vec![0xa5; 127]),
            (13, vec![0x5a; 128]),
        ] {
            let pointer = vm
                .alloc_input_tlv(&test_tlv(PointerType::Blob, &payload))
                .expect("allocate SM4 input");
            vm.set_register(register, pointer);
        }
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_SM4_GCM_SEAL, &vm)
            .expect("quote SM4");
        assert_eq!(quote, DefaultHost::sm4_gas(127, 128));
        assert_eq!(
            host.syscall(syscalls::SYSCALL_SM4_GCM_SEAL, &mut vm)
                .expect("invalid key is a metered verification result"),
            quote
        );
        assert_eq!(DefaultHost::sm4_gas(usize::MAX, usize::MAX), u64::MAX);
        assert_eq!(
            DefaultHost::signature_verify_gas(usize::MAX, usize::MAX, usize::MAX),
            u64::MAX
        );
        assert_eq!(DefaultHost::tlv_eq_gas(usize::MAX, usize::MAX), u64::MAX);
    }
    #[test]
    fn signature_and_sm2_verification_reject_retired_message_carriers() {
        crate::set_banner_enabled(false);
        for message_type in [PointerType::NoritoBytes, PointerType::Json] {
            let mut vm = IVM::new(u64::MAX);
            let message = vm
                .alloc_input_tlv(&test_tlv(message_type, b"message"))
                .expect("allocate retired message carrier");
            let signature = vm
                .alloc_input_tlv(&test_tlv(PointerType::Blob, b"signature"))
                .expect("allocate signature");
            let public_key = vm
                .alloc_input_tlv(&test_tlv(PointerType::Blob, b"public-key"))
                .expect("allocate public key");
            vm.set_register(10, message);
            vm.set_register(11, signature);
            vm.set_register(12, public_key);
            vm.set_register(13, u64::MAX);
            let mut host = DefaultHost::new();
            assert_eq!(
                host.prepare_syscall(syscalls::SYSCALL_VERIFY_SIGNATURE, &vm),
                Err(VMError::NoritoInvalid)
            );
            assert_eq!(
                host.syscall(syscalls::SYSCALL_VERIFY_SIGNATURE, &mut vm),
                Err(VMError::NoritoInvalid)
            );
            assert_eq!(vm.register(10), message);
            let mut sm_host = DefaultHost::new().with_sm_enabled(true);
            assert_eq!(
                sm_host.syscall(syscalls::SYSCALL_SM2_VERIFY, &mut vm),
                Err(VMError::NoritoInvalid)
            );
            assert_eq!(vm.register(10), message);
        }
    }
    #[test]
    fn unaffordable_signature_syscall_preserves_inputs_before_dispatch() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut code = Vec::new();
        code.extend_from_slice(
            &crate::encoding::wide::encode_sys(
                crate::instruction::wide::system::SCALL,
                u8::try_from(syscalls::SYSCALL_VERIFY_SIGNATURE).expect("syscall fits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_code(&code).expect("load signature test program");
        let message = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, b"message"))
            .expect("allocate message");
        let signature = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, b"signature"))
            .expect("allocate signature");
        let public_key = vm
            .alloc_input_tlv(&test_tlv(PointerType::Blob, b"public-key"))
            .expect("allocate public key");
        vm.set_register(10, message);
        vm.set_register(11, signature);
        vm.set_register(12, public_key);
        let mut host = DefaultHost::new();
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_VERIFY_SIGNATURE, &vm)
            .expect("quote signature verification");
        vm.set_gas_limit(quote.saturating_add(4));
        let error = vm
            .run_with_host(&mut host)
            .expect_err("the quote is one gas beyond the post-SCALL budget");
        assert_eq!(error, VMError::OutOfGas);
        assert_eq!(vm.register(10), message);
        assert_eq!(vm.register(11), signature);
        assert_eq!(vm.register(12), public_key);
    }
    #[test]
    fn execution_summary_and_merkle_quotes_match_actual_costs() {
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let proof_quote = host
            .prepare_syscall(syscalls::SYSCALL_EXECUTION_SUMMARY, &vm)
            .expect("quote proof");
        assert_eq!(
            host.syscall(syscalls::SYSCALL_EXECUTION_SUMMARY, &mut vm)
                .expect("produce proof"),
            proof_quote
        );
        for depth_cap in [0, 1, 8, 32, u64::MAX] {
            let mut vm = IVM::new(u64::MAX);
            let mut host = DefaultHost::new();
            vm.memory
                .store_u32(Memory::HEAP_START, 0xfeed_beef)
                .expect("seed Merkle leaf");
            vm.set_register(10, Memory::HEAP_START);
            vm.set_register(11, Memory::OUTPUT_START);
            vm.set_register(12, depth_cap);
            vm.set_register(13, 0);
            let quote = host
                .prepare_syscall(syscalls::SYSCALL_GET_MERKLE_COMPACT, &vm)
                .expect("quote compact proof");
            assert_eq!(
                host.syscall(syscalls::SYSCALL_GET_MERKLE_COMPACT, &mut vm)
                    .expect("produce compact proof"),
                quote
            );
        }
        let mut vm = IVM::new(u64::MAX);
        let stack_top = vm.memory.stack_top();
        vm.set_register(10, stack_top);
        assert_eq!(
            DefaultHost::new().prepare_syscall(syscalls::SYSCALL_GET_MERKLE_PATH, &vm),
            Err(VMError::MemoryOutOfBounds)
        );
        vm.set_register(10, crate::parallel::REGISTER_COUNT as u64);
        assert_eq!(
            DefaultHost::new().prepare_syscall(syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT, &vm),
            Err(VMError::RegisterOutOfBounds)
        );
    }
    #[test]
    fn merkle_path_quote_rounds_partial_leaf_up_at_power_of_two_boundary() {
        const GAS_LIMIT: u64 = 262_148;
        let mut vm = IVM::new_with_config(crate::runtime::IvmConfig::new(GAS_LIMIT));
        assert_eq!(vm.memory.stack_limit(), 1_048_592);
        vm.memory
            .store_u32(Memory::HEAP_START, 0xfeed_beef)
            .expect("seed Merkle leaf");
        vm.set_register(10, Memory::HEAP_START);
        vm.set_register(11, Memory::OUTPUT_START);
        vm.set_register(12, 0);
        let mut host = DefaultHost::new();
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_GET_MERKLE_PATH, &vm)
            .expect("quote full Merkle path");
        let actual = host
            .syscall(syscalls::SYSCALL_GET_MERKLE_PATH, &mut vm)
            .expect("produce full Merkle path");
        assert_eq!(vm.register(10), 18, "partial leaf increases tree depth");
        assert_eq!(actual, quote);
    }
    #[test]
    fn disabled_and_unknown_syscall_quotes_fail_closed_without_over_reserving() {
        let vm = IVM::new(u64::MAX);
        let host = DefaultHost::new();
        assert_eq!(host.prepare_syscall(syscalls::SYSCALL_SM3_HASH, &vm), Ok(0));
        assert_eq!(
            host.prepare_syscall(syscalls::SYSCALL_REGISTER_DOMAIN, &vm),
            Ok(MUTATION_GAS)
        );
        assert_eq!(
            host.prepare_syscall(0xffff_fffe, &vm),
            Err(VMError::UnknownSyscall(0xffff_fffe))
        );
    }
    #[test]
    fn default_host_sm4_gcm_charges_aad_and_data_bytes() {
        fn tlv(kind: PointerType, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
            out.extend_from_slice(&(kind as u16).to_be_bytes());
            out.push(1);
            out.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("test payload length")
                    .to_be_bytes(),
            );
            out.extend_from_slice(payload);
            let hash: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new(payload).into();
            out.extend_from_slice(&hash);
            out
        }
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new().with_sm_enabled(true);
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let aad = b"aad";
        let plaintext = b"plaintext";
        let key_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, &key))
            .expect("alloc key");
        let nonce_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, &nonce))
            .expect("alloc nonce");
        let aad_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, aad))
            .expect("alloc aad");
        let plaintext_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, plaintext))
            .expect("alloc plaintext");
        vm.set_register(10, key_ptr);
        vm.set_register(11, nonce_ptr);
        vm.set_register(12, aad_ptr);
        vm.set_register(13, plaintext_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_SM4_GCM_SEAL, &mut vm),
            Ok(DefaultHost::sm4_gas(aad.len(), plaintext.len()))
        );
        let sealed_ptr = vm.register(10);
        let sealed_len = {
            let sealed = vm.validate_tlv(sealed_ptr).expect("sealed tlv");
            assert_eq!(sealed.type_id, PointerType::Blob);
            assert_eq!(sealed.payload.len(), plaintext.len() + 16);
            sealed.payload.len()
        };
        vm.set_register(10, key_ptr);
        vm.set_register(11, nonce_ptr);
        vm.set_register(12, aad_ptr);
        vm.set_register(13, sealed_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_SM4_GCM_OPEN, &mut vm),
            Ok(DefaultHost::sm4_gas(aad.len(), sealed_len))
        );
        let opened = vm.validate_tlv(vm.register(10)).expect("opened tlv");
        assert_eq!(opened.type_id, PointerType::Blob);
        assert_eq!(opened.payload, plaintext);
    }
    #[test]
    fn default_host_tlv_eq_charges_payload_bytes() {
        fn tlv(kind: PointerType, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
            out.extend_from_slice(&(kind as u16).to_be_bytes());
            out.push(1);
            out.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("test payload length")
                    .to_be_bytes(),
            );
            out.extend_from_slice(payload);
            let hash: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new(payload).into();
            out.extend_from_slice(&hash);
            out
        }
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let left = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, b"same"))
            .expect("alloc left");
        let right = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, b"same"))
            .expect("alloc right");
        vm.set_register(10, left);
        vm.set_register(11, right);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_TLV_EQ, &mut vm),
            Ok(DefaultHost::tlv_eq_gas(4, 4))
        );
        assert_eq!(vm.register(10), 1);
    }
    #[test]
    fn default_host_tlv_len_charges_payload_bytes() {
        fn tlv(kind: PointerType, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
            out.extend_from_slice(&(kind as u16).to_be_bytes());
            out.push(1);
            out.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("test payload length")
                    .to_be_bytes(),
            );
            out.extend_from_slice(payload);
            let hash: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new(payload).into();
            out.extend_from_slice(&hash);
            out
        }
        crate::set_banner_enabled(false);
        let mut vm = IVM::new(u64::MAX);
        let mut host = DefaultHost::new();
        let ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, b"length"))
            .expect("alloc tlv");
        vm.set_register(10, ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_TLV_LEN, &mut vm),
            Ok(DefaultHost::tlv_len_gas(6))
        );
        assert_eq!(vm.register(10), 6);
    }
    #[test]
    fn input_publish_accepts_owned_public_heap_tlv_without_copying() {
        let mut host = DefaultHost::new();
        let mut vm = IVM::new(u64::MAX);
        let envelope = test_tlv(PointerType::Blob, b"heap result");
        let pointer = vm
            .alloc_heap(envelope.len() as u64)
            .expect("allocate owned heap range");
        vm.store_bytes(pointer, &envelope)
            .expect("store public heap TLV");
        vm.set_register(10, pointer);
        assert_eq!(
            host.prepare_syscall(syscalls::SYSCALL_INPUT_PUBLISH_TLV, &vm),
            Ok(DefaultHost::input_publish_gas(envelope.len()))
        );
        assert_eq!(
            host.syscall(syscalls::SYSCALL_INPUT_PUBLISH_TLV, &mut vm),
            Ok(DefaultHost::input_publish_gas(envelope.len()))
        );
        assert_eq!(vm.register(10), pointer);
    }
    #[test]
    fn input_publish_rejects_malformed_and_unowned_heap_tlvs() {
        let mut host = DefaultHost::new();
        let mut vm = IVM::new(u64::MAX);
        let mut malformed = test_tlv(PointerType::Blob, b"bad hash");
        *malformed.last_mut().expect("hash byte") ^= 1;
        let malformed_pointer = vm
            .alloc_heap(malformed.len() as u64)
            .expect("allocate malformed envelope");
        vm.store_bytes(malformed_pointer, &malformed)
            .expect("store malformed envelope");
        vm.set_register(10, malformed_pointer);
        assert!(matches!(
            host.syscall(syscalls::SYSCALL_INPUT_PUBLISH_TLV, &mut vm),
            Err(VMError::NoritoInvalid)
        ));
        let unowned = test_tlv(PointerType::Blob, b"unowned");
        let unowned_pointer = Memory::HEAP_START + 0x10_000;
        vm.store_bytes(unowned_pointer, &unowned)
            .expect("memory permissions alone permit the adversarial write");
        vm.set_register(10, unowned_pointer);
        assert!(matches!(
            host.prepare_syscall(syscalls::SYSCALL_INPUT_PUBLISH_TLV, &vm),
            Err(VMError::NoritoInvalid)
        ));
        assert_eq!(vm.register(10), unowned_pointer);
    }
    #[test]
    fn default_host_runtime_helpers_charge_declared_gas() {
        crate::set_banner_enabled(false);
        let record =
            crate::private_input::int_record(42_u64.into()).expect("encode typed private input");
        let mut host =
            DefaultHost::with_private_inputs(vec![record]).expect("construct bounded host");
        let mut vm = IVM::new(u64::MAX);
        vm.set_zk_mode(true)
            .expect("private lifecycle cleanup succeeds");
        vm.set_register(10, 0);
        vm.set_register(11, PrivateInputKindV1::Int.tag());
        assert_eq!(
            host.syscall(syscalls::SYSCALL_GET_PRIVATE_INPUT, &mut vm),
            Ok(GET_PRIVATE_INPUT_GAS)
        );
        assert!(vm.register(10) >= Memory::HEAP_START);
        assert_eq!(
            vm.ensure_public_tlv_register(10),
            Err(VMError::PrivacyViolation),
            "the host must mark the complete private-input envelope as private memory"
        );
        vm.memory
            .set_heap_limit(0x10_000)
            .expect("shrink heap limit for grow test");
        vm.set_register(10, 4097);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_GROW_HEAP, &mut vm),
            Ok(DefaultHost::grow_heap_gas(4097))
        );
        assert_eq!(
            host.syscall(syscalls::SYSCALL_COMMIT_OUTPUT, &mut vm),
            Ok(COMMIT_OUTPUT_GAS)
        );
        let tlv = test_tlv(PointerType::Blob, b"publish");
        let publish_ptr = vm.alloc_input_tlv(&tlv).expect("alloc publish tlv");
        vm.set_register(10, publish_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_INPUT_PUBLISH_TLV, &mut vm),
            Ok(DefaultHost::input_publish_gas(tlv.len()))
        );
        let account_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::AccountId, b""))
            .expect("alloc account");
        let name_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::Name, b"k"))
            .expect("alloc name");
        let json_payload = b"{\"v\":1}";
        let json_ptr = vm
            .alloc_input_tlv(&test_tlv(PointerType::Json, json_payload))
            .expect("alloc json");
        vm.set_register(10, account_ptr);
        vm.set_register(11, name_ptr);
        vm.set_register(12, json_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_SET_ACCOUNT_DETAIL, &mut vm),
            Ok(DefaultHost::mutation_gas(json_payload.len()))
        );
        let msg = test_tlv(PointerType::Blob, b"m");
        let sig = test_tlv(PointerType::Blob, b"sig");
        let pk = test_tlv(PointerType::Blob, b"pk");
        let msg_ptr = vm.alloc_input_tlv(&msg).expect("alloc msg");
        let sig_ptr = vm.alloc_input_tlv(&sig).expect("alloc sig");
        let pk_ptr = vm.alloc_input_tlv(&pk).expect("alloc pk");
        vm.set_register(10, msg_ptr);
        vm.set_register(11, sig_ptr);
        vm.set_register(12, pk_ptr);
        vm.set_register(13, u64::MAX);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_VERIFY_SIGNATURE, &mut vm),
            Ok(DefaultHost::signature_verify_gas(1, 3, 2))
        );
        assert_eq!(vm.register(10), 0);
        let addr = crate::Memory::HEAP_START;
        vm.memory.store_u32(addr, 0xABCD).expect("store heap");
        vm.memory.commit();
        let path_len = vm.memory.merkle_path(addr).unwrap().len();
        vm.set_register(10, addr);
        vm.set_register(11, crate::Memory::OUTPUT_START);
        vm.set_register(12, 0);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_GET_MERKLE_PATH, &mut vm),
            Ok(DefaultHost::merkle_path_gas(path_len))
        );
        assert_eq!(
            vm.register(10),
            u64::try_from(path_len).expect("path len fits")
        );
    }
    #[test]
    fn commit_output_charges_and_copies_only_the_written_prefix() {
        let full = usize::try_from(Memory::OUTPUT_SIZE).expect("output size fits usize");
        for size in [0_usize, 7, full] {
            let payload = vec![0x5a; size];
            let mut vm = IVM::new(u64::MAX);
            if !payload.is_empty() {
                vm.store_bytes(Memory::OUTPUT_START, &payload)
                    .expect("write output prefix");
            }
            let mut host = DefaultHost::new();
            let expected = gas::commit_output_gas(
                u64::try_from(size).expect("output fixture length fits u64"),
            );
            for _ in 0..3 {
                let quote = host
                    .prepare_syscall(syscalls::SYSCALL_COMMIT_OUTPUT, &vm)
                    .expect("quote output commit");
                let actual = host
                    .syscall(syscalls::SYSCALL_COMMIT_OUTPUT, &mut vm)
                    .expect("commit output");
                assert_eq!(quote, expected);
                assert_eq!(actual, expected);
                assert_eq!(host.take_output(), payload);
            }
        }
    }
    mod quantity_pointer_tests;
}
