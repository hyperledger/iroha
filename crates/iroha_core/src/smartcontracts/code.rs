//! On-chain smart contract registry helpers backed by the world state.
//!
//! This module exposes thin helpers that wrap the canonical ISI instructions for registering
//! manifests, storing bytecode, and binding contract instances. Read APIs query the authenticated
//! world-state view so callers never rely on process-local caches. This replaces the historical
//! process-global map and ensures every node observes the same registry contents.
use crate::execution_attempt::ExecutionAttemptError;
#[cfg(any(test, feature = "iroha-core-tests"))]
use crate::smartcontracts::Execute;
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};
use iroha_crypto::Hash;
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_data_model::isi::smart_contract_code::{
    ActivateContractInstance, RegisterSmartContractBytes, RegisterSmartContractCode,
};
use iroha_data_model::{
    account::AccountId,
    parameter::{CustomParameterId, Parameters},
    prelude::ValidationFail,
    smart_contract::{
        ContractAddress, ContractAlias, ContractArtifactId, ContractLifecycleControlV1,
        ContractLifecycleOwnerV1,
        manifest::{ContractManifest, EntryPointKind},
    },
};
use iroha_model_base::{name::Name, state_path::StatePath};
use mv::storage::StorageReadOnly;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
/// Consensus-persisted, irreversible subject identity for one contract address.
///
/// Bindings are retained after deactivation so every historical contract subject remains
/// permanently non-signing. The first-release format has one hash-to-point derivation and no
/// legacy version or migration metadata.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::smartcontracts::code::ContractSubjectBinding")]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
pub struct ContractSubjectBinding {
    /// Exact account authority used while this contract executes.
    pub(crate) subject: AccountId,
    /// Exact ownership and lifecycle-control state for this address.
    pub(crate) lifecycle: ContractLifecycleControlV1,
}
impl ContractSubjectBinding {
    /// Construct the canonical direct-deployment binding for an address.
    #[must_use]
    pub(crate) fn new_direct(address: &ContractAddress, deployer: AccountId) -> Self {
        Self {
            subject: address.subject_id(),
            lifecycle: ContractLifecycleControlV1::direct(deployer),
        }
    }
    /// Construct the canonical Parliament-deployment binding for an address.
    #[must_use]
    pub(crate) fn new_parliament(
        address: &ContractAddress,
        proposer: AccountId,
        proposal_content_id: [u8; 32],
        governance_attempt_id: [u8; 32],
    ) -> Self {
        Self {
            subject: address.subject_id(),
            lifecycle: ContractLifecycleControlV1::parliament(
                proposer,
                proposal_content_id,
                governance_attempt_id,
            ),
        }
    }
    /// Seed an already-active binding while constructing an internally consistent fixture.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_active_code_hash(mut self, code_hash: Hash) -> Self {
        self.lifecycle.active_code_hash = Some(code_hash);
        self
    }
    /// Validate that the persisted subject matches the canonical address derivation.
    pub(crate) fn validate_for(&self, address: &ContractAddress) -> Result<(), String> {
        let expected = address.subject_id();
        if self.subject != expected {
            return Err(format!(
                "contract subject binding mismatch for `{address}`: expected `{expected}`, stored `{}`",
                self.subject
            ));
        }
        self.lifecycle
            .validate()
            .map_err(|error| format!("invalid lifecycle binding for `{address}`: {error}"))?;
        Ok(())
    }
}
/// Read the complete lifecycle record for a contract address, including inactive addresses.
///
/// The returned subject is the consensus-persisted non-signing execution authority. `None` means
/// the address has never been deployed; malformed persisted bindings fail closed with an error.
///
/// # Errors
/// Returns an invariant explanation when the binding or its active-code index is inconsistent.
pub fn fetch_contract_lifecycle(
    world: &impl WorldReadOnly,
    address: &ContractAddress,
) -> Result<Option<(AccountId, ContractLifecycleControlV1)>, String> {
    let Some(binding) = world.contract_subject_bindings().get(address) else {
        if world.contract_instances().get(address).is_some() {
            return Err(format!(
                "active contract instance `{address}` has no lifecycle binding"
            ));
        }
        return Ok(None);
    };
    binding.validate_for(address)?;
    if world.accounts().get(&binding.subject).is_none() {
        return Err(format!(
            "contract subject account `{}` for `{address}` does not exist",
            binding.subject
        ));
    }
    let indexed_active_code_hash = world.contract_instances().get(address).copied();
    if binding.lifecycle.active_code_hash != indexed_active_code_hash {
        return Err(format!(
            "contract lifecycle active code hash for `{address}` does not match the active-instance index"
        ));
    }
    Ok(Some((binding.subject.clone(), binding.lifecycle.clone())))
}
/// Return the retained contract whose irreversible subject is `subject`.
pub(crate) fn historical_contract_for_subject(
    world: &impl WorldReadOnly,
    subject: &AccountId,
) -> Option<ContractAddress> {
    world.contract_subject_addresses().get(subject).cloned()
}
/// Return whether an account is an irreversible historical contract subject.
pub(crate) fn is_historical_contract_subject(
    world: &impl WorldReadOnly,
    subject: &AccountId,
) -> bool {
    historical_contract_for_subject(world, subject).is_some()
}
/// Return a contract that retains `account` as its current or pending lifecycle owner.
pub(crate) fn contract_owned_or_pending_for_account(
    world: &impl WorldReadOnly,
    account: &AccountId,
) -> Option<ContractAddress> {
    world
        .contract_subject_bindings()
        .iter()
        .find_map(|(address, binding)| {
            let owns = matches!(
                &binding.lifecycle.owner,
                ContractLifecycleOwnerV1::Account(owner) if owner == account
            );
            let pending = matches!(
                binding.lifecycle.pending_owner.as_ref(),
                Some(ContractLifecycleOwnerV1::Account(owner)) if owner == account
            );
            (owns || pending).then(|| address.clone())
        })
}
/// Reject execution while a certified Parliament emergency hold is active.
pub(crate) fn ensure_contract_execution_allowed(
    world: &impl WorldReadOnly,
    address: &ContractAddress,
    height: u64,
) -> Result<(), String> {
    let binding = world
        .contract_subject_bindings()
        .get(address)
        .ok_or_else(|| format!("contract `{address}` has no lifecycle binding"))?;
    binding.validate_for(address)?;
    if binding.lifecycle.is_held_at(height) {
        let hold = binding
            .lifecycle
            .emergency_hold
            .as_ref()
            .expect("active hold predicate requires a retained hold");
        return Err(format!(
            "contract `{address}` execution is held by Parliament through block {}: {}",
            hold.expires_at_height.saturating_sub(1),
            hold.reason
        ));
    }
    Ok(())
}
/// Smart contract registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Underlying instruction execution failed.
    #[error("instruction failed: {0}")]
    Instruction(#[from] crate::smartcontracts::Error),
    /// Contract manifest must declare `code_hash`.
    #[error("manifest.code_hash missing")]
    MissingCodeHash,
    /// Contract manifest must declare `abi_hash`.
    #[error("manifest.abi_hash missing")]
    MissingAbiHash,
    /// Bytecode image is not a valid self-describing IVM contract artifact.
    #[error("invalid contract bytecode: {0}")]
    InvalidCode(String),
}
/// Canonical custom-parameter name for the first-release contract namespace policy.
pub const PROTECTED_CONTRACT_NAMESPACES_PARAMETER: &str = "gov_protected_namespaces";
/// Error returned when the persisted protected-contract namespace policy is malformed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProtectedContractNamespacesError {
    /// The parameter payload is not the canonical array-of-strings shape.
    #[error("`{PROTECTED_CONTRACT_NAMESPACES_PARAMETER}` must be an array of strings")]
    InvalidPayload,
    /// One namespace is not an exact non-empty ASCII token.
    #[error(
        "`{PROTECTED_CONTRACT_NAMESPACES_PARAMETER}` namespaces[{index}] must be a non-empty ASCII token without whitespace or control characters"
    )]
    InvalidNamespace {
        /// Zero-based position of the malformed namespace.
        index: usize,
    },
    /// Namespace entries must be unique so the policy has one canonical representation.
    #[error(
        "`{PROTECTED_CONTRACT_NAMESPACES_PARAMETER}` contains duplicate namespace `{namespace}`"
    )]
    DuplicateNamespace {
        /// Repeated namespace token.
        namespace: String,
    },
}
/// Validate the canonical first-release protected-contract namespace list.
///
/// # Errors
///
/// Returns [`ProtectedContractNamespacesError`] for malformed or duplicate tokens.
pub fn validate_protected_contract_namespaces(
    namespaces: &[String],
) -> Result<(), ProtectedContractNamespacesError> {
    let mut seen = BTreeSet::new();
    for (index, namespace) in namespaces.iter().enumerate() {
        if namespace.is_empty()
            || !namespace.is_ascii()
            || namespace
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(ProtectedContractNamespacesError::InvalidNamespace { index });
        }
        if !seen.insert(namespace.as_str()) {
            return Err(ProtectedContractNamespacesError::DuplicateNamespace {
                namespace: namespace.clone(),
            });
        }
    }
    Ok(())
}
/// Decode the persisted protected-contract namespace policy.
///
/// `Ok(None)` means the parameter is absent. A present parameter is always decoded and validated;
/// callers must propagate an error rather than interpreting malformed state as an empty policy.
///
/// # Errors
///
/// Returns [`ProtectedContractNamespacesError`] when a present payload is not canonical.
pub fn protected_contract_namespaces(
    parameters: &Parameters,
) -> Result<Option<Vec<String>>, ProtectedContractNamespacesError> {
    let id = CustomParameterId::new(
        PROTECTED_CONTRACT_NAMESPACES_PARAMETER
            .parse::<Name>()
            .expect("protected-contract namespace parameter name must remain valid"),
    );
    let Some(custom) = parameters.custom().get(&id) else {
        return Ok(None);
    };
    let namespaces = custom
        .payload()
        .try_into_any_norito::<Vec<String>>()
        .map_err(|_| ProtectedContractNamespacesError::InvalidPayload)?;
    validate_protected_contract_namespaces(&namespaces)?;
    Ok(Some(namespaces))
}
/// Reserved physical durable-state namespace for consensus-managed contract lifecycle markers.
///
/// Raw IVM state syscalls reject this namespace and deployed contracts are always scoped below
/// `sc/<contract-address-digest>/`, so only the runtime can create or consume these records.
pub(crate) const CONTRACT_LIFECYCLE_STATE_PREFIX: &str = "lc";
const CONTRACT_LIFECYCLE_RECORD_MAGIC: [u8; 4] = *b"KLC1";
/// Consensus-bound lifecycle transition awaiting its branded hook.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::smartcontracts::code::PendingContractLifecycle")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, norito::codec::Decode, norito::codec::Encode)]
pub(crate) enum PendingContractLifecycle {
    /// A newly activated instance must execute its `hajimari`/`始まり` hook once.
    Hajimari {
        /// Unique deterministic identity of this activation transition.
        transition_id: Hash,
        /// Code hash activated for the new instance.
        code_hash: Hash,
    },
    /// An existing instance was rebound from one code hash to another and must execute
    /// its `kaizen`/`改善` hook once.
    Kaizen {
        /// Unique deterministic identity of this replacement transition.
        transition_id: Hash,
        /// Code hash that was active immediately before `kaizen`/`改善`.
        previous_code_hash: Hash,
        /// Newly activated code hash whose hook must execute.
        code_hash: Hash,
    },
}
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::codec::Decode,
    norito::codec::Encode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::smartcontracts::code::ContractLifecycleRecordV1")]
struct ContractLifecycleRecordV1 {
    domain: [u8; 4],
    pending: PendingContractLifecycle,
}
impl PendingContractLifecycle {
    /// Code hash whose entrypoint is allowed to consume this transition.
    #[must_use]
    pub(crate) const fn code_hash(self) -> Hash {
        match self {
            Self::Hajimari { code_hash, .. } | Self::Kaizen { code_hash, .. } => code_hash,
        }
    }
    /// Branded entrypoint kind required to consume this transition.
    #[must_use]
    pub(crate) const fn entrypoint_kind(self) -> EntryPointKind {
        match self {
            Self::Hajimari { .. } => EntryPointKind::Hajimari,
            Self::Kaizen { .. } => EntryPointKind::Kaizen,
        }
    }
    fn encode(self) -> Vec<u8> {
        norito::to_bytes(&ContractLifecycleRecordV1 {
            domain: CONTRACT_LIFECYCLE_RECORD_MAGIC,
            pending: self,
        })
        .expect("contract lifecycle record must encode to canonical Norito")
    }
    fn decode(encoded: &[u8]) -> Result<Self, &'static str> {
        let record: ContractLifecycleRecordV1 = norito::decode_from_bytes(encoded)
            .map_err(|_| "lifecycle record is not canonical Norito")?;
        let canonical =
            norito::to_bytes(&record).map_err(|_| "lifecycle record is not canonical Norito")?;
        if canonical.as_slice() != encoded {
            return Err("lifecycle record is not canonical Norito");
        }
        if record.domain != CONTRACT_LIFECYCLE_RECORD_MAGIC {
            return Err("lifecycle record has an invalid domain tag");
        }
        Ok(record.pending)
    }
}
/// Build a pending lifecycle transition with an ABA-resistant deterministic identity.
///
/// The identity binds the current transaction/trigger execution, its transition ordinal, the
/// exact address and lifecycle kind, and both old and new code hashes. Consequently a later
/// deactivate/reactivate or A→B→A sequence cannot recreate the bytes observed by a stale
/// prepared lifecycle call.
pub(crate) fn new_pending_contract_lifecycle(
    state_transaction: &mut StateTransaction<'_, '_>,
    contract_address: &ContractAddress,
    previous_code_hash: Option<Hash>,
    code_hash: Hash,
    kind: EntryPointKind,
) -> Result<PendingContractLifecycle, &'static str> {
    let (execution_identity, ordinal) = state_transaction.next_lifecycle_transition_seed()?;
    let mut preimage = Vec::from(&b"iroha:contract-lifecycle-transition:v1\0"[..]);
    preimage.extend_from_slice(execution_identity.as_ref());
    preimage.extend_from_slice(&ordinal.to_le_bytes());
    preimage.extend_from_slice(
        &u64::try_from(contract_address.as_str().len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    preimage.extend_from_slice(contract_address.as_str().as_bytes());
    preimage.push(match kind {
        EntryPointKind::Hajimari => 0,
        EntryPointKind::Kaizen => 1,
        EntryPointKind::Kotoage | EntryPointKind::View => {
            return Err("ordinary entrypoint kind cannot stage a lifecycle transition");
        }
    });
    if let Some(previous_code_hash) = previous_code_hash {
        preimage.push(1);
        preimage.extend_from_slice(previous_code_hash.as_ref());
    } else {
        preimage.push(0);
    }
    preimage.extend_from_slice(code_hash.as_ref());
    let transition_id = Hash::new(preimage);
    match (kind, previous_code_hash) {
        (EntryPointKind::Hajimari, None) => Ok(PendingContractLifecycle::Hajimari {
            transition_id,
            code_hash,
        }),
        (EntryPointKind::Kaizen, Some(previous_code_hash)) => {
            Ok(PendingContractLifecycle::Kaizen {
                transition_id,
                previous_code_hash,
                code_hash,
            })
        }
        (EntryPointKind::Hajimari, Some(_)) => {
            Err("hajimari/始まり cannot stage a previous code hash")
        }
        (EntryPointKind::Kaizen, None) => Err("kaizen/改善 requires a previous code hash"),
        (EntryPointKind::Kotoage | EntryPointKind::View, _) => {
            Err("ordinary entrypoint kind cannot stage a lifecycle transition")
        }
    }
}
/// Return the reserved physical durable-state key for an instance lifecycle marker.
#[must_use]
pub(crate) fn contract_lifecycle_state_key(contract_address: &ContractAddress) -> StatePath {
    let digest = hex::encode(Hash::new(contract_address.as_str().as_bytes()).as_ref());
    format!("{CONTRACT_LIFECYCLE_STATE_PREFIX}/{digest}")
        .parse()
        .expect("contract lifecycle state key is a valid StatePath")
}
/// Read and validate the pending lifecycle transition for `contract_address`.
///
/// Corrupt records fail closed because they are consensus state, not user input.
pub(crate) fn pending_contract_lifecycle(
    world: &impl WorldReadOnly,
    contract_address: &ContractAddress,
) -> Result<Option<PendingContractLifecycle>, ValidationFail> {
    let key = contract_lifecycle_state_key(contract_address);
    world
        .smart_contract_state()
        .get(&key)
        .map(|encoded| {
            PendingContractLifecycle::decode(encoded).map_err(|reason| {
                ValidationFail::InternalError(format!(
                    "invalid lifecycle state for contract `{contract_address}`: {reason}"
                ))
            })
        })
        .transpose()
}
/// Stage or clear the runtime-owned pending lifecycle marker.
pub(crate) fn set_pending_contract_lifecycle(
    state_transaction: &mut StateTransaction<'_, '_>,
    contract_address: &ContractAddress,
    pending: Option<PendingContractLifecycle>,
) {
    let key = contract_lifecycle_state_key(contract_address);
    if let Some(pending) = pending {
        state_transaction
            .world
            .smart_contract_state
            .insert(key, pending.encode());
    } else {
        state_transaction.world.smart_contract_state.remove(key);
    }
}
/// Validate lifecycle availability for a top-level call against the live binding.
///
/// A pending transition blocks all other entrypoints, including views, until its exact branded
/// hook succeeds. The returned transition is attached to the runtime context so successful VM
/// execution can consume the marker atomically with the rest of its overlay.
pub(crate) fn validate_contract_lifecycle_call(
    world: &impl WorldReadOnly,
    contract_address: &ContractAddress,
    executing_code_hash: Hash,
    kind: EntryPointKind,
) -> Result<Option<PendingContractLifecycle>, ValidationFail> {
    let bound_code_hash = world
        .contract_instances()
        .get(contract_address)
        .copied()
        .ok_or_else(|| {
            ValidationFail::NotPermitted(format!(
                "contract instance `{contract_address}` is not active"
            ))
        })?;
    if bound_code_hash != executing_code_hash {
        return Err(ValidationFail::NotPermitted(format!(
            "contract instance `{contract_address}` changed from code `{executing_code_hash}` to `{bound_code_hash}`"
        )));
    }
    let pending = pending_contract_lifecycle(world, contract_address)?;
    match (kind, pending) {
        (EntryPointKind::Hajimari, Some(pending @ PendingContractLifecycle::Hajimari { .. }))
            if pending.code_hash() == executing_code_hash =>
        {
            Ok(Some(pending))
        }
        (EntryPointKind::Kaizen, Some(pending @ PendingContractLifecycle::Kaizen { .. }))
            if pending.code_hash() == executing_code_hash =>
        {
            Ok(Some(pending))
        }
        (EntryPointKind::Hajimari, Some(other)) => Err(ValidationFail::NotPermitted(format!(
            "contract `{contract_address}` is awaiting {:?}, not hajimari/始まり",
            other.entrypoint_kind()
        ))),
        (EntryPointKind::Kaizen, Some(other)) => Err(ValidationFail::NotPermitted(format!(
            "contract `{contract_address}` is awaiting {:?}, not kaizen/改善",
            other.entrypoint_kind()
        ))),
        (EntryPointKind::Hajimari, None) => Err(ValidationFail::NotPermitted(format!(
            "contract `{contract_address}` has no pending hajimari/始まり transition"
        ))),
        (EntryPointKind::Kaizen, None) => Err(ValidationFail::NotPermitted(format!(
            "contract `{contract_address}` has no pending kaizen/改善 transition"
        ))),
        (EntryPointKind::Kotoage | EntryPointKind::View, Some(pending)) => {
            Err(ValidationFail::NotPermitted(format!(
                "contract `{contract_address}` must complete {:?} before other entrypoints are callable",
                pending.entrypoint_kind()
            )))
        }
        (EntryPointKind::Kotoage | EntryPointKind::View, None) => Ok(None),
    }
}
/// Recheck a prepared lifecycle completion against current state immediately before apply.
pub(crate) fn validate_contract_lifecycle_completion(
    world: &impl WorldReadOnly,
    contract_address: &ContractAddress,
    expected: PendingContractLifecycle,
) -> Result<(), ValidationFail> {
    let current = pending_contract_lifecycle(world, contract_address)?;
    if current != Some(expected) {
        return Err(ValidationFail::NotPermitted(format!(
            "pending hajimari/始まり or kaizen/改善 transition for `{contract_address}` changed before apply"
        )));
    }
    if world.contract_instances().get(contract_address).copied() != Some(expected.code_hash()) {
        return Err(ValidationFail::NotPermitted(format!(
            "contract binding for `{contract_address}` changed before lifecycle apply"
        )));
    }
    Ok(())
}
/// Reject a view while its instance is awaiting `hajimari`/`始まり` or `kaizen`/`改善`.
///
/// # Errors
/// Returns an error when the binding changed, the lifecycle marker is corrupt, or a transition
/// is still pending.
pub fn ensure_contract_ready_for_view(
    world: &impl WorldReadOnly,
    contract_address: &ContractAddress,
    executing_code_hash: Hash,
) -> Result<(), ValidationFail> {
    validate_contract_lifecycle_call(
        world,
        contract_address,
        executing_code_hash,
        EntryPointKind::View,
    )
    .map(|_| ())
}
/// Validate lifecycle availability for a non-mutating simulation of a top-level entrypoint.
///
/// # Errors
/// Returns an error when the entrypoint does not match the exact pending activation transition.
pub fn ensure_contract_entrypoint_lifecycle(
    world: &impl WorldReadOnly,
    contract_address: &ContractAddress,
    executing_code_hash: Hash,
    kind: EntryPointKind,
) -> Result<(), ValidationFail> {
    validate_contract_lifecycle_call(world, contract_address, executing_code_hash, kind).map(|_| ())
}
/// Record combining a contract manifest with optional bytecode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractCodeRecord {
    /// Manifest stored under the `code_hash` key.
    pub manifest: ContractManifest,
    /// Optional compiled bytecode bytes (entire `.to` image).
    pub code_bytes: Option<Vec<u8>>,
}
#[cfg(any(test, feature = "iroha-core-tests"))]
/// Register a smart contract manifest on-chain via the canonical ISI.
///
/// Any registered authority may publish an exact artifact manifest signed by its own key.
/// Publication pays normal transaction fees and cannot create a contract address. Namespaces listed
/// in `gov_protected_namespaces` remain deployable only through Parliament.
/// The manifest must include `code_hash` and `abi_hash`, and the corresponding
/// bytecode must already be stored as a verified self-describing artifact.
///
/// # Errors
///
/// Returns [`RegistryError`] when the manifest is missing a required hash or
/// the underlying `RegisterSmartContractCode` instruction fails during execution.
pub fn register_manifest(
    authority: &AccountId,
    dataspace_id: iroha_model_base::topology::DataSpaceId,
    manifest: ContractManifest,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), RegistryError> {
    if manifest.code_hash.is_none() {
        return Err(RegistryError::MissingCodeHash);
    }
    if manifest.abi_hash.is_none() {
        return Err(RegistryError::MissingAbiHash);
    }
    RegisterSmartContractCode {
        artifact_id: ContractArtifactId::new(
            dataspace_id,
            manifest.code_hash.ok_or(RegistryError::MissingCodeHash)?,
        ),
        manifest,
    }
    .execute(authority, state_transaction)?;
    Ok(())
}
#[cfg(any(test, feature = "iroha-core-tests"))]
/// Register compiled contract bytecode on-chain and return its `code_hash`.
///
/// The helper verifies the self-describing `CNTR` artifact, uses its canonical
/// artifact hash, and submits the [`RegisterSmartContractBytes`] instruction.
/// The authority must be registered; normal transaction fee admission applies.
///
/// # Errors
///
/// Returns [`RegistryError`] when the bytecode header is invalid or when the
/// underlying instruction execution fails.
pub fn register_code_bytes(
    authority: &AccountId,
    dataspace_id: iroha_model_base::topology::DataSpaceId,
    code: Vec<u8>,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<Hash, RegistryError> {
    let verified = ivm::verify_contract_artifact_with_memory_budget(
        &code,
        &state_transaction.execution_budget(),
    )
    .map_err(|error| {
        if let Some(local) = error.local_vm_error()
            && let Some(reason) = crate::execution_attempt::ExecutionDeferred::from_vm_error(&local)
        {
            return RegistryError::Instruction(
                state_transaction.world.attempt_error_to_instruction_error(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(reason),
                ),
            );
        }
        RegistryError::InvalidCode(error.to_string())
    })?;
    let code_hash = verified.code_hash;
    RegisterSmartContractBytes {
        artifact_id: ContractArtifactId::new(dataspace_id, code_hash),
        code,
    }
    .execute(authority, state_transaction)?;
    Ok(code_hash)
}
#[cfg(any(test, feature = "iroha-core-tests"))]
/// Bind `contract_address` to a `code_hash` at an exact lifecycle revision.
///
/// The address must already have a retained lifecycle record owned by
/// `authority`. A stale `expected_revision` fails closed. Rebinding an active
/// address is a genuine in-place `kaizen`/`改善` and stages its declared hook.
///
/// # Errors
///
/// Returns [`RegistryError`] when the activation instruction fails during execution.
pub fn activate_instance(
    authority: &AccountId,
    contract_address: ContractAddress,
    expected_revision: u64,
    code_hash: Hash,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), RegistryError> {
    ActivateContractInstance {
        contract_address,
        expected_revision,
        code_hash,
    }
    .execute(authority, state_transaction)?;
    Ok(())
}
/// Fetch the manifest stored for `artifact_id`, if any.
///
/// # Errors
/// Returns a scope rejection or the original local decode refusal without treating it as absence.
pub fn fetch_manifest(
    state: &impl StateReadOnly,
    artifact_id: &ContractArtifactId,
) -> Result<Option<ContractManifest>, ExecutionAttemptError<ValidationFail>> {
    crate::executor::root_scope::ensure_committed_artifact_scope(state.world(), artifact_id)?;
    Ok(state.world().contract_manifests().get(artifact_id).cloned())
}
/// Fetch the stored bytecode for `artifact_id`, if any.
///
/// # Errors
/// Returns a scope rejection or the original local decode refusal without treating it as absence.
pub fn fetch_code_bytes(
    state: &impl StateReadOnly,
    artifact_id: &ContractArtifactId,
) -> Result<Option<Vec<u8>>, ExecutionAttemptError<ValidationFail>> {
    crate::executor::root_scope::ensure_committed_artifact_scope(state.world(), artifact_id)?;
    Ok(state.world().contract_code().get(artifact_id).cloned())
}
/// Retrieve a combined record (manifest + optional bytecode) for `artifact_id`.
///
/// # Errors
/// Returns a scope rejection or the original local decode refusal without treating it as absence.
pub fn fetch_record(
    state: &impl StateReadOnly,
    artifact_id: &ContractArtifactId,
) -> Result<Option<ContractCodeRecord>, ExecutionAttemptError<ValidationFail>> {
    let Some(manifest) = fetch_manifest(state, artifact_id)? else {
        return Ok(None);
    };
    let code_bytes = fetch_code_bytes(state, artifact_id)?;
    Ok(Some(ContractCodeRecord {
        manifest,
        code_bytes,
    }))
}
/// Batched contract lookup combining manifest, bytecode, and optional binding lookup.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContractArtifacts {
    /// Stored manifest for `code_hash`, if any.
    pub manifest: Option<ContractManifest>,
    /// Stored bytecode for `code_hash`, if any.
    pub code_bytes: Option<Vec<u8>>,
    /// Code hash bound to `contract_address`, if a binding exists.
    pub bound_code_hash: Option<Hash>,
}
/// Fully resolved on-chain contract instance record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundContractRecord {
    /// Canonical instance address used to resolve the binding.
    pub contract_address: ContractAddress,
    /// Consensus-persisted runtime authority for this exact address.
    pub contract_subject: AccountId,
    /// Optional stable alias currently bound to the instance.
    pub contract_alias: Option<ContractAlias>,
    /// Complete alias binding record captured with the instance, including lease provenance.
    pub contract_alias_binding: Option<crate::state::ContractAliasBindingRecord>,
    /// Code hash currently bound to the instance.
    pub code_hash: Hash,
    /// Stored manifest for the bound code hash.
    pub manifest: ContractManifest,
    /// Stored bytecode for the bound code hash.
    pub code_bytes: Vec<u8>,
}
/// Lightweight bound-instance identity that never copies contract bytecode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundContractIdentity {
    /// Canonical instance address used to resolve the binding.
    pub contract_address: ContractAddress,
    /// Optional stable alias currently bound to the instance.
    pub contract_alias: Option<ContractAlias>,
    /// Complete alias binding record captured with the instance, including lease provenance.
    pub contract_alias_binding: Option<crate::state::ContractAliasBindingRecord>,
    /// Code hash currently bound to the instance.
    pub code_hash: Hash,
}
/// Fetch manifest, code bytes, and instance binding in a single pass.
///
/// # Errors
/// Returns a scope rejection or the original local decode refusal without treating it as absence.
pub fn fetch_artifacts(
    state: &impl StateReadOnly,
    artifact_id: &ContractArtifactId,
    binding: Option<&ContractAddress>,
) -> Result<ContractArtifacts, ExecutionAttemptError<ValidationFail>> {
    let manifest = fetch_manifest(state, artifact_id)?;
    let code_bytes = fetch_code_bytes(state, artifact_id)?;
    let bound_code_hash = binding
        .filter(|address| address.dataspace_id().ok() == Some(artifact_id.dataspace_id))
        .and_then(|contract_address| {
            state
                .world()
                .contract_instances()
                .get(contract_address)
                .copied()
        });
    Ok(ContractArtifacts {
        manifest,
        code_bytes,
        bound_code_hash,
    })
}
/// Return the code hash bound to `contract_address`, if any.
///
/// # Errors
/// Returns a scope rejection or the original local decode refusal without treating it as absence.
pub fn fetch_instance_binding(
    state: &impl StateReadOnly,
    contract_address: &ContractAddress,
) -> Result<Option<Hash>, ExecutionAttemptError<ValidationFail>> {
    let Some(hash) = state
        .world()
        .contract_instances()
        .get(contract_address)
        .copied()
    else {
        return Ok(None);
    };
    let Ok(artifact_id) = ContractArtifactId::for_address(contract_address, hash) else {
        return Ok(None);
    };
    crate::executor::root_scope::ensure_committed_artifact_scope(state.world(), &artifact_id)?;
    Ok(Some(hash))
}
/// Resolve the consensus-persisted runtime authority for an active contract instance.
#[must_use]
pub fn fetch_bound_contract_subject(
    state: &impl StateReadOnly,
    contract_address: &ContractAddress,
) -> Option<AccountId> {
    bound_contract_subject_from_world(state.world(), contract_address)
}
/// Resolve a validated active contract authority directly from a world-state view.
#[must_use]
pub(crate) fn bound_contract_subject_from_world(
    world: &impl WorldReadOnly,
    contract_address: &ContractAddress,
) -> Option<AccountId> {
    borrow_bound_contract_subject_from_world(world, contract_address).cloned()
}
/// Borrow the validated consensus-persisted runtime authority for an active contract.
///
/// Read paths which immediately serialize the subject can avoid cloning a potentially nested
/// account controller by keeping the world view alive for the duration of the checked write.
#[must_use]
pub fn borrow_bound_contract_subject_from_world<'a>(
    world: &'a impl WorldReadOnly,
    contract_address: &ContractAddress,
) -> Option<&'a AccountId> {
    let code_hash = world.contract_instances().get(contract_address)?;
    let artifact_id = ContractArtifactId::for_address(contract_address, *code_hash).ok()?;
    crate::executor::root_scope::ensure_committed_artifact_scope(world, &artifact_id).ok()?;
    let binding = world.contract_subject_bindings().get(contract_address)?;
    binding.validate_for(contract_address).ok()?;
    if binding.lifecycle.active_code_hash.as_ref() != Some(code_hash) {
        return None;
    }
    world.accounts().get(&binding.subject)?;
    Some(&binding.subject)
}
/// Resolve a bound instance without cloning its manifest or bytecode.
///
/// # Errors
/// Returns a scope rejection or the original local decode refusal without treating it as absence.
pub fn fetch_bound_contract_identity(
    state: &impl StateReadOnly,
    contract_address: &ContractAddress,
) -> Result<Option<BoundContractIdentity>, ExecutionAttemptError<ValidationFail>> {
    let Some(code_hash) = fetch_instance_binding(state, contract_address)? else {
        return Ok(None);
    };
    if fetch_bound_contract_subject(state, contract_address).is_none() {
        return Ok(None);
    }
    let contract_alias_binding = state
        .world()
        .contract_alias_bindings()
        .get(contract_address)
        .cloned();
    let contract_alias = contract_alias_binding
        .as_ref()
        .map(|binding| binding.alias.clone());
    if let Some(alias) = contract_alias.as_ref()
        && state.world().contract_aliases().get(alias) != Some(contract_address)
    {
        return Ok(None);
    }
    Ok(Some(BoundContractIdentity {
        contract_address: contract_address.clone(),
        contract_alias,
        contract_alias_binding,
        code_hash,
    }))
}
/// Borrow stored bytecode only for the duration of `use_bytes`.
///
/// This lets content-addressed cache misses prepare directly from world state
/// without first cloning the complete deployable image.
///
/// # Errors
/// Returns a scope rejection or the original local decode refusal without treating it as absence.
pub fn with_code_bytes<T>(
    state: &impl StateReadOnly,
    artifact_id: &ContractArtifactId,
    use_bytes: impl FnOnce(&[u8]) -> T,
) -> Result<Option<T>, ExecutionAttemptError<ValidationFail>> {
    crate::executor::root_scope::ensure_committed_artifact_scope(state.world(), artifact_id)?;
    Ok(state
        .world()
        .contract_code()
        .get(artifact_id)
        .map(|bytes| use_bytes(bytes.as_ref())))
}
/// Resolve the fully bound contract instance record for `contract_address`.
///
/// # Errors
/// Returns a scope rejection or the original local decode refusal without treating it as absence.
pub fn fetch_bound_contract_record(
    state: &impl StateReadOnly,
    contract_address: &ContractAddress,
) -> Result<Option<BoundContractRecord>, ExecutionAttemptError<ValidationFail>> {
    let Some(code_hash) = fetch_instance_binding(state, contract_address)? else {
        return Ok(None);
    };
    let Some(contract_subject) =
        borrow_bound_contract_subject_from_world(state.world(), contract_address)
    else {
        return Ok(None);
    };
    let Ok(artifact_id) = ContractArtifactId::for_address(contract_address, code_hash) else {
        return Ok(None);
    };
    let Some(manifest) = fetch_manifest(state, &artifact_id)? else {
        return Ok(None);
    };
    let Some(code_bytes) = fetch_code_bytes(state, &artifact_id)? else {
        return Ok(None);
    };
    let contract_alias_binding = state
        .world()
        .contract_alias_bindings()
        .get(contract_address)
        .cloned();
    let contract_alias = contract_alias_binding
        .as_ref()
        .map(|binding| binding.alias.clone());
    if let Some(alias) = contract_alias.as_ref()
        && state.world().contract_aliases().get(alias) != Some(contract_address)
    {
        return Ok(None);
    }
    Ok(Some(BoundContractRecord {
        contract_address: contract_address.clone(),
        contract_subject: contract_subject.clone(),
        contract_alias,
        contract_alias_binding,
        code_hash,
        manifest,
        code_bytes,
    }))
}
/// Resolve the fully bound contract instance record for a deterministic contract subject.
///
/// # Errors
/// Returns a scope rejection or the original local decode refusal without treating it as absence.
pub fn fetch_bound_contract_record_by_subject(
    state: &impl StateReadOnly,
    contract_subject: &AccountId,
) -> Result<Option<BoundContractRecord>, ExecutionAttemptError<ValidationFail>> {
    let Some(contract_address) = state
        .world()
        .contract_subject_addresses()
        .get(contract_subject)
    else {
        return Ok(None);
    };
    fetch_bound_contract_record(state, contract_address)
}
/// Snapshot all deployed contract instance records keyed by deterministic contract subject.
///
/// # Errors
/// Returns the original incomplete read when immutable scope cannot be decoded locally.
/// No partially built snapshot is returned on refusal.
pub fn snapshot_bound_contract_records_by_subject(
    state: &impl StateReadOnly,
) -> Result<BTreeMap<AccountId, BoundContractRecord>, ExecutionAttemptError<ValidationFail>> {
    let mut records = BTreeMap::new();
    for (contract_address, _) in state.world().contract_instances().iter() {
        if let Some(record) = fetch_bound_contract_record(state, contract_address)? {
            records.insert(record.contract_subject.clone(), record);
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        isi::{
            Grant, SetParameter,
            error::{InstructionExecutionError, InvalidParameterError},
            smart_contract_code::DeactivateContractInstance,
        },
        parameter::custom::{CustomParameter, CustomParameterId},
        permission,
        prelude::*,
        smart_contract::manifest::{EntryPointKind, EntrypointDescriptor},
    };
    use iroha_executor_data_model::permission::parameter::CanSetParameters;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("smart contract code fixture key generation should succeed")
    }
    fn protected_namespaces_parameter(payload: iroha_primitives::json::Json) -> CustomParameter {
        CustomParameter::new(
            CustomParameterId::new(
                PROTECTED_CONTRACT_NAMESPACES_PARAMETER
                    .parse()
                    .expect("protected namespace parameter id"),
            ),
            payload,
        )
    }
    #[test]
    fn checked_keypair_preserves_default_algorithm() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    }
    #[test]
    fn protected_namespace_policy_distinguishes_absent_valid_and_malformed_state() {
        let mut parameters = Parameters::default();
        assert_eq!(
            protected_contract_namespaces(&parameters).expect("absent policy is valid"),
            None
        );

        parameters.set_parameter(Parameter::Custom(protected_namespaces_parameter(
            iroha_primitives::json::Json::new(vec!["apps".to_owned(), "dataspace:0".to_owned()]),
        )));
        assert_eq!(
            protected_contract_namespaces(&parameters).expect("canonical policy"),
            Some(vec!["apps".to_owned(), "dataspace:0".to_owned()])
        );

        parameters.set_parameter(Parameter::Custom(protected_namespaces_parameter(
            iroha_primitives::json::Json::new("apps"),
        )));
        assert_eq!(
            protected_contract_namespaces(&parameters),
            Err(ProtectedContractNamespacesError::InvalidPayload)
        );
    }
    #[test]
    fn protected_namespace_policy_rejects_noncanonical_and_duplicate_tokens() {
        for (namespaces, expected) in [
            (
                vec![" apps".to_owned()],
                ProtectedContractNamespacesError::InvalidNamespace { index: 0 },
            ),
            (
                vec!["système".to_owned()],
                ProtectedContractNamespacesError::InvalidNamespace { index: 0 },
            ),
            (
                vec!["apps".to_owned(), "apps".to_owned()],
                ProtectedContractNamespacesError::DuplicateNamespace {
                    namespace: "apps".to_owned(),
                },
            ),
        ] {
            assert_eq!(
                validate_protected_contract_namespaces(&namespaces),
                Err(expected)
            );
        }
    }
    fn minimal_contract_artifact(
        abi_version: u8,
    ) -> (
        Vec<u8>,
        iroha_data_model::smart_contract::manifest::ContractManifest,
    ) {
        let meta = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 4,
            abi_version,
        };
        let entrypoint = EntrypointDescriptor {
            name: "main".to_owned(),
            kind: EntryPointKind::View,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            permission: None,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: None,
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
        };
        let interface = ivm::EmbeddedContractInterfaceV1 {
            callables: vec![ivm::call::EmbeddedCallableV1 {
                entry_pc: 0,
                frame_bytes: 0,
                arguments: ivm::call::CallSchemaV1::empty(),
                results: ivm::call::CallSchemaV1::unit(),
            }],
            seiyaku_name: "TestContract".to_owned(),
            compiler_fingerprint: "iroha-core-test".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
                name: entrypoint.name.clone(),
                kind: entrypoint.kind,
                params: entrypoint.params.clone(),
                argument_schema: entrypoint.argument_schema.clone(),
                return_type: entrypoint.return_type.clone(),
                return_schema: entrypoint.return_schema.clone(),
                permission: entrypoint.permission.clone(),
                read_keys: entrypoint.read_keys.clone(),
                write_keys: entrypoint.write_keys.clone(),
                access_hints_complete: entrypoint.access_hints_complete,
                access_hints_skipped: entrypoint.access_hints_skipped.clone(),
                triggers: entrypoint.triggers.clone(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let mut code = Vec::new();
        for instruction in [
            ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
            ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
            ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
            ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
        ] {
            code.extend_from_slice(&instruction.to_le_bytes());
        }
        let mut out = meta.encode();
        out.extend_from_slice(&interface.encode_section());
        out.extend_from_slice(&code);
        let verified = ivm::verify_contract_artifact(&out).expect("valid test contract artifact");
        (out, verified.manifest)
    }
    fn minimal_ivm_program(abi_version: u8) -> Vec<u8> {
        minimal_contract_artifact(abi_version).0
    }
    fn lifecycle_contract(
        source: &str,
    ) -> (
        Vec<u8>,
        iroha_data_model::smart_contract::manifest::ContractManifest,
    ) {
        kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile lifecycle contract")
    }
    fn test_state() -> (State, AccountId, KeyPair) {
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let kp = checked_keypair();
        let (pubkey, _) = kp.clone().into_parts();
        let dom: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let auth = AccountId::of(pubkey);
        let domain = Domain::new(dom.clone()).build(&auth);
        let account = Account::new(auth.clone()).build(&auth);
        let mut world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
        let mut parameters = world.parameters.block();
        parameters.set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ));
        parameters.commit();
        let mut permissions = permission::Permissions::new();
        assert!(
            permissions.insert(
                iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode
                    .into(),
            )
        );
        world
            .account_permissions_mut_for_testing()
            .insert(auth.clone(), permissions);
        let state = State::new_for_testing(world, kura, query);
        (state, auth, kp)
    }
    fn default_header(height: u64) -> iroha_data_model::block::BlockHeader {
        iroha_data_model::block::BlockHeader::new(
            core::num::NonZeroU64::new(height).expect("block height must be non-zero"),
            None,
            None,
            0,
            0,
        )
    }
    #[test]
    fn artifact_reads_reject_foreign_private_scope_even_when_storage_contains_it() {
        let (state, _, _) = test_state();
        let mut block = state.block(default_header(1));
        let mut transaction = block.transaction();
        let dataspace_id = iroha_model_base::topology::DataSpaceId::new(u64::MAX);
        transaction.world.parameters.set_parameter(
            crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
                    parent_network_id: state.network_id,
                    dataspace_id,
                },
            ),
        );
        let (bytes, manifest) = minimal_contract_artifact(1);
        let hash = ivm::contract_code_hash(&bytes);
        let owned = ContractArtifactId::new(dataspace_id, hash);
        let foreign =
            ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, hash);
        for artifact in [owned, foreign] {
            transaction
                .world
                .contract_code
                .insert(artifact, bytes.clone());
            transaction
                .world
                .contract_manifests
                .insert(artifact, manifest.clone());
        }
        assert_eq!(
            fetch_code_bytes(&transaction, &owned).expect("registry read completes"),
            Some(bytes)
        );
        assert_eq!(
            fetch_manifest(&transaction, &owned).expect("registry read completes"),
            Some(manifest)
        );
        assert!(matches!(
            fetch_code_bytes(&transaction, &foreign),
            Err(ExecutionAttemptError::Rejected(
                ValidationFail::NotPermitted(_)
            ))
        ));
        assert!(matches!(
            fetch_manifest(&transaction, &foreign),
            Err(ExecutionAttemptError::Rejected(
                ValidationFail::NotPermitted(_)
            ))
        ));
        assert!(matches!(
            with_code_bytes(&transaction, &foreign, <[u8]>::len),
            Err(ExecutionAttemptError::Rejected(
                ValidationFail::NotPermitted(_)
            ))
        ));
        assert!(matches!(
            fetch_record(&transaction, &foreign),
            Err(ExecutionAttemptError::Rejected(
                ValidationFail::NotPermitted(_)
            ))
        ));
    }
    #[test]
    fn registry_roundtrip_manifest_and_code() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (state, authority, kp) = test_state();
        let mut block = state.block(default_header(1));
        let mut stx = block.transaction();
        // Register bytecode and manifest, then activate an authorized namespace binding.
        let (code, manifest) = minimal_contract_artifact(1);
        let code_hash = register_code_bytes(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code.clone(),
            &mut stx,
        )
        .expect("register bytecode");
        let manifest = manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        register_manifest(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            manifest.clone(),
            &mut stx,
        )
        .expect("register manifest");
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        stx.world.bind_inactive_contract_subject_for_testing(
            contract_address.clone(),
            authority.clone(),
        );
        activate_instance(&authority, contract_address.clone(), 1, code_hash, &mut stx)
            .expect("activate instance");
        assert_eq!(
            pending_contract_lifecycle(&stx.world, &contract_address)
                .expect("valid lifecycle state"),
            None,
            "contracts without hajimari remain immediately callable"
        );
        let alias = ContractAlias::from_components("registry", Some("wonderland"), "universal")
            .expect("valid contract alias");
        stx.world
            .bind_contract_alias(&contract_address, alias.clone(), None, None, 0)
            .expect("bind contract alias");
        assert_eq!(
            fetch_bound_contract_identity(&stx, &contract_address)
                .expect("registry read completes")
                .expect("consistent alias binding is callable")
                .contract_alias,
            Some(alias.clone())
        );
        stx.world.contract_aliases.remove(alias.clone());
        assert!(
            fetch_bound_contract_identity(&stx, &contract_address)
                .expect("registry read completes")
                .is_none(),
            "a forward-only alias binding must fail closed before contract execution"
        );
        stx.world
            .contract_aliases
            .insert(alias, contract_address.clone());
        stx.world.clear_contract_alias(&contract_address);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit block");
        let view = state.view();
        // Manifest fetch
        let got_manifest = fetch_manifest(
            &view,
            &iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                code_hash,
            ),
        )
        .expect("registry read completes")
        .expect("manifest stored");
        assert_eq!(got_manifest, manifest);
        // Bytecode fetch
        let got_code = fetch_code_bytes(
            &view,
            &iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                code_hash,
            ),
        )
        .expect("registry read completes")
        .expect("code stored");
        assert_eq!(got_code, code);
        // Combined record fetch
        let record = fetch_record(
            &view,
            &iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                code_hash,
            ),
        )
        .expect("registry read completes")
        .expect("record exists");
        assert_eq!(record.manifest, manifest);
        assert_eq!(record.code_bytes.as_deref(), Some(code.as_slice()));
        // Instance binding fetch
        let bound = fetch_instance_binding(&view, &contract_address)
            .expect("registry read completes")
            .expect("binding exists");
        assert_eq!(bound, code_hash);
        let identity = fetch_bound_contract_identity(&view, &contract_address)
            .expect("registry read completes")
            .expect("lightweight binding exists");
        assert_eq!(identity.contract_address, contract_address);
        assert_eq!(identity.code_hash, code_hash);
        assert_eq!(identity.contract_alias, None);
        let artifact_id = ContractArtifactId::for_address(&contract_address, code_hash)
            .expect("contract address retains its exact artifact dataspace");
        let borrowed = with_code_bytes(&view, &artifact_id, |bytes| {
            (bytes.as_ptr(), bytes.to_vec())
        })
        .expect("registry read completes")
        .expect("borrow stored bytes");
        assert_eq!(borrowed.1, code);
        let stored_ptr = view
            .world()
            .contract_code()
            .get(&artifact_id)
            .expect("stored bytes")
            .as_ptr();
        assert_eq!(borrowed.0, stored_ptr, "borrow helper must not clone bytes");
    }
    #[test]
    fn protected_contract_activation_uses_existing_owner_lifecycle() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (state, authority, kp) = test_state();
        let mut block = state.block(default_header(1));
        let mut stx = block.transaction();
        // Namespace protection applies to address deployment. Once Parliament has
        // established a lifecycle binding, its owner may perform revision-CAS activation.
        let set_params: permission::Permission = CanSetParameters.into();
        Grant::account_permission(set_params, authority.clone())
            .execute(&authority, &mut stx)
            .expect("grant CanSetParameters");
        // Protect the `apps` namespace.
        let id = CustomParameterId("gov_protected_namespaces".parse().unwrap());
        let payload = iroha_primitives::json::Json::from(
            norito::json::array(["apps"]).expect("serialize protected namespaces"),
        );
        let custom = CustomParameter::new(id, payload);
        SetParameter::new(Parameter::Custom(custom))
            .execute(&authority, &mut stx)
            .expect("set protected namespaces");
        // Register code + manifest and activate under governance protection.
        let (code, manifest) = minimal_contract_artifact(1);
        let code_hash = register_code_bytes(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code.clone(),
            &mut stx,
        )
        .expect("register bytecode");
        let manifest = manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &kp,
            )
            .expect("sign bounded fixture manifest");
        register_manifest(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            manifest,
            &mut stx,
        )
        .expect("register manifest");
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            1,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        stx.world.bind_inactive_contract_subject_for_testing(
            contract_address.clone(),
            authority.clone(),
        );
        activate_instance(&authority, contract_address.clone(), 1, code_hash, &mut stx)
            .expect("governed activation");
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit block");
        let view = state.view();
        let bound = fetch_instance_binding(&view, &contract_address)
            .expect("registry read completes")
            .expect("binding exists");
        assert_eq!(bound, code_hash);
    }
    #[test]
    fn lifecycle_hooks_are_single_use_and_bound_to_real_activation_transitions() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (state, authority, keypair) = test_state();
        let mut block = state.block(default_header(1));
        let mut transaction = block.transaction();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            7,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        transaction
            .world
            .bind_inactive_contract_subject_for_testing(
                contract_address.clone(),
                authority.clone(),
            );
        let (v1_code, v1_manifest) = lifecycle_contract(
            r#"
seiyaku LifecycleOne {
  hajimari() {}
  kaizen() {}
  kotoage fn run() authorize("CanRunLifecycleOne") {}
}
"#,
        );
        let v1_hash = register_code_bytes(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            v1_code,
            &mut transaction,
        )
        .expect("register v1 bytecode");
        register_manifest(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            v1_manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &keypair,
                )
                .expect("sign bounded fixture manifest"),
            &mut transaction,
        )
        .expect("register v1 manifest");
        activate_instance(
            &authority,
            contract_address.clone(),
            1,
            v1_hash,
            &mut transaction,
        )
        .expect("activate v1");
        let hajimari = pending_contract_lifecycle(&transaction.world, &contract_address)
            .expect("valid lifecycle state")
            .expect("activation staged hajimari");
        assert!(matches!(
            hajimari,
            PendingContractLifecycle::Hajimari { code_hash, .. } if code_hash == v1_hash
        ));
        assert_eq!(
            validate_contract_lifecycle_call(
                &transaction.world,
                &contract_address,
                v1_hash,
                EntryPointKind::Hajimari,
            )
            .expect("new activation admits hajimari"),
            Some(hajimari)
        );
        assert!(
            validate_contract_lifecycle_call(
                &transaction.world,
                &contract_address,
                v1_hash,
                EntryPointKind::Kotoage,
            )
            .is_err(),
            "ordinary calls must wait for hajimari"
        );
        assert!(
            validate_contract_lifecycle_call(
                &transaction.world,
                &contract_address,
                v1_hash,
                EntryPointKind::Kaizen,
            )
            .is_err(),
            "a fresh activation is not a kaizen transition"
        );
        validate_contract_lifecycle_completion(&transaction.world, &contract_address, hajimari)
            .expect("live completion matches pending hajimari");
        set_pending_contract_lifecycle(&mut transaction, &contract_address, None);
        assert!(
            validate_contract_lifecycle_call(
                &transaction.world,
                &contract_address,
                v1_hash,
                EntryPointKind::Hajimari,
            )
            .is_err(),
            "hajimari cannot replay after consumption"
        );
        validate_contract_lifecycle_call(
            &transaction.world,
            &contract_address,
            v1_hash,
            EntryPointKind::Kotoage,
        )
        .expect("ordinary calls open after hajimari");
        activate_instance(
            &authority,
            contract_address.clone(),
            2,
            v1_hash,
            &mut transaction,
        )
        .expect("same-code activation is idempotent");
        assert_eq!(
            pending_contract_lifecycle(&transaction.world, &contract_address)
                .expect("valid lifecycle state"),
            None,
            "idempotent activation must not recreate a consumed hajimari"
        );
        let (v2_code, v2_manifest) = lifecycle_contract(
            r#"
seiyaku LifecycleTwo {
  hajimari() {}
  kaizen() {}
  kotoage fn run() authorize("CanRunLifecycleTwo") {}
}
"#,
        );
        let v2_hash = register_code_bytes(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            v2_code,
            &mut transaction,
        )
        .expect("register v2 bytecode");
        register_manifest(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            v2_manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &keypair,
                )
                .expect("sign bounded fixture manifest"),
            &mut transaction,
        )
        .expect("register v2 manifest");
        activate_instance(
            &authority,
            contract_address.clone(),
            2,
            v2_hash,
            &mut transaction,
        )
        .expect("the lifecycle owner may replace the active binding");
        let kaizen = pending_contract_lifecycle(&transaction.world, &contract_address)
            .expect("valid lifecycle state")
            .expect("replacement staged kaizen");
        assert!(matches!(
            kaizen,
            PendingContractLifecycle::Kaizen {
                previous_code_hash,
                code_hash,
                ..
            } if previous_code_hash == v1_hash && code_hash == v2_hash
        ));
        assert_eq!(
            validate_contract_lifecycle_call(
                &transaction.world,
                &contract_address,
                v2_hash,
                EntryPointKind::Kaizen,
            )
            .expect("genuine code replacement admits kaizen"),
            Some(kaizen)
        );
        assert!(
            validate_contract_lifecycle_call(
                &transaction.world,
                &contract_address,
                v2_hash,
                EntryPointKind::Hajimari,
            )
            .is_err(),
            "an in-place kaizen is not a new hajimari activation"
        );
        assert!(
            validate_contract_lifecycle_call(
                &transaction.world,
                &contract_address,
                v1_hash,
                EntryPointKind::Kaizen,
            )
            .is_err(),
            "old code cannot consume the new code's kaizen transition"
        );
        validate_contract_lifecycle_completion(&transaction.world, &contract_address, kaizen)
            .expect("live completion matches pending kaizen");
        set_pending_contract_lifecycle(&mut transaction, &contract_address, None);
        assert!(
            validate_contract_lifecycle_call(
                &transaction.world,
                &contract_address,
                v2_hash,
                EntryPointKind::Kaizen,
            )
            .is_err(),
            "kaizen cannot replay after consumption"
        );
    }
    #[test]
    fn lifecycle_transitions_in_one_execution_have_distinct_ordinals() {
        let (state, authority, _) = test_state();
        let mut block = state.block(default_header(1));
        let mut transaction = block.transaction();
        transaction.tx_call_hash = Some(Hash::new(b"one-execution-two-lifecycle-transitions"));
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            80,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let code_hash = Hash::new(b"ordinal-regression-code");
        let first = new_pending_contract_lifecycle(
            &mut transaction,
            &contract_address,
            None,
            code_hash,
            EntryPointKind::Hajimari,
        )
        .expect("first transition");
        let second = new_pending_contract_lifecycle(
            &mut transaction,
            &contract_address,
            None,
            code_hash,
            EntryPointKind::Hajimari,
        )
        .expect("second transition");
        assert_ne!(
            first, second,
            "the per-execution ordinal must distinguish otherwise identical lifecycle mutations"
        );
    }
    #[test]
    fn stale_hajimari_completion_rejects_deactivate_reactivate_aba() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (state, authority, keypair) = test_state();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            81,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let (code, manifest) = lifecycle_contract(
            r#"
seiyaku LifecycleAba {
  hajimari() {}
  kotoage fn run() authorize("CanRunLifecycleAba") {}
}
"#,
        );
        let mut first_block = state.block(default_header(1));
        let mut first_transaction = first_block.transaction();
        first_transaction.tx_call_hash = Some(Hash::new(b"lifecycle-aba-first-activation"));
        first_transaction
            .world
            .bind_inactive_contract_subject_for_testing(
                contract_address.clone(),
                authority.clone(),
            );
        let code_hash = register_code_bytes(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code,
            &mut first_transaction,
        )
        .expect("register lifecycle bytecode");
        register_manifest(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &keypair,
                )
                .expect("sign bounded fixture manifest"),
            &mut first_transaction,
        )
        .expect("register lifecycle manifest");
        activate_instance(
            &authority,
            contract_address.clone(),
            1,
            code_hash,
            &mut first_transaction,
        )
        .expect("first activation");
        let stale_transition =
            pending_contract_lifecycle(&first_transaction.world, &contract_address)
                .expect("valid first lifecycle state")
                .expect("first hajimari transition");
        first_transaction.apply();
        first_block
            .commit_world_overlay_for_testing()
            .expect("commit first activation");
        let mut completion_block = state.block(default_header(2));
        let mut completion = completion_block.transaction();
        set_pending_contract_lifecycle(&mut completion, &contract_address, None);
        completion.apply();
        completion_block
            .commit_world_overlay_for_testing()
            .expect("commit first completion");
        let mut deactivate_block = state.block(default_header(3));
        let mut deactivate = deactivate_block.transaction();
        deactivate.tx_call_hash = Some(Hash::new(b"lifecycle-aba-deactivation"));
        DeactivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 2,
            reason: Some("ABA regression fixture".to_owned()),
        }
        .execute(&authority, &mut deactivate)
        .expect("authorized deactivation");
        deactivate.apply();
        deactivate_block
            .commit_world_overlay_for_testing()
            .expect("commit deactivation");
        let mut second_block = state.block(default_header(4));
        let mut second_transaction = second_block.transaction();
        second_transaction.tx_call_hash = Some(Hash::new(b"lifecycle-aba-second-activation"));
        activate_instance(
            &authority,
            contract_address.clone(),
            3,
            code_hash,
            &mut second_transaction,
        )
        .expect("second activation");
        let current_transition =
            pending_contract_lifecycle(&second_transaction.world, &contract_address)
                .expect("valid second lifecycle state")
                .expect("second hajimari transition");
        assert_ne!(
            current_transition, stale_transition,
            "a new activation must never recreate an earlier KLC1 record"
        );
        assert!(matches!(
            validate_contract_lifecycle_completion(
                &second_transaction.world,
                &contract_address,
                stale_transition,
            ),
            Err(ValidationFail::NotPermitted(_))
        ));
        validate_contract_lifecycle_completion(
            &second_transaction.world,
            &contract_address,
            current_transition,
        )
        .expect("the exact current activation remains completable");
    }
    #[test]
    fn corrupt_lifecycle_marker_fails_closed() {
        let (state, authority, _) = test_state();
        let mut block = state.block(default_header(1));
        let mut transaction = block.transaction();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            8,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        transaction.world.smart_contract_state.insert(
            contract_lifecycle_state_key(&contract_address),
            b"not-a-lifecycle-record".to_vec(),
        );
        assert!(matches!(
            pending_contract_lifecycle(&transaction.world, &contract_address),
            Err(ValidationFail::InternalError(message))
                if message.contains("invalid lifecycle state")
        ));
        let pending = PendingContractLifecycle::Hajimari {
            transition_id: Hash::new(b"noncanonical-lifecycle-transition"),
            code_hash: Hash::new(b"noncanonical-lifecycle-record"),
        };
        let record = ContractLifecycleRecordV1 {
            domain: CONTRACT_LIFECYCLE_RECORD_MAGIC,
            pending,
        };
        crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
            &record,
            "iroha_core::smartcontracts::code::ContractLifecycleRecordV1",
        );
        let frame = pending.encode();
        assert_eq!(
            frame,
            norito::encode_canonical(&record).expect("lifecycle owner frame")
        );
        transaction.world.smart_contract_state.insert(
            contract_lifecycle_state_key(&contract_address),
            frame.clone(),
        );
        assert_eq!(
            pending_contract_lifecycle(&transaction.world, &contract_address)
                .expect("valid persisted lifecycle owner"),
            Some(pending),
        );
        let mut wrong_owner = frame.clone();
        wrong_owner[6..22].copy_from_slice(&norito::schema::identity::frame_hash::<Hash>());
        for malformed in [wrong_owner, frame[..frame.len() - 1].to_vec()] {
            transaction
                .world
                .smart_contract_state
                .insert(contract_lifecycle_state_key(&contract_address), malformed);
            assert!(matches!(
                pending_contract_lifecycle(&transaction.world, &contract_address),
                Err(ValidationFail::InternalError(message))
                    if message.contains("not canonical Norito")
            ));
        }
        let invalid_domain = ContractLifecycleRecordV1 {
            domain: *b"BAD!",
            pending,
        };
        assert_eq!(
            PendingContractLifecycle::decode(
                &norito::encode_canonical(&invalid_domain).expect("correct owner, invalid domain"),
            ),
            Err("lifecycle record has an invalid domain tag"),
        );
        let bare = norito::codec::Encode::encode(&ContractLifecycleRecordV1 {
            domain: CONTRACT_LIFECYCLE_RECORD_MAGIC,
            pending,
        });
        transaction
            .world
            .smart_contract_state
            .insert(contract_lifecycle_state_key(&contract_address), bare);
        assert!(matches!(
            pending_contract_lifecycle(&transaction.world, &contract_address),
            Err(ValidationFail::InternalError(message))
                if message.contains("not canonical Norito")
        ));
        let mut trailing = pending.encode();
        trailing.push(0);
        transaction
            .world
            .smart_contract_state
            .insert(contract_lifecycle_state_key(&contract_address), trailing);
        assert!(matches!(
            pending_contract_lifecycle(&transaction.world, &contract_address),
            Err(ValidationFail::InternalError(message))
                if message.contains("not canonical Norito")
        ));
    }
    #[test]
    fn register_code_obeys_size_cap() {
        let (state, authority, _kp) = test_state();
        let mut block = state.block(default_header(1));
        let mut stx = block.transaction();
        // Set very small cap via custom parameter to ensure registration fails.
        let id = CustomParameterId("max_contract_code_bytes".parse().unwrap());
        let cap = CustomParameter::new(id, iroha_primitives::json::Json::new(8u64));
        SetParameter::new(Parameter::Custom(cap))
            .execute(&authority, &mut stx)
            .expect("set cap");
        let code = minimal_ivm_program(1);
        let err = register_code_bytes(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code,
            &mut stx,
        )
        .unwrap_err();
        match err {
            RegistryError::Instruction(inner) => {
                let msg = inner.to_string();
                assert!(
                    msg.contains("code bytes exceed cap"),
                    "unexpected instruction error: {msg}"
                );
            }
            other => panic!("expected instruction error, got {other:?}"),
        }
    }
    #[test]
    fn register_code_rejects_zero_cycle_ceiling() {
        let (state, authority, _kp) = test_state();
        let mut block = state.block(default_header(1));
        let mut stx = block.transaction();
        let (mut code, _) = minimal_contract_artifact(1);
        code[8..16].copy_from_slice(&0_u64.to_le_bytes());
        let code_hash = ivm::contract_code_hash(&code);
        let error = register_code_bytes(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code,
            &mut stx,
        )
        .expect_err("zero-cycle artifact registration must fail closed");
        assert!(
            matches!(
                &error,
                RegistryError::Instruction(
                    InstructionExecutionError::InvalidParameter(
                        InvalidParameterError::SmartContract(message)
                    )
                ) if message.contains("omits a non-zero `max_cycles`")
            ),
            "unexpected registration error: {error:?}"
        );
        assert!(
            stx.world
                .contract_code
                .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    code_hash
                ))
                .is_none(),
            "rejected artifact must not enter world state"
        );
    }
    #[test]
    fn register_code_rejects_cycle_ceiling_above_node_policy() {
        let (mut state, authority, _kp) = test_state();
        let mut pipeline = state.installed_pipeline().clone();
        pipeline.ivm_max_cycles_upper_bound =
            core::num::NonZeroU64::new(1).expect("test ceiling is non-zero");
        state.set_pipeline(pipeline);
        let mut block = state.block(default_header(1));
        let mut stx = block.transaction();
        let (mut code, _) = minimal_contract_artifact(1);
        code[8..16].copy_from_slice(&2_u64.to_le_bytes());
        let code_hash = ivm::contract_code_hash(&code);
        let error = register_code_bytes(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code,
            &mut stx,
        )
        .expect_err("over-ceiling artifact registration must fail closed");
        assert!(
            matches!(
                &error,
                RegistryError::Instruction(
                    InstructionExecutionError::InvalidParameter(
                        InvalidParameterError::SmartContract(message)
                    )
                ) if message.contains("`max_cycles` exceeds upper bound")
            ),
            "unexpected registration error: {error:?}"
        );
        assert!(
            stx.world
                .contract_code
                .get(&iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    code_hash
                ))
                .is_none(),
            "rejected artifact must not enter world state"
        );
    }
    #[test]
    fn register_manifest_requires_code_hash() {
        let (state, authority, _kp) = test_state();
        let mut block = state.block(default_header(1));
        let mut stx = block.transaction();
        let manifest = ContractManifest {
            seiyaku_name: None,
            code_hash: None,
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
        };
        let err = register_manifest(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            manifest,
            &mut stx,
        )
        .unwrap_err();
        assert!(matches!(err, RegistryError::MissingCodeHash));
    }
    #[test]
    fn register_manifest_requires_abi_hash() {
        let (state, authority, _kp) = test_state();
        let mut block = state.block(default_header(1));
        let mut stx = block.transaction();
        let manifest = ContractManifest {
            seiyaku_name: None,
            code_hash: Some(Hash::new(b"manifest-without-abi-hash")),
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
        };
        let err = register_manifest(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            manifest,
            &mut stx,
        )
        .unwrap_err();
        assert!(matches!(err, RegistryError::MissingAbiHash));
    }
    #[test]
    fn subject_binding_initialization_builds_reverse_index() {
        let authority = AccountId::new(checked_keypair().public_key().clone());
        let address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            7,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let mut world = crate::sumeragi::lanes::routing::test_support::world(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        );
        world.accounts.insert(
            authority.clone(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        let subject = address.subject_id();
        world.accounts.insert(
            subject.clone(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        let active_code_hash = Hash::new(b"active-contract");
        world
            .contract_instances
            .insert(address.clone(), active_code_hash);
        world.contract_subject_bindings.insert(
            address.clone(),
            ContractSubjectBinding::new_direct(&address, authority.clone())
                .with_active_code_hash(active_code_hash),
        );
        crate::state::contract_subject_restore::rebuild(&mut world)
            .expect("initialize subject ledger");
        let bindings = world.contract_subject_bindings.view();
        let binding = bindings.get(&address).expect("binding");
        assert_eq!(binding.subject, address.subject_id());
        let world_view = world.view();
        let (persisted_subject, lifecycle) = fetch_contract_lifecycle(&world_view, &address)
            .expect("valid lifecycle lookup")
            .expect("retained lifecycle");
        assert_eq!(persisted_subject, subject);
        assert_eq!(lifecycle.active_code_hash, Some(active_code_hash));
        assert_eq!(
            borrow_bound_contract_subject_from_world(&world_view, &address),
            Some(&binding.subject),
        );
        assert_eq!(
            world
                .contract_subject_addresses
                .view()
                .get(&binding.subject),
            Some(&address)
        );
        drop(world_view);
        drop(bindings);
        crate::state::contract_subject_restore::rebuild(&mut world)
            .expect("validated subject ledger");
    }
    #[test]
    fn subject_binding_initialization_rejects_missing_subject_account() {
        let authority = AccountId::new(checked_keypair().public_key().clone());
        let address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            72,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let missing_subject = address.subject_id();
        let mut world = World::default();
        world.accounts.insert(
            authority.clone(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        world.contract_subject_bindings.insert(
            address.clone(),
            ContractSubjectBinding::new_direct(&address, authority),
        );

        let error = crate::state::contract_subject_restore::rebuild(&mut world)
            .expect_err("a retained binding cannot reference an absent subject account");
        assert!(
            error.contains(&format!(
                "contract subject account `{missing_subject}` for `{address}` does not exist"
            )),
            "unexpected missing-subject validation error: {error}"
        );
    }
    #[test]
    fn active_contract_lookups_reject_missing_subject_account() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (state, authority, keypair) = test_state();
        let mut block = state.block(default_header(1));
        let mut transaction = block.transaction();
        let (code, manifest) = minimal_contract_artifact(1);
        let code_hash = register_code_bytes(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code,
            &mut transaction,
        )
        .expect("register contract bytecode");
        register_manifest(
            &authority,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &keypair,
                )
                .expect("sign bounded fixture manifest"),
            &mut transaction,
        )
        .expect("register contract manifest");
        let address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            73,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        transaction
            .world
            .bind_inactive_contract_subject_for_testing(address.clone(), authority.clone());
        activate_instance(&authority, address.clone(), 1, code_hash, &mut transaction)
            .expect("activate contract");
        assert!(
            fetch_bound_contract_record(&transaction, &address)
                .expect("registry read completes")
                .is_some()
        );

        let subject = address.subject_id();
        assert!(transaction.world.accounts.remove(subject.clone()).is_some());
        let lifecycle_error = fetch_contract_lifecycle(&transaction.world, &address)
            .expect_err("lifecycle lookup must reject a missing subject account");
        assert!(lifecycle_error.contains(&subject.to_string()));
        assert!(
            fetch_bound_contract_subject(&transaction, &address).is_none(),
            "active subject lookup must fail closed"
        );
        assert!(
            fetch_bound_contract_identity(&transaction, &address)
                .expect("registry read completes")
                .is_none(),
            "active identity lookup must fail closed"
        );
        assert!(
            fetch_bound_contract_record(&transaction, &address)
                .expect("registry read completes")
                .is_none(),
            "active record lookup must fail closed"
        );
    }
    #[test]
    fn emergency_hold_blocks_only_its_exact_interval_and_remains_auditable_after_expiry() {
        let authority = AccountId::new(checked_keypair().public_key().clone());
        let address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            71,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let mut binding = ContractSubjectBinding::new_direct(&address, authority);
        binding.lifecycle.emergency_hold =
            Some(iroha_data_model::smart_contract::ContractEmergencyHoldV1 {
                incident_digest: [0xC1; 32],
                proposal_content_id: [0xC2; 32],
                governance_attempt_id: [0xC3; 32],
                reason: "bounded incident containment".to_owned(),
                imposed_at_height: 8,
                expires_at_height: 10,
            });
        let mut world = World::default();
        world
            .contract_subject_bindings
            .insert(address.clone(), binding);
        let view = world.view();

        assert!(ensure_contract_execution_allowed(&view, &address, 7).is_ok());
        for height in [8, 9] {
            let error = ensure_contract_execution_allowed(&view, &address, height)
                .expect_err("hold interval must suspend execution");
            assert!(error.contains("held by Parliament"));
            assert!(error.contains("through block 9"));
        }
        assert!(ensure_contract_execution_allowed(&view, &address, 10).is_ok());
        assert!(
            view.contract_subject_bindings()
                .get(&address)
                .expect("retained lifecycle")
                .lifecycle
                .emergency_hold
                .is_some(),
            "expiry must not erase the hold before its certified retrospective"
        );
    }
    #[test]
    fn lifecycle_lookup_rejects_active_index_drift() {
        let authority = AccountId::new(checked_keypair().public_key().clone());
        let address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            70,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let mut world = World::default();
        for account in [authority.clone(), address.subject_id()] {
            world.accounts.insert(
                account,
                iroha_data_model::account::AccountValue::new(
                    iroha_data_model::account::AccountDetails::default(),
                ),
            );
        }
        world.contract_subject_bindings.insert(
            address.clone(),
            ContractSubjectBinding::new_direct(&address, authority),
        );
        world
            .contract_instances
            .insert(address.clone(), Hash::new(b"drifted active index"));
        let world_view = world.view();
        let error = fetch_contract_lifecycle(&world_view, &address)
            .expect_err("active-index drift must fail closed");
        assert!(error.contains("does not match the active-instance index"));
        assert!(
            borrow_bound_contract_subject_from_world(&world_view, &address).is_none(),
            "active execution identity must fail closed on lifecycle/index drift"
        );
    }
    #[test]
    fn subject_binding_initialization_rejects_mismatched_existing_binding() {
        let authority_keypair = checked_keypair();
        let authority = AccountId::new(authority_keypair.public_key().clone());
        let address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            8,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let mut world = World::default();
        world
            .contract_instances
            .insert(address.clone(), Hash::new(b"active-contract"));
        world.contract_subject_bindings.insert(
            address.clone(),
            ContractSubjectBinding {
                subject: authority.clone(),
                lifecycle: ContractLifecycleControlV1::direct(authority.clone()),
            },
        );
        let error = crate::state::contract_subject_restore::rebuild(&mut world)
            .expect_err("mismatched existing binding must fail closed");
        assert!(
            error.contains("contract subject binding mismatch"),
            "unexpected error: {error}"
        );
        assert!(world.contract_subject_addresses.view().is_empty());
    }
}
