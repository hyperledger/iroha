#[cfg(test)]
use crate::memory::Memory;
use crate::{
    VMError,
    axt::{self, AxtPolicy, ProofBlob, TouchManifest},
    gas,
    host::{
        IVMHost, common_syscall_gas_quote, conservative_syscall_gas_quote, is_sm_syscall,
        preflight_reserved_syscall_gas, quote_tlv_payload_len_at,
        require_host_syscall_metering_spec, reserve_available_syscall_gas,
        reserve_available_syscall_gas_at_least,
    },
    ivm::IVM,
    parallel::StateUpdate,
    pointer_abi::{self, PointerType},
    schema_registry::{DefaultRegistry, SchemaRegistry},
    state_overlay::{DurableStateOverlay, DurableStateSnapshot},
    syscalls,
};
#[cfg(test)]
thread_local! {
    /// Payload bytes actually copied by owned mock-WSV reads on this test thread.
    pub(crate) static OWNED_STATE_READ_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
use core::str::FromStr;
use iroha_crypto::{Hash as CryptoHash, HashOf, PublicKey};
pub use iroha_data_model::account::AccountId;
pub use iroha_data_model::prelude::{AssetDefinitionId, Mintable, NftId, Peer};
use iroha_data_model::{
    asset::{AssetBalanceScope, AssetId},
    isi::{smart_contract_code as scode, transfer::TransferAssetBatch},
    nexus::{
        AxtPolicyBinding, AxtPolicyEntry, AxtPolicySnapshot, AxtPolicySnapshotValidationError,
    },
    proof::{ProofAttachment, VerifyingKeyId},
    query::QueryRequest,
    smart_contract::ContractAddress,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::state_path::StatePath;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
#[cfg(test)]
use iroha_primitives::numeric::Numeric;
use iroha_primitives::{
    json::Json,
    numeric::{NumericSpec, Quantity},
    numeric_abi::QuantityValueV1,
};
use ivm_abi::codec::{decode_canonical_norito, encode_canonical_norito};
use norito::{
    decode_from_bytes,
    derive::{Decode, Encode},
    json::{self as njson},
};
use sha2::{Digest as _, Sha256};
use std::{
    any::Any,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    num::{NonZeroU16, NonZeroU64},
    path::PathBuf,
    sync::Arc,
};
#[cfg(test)]
#[path = "mock_wsv/contract_call_tests.rs"]
mod contract_call_tests;
#[path = "mock_wsv/contract_calls.rs"]
mod contract_calls;
#[cfg(test)]
#[path = "mock_wsv/contract_permission_tests.rs"]
mod contract_permission_tests;
#[cfg(test)]
#[path = "mock_wsv/vrf_epoch_seed_tests.rs"]
mod vrf_epoch_seed_tests;
use contract_calls::MockContractInstance;
pub use contract_calls::{MockContractEvent, contract_state_path};
/// Definition of an asset type.
#[derive(Clone, Debug)]
struct AssetDefinition {
    /// Human-readable display name supplied at registration.
    name: String,
    /// Numeric spec every minted quantity must satisfy.
    spec: NumericSpec,
    mintable: Mintable,
    total_supply: Quantity,
    owner: AccountId,
}
impl AssetDefinition {
    fn new(name: String, spec: NumericSpec, mintable: Mintable, owner: AccountId) -> Self {
        Self {
            name,
            spec,
            mintable,
            total_supply: Quantity::zero(),
            owner,
        }
    }
}
/// Decode the `REGISTER_ASSET` display name (`r11` payload), numeric-spec
/// word (`r12`) and mintability word (`r13`) with the data-model decoder that
/// CoreHost also uses, so both hosts accept and reject exactly the same calls.
///
/// # Errors
/// Returns [`VMError::DecodeError`] for an invalid display name or a word
/// outside the encoding, as CoreHost does.
fn decode_asset_registration(
    name: &[u8],
    spec_word: u64,
    mintable_word: u64,
) -> Result<iroha_data_model::asset::definition::ivm_registration::Registration, VMError> {
    iroha_data_model::asset::definition::ivm_registration::decode_registration(
        name,
        spec_word,
        mintable_word,
    )
    .map_err(|_| VMError::DecodeError)
}
/// NFT state tracking the current owner, stored metadata, and the issuing authority.
#[derive(Clone, Debug)]
struct NftRecord {
    owner: AccountId,
    metadata: HashMap<Name, Vec<u8>>,
    issuer: AccountId,
}
/// Per-dataspace policy sourced from Space Directory/WSV for AXT enforcement.
#[derive(Clone, Debug, Default, Encode, Decode)]
pub struct DataspaceAxtPolicy {
    pub manifest_root: [u8; 32],
    pub target_lane: LaneId,
    pub active_handle_era: u64,
    pub next_handle_counter: u64,
    pub current_slot: u64,
}
impl DataspaceAxtPolicy {
    fn to_model_entry(&self) -> AxtPolicyEntry {
        AxtPolicyEntry {
            manifest_root: self.manifest_root,
            target_lane: self.target_lane,
            active_handle_era: self.active_handle_era,
            next_handle_counter: self.next_handle_counter,
            current_slot: self.current_slot,
        }
    }
    fn from_model_entry(entry: &AxtPolicyEntry) -> Self {
        Self {
            manifest_root: entry.manifest_root,
            target_lane: entry.target_lane,
            active_handle_era: entry.active_handle_era,
            next_handle_counter: entry.next_handle_counter,
            current_slot: entry.current_slot,
        }
    }
}
/// Space Directory-backed AXT policy used by WsvHost (and injectable into CoreHost in tests).
#[derive(Clone, Default)]
pub struct SpaceDirectoryAxtPolicy {
    policies: HashMap<DataSpaceId, DataspaceAxtPolicy>,
}
impl SpaceDirectoryAxtPolicy {
    pub fn from_snapshot(policies: HashMap<DataSpaceId, DataspaceAxtPolicy>) -> Self {
        Self::from_snapshot_with_timing(
            policies,
            NonZeroU64::new(1).expect("non-zero slot length"),
            0,
        )
    }
    pub fn from_snapshot_with_timing(
        policies: HashMap<DataSpaceId, DataspaceAxtPolicy>,
        _slot_length_ms: NonZeroU64,
        _max_clock_skew_ms: u64,
    ) -> Self {
        Self { policies }
    }
    /// Construct a policy from a canonical data-model snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AxtPolicySnapshotValidationError`] when the snapshot is not
    /// canonically ordered or its version does not bind its exact entries.
    pub fn from_policy_snapshot(
        snapshot: &AxtPolicySnapshot,
    ) -> Result<Self, AxtPolicySnapshotValidationError> {
        Self::from_policy_snapshot_with_timing(
            snapshot,
            NonZeroU64::new(1).expect("non-zero slot length"),
            0,
        )
    }
    /// Construct a policy from a canonical data-model snapshot and timing.
    ///
    /// # Errors
    ///
    /// Returns [`AxtPolicySnapshotValidationError`] when the snapshot is not
    /// canonically ordered or its version does not bind its exact entries.
    pub fn from_policy_snapshot_with_timing(
        snapshot: &AxtPolicySnapshot,
        slot_length_ms: NonZeroU64,
        max_clock_skew_ms: u64,
    ) -> Result<Self, AxtPolicySnapshotValidationError> {
        snapshot.validate()?;
        let mut policies = HashMap::new();
        for binding in &snapshot.entries {
            policies.insert(
                binding.dsid,
                DataspaceAxtPolicy::from_model_entry(&binding.policy),
            );
        }
        Ok(Self::from_snapshot_with_timing(
            policies,
            slot_length_ms,
            max_clock_skew_ms,
        ))
    }
    pub fn with_current_slot(mut self, slot: u64) -> Self {
        for policy in self.policies.values_mut() {
            policy.current_slot = slot;
        }
        self
    }
}
impl AxtPolicy for SpaceDirectoryAxtPolicy {
    fn allow_touch(&self, _dsid: DataSpaceId, _manifest: &TouchManifest) -> Result<(), VMError> {
        Ok(())
    }
}
/// Permission tokens used for authorising operations.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum PermissionToken {
    RegisterDomain,
    RegisterAccount,
    RegisterAssetDefinition,
    /// Permission to register ZK policy for an asset
    RegisterZkAsset(AssetDefinitionId),
    MintAsset(AssetDefinitionId),
    BurnAsset(AssetDefinitionId),
    /// Definition-wide transfer permission retained for general executor parity.
    TransferAsset(AssetDefinitionId),
    /// Permission to transfer one exact owner/dataspace balance bucket.
    TransferAssetBucket(AssetId),
    /// Permission to set transfer availability for one exact account and asset definition.
    SetAssetTransferAvailability {
        account: AccountId,
        asset_definition: AssetDefinitionId,
    },
    /// Permission to set a daily transfer limit for one asset and exact account alias scope.
    SetAssetTransferDailyLimit {
        asset_definition: AssetDefinitionId,
        account_domain: Name,
        account_dataspace: DataSpaceId,
    },
    /// Permission to set a holding limit for one exact account and asset definition.
    SetAssetHoldingLimit {
        account: AccountId,
        asset_definition: AssetDefinitionId,
    },
    /// Permission to add a signatory for the given account
    AddSignatory(AccountId),
    /// Permission to remove a signatory for the given account
    RemoveSignatory(AccountId),
    /// Permission to update the quorum for the given account
    SetAccountQuorum(AccountId),
    /// Permission to set account detail for the given account
    SetAccountDetail(AccountId),
    /// Permission to read balances of the given account
    ReadAccountAssets(AccountId),
    /// Permission to create, delete, grant, and revoke roles.
    ManageRoles,
    /// Permission to grant and revoke direct permissions.
    ManagePermissions,
    /// Permission to create, mutate, and remove triggers.
    ManageTriggers,
    /// Permission to register and unregister peers.
    ManagePeers,
    /// Permission to invoke one exact entrypoint of one deployed contract instance.
    ContractEntrypoint {
        /// Immutable deployed contract address.
        contract: ContractAddress,
        /// Exact case-sensitive public selector.
        entrypoint: String,
    },
    /// Permission declared by one immutable deployed contract instance.
    ContractPermission {
        /// Immutable deployed contract address.
        contract: ContractAddress,
        /// Exact name in the current authenticated declaration table.
        permission: Name,
    },
    /// Exact chain-wide marker token, imported explicitly by a contract.
    Custom(String),
}
/// Minimal account representation tracking signatories, quorum, and metadata.
#[derive(Clone, Debug)]
struct Account {
    /// Public keys (or opaque identifiers) authorised to sign for the account.
    signatories: HashSet<String>,
    /// Required number of signatures for multisig operations. `1` by default.
    quorum: u32,
    /// Account detail entries keyed by `Name`.
    detail: HashMap<String, Vec<u8>>,
}
impl Account {
    fn insert_signatory(&mut self, key: String) -> bool {
        self.signatories.insert(key)
    }
    fn remove_signatory(&mut self, key: &str) -> bool {
        self.signatories.remove(key)
    }
    fn set_quorum(&mut self, quorum: u32) {
        self.quorum = quorum.max(1);
    }
    fn set_detail(&mut self, key: &str, value: Vec<u8>) {
        self.detail.insert(key.to_string(), value);
    }
}
impl Default for Account {
    fn default() -> Self {
        Self {
            signatories: HashSet::new(),
            quorum: 1,
            detail: HashMap::new(),
        }
    }
}
/// A very small in-memory mock of Iroha's World State View (WSV).
///
/// Scope and purpose
/// - Provides minimal primitives for tests (domain/account/asset/nft/roles/triggers/peers) and
///   a compact shielded (ZK) asset state with recent-root windows.
/// - Enforces canonical `NoritoBytes(QueryRequest)` at
///   `SMARTCONTRACT_EXECUTE_QUERY (0xA1)`, then reports `NotImplemented` because this mock has no
///   query-state executor.
/// - Accepts only canonical `NoritoBytes(InstructionBox)` plus the matching mandatory operation
///   tag at `SMARTCONTRACT_EXECUTE_INSTRUCTION (0xA0)`, matching the production V1 ABI.
#[derive(Clone, Default)]
pub struct MockWorldStateView {
    domains: HashMap<DomainId, ()>,
    domain_accounts: HashMap<DomainId, HashSet<AccountId>>,
    accounts: HashMap<AccountId, Account>,
    permissions: HashMap<AccountId, HashSet<PermissionToken>>,
    asset_definitions: HashMap<AssetDefinitionId, AssetDefinition>,
    balances: HashMap<(AccountId, AssetDefinitionId), Quantity>,
    asset_transfer_availability: HashMap<(AccountId, AssetDefinitionId), (u64, bool, bool)>,
    asset_transfer_daily_limits: HashMap<(AccountId, AssetDefinitionId), Option<Quantity>>,
    asset_holding_limits: HashMap<(AccountId, AssetDefinitionId), Option<Quantity>>,
    nfts: HashMap<NftId, NftRecord>,
    peers: HashSet<Peer>,
    triggers: HashMap<String, bool>,
    roles: HashMap<String, HashSet<PermissionToken>>,
    role_assignments: HashMap<AccountId, HashSet<String>>, // account subject -> role names
    // ZK (shielded) state
    zk_assets: HashMap<AssetDefinitionId, ZkAssetState>,
    elections: HashMap<String, ElectionState>,
    /// Exact committed epoch seeds supplied by local diagnostic fixtures.
    vrf_epoch_seeds: BTreeMap<u64, [u8; 32]>,
    /// Events emitted by ZK operations for test visibility
    zk_events: Vec<ZkEvent>,
    /// Durable smart-contract state (path -> NoritoBytes payload TLVs)
    state_overlay: DurableStateOverlay,
    /// Complete admitted artifacts owned by their exact dataspace and code hash.
    contract_artifacts:
        HashMap<iroha_data_model::smart_contract::ContractArtifactId, crate::PreparedContract>,
    /// Explicit diagnostic lifecycle fixtures keyed by immutable instance address.
    contract_instances: HashMap<ContractAddress, MockContractInstance>,
    /// Logical wall-clock timestamp used for time-gated operations (ms since epoch).
    current_time_ms: u64,
    /// Deterministic block height reported to contracts; local tests advance it explicitly.
    current_block_height: u64,
    /// Slot length (ms) used to derive current slot for expiry checks.
    slot_length_ms: u64,
    /// Maximum wall-clock skew (ms) tolerated for AXT expiry calculations.
    axt_max_clock_skew_ms: u64,
    verifying_keys: BTreeMap<VerifyingKeyId, MockVerifyingKeyRecord>,
    axt_policies: HashMap<DataSpaceId, DataspaceAxtPolicy>,
}
pub struct ZkPolicyConfig {
    pub vk_unshield: Option<VerifyingKeyId>,
}
impl MockWorldStateView {
    /// Supply one exact deterministic epoch seed for a local diagnostic fixture.
    /// This never fabricates a seed for a different or missing epoch.
    pub fn set_vrf_epoch_seed_fixture(&mut self, epoch: u64, seed: [u8; 32]) {
        self.vrf_epoch_seeds.insert(epoch, seed);
    }
    /// Create an empty mock WSV.
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
            domain_accounts: HashMap::new(),
            accounts: HashMap::new(),
            permissions: HashMap::new(),
            asset_definitions: HashMap::new(),
            balances: HashMap::new(),
            asset_transfer_availability: HashMap::new(),
            asset_transfer_daily_limits: HashMap::new(),
            asset_holding_limits: HashMap::new(),
            nfts: HashMap::new(),
            peers: HashSet::new(),
            triggers: HashMap::new(),
            roles: HashMap::new(),
            role_assignments: HashMap::new(),
            zk_assets: HashMap::new(),
            elections: HashMap::new(),
            zk_events: Vec::new(),
            state_overlay: DurableStateOverlay::in_memory(),
            contract_artifacts: HashMap::new(),
            vrf_epoch_seeds: BTreeMap::new(),
            contract_instances: HashMap::new(),
            current_time_ms: 0,
            current_block_height: 0,
            slot_length_ms: 1,
            axt_max_clock_skew_ms: 0,
            verifying_keys: BTreeMap::new(),
            axt_policies: HashMap::new(),
        }
    }
    /// Create a mock WSV whose contract state persists to the provided path.
    pub fn with_state_store(path: PathBuf) -> Result<Self, VMError> {
        let mut base = Self::new();
        base.state_overlay = DurableStateOverlay::with_persist_path(path)?;
        Ok(base)
    }
    /// Override the logical wall-clock timestamp (milliseconds since epoch).
    ///
    /// Tests should set this to exercise election time windows deterministically.
    pub fn set_current_time_ms(&mut self, ts: u64) {
        self.current_time_ms = ts;
    }
    /// Configure slot length (ms) used for deriving current slot in AXT checks.
    pub fn set_slot_length_ms(&mut self, len: u64) {
        self.slot_length_ms = len.max(1);
    }
    /// Configure the maximum wall-clock skew (ms) tolerated for AXT expiry checks.
    pub fn set_max_clock_skew_ms(&mut self, skew_ms: u64) {
        self.axt_max_clock_skew_ms = skew_ms;
    }
    /// Expose the configured slot length used for AXT calculations.
    pub fn slot_length_ms(&self) -> NonZeroU64 {
        NonZeroU64::new(self.slot_length_ms.max(1)).expect("slot length is clamped to non-zero")
    }
    /// Expose the configured wall-clock skew allowance for AXT expiry checks.
    pub fn max_clock_skew_ms(&self) -> u64 {
        self.axt_max_clock_skew_ms
    }
    /// Derive the current slot from logical time and slot length.
    pub fn current_slot(&self) -> u64 {
        let len = self.slot_length_ms.max(1);
        self.current_time_ms / len
    }
    /// Install or update an AXT policy entry for a dataspace.
    pub fn set_axt_policy(&mut self, dsid: DataSpaceId, policy: DataspaceAxtPolicy) {
        let mut policy = policy;
        if policy.current_slot == 0 {
            policy.current_slot = self.current_slot();
        }
        self.axt_policies.insert(dsid, policy);
    }
    /// Snapshot all configured AXT policy entries.
    pub fn axt_policy_snapshot(&self) -> HashMap<DataSpaceId, DataspaceAxtPolicy> {
        self.axt_policies.clone()
    }
    /// Emit a data-model AXT policy snapshot for block/replication plumbing.
    pub fn axt_policy_snapshot_model(&self) -> AxtPolicySnapshot {
        let fallback_slot = if self
            .axt_policies
            .values()
            .any(|policy| policy.current_slot != 0)
        {
            None
        } else {
            Some(self.current_slot())
        };
        let mut entries: Vec<_> = self
            .axt_policies
            .iter()
            .map(|(dsid, policy)| {
                let mut entry = policy.to_model_entry();
                if let Some(slot) = fallback_slot {
                    entry.current_slot = slot;
                }
                AxtPolicyBinding {
                    dsid: *dsid,
                    policy: entry,
                }
            })
            .collect();
        entries.sort_by_key(|binding| binding.dsid);
        let version = AxtPolicySnapshot::compute_version(&entries);
        AxtPolicySnapshot { version, entries }
    }
    /// Load AXT policies from a data-model snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AxtPolicySnapshotValidationError`] without changing the
    /// installed policies when the snapshot is not canonical.
    pub fn load_axt_policy_snapshot_model(
        &mut self,
        snapshot: &AxtPolicySnapshot,
    ) -> Result<(), AxtPolicySnapshotValidationError> {
        snapshot.validate()?;
        let map = snapshot
            .entries
            .iter()
            .map(|binding| {
                (
                    binding.dsid,
                    DataspaceAxtPolicy::from_model_entry(&binding.policy),
                )
            })
            .collect();
        self.axt_policies = map;
        Ok(())
    }
    /// Return the logical wall-clock timestamp used for gating elections.
    pub fn current_time_ms(&self) -> u64 {
        self.current_time_ms
    }
    /// Override the block height reported by `context::block_height()`.
    pub fn set_current_block_height(&mut self, height: u64) {
        self.current_block_height = height;
    }
    /// Return the block height reported by `context::block_height()`.
    pub fn current_block_height(&self) -> u64 {
        self.current_block_height
    }
    // -----------------------------
    // Smart-contract durable state (mock)
    // -----------------------------
    pub fn sc_get<P: AsRef<str>>(&self, path: P) -> Option<Vec<u8>> {
        let path: StatePath = path.as_ref().parse().ok()?;
        let out = self.state_overlay.get(&path);
        #[cfg(test)]
        if let Some(value) = &out {
            OWNED_STATE_READ_BYTES.with(|bytes| bytes.set(bytes.get().saturating_add(value.len())));
        }
        if crate::dev_env::decode_trace_enabled() {
            eprintln!(
                "sc_get: {path} -> {}",
                if out.is_some() { "hit" } else { "miss" }
            );
        }
        out
    }
    pub fn sc_set<P: AsRef<str>>(&mut self, path: P, value: Vec<u8>) -> Result<(), VMError> {
        let path: StatePath = path.as_ref().parse().map_err(|_| VMError::NoritoInvalid)?;
        if crate::dev_env::decode_trace_enabled() {
            eprintln!("sc_set: {path} -> {value:?}");
        }
        self.state_overlay.set(&path, value)
    }
    pub fn sc_del<P: AsRef<str>>(&mut self, path: P) -> Result<(), VMError> {
        let path: StatePath = path.as_ref().parse().map_err(|_| VMError::NoritoInvalid)?;
        self.state_overlay.del(&path)
    }
    pub fn sc_snapshot(&self) -> DurableStateSnapshot {
        self.state_overlay.checkpoint()
    }
    pub fn sc_restore(&mut self, snapshot: &DurableStateSnapshot) -> Result<(), VMError> {
        self.state_overlay.restore(snapshot)
    }
    pub fn sc_flush(&self) -> Result<(), VMError> {
        self.state_overlay.flush()
    }
    // -----------------------------
    // ZK shielded ledger handlers (permissions and full Merkle enforcement outstanding)
    // -----------------------------
    /// Register a ZK policy for an existing asset definition.
    pub fn register_zk_asset(&mut self, asset: AssetDefinitionId, policy: ZkPolicyConfig) -> bool {
        if !self.asset_definitions.contains_key(&asset) {
            return false;
        }
        let vk_unshield_binding = policy
            .vk_unshield
            .as_ref()
            .map(|id| self.binding_from_registry(id));
        let st = self.zk_assets.entry(asset.clone()).or_default();
        st.vk_unshield = vk_unshield_binding;
        // Emit a policy-updated event
        self.zk_events.push(ZkEvent::ZkPolicyUpdated {
            asset: asset.clone(),
        });
        true
    }
    /// Return latest and recent roots for the asset's shielded ledger.
    pub fn get_roots(
        &self,
        asset: &AssetDefinitionId,
        max: usize,
    ) -> ([u8; 32], Vec<[u8; 32]>, u32) {
        if let Some(st) = self.zk_assets.get(asset) {
            let all_roots = if st.root_history.is_empty() {
                vec![iroha_data_model::zk::CONFIDENTIAL_TREE_POSEIDON_PASTA_V1_EMPTY_ROOT]
            } else {
                st.root_history.iter().map(|h| *h.as_ref()).collect()
            };
            let latest = *all_roots
                .last()
                .expect("registered ZK assets always expose at least the profile empty root");
            let list = if max == 0 || all_roots.len() <= max {
                all_roots
            } else {
                all_roots[all_roots.len() - max..].to_vec()
            };
            let height = u32::try_from(st.commitments.len()).unwrap_or(u32::MAX);
            (latest, list, height)
        } else {
            ([0u8; 32], Vec::new(), 0)
        }
    }
    /// Test helper: drain and return accumulated ZK events.
    pub fn drain_zk_events(&mut self) -> Vec<ZkEvent> {
        core::mem::take(&mut self.zk_events)
    }
    /// Create an election with parameters.
    pub fn create_election(
        &mut self,
        election_id: String,
        options: u32,
        eligible_root: [u8; 32],
        start_ts: u64,
        end_ts: u64,
    ) -> bool {
        let Ok(option_count) = DMZk::validate_election_options_v1(options) else {
            return false;
        };
        if end_ts < start_ts || self.elections.contains_key(&election_id) {
            return false;
        }
        let e = ElectionState {
            options,
            eligible_root,
            start_ts,
            end_ts,
            finalized: false,
            tally: vec![0; option_count],
            ballot_nullifiers: HashSet::new(),
            ciphertexts: Vec::new(),
        };
        let previous = self.elections.insert(election_id, e);
        debug_assert!(previous.is_none());
        true
    }
    /// Submit a ballot ciphertext with a unique nullifier.
    /// Enforces the election time window and basic proof structure checks.
    pub fn submit_ballot(
        &mut self,
        election_id: &str,
        ciphertext: Vec<u8>,
        nullifier: [u8; 32],
        proof: ProofAttachment,
    ) -> bool {
        if !self.validate_vote_proof(&proof) {
            return false;
        }
        let Some(e) = self.elections.get_mut(election_id) else {
            return false;
        };
        if e.finalized {
            return false;
        }
        if self.current_time_ms < e.start_ts || self.current_time_ms > e.end_ts {
            return false;
        }
        if !e.ballot_nullifiers.insert(nullifier) {
            return false;
        }
        e.ciphertexts.push(ciphertext);
        true
    }
    fn validate_vote_proof(&self, proof: &ProofAttachment) -> bool {
        if proof.backend != proof.proof.backend {
            return false;
        }
        if proof.proof.bytes.is_empty() {
            return false;
        }
        if !self.verifying_keys.contains_key(&proof.vk_ref) {
            return false;
        }
        proof.envelope_hash.is_some()
    }
    /// Finalize an election with a provided tally.
    pub fn finalize_election(
        &mut self,
        election_id: &str,
        tally: Vec<u128>,
        proof: ProofAttachment,
    ) -> bool {
        if !self.validate_vote_proof(&proof) {
            return false;
        }
        let Some(e) = self.elections.get_mut(election_id) else {
            return false;
        };
        if e.finalized
            || DMZk::validate_election_tally_v1(e.options, e.tally.len()).is_err()
            || DMZk::validate_election_tally_v1(e.options, tally.len()).is_err()
            || tally
                .iter()
                .try_fold(0_u128, |total, weight| total.checked_add(*weight))
                .is_none()
        {
            return false;
        }
        e.tally = tally;
        e.finalized = true;
        true
    }
    fn account_subject(account: &AccountId) -> AccountId {
        account.subject_id()
    }
    fn account_is_linked(&self, account: &AccountId) -> bool {
        let subject = Self::account_subject(account);
        self.accounts.contains_key(&subject) || self.subject_has_any_domain(&subject)
    }
    fn subject_has_any_domain(&self, subject: &AccountId) -> bool {
        self.domain_accounts
            .values()
            .any(|subjects| subjects.contains(subject))
    }
    /// List all domains currently associated with the supplied account.
    ///
    /// The returned list is sorted for deterministic test assertions.
    #[must_use]
    pub fn domains_for_account(&self, account: &AccountId) -> Vec<DomainId> {
        let subject = Self::account_subject(account);
        let mut domains: Vec<DomainId> = self
            .domain_accounts
            .iter()
            .filter_map(|(domain, subjects)| {
                if subjects.contains(&subject) {
                    Some(domain.clone())
                } else {
                    None
                }
            })
            .collect();
        domains.sort();
        domains
    }
    /// List all account subjects currently linked to a domain.
    ///
    /// The returned list is sorted for deterministic test assertions.
    #[must_use]
    pub fn linked_subjects_for_domain(&self, domain: &DomainId) -> Vec<AccountId> {
        let mut subjects: Vec<AccountId> = self
            .domain_accounts
            .get(domain)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        subjects.sort();
        subjects
    }
    /// Link an existing account subject into a domain.
    ///
    /// Returns `true` when the link is newly created and `false` when the
    /// domain does not exist or the subject is already linked.
    pub fn link_subject_to_domain(&mut self, subject: AccountId, domain: DomainId) -> bool {
        if !self.domains.contains_key(&domain) {
            return false;
        }
        self.accounts.entry(subject.clone()).or_default();
        self.domain_accounts
            .entry(domain)
            .or_default()
            .insert(subject)
    }
    fn canonical_account_id_for_subject(&self, subject: &AccountId) -> Option<AccountId> {
        (self.accounts.contains_key(subject) || self.subject_has_any_domain(subject))
            .then(|| subject.clone())
    }
    /// Test helper: register an account without permission checks or domain validation.
    /// Intended for unit tests that need to seed the mock quickly.
    pub fn add_account_unchecked(&mut self, id: AccountId) {
        let subject = Self::account_subject(&id);
        self.accounts.entry(subject).or_default();
    }
    /// Insert a verifying key record for ZK bindings.
    pub fn insert_verifying_key(&mut self, id: VerifyingKeyId, bytes: Vec<u8>) {
        let commitment = hash_vk_bytes(&id.backend.to_string(), &bytes);
        self.verifying_keys
            .insert(id, MockVerifyingKeyRecord { commitment });
    }
    /// Grant a permission token to `account`.
    pub fn grant_permission(&mut self, account: &AccountId, token: PermissionToken) {
        self.permissions
            .entry(Self::account_subject(account))
            .or_default()
            .insert(token);
    }
    /// Revoke a permission token from `account`.
    pub fn revoke_permission(&mut self, account: &AccountId, token: &PermissionToken) {
        if let Some(set) = self.permissions.get_mut(&Self::account_subject(account)) {
            set.remove(token);
        }
    }
    /// Add a signatory to `account`. Caller must be the account owner or hold `AddSignatory`.
    pub fn add_signatory(
        &mut self,
        caller: &AccountId,
        account: &AccountId,
        public_key: String,
    ) -> bool {
        let caller_subject = Self::account_subject(caller);
        let account_subject = Self::account_subject(account);
        if caller_subject != account_subject {
            let token = PermissionToken::AddSignatory(account_subject.clone());
            if !self.has_permission(caller, &token) {
                return false;
            }
        }
        if !self.account_is_linked(account) {
            return false;
        }
        let Some(acc) = self.accounts.get_mut(&account_subject) else {
            return false;
        };
        acc.insert_signatory(public_key)
    }
    /// Remove a signatory from `account`. Caller must be owner or hold `RemoveSignatory`.
    pub fn remove_signatory(
        &mut self,
        caller: &AccountId,
        account: &AccountId,
        public_key: &str,
    ) -> bool {
        let caller_subject = Self::account_subject(caller);
        let account_subject = Self::account_subject(account);
        if caller_subject != account_subject {
            let token = PermissionToken::RemoveSignatory(account_subject.clone());
            if !self.has_permission(caller, &token) {
                return false;
            }
        }
        if !self.account_is_linked(account) {
            return false;
        }
        let Some(acc) = self.accounts.get_mut(&account_subject) else {
            return false;
        };
        acc.remove_signatory(public_key)
    }
    /// Update quorum for `account`. Caller must be owner or hold `SetAccountQuorum`.
    pub fn set_account_quorum(
        &mut self,
        caller: &AccountId,
        account: &AccountId,
        quorum: u32,
    ) -> bool {
        if quorum == 0 {
            return false;
        }
        let caller_subject = Self::account_subject(caller);
        let account_subject = Self::account_subject(account);
        if caller_subject != account_subject {
            let token = PermissionToken::SetAccountQuorum(account_subject.clone());
            if !self.has_permission(caller, &token) {
                return false;
            }
        }
        if !self.account_is_linked(account) {
            return false;
        }
        let Some(acc) = self.accounts.get_mut(&account_subject) else {
            return false;
        };
        acc.set_quorum(quorum);
        true
    }
    /// Store account detail (metadata) under `key`. Caller must be owner or hold `SetAccountDetail`.
    pub fn set_account_detail(
        &mut self,
        caller: &AccountId,
        account: &AccountId,
        key: &str,
        value: Vec<u8>,
    ) -> bool {
        if key.is_empty() {
            return false;
        }
        let caller_subject = Self::account_subject(caller);
        let account_subject = Self::account_subject(account);
        if caller_subject != account_subject {
            let token = PermissionToken::SetAccountDetail(account_subject.clone());
            if !self.has_permission(caller, &token) {
                return false;
            }
        }
        if !self.account_is_linked(account) {
            return false;
        }
        let Some(acc) = self.accounts.get_mut(&account_subject) else {
            return false;
        };
        acc.set_detail(key, value);
        true
    }
    /// Read back account quorum.
    pub fn account_quorum(&self, account: &AccountId) -> Option<u32> {
        if !self.account_is_linked(account) {
            return None;
        }
        self.accounts
            .get(&Self::account_subject(account))
            .map(|a| a.quorum)
    }
    /// Read back account signatories.
    pub fn account_signatories(&self, account: &AccountId) -> Option<Vec<String>> {
        if !self.account_is_linked(account) {
            return None;
        }
        self.accounts
            .get(&Self::account_subject(account))
            .map(|a| a.signatories.iter().cloned().collect())
    }
    /// Read back an account detail entry.
    pub fn account_detail_value(&self, account: &AccountId, key: &str) -> Option<Vec<u8>> {
        if !self.account_is_linked(account) {
            return None;
        }
        self.accounts
            .get(&Self::account_subject(account))
            .and_then(|a| a.detail.get(key).cloned())
    }
    pub fn has_permission(&self, account: &AccountId, token: &PermissionToken) -> bool {
        let subject = Self::account_subject(account);
        if !self.account_is_linked(account) {
            return false;
        }
        // Direct permission
        if self
            .permissions
            .get(&subject)
            .map(|set| set.contains(token))
            .unwrap_or(false)
        {
            return true;
        }
        // Role-derived permissions
        if let Some(role_names) = self.role_assignments.get(&subject) {
            for r in role_names {
                if let Some(perms) = self.roles.get(r)
                    && perms.contains(token)
                {
                    return true;
                }
            }
        }
        false
    }
    /// Initialize with a list of balances.
    pub fn with_balances(entries: &[((AccountId, AssetDefinitionId), Quantity)]) -> Self {
        let mut wsv = Self::new();
        for ((account, asset), amount) in entries {
            assert!(
                Self::is_scale0(amount),
                "mock WSV balances must have scale=0"
            );
            let subject = Self::account_subject(account);
            wsv.accounts.entry(subject.clone()).or_default();
            wsv.asset_definitions
                .entry(asset.clone())
                .or_insert_with(|| {
                    AssetDefinition::new(
                        asset.to_string(),
                        NumericSpec::unconstrained(),
                        Mintable::Infinitely,
                        account.clone(),
                    )
                });
            wsv.balances
                .insert((subject, asset.clone()), amount.clone());
            if let Some(def) = wsv.asset_definitions.get_mut(asset) {
                def.total_supply = def
                    .total_supply
                    .checked_add(amount)
                    .expect("mock total supply overflow");
            }
        }
        wsv
    }
    /// Readback: check if a peer entry exists.
    pub fn has_peer(&self, peer: &Peer) -> bool {
        self.peers.contains(peer)
    }
    /// Readback: return trigger enabled state if present.
    pub fn trigger_state(&self, name: &str) -> Option<bool> {
        self.triggers.get(name).copied()
    }
    /// Create a role with the given permission set if it doesn't exist.
    pub fn create_role(&mut self, name: &str, perms: HashSet<PermissionToken>) -> bool {
        if self.roles.contains_key(name) {
            false
        } else {
            self.roles.insert(name.to_string(), perms);
            true
        }
    }
    /// Delete a role if it has no assignees.
    pub fn delete_role(&mut self, name: &str) -> bool {
        // Ensure no assignments reference this role
        let assigned = self.role_assignments.values().any(|set| set.contains(name));
        if assigned {
            return false;
        }
        self.roles.remove(name).is_some()
    }
    /// Grant a role to an account if the role exists.
    pub fn grant_role(&mut self, account: &AccountId, role: &str) -> bool {
        if !self.roles.contains_key(role) {
            return false;
        }
        let subject = Self::account_subject(account);
        self.role_assignments
            .entry(subject)
            .or_default()
            .insert(role.to_string())
    }
    /// Revoke a role from an account.
    pub fn revoke_role(&mut self, account: &AccountId, role: &str) -> bool {
        let subject = Self::account_subject(account);
        if let Some(set) = self.role_assignments.get_mut(&subject) {
            set.remove(role)
        } else {
            false
        }
    }
    /// Register a new domain. Caller must hold `RegisterDomain`.
    pub fn register_domain(&mut self, caller: &AccountId, id: DomainId) -> bool {
        if !self.has_permission(caller, &PermissionToken::RegisterDomain) {
            return false;
        }
        self.domains.insert(id, ()).is_none()
    }
    /// Unregister a domain if it exists and has no accounts, assets, or NFTs.
    pub fn unregister_domain(&mut self, id: &DomainId) -> bool {
        // Asset-definition identifiers are opaque and do not imply domain
        // ownership. Only explicit domain-owned records may pin this row.
        let has_accounts = self
            .domain_accounts
            .get(id)
            .is_some_and(|subjects| !subjects.is_empty());
        let has_nfts = self.nfts.keys().any(|nft_id| nft_id.domain() == id);
        if has_accounts || has_nfts {
            return false;
        }
        self.domain_accounts.remove(id);
        self.domains.remove(id).is_some()
    }
    /// Register a new account. Returns `true` if it didn't exist before and the domain exists.
    pub fn register_account(&mut self, caller: &AccountId, id: AccountId) -> bool {
        if !self.has_permission(caller, &PermissionToken::RegisterAccount) {
            return false;
        }
        let subject = Self::account_subject(&id);
        self.accounts.insert(subject, Account::default()).is_none()
    }
    /// Attempt to unregister an account from the selected domain.
    ///
    /// If the account subject is linked to multiple domains, only the current
    /// domain link is removed. When the final domain link is removed, subject
    /// authority state remains detached so permissions and role assignments can
    /// be reattached by a later re-registration of the same subject.
    ///
    /// Unlinking the final domain while non-zero balances or NFT ownership
    /// remain is rejected to avoid leaving owned resources without a canonical
    /// account registration in this mock world-state model.
    pub fn unregister_account(&mut self, id: &AccountId) -> bool {
        let subject = Self::account_subject(id);
        self.unregister_account_subject(&subject)
    }
    /// Attempt to unregister an account subject across all linked domains.
    ///
    /// This models the canonical `Unregister::account(AccountId)` surface while
    /// keeping the mock's simplified subject/domain index intact.
    pub fn unregister_account_subject(&mut self, subject: &AccountId) -> bool {
        if !self.accounts.contains_key(subject) {
            return false;
        }
        let has_bal = self
            .balances
            .iter()
            .any(|((acc, _), amount)| acc == subject && !amount.is_zero());
        let has_nfts = self.nfts.values().any(|rec| rec.owner == *subject);
        if has_bal || has_nfts {
            return false;
        }
        for subjects in self.domain_accounts.values_mut() {
            subjects.remove(subject);
        }
        self.domain_accounts
            .retain(|_, subjects| !subjects.is_empty());
        self.accounts.remove(subject);
        true
    }
    /// Register a new asset definition with given mintability.
    ///
    /// The mock matches the core host and accepts canonical opaque asset
    /// definition identifiers without projecting domain ownership from the ID.
    ///
    /// Returns `true` if the definition was added.
    pub fn register_asset_definition(
        &mut self,
        caller: &AccountId,
        id: AssetDefinitionId,
        mintable: Mintable,
    ) -> bool {
        let name = id.to_string();
        self.register_asset_definition_with_spec(
            caller,
            id,
            name,
            NumericSpec::unconstrained(),
            mintable,
        )
    }
    /// Register an asset definition with the display name, numeric spec and
    /// mintability a contract supplied through `REGISTER_ASSET`.
    pub fn register_asset_definition_with_spec(
        &mut self,
        caller: &AccountId,
        id: AssetDefinitionId,
        name: String,
        spec: NumericSpec,
        mintable: Mintable,
    ) -> bool {
        if !self.has_permission(caller, &PermissionToken::RegisterAssetDefinition)
            || iroha_data_model::asset::definition::validate_asset_name(&name).is_err()
        {
            return false;
        }
        if self.asset_definitions.contains_key(&id) {
            return false;
        }
        self.asset_definitions.insert(
            id,
            AssetDefinition::new(name, spec, mintable, caller.clone()),
        );
        true
    }
    /// Display name, numeric spec and mintability recorded for an asset definition.
    pub fn asset_definition_registration(
        &self,
        id: &AssetDefinitionId,
    ) -> Option<(&str, NumericSpec, Mintable)> {
        self.asset_definitions.get(id).map(|definition| {
            (
                definition.name.as_str(),
                definition.spec,
                definition.mintable,
            )
        })
    }
    /// Unregister an asset definition when no non-zero balances exist for it.
    pub fn unregister_asset_definition(&mut self, id: &AssetDefinitionId) -> bool {
        let has_bal = self
            .balances
            .iter()
            .any(|((_, ad), amount)| ad == id && !amount.is_zero());
        if has_bal {
            return false;
        }
        self.asset_definitions.remove(id).is_some()
    }
    /// Get the balance of `account_id` for `asset_id`.
    pub fn balance(&self, account_id: AccountId, asset_id: AssetDefinitionId) -> Quantity {
        if !self.account_is_linked(&account_id) {
            return Quantity::zero();
        }
        let subject = Self::account_subject(&account_id);
        self.balances
            .get(&(subject, asset_id))
            .cloned()
            .unwrap_or_else(Quantity::zero)
    }
    fn is_scale0(amount: &Quantity) -> bool {
        amount.scale() == 0
    }
    /// Get the balance of `account_id` for `asset_id` if `caller` is allowed to
    /// view it. Returns `None` if the caller lacks permission.
    pub fn balance_checked(
        &self,
        caller: &AccountId,
        account_id: &AccountId,
        asset_id: &AssetDefinitionId,
    ) -> Option<Quantity> {
        if Self::account_subject(caller) == Self::account_subject(account_id)
            || self.has_permission(
                caller,
                &PermissionToken::ReadAccountAssets(Self::account_subject(account_id)),
            )
        {
            Some(self.balance(account_id.clone(), asset_id.clone()))
        } else {
            None
        }
    }
    /// Return the last native transfer-availability state applied in this mock world.
    #[must_use]
    pub fn asset_transfer_availability(
        &self,
        account_id: &AccountId,
        asset_id: &AssetDefinitionId,
    ) -> Option<(u64, bool, bool)> {
        self.asset_transfer_availability
            .get(&(Self::account_subject(account_id), asset_id.clone()))
            .copied()
    }
    /// Return the last native daily transfer cap applied in this mock world.
    #[must_use]
    pub fn asset_transfer_daily_limit(
        &self,
        account_id: &AccountId,
        asset_id: &AssetDefinitionId,
    ) -> Option<Option<Quantity>> {
        self.asset_transfer_daily_limits
            .get(&(Self::account_subject(account_id), asset_id.clone()))
            .cloned()
    }
    /// Return the last native holding limit applied in this mock world.
    #[must_use]
    pub fn asset_holding_limit(
        &self,
        account_id: &AccountId,
        asset_id: &AssetDefinitionId,
    ) -> Option<Option<Quantity>> {
        self.asset_holding_limits
            .get(&(Self::account_subject(account_id), asset_id.clone()))
            .cloned()
    }
    /// Transfer `amount` of `asset_id` from `from` to `to`.
    /// Returns `true` on success or `false` if `from` lacks funds.
    pub fn transfer(
        &mut self,
        caller: &AccountId,
        from: AccountId,
        to: AccountId,
        asset_id: AssetDefinitionId,
        amount: Quantity,
    ) -> bool {
        self.transfer_with_permission_bypass(caller, from, to, asset_id, amount, false)
    }
    pub fn transfer_with_permission_bypass(
        &mut self,
        caller: &AccountId,
        from: AccountId,
        to: AccountId,
        asset_id: AssetDefinitionId,
        amount: Quantity,
        bypass_transfer_permission: bool,
    ) -> bool {
        if !self.account_is_linked(&from) || !self.account_is_linked(&to) {
            return false;
        }
        if !Self::is_scale0(&amount) {
            return false;
        }
        if Self::account_subject(caller) != Self::account_subject(&from)
            && !bypass_transfer_permission
        {
            let token = PermissionToken::TransferAsset(asset_id.clone());
            if !self.has_permission(caller, &token) {
                return false;
            }
        }
        let from_subject = Self::account_subject(&from);
        let to_subject = Self::account_subject(&to);
        let from_key = (from_subject, asset_id.clone());
        let to_key = (to_subject, asset_id);
        if from_key == to_key {
            let current = self
                .balances
                .get(&from_key)
                .cloned()
                .unwrap_or_else(Quantity::zero);
            return current.checked_sub(&amount).is_ok();
        }
        let from_current = self
            .balances
            .get(&from_key)
            .cloned()
            .unwrap_or_else(Quantity::zero);
        let from_remaining = match from_current.checked_sub(&amount) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let to_current = self
            .balances
            .get(&to_key)
            .cloned()
            .unwrap_or_else(Quantity::zero);
        let to_next = match to_current.checked_add(&amount) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if from_remaining.is_zero() {
            self.balances.remove(&from_key);
        } else {
            self.balances.insert(from_key, from_remaining);
        }
        self.balances.insert(to_key, to_next);
        true
    }
    /// Mint `amount` of `asset_id` into `account_id`.
    pub fn mint(
        &mut self,
        caller: &AccountId,
        account_id: AccountId,
        asset_id: AssetDefinitionId,
        amount: Quantity,
    ) -> bool {
        if !self.account_is_linked(&account_id) {
            return false;
        }
        if !Self::is_scale0(&amount) {
            return false;
        }
        let token = PermissionToken::MintAsset(asset_id.clone());
        if !self.has_permission(caller, &token) {
            return false;
        }
        let Some(def) = self.asset_definitions.get_mut(&asset_id) else {
            return false;
        };
        if def.spec.check(amount.as_numeric()).is_err() {
            return false;
        }
        let balance_key = (Self::account_subject(&account_id), asset_id.clone());
        let current = self
            .balances
            .get(&balance_key)
            .cloned()
            .unwrap_or_else(Quantity::zero);
        let next = match current.checked_add(&amount) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let total = match def.total_supply.checked_add(&amount) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if def.mintable.consume_one().is_err() {
            return false;
        }
        self.balances.insert(balance_key, next);
        def.total_supply = total;
        true
    }
    /// Burn `amount` of `asset_id` from `account_id`. Returns `true` if the
    /// balance was sufficient and the burn succeeded.
    pub fn burn(
        &mut self,
        caller: &AccountId,
        account_id: AccountId,
        asset_id: AssetDefinitionId,
        amount: Quantity,
    ) -> bool {
        if !self.account_is_linked(&account_id) {
            return false;
        }
        if !Self::is_scale0(&amount) {
            return false;
        }
        if Self::account_subject(caller) != Self::account_subject(&account_id) {
            let token = PermissionToken::BurnAsset(asset_id.clone());
            if !self.has_permission(caller, &token) {
                return false;
            }
        }
        let Some(def) = self.asset_definitions.get_mut(&asset_id) else {
            return false;
        };
        let balance_key = (Self::account_subject(&account_id), asset_id.clone());
        let current = self
            .balances
            .get(&balance_key)
            .cloned()
            .unwrap_or_else(Quantity::zero);
        let remaining = match current.checked_sub(&amount) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let total = match def.total_supply.checked_sub(&amount) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if remaining.is_zero() {
            self.balances.remove(&balance_key);
        } else {
            self.balances.insert(balance_key, remaining);
        }
        def.total_supply = total;
        true
    }
    /// Create an NFT with `owner` and `issuer` if it does not already exist.
    pub fn create_nft(&mut self, owner: AccountId, issuer: AccountId, id: NftId) -> bool {
        if !self.account_is_linked(&owner) || !self.account_is_linked(&issuer) {
            return false;
        }
        let owner_subject = Self::account_subject(&owner);
        let issuer_subject = Self::account_subject(&issuer);
        self.nfts
            .insert(
                id,
                NftRecord {
                    owner: owner_subject,
                    metadata: HashMap::new(),
                    issuer: issuer_subject,
                },
            )
            .is_none()
    }
    /// Transfer an NFT from `from` to `to`. Caller must be the owner or issuer.
    pub fn transfer_nft(
        &mut self,
        caller: &AccountId,
        from: AccountId,
        to: AccountId,
        id: &NftId,
    ) -> bool {
        if !self.account_is_linked(&from) || !self.account_is_linked(&to) {
            return false;
        }
        let caller_subject = Self::account_subject(caller);
        let from_subject = Self::account_subject(&from);
        let to_subject = Self::account_subject(&to);
        let Some(rec) = self.nfts.get_mut(id) else {
            return false;
        };
        if caller_subject != rec.owner && caller_subject != rec.issuer {
            return false;
        }
        if rec.owner != from_subject && caller_subject != rec.owner {
            return false;
        }
        rec.owner = to_subject;
        true
    }
    /// Set keyed metadata for an NFT. Caller must be owner or issuer.
    pub fn set_nft_metadata(
        &mut self,
        caller: &AccountId,
        id: &NftId,
        key: Name,
        json: Vec<u8>,
    ) -> bool {
        let caller_subject = Self::account_subject(caller);
        let Some(rec) = self.nfts.get_mut(id) else {
            return false;
        };
        if rec.owner != caller_subject && rec.issuer != caller_subject {
            return false;
        }
        rec.metadata.insert(key, json);
        true
    }
    /// Burn (remove) an NFT. Caller must be owner or issuer.
    pub fn burn_nft(&mut self, caller: &AccountId, id: &NftId) -> bool {
        let caller_subject = Self::account_subject(caller);
        if let Some(rec) = self.nfts.get(id) {
            if rec.owner != caller_subject && rec.issuer != caller_subject {
                return false;
            }
        } else {
            return false;
        }
        self.nfts.remove(id).is_some()
    }
    /// Return the current owner of an NFT if it exists.
    pub fn nft_owner(&self, id: &NftId) -> Option<AccountId> {
        let subject = self.nfts.get(id).map(|rec| &rec.owner)?;
        self.canonical_account_id_for_subject(subject)
    }
}
#[derive(Clone, Debug)]
struct MockVerifyingKeyRecord {
    commitment: [u8; 32],
}
impl MockWorldStateView {
    fn binding_from_registry(&self, id: &VerifyingKeyId) -> ZkAssetVerifierBinding {
        let commitment = self.verifying_keys.get(id).map(|rec| rec.commitment);
        ZkAssetVerifierBinding {
            id: id.clone(),
            commitment,
        }
    }
}
fn hash_vk_bytes(backend: &str, bytes: &[u8]) -> [u8; 32] {
    let backend_len = u64::try_from(backend.len()).expect("backend length must fit into u64");
    let bytes_len = u64::try_from(bytes.len()).expect("VK length must fit into u64");
    let mut h = Sha256::new();
    h.update(b"iroha:zk:v1:vk");
    h.update(backend_len.to_be_bytes());
    h.update(backend.as_bytes());
    h.update(bytes_len.to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}
// NOTE: These items are already imported at the top of the module. The
// duplicate import caused E0252 (name defined multiple times). Remove it.
// use crate::{error::VMError, host::IVMHost, ivm::IVM, syscalls};
use core::str;
use iroha_data_model::isi::{InstructionBox as DMInstructionBox, zk as DMZk};
// -----------------------------
// ZK shielded ledger structures
// -----------------------------
/// Verifying-key binding enforced for a ZK asset operation.
#[derive(Clone, Debug)]
pub struct ZkAssetVerifierBinding {
    pub id: VerifyingKeyId,
    pub commitment: Option<[u8; 32]>,
}
/// Policy and state for a shielded asset.
#[derive(Clone, Debug, Default)]
pub struct ZkAssetState {
    pub commitments: Vec<[u8; 32]>,
    pub root_history: Vec<HashOf<iroha_crypto::MerkleTree<[u8; 32]>>>,
    pub nullifiers: HashSet<[u8; 32]>,
    pub vk_unshield: Option<ZkAssetVerifierBinding>,
}
/// Election state for anonymous voting.
#[derive(Clone, Debug, Default)]
pub struct ElectionState {
    pub options: u32,
    pub eligible_root: [u8; 32],
    pub start_ts: u64,
    pub end_ts: u64,
    pub finalized: bool,
    pub tally: Vec<u128>,
    pub ballot_nullifiers: HashSet<[u8; 32]>,
    pub ciphertexts: Vec<Vec<u8>>,
}
#[cfg(test)]
fn test_account_id(signatory: &str, domain: &str) -> AccountId {
    let _domain = DomainId::try_new(domain, "universal").expect("test domain id must parse");
    AccountId::new(
        signatory
            .parse()
            .expect("test public key literal must parse"),
    )
}
/// ZK event stream for tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkEvent {
    /// ZK policy was updated for an asset.
    ZkPolicyUpdated { asset: AssetDefinitionId },
    /// New commitment was appended and root updated.
    CommitmentAdded {
        asset: AssetDefinitionId,
        commitment: [u8; 32],
        new_root: [u8; 32],
    },
}
/// Host environment exposing WSV operations via syscalls and enforcing permissions.
#[derive(Clone)]
struct MockAccountAliasBinding {
    account: AccountId,
    domain: Option<Name>,
    dataspace_name: Name,
    dataspace_id: Option<DataSpaceId>,
}
#[derive(Clone)]
pub struct WsvHost {
    pub wsv: MockWorldStateView,
    pub caller: AccountId,
    account_aliases: BTreeMap<String, MockAccountAliasBinding>,
    public_inputs: BTreeMap<Name, Vec<u8>>,
    // ZK verify gating and configuration
    zk_verified_ballot: VecDeque<[u8; 32]>,
    zk_verified_tally: Option<[u8; 32]>,
    zk_cfg: crate::host::ZkVerifyLimits,
    axt_state: Option<axt::HostAxtState>,
    axt_policy: Arc<dyn AxtPolicy>,
    axt_policy_overridden: bool,
    sm_enabled: bool,
    contract_runtime_invoker: Option<AccountId>,
    contract_runtime_address: Option<ContractAddress>,
    contract_runtime_entrypoint: Option<String>,
    contract_fixture_state_scope: Option<ContractAddress>,
    contract_execution_budget: iroha_allocation::AllocationBudget,
    contract_ancestors: Vec<ContractAddress>,
    contract_events: Vec<MockContractEvent>,
    fastpq_batch_entries: Option<Vec<(AccountId, AccountId, AssetDefinitionId, Quantity)>>,
    actual_access: crate::host::AccessLog,
    state_overlay: BTreeMap<StatePath, Option<Vec<u8>>>,
    tx_active: bool,
    /// Authoritative schema registry for typed Norito encode/decode.
    schema: std::sync::Arc<dyn SchemaRegistry + Send + Sync>,
}
#[derive(Clone)]
struct WsvHostSnapshot {
    wsv: MockWorldStateView,
    caller: AccountId,
    account_aliases: BTreeMap<String, MockAccountAliasBinding>,
    public_inputs: BTreeMap<Name, Vec<u8>>,
    zk_verified_ballot: VecDeque<[u8; 32]>,
    zk_verified_tally: Option<[u8; 32]>,
    zk_cfg: crate::host::ZkVerifyLimits,
    axt_state: Option<axt::HostAxtState>,
    axt_policy: Arc<dyn AxtPolicy>,
    axt_policy_overridden: bool,
    sm_enabled: bool,
    contract_runtime_invoker: Option<AccountId>,
    contract_runtime_address: Option<ContractAddress>,
    contract_runtime_entrypoint: Option<String>,
    contract_fixture_state_scope: Option<ContractAddress>,
    contract_execution_budget: iroha_allocation::AllocationBudget,
    contract_ancestors: Vec<ContractAddress>,
    contract_events: Vec<MockContractEvent>,
    fastpq_batch_entries: Option<Vec<(AccountId, AccountId, AssetDefinitionId, Quantity)>>,
    actual_access: crate::host::AccessLog,
    state_overlay: BTreeMap<StatePath, Option<Vec<u8>>>,
    tx_active: bool,
    schema: std::sync::Arc<dyn SchemaRegistry + Send + Sync>,
}
impl WsvHost {
    /// Quote response-producing WSV helpers from pointer headers and ABI
    /// region bounds only. No world-state lookup, schema call, proof walk, or
    /// guest allocation is allowed during preparation.
    fn bounded_response_gas_quote(&self, number: u32, vm: &IVM) -> Result<Option<u64>, VMError> {
        let maximum_output =
            usize::try_from(crate::memory::Memory::INPUT_SIZE).unwrap_or(usize::MAX);
        let quote = match number {
            crate::syscalls::SYSCALL_GET_PUBLIC_INPUT => {
                crate::core_host::CoreHost::quote_codec_tlv_payload_len(
                    vm,
                    10,
                    PointerType::Name,
                    false,
                )?;
                reserve_available_syscall_gas_at_least(vm, PUBLIC_INPUT_GAS_BASE)?
            }
            crate::syscalls::SYSCALL_SCHEMA_ENCODE
            | crate::syscalls::SYSCALL_SCHEMA_DECODE
            | crate::syscalls::SYSCALL_SCHEMA_INFO => {
                let schema = crate::core_host::CoreHost::quote_codec_tlv_payload_len(
                    vm,
                    10,
                    PointerType::Name,
                    false,
                )?;
                let value = match number {
                    crate::syscalls::SYSCALL_SCHEMA_ENCODE => {
                        crate::core_host::CoreHost::quote_codec_tlv_payload_len(
                            vm,
                            11,
                            PointerType::Json,
                            false,
                        )?
                    }
                    crate::syscalls::SYSCALL_SCHEMA_DECODE => {
                        crate::core_host::CoreHost::quote_codec_tlv_payload_len(
                            vm,
                            11,
                            PointerType::NoritoBytes,
                            false,
                        )?
                    }
                    _ => 0,
                };
                Self::schema_gas(schema.saturating_add(value), maximum_output)
            }
            crate::syscalls::SYSCALL_ZK_ROOTS_GET | crate::syscalls::SYSCALL_ZK_VOTE_GET_TALLY => {
                let input = crate::core_host::CoreHost::quote_codec_tlv_payload_len(
                    vm,
                    10,
                    PointerType::NoritoBytes,
                    false,
                )?;
                reserve_available_syscall_gas_at_least(vm, Self::state_query_gas(input))?
            }
            crate::syscalls::SYSCALL_GET_ACCOUNT_BALANCE => {
                crate::core_host::CoreHost::quote_codec_tlv_payload_len(
                    vm,
                    10,
                    PointerType::AccountId,
                    false,
                )?;
                crate::core_host::CoreHost::quote_codec_tlv_payload_len(
                    vm,
                    11,
                    PointerType::AssetDefinitionId,
                    false,
                )?;
                Self::singular_query_gas(maximum_output)
            }
            crate::syscalls::SYSCALL_GET_AUTHORITY | crate::syscalls::SYSCALL_SYSVAR_AUTHORITY => {
                Self::sysvar_gas(maximum_output)
            }
            crate::syscalls::SYSCALL_CURRENT_TIME_MS
            | crate::syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS
            | crate::syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT
            | crate::syscalls::SYSCALL_SYSVAR_CHAIN_ID => Self::sysvar_gas(0),
            crate::syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS => Self::sysvar_gas(
                self.contract_runtime_address
                    .as_ref()
                    .map_or(0, |address| address.as_str().len()),
            ),
            crate::syscalls::SYSCALL_SYSVAR_ENTRYPOINT => Self::sysvar_gas(
                self.contract_runtime_entrypoint
                    .as_ref()
                    .map_or(0, String::len),
            ),
            _ => return Ok(None),
        };
        Ok(Some(quote))
    }
    fn materialize_subject_account(wsv: &mut MockWorldStateView, subject: &AccountId) -> AccountId {
        if let Some(existing) = wsv.canonical_account_id_for_subject(subject) {
            return existing;
        }
        let account_id = subject.clone();
        wsv.add_account_unchecked(account_id.clone());
        account_id
    }
    /// Construct a host from one canonical caller identity.
    pub fn new_with_subject(mut wsv: MockWorldStateView, caller: AccountId) -> Self {
        let caller = Self::materialize_subject_account(&mut wsv, &caller);
        let policy = Self::build_wsv_axt_policy(&wsv);
        Self {
            wsv,
            caller,
            account_aliases: BTreeMap::new(),
            public_inputs: BTreeMap::new(),
            zk_verified_ballot: VecDeque::new(),
            zk_verified_tally: None,
            zk_cfg: crate::host::ZkVerifyLimits::default(),
            axt_state: None,
            axt_policy: policy,
            axt_policy_overridden: false,
            sm_enabled: false,
            contract_runtime_invoker: None,
            contract_runtime_address: None,
            contract_runtime_entrypoint: None,
            contract_fixture_state_scope: None,
            contract_execution_budget: iroha_allocation::AllocationBudget::new(128 * 1024 * 1024),
            contract_ancestors: Vec::new(),
            contract_events: Vec::new(),
            fastpq_batch_entries: None,
            actual_access: crate::host::AccessLog::default(),
            state_overlay: BTreeMap::new(),
            tx_active: false,
            schema: Arc::new(DefaultRegistry::new()),
        }
    }
    /// Return the current canonical caller identity.
    #[must_use]
    pub fn caller_subject(&self) -> AccountId {
        self.caller.clone()
    }
    /// Switch the caller using a canonical account identity.
    pub fn set_caller_subject(&mut self, caller: AccountId) {
        self.caller = Self::materialize_subject_account(&mut self.wsv, &caller);
        self.contract_runtime_invoker = None;
        self.contract_runtime_address = None;
        self.contract_runtime_entrypoint = None;
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
    fn build_wsv_axt_policy(wsv: &MockWorldStateView) -> Arc<SpaceDirectoryAxtPolicy> {
        let slot_length_ms = wsv.slot_length_ms();
        let max_clock_skew_ms = wsv.max_clock_skew_ms();
        let has_explicit_slot = wsv
            .axt_policies
            .values()
            .any(|policy| policy.current_slot != 0);
        let mut policy = SpaceDirectoryAxtPolicy::from_snapshot_with_timing(
            wsv.axt_policy_snapshot(),
            slot_length_ms,
            max_clock_skew_ms,
        );
        if !has_explicit_slot {
            policy = policy.with_current_slot(wsv.current_slot());
        }
        Arc::new(policy)
    }
    fn refresh_axt_policy(&mut self) {
        if !self.axt_policy_overridden {
            self.axt_policy = Self::build_wsv_axt_policy(&self.wsv);
        }
    }
    fn checkpoint_state(&self) -> WsvHostSnapshot {
        WsvHostSnapshot {
            wsv: self.wsv.clone(),
            caller: self.caller.clone(),
            account_aliases: self.account_aliases.clone(),
            public_inputs: self.public_inputs.clone(),
            zk_verified_ballot: self.zk_verified_ballot.clone(),
            zk_verified_tally: self.zk_verified_tally,
            zk_cfg: self.zk_cfg,
            axt_state: self.axt_state.clone(),
            axt_policy: Arc::clone(&self.axt_policy),
            axt_policy_overridden: self.axt_policy_overridden,
            sm_enabled: self.sm_enabled,
            contract_runtime_invoker: self.contract_runtime_invoker.clone(),
            contract_runtime_address: self.contract_runtime_address.clone(),
            contract_runtime_entrypoint: self.contract_runtime_entrypoint.clone(),
            contract_fixture_state_scope: self.contract_fixture_state_scope.clone(),
            contract_execution_budget: self.contract_execution_budget.clone(),
            contract_ancestors: self.contract_ancestors.clone(),
            contract_events: self.contract_events.clone(),
            fastpq_batch_entries: self.fastpq_batch_entries.clone(),
            actual_access: self.actual_access.clone(),
            state_overlay: self.state_overlay.clone(),
            tx_active: self.tx_active,
            schema: self.schema.clone(),
        }
    }
    fn restore_state(&mut self, snapshot: &WsvHostSnapshot) -> Result<(), VMError> {
        self.wsv = snapshot.wsv.clone();
        self.caller = snapshot.caller.clone();
        self.account_aliases = snapshot.account_aliases.clone();
        self.public_inputs = snapshot.public_inputs.clone();
        self.zk_verified_ballot = snapshot.zk_verified_ballot.clone();
        self.zk_verified_tally = snapshot.zk_verified_tally;
        self.zk_cfg = snapshot.zk_cfg;
        self.axt_state = snapshot.axt_state.clone();
        self.axt_policy = Arc::clone(&snapshot.axt_policy);
        self.axt_policy_overridden = snapshot.axt_policy_overridden;
        self.sm_enabled = snapshot.sm_enabled;
        self.contract_runtime_invoker = snapshot.contract_runtime_invoker.clone();
        self.contract_runtime_address = snapshot.contract_runtime_address.clone();
        self.contract_runtime_entrypoint = snapshot.contract_runtime_entrypoint.clone();
        self.contract_fixture_state_scope = snapshot.contract_fixture_state_scope.clone();
        self.contract_execution_budget = snapshot.contract_execution_budget.clone();
        self.contract_ancestors = snapshot.contract_ancestors.clone();
        self.contract_events = snapshot.contract_events.clone();
        self.fastpq_batch_entries = snapshot.fastpq_batch_entries.clone();
        self.actual_access = snapshot.actual_access.clone();
        self.state_overlay = snapshot.state_overlay.clone();
        self.tx_active = snapshot.tx_active;
        self.schema = snapshot.schema.clone();
        self.refresh_axt_policy();
        self.wsv.sc_flush()
    }
    /// Configure Halo2 verification limits for this host.
    pub fn with_zk_verify_limits(mut self, cfg: crate::host::ZkVerifyLimits) -> Self {
        self.zk_cfg = cfg;
        self
    }
    /// Override the default allow-all AXT policy (e.g., when wiring UAID manifests in tests).
    pub fn with_axt_policy(mut self, policy: Arc<dyn AxtPolicy>) -> Self {
        self.axt_policy = policy;
        self.axt_policy_overridden = true;
        self
    }
    /// Configure the expected manifest root for a dataspace (Space Directory policy).
    pub fn set_axt_manifest_root(&mut self, dsid: DataSpaceId, root: [u8; 32]) {
        let entry = self.wsv.axt_policies.entry(dsid).or_default();
        entry.manifest_root = root;
        self.refresh_axt_policy();
    }
    /// Configure the expected lane for a dataspace (Space Directory policy).
    pub fn set_axt_target_lane(&mut self, dsid: DataSpaceId, lane: u8) {
        let entry = self.wsv.axt_policies.entry(dsid).or_default();
        entry.target_lane = LaneId::new(u32::from(lane));
        self.refresh_axt_policy();
    }
    /// Configure the current slot used for expiry checks (Space Directory policy).
    pub fn set_axt_current_slot(&mut self, slot: u64) {
        self.wsv
            .set_current_time_ms(slot * self.wsv.slot_length_ms.max(1));
        self.refresh_axt_policy();
    }
    /// Configure the exact active handle era for a dataspace (Space Directory policy).
    pub fn set_axt_active_handle_era(&mut self, dsid: DataSpaceId, era: u64) {
        let entry = self.wsv.axt_policies.entry(dsid).or_default();
        entry.active_handle_era = era;
        self.refresh_axt_policy();
    }
    /// Configure the exact next handle counter for a dataspace (Space Directory policy).
    pub fn set_axt_next_handle_counter(&mut self, dsid: DataSpaceId, counter: u64) {
        let entry = self.wsv.axt_policies.entry(dsid).or_default();
        entry.next_handle_counter = counter;
        self.refresh_axt_policy();
    }
    /// Builder-style helper to set a manifest root expectation.
    pub fn with_axt_manifest_root(mut self, dsid: DataSpaceId, root: [u8; 32]) -> Self {
        self.set_axt_manifest_root(dsid, root);
        self
    }
    /// Builder-style helper to seed AXT policies from a Space Directory snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AxtPolicySnapshotValidationError`] when the supplied snapshot is not canonical.
    pub fn with_axt_policy_snapshot(
        mut self,
        snapshot: AxtPolicySnapshot,
    ) -> Result<Self, AxtPolicySnapshotValidationError> {
        self.wsv.load_axt_policy_snapshot_model(&snapshot)?;
        self.refresh_axt_policy();
        Ok(self)
    }
    /// Builder-style helper to set a target lane expectation.
    pub fn with_axt_target_lane(mut self, dsid: DataSpaceId, lane: u8) -> Self {
        self.set_axt_target_lane(dsid, lane);
        self
    }
    /// Builder-style helper to set the exact active handle era.
    pub fn with_axt_active_handle_era(mut self, dsid: DataSpaceId, era: u64) -> Self {
        self.set_axt_active_handle_era(dsid, era);
        self
    }
    /// Builder-style helper to set the exact next handle counter.
    pub fn with_axt_next_handle_counter(mut self, dsid: DataSpaceId, sub_nonce: u64) -> Self {
        self.set_axt_next_handle_counter(dsid, sub_nonce);
        self
    }
    /// Override the logical wall-clock timestamp and propagate to AXT expiry slot checks.
    pub fn set_current_time_ms(&mut self, ts: u64) {
        self.wsv.set_current_time_ms(ts);
        self.refresh_axt_policy();
    }
    fn log_read_key(&mut self, key: &str) {
        self.actual_access.read_keys.insert(key.to_string());
    }
    fn log_write_key(&mut self, key: &str) {
        self.actual_access.write_keys.insert(key.to_string());
        self.actual_access.state_writes.push(StateUpdate {
            key: key.to_string(),
            value: 1,
        });
    }
    fn state_key_matches_prefix(key: &str, prefix: &str) -> bool {
        key == prefix
            || key
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
    fn state_key_present(&self, key: &StatePath) -> bool {
        if self.tx_active
            && let Some(entry) = self.state_overlay.get(key)
        {
            return entry.is_some();
        }
        self.wsv.state_overlay.get_ref(key).is_some()
    }
    fn state_value_payload_len(stored: &[u8]) -> Result<usize, VMError> {
        crate::host::validate_state_value_payload_len(stored.len())?;
        Ok(stored.len())
    }
    fn state_value_len(&self, key: &StatePath) -> Result<Option<usize>, VMError> {
        if self.tx_active
            && let Some(entry) = self.state_overlay.get(key)
        {
            return entry
                .as_deref()
                .map(Self::state_value_payload_len)
                .transpose();
        }
        self.wsv
            .state_overlay
            .value_payload_ref(key)?
            .map(Self::state_value_payload_len)
            .transpose()
    }
    fn state_query_gas(payload_len: usize) -> u64 {
        16_u64.saturating_add(u64::try_from(payload_len).unwrap_or(u64::MAX))
    }
    /// Materialize the one typed definition query supported by the scale-zero mock.
    /// No page scan or general query executor is implied by this bounded read.
    fn asset_definition_query(&self, vm: &mut IVM) -> Result<u64, VMError> {
        let id = self.decode_asset_reg(vm, 11)?;
        let input_len = vm.validate_tlv(vm.register(11))?.payload.len();
        let layout = crate::sum::SumLayoutV1::option(7).map_err(|_| VMError::DecodeError)?;
        let Some(definition) = self.wsv.asset_definitions.get(&id) else {
            let gas = Self::state_query_gas(input_len);
            preflight_reserved_syscall_gas(vm, gas)?;
            let handle = crate::sum::allocate_words(vm, layout, 0, &[])?;
            vm.set_register(10, handle);
            return Ok(gas);
        };
        // The mock only stores integer quantities. Reporting an unconstrained or
        // caller-selected scale would conceal precision failures in pool tests.
        let scale = iroha_primitives::numeric_abi::IntValueV1::try_new(0.into())
            .and_then(|value| value.encode_frame())
            .map_err(|_| VMError::NoritoInvalid)?;
        let quantity = QuantityValueV1::new(definition.total_supply.clone())
            .encode_frame()
            .map_err(|_| VMError::NoritoInvalid)?;
        let metadata = Json::from(njson::Value::Object(njson::Map::new()));
        let leaves = [
            (
                PointerType::AssetDefinitionId,
                encode_canonical_norito(&id)?,
            ),
            (PointerType::Blob, Vec::new()),
            (
                PointerType::AccountId,
                encode_canonical_norito(&definition.owner)?,
            ),
            (PointerType::Quantity, quantity),
            (PointerType::Int, scale),
            (PointerType::Json, encode_canonical_norito(&metadata)?),
        ];
        let output_len = leaves.iter().fold(0usize, |total, (_, payload)| {
            total
                .saturating_add(payload.len())
                .saturating_add(7 + CryptoHash::LENGTH)
        });
        let gas = Self::state_query_gas(input_len.saturating_add(output_len));
        preflight_reserved_syscall_gas(vm, gas)?;
        let mut pointers = [0; 6];
        for (index, (kind, payload)) in leaves.iter().enumerate() {
            pointers[index] = Self::alloc_tlv_payload(vm, *kind, payload)?;
        }
        let optional = crate::sum::SumLayoutV1::option(1).map_err(|_| VMError::DecodeError)?;
        let description = crate::sum::allocate_words(vm, optional, 0, &[])?;
        let numeric_scale = crate::sum::allocate_words(vm, optional, 1, &[pointers[4]])?;
        let words = [
            pointers[0],
            pointers[1],
            description,
            pointers[2],
            pointers[3],
            numeric_scale,
            pointers[5],
        ];
        let handle = crate::sum::allocate_words(vm, layout, 1, &words)?;
        vm.set_register(10, handle);
        Ok(gas)
    }
    fn sysvar_gas(payload_len: usize) -> u64 {
        16_u64.saturating_add(u64::try_from(payload_len).unwrap_or(u64::MAX))
    }
    fn singular_query_gas(payload_len: usize) -> u64 {
        1_000_u64
            .saturating_add(250)
            .saturating_add(2_u64.saturating_mul(u64::try_from(payload_len).unwrap_or(u64::MAX)))
    }
    fn byte_gas(base: u64, input_len: usize, output_len: usize) -> u64 {
        base.saturating_add(u64::try_from(input_len).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(output_len).unwrap_or(u64::MAX))
    }
    fn json_gas(input_len: usize, output_len: usize) -> u64 {
        Self::byte_gas(16, input_len, output_len)
    }
    fn name_decode_gas(input_len: usize, output_len: usize) -> u64 {
        Self::byte_gas(16, input_len, output_len)
    }
    #[cfg(test)]
    fn path_gas(input_len: usize, output_len: usize) -> u64 {
        Self::byte_gas(16, input_len, output_len)
    }
    fn schema_gas(input_len: usize, output_len: usize) -> u64 {
        Self::byte_gas(32, input_len, output_len)
    }
    fn pointer_gas(payload_len: usize) -> u64 {
        16_u64.saturating_add(u64::try_from(payload_len).unwrap_or(u64::MAX))
    }
    fn tlv_eq_gas(left_len: usize, right_len: usize) -> u64 {
        let bytes = u64::try_from(left_len)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(right_len).unwrap_or(u64::MAX));
        16_u64.saturating_add(bytes)
    }
    fn tlv_len_gas(payload_len: usize) -> u64 {
        16_u64.saturating_add(u64::try_from(payload_len).unwrap_or(u64::MAX))
    }
    fn verify_gas(payload_len: usize) -> u64 {
        64_u64.saturating_add(u64::try_from(payload_len).unwrap_or(u64::MAX))
    }
    fn axt_gas(payload_len: usize) -> u64 {
        let bytes = u64::try_from(payload_len).unwrap_or(u64::MAX);
        AXT_GAS_BASE.saturating_add(AXT_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn axt_commit_gas(state: &axt::HostAxtState) -> u64 {
        let entries = state.touches().len().saturating_add(state.proofs().len());
        Self::axt_gas(entries)
    }
    fn input_publish_gas(envelope_len: usize) -> u64 {
        let bytes = u64::try_from(envelope_len).unwrap_or(u64::MAX);
        INPUT_PUBLISH_GAS_BASE.saturating_add(INPUT_PUBLISH_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn mutation_gas(payload_len: usize) -> u64 {
        let bytes = u64::try_from(payload_len).unwrap_or(u64::MAX);
        MUTATION_GAS.saturating_add(MUTATION_GAS_PER_BYTE.saturating_mul(bytes))
    }
    fn mutation_batch_gas(entries: usize) -> u64 {
        MUTATION_GAS.saturating_mul(u64::try_from(entries).unwrap_or(u64::MAX))
    }
    fn state_count_with_prefix(
        &self,
        vm: &IVM,
        prefix: &StatePath,
        path_len: usize,
    ) -> Result<(u64, u64), VMError> {
        let prefix_text = prefix.as_ref();
        let backing = self.wsv.state_overlay.keys_with_text_prefix(prefix_text);
        let overlay = self
            .state_overlay
            .range::<str, _>((
                std::ops::Bound::Included(prefix_text),
                std::ops::Bound::Unbounded,
            ))
            .take_while(|(key, _)| key.as_ref().starts_with(prefix_text))
            .take(if self.tx_active { usize::MAX } else { 0 })
            .map(|(key, value)| (key, value.is_some()));
        let mut total = 0_u64;
        let mut scan_work_gas = u64::try_from(path_len).unwrap_or(u64::MAX);
        for (key, present) in crate::state_scan::merge_candidates(backing, overlay) {
            crate::host::preflight_reserved_state_scan_work(vm, scan_work_gas, key.as_ref().len())?;
            crate::host::validate_state_path(key)?;
            scan_work_gas = scan_work_gas
                .saturating_add(1)
                .saturating_add(u64::try_from(key.as_ref().len()).unwrap_or(u64::MAX));
            if present && Self::state_key_matches_prefix(key.as_ref(), prefix_text) {
                total = total.saturating_add(1);
            }
        }
        Ok((total, scan_work_gas))
    }
    /// Enable or disable SM helper syscalls.
    pub fn with_sm_enabled(mut self, enabled: bool) -> Self {
        self.sm_enabled = enabled;
        self
    }
    /// Toggle SM helper support at runtime.
    pub fn set_sm_enabled(&mut self, enabled: bool) {
        self.sm_enabled = enabled;
    }
    /// Bind a deployed-contract invocation while keeping the invoking authority distinct from
    /// the immutable account which authorizes ledger effects.
    pub fn bind_contract_runtime_context(
        &mut self,
        invoker: AccountId,
        contract: ContractAddress,
        entrypoint: String,
    ) -> Result<(), String> {
        if entrypoint.is_empty() || entrypoint.trim() != entrypoint {
            return Err(
                "contract runtime entrypoint must be a non-empty canonical selector".into(),
            );
        }
        let invoker = Self::materialize_subject_account(&mut self.wsv, &invoker);
        let contract_subject =
            Self::materialize_subject_account(&mut self.wsv, &contract.subject_id());
        self.caller = contract_subject;
        self.contract_runtime_invoker = Some(invoker);
        self.contract_runtime_address = Some(contract);
        self.contract_runtime_entrypoint = Some(entrypoint);
        Ok(())
    }
    /// Leave deployed-contract scope and restore the surrounding authority.
    pub fn clear_contract_runtime_context(&mut self, authority: AccountId) {
        self.caller = Self::materialize_subject_account(&mut self.wsv, &authority);
        self.contract_runtime_invoker = None;
        self.contract_runtime_address = None;
        self.contract_runtime_entrypoint = None;
    }
    fn context_authority_subject(&self) -> AccountId {
        self.contract_runtime_invoker
            .clone()
            .unwrap_or_else(|| self.caller.clone())
    }
    fn parse_account_alias_scope(alias: &str) -> Result<(Option<Name>, Name), String> {
        if alias.is_empty() || alias.trim() != alias {
            return Err("account alias must be a non-empty canonical literal".to_owned());
        }
        let mut at_parts = alias.split('@');
        let label = at_parts.next().unwrap_or_default();
        let scope = at_parts
            .next()
            .ok_or_else(|| "account alias must contain exactly one `@`".to_owned())?;
        if at_parts.next().is_some() {
            return Err("account alias must contain exactly one `@`".to_owned());
        }
        let label_name = Name::from_str(label)
            .map_err(|_| "account alias label is not a canonical Name".to_owned())?;
        if label_name.as_ref() != label {
            return Err("account alias label is not canonically encoded".to_owned());
        }
        let scope_parts = scope.split('.').collect::<Vec<_>>();
        if !(1..=2).contains(&scope_parts.len()) {
            return Err(
                "account alias must be `name@dataspace` or `name@domain.dataspace`".to_owned(),
            );
        }
        let mut canonical_parts = Vec::with_capacity(scope_parts.len());
        for part in scope_parts {
            let name = Name::from_str(part)
                .map_err(|_| "account alias scope contains an invalid Name".to_owned())?;
            if name.as_ref() != part {
                return Err("account alias scope is not canonically encoded".to_owned());
            }
            canonical_parts.push(name);
        }
        match canonical_parts.as_slice() {
            [dataspace] => Ok((None, dataspace.clone())),
            [domain, dataspace] => Ok((Some(domain.clone()), dataspace.clone())),
            _ => unreachable!("scope arity was validated above"),
        }
    }
    /// Seed one canonical account alias for contract-test query execution.
    pub fn register_account_alias(
        &mut self,
        alias: String,
        account: AccountId,
    ) -> Result<(), String> {
        self.register_account_alias_with_dataspace(alias, account, None)
    }
    /// Seed a canonical account alias together with its exact numeric dataspace binding.
    pub fn register_account_alias_with_dataspace(
        &mut self,
        alias: String,
        account: AccountId,
        dataspace_id: Option<DataSpaceId>,
    ) -> Result<(), String> {
        let (domain, dataspace_name) = Self::parse_account_alias_scope(&alias)?;
        let account = Self::materialize_subject_account(&mut self.wsv, &account);
        if let Some(existing) = self.account_aliases.get(&alias) {
            let conflict = if existing.account == account && existing.dataspace_id == dataspace_id {
                "duplicate"
            } else {
                "conflicting"
            };
            return Err(format!(
                "{conflict} account alias registration for `{alias}` (existing `{}`, requested `{account}`)",
                existing.account,
            ));
        }
        self.account_aliases.insert(
            alias,
            MockAccountAliasBinding {
                account,
                domain,
                dataspace_name,
                dataspace_id,
            },
        );
        Ok(())
    }
    fn account_transfer_control_scope(
        &self,
        account: &AccountId,
    ) -> Result<(Name, Name, DataSpaceId), VMError> {
        let mut matching = self
            .account_aliases
            .values()
            .filter(|binding| binding.account == *account)
            .filter_map(|binding| {
                Some((
                    binding.domain.clone()?,
                    binding.dataspace_name.clone(),
                    binding.dataspace_id?,
                ))
            });
        let scope = matching.next().ok_or(VMError::PermissionDenied)?;
        if matching.any(|candidate| candidate != scope) {
            return Err(VMError::PermissionDenied);
        }
        Ok(scope)
    }
    fn load_state_value(vm: &mut IVM, stored: &[u8]) -> Result<(), VMError> {
        crate::host::validate_state_value_payload_len(stored.len())?;
        let mut env = Vec::with_capacity(7 + stored.len() + iroha_crypto::Hash::LENGTH);
        env.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
        env.push(1);
        env.extend_from_slice(&(stored.len() as u32).to_be_bytes());
        env.extend_from_slice(stored);
        let h: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new(stored).into();
        env.extend_from_slice(&h);
        let p = vm.alloc_host_tlv(&env)?;
        vm.set_register(10, p);
        Ok(())
    }
    #[cfg(test)]
    pub fn __test_push_verified_ballot(&mut self, hash: [u8; 32]) {
        self.zk_verified_ballot.push_back(hash);
    }
    #[cfg(test)]
    pub fn __test_set_verified_tally(&mut self, hash: [u8; 32]) {
        self.zk_verified_tally = Some(hash);
    }
    #[cfg(test)]
    pub fn __test_verified_tally(&self) -> Option<[u8; 32]> {
        self.zk_verified_tally
    }
    fn decode_account_payload(&self, payload: &[u8]) -> Result<AccountId, VMError> {
        decode_canonical_norito(payload).map_err(|_| VMError::DecodeError)
    }
    fn decode_asset_payload(&self, payload: &[u8]) -> Result<AssetDefinitionId, VMError> {
        decode_canonical_norito(payload).map_err(|_| VMError::DecodeError)
    }
    fn decode_domain_payload(&self, payload: &[u8]) -> Result<DomainId, VMError> {
        decode_canonical_norito(payload).map_err(|_| VMError::DecodeError)
    }
    fn decode_nft_payload(&self, payload: &[u8]) -> Result<NftId, VMError> {
        decode_canonical_norito(payload).map_err(|_| VMError::DecodeError)
    }
    /// Decode an `AccountId` from a provenance-valid V1 TLV pointer.
    fn decode_account_reg(&self, vm: &IVM, reg: usize) -> Result<AccountId, VMError> {
        let v = vm.register(reg);
        if crate::dev_env::debug_wsv_enabled() {
            eprintln!("[wsv.decode_account_reg] reg=r{reg} ptr=0x{v:08x}");
        }
        let tlv = vm.validate_tlv(v)?;
        if crate::dev_env::debug_wsv_enabled() {
            eprintln!(
                "[wsv.decode_account_reg] tlv type={:?} len={}",
                tlv.type_id,
                tlv.payload.len()
            );
        }
        if tlv.type_id != PointerType::AccountId {
            return Err(VMError::NoritoInvalid);
        }
        self.decode_account_payload(tlv.payload)
    }
    /// Decode a canonical account subject from a provenance-valid V1 TLV pointer.
    fn decode_account_subject_reg(&self, vm: &IVM, reg: usize) -> Result<AccountId, VMError> {
        self.decode_account_reg(vm, reg)
    }
    fn decode_canonical_account_reg(&self, vm: &IVM, reg: usize) -> Result<AccountId, VMError> {
        let subject = self.decode_account_subject_reg(vm, reg)?;
        self.wsv
            .canonical_account_id_for_subject(&subject)
            .ok_or(VMError::DecodeError)
    }
    /// Decode an `AssetDefinitionId` from a provenance-valid V1 TLV pointer.
    fn decode_asset_reg(&self, vm: &IVM, reg: usize) -> Result<AssetDefinitionId, VMError> {
        let v = vm.register(reg);
        let tlv = vm.validate_tlv(v)?;
        if tlv.type_id != PointerType::AssetDefinitionId {
            return Err(VMError::NoritoInvalid);
        }
        self.decode_asset_payload(tlv.payload)
    }
    fn decode_dataspace_reg(&self, vm: &IVM, reg: usize) -> Result<DataSpaceId, VMError> {
        let v = vm.register(reg);
        let tlv = vm.validate_tlv(v)?;
        if tlv.type_id != PointerType::DataSpaceId {
            return Err(VMError::NoritoInvalid);
        }
        decode_canonical_norito::<DataSpaceId>(tlv.payload).map_err(|_| VMError::DecodeError)
    }
    /// Decode one canonical V1 `quantity` argument from a register.
    fn decode_amount_reg(&self, vm: &IVM, reg: usize) -> Result<Quantity, VMError> {
        let tlv = vm.validate_tlv(vm.register(reg))?;
        if tlv.type_id != PointerType::Quantity {
            return Err(VMError::NoritoInvalid);
        }
        QuantityValueV1::decode_frame(tlv.payload)
            .map(QuantityValueV1::into_quantity)
            .map_err(|_| VMError::DecodeError)
    }
    /// Decode NftId from a register that may be an INPUT TLV pointer.
    fn decode_nft_reg(&self, vm: &IVM, reg: usize) -> Result<NftId, VMError> {
        let v = vm.register(reg);
        if crate::dev_env::debug_wsv_enabled() {
            eprintln!("[wsv.decode_nft_reg] reg=r{reg} ptr=0x{v:08x}");
        }
        // No index map for NftId in this mock; require TLV pointer
        let tlv = vm.validate_tlv(v)?;
        if crate::dev_env::debug_wsv_enabled() {
            eprintln!(
                "[wsv.decode_nft_reg] tlv type={:?} len={}",
                tlv.type_id,
                tlv.payload.len()
            );
        }
        if tlv.type_id != PointerType::NftId {
            return Err(VMError::NoritoInvalid);
        }
        self.decode_nft_payload(tlv.payload)
    }
    fn begin_fastpq_batch(&mut self) -> Result<u64, VMError> {
        if self.fastpq_batch_entries.is_some() {
            return Err(VMError::metered(
                gas::G_FASTPQ_BATCH,
                VMError::PermissionDenied,
            ));
        }
        self.fastpq_batch_entries = Some(Vec::new());
        Ok(gas::G_FASTPQ_BATCH)
    }
    fn push_fastpq_batch_entry(&mut self, vm: &IVM) -> Result<u64, VMError> {
        if self.fastpq_batch_entries.is_none() {
            return Err(VMError::PermissionDenied);
        }
        let from = self.decode_account_reg(vm, 10)?;
        let to = self.decode_account_reg(vm, 11)?;
        let asset = self.decode_asset_reg(vm, 12)?;
        let amount = self.decode_amount_reg(vm, 13)?;
        self.fastpq_batch_entries
            .as_mut()
            .expect("batch presence checked above")
            .push((from, to, asset, amount));
        Ok(Self::mutation_gas(0))
    }
    fn finish_fastpq_batch(&mut self) -> Result<u64, VMError> {
        let Some(entries) = self.fastpq_batch_entries.take() else {
            return Err(VMError::metered(
                gas::G_FASTPQ_BATCH,
                VMError::PermissionDenied,
            ));
        };
        if entries.is_empty() {
            return Err(VMError::metered(gas::G_FASTPQ_BATCH, VMError::DecodeError));
        }
        for (from, to, asset, amount) in entries {
            if !self.wsv.transfer(
                &self.caller,
                from.clone(),
                to.clone(),
                asset.clone(),
                amount,
            ) {
                return Err(VMError::PermissionDenied);
            }
        }
        Ok(gas::G_FASTPQ_BATCH)
    }
    fn apply_fastpq_batch_tlv(&mut self, vm: &IVM) -> Result<u64, VMError> {
        if self.fastpq_batch_entries.is_some() {
            return Err(VMError::PermissionDenied);
        }
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
        let entry_count = batch.entries().len();
        for entry in batch.entries() {
            let from = Self::materialize_subject_account(&mut self.wsv, entry.from());
            let to = Self::materialize_subject_account(&mut self.wsv, entry.to());
            if !self.wsv.transfer(
                &self.caller,
                from,
                to,
                entry.asset_definition().clone(),
                entry.amount().clone(),
            ) {
                return Err(VMError::PermissionDenied);
            }
        }
        Ok(Self::mutation_batch_gas(entry_count))
    }
    fn unsupported_syscall_error(number: u32) -> VMError {
        if syscalls::abi_syscall_list().binary_search(&number).is_ok() {
            VMError::metered_not_implemented(MUTATION_GAS, number)
        } else {
            VMError::UnknownSyscall(number)
        }
    }
    fn axt_expiry_slot_with_skew(&self, expiry_slot: u64) -> u64 {
        axt::expiry_slot_with_skew(
            expiry_slot,
            self.wsv.slot_length_ms(),
            self.wsv.max_clock_skew_ms(),
            None,
        )
    }
    fn validate_axt_proof(&self, dsid: DataSpaceId, proof: &ProofBlob) -> Result<(), VMError> {
        let Some(policy) = self.wsv.axt_policies.get(&dsid) else {
            return Err(VMError::PermissionDenied);
        };
        if policy.manifest_root.iter().all(|byte| *byte == 0) {
            return Err(VMError::PermissionDenied);
        }
        axt::validate_proof_blob(proof)?;
        if let Some(expiry_slot) = proof.expiry_slot {
            let expiry_with_skew = self.axt_expiry_slot_with_skew(expiry_slot);
            let current_slot = policy.current_slot;
            if current_slot > 0 && current_slot > expiry_with_skew {
                return Err(VMError::PermissionDenied);
            }
        }
        let envelope = decode_canonical_norito::<axt::AxtProofEnvelope>(&proof.payload)?;
        axt::preflight_fastpq_v1_proof_envelope_for_manifest(
            &envelope,
            dsid,
            policy.manifest_root,
        )?;
        // The mock WSV host can diagnose envelope routing, but it does not link
        // the real FastPQ verifier. Proof-consuming calls therefore fail closed.
        Err(VMError::PermissionDenied)
    }
    fn handle_axt_begin(&mut self, vm: &mut IVM) -> Result<u64, VMError> {
        self.refresh_axt_policy();
        let tlv = vm.validate_tlv(vm.register(10))?;
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
        let ds_tlv = vm.validate_tlv(vm.register(10))?;
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
        self.axt_policy.allow_touch(dsid, &manifest)?;
        state.record_touch(dsid, manifest)?;
        Ok(Self::axt_gas(gas_len))
    }
    fn handle_axt_verify_ds_proof(&mut self, vm: &mut IVM) -> Result<u64, VMError> {
        let state_view = self.axt_state.as_ref().ok_or(VMError::PermissionDenied)?;
        let ds_tlv = vm.validate_tlv(vm.register(10))?;
        if ds_tlv.type_id != PointerType::DataSpaceId {
            return Err(VMError::NoritoInvalid);
        }
        let dsid: DataSpaceId = decode_canonical_norito(ds_tlv.payload)?;
        if !state_view.expected_dsids().contains(&dsid) {
            return Err(VMError::PermissionDenied);
        }
        let proof_ptr = vm.register(11);
        if proof_ptr == 0 {
            if !self.wsv.axt_policies.contains_key(&dsid) {
                return Err(VMError::PermissionDenied);
            }
            let state = self.axt_state.as_mut().expect("axt_state checked above");
            state.record_proof(dsid, None, None)?;
            return Ok(Self::verify_gas(0));
        }
        let proof_tlv = vm.validate_tlv(proof_ptr)?;
        if proof_tlv.type_id != PointerType::ProofBlob {
            return Err(VMError::NoritoInvalid);
        }
        let gas = Self::verify_gas(proof_tlv.payload.len());
        let proof: ProofBlob = decode_canonical_norito(proof_tlv.payload)?;
        axt::validate_proof_blob(&proof)?;
        self.validate_axt_proof(dsid, &proof)?;
        let state = self.axt_state.as_mut().expect("axt_state checked above");
        state.record_proof(dsid, Some(proof), None)?;
        Ok(gas)
    }
    fn handle_axt_commit(&mut self) -> Result<u64, VMError> {
        let state = self.axt_state.take().ok_or(VMError::PermissionDenied)?;
        let gas = Self::axt_commit_gas(&state);
        match state.validate_commit() {
            Ok(()) => Ok(gas),
            Err(err) => {
                self.axt_state = Some(state);
                Err(err)
            }
        }
    }
    fn handle_submit_ballot(&mut self, instr: &DMZk::SubmitBallot) -> Result<u64, VMError> {
        let Some(expected_hash) = self.zk_verified_ballot.pop_front() else {
            return Err(VMError::PermissionDenied);
        };
        let mut proof = instr.ballot_proof().clone();
        match proof.envelope_hash {
            Some(hash) if hash != expected_hash => {
                return Err(VMError::PermissionDenied);
            }
            None => {
                proof.envelope_hash = Some(expected_hash);
            }
            _ => {}
        }
        let ok = self.wsv.submit_ballot(
            instr.election_id(),
            instr.ciphertext().clone(),
            *instr.nullifier(),
            proof,
        );
        if ok {
            Ok(Self::mutation_gas(0))
        } else {
            Err(VMError::PermissionDenied)
        }
    }
    #[cfg(test)]
    fn handle_finalize_election(&mut self, instr: &DMZk::FinalizeElection) -> Result<u64, VMError> {
        let Some(expected_hash) = self.zk_verified_tally.take() else {
            return Err(VMError::PermissionDenied);
        };
        let mut proof = instr.tally_proof().clone();
        match proof.envelope_hash {
            Some(hash) if hash != expected_hash => {
                return Err(VMError::PermissionDenied);
            }
            None => {
                proof.envelope_hash = Some(expected_hash);
            }
            _ => {}
        }
        let ok = self
            .wsv
            .finalize_election(instr.election_id(), instr.tally().clone(), proof);
        if ok {
            Ok(Self::mutation_gas(0))
        } else {
            Err(VMError::PermissionDenied)
        }
    }
    /// Decode a DomainId from a provenance-valid pointer-ABI TLV register.
    fn decode_domain_reg(&self, vm: &IVM, reg: usize) -> Result<DomainId, VMError> {
        let v = vm.register(reg);
        if crate::dev_env::debug_wsv_enabled() {
            eprintln!("[wsv] decode_domain_reg: r{reg}=0x{v:x}");
        }
        let tlv = vm.validate_tlv(v)?;
        if crate::dev_env::debug_wsv_enabled() {
            eprintln!(
                "[wsv] TLV: type=0x{:04x} len={}",
                tlv.type_id as u16,
                tlv.payload.len()
            );
        }
        if tlv.type_id != PointerType::DomainId {
            return Err(VMError::NoritoInvalid);
        }
        self.decode_domain_payload(tlv.payload)
    }
    fn alloc_tlv_payload(
        vm: &mut IVM,
        pointer_type: PointerType,
        payload: &[u8],
    ) -> Result<u64, VMError> {
        let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
        out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
        out.push(1);
        let len = u32::try_from(payload.len()).map_err(|_| VMError::NoritoInvalid)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        let h: [u8; iroha_crypto::Hash::LENGTH] = iroha_crypto::Hash::new(payload).into();
        out.extend_from_slice(&h);
        vm.alloc_host_tlv(&out)
    }
    fn decode_name_payload(&self, payload: &[u8]) -> Result<Name, VMError> {
        decode_canonical_norito(payload).map_err(|_| VMError::DecodeError)
    }
    fn decode_name_reg(&self, vm: &IVM, reg: usize) -> Result<Name, VMError> {
        let v = vm.register(reg);
        let resolved = crate::core_host::CoreHost::resolve_code_tlv_addr(vm, v);
        let tlv = vm.validate_tlv(resolved)?;
        if tlv.type_id != PointerType::Name {
            return Err(VMError::NoritoInvalid);
        }
        self.decode_name_payload(tlv.payload)
    }
    fn decode_state_path_reg(&self, vm: &IVM, reg: usize) -> Result<(StatePath, usize), VMError> {
        let pointer = crate::core_host::CoreHost::resolve_code_tlv_addr(vm, vm.register(reg));
        let tlv = vm.validate_tlv(pointer)?;
        if tlv.type_id != PointerType::NoritoBytes
            || tlv.payload.len() > syscalls::STATE_MAX_PATH_FRAME_BYTES
        {
            return Err(VMError::NoritoInvalid);
        }
        let path: StatePath =
            decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
        crate::host::validate_state_path(&path)?;
        Ok((path, tlv.payload.len()))
    }
}
/// Parse a permission token from a compact Name string. Supported formats:
/// - "register_domain"
/// - "register_account"
/// - "register_asset_definition"
/// - "read_assets:<account_id>"
/// - "mint_asset:<asset_def_id>"
/// - "burn_asset:<asset_def_id>"
/// - "transfer_asset:<asset_def_id>"
fn parse_permission_name(s: &str) -> Result<PermissionToken, VMError> {
    if s == "register_domain" {
        return Ok(PermissionToken::RegisterDomain);
    }
    if s == "register_account" {
        return Ok(PermissionToken::RegisterAccount);
    }
    if s == "register_asset_definition" {
        return Ok(PermissionToken::RegisterAssetDefinition);
    }
    if let Some(rest) = s.strip_prefix("read_assets:") {
        let id = parse_account_subject_literal(rest)?;
        return Ok(PermissionToken::ReadAccountAssets(id));
    }
    if let Some(rest) = s.strip_prefix("add_signatory:") {
        let id = parse_account_subject_literal(rest)?;
        return Ok(PermissionToken::AddSignatory(id));
    }
    if let Some(rest) = s.strip_prefix("remove_signatory:") {
        let id = parse_account_subject_literal(rest)?;
        return Ok(PermissionToken::RemoveSignatory(id));
    }
    if let Some(rest) = s.strip_prefix("set_account_quorum:") {
        let id = parse_account_subject_literal(rest)?;
        return Ok(PermissionToken::SetAccountQuorum(id));
    }
    if let Some(rest) = s.strip_prefix("set_account_detail:") {
        let id = parse_account_subject_literal(rest)?;
        return Ok(PermissionToken::SetAccountDetail(id));
    }
    if let Some(rest) = s.strip_prefix("register_zk_asset:") {
        let id =
            AssetDefinitionId::parse_address_literal(rest).map_err(|_| VMError::NoritoInvalid)?;
        return Ok(PermissionToken::RegisterZkAsset(id));
    }
    if let Some(rest) = s.strip_prefix("mint_asset:") {
        let id =
            AssetDefinitionId::parse_address_literal(rest).map_err(|_| VMError::NoritoInvalid)?;
        return Ok(PermissionToken::MintAsset(id));
    }
    if let Some(rest) = s.strip_prefix("burn_asset:") {
        let id =
            AssetDefinitionId::parse_address_literal(rest).map_err(|_| VMError::NoritoInvalid)?;
        return Ok(PermissionToken::BurnAsset(id));
    }
    if let Some(rest) = s.strip_prefix("transfer_asset:") {
        let id =
            AssetDefinitionId::parse_address_literal(rest).map_err(|_| VMError::NoritoInvalid)?;
        return Ok(PermissionToken::TransferAsset(id));
    }
    if s == "manage_roles" {
        return Ok(PermissionToken::ManageRoles);
    }
    if s == "manage_permissions" {
        return Ok(PermissionToken::ManagePermissions);
    }
    if s == "manage_triggers" {
        return Ok(PermissionToken::ManageTriggers);
    }
    if s == "manage_peers" {
        return Ok(PermissionToken::ManagePeers);
    }
    if s.is_empty() {
        return Err(VMError::NoritoInvalid);
    }
    Ok(PermissionToken::Custom(s.to_string()))
}
const PUBLIC_INPUT_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const PUBLIC_INPUT_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const DEBUG_GAS: u64 = gas::HOST_DEBUG_GAS_BASE;
const INPUT_PUBLISH_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const INPUT_PUBLISH_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const MUTATION_GAS: u64 = gas::HOST_BYTE_GAS_BASE;
const MUTATION_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
const AXT_GAS_BASE: u64 = gas::HOST_BYTE_GAS_BASE;
const AXT_GAS_PER_BYTE: u64 = gas::SYSCALL_GAS_PER_BYTE;
/// Decode one canonical pointer-ABI `Json` payload.
fn parse_json_value(bytes: &[u8]) -> Result<njson::Value, VMError> {
    let json: Json = decode_canonical_norito(bytes)?;
    njson::from_str(json.get()).map_err(|_| VMError::NoritoInvalid)
}
/// Parse a canonical pointer-ABI `Json` payload and return selected field contents.
fn parse_json_string(bytes: &[u8], keys: &[&str]) -> Result<String, VMError> {
    let value = parse_json_value(bytes)?;
    if let Some(s) = value.as_str() {
        return Ok(s.to_string());
    }
    for key in keys {
        if let Some(str_val) = value.get(*key).and_then(|v| v.as_str()) {
            return Ok(str_val.to_string());
        }
    }
    Err(VMError::NoritoInvalid)
}
/// Parse a canonical pointer-ABI `Json` payload and extract a string array.
fn parse_json_string_array(bytes: &[u8], keys: &[&str]) -> Result<Vec<String>, VMError> {
    let value = parse_json_value(bytes)?;
    let array = if let Some(arr) = value.as_array() {
        arr
    } else if let Some(map) = value.as_object() {
        keys.iter()
            .find_map(|key| map.get(*key))
            .and_then(njson::Value::as_array)
            .ok_or(VMError::NoritoInvalid)?
    } else {
        return Err(VMError::NoritoInvalid);
    };
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        let s = item.as_str().ok_or(VMError::NoritoInvalid)?;
        out.push(s.to_string());
    }
    Ok(out)
}
fn parse_account_subject_literal(raw: &str) -> Result<AccountId, VMError> {
    AccountId::parse_encoded(raw)
        .or_else(|_| {
            raw.parse::<iroha_data_model::smart_contract::ContractAddress>()
                .map(|address| address.subject_id())
        })
        .map_err(|_| VMError::NoritoInvalid)
}
/// Parse a peer identifier from a canonical `Json` payload.
fn parse_peer(bytes: &[u8]) -> Result<Peer, VMError> {
    let peer = parse_json_string(bytes, &["peer"])?;
    Peer::from_str(&peer).map_err(|_| VMError::NoritoInvalid)
}
fn parse_permission_name_payload(bytes: &[u8]) -> Result<PermissionToken, VMError> {
    let name: Name = decode_canonical_norito(bytes)?;
    parse_permission_name(name.as_ref())
}
// Keep tests at the end of the file to satisfy clippy::items_after_test_module
// without requiring an allow attribute.
/* tests moved to EOF */
impl IVMHost for WsvHost {
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
        if number == syscalls::SYSCALL_VRF_EPOCH_SEED {
            vm.ensure_public_register(10)?;
            return Ok(crate::vrf::epoch_seed_gas(
                self.wsv.vrf_epoch_seeds.contains_key(&vm.register(10)),
            ));
        }
        if number == syscalls::SYSCALL_CALL_CONTRACT {
            let bytes = Self::quote_contract_call(vm)?;
            return reserve_available_syscall_gas_at_least(
                vm,
                gas::syscall_byte_gas(gas::G_CALL_CONTRACT, bytes, 0),
            );
        }
        if number == syscalls::SYSCALL_EMIT_CONTRACT_EVENT {
            for register in 10..=12 {
                vm.ensure_public_register(register)?;
            }
            return reserve_available_syscall_gas_at_least(vm, 32);
        }

        let metering = require_host_syscall_metering_spec(vm.syscall_policy(), number)?;
        if metering.metering == crate::syscall_metering::SyscallMetering::Staged {
            return Ok(0);
        }
        if is_sm_syscall(number) && !self.sm_enabled {
            return Ok(0);
        }
        if let Some(quote) = common_syscall_gas_quote(number, vm)? {
            return Ok(quote);
        }
        if matches!(
            number,
            crate::syscalls::SYSCALL_BUILD_PATH_KEY_NORITO
                | crate::syscalls::SYSCALL_STATE_MAP_KEY_AT
                | crate::syscalls::SYSCALL_VALUE_ENCODE
                | crate::syscalls::SYSCALL_BLOB_CONCAT
                | crate::syscalls::SYSCALL_UTF8_VALIDATE
                | crate::syscalls::SYSCALL_VALUE_TO_STRING
                | crate::syscalls::SYSCALL_STATE_VALUE_ENCODE
                | crate::syscalls::SYSCALL_STATE_VALUE_DECODE
                | crate::syscalls::SYSCALL_STATE_PATH_FROM_NAME
                | crate::syscalls::SYSCALL_NORMALIZE_NORITO_BYTES
                | crate::syscalls::SYSCALL_JSON_BUILD
        ) {
            return crate::core_host::CoreHost::new().prepare_syscall(number, vm);
        }
        let state_quote = match number {
            crate::syscalls::SYSCALL_STATE_GET => {
                let path_len = crate::host::quote_state_path_payload_len_at(vm, vm.register(10))?;
                Some(reserve_available_syscall_gas_at_least(
                    vm,
                    crate::host::state_path_gas(path_len),
                )?)
            }
            crate::syscalls::SYSCALL_STATE_LEN => {
                let path_len = crate::host::quote_state_path_payload_len_at(vm, vm.register(10))?;
                Some(crate::host::state_path_gas(path_len))
            }
            crate::syscalls::SYSCALL_STATE_SCAN => Some(reserve_available_syscall_gas_at_least(
                vm,
                crate::state_scan::prepare_minimum(vm)?,
            )?),
            crate::syscalls::SYSCALL_STATE_COUNT => {
                let path_len = crate::host::quote_state_path_payload_len_at(vm, vm.register(10))?;
                Some(reserve_available_syscall_gas_at_least(
                    vm,
                    crate::host::state_path_gas(path_len),
                )?)
            }
            crate::syscalls::SYSCALL_STATE_SET => {
                let path_len = crate::host::quote_state_path_payload_len_at(vm, vm.register(10))?;
                let value_len =
                    quote_tlv_payload_len_at(vm, vm.register(11), PointerType::NoritoBytes)?;
                crate::host::validate_state_value_payload_len(value_len)?;
                Some(crate::host::state_value_gas(path_len, value_len))
            }
            crate::syscalls::SYSCALL_STATE_DEL | crate::syscalls::SYSCALL_STATE_HAS => {
                let path_len = crate::host::quote_state_path_payload_len_at(vm, vm.register(10))?;
                Some(crate::host::state_path_gas(path_len))
            }
            crate::syscalls::SYSCALL_CORE_QUERY_GET => Some(
                reserve_available_syscall_gas_at_least(vm, Self::state_query_gas(0))?,
            ),
            crate::syscalls::SYSCALL_CORE_QUERY_PAGE => Some(Self::state_query_gas(0)),
            _ => None,
        };
        if let Some(quote) = state_quote {
            return Ok(quote);
        }
        if number == crate::syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY {
            // The query response is gas-budgeted while it is produced. Avoid
            // executing a potentially large WSV query twice merely to quote it.
            return reserve_available_syscall_gas(vm);
        }
        if let Some(quote) = crate::core_host::CoreHost::codec_gas_quote(number, vm)? {
            return Ok(quote);
        }
        if let Some(quote) = self.bounded_response_gas_quote(number, vm)? {
            return Ok(quote);
        }
        // Mutating ledger calls and proof verification retain the generic
        // deterministic bound; unlike response-producing reads they have no
        // host-cardinality-dependent output to estimate.
        Ok(conservative_syscall_gas_quote(number, vm))
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        require_host_syscall_metering_spec(vm.syscall_policy(), number)?;
        if crate::syscalls::is_numeric_v1_syscall(number) {
            return crate::numeric_v1::execute(number, vm);
        }
        if crate::syscalls::is_json_getter_syscall(number) {
            let cost = crate::json::typed_getter(
                vm,
                number,
                crate::core_host::CoreHost::resolve_code_tlv_addr,
            )?;
            return Ok(Self::json_gas(cost.input_bytes, cost.output_bytes));
        }
        match number {
            syscalls::SYSCALL_VRF_EPOCH_SEED => {
                let epoch = vm.register(10);
                crate::vrf::publish_epoch_seed(vm, self.wsv.vrf_epoch_seeds.get(&epoch))
            }

            syscalls::SYSCALL_CALL_CONTRACT => self.call_contract(vm),
            syscalls::SYSCALL_EMIT_CONTRACT_EVENT => self.emit_contract_event(vm),

            crate::syscalls::SYSCALL_CORE_QUERY_GET => {
                let tag = ivm_abi::core_query::CoreQueryEntityTagV1::try_from(vm.register(10))
                    .map_err(|_| VMError::DecodeError)?;
                if tag == ivm_abi::core_query::CoreQueryEntityTagV1::AssetDefinition {
                    self.asset_definition_query(vm)
                } else {
                    Err(VMError::metered_not_implemented(
                        Self::state_query_gas(0),
                        number,
                    ))
                }
            }
            crate::syscalls::SYSCALL_CORE_QUERY_PAGE => Err(VMError::metered_not_implemented(
                Self::state_query_gas(0),
                number,
            )),
            // Durable smart-contract state syscalls
            crate::syscalls::SYSCALL_STATE_GET => {
                // r10 = &NoritoBytes(StatePath) -> return a host-owned
                // &NoritoBytes value (or 0 if none).
                let (path, path_len) = self.decode_state_path_reg(vm, 10)?;
                crate::host::validate_declared_state_path(vm, &path)?;
                let logical_path = path;
                let path = self.scoped_state_path(&logical_path)?;
                if self.tx_active
                    && let Some(entry) = self.state_overlay.get(&path)
                {
                    if crate::dev_env::decode_trace_enabled() {
                        eprintln!(
                            "[WsvHost] overlay STATE_GET path='{path}' staged={}",
                            entry.is_some()
                        );
                    }
                    match entry {
                        Some(val) => {
                            let len = Self::state_value_payload_len(val)?;
                            let gas = crate::host::state_value_gas(path_len, len);
                            preflight_reserved_syscall_gas(vm, gas)?;
                            crate::host::validate_declared_state_value_payload(
                                vm,
                                &logical_path,
                                val,
                            )?;
                            let val = val.clone();
                            self.log_read_key(path.as_ref());
                            Self::load_state_value(vm, &val)?;
                            return Ok(gas);
                        }
                        None => {
                            let gas = crate::host::state_path_gas(path_len);
                            preflight_reserved_syscall_gas(vm, gas)?;
                            self.log_read_key(path.as_ref());
                            vm.set_register(10, 0);
                            return Ok(gas);
                        }
                    }
                }
                if let Some(env) = self.wsv.state_overlay.value_payload_ref(&path)? {
                    let len = Self::state_value_payload_len(env)?;
                    let gas = crate::host::state_value_gas(path_len, len);
                    preflight_reserved_syscall_gas(vm, gas)?;
                    crate::host::validate_declared_state_value_payload(vm, &logical_path, env)?;
                    let env = env.to_vec();
                    self.log_read_key(path.as_ref());
                    Self::load_state_value(vm, &env)?;
                    Ok(gas)
                } else {
                    let gas = crate::host::state_path_gas(path_len);
                    preflight_reserved_syscall_gas(vm, gas)?;
                    self.log_read_key(path.as_ref());
                    vm.set_register(10, 0);
                    Ok(gas)
                }
            }
            crate::syscalls::SYSCALL_STATE_SET => {
                // r10 = &NoritoBytes(StatePath); r11 = &NoritoBytes value
                if crate::dev_env::decode_trace_enabled() {
                    eprintln!(
                        "[WsvHost] STATE_SET regs r10=0x{path:08x} r11=0x{val:08x}",
                        path = vm.register(10),
                        val = vm.register(11)
                    );
                }
                let p_val = vm.validate_tlv(vm.register(11))?;
                if p_val.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                // Enforce pointer-ABI policy for the value type
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, p_val.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: p_val.type_id as u16,
                    });
                }
                let (path, path_len) = self.decode_state_path_reg(vm, 10)?;
                crate::host::validate_declared_state_path(vm, &path)?;
                crate::host::validate_state_value_payload_len(p_val.payload.len())?;
                crate::host::validate_declared_state_value_payload(vm, &path, p_val.payload)?;
                let path = self.scoped_state_path(&path)?;
                self.log_write_key(path.as_ref());
                let stored = p_val.payload.to_vec();
                if self.tx_active {
                    if crate::dev_env::decode_trace_enabled() {
                        eprintln!(
                            "[WsvHost] overlay STATE_SET path='{path}' bytes={}",
                            stored.len()
                        );
                    }
                    self.state_overlay.insert(path, Some(stored));
                } else {
                    self.wsv.sc_set(&path, stored)?;
                }
                Ok(crate::host::state_value_gas(path_len, p_val.payload.len()))
            }
            crate::syscalls::SYSCALL_STATE_DEL => {
                // r10 = &NoritoBytes(StatePath)
                let (path, path_len) = self.decode_state_path_reg(vm, 10)?;
                crate::host::validate_declared_state_path(vm, &path)?;
                let path = self.scoped_state_path(&path)?;
                self.log_write_key(path.as_ref());
                if self.tx_active {
                    if crate::dev_env::decode_trace_enabled() {
                        eprintln!("[WsvHost] overlay STATE_DEL path='{}'", path.as_ref());
                    }
                    self.state_overlay.insert(path, None);
                } else {
                    self.wsv.sc_del(&path)?;
                }
                Ok(crate::host::state_path_gas(path_len))
            }
            crate::syscalls::SYSCALL_STATE_SCAN => {
                let instance = self
                    .contract_runtime_address
                    .as_ref()
                    .or(self.contract_fixture_state_scope.as_ref())
                    .map_or_else(|| "local".to_owned(), ToString::to_string);
                let request = crate::state_scan::StateScanRequest::decode(vm, &instance)?;
                let map = request.map().clone();
                let namespace = self.state_namespace();
                let prefix = format!("{}{}/", namespace, map.as_ref());
                let after = request
                    .after()
                    .map(|path| self.scoped_state_path(path))
                    .transpose()?;
                let lower = after
                    .as_ref()
                    .map_or(std::ops::Bound::Included(prefix.as_str()), |key| {
                        std::ops::Bound::Excluded(key.as_ref())
                    });
                let backing = self
                    .wsv
                    .state_overlay
                    .keys_after_with_text_prefix(&prefix, after.as_ref().map(|path| path.as_ref()));
                let overlay = self
                    .state_overlay
                    .range::<str, _>((lower, std::ops::Bound::Unbounded))
                    .take_while(|(key, _)| key.as_ref().starts_with(&prefix))
                    .take(if self.tx_active { usize::MAX } else { 0 })
                    .map(|(key, value)| (key, value.is_some()));
                let mut page = crate::state_scan::StateScanPage::new(request);
                for (key, present) in crate::state_scan::merge_candidates(backing, overlay) {
                    if page
                        .examine(
                            vm,
                            key.as_ref()
                                .strip_prefix(&namespace)
                                .ok_or(VMError::DecodeError)?,
                            key.as_ref().len(),
                            present,
                        )?
                        .is_break()
                    {
                        break;
                    }
                }
                let gas = page.publish(vm)?;
                self.log_read_key(self.scoped_state_path(&map)?.as_ref());
                Ok(gas)
            }
            crate::syscalls::SYSCALL_STATE_HAS => {
                let (path, path_len) = self.decode_state_path_reg(vm, 10)?;
                crate::host::validate_declared_state_path(vm, &path)?;
                let path = self.scoped_state_path(&path)?;
                self.log_read_key(path.as_ref());
                vm.set_register(10, u64::from(self.state_key_present(&path)));
                Ok(crate::host::state_path_gas(path_len))
            }
            crate::syscalls::SYSCALL_STATE_LEN => {
                let (path, path_len) = self.decode_state_path_reg(vm, 10)?;
                crate::host::validate_declared_state_path(vm, &path)?;
                let path = self.scoped_state_path(&path)?;
                self.log_read_key(path.as_ref());
                if let Some(len) = self.state_value_len(&path)? {
                    let gas = crate::host::state_path_gas(path_len);
                    preflight_reserved_syscall_gas(vm, gas)?;
                    vm.set_register(10, u64::try_from(len).unwrap_or(u64::MAX));
                    vm.set_register(11, 1);
                    Ok(gas)
                } else {
                    let gas = crate::host::state_path_gas(path_len);
                    preflight_reserved_syscall_gas(vm, gas)?;
                    vm.set_register(10, 0);
                    vm.set_register(11, 0);
                    Ok(gas)
                }
            }
            crate::syscalls::SYSCALL_STATE_COUNT => {
                let (prefix, path_len) = self.decode_state_path_reg(vm, 10)?;
                crate::host::validate_declared_state_scan_path(vm, &prefix)?;
                let prefix = self.scoped_state_path(&prefix)?;
                let (total, scan_work_gas) = self.state_count_with_prefix(vm, &prefix, path_len)?;
                let gas = crate::host::STATE_QUERY_GAS_BASE.saturating_add(scan_work_gas);
                preflight_reserved_syscall_gas(vm, gas)?;
                self.log_read_key(prefix.as_ref());
                vm.set_register(10, total);
                Ok(gas)
            }
            crate::syscalls::SYSCALL_GET_PUBLIC_INPUT => {
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
            crate::syscalls::SYSCALL_ALLOC => {
                let size = vm.register(10);
                let addr = vm.alloc_heap(size)?;
                vm.set_register(10, addr);
                Ok(crate::host::allocation_gas(size))
            }
            crate::syscalls::SYSCALL_JSON_ENCODE => {
                let tlv = vm.validate_tlv(vm.register(10))?;
                if tlv.type_id != PointerType::Json {
                    return Err(VMError::NoritoInvalid);
                }
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: tlv.type_id as u16,
                    });
                }
                let input_len = tlv.payload.len();
                let json: iroha_primitives::json::Json =
                    decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
                let body = encode_canonical_norito(&json)?;
                let mut out = Vec::with_capacity(7 + body.len() + 32);
                out.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
                out.push(1);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                let h: [u8; 32] = iroha_crypto::Hash::new(&body).into();
                out.extend_from_slice(&h);
                let p = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, p);
                Ok(Self::json_gas(input_len, body.len()))
            }
            crate::syscalls::SYSCALL_JSON_DECODE => {
                let addr = vm.register(10);
                if addr == 0 {
                    vm.set_register(10, 0);
                    return Ok(Self::json_gas(0, 0));
                }
                let tlv = vm.validate_tlv(addr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let input_len = tlv.payload.len();
                let json: iroha_primitives::json::Json =
                    decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
                let body = encode_canonical_norito(&json)?;
                let mut out = Vec::with_capacity(7 + body.len() + 32);
                out.extend_from_slice(&(PointerType::Json as u16).to_be_bytes());
                out.push(1);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                let h: [u8; 32] = iroha_crypto::Hash::new(&body).into();
                out.extend_from_slice(&h);
                let p = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, p);
                Ok(Self::json_gas(input_len, body.len()))
            }
            crate::syscalls::SYSCALL_JSON_OBJECT => {
                let out_json = Json::from(njson::Value::Object(njson::Map::new()));
                let body = encode_canonical_norito(&out_json)?;
                let mut out = Vec::with_capacity(7 + body.len() + 32);
                out.extend_from_slice(&(PointerType::Json as u16).to_be_bytes());
                out.push(1);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                let h: [u8; 32] = CryptoHash::new(&body).into();
                out.extend_from_slice(&h);
                let p = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, p);
                Ok(Self::json_gas(0, body.len()))
            }
            crate::syscalls::SYSCALL_JSON_SET_I64
            | crate::syscalls::SYSCALL_JSON_SET_ACCOUNT_ID => {
                let json_addr =
                    crate::core_host::CoreHost::resolve_code_tlv_addr(vm, vm.register(10));
                let key_addr =
                    crate::core_host::CoreHost::resolve_code_tlv_addr(vm, vm.register(11));
                let json_tlv = vm.validate_tlv(json_addr)?;
                let key_tlv = vm.validate_tlv(key_addr)?;
                if json_tlv.type_id != PointerType::Json || key_tlv.type_id != PointerType::Name {
                    return Err(VMError::NoritoInvalid);
                }
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, json_tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: json_tlv.type_id as u16,
                    });
                }
                if !pointer_abi::is_type_allowed_for_policy(policy, key_tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: key_tlv.type_id as u16,
                    });
                }
                let json: Json =
                    decode_canonical_norito(json_tlv.payload).map_err(|_| VMError::DecodeError)?;
                let mut input_len = json_tlv.payload.len().saturating_add(key_tlv.payload.len());
                let value: njson::Value = json
                    .try_into_any_norito()
                    .map_err(|_| VMError::DecodeError)?;
                let mut obj = match value {
                    njson::Value::Object(map) => map,
                    _ => return Err(VMError::DecodeError),
                };
                let key_name: Name =
                    decode_canonical_norito(key_tlv.payload).map_err(|_| VMError::DecodeError)?;
                let field = match number {
                    crate::syscalls::SYSCALL_JSON_SET_I64 => {
                        input_len = input_len.saturating_add(core::mem::size_of::<i64>());
                        njson::Value::from(vm.register(12) as i64)
                    }
                    crate::syscalls::SYSCALL_JSON_SET_ACCOUNT_ID => {
                        let value_addr =
                            crate::core_host::CoreHost::resolve_code_tlv_addr(vm, vm.register(12));
                        let value_tlv = vm.validate_tlv(value_addr)?;
                        if value_tlv.type_id != PointerType::AccountId {
                            return Err(VMError::NoritoInvalid);
                        }
                        if !pointer_abi::is_type_allowed_for_policy(policy, value_tlv.type_id) {
                            return Err(VMError::AbiTypeNotAllowed {
                                abi: vm.abi_version(),
                                type_id: value_tlv.type_id as u16,
                            });
                        }
                        input_len = input_len.saturating_add(value_tlv.payload.len());
                        let account: AccountId = decode_canonical_norito(value_tlv.payload)
                            .map_err(|_| VMError::DecodeError)?;
                        njson::Value::from(account.to_string())
                    }
                    _ => return Err(VMError::UnknownSyscall(number)),
                };
                obj.insert(key_name.to_string(), field);
                let out_json = Json::from(njson::Value::Object(obj));
                let body = encode_canonical_norito(&out_json)?;
                let mut out = Vec::with_capacity(7 + body.len() + 32);
                out.extend_from_slice(&(PointerType::Json as u16).to_be_bytes());
                out.push(1);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                let h: [u8; 32] = CryptoHash::new(&body).into();
                out.extend_from_slice(&h);
                let p = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, p);
                Ok(Self::json_gas(input_len, body.len()))
            }
            crate::syscalls::SYSCALL_TLV_LEN => {
                let addr = vm.register(10);
                if addr == 0 {
                    vm.set_register(10, 0);
                    return Ok(Self::tlv_len_gas(0));
                }
                let tlv = vm.validate_tlv(addr)?;
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: tlv.type_id as u16,
                    });
                }
                let payload_len = tlv.payload.len();
                vm.set_register(10, payload_len as u64);
                Ok(Self::tlv_len_gas(payload_len))
            }
            crate::syscalls::SYSCALL_DECODE_ARGUMENT_RECORD => {
                crate::argument_record::decode_argument_record(vm)
            }
            crate::syscalls::SYSCALL_NAME_DECODE => {
                // r10 = &NoritoBytes(canonical Name) -> r10 = &Name
                let addr = vm.register(10);
                if addr == 0 {
                    vm.set_register(10, 0);
                    return Ok(Self::name_decode_gas(0, 0));
                }
                let tlv = vm.validate_tlv(addr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: tlv.type_id as u16,
                    });
                }
                let input_len = tlv.payload.len();
                let nm: iroha_model_base::name::Name =
                    decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
                let body = encode_canonical_norito(&nm)?;
                let mut out = Vec::with_capacity(7 + body.len() + 32);
                out.extend_from_slice(&(PointerType::Name as u16).to_be_bytes());
                out.push(1);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                let h: [u8; 32] = iroha_crypto::Hash::new(&body).into();
                out.extend_from_slice(&h);
                let p = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, p);
                Ok(Self::name_decode_gas(input_len, body.len()))
            }
            crate::syscalls::SYSCALL_POINTER_TO_NORITO => {
                let ptr = vm.register(10);
                if ptr == 0 {
                    return Err(VMError::NoritoInvalid);
                }
                let tlv = vm.validate_tlv(ptr)?;
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: tlv.type_id as u16,
                    });
                }
                crate::numeric_tlv::validate_numeric_frame_if_needed(tlv.type_id, tlv.payload)?;
                let mut body = Vec::with_capacity(2 + 1 + 4 + tlv.payload.len() + 32);
                body.extend_from_slice(&(tlv.type_id_raw().to_be_bytes()));
                body.push(tlv.version);
                body.extend_from_slice(&(tlv.payload.len() as u32).to_be_bytes());
                body.extend_from_slice(tlv.payload);
                let inner_hash: [u8; 32] = iroha_crypto::Hash::new(tlv.payload).into();
                body.extend_from_slice(&inner_hash);
                let mut out = Vec::with_capacity(7 + body.len() + 32);
                out.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
                out.push(1);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                let outer_hash: [u8; 32] = iroha_crypto::Hash::new(&body).into();
                out.extend_from_slice(&outer_hash);
                let p = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, p);
                Ok(Self::pointer_gas(body.len()))
            }
            crate::syscalls::SYSCALL_POINTER_FROM_NORITO => {
                let addr = vm.register(10);
                if addr == 0 {
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
                let tlv = vm.validate_tlv(addr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let encoded_len = tlv.payload.len();
                let policy = vm.syscall_policy();
                let expected =
                    u16::try_from(vm.register(11)).map_err(|_| VMError::NoritoInvalid)?;
                let inner = pointer_abi::validate_tlv_bytes(tlv.payload)
                    .map_err(|_| VMError::NoritoInvalid)?;
                if expected != 0 && expected != inner.type_id as u16 {
                    return Err(VMError::NoritoInvalid);
                }
                if !pointer_abi::is_type_allowed_for_policy(policy, inner.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: inner.type_id as u16,
                    });
                }
                crate::numeric_tlv::validate_numeric_frame_if_needed(inner.type_id, inner.payload)?;
                let mut out = Vec::with_capacity(7 + inner.payload.len() + 32);
                out.extend_from_slice(&(inner.type_id as u16).to_be_bytes());
                out.push(inner.version);
                out.extend_from_slice(&(inner.payload.len() as u32).to_be_bytes());
                out.extend_from_slice(inner.payload);
                let h: [u8; 32] = iroha_crypto::Hash::new(inner.payload).into();
                out.extend_from_slice(&h);
                let p = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, p);
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
                // Check headers and payload
                let eq = tlv1.type_id == tlv2.type_id
                    && tlv1.version == tlv2.version
                    && tlv1.payload == tlv2.payload;
                vm.set_register(10, if eq { 1 } else { 0 });
                Ok(Self::tlv_eq_gas(left_len, right_len))
            }
            crate::syscalls::SYSCALL_SCHEMA_ENCODE
            | crate::syscalls::SYSCALL_SCHEMA_DECODE
            | crate::syscalls::SYSCALL_SCHEMA_INFO => {
                crate::core_host::CoreHost::new_with_registry(Box::new(Arc::clone(&self.schema)))
                    .syscall(number, vm)
            }
            crate::syscalls::SYSCALL_BUILD_PATH_KEY_NORITO
            | crate::syscalls::SYSCALL_STATE_MAP_KEY_AT
            | crate::syscalls::SYSCALL_VALUE_ENCODE
            | crate::syscalls::SYSCALL_BLOB_CONCAT
            | crate::syscalls::SYSCALL_UTF8_VALIDATE
            | crate::syscalls::SYSCALL_VALUE_TO_STRING
            | crate::syscalls::SYSCALL_STATE_VALUE_ENCODE
            | crate::syscalls::SYSCALL_STATE_VALUE_DECODE
            | crate::syscalls::SYSCALL_STATE_PATH_FROM_NAME
            | crate::syscalls::SYSCALL_NORMALIZE_NORITO_BYTES
            | crate::syscalls::SYSCALL_JSON_BUILD => {
                crate::core_host::CoreHost::new().syscall(number, vm)
            }
            crate::syscalls::SYSCALL_SHA256_HASH
            | crate::syscalls::SYSCALL_SHA3_HASH
            | crate::syscalls::SYSCALL_BLAKE2B256_HASH
            | crate::syscalls::SYSCALL_KECCAK256_HASH
            | crate::syscalls::SYSCALL_IROHA_HASH => {
                let mut default = crate::host::DefaultHost::new();
                default.syscall(number, vm)
            }
            crate::syscalls::SYSCALL_SM3_HASH
            | crate::syscalls::SYSCALL_SM2_VERIFY
            | crate::syscalls::SYSCALL_SM4_GCM_SEAL
            | crate::syscalls::SYSCALL_SM4_GCM_OPEN
            | crate::syscalls::SYSCALL_SM4_CCM_SEAL
            | crate::syscalls::SYSCALL_SM4_CCM_OPEN => {
                if !self.sm_enabled {
                    return Err(VMError::PermissionDenied);
                }
                let mut default = crate::host::DefaultHost::new().with_sm_enabled(true);
                default.syscall(number, vm)
            }
            // Developer helper used by Kotodama-compiled programs to validate a
            // public host-owned TLV. Heap-spilled host results remain in place;
            // immutable literals are materialized into the host arena.
            crate::syscalls::SYSCALL_INPUT_PUBLISH_TLV => {
                let src = vm.register(10);
                if crate::dev_env::debug_wsv_enabled() {
                    eprintln!("[wsv] INPUT_PUBLISH_TLV src=0x{src:x}");
                }
                if src == 0 {
                    vm.set_register(10, 0);
                    return Ok(Self::input_publish_gas(0));
                }
                if src >= crate::memory::Memory::HEAP_START {
                    let tlv = vm.validate_tlv(src)?;
                    let envelope_len = 7usize.saturating_add(tlv.payload.len()).saturating_add(32);
                    if envelope_len > self.zk_cfg.max_envelope_bytes {
                        return Err(VMError::PermissionDenied);
                    }
                    return Ok(Self::input_publish_gas(envelope_len));
                }
                let resolved = crate::core_host::CoreHost::resolve_code_tlv_addr(vm, src);
                let bytes_vec = vm.clone_tlv(resolved)?;
                let total = bytes_vec.len();
                if total > self.zk_cfg.max_envelope_bytes {
                    return Err(VMError::PermissionDenied);
                }
                let dst = vm.alloc_host_tlv(&bytes_vec)?;
                vm.set_register(10, dst);
                Ok(Self::input_publish_gas(total))
            }
            // WsvHost has no query-state executor, but it enforces the canonical V1
            // request boundary before reporting that limitation.
            crate::syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let _: QueryRequest = decode_canonical_norito(tlv.payload)?;
                Err(VMError::NotImplemented { syscall: number })
            }
            // Decode bounded proof envelopes; standalone hosts cannot authorize proofs.
            syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT | syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY => {
                // Expect NoritoBytes TLV in r10 for a `iroha_data_model::zk::OpenVerifyEnvelope`.
                //
                // Note: `WsvHost` is a development/mock host. It does not perform full
                // cryptographic proof verification. The production node host (CoreHost)
                // verifies the proof end-to-end.
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let gas = Self::verify_gas(tlv.payload.len());
                if tlv.payload.len() > self.zk_cfg.max_envelope_bytes {
                    vm.set_register(10, 0);
                    vm.set_register(11, crate::host::ERR_ENVELOPE_SIZE);
                    return Ok(gas);
                }
                let env: iroha_data_model::zk::OpenVerifyEnvelope =
                    match decode_canonical_norito(tlv.payload) {
                        Ok(env) => env,
                        Err(_) => {
                            vm.set_register(10, 0);
                            vm.set_register(11, crate::host::ERR_DECODE);
                            return Ok(gas);
                        }
                    };
                if env.proof_bytes.len() > self.zk_cfg.max_proof_bytes {
                    vm.set_register(10, 0);
                    vm.set_register(11, crate::host::ERR_PROOF_LEN);
                    return Ok(gas);
                }
                // This standalone mock has no authenticated verifier registry.
                // Structural parsing must never grant ballot or tally authority.
                vm.set_register(10, 0);
                vm.set_register(11, crate::host::ERR_BACKEND);
                Ok(gas)
            }
            syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION => {
                // r10 = &NoritoBytes(canonical data-model InstructionBox), r11 = operation tag.
                let p = vm.register(10);
                let tlv = vm.validate_tlv(p)?;
                let instruction_gas = Self::mutation_gas(tlv.payload.len());
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let ib: DMInstructionBox = decode_canonical_norito(tlv.payload)?;
                let any = (&*ib) as &dyn iroha_data_model::isi::Instruction;
                let any_ref = any.as_any();
                match vm.register(11) {
                    syscalls::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT => {
                        let Some(instr) = any_ref.downcast_ref::<DMZk::SubmitBallot>() else {
                            return Err(VMError::PermissionDenied);
                        };
                        self.handle_submit_ballot(instr)?;
                        Ok(instruction_gas)
                    }
                    // Contracts record no SCCP messages (specs/sccp.md §4.4): the retired
                    // operation tag 2 fails like every other unknown tag.
                    _ => Err(VMError::PermissionDenied),
                }
            }
            // ZK read-only syscalls for shielded ledger/elections
            syscalls::SYSCALL_ZK_ROOTS_GET => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let input_len = tlv.payload.len();
                let req: crate::zk_verify::RootsGetRequest = decode_canonical_norito(tlv.payload)?;
                let asset: AssetDefinitionId =
                    req.asset_id.parse().map_err(|_| VMError::NoritoInvalid)?;
                let (latest, roots, height) = self.wsv.get_roots(&asset, req.max as usize);
                let resp = crate::zk_verify::RootsGetResponse {
                    latest,
                    roots,
                    height,
                };
                let body = encode_canonical_norito(&resp)?;
                let gas = Self::state_query_gas(input_len.saturating_add(body.len()));
                preflight_reserved_syscall_gas(vm, gas)?;
                let mut out = Vec::with_capacity(7 + body.len() + 32);
                out.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
                out.push(1);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                let h: [u8; 32] = iroha_crypto::Hash::new(&body).into();
                out.extend_from_slice(&h);
                let p = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, p);
                Ok(gas)
            }
            syscalls::SYSCALL_ZK_VOTE_GET_TALLY => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let input_len = tlv.payload.len();
                let req: crate::zk_verify::VoteGetTallyRequest =
                    decode_canonical_norito(tlv.payload)?;
                if !req.is_valid_v1() {
                    return Err(VMError::NoritoInvalid);
                }
                let (finalized, tally) = if let Some(e) = self.wsv.elections.get(&req.election_id) {
                    DMZk::validate_election_tally_v1(e.options, e.tally.len())
                        .map_err(|_| VMError::NoritoInvalid)?;
                    e.tally
                        .iter()
                        .try_fold(0_u128, |total, weight| total.checked_add(*weight))
                        .ok_or(VMError::NoritoInvalid)?;
                    (e.finalized, e.tally.clone())
                } else {
                    (false, Vec::new())
                };
                let resp = crate::zk_verify::VoteGetTallyResponse { finalized, tally };
                let body = encode_canonical_norito(&resp)?;
                let gas = Self::state_query_gas(input_len.saturating_add(body.len()));
                preflight_reserved_syscall_gas(vm, gas)?;
                let mut out = Vec::with_capacity(7 + body.len() + 32);
                out.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
                out.push(1);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(&body);
                let h: [u8; 32] = iroha_crypto::Hash::new(&body).into();
                out.extend_from_slice(&h);
                let p = vm.alloc_host_tlv(&out)?;
                vm.set_register(10, p);
                Ok(gas)
            }
            syscalls::SYSCALL_REGISTER_PEER => {
                // r10 = &Json peer info
                let v = vm.register(10);
                let tlv = vm.validate_tlv(v)?;
                if tlv.type_id != PointerType::Json {
                    return Err(VMError::NoritoInvalid);
                }
                let peer = parse_peer(tlv.payload)?;
                self.wsv.peers.insert(peer);
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_UNREGISTER_PEER => {
                // r10 = &Json peer info
                let v = vm.register(10);
                let tlv = vm.validate_tlv(v)?;
                if tlv.type_id != PointerType::Json {
                    return Err(VMError::NoritoInvalid);
                }
                let peer = parse_peer(tlv.payload)?;
                if self.wsv.peers.remove(&peer) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_CREATE_TRIGGER => {
                // r10 = &Json trigger spec; expect a "name" field
                let v = vm.register(10);
                let tlv = vm.validate_tlv(v)?;
                if tlv.type_id != PointerType::Json {
                    return Err(VMError::NoritoInvalid);
                }
                let name = parse_json_string(tlv.payload, &["name"])?;
                self.wsv.triggers.insert(name, true);
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_REMOVE_TRIGGER => {
                // r10 = &Name
                let v = vm.register(10);
                let tlv = vm.validate_tlv(v)?;
                if tlv.type_id != PointerType::Name {
                    return Err(VMError::NoritoInvalid);
                }
                let name = self.decode_name_payload(tlv.payload)?;
                if self.wsv.triggers.remove(name.as_ref()).is_some() {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_SET_TRIGGER_ENABLED => {
                // r10 = &Name; r11 = enabled:u64
                let v = vm.register(10);
                let tlv = vm.validate_tlv(v)?;
                if tlv.type_id != PointerType::Name {
                    return Err(VMError::NoritoInvalid);
                }
                let name = self.decode_name_payload(tlv.payload)?;
                let enable = vm.register(11) != 0;
                if let Some(e) = self.wsv.triggers.get_mut(name.as_ref()) {
                    *e = enable;
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_DEACTIVATE_CONTRACT_INSTANCE => {
                let ptr = vm.register(10);
                let tlv = vm.validate_tlv(ptr)?;
                if tlv.type_id != PointerType::NoritoBytes {
                    return Err(VMError::NoritoInvalid);
                }
                let req: scode::DeactivateContractInstance = decode_canonical_norito(tlv.payload)?;
                let instance = self
                    .wsv
                    .contract_instances
                    .get_mut(req.contract_address())
                    .ok_or(VMError::PermissionDenied)?;
                if instance.lifecycle.owner
                    != iroha_data_model::smart_contract::ContractLifecycleOwnerV1::Account(
                        self.caller.clone(),
                    )
                    || instance.lifecycle.revision != *req.expected_revision()
                    || instance.lifecycle.active_code_hash.is_none()
                {
                    return Err(VMError::PermissionDenied);
                }
                instance.lifecycle.revision = instance
                    .lifecycle
                    .revision
                    .checked_add(1)
                    .ok_or(VMError::PermissionDenied)?;
                instance.lifecycle.active_code_hash = None;
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_REMOVE_SMART_CONTRACT_BYTES => {
                // Installed mock artifacts always include the authenticated declaration table;
                // deleting code independently of that retained fixture would create invalid state.
                Err(VMError::PermissionDenied)
            }
            syscalls::SYSCALL_REGISTER_DOMAIN => {
                // r10=&DomainId TLV; caller must have RegisterDomain
                let id = self.decode_domain_reg(vm, 10)?;
                if self.wsv.register_domain(&self.caller, id) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_REGISTER_ACCOUNT => {
                // r10=&AccountId TLV; domain must exist and caller must have RegisterAccount
                let id = self.decode_account_reg(vm, 10)?;
                if self.wsv.register_account(&self.caller, id) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_ADD_SIGNATORY => {
                // r10 = &AccountId; r11 = &Json PublicKey
                let account = self.decode_canonical_account_reg(vm, 10)?;
                let tlv = vm.validate_tlv(vm.register(11))?;
                if tlv.type_id != PointerType::Json {
                    return Err(VMError::NoritoInvalid);
                }
                let json: Json =
                    decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
                let signatory: PublicKey =
                    njson::from_str(json.get()).map_err(|_| VMError::NoritoInvalid)?;
                if self
                    .wsv
                    .add_signatory(&self.caller, &account, signatory.to_string())
                {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_REMOVE_SIGNATORY => {
                // r10 = &AccountId; r11 = &Json PublicKey
                let account = self.decode_canonical_account_reg(vm, 10)?;
                let tlv = vm.validate_tlv(vm.register(11))?;
                if tlv.type_id != PointerType::Json {
                    return Err(VMError::NoritoInvalid);
                }
                let json: Json =
                    decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
                let signatory: PublicKey =
                    njson::from_str(json.get()).map_err(|_| VMError::NoritoInvalid)?;
                let key = signatory.to_string();
                if self.wsv.remove_signatory(&self.caller, &account, &key) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_SET_ACCOUNT_QUORUM => {
                // r10 = &AccountId; r11 = quorum
                let account = self.decode_canonical_account_reg(vm, 10)?;
                let quorum_raw = vm.register(11);
                let quorum_u16 = u16::try_from(quorum_raw).map_err(|_| VMError::DecodeError)?;
                let quorum = NonZeroU16::new(quorum_u16).ok_or(VMError::DecodeError)?;
                if self
                    .wsv
                    .set_account_quorum(&self.caller, &account, u32::from(quorum.get()))
                {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_SET_ACCOUNT_DETAIL => {
                let account = self.decode_canonical_account_reg(vm, 10)?;
                let key_tlv = vm.validate_tlv(vm.register(11))?;
                if key_tlv.type_id != PointerType::Name {
                    return Err(VMError::NoritoInvalid);
                }
                let key = self.decode_name_payload(key_tlv.payload)?;
                let val_tlv = vm.validate_tlv(vm.register(12))?;
                if val_tlv.type_id != PointerType::Json {
                    return Err(VMError::NoritoInvalid);
                }
                let json: Json =
                    decode_canonical_norito(val_tlv.payload).map_err(|_| VMError::DecodeError)?;
                let value: njson::Value =
                    njson::from_str(json.get()).map_err(|_| VMError::NoritoInvalid)?;
                let minified = njson::to_vec(&value).map_err(|_| VMError::NoritoInvalid)?;
                if self
                    .wsv
                    .set_account_detail(&self.caller, &account, key.as_ref(), minified)
                {
                    Ok(Self::mutation_gas(val_tlv.payload.len()))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_REGISTER_ASSET => {
                // r10 = &AssetDefinitionId, r11 = &Blob UTF-8 display name,
                // r12 = numeric-spec word, r13 = mintability word, decoded by the
                // data-model `ivm_registration` decoder shared with CoreHost.
                let id = match vm.validate_tlv(vm.register(10)) {
                    Ok(tlv) => match tlv.type_id {
                        PointerType::AssetDefinitionId => self.decode_asset_payload(tlv.payload)?,
                        PointerType::Name | PointerType::Blob => {
                            return Err(VMError::DecodeError);
                        }
                        _ => return Err(VMError::NoritoInvalid),
                    },
                    Err(error) => return Err(error),
                };
                let name_tlv = vm.validate_tlv(vm.register(11))?;
                if name_tlv.type_id != PointerType::Blob {
                    return Err(VMError::NoritoInvalid);
                }
                let registration =
                    decode_asset_registration(name_tlv.payload, vm.register(12), vm.register(13))?;
                if self.wsv.register_asset_definition_with_spec(
                    &self.caller,
                    id,
                    registration.name,
                    registration.spec,
                    registration.mintable,
                ) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY => {
                let account = self.decode_canonical_account_reg(vm, 10)?;
                let asset_definition = self.decode_asset_reg(vm, 11)?;
                let expected_revision = vm.register(12);
                let availability_flags = vm.register(13);
                if availability_flags & !0b11 != 0 {
                    return Err(VMError::DecodeError);
                }
                let incoming = availability_flags & 0b01 != 0;
                let outgoing = availability_flags & 0b10 != 0;
                let option_layout =
                    crate::sum::SumLayoutV1::option(1).map_err(|_| VMError::DecodeError)?;
                let (has_reason, reason_words) =
                    crate::sum::read_words(vm, vm.register(14), option_layout)?;
                if has_reason {
                    let reason_ptr = reason_words.first().copied().ok_or(VMError::DecodeError)?;
                    let reason = vm.validate_tlv(reason_ptr)?;
                    if reason.type_id != PointerType::Blob
                        || core::str::from_utf8(reason.payload).is_err()
                    {
                        return Err(VMError::DecodeError);
                    }
                }
                let permission = PermissionToken::SetAssetTransferAvailability {
                    account: account.clone(),
                    asset_definition: asset_definition.clone(),
                };
                if !self.wsv.has_permission(&self.caller, &permission)
                    || !self.wsv.account_is_linked(&account)
                    || !self.wsv.asset_definitions.contains_key(&asset_definition)
                {
                    return Err(VMError::PermissionDenied);
                }
                let key = (
                    MockWorldStateView::account_subject(&account),
                    asset_definition,
                );
                let (current_revision, current_incoming, current_outgoing) = self
                    .wsv
                    .asset_transfer_availability
                    .get(&key)
                    .copied()
                    .unwrap_or((0, true, true));
                if current_revision != expected_revision
                    || (current_incoming == incoming && current_outgoing == outgoing)
                {
                    return Err(VMError::PermissionDenied);
                }
                let next_revision = current_revision
                    .checked_add(1)
                    .ok_or(VMError::PermissionDenied)?;
                self.wsv
                    .asset_transfer_availability
                    .insert(key, (next_revision, incoming, outgoing));
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_SET_ASSET_HOLDING_LIMIT => {
                let account = self.decode_canonical_account_reg(vm, 10)?;
                let asset_definition = self.decode_asset_reg(vm, 11)?;
                let layout =
                    crate::sum::SumLayoutV1::option(1).map_err(|_| VMError::DecodeError)?;
                let (is_some, words) = crate::sum::read_words(vm, vm.register(12), layout)?;
                let limit = if is_some {
                    let pointer = words.first().copied().ok_or(VMError::DecodeError)?;
                    let tlv = vm.validate_tlv(pointer)?;
                    if tlv.type_id != PointerType::Quantity {
                        return Err(VMError::NoritoInvalid);
                    }
                    Some(
                        QuantityValueV1::decode_frame(tlv.payload)
                            .map(QuantityValueV1::into_quantity)
                            .map_err(|_| VMError::DecodeError)?,
                    )
                } else {
                    None
                };
                let permission = PermissionToken::SetAssetHoldingLimit {
                    account: account.clone(),
                    asset_definition: asset_definition.clone(),
                };
                if !self.wsv.has_permission(&self.caller, &permission)
                    || !self.wsv.account_is_linked(&account)
                    || !self.wsv.asset_definitions.contains_key(&asset_definition)
                {
                    return Err(VMError::PermissionDenied);
                }
                self.wsv.asset_holding_limits.insert(
                    (
                        MockWorldStateView::account_subject(&account),
                        asset_definition,
                    ),
                    limit,
                );
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT => {
                let account = self.decode_canonical_account_reg(vm, 10)?;
                let asset_definition = self.decode_asset_reg(vm, 11)?;
                let layout =
                    crate::sum::SumLayoutV1::option(1).map_err(|_| VMError::DecodeError)?;
                let (is_some, words) = crate::sum::read_words(vm, vm.register(12), layout)?;
                let cap = if is_some {
                    let pointer = words.first().copied().ok_or(VMError::DecodeError)?;
                    let tlv = vm.validate_tlv(pointer)?;
                    if tlv.type_id != PointerType::Quantity {
                        return Err(VMError::NoritoInvalid);
                    }
                    Some(
                        QuantityValueV1::decode_frame(tlv.payload)
                            .map(QuantityValueV1::into_quantity)
                            .map_err(|_| VMError::DecodeError)?,
                    )
                } else {
                    None
                };
                let (account_domain, _dataspace_name, account_dataspace) =
                    self.account_transfer_control_scope(&account)?;
                let permission = PermissionToken::SetAssetTransferDailyLimit {
                    asset_definition: asset_definition.clone(),
                    account_domain,
                    account_dataspace,
                };
                if !self.wsv.has_permission(&self.caller, &permission)
                    || !self.wsv.account_is_linked(&account)
                    || !self.wsv.asset_definitions.contains_key(&asset_definition)
                {
                    return Err(VMError::PermissionDenied);
                }
                self.wsv.asset_transfer_daily_limits.insert(
                    (
                        MockWorldStateView::account_subject(&account),
                        asset_definition,
                    ),
                    cap,
                );
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_DEBUG_PRINT => {
                let value = vm.register(10);
                if cfg!(any(test, debug_assertions)) {
                    eprintln!("[IVM] debug_print r10={value}");
                }
                Ok(DEBUG_GAS)
            }
            syscalls::SYSCALL_EXIT => {
                let status = vm.register(10);
                vm.request_exit();
                vm.set_register(10, status);
                Ok(DEBUG_GAS)
            }
            syscalls::SYSCALL_ABORT => {
                vm.request_abort();
                Ok(DEBUG_GAS)
            }
            syscalls::SYSCALL_CONTRACT_ABORT => crate::host::request_nominal_contract_abort(
                vm,
                crate::core_host::CoreHost::resolve_code_tlv_addr,
            ),
            syscalls::SYSCALL_DEBUG_LOG => {
                let pointer = vm.register(10);
                if pointer == 0 {
                    return Ok(DEBUG_GAS);
                }
                let resolved = crate::core_host::CoreHost::resolve_code_tlv_addr(vm, pointer);
                let tlv = vm.validate_tlv(resolved)?;
                let policy = vm.syscall_policy();
                if !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
                    return Err(VMError::AbiTypeNotAllowed {
                        abi: vm.abi_version(),
                        type_id: tlv.type_id as u16,
                    });
                }
                if !matches!(
                    tlv.type_id,
                    PointerType::Blob | PointerType::NoritoBytes | PointerType::Json
                ) {
                    return Err(VMError::NoritoInvalid);
                }
                if crate::dev_env::debug_wsv_enabled() {
                    let message = if tlv.type_id == PointerType::Json {
                        decode_from_bytes::<Json>(tlv.payload)
                            .map(|value| value.to_string())
                            .unwrap_or_else(|_| {
                                core::str::from_utf8(tlv.payload)
                                    .unwrap_or("<non-utf8>")
                                    .to_owned()
                            })
                    } else {
                        core::str::from_utf8(tlv.payload)
                            .unwrap_or("<non-utf8>")
                            .to_owned()
                    };
                    eprintln!("[WsvHost] {message}");
                }
                Ok(crate::host::debug_log_gas(tlv.payload.len()))
            }
            syscalls::SYSCALL_GET_AUTHORITY | syscalls::SYSCALL_SYSVAR_AUTHORITY => {
                // Return the domainless account subject so raw equality checks inside
                // contracts match AccountId::parse(...) literals and stored AccountId state.
                let authority = self.context_authority_subject();
                let payload = encode_canonical_norito(&authority)?;
                let mut tlv = Vec::with_capacity(7 + payload.len() + 32);
                tlv.extend_from_slice(&(PointerType::AccountId as u16).to_be_bytes());
                tlv.push(1);
                tlv.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                tlv.extend_from_slice(&payload);
                let h: [u8; 32] = iroha_crypto::Hash::new(&payload).into();
                tlv.extend_from_slice(&h);
                let ptr = vm.alloc_host_tlv(&tlv)?;
                vm.set_register(10, ptr);
                Ok(Self::sysvar_gas(payload.len()))
            }
            syscalls::SYSCALL_CURRENT_TIME_MS | syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS => {
                vm.set_register(10, self.wsv.current_time_ms());
                Ok(Self::sysvar_gas(0))
            }
            syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT => {
                vm.set_register(10, self.wsv.current_block_height());
                Ok(Self::sysvar_gas(0))
            }
            syscalls::SYSCALL_SYSVAR_CHAIN_ID => {
                vm.set_register(10, 0);
                Ok(Self::sysvar_gas(0))
            }
            syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS => {
                let Some(contract) = self.contract_runtime_address.as_ref() else {
                    vm.set_register(10, 0);
                    return Ok(Self::sysvar_gas(0));
                };
                let payload = contract.as_str().as_bytes();
                let pointer = Self::alloc_tlv_payload(vm, PointerType::Blob, payload)?;
                vm.set_register(10, pointer);
                Ok(Self::sysvar_gas(payload.len()))
            }
            syscalls::SYSCALL_SYSVAR_CONTRACT_SUBJECT => {
                let contract = self
                    .contract_runtime_address
                    .as_ref()
                    .ok_or(VMError::PermissionDenied)?;
                let payload = encode_canonical_norito(&contract.subject_id())?;
                let pointer = Self::alloc_tlv_payload(vm, PointerType::AccountId, &payload)?;
                vm.set_register(10, pointer);
                Ok(Self::sysvar_gas(payload.len()))
            }
            syscalls::SYSCALL_SYSVAR_ENTRYPOINT => {
                let Some(entrypoint) = self.contract_runtime_entrypoint.as_ref() else {
                    vm.set_register(10, 0);
                    return Ok(Self::sysvar_gas(0));
                };
                let payload = entrypoint.as_bytes();
                let pointer = Self::alloc_tlv_payload(vm, PointerType::Blob, payload)?;
                vm.set_register(10, pointer);
                Ok(Self::sysvar_gas(payload.len()))
            }
            syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS => {
                let alias_pointer = vm.register(10);
                let alias_tlv = vm.validate_tlv(alias_pointer)?;
                if alias_tlv.type_id != PointerType::Blob {
                    return Err(VMError::NoritoInvalid);
                }
                let alias_input_len = alias_tlv.payload.len();
                let alias = String::from_utf8(alias_tlv.payload.to_vec())
                    .map_err(|_| VMError::DecodeError)?;
                Self::parse_account_alias_scope(&alias).map_err(|_| VMError::NoritoInvalid)?;
                let account = self
                    .account_aliases
                    .get(&alias)
                    .map(|binding| binding.account.clone())
                    .ok_or(VMError::PermissionDenied)?;
                let payload = encode_canonical_norito(&account)?;
                let pointer = Self::alloc_tlv_payload(vm, PointerType::AccountId, &payload)?;
                vm.set_register(10, pointer);
                Ok(Self::singular_query_gas(
                    alias_input_len.saturating_add(payload.len()),
                ))
            }
            syscalls::SYSCALL_GRANT_PERMISSION => {
                if !self
                    .wsv
                    .has_permission(&self.caller, &PermissionToken::ManagePermissions)
                {
                    return Err(VMError::PermissionDenied);
                }
                // r10=&AccountId (subject), r11=&Name(permission)
                let subject = self.decode_account_subject_reg(vm, 10)?;
                // Decode permission token from TLV in r11
                let token = {
                    let v = vm.register(11);
                    if crate::dev_env::debug_wsv_enabled() {
                        eprintln!("[wsv.grant_permission] reg=r11 ptr=0x{v:08x}");
                    }
                    let tlv = vm.validate_tlv(v)?;
                    if crate::dev_env::debug_wsv_enabled() {
                        eprintln!(
                            "[wsv.grant_permission] tlv type={:?} len={}",
                            tlv.type_id,
                            tlv.payload.len()
                        );
                    }
                    if tlv.type_id != PointerType::Name {
                        return Err(VMError::NoritoInvalid);
                    }
                    parse_permission_name_payload(tlv.payload)?
                };
                self.wsv.grant_permission(&subject, token);
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_REVOKE_PERMISSION => {
                if !self
                    .wsv
                    .has_permission(&self.caller, &PermissionToken::ManagePermissions)
                {
                    return Err(VMError::PermissionDenied);
                }
                let subject = self.decode_account_subject_reg(vm, 10)?;
                let token = {
                    let v = vm.register(11);
                    let tlv = vm.validate_tlv(v)?;
                    if tlv.type_id != PointerType::Name {
                        return Err(VMError::NoritoInvalid);
                    }
                    parse_permission_name_payload(tlv.payload)?
                };
                self.wsv.revoke_permission(&subject, &token);
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION
            | syscalls::SYSCALL_REVOKE_CONTRACT_PERMISSION => {
                let subject = self.decode_account_subject_reg(vm, 10)?;
                let permission = self.decode_name_reg(vm, 11)?;
                let contract = self
                    .contract_runtime_address
                    .clone()
                    .ok_or(VMError::PermissionDenied)?;
                let interface = vm.contract_interface().ok_or(VMError::InvalidMetadata)?;
                let declared = interface.permissions.iter().any(|declaration| {
                    declaration.name == permission
                        && matches!(
                            declaration.scope,
                            iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1::Instance
                        )
                });
                if !declared || self.caller != contract.subject_id() {
                    return Err(VMError::PermissionDenied);
                }
                let token = PermissionToken::ContractPermission {
                    contract,
                    permission,
                };
                if !self.wsv.has_permission(&self.caller, &token) {
                    return Err(VMError::PermissionDenied);
                }
                let is_grant = number == syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION;
                let exists = self.wsv.has_permission(&subject, &token);
                if exists == is_grant {
                    return Err(VMError::PermissionDenied);
                }
                if is_grant {
                    self.wsv.grant_permission(&subject, token);
                } else {
                    self.wsv.revoke_permission(&subject, &token);
                }
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_CREATE_ROLE => {
                if !self
                    .wsv
                    .has_permission(&self.caller, &PermissionToken::ManageRoles)
                {
                    return Err(VMError::PermissionDenied);
                }
                // r10 = &Name (role), r11 = &Json (perm set)
                let rname = self.decode_name_reg(vm, 10)?.to_string();
                let perms = {
                    let v = vm.register(11);
                    let tlv = vm.validate_tlv(v)?;
                    if tlv.type_id != PointerType::Json {
                        return Err(VMError::NoritoInvalid);
                    }
                    let mut set = HashSet::new();
                    for name in parse_json_string_array(tlv.payload, &["perms", "permissions"])? {
                        let tok = parse_permission_name(&name)?;
                        set.insert(tok);
                    }
                    set
                };
                if self.wsv.create_role(&rname, perms) {
                    Ok(Self::mutation_gas(0))
                } else {
                    eprintln!("[wsv] create_role permission denied for {rname}");
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_DELETE_ROLE => {
                if !self
                    .wsv
                    .has_permission(&self.caller, &PermissionToken::ManageRoles)
                {
                    return Err(VMError::PermissionDenied);
                }
                // r10 = &Name
                let rname = self.decode_name_reg(vm, 10)?.to_string();
                if self.wsv.delete_role(&rname) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_GRANT_ROLE => {
                if !self
                    .wsv
                    .has_permission(&self.caller, &PermissionToken::ManageRoles)
                {
                    return Err(VMError::PermissionDenied);
                }
                // r10 = &AccountId, r11=&Name
                let subj = self.decode_account_subject_reg(vm, 10)?;
                let rname = self.decode_name_reg(vm, 11)?.to_string();
                if self.wsv.grant_role(&subj, &rname) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_REVOKE_ROLE => {
                if !self
                    .wsv
                    .has_permission(&self.caller, &PermissionToken::ManageRoles)
                {
                    return Err(VMError::PermissionDenied);
                }
                let subj = self.decode_account_subject_reg(vm, 10)?;
                let rname = self.decode_name_reg(vm, 11)?.to_string();
                if self.wsv.revoke_role(&subj, &rname) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_TRANSFER_V1 => {
                if self.fastpq_batch_entries.is_some() {
                    self.push_fastpq_batch_entry(vm)
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_TRANSFER_ASSET_SCOPED => {
                if self.fastpq_batch_entries.is_some() {
                    return Err(VMError::PermissionDenied);
                }
                let from_id = self.decode_canonical_account_reg(vm, 10)?;
                let to_id = self.decode_canonical_account_reg(vm, 11)?;
                let asset_id = self.decode_asset_reg(vm, 12)?;
                let amount = self.decode_amount_reg(vm, 13)?;
                // r14 = 0 means the call named no `dataspace:`; mock definitions are
                // all globally scoped, so the transfer uses the global bucket.
                let scope = match vm.register(14) {
                    0 => AssetBalanceScope::Global,
                    _ => AssetBalanceScope::Dataspace(self.decode_dataspace_reg(vm, 14)?),
                };
                let transfers_external_bucket = MockWorldStateView::account_subject(&from_id)
                    != MockWorldStateView::account_subject(&self.caller);
                if transfers_external_bucket {
                    let exact = PermissionToken::TransferAssetBucket(AssetId::with_scope(
                        asset_id.clone(),
                        from_id.clone(),
                        scope,
                    ));
                    let definition_wide = PermissionToken::TransferAsset(asset_id.clone());
                    if !self.wsv.has_permission(&self.caller, &exact)
                        && !self.wsv.has_permission(&self.caller, &definition_wide)
                    {
                        return Err(VMError::PermissionDenied);
                    }
                }
                // The bucket permission checked above authorizes an external-bucket transfer.
                if self.wsv.transfer_with_permission_bypass(
                    &self.caller,
                    from_id,
                    to_id,
                    asset_id,
                    amount,
                    transfers_external_bucket,
                ) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN => self.begin_fastpq_batch(),
            syscalls::SYSCALL_TRANSFER_V1_BATCH_END => self.finish_fastpq_batch(),
            syscalls::SYSCALL_TRANSFER_V1_BATCH_APPLY => self.apply_fastpq_batch_tlv(vm),
            syscalls::SYSCALL_MINT_ASSET => {
                let account_id = self.decode_canonical_account_reg(vm, 10)?;
                let asset_id = self.decode_asset_reg(vm, 11)?;
                let amount = self.decode_amount_reg(vm, 12)?;
                let token = PermissionToken::MintAsset(asset_id.clone());
                if !self.wsv.has_permission(&self.caller, &token) {
                    return Err(VMError::PermissionDenied);
                }
                if self.wsv.mint(&self.caller, account_id, asset_id, amount) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_BURN_ASSET => {
                let account_id = self.decode_canonical_account_reg(vm, 10)?;
                let asset_id = self.decode_asset_reg(vm, 11)?;
                let amount = self.decode_amount_reg(vm, 12)?;
                if MockWorldStateView::account_subject(&account_id)
                    != MockWorldStateView::account_subject(&self.caller)
                {
                    let token = PermissionToken::BurnAsset(asset_id.clone());
                    if !self.wsv.has_permission(&self.caller, &token) {
                        return Err(VMError::PermissionDenied);
                    }
                }
                if self.wsv.burn(&self.caller, account_id, asset_id, amount) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_UNREGISTER_ASSET => {
                let asset_id = self.decode_asset_reg(vm, 10)?;
                if !self.wsv.unregister_asset_definition(&asset_id) {
                    return Err(VMError::PermissionDenied);
                }
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_UNREGISTER_ACCOUNT => {
                let subject = self.decode_account_subject_reg(vm, 10)?;
                if !self.wsv.unregister_account_subject(&subject) {
                    return Err(VMError::PermissionDenied);
                }
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_UNREGISTER_DOMAIN => {
                let dom = self.decode_domain_reg(vm, 10)?;
                if !self.wsv.unregister_domain(&dom) {
                    return Err(VMError::PermissionDenied);
                }
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_TRANSFER_DOMAIN => {
                // r10=&DomainId, r11=&AccountId(to). This mock host validates TLVs
                // and returns success; ownership is not tracked in MockWorldStateView.
                let _dom = self.decode_domain_reg(vm, 10)?;
                let _to = self.decode_account_subject_reg(vm, 11)?;
                Ok(Self::mutation_gas(0))
            }
            syscalls::SYSCALL_GET_ACCOUNT_BALANCE => {
                let account_id = self.decode_canonical_account_reg(vm, 10)?;
                let asset_id = self.decode_asset_reg(vm, 11)?;
                let authority = self.context_authority_subject();
                if MockWorldStateView::account_subject(&account_id)
                    != MockWorldStateView::account_subject(&authority)
                {
                    let token = PermissionToken::ReadAccountAssets(
                        MockWorldStateView::account_subject(&account_id),
                    );
                    if !self.wsv.has_permission(&authority, &token) {
                        return Err(VMError::PermissionDenied);
                    }
                }
                if let Some(b) = self.wsv.balance_checked(&authority, &account_id, &asset_id) {
                    let payload = QuantityValueV1::new(b)
                        .encode_frame()
                        .map_err(|_| VMError::NoritoInvalid)?;
                    let p = Self::alloc_tlv_payload(vm, PointerType::Quantity, &payload)?;
                    vm.set_register(10, p);
                    Ok(Self::singular_query_gas(payload.len()))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_NFT_MINT_ASSET => {
                let nft = self.decode_nft_reg(vm, 10)?;
                let owner = self.decode_canonical_account_reg(vm, 11)?;
                if self.wsv.create_nft(owner, self.caller.clone(), nft) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_NFT_TRANSFER_ASSET => {
                let from = self.decode_canonical_account_reg(vm, 10)?;
                let nft = self.decode_nft_reg(vm, 11)?;
                let to = self.decode_canonical_account_reg(vm, 12)?;
                if self.wsv.transfer_nft(&self.caller, from, to, &nft) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_NFT_SET_METADATA => {
                let nft = self.decode_nft_reg(vm, 10)?;
                let key = self.decode_name_reg(vm, 11)?;
                let v = vm.register(12);
                let tlv = vm.validate_tlv(v)?;
                if tlv.type_id != PointerType::Json {
                    return Err(VMError::NoritoInvalid);
                }
                let _: Json =
                    decode_canonical_norito(tlv.payload).map_err(|_| VMError::DecodeError)?;
                if self
                    .wsv
                    .set_nft_metadata(&self.caller, &nft, key, tlv.payload.to_vec())
                {
                    Ok(Self::mutation_gas(tlv.payload.len()))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_NFT_BURN_ASSET => {
                let nft = self.decode_nft_reg(vm, 10)?;
                if self.wsv.burn_nft(&self.caller, &nft) {
                    Ok(Self::mutation_gas(0))
                } else {
                    Err(VMError::PermissionDenied)
                }
            }
            syscalls::SYSCALL_AXT_BEGIN => self.handle_axt_begin(vm),
            syscalls::SYSCALL_AXT_TOUCH => self.handle_axt_touch(vm),
            syscalls::SYSCALL_VERIFY_DS_PROOF => self.handle_axt_verify_ds_proof(vm),
            syscalls::SYSCALL_AXT_STAGE_ANCHORED_SPEND => Err(VMError::PermissionDenied),
            syscalls::SYSCALL_AXT_COMMIT => self.handle_axt_commit(),
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
    fn begin_tx(&mut self, _declared: &crate::parallel::StateAccessSet) -> Result<(), VMError> {
        self.actual_access.read_keys.clear();
        self.actual_access.write_keys.clear();
        self.actual_access.reg_tags.clear();
        self.actual_access.state_writes.clear();
        self.state_overlay.clear();
        self.tx_active = true;
        if crate::dev_env::decode_trace_enabled() {
            eprintln!("[WsvHost] begin_tx activated overlay");
        }
        Ok(())
    }
    fn finish_tx(&mut self) -> Result<crate::host::AccessLog, VMError> {
        if self.tx_active {
            if crate::dev_env::decode_trace_enabled() {
                eprintln!(
                    "[WsvHost] finish_tx flushing {} staged entries",
                    self.state_overlay.len()
                );
            }
            let overlay = std::mem::take(&mut self.state_overlay);
            self.tx_active = false;
            for (path, val) in overlay {
                match val {
                    Some(bytes) => self.wsv.sc_set(&path, bytes)?,
                    None => self.wsv.sc_del(&path)?,
                }
            }
        } else {
            self.state_overlay.clear();
        }
        Ok(self.actual_access.clone())
    }
    fn checkpoint(&self) -> Option<Box<dyn Any + Send>> {
        Some(Box::new(self.checkpoint_state()))
    }
    fn restore(&mut self, snapshot: &dyn Any) -> Result<(), VMError> {
        let saved = snapshot
            .downcast_ref::<WsvHostSnapshot>()
            .ok_or(VMError::HostUnavailable)?;
        self.restore_state(saved)
    }
    fn access_logging_supported(&self) -> bool {
        true
    }
}
// Keep tests at the end of the file to satisfy clippy without local allows.
#[cfg(test)]
mod tests_peer_json {
    use super::*;
    #[test]
    fn parse_peer_accepts_canonical_string_and_wrapped_json() {
        const SAMPLE: &str =
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774@127.0.0.1:1337";
        let raw = format!("\"{SAMPLE}\"");
        let raw = Json::from_str_norito(&raw).expect("string Json");
        let raw = encode_canonical_norito(&raw).expect("canonical string Json");
        let peer_raw = parse_peer(&raw).expect("string peer parses");
        assert_eq!(peer_raw.to_string(), SAMPLE);
        let wrapped = format!("{{\"peer\":\"{SAMPLE}\"}}");
        let wrapped = Json::from_str_norito(&wrapped).expect("wrapped Json");
        let wrapped = encode_canonical_norito(&wrapped).expect("canonical wrapped Json");
        let peer_wrapped = parse_peer(&wrapped).expect("wrapped peer parses");
        assert_eq!(peer_wrapped.to_string(), SAMPLE);
    }
    #[test]
    fn parse_peer_rejects_raw_and_missing_payload() {
        assert_eq!(
            parse_peer(br#"{"peer":"not-a-frame"}"#),
            Err(VMError::NoritoInvalid)
        );
        let missing =
            Json::from_str_norito(r#"{"not_peer":true}"#).expect("missing-peer Json value");
        let missing = encode_canonical_norito(&missing).expect("canonical missing-peer Json");
        assert!(matches!(parse_peer(&missing), Err(VMError::NoritoInvalid)));
    }
}
#[cfg(test)]
mod tests_axt_policy_snapshot {
    use super::*;

    #[test]
    fn default_space_directory_axt_policy_is_empty() {
        assert!(SpaceDirectoryAxtPolicy::default().policies.is_empty());
    }
    use iroha_data_model::nexus::MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES;

    #[test]
    fn axt_proof_validation_rejects_oversized_payload_before_decode() {
        let dsid = DataSpaceId::new(6);
        let mut wsv = MockWorldStateView::new();
        wsv.set_axt_policy(
            dsid,
            DataspaceAxtPolicy {
                manifest_root: [0x11; 32],
                ..DataspaceAxtPolicy::default()
            },
        );
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(wsv, caller);
        let proof = ProofBlob {
            payload: vec![0; MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES + 1],
            expiry_slot: None,
        };

        assert_eq!(
            host.validate_axt_proof(dsid, &proof),
            Err(VMError::NoritoInvalid)
        );
    }

    #[test]
    fn axt_policy_snapshot_model_roundtrips() {
        let mut wsv = MockWorldStateView::new();
        let dsid = DataSpaceId::new(7);
        wsv.set_axt_policy(
            dsid,
            DataspaceAxtPolicy {
                manifest_root: [0x11; 32],
                target_lane: LaneId::new(3),
                active_handle_era: 5,
                next_handle_counter: 9,
                current_slot: 42,
            },
        );
        let snapshot = wsv.axt_policy_snapshot_model();
        assert_eq!(snapshot.entries.len(), 1);
        let entry = &snapshot.entries[0];
        assert_eq!(entry.dsid, dsid);
        assert_eq!(entry.policy.target_lane.as_u32(), 3);
        assert_eq!(entry.policy.active_handle_era, 5);
        assert_eq!(entry.policy.next_handle_counter, 9);
        assert_eq!(entry.policy.current_slot, 42);
        let mut wsv_loaded = MockWorldStateView::new();
        wsv_loaded
            .load_axt_policy_snapshot_model(&snapshot)
            .expect("canonical policy snapshot");
        let policies = wsv_loaded.axt_policy_snapshot();
        let loaded = policies.get(&dsid).expect("policy present");
        assert_eq!(loaded.target_lane.as_u32(), 3);
        assert_eq!(loaded.active_handle_era, 5);
        assert_eq!(loaded.next_handle_counter, 9);
        assert_eq!(loaded.current_slot, 42);
        assert_eq!(loaded.manifest_root, [0x11; 32]);
    }
    #[test]
    fn noncanonical_axt_policy_snapshot_is_rejected_without_mutation() {
        let mut wsv = MockWorldStateView::new();
        let dsid = DataSpaceId::new(7);
        wsv.set_axt_policy(
            dsid,
            DataspaceAxtPolicy {
                manifest_root: [0x11; 32],
                target_lane: LaneId::new(3),
                active_handle_era: 5,
                next_handle_counter: 9,
                current_slot: 42,
            },
        );
        let before = wsv.axt_policy_snapshot_model();
        let mut invalid = before.clone();
        invalid.version ^= 1;
        assert!(matches!(
            SpaceDirectoryAxtPolicy::from_policy_snapshot(&invalid),
            Err(AxtPolicySnapshotValidationError::VersionMismatch { .. })
        ));
        assert!(matches!(
            wsv.load_axt_policy_snapshot_model(&invalid),
            Err(AxtPolicySnapshotValidationError::VersionMismatch { .. })
        ));
        assert_eq!(wsv.axt_policy_snapshot_model(), before);
    }
    #[test]
    fn axt_policy_snapshot_model_fills_slot_from_time() {
        let mut wsv = MockWorldStateView::new();
        wsv.set_slot_length_ms(10);
        wsv.set_current_time_ms(25); // current_slot = 2
        let dsid = DataSpaceId::new(8);
        wsv.set_axt_policy(
            dsid,
            DataspaceAxtPolicy {
                manifest_root: [0x22; 32],
                target_lane: LaneId::new(1),
                active_handle_era: 1,
                next_handle_counter: 1,
                current_slot: 0,
            },
        );
        let snapshot = wsv.axt_policy_snapshot_model();
        let entry = snapshot
            .entries
            .iter()
            .find(|binding| binding.dsid == dsid)
            .expect("policy entry present");
        assert_eq!(entry.policy.current_slot, 2);
    }
}
#[cfg(test)]
mod tests_governance_elections {
    use super::*;
    use crate::Memory;
    use iroha_data_model::proof::{ProofAttachment, ProofBox, VerifyingKeyId};
    fn vote_vk_id() -> VerifyingKeyId {
        VerifyingKeyId::new("mock/governance-fixture", "governance_vote_vk")
    }
    fn register_vote_vk(wsv: &mut MockWorldStateView) {
        wsv.insert_verifying_key(vote_vk_id(), vec![0x02]);
    }
    fn dummy_ballot_proof(hash: [u8; 32]) -> ProofAttachment {
        let mut attachment = ProofAttachment::new_ref(
            "mock/governance-fixture".into(),
            ProofBox::new("mock/governance-fixture".into(), vec![0x01]),
            vote_vk_id(),
        );
        attachment.envelope_hash = Some(hash);
        attachment
    }
    fn dummy_tally_proof(hash: [u8; 32]) -> ProofAttachment {
        let mut attachment = ProofAttachment::new_ref(
            "mock/governance-fixture".into(),
            ProofBox::new("mock/governance-fixture".into(), vec![0x11]),
            vote_vk_id(),
        );
        attachment.envelope_hash = Some(hash);
        attachment
    }
    #[test]
    fn create_election_enforces_v1_shape_before_mutation() {
        let mut wsv = MockWorldStateView::new();
        assert!(!wsv.create_election("zero".to_owned(), 0, [0; 32], 0, 1));
        assert!(wsv.elections.is_empty());
        assert!(!wsv.create_election(
            "too-many".to_owned(),
            DMZk::MAX_ELECTION_OPTIONS_V1 + 1,
            [0; 32],
            0,
            1
        ));
        assert!(wsv.elections.is_empty());
        assert!(!wsv.create_election("one".to_owned(), 1, [1; 32], 0, 1));
        assert!(wsv.elections.is_empty());
        assert!(!wsv.create_election(
            "inverted".to_owned(),
            DMZk::MIN_ELECTION_OPTIONS_V1,
            [0; 32],
            2,
            1
        ));
        assert!(wsv.elections.is_empty());
        assert!(wsv.create_election(
            "minimum".to_owned(),
            DMZk::MIN_ELECTION_OPTIONS_V1,
            [1; 32],
            0,
            1
        ));
        let minimum = wsv.elections.get("minimum").expect("minimum election");
        assert_eq!(minimum.options, DMZk::MIN_ELECTION_OPTIONS_V1);
        assert_eq!(minimum.tally, vec![0, 0]);
        assert!(!wsv.create_election(
            "minimum".to_owned(),
            DMZk::MAX_ELECTION_OPTIONS_V1,
            [2; 32],
            0,
            1
        ));
        let minimum = wsv
            .elections
            .get("minimum")
            .expect("original election retained");
        assert_eq!(minimum.options, DMZk::MIN_ELECTION_OPTIONS_V1);
        assert_eq!(minimum.eligible_root, [1; 32]);
        assert_eq!(minimum.tally, vec![0, 0]);
        assert!(wsv.create_election(
            "max".to_owned(),
            DMZk::MAX_ELECTION_OPTIONS_V1,
            [3; 32],
            0,
            1
        ));
        assert_eq!(
            wsv.elections.get("max").expect("max election").tally.len(),
            DMZk::MAX_ELECTION_OPTIONS_V1 as usize
        );
        assert_eq!(wsv.elections.len(), 2);
    }
    #[test]
    fn submit_ballot_requires_verify_and_rejects_duplicate_nullifier() {
        // Duplicate nullifier rejection using WSV helpers
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("e1".to_string(), 2, [0u8; 32], 0, u64::MAX));
        let proof_ok = dummy_ballot_proof([1u8; 32]);
        assert!(wsv.submit_ballot("e1", vec![1, 2, 3], [7u8; 32], proof_ok));
        let proof_dup = dummy_ballot_proof([2u8; 32]);
        assert!(!wsv.submit_ballot("e1", vec![4, 5, 6], [7u8; 32], proof_dup));
    }
    #[test]
    fn submit_ballot_enforces_time_window() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("time-test".to_string(), 2, [0u8; 32], 10, 20));
        // Too early
        wsv.set_current_time_ms(5);
        let proof_early = dummy_ballot_proof([3u8; 32]);
        assert!(!wsv.submit_ballot("time-test", vec![0x10], [0x01; 32], proof_early,));
        // Within window
        wsv.set_current_time_ms(15);
        let proof_ok = dummy_ballot_proof([4u8; 32]);
        assert!(wsv.submit_ballot("time-test", vec![0x11], [0x02; 32], proof_ok,));
        // Too late
        wsv.set_current_time_ms(25);
        let proof_late = dummy_ballot_proof([5u8; 32]);
        assert!(!wsv.submit_ballot("time-test", vec![0x12], [0x03; 32], proof_late,));
    }
    #[test]
    fn submit_ballot_rejects_invalid_proof() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("proof-test".to_string(), 2, [0u8; 32], 0, u64::MAX));
        wsv.set_current_time_ms(1);
        // Missing envelope hash
        let missing_hash = ProofAttachment::new_ref(
            "mock/governance-fixture".into(),
            ProofBox::new("mock/governance-fixture".into(), vec![0x0a]),
            vote_vk_id(),
        );
        assert!(!wsv.submit_ballot("proof-test", vec![0x20], [0x04; 32], missing_hash,));
        // Empty proof bytes
        let mut empty_proof = ProofAttachment::new_ref(
            "mock/governance-fixture".into(),
            ProofBox::new("mock/governance-fixture".into(), Vec::new()),
            vote_vk_id(),
        );
        empty_proof.envelope_hash = Some([0x06; 32]);
        assert!(!wsv.submit_ballot("proof-test", vec![0x21], [0x05; 32], empty_proof,));
        // Missing registry reference should fail.
        let mut vk_mismatch = ProofAttachment::new_ref(
            "mock/governance-fixture".into(),
            ProofBox::new("mock/governance-fixture".into(), vec![0x0d]),
            VerifyingKeyId::new("mock/governance-fixture", "missing_vote_vk"),
        );
        vk_mismatch.envelope_hash = Some([0x07; 32]);
        assert!(!wsv.submit_ballot("proof-test", vec![0x22], [0x06; 32], vk_mismatch,));
        // Valid proof succeeds
        let proof_ok = dummy_ballot_proof([0x08; 32]);
        assert!(wsv.submit_ballot("proof-test", vec![0x23], [0x07; 32], proof_ok,));
    }
    #[test]
    fn finalize_requires_valid_proof_and_sets_tally() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("e2".to_string(), 3, [0u8; 32], 0, u64::MAX));
        let large_weight = u128::from(u64::MAX) + 1;
        let proof_ok = dummy_tally_proof([9u8; 32]);
        assert!(wsv.finalize_election("e2", vec![large_weight, 2, 1], proof_ok));
        // Second finalize should be rejected
        let proof_second = dummy_tally_proof([0xAA; 32]);
        assert!(!wsv.finalize_election("e2", vec![9, 9, 9], proof_second));
        let e = wsv.elections.get("e2").unwrap();
        assert_eq!(e.tally, vec![large_weight, 2, 1]);
        assert!(e.finalized);
    }
    #[test]
    fn finalize_rejects_invalid_inputs() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("e-invalid".to_string(), 2, [0u8; 32], 0, u64::MAX));
        // Missing envelope hash -> reject
        let proof_missing = ProofAttachment::new_ref(
            "mock/governance-fixture".into(),
            ProofBox::new("mock/governance-fixture".into(), vec![0x21]),
            vote_vk_id(),
        );
        assert!(!wsv.finalize_election("e-invalid", vec![1, 2], proof_missing));
        // Wrong tally length -> reject even with valid proof
        let proof_bad_len = dummy_tally_proof([0x55; 32]);
        assert!(!wsv.finalize_election("e-invalid", vec![1, 2, 3], proof_bad_len));
        assert!(!wsv.finalize_election(
            "e-invalid",
            vec![u128::MAX, 1],
            dummy_tally_proof([0x56; 32]),
        ));
        assert!(!wsv.elections.get("e-invalid").unwrap().finalized);
        // Valid path succeeds
        let proof_ok = dummy_tally_proof([0x66; 32]);
        assert!(wsv.finalize_election("e-invalid", vec![10, 11], proof_ok));
        let e = wsv.elections.get("e-invalid").unwrap();
        assert_eq!(e.tally, vec![10, 11]);
    }
    #[test]
    fn finalize_rejects_corrupt_stored_shape_without_mutation() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("corrupt".to_owned(), 2, [0; 32], 0, u64::MAX));
        wsv.elections
            .get_mut("corrupt")
            .expect("election")
            .tally
            .pop();
        assert!(!wsv.finalize_election("corrupt", vec![5, 7], dummy_tally_proof([0x44; 32])));
        let election = wsv.elections.get("corrupt").expect("election retained");
        assert!(!election.finalized);
        assert_eq!(election.tally, vec![0]);
    }
    #[test]
    fn finalize_enforces_zero_max_and_over_max_tally_boundaries() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        for election_id in ["submitted", "stored-zero", "stored-over"] {
            assert!(wsv.create_election(
                election_id.to_owned(),
                DMZk::MAX_ELECTION_OPTIONS_V1,
                [0; 32],
                0,
                u64::MAX
            ));
        }
        assert!(!wsv.finalize_election("submitted", Vec::new(), dummy_tally_proof([0x50; 32])));
        assert!(!wsv.finalize_election(
            "submitted",
            vec![1; DMZk::MAX_ELECTION_OPTIONS_V1 as usize + 1],
            dummy_tally_proof([0x51; 32])
        ));
        let submitted = wsv.elections.get("submitted").expect("election");
        assert!(!submitted.finalized);
        assert_eq!(
            submitted.tally,
            vec![0; DMZk::MAX_ELECTION_OPTIONS_V1 as usize]
        );
        wsv.elections
            .get_mut("stored-zero")
            .expect("election")
            .tally
            .clear();
        assert!(!wsv.finalize_election(
            "stored-zero",
            vec![1; DMZk::MAX_ELECTION_OPTIONS_V1 as usize],
            dummy_tally_proof([0x52; 32])
        ));
        let stored_zero = wsv.elections.get("stored-zero").expect("election");
        assert!(!stored_zero.finalized);
        assert!(stored_zero.tally.is_empty());
        wsv.elections
            .get_mut("stored-over")
            .expect("election")
            .tally
            .push(0);
        assert!(!wsv.finalize_election(
            "stored-over",
            vec![1; DMZk::MAX_ELECTION_OPTIONS_V1 as usize],
            dummy_tally_proof([0x53; 32])
        ));
        let stored_over = wsv.elections.get("stored-over").expect("election");
        assert!(!stored_over.finalized);
        assert_eq!(
            stored_over.tally.len(),
            DMZk::MAX_ELECTION_OPTIONS_V1 as usize + 1
        );
        let final_tally: Vec<u128> = (0..DMZk::MAX_ELECTION_OPTIONS_V1).map(u128::from).collect();
        assert!(wsv.finalize_election(
            "submitted",
            final_tally.clone(),
            dummy_tally_proof([0x54; 32])
        ));
        let submitted = wsv.elections.get("submitted").expect("election");
        assert!(submitted.finalized);
        assert_eq!(submitted.tally, final_tally);
    }
    #[test]
    fn wsv_host_new_with_subject_registers_canonical_caller() {
        let caller = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "wonderland",
        );
        let caller_subject = caller.clone();
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller_subject.clone());
        assert_eq!(host.caller, caller_subject);
        assert!(host.wsv.account_signatories(&host.caller).is_some());
    }
    #[test]
    fn raw_integer_entity_registers_are_rejected() {
        let caller = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(u64::MAX);
        vm.set_register(10, 7);
        assert!(
            host.decode_account_reg(&vm, 10).is_err(),
            "a raw integer must not be interpreted as an account index"
        );
        assert!(
            host.decode_asset_reg(&vm, 10).is_err(),
            "a raw integer must not be interpreted as an asset index"
        );
    }
    #[test]
    fn wsv_host_set_caller_subject_materializes_and_switches_caller() {
        let alice = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "wonderland",
        );
        let bob = test_account_id(
            "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
            "finance",
        );
        let alice_subject = alice.clone();
        let bob_subject = bob.clone();
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), alice_subject);
        host.set_caller_subject(bob_subject.clone());
        assert_eq!(host.caller_subject(), bob_subject);
        assert!(host.wsv.account_signatories(&host.caller).is_some());
    }
    #[test]
    fn finalize_binds_to_verified_envelope_hash() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("e-bind".to_string(), 2, [0u8; 32], 0, u64::MAX));
        let caller: AccountId = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "domain",
        );
        let mut host = WsvHost::new_with_subject(wsv, caller.clone());
        host.__test_set_verified_tally([0xAB; 32]);
        let fin = iroha_data_model::isi::zk::FinalizeElection {
            election_id: "e-bind".to_string(),
            tally: vec![4, 6],
            tally_proof: iroha_data_model::proof::ProofAttachment::new_ref(
                "mock/governance-fixture".into(),
                iroha_data_model::proof::ProofBox::new(
                    "mock/governance-fixture".into(),
                    vec![0x31],
                ),
                vote_vk_id(),
            ),
        };
        let res = host.handle_finalize_election(&fin);
        assert_eq!(res, Ok(WsvHost::mutation_gas(0)));
        let election = host.wsv.elections.get("e-bind").unwrap();
        assert!(election.finalized);
        assert_eq!(election.tally, vec![4, 6]);
        let res_second = host.handle_finalize_election(&fin);
        assert!(
            matches!(res_second, Err(VMError::PermissionDenied)),
            "res_second: {res_second:?}"
        );
    }
    #[test]
    fn finalize_rejects_mismatched_envelope_hash() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("e-mismatch".to_string(), 2, [0u8; 32], 0, u64::MAX));
        let caller: AccountId = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "domain",
        );
        let mut host = WsvHost::new_with_subject(wsv, caller.clone());
        host.__test_set_verified_tally([0xFE; 32]);
        let mut tally_proof = iroha_data_model::proof::ProofAttachment::new_ref(
            "mock/governance-fixture".into(),
            iroha_data_model::proof::ProofBox::new("mock/governance-fixture".into(), vec![0x41]),
            vote_vk_id(),
        );
        tally_proof.envelope_hash = Some([0xEF; 32]); // mismatch
        let fin = iroha_data_model::isi::zk::FinalizeElection {
            election_id: "e-mismatch".to_string(),
            tally: vec![7, 3],
            tally_proof,
        };
        let res = host.handle_finalize_election(&fin);
        assert!(matches!(res, Err(VMError::PermissionDenied)));
        let election = host.wsv.elections.get("e-mismatch").unwrap();
        assert!(!election.finalized);
        assert!(
            host.__test_verified_tally().is_none(),
            "latch persisted: {:?}",
            host.__test_verified_tally()
        );
    }
    #[test]
    fn malformed_verify_ballot_keeps_latch_off_and_submit_rejected() {
        // Host + VM with one election
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("e1".to_string(), 2, [0u8; 32], 0, u64::MAX));
        let caller: AccountId = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "domain",
        );
        let host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(0);
        vm.set_host(host);
        // 1) Malformed envelope for ballot verify: NoritoBytes TLV with empty body
        let empty_env: Vec<u8> = Vec::new();
        let mut env_tlv = Vec::with_capacity(7 + empty_env.len() + 32);
        env_tlv.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
        env_tlv.push(1);
        env_tlv.extend_from_slice(&(empty_env.len() as u32).to_be_bytes());
        env_tlv.extend_from_slice(&empty_env);
        let h: [u8; 32] = iroha_crypto::Hash::new(&empty_env).into();
        env_tlv.extend_from_slice(&h);
        vm.memory.preload_input(0, &env_tlv).expect("preload input");
        vm.set_register(10, Memory::INPUT_START);
        // Call verify syscall (should return 0 status and not set latch)
        let _ = unsafe {
            let host_ptr = vm
                .host_mut_any()
                .unwrap()
                .downcast_mut::<WsvHost>()
                .unwrap() as *mut WsvHost;
            (*host_ptr)
                .syscall(syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT, &mut vm)
                .unwrap_or(0)
        };
        // 2) Try to submit a ballot; should be PermissionDenied and no ciphertexts
        let sb = iroha_data_model::isi::zk::SubmitBallot {
            election_id: "e1".to_string(),
            ciphertext: vec![1, 2, 3],
            ballot_proof: iroha_data_model::proof::ProofAttachment::new_ref(
                "mock/governance-fixture".into(),
                iroha_data_model::proof::ProofBox::new(
                    "mock/governance-fixture".into(),
                    vec![0x01],
                ),
                vote_vk_id(),
            ),
            nullifier: [7u8; 32],
        };
        let ib_bytes = encode_canonical_norito(&DMInstructionBox::from(sb))
            .expect("encode canonical ballot InstructionBox");
        let mut tlv = Vec::with_capacity(7 + ib_bytes.len() + 32);
        tlv.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
        tlv.push(1);
        tlv.extend_from_slice(&(ib_bytes.len() as u32).to_be_bytes());
        tlv.extend_from_slice(&ib_bytes);
        let hh: [u8; 32] = iroha_crypto::Hash::new(&ib_bytes).into();
        tlv.extend_from_slice(&hh);
        vm.memory.preload_input(0, &tlv).expect("preload input");
        vm.set_register(10, Memory::INPUT_START);
        vm.set_register(11, syscalls::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT);
        let res = unsafe {
            let host_ptr = vm
                .host_mut_any()
                .unwrap()
                .downcast_mut::<WsvHost>()
                .unwrap() as *mut WsvHost;
            (*host_ptr).syscall(syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION, &mut vm)
        };
        assert!(matches!(res, Err(VMError::PermissionDenied)));
        let host_ref = vm.host_mut_any().unwrap();
        let host = host_ref.downcast_ref::<WsvHost>().unwrap();
        assert_eq!(host.wsv.elections.get("e1").unwrap().ciphertexts.len(), 0);
    }
    #[test]
    fn host_submit_ballot_requires_matching_envelope_hash() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("gov1".to_string(), 2, [0u8; 32], 0, u64::MAX));
        wsv.set_current_time_ms(100);
        let caller: AccountId = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "domain",
        );
        let host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(0);
        vm.set_host(host);
        {
            let host_ref = vm.host_mut_any().unwrap();
            let host = host_ref.downcast_mut::<WsvHost>().unwrap();
            host.wsv.set_current_time_ms(150);
            host.__test_push_verified_ballot([0x11; 32]);
        }
        // Submit instruction without envelope hash; host should inject expected hash and succeed.
        let submit = iroha_data_model::isi::zk::SubmitBallot {
            election_id: "gov1".to_string(),
            ciphertext: vec![0xaa, 0xbb, 0xcc],
            ballot_proof: ProofAttachment::new_ref(
                "mock/governance-fixture".into(),
                ProofBox::new("mock/governance-fixture".into(), vec![0x01]),
                vote_vk_id(),
            ),
            nullifier: [0x09; 32],
        };
        let res = {
            let host_ref = vm.host_mut_any().unwrap();
            let host = host_ref.downcast_mut::<WsvHost>().unwrap();
            host.handle_submit_ballot(&submit)
        };
        assert_eq!(res, Ok(WsvHost::mutation_gas(0)));
        {
            let host_ref = vm.host_mut_any().unwrap();
            let host = host_ref.downcast_ref::<WsvHost>().unwrap();
            let election = host.wsv.elections.get("gov1").unwrap();
            assert_eq!(election.ciphertexts.len(), 1);
        }
        // Push verified hash but provide mismatching envelope hash in the proof; should be rejected.
        {
            let host_ref = vm.host_mut_any().unwrap();
            let host = host_ref.downcast_mut::<WsvHost>().unwrap();
            host.__test_push_verified_ballot([0x22; 32]);
        }
        let mut mismatch_proof = ProofAttachment::new_ref(
            "mock/governance-fixture".into(),
            ProofBox::new("mock/governance-fixture".into(), vec![0x03]),
            vote_vk_id(),
        );
        mismatch_proof.envelope_hash = Some([0x33; 32]);
        let submit_bad = iroha_data_model::isi::zk::SubmitBallot {
            election_id: "gov1".to_string(),
            ciphertext: vec![0xdd, 0xee, 0xff],
            ballot_proof: mismatch_proof,
            nullifier: [0x10; 32],
        };
        let res_bad = {
            let host_ref = vm.host_mut_any().unwrap();
            let host = host_ref.downcast_mut::<WsvHost>().unwrap();
            host.handle_submit_ballot(&submit_bad)
        };
        assert!(matches!(res_bad, Err(VMError::PermissionDenied)));
        {
            let host_ref = vm.host_mut_any().unwrap();
            let host = host_ref.downcast_ref::<WsvHost>().unwrap();
            let election = host.wsv.elections.get("gov1").unwrap();
            assert_eq!(election.ciphertexts.len(), 1);
        }
    }
    #[test]
    fn malformed_verify_tally_keeps_latch_off_and_finalize_rejected() {
        let mut wsv = MockWorldStateView::new();
        register_vote_vk(&mut wsv);
        assert!(wsv.create_election("e2".to_string(), 3, [0u8; 32], 0, u64::MAX));
        let caller: AccountId = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "domain",
        );
        let host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(0);
        vm.set_host(host);
        // Malformed tally verify
        let empty_env: Vec<u8> = Vec::new();
        let mut env_tlv = Vec::with_capacity(7 + empty_env.len() + 32);
        env_tlv.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
        env_tlv.push(1);
        env_tlv.extend_from_slice(&(empty_env.len() as u32).to_be_bytes());
        env_tlv.extend_from_slice(&empty_env);
        let h: [u8; 32] = iroha_crypto::Hash::new(&empty_env).into();
        env_tlv.extend_from_slice(&h);
        vm.memory.preload_input(0, &env_tlv).expect("preload input");
        vm.set_register(10, Memory::INPUT_START);
        let _ = unsafe {
            let host_ptr = vm
                .host_mut_any()
                .unwrap()
                .downcast_mut::<WsvHost>()
                .unwrap() as *mut WsvHost;
            (*host_ptr)
                .syscall(syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY, &mut vm)
                .unwrap_or(0)
        };
        // Finalize should be rejected
        let fe = iroha_data_model::isi::zk::FinalizeElection {
            election_id: "e2".to_string(),
            tally: vec![5, 2, 1],
            tally_proof: iroha_data_model::proof::ProofAttachment::new_ref(
                "mock/governance-fixture".into(),
                iroha_data_model::proof::ProofBox::new(
                    "mock/governance-fixture".into(),
                    vec![0x03],
                ),
                vote_vk_id(),
            ),
        };
        let res = {
            let host = vm
                .host_mut_any()
                .expect("host")
                .downcast_mut::<WsvHost>()
                .expect("WsvHost");
            host.handle_finalize_election(&fe)
        };
        assert!(matches!(res, Err(VMError::PermissionDenied)));
    }
}
#[cfg(test)]
mod tests_zk_asset_bindings {
    use super::*;
    #[test]
    fn register_asset_definition_does_not_require_domain_row_for_opaque_id() {
        let caller: AccountId = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "domain",
        );
        let asset: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonder", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let opaque = norito::decode_from_bytes::<AssetDefinitionId>(
            &norito::to_bytes(&asset).expect("encode asset definition"),
        )
        .expect("decode opaque canonical asset definition");
        let mut wsv = MockWorldStateView::new();
        wsv.add_account_unchecked(caller.clone());
        wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
        assert!(
            wsv.register_asset_definition(&caller, opaque.clone(), Mintable::Infinitely),
            "opaque asset definition ids should register without a matching domain row"
        );
        assert!(
            wsv.asset_definitions.contains_key(&opaque),
            "registered opaque asset definition should be stored"
        );
    }
    #[test]
    fn unregister_domain_ignores_opaque_asset_definition_ids() {
        let caller: AccountId = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "domain",
        );
        let domain: DomainId = DomainId::try_new("wonder", "universal").unwrap();
        let projected = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            domain.clone(),
            "rose".parse().unwrap(),
        );
        let opaque = norito::decode_from_bytes::<AssetDefinitionId>(
            &norito::to_bytes(&projected).expect("encode asset definition"),
        )
        .expect("decode opaque canonical asset definition");
        let mut wsv = MockWorldStateView::new();
        wsv.add_account_unchecked(caller.clone());
        wsv.grant_permission(&caller, PermissionToken::RegisterDomain);
        wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
        assert!(wsv.register_domain(&caller, domain.clone()));
        assert!(wsv.register_asset_definition(&caller, opaque, Mintable::Infinitely));
        assert!(
            wsv.unregister_domain(&domain),
            "opaque asset definitions must not pin a domain because they have no domain projection"
        );
    }
}
#[cfg(test)]
mod tests_nft_decode {
    use super::*;

    #[test]
    fn decode_nft_payload_accepts_norito_encoded_bytes() {
        let nft_id: NftId = "n0$wonderland.universal".parse().unwrap();
        let payload = norito::to_bytes(&nft_id).expect("encode nft id");
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let decoded = host.decode_nft_payload(&payload).expect("decode ok");
        assert_eq!(decoded, nft_id);
    }
}
#[cfg(test)]
mod tests_null_decode {
    use super::*;
    use iroha_model_base::name::Name;
    use iroha_primitives::json::Json;

    fn load_int_state_map_schema(vm: &mut IVM, name: &str) {
        let interface = crate::metadata::EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            callables: vec![ivm_abi::call::EmbeddedCallableV1 {
                entry_pc: 0,
                frame_bytes: 0,
                arguments: ivm_abi::call::CallSchemaV1::empty(),
                results: ivm_abi::call::CallSchemaV1::unit(),
            }],
            seiyaku_name: "MockWsvStateMapFixture".to_owned(),
            compiler_fingerprint: "ivm-mock-wsv-tests".to_owned(),
            abi_hash: crate::syscalls::compute_abi_hash(crate::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![crate::metadata::EmbeddedEntrypointDescriptor {
                name: "inspect".to_owned(),
                kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(ivm_abi::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization:
                    iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            states: vec![crate::metadata::EmbeddedStateDescriptor {
                name: name.to_owned(),
                ty: crate::metadata::EmbeddedStateType::StateMap {
                    key: Box::new(crate::metadata::EmbeddedStateType::Int),
                    value: Box::new(crate::metadata::EmbeddedStateType::Bytes),
                },
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
        };
        let mut artifact = crate::metadata::ProgramMetadata::default().encode();
        artifact.extend_from_slice(&interface.encode_section());
        for word in [
            crate::encoding::wide::encode_store(
                crate::instruction::wide::memory::STORE64,
                12,
                0,
                0,
            ),
            crate::encoding::wide::encode_ri(crate::instruction::wide::arithmetic::ADDI, 10, 12, 0),
            crate::encoding::wide::encode_ri(crate::instruction::wide::arithmetic::ADDI, 11, 0, 1),
            crate::encoding::wide::encode_rr(crate::instruction::wide::control::JALR, 0, 1, 0),
        ] {
            artifact.extend_from_slice(&word.to_le_bytes());
        }
        vm.load_program(&artifact)
            .expect("load mock WSV map schema");
    }
    fn make_tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
        out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
        out.push(1);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
        out.extend_from_slice(&h);
        out
    }
    fn call_syscall(vm: &mut IVM, number: u32) -> Result<u64, VMError> {
        unsafe {
            let host_ptr = vm
                .host_mut_any()
                .unwrap()
                .downcast_mut::<WsvHost>()
                .unwrap() as *mut WsvHost;
            (*host_ptr).syscall(number, vm)
        }
    }
    fn quote_syscall(vm: &mut IVM, number: u32) -> Result<u64, VMError> {
        unsafe {
            let host_ptr = vm
                .host_mut_any()
                .unwrap()
                .downcast_mut::<WsvHost>()
                .unwrap() as *mut WsvHost;
            (*host_ptr).prepare_syscall(number, vm)
        }
    }
    fn call_syscall_with_quote(vm: &mut IVM, number: u32) -> Result<u64, VMError> {
        let quote = quote_syscall(vm, number)?;
        let actual = call_syscall(vm, number)?;
        assert!(
            actual <= quote,
            "syscall {number:#x} exceeded bounded quote {quote} with {actual}"
        );
        Ok(actual)
    }
    #[test]
    fn decode_syscalls_accept_null_pointers() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let cases = [
            syscalls::SYSCALL_JSON_DECODE,
            syscalls::SYSCALL_NAME_DECODE,
            syscalls::SYSCALL_POINTER_FROM_NORITO,
            syscalls::SYSCALL_INPUT_PUBLISH_TLV,
        ];
        for &number in &cases {
            vm.set_register(10, 0);
            vm.set_register(11, 0);
            call_syscall(&mut vm, number).expect("syscall should accept null");
            assert_eq!(vm.register(10), 0);
        }
        for kind in [
            PointerType::Int,
            PointerType::Decimal,
            PointerType::Quantity,
        ] {
            vm.set_register(10, 0);
            vm.set_register(11, u64::from(kind as u16));
            assert_eq!(
                call_syscall(&mut vm, syscalls::SYSCALL_POINTER_FROM_NORITO),
                Err(VMError::NoritoInvalid),
                "numeric {kind:?} cannot decode from null"
            );
            assert_eq!(vm.register(10), 0);
        }
    }
    #[test]
    fn contract_context_byte_outputs_have_exact_gas_quotes_and_canonical_address_bytes() {
        let caller = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "fixture",
        );
        let address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .unwrap(),
            &caller,
            812,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        host.contract_runtime_address = Some(address.clone());
        host.contract_runtime_entrypoint = Some("digest_for".into());
        for (number, expected) in [
            (
                syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS,
                address.as_str().as_bytes(),
            ),
            (
                syscalls::SYSCALL_SYSVAR_ENTRYPOINT,
                b"digest_for".as_slice(),
            ),
        ] {
            let mut vm = IVM::new(1_000_000);
            let quote = host.prepare_syscall(number, &vm).unwrap();
            let used = host.syscall(number, &mut vm).unwrap();
            assert_eq!(quote, used);
            assert_eq!(used, WsvHost::sysvar_gas(expected.len()));
            let output = vm.validate_tlv(vm.register(10)).unwrap();
            assert_eq!(output.type_id, PointerType::Blob);
            assert_eq!(output.payload, expected);
        }
        host.contract_runtime_address = None;
        host.contract_runtime_entrypoint = None;
        for number in [
            syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS,
            syscalls::SYSCALL_SYSVAR_ENTRYPOINT,
        ] {
            let mut vm = IVM::new(1_000_000);
            assert_eq!(
                host.prepare_syscall(number, &vm).unwrap(),
                WsvHost::sysvar_gas(0)
            );
            assert_eq!(
                host.syscall(number, &mut vm).unwrap(),
                WsvHost::sysvar_gas(0)
            );
            assert_eq!(vm.register(10), 0);
        }
    }
    #[test]
    fn current_time_syscall_returns_host_time() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        host.set_current_time_ms(1_717_171_717_000);
        let mut vm = IVM::new(u64::MAX);
        let quote = IVMHost::prepare_syscall(&host, syscalls::SYSCALL_CURRENT_TIME_MS, &vm)
            .expect("quote current time");
        assert_eq!(
            IVMHost::syscall(&mut host, syscalls::SYSCALL_CURRENT_TIME_MS, &mut vm),
            Ok(WsvHost::sysvar_gas(0))
        );
        assert!(WsvHost::sysvar_gas(0) <= quote);
        assert_eq!(vm.register(10), 1_717_171_717_000);
    }
    #[test]
    fn debug_log_syscall_accepts_current_kotodama_payloads_and_charges_bytes() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(u64::MAX);
        let payload = b"first-release-contract-event";
        let pointer = vm
            .alloc_input_tlv(&make_tlv(PointerType::Blob, payload))
            .expect("allocate debug log payload");
        vm.set_register(10, pointer);
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_DEBUG_LOG, &vm)
            .expect("quote debug log");
        let actual = host
            .syscall(syscalls::SYSCALL_DEBUG_LOG, &mut vm)
            .expect("execute debug log");
        assert_eq!(actual, crate::host::debug_log_gas(payload.len()));
        assert_eq!(actual, quote);
    }
    #[test]
    fn authority_response_quote_covers_actual_and_fits_default_budget() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(1_000_000);
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_GET_AUTHORITY, &vm)
            .expect("quote authority response");
        let actual = host
            .syscall(syscalls::SYSCALL_GET_AUTHORITY, &mut vm)
            .expect("return authority");
        assert!(actual <= quote);
        assert!(quote <= 1_000_000);
    }
    #[test]
    fn add_signatory_syscall_accepts_account_id_payloads() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut wsv = MockWorldStateView::new();
        wsv.add_account_unchecked(caller.clone());
        let host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let opaque_payload = norito::to_bytes(&caller).expect("encode account id");
        let account_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::AccountId, &opaque_payload))
            .expect("alloc account tlv");
        let signatory = Json::from_str_norito(
            "\"ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774\"",
        )
        .expect("json signatory");
        let signatory_bytes = norito::to_bytes(&signatory).expect("encode signatory json");
        let signatory_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &signatory_bytes))
            .expect("alloc signatory tlv");
        vm.set_register(10, account_ptr);
        vm.set_register(11, signatory_ptr);
        call_syscall(&mut vm, syscalls::SYSCALL_ADD_SIGNATORY).expect("account payload accepted");
    }
    #[test]
    fn add_signatory_syscall_rejects_malformed_account_payloads() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut wsv = MockWorldStateView::new();
        wsv.add_account_unchecked(caller.clone());
        let host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let account_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::AccountId, b"not-an-account-id"))
            .expect("alloc account tlv");
        let signatory = Json::from_str_norito(
            "\"ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774\"",
        )
        .expect("json signatory");
        let signatory_bytes = norito::to_bytes(&signatory).expect("encode signatory json");
        let signatory_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &signatory_bytes))
            .expect("alloc signatory tlv");
        vm.set_register(10, account_ptr);
        vm.set_register(11, signatory_ptr);
        let err = call_syscall(&mut vm, syscalls::SYSCALL_ADD_SIGNATORY)
            .expect_err("malformed account payload should be rejected");
        assert!(matches!(err, VMError::DecodeError));
    }
    #[test]
    fn get_account_balance_syscall_accepts_account_id_payloads() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "rose".parse().expect("asset name"),
        );
        let wsv = MockWorldStateView::with_balances(&[(
            (caller.clone(), asset.clone()),
            Quantity::from(41_u64),
        )]);
        let host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let account_bytes = norito::to_bytes(&caller).expect("encode account subject");
        let account_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::AccountId, &account_bytes))
            .expect("alloc account tlv");
        let asset_bytes = norito::to_bytes(&asset).expect("encode asset definition id");
        let asset_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::AssetDefinitionId, &asset_bytes))
            .expect("alloc asset tlv");
        vm.set_register(10, account_ptr);
        vm.set_register(11, asset_ptr);
        let quote = quote_syscall(&mut vm, syscalls::SYSCALL_GET_ACCOUNT_BALANCE)
            .expect("quote balance syscall");
        let gas =
            call_syscall(&mut vm, syscalls::SYSCALL_GET_ACCOUNT_BALANCE).expect("balance syscall");
        let out = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("balance tlv");
        assert_eq!(out.type_id, PointerType::Quantity);
        let decoded = QuantityValueV1::decode_frame(out.payload)
            .expect("decode quantity frame")
            .into_quantity();
        assert_eq!(decoded, Quantity::from(41_u64));
        let canonical =
            ivm_abi::numeric_tlv::encode_quantity(&decoded).expect("canonical quantity envelope");
        assert_eq!(
            vm.memory
                .load_region(vm.register(10), u64::try_from(canonical.len()).unwrap())
                .expect("complete balance envelope"),
            canonical,
            "the mock and production quantity pointer codecs must be byte-identical"
        );
        assert_eq!(gas, WsvHost::singular_query_gas(out.payload.len()));
        assert!(gas <= quote);
        assert!(quote <= 1_000_000);
    }
    #[test]
    fn get_account_balance_result_spills_to_owned_heap() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "rose".parse().expect("asset name"),
        );
        let wsv = MockWorldStateView::with_balances(&[(
            (caller.clone(), asset.clone()),
            Quantity::from(41_u64),
        )]);
        let host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        vm.alloc_input_tlv(&vec![0; Memory::INPUT_SIZE as usize])
            .expect("fill INPUT exactly");
        let account_bytes = norito::to_bytes(&caller).expect("encode account subject");
        let account_pointer = vm
            .alloc_host_tlv(&make_tlv(PointerType::AccountId, &account_bytes))
            .expect("spill account argument to HEAP");
        let asset_bytes = norito::to_bytes(&asset).expect("encode asset definition id");
        let asset_pointer = vm
            .alloc_host_tlv(&make_tlv(PointerType::AssetDefinitionId, &asset_bytes))
            .expect("spill asset argument to HEAP");
        vm.set_register(10, account_pointer);
        vm.set_register(11, asset_pointer);
        call_syscall(&mut vm, syscalls::SYSCALL_GET_ACCOUNT_BALANCE)
            .expect("materialize balance after INPUT exhaustion");
        let output_pointer = vm.register(10);
        assert!((Memory::HEAP_START..Memory::INPUT_START).contains(&output_pointer));
        let output = vm
            .validate_tlv(output_pointer)
            .expect("validate HEAP balance result");
        assert_eq!(output.type_id, PointerType::Quantity);
        assert_eq!(
            QuantityValueV1::decode_frame(output.payload)
                .expect("decode quantity frame")
                .into_quantity(),
            Quantity::from(41_u64)
        );
    }
    #[test]
    fn zk_verify_status_paths_charge_payload_bytes() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let malformed = [0xff, 0x00, 0x01, 0x02];
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &malformed))
            .expect("alloc malformed envelope");
        vm.set_register(10, ptr);
        let gas =
            call_syscall(&mut vm, syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT).expect("zk verify");
        assert_eq!(gas, WsvHost::verify_gas(malformed.len()));
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), crate::host::ERR_DECODE);
    }
    #[test]
    fn canonical_proof_envelopes_never_set_mock_verification_latches() {
        use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
        let caller = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        for backend in BackendTag::ALL {
            for syscall in [
                syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT,
                syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY,
            ] {
                let envelope = OpenVerifyEnvelope::new(
                    backend,
                    "mock-unadmitted-relation",
                    [1; 32],
                    vec![2; 32],
                    vec![3; 32],
                );
                let payload = encode_canonical_norito(&envelope).expect("envelope");
                let ptr = vm
                    .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &payload))
                    .expect("allocate proof");
                vm.set_register(10, ptr);
                call_syscall(&mut vm, syscall).expect("bounded rejection");
                assert_eq!(vm.register(10), 0);
                assert_eq!(vm.register(11), crate::host::ERR_BACKEND);
                let host = vm
                    .host_mut_any()
                    .expect("host")
                    .downcast_ref::<WsvHost>()
                    .expect("mock host");
                assert!(host.zk_verified_ballot.is_empty());
                assert!(host.zk_verified_tally.is_none());
            }
        }
    }
    #[test]
    fn zk_read_helpers_charge_request_and_response_bytes() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let asset_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "rose".parse().expect("asset name"),
        );
        let roots_req = crate::zk_verify::RootsGetRequest {
            asset_id: asset_id.to_string(),
            max: 4,
        };
        let roots_payload = norito::to_bytes(&roots_req).expect("encode roots request");
        let roots_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &roots_payload))
            .expect("alloc roots request");
        vm.set_register(10, roots_ptr);
        let roots_quote =
            quote_syscall(&mut vm, syscalls::SYSCALL_ZK_ROOTS_GET).expect("quote roots get");
        let roots_gas = call_syscall(&mut vm, syscalls::SYSCALL_ZK_ROOTS_GET).expect("roots get");
        let roots_out = vm.validate_tlv(vm.register(10)).expect("roots tlv");
        assert_eq!(
            roots_gas,
            WsvHost::state_query_gas(roots_payload.len().saturating_add(roots_out.payload.len()))
        );
        assert!(roots_gas <= roots_quote);
        let tally_req = crate::zk_verify::VoteGetTallyRequest {
            election_id: "election".to_string(),
        };
        let tally_payload = norito::to_bytes(&tally_req).expect("encode tally request");
        let tally_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &tally_payload))
            .expect("alloc tally request");
        vm.set_register(10, tally_ptr);
        let tally_quote =
            quote_syscall(&mut vm, syscalls::SYSCALL_ZK_VOTE_GET_TALLY).expect("quote vote tally");
        let tally_gas =
            call_syscall(&mut vm, syscalls::SYSCALL_ZK_VOTE_GET_TALLY).expect("vote tally");
        let tally_out = vm.validate_tlv(vm.register(10)).expect("tally tlv");
        assert_eq!(
            tally_gas,
            WsvHost::state_query_gas(tally_payload.len().saturating_add(tally_out.payload.len()))
        );
        assert!(tally_gas <= tally_quote);
    }
    #[test]
    fn vote_tally_query_rejects_invalid_shape_or_total_and_returns_exact_max() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut overflowing = vec![0_u128; DMZk::MAX_ELECTION_OPTIONS_V1 as usize];
        overflowing[0] = u128::MAX;
        overflowing[1] = 1;
        for corrupt_tally in [
            Vec::new(),
            vec![0; DMZk::MAX_ELECTION_OPTIONS_V1 as usize + 1],
            overflowing,
        ] {
            let mut wsv = MockWorldStateView::new();
            assert!(wsv.create_election(
                "corrupt".to_owned(),
                DMZk::MAX_ELECTION_OPTIONS_V1,
                [0; 32],
                0,
                u64::MAX
            ));
            wsv.elections.get_mut("corrupt").expect("election").tally = corrupt_tally;
            let host = WsvHost::new_with_subject(wsv, caller.clone());
            let mut vm = IVM::new(u64::MAX);
            vm.set_host(host);
            let request = crate::zk_verify::VoteGetTallyRequest {
                election_id: "corrupt".to_owned(),
            };
            let payload = encode_canonical_norito(&request).expect("encode tally request");
            let request_ptr = vm
                .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &payload))
                .expect("allocate tally request");
            vm.set_register(10, request_ptr);
            assert_eq!(
                call_syscall(&mut vm, syscalls::SYSCALL_ZK_VOTE_GET_TALLY),
                Err(VMError::NoritoInvalid),
                "invalid stored tally must fail closed"
            );
            assert_eq!(
                vm.register(10),
                request_ptr,
                "failed query must not publish a response"
            );
        }
        let mut wsv = MockWorldStateView::new();
        assert!(wsv.create_election(
            "max".to_owned(),
            DMZk::MAX_ELECTION_OPTIONS_V1,
            [0; 32],
            0,
            u64::MAX
        ));
        let mut expected: Vec<u128> = (0..DMZk::MAX_ELECTION_OPTIONS_V1).map(u128::from).collect();
        expected[0] = u128::from(u64::MAX) + 1;
        let election = wsv.elections.get_mut("max").expect("election");
        election.tally.clone_from(&expected);
        election.finalized = true;
        let host = WsvHost::new_with_subject(wsv, caller);
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let request = crate::zk_verify::VoteGetTallyRequest {
            election_id: "max".to_owned(),
        };
        let payload = encode_canonical_norito(&request).expect("encode tally request");
        let request_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &payload))
            .expect("allocate tally request");
        vm.set_register(10, request_ptr);
        call_syscall(&mut vm, syscalls::SYSCALL_ZK_VOTE_GET_TALLY)
            .expect("valid max-size tally response");
        let output = vm
            .validate_tlv(vm.register(10))
            .expect("tally response TLV");
        assert_eq!(output.type_id, PointerType::NoritoBytes);
        let response: crate::zk_verify::VoteGetTallyResponse =
            decode_canonical_norito(output.payload).expect("canonical tally response");
        assert!(response.finalized);
        assert_eq!(response.tally, expected);
        assert_eq!(response.tally.len(), DMZk::MAX_ELECTION_OPTIONS_V1 as usize);
    }
    #[test]
    fn vote_tally_query_rejects_noncanonical_selector_without_response() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let request = crate::zk_verify::VoteGetTallyRequest {
            election_id: "election/alias".to_owned(),
        };
        let payload = encode_canonical_norito(&request).expect("encode tally request");
        let request_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &payload))
            .expect("allocate tally request");
        vm.set_register(10, request_ptr);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_ZK_VOTE_GET_TALLY),
            Err(VMError::NoritoInvalid)
        );
        assert_eq!(
            vm.register(10),
            request_ptr,
            "failed tally queries must not publish a response pointer"
        );
    }
    #[test]
    fn input_publish_tlv_rejects_oversized_envelope() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone())
            .with_zk_verify_limits(crate::host::ZkVerifyLimits {
                max_envelope_bytes: 64,
                ..Default::default()
            });
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let payload = vec![b'x'; 128];
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &payload))
            .expect("alloc oversized json tlv");
        vm.set_register(10, ptr);
        let err = call_syscall(&mut vm, syscalls::SYSCALL_INPUT_PUBLISH_TLV)
            .expect_err("oversized tlv should be rejected");
        assert!(matches!(err, VMError::PermissionDenied));
    }
    #[test]
    fn input_publish_tlv_charges_envelope_bytes() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let tlv = make_tlv(PointerType::Json, b"{}");
        let ptr = vm.alloc_input_tlv(&tlv).expect("alloc json tlv");
        vm.set_register(10, ptr);
        let gas =
            call_syscall(&mut vm, syscalls::SYSCALL_INPUT_PUBLISH_TLV).expect("input publish");
        assert_eq!(gas, WsvHost::input_publish_gas(tlv.len()));
    }
    #[test]
    fn direct_mutation_syscalls_charge_declared_gas() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut wsv = MockWorldStateView::new();
        wsv.add_account_unchecked(caller.clone());
        let host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let account_payload = norito::to_bytes(&caller).expect("encode account id");
        let account_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::AccountId, &account_payload))
            .expect("alloc account tlv");
        let key: Name = "tier".parse().expect("name");
        let key_payload = norito::to_bytes(&key).expect("encode name");
        let key_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &key_payload))
            .expect("alloc name tlv");
        let detail = Json::from_str_norito("{\"level\":3}").expect("json detail");
        let detail_payload = norito::to_bytes(&detail).expect("encode detail json");
        let detail_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &detail_payload))
            .expect("alloc detail tlv");
        vm.set_register(10, account_ptr);
        vm.set_register(11, key_ptr);
        vm.set_register(12, detail_ptr);
        let gas = call_syscall(&mut vm, syscalls::SYSCALL_SET_ACCOUNT_DETAIL)
            .expect("set account detail");
        assert_eq!(gas, WsvHost::mutation_gas(detail_payload.len()));
    }
    #[test]
    fn direct_admin_syscalls_require_management_permissions() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut wsv = MockWorldStateView::new();
        wsv.add_account_unchecked(caller.clone());
        let mut host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(u64::MAX);
        let role: Name = "operator".parse().expect("role name");
        let role_payload = norito::to_bytes(&role).expect("encode role name");
        let role_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &role_payload))
            .expect("alloc role name");
        let perms = Json::from_str_norito("{\"permissions\":[\"manage_roles\"]}")
            .expect("role permissions json");
        let perms_payload = norito::to_bytes(&perms).expect("encode permissions json");
        let perms_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &perms_payload))
            .expect("alloc permissions");
        vm.set_register(10, role_ptr);
        vm.set_register(11, perms_ptr);
        let err = host
            .syscall(syscalls::SYSCALL_CREATE_ROLE, &mut vm)
            .expect_err("create_role must require ManageRoles");
        assert!(matches!(err, VMError::PermissionDenied));
        assert!(!host.wsv.roles.contains_key("operator"));
        let account_payload = norito::to_bytes(&caller).expect("encode account id");
        let account_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::AccountId, &account_payload))
            .expect("alloc account");
        let permission: Name = "BenefitSpend".parse().expect("permission name");
        let permission_payload = norito::to_bytes(&permission).expect("encode permission name");
        let permission_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &permission_payload))
            .expect("alloc permission");
        vm.set_register(10, account_ptr);
        vm.set_register(11, permission_ptr);
        let err = host
            .syscall(syscalls::SYSCALL_GRANT_PERMISSION, &mut vm)
            .expect_err("grant_permission must require ManagePermissions");
        assert!(matches!(err, VMError::PermissionDenied));
        assert!(!host.wsv.has_permission(
            &caller,
            &PermissionToken::Custom("BenefitSpend".to_string())
        ));
    }
    #[test]
    fn direct_admin_syscalls_succeed_with_management_permissions() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut wsv = MockWorldStateView::new();
        wsv.add_account_unchecked(caller.clone());
        wsv.grant_permission(&caller, PermissionToken::ManageRoles);
        wsv.grant_permission(&caller, PermissionToken::ManagePermissions);
        let mut host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(u64::MAX);
        let role: Name = "operator".parse().expect("role name");
        let role_payload = norito::to_bytes(&role).expect("encode role name");
        let role_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &role_payload))
            .expect("alloc role name");
        let perms = Json::from_str_norito("{\"permissions\":[\"manage_permissions\"]}")
            .expect("role permissions json");
        let perms_payload = norito::to_bytes(&perms).expect("encode permissions json");
        let perms_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &perms_payload))
            .expect("alloc permissions");
        vm.set_register(10, role_ptr);
        vm.set_register(11, perms_ptr);
        host.syscall(syscalls::SYSCALL_CREATE_ROLE, &mut vm)
            .expect("create_role should accept ManageRoles caller");
        assert!(host.wsv.roles.contains_key("operator"));
        let account_payload = norito::to_bytes(&caller).expect("encode account id");
        let account_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::AccountId, &account_payload))
            .expect("alloc account");
        let permission: Name = "BenefitSpend".parse().expect("permission name");
        let permission_payload = norito::to_bytes(&permission).expect("encode permission name");
        let permission_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &permission_payload))
            .expect("alloc permission");
        vm.set_register(10, account_ptr);
        vm.set_register(11, permission_ptr);
        host.syscall(syscalls::SYSCALL_GRANT_PERMISSION, &mut vm)
            .expect("grant_permission should accept ManagePermissions caller");
        assert!(host.wsv.has_permission(
            &caller,
            &PermissionToken::Custom("BenefitSpend".to_string())
        ));
    }
    #[test]
    fn smartcontract_query_accepts_only_canonical_query_request() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let request =
            QueryRequest::Singular(iroha_data_model::query::SingularQueryBox::FindParameters(
                iroha_data_model::query::executor::FindParameters,
            ));
        let canonical_payload =
            encode_canonical_norito(&request).expect("encode canonical QueryRequest");
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &canonical_payload))
            .expect("alloc canonical query");
        vm.set_register(10, ptr);
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let ambient_guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_probe = vec!["ambient".to_owned(), "layout".to_owned()];
        let ambient_before = norito::to_bytes(&ambient_probe).expect("encode ambient probe");
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY),
            Err(VMError::NotImplemented {
                syscall: syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY,
            })
        );
        assert_eq!(
            norito::to_bytes(&ambient_probe).expect("re-encode ambient probe"),
            ambient_before,
            "canonical query decoding must restore ambient Norito flags"
        );
        drop(ambient_guard);
        let alternate_payload = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&request).expect("encode alternate-layout QueryRequest")
        };
        assert_ne!(alternate_payload, canonical_payload);
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &alternate_payload))
            .expect("alloc alternate-layout query");
        vm.set_register(10, ptr);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY),
            Err(VMError::NoritoInvalid)
        );
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &canonical_payload))
            .expect("alloc wrong pointer type");
        vm.set_register(10, ptr);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY),
            Err(VMError::NoritoInvalid)
        );
        let wrong_payload = encode_canonical_norito(&Json::from(norito::json::Value::Object(
            norito::json::Map::new(),
        )))
        .expect("encode wrong nominal type");
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &wrong_payload))
            .expect("alloc wrong nominal payload");
        vm.set_register(10, ptr);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY),
            Err(VMError::NoritoInvalid)
        );
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &[0xFF]))
            .expect("alloc malformed query");
        vm.set_register(10, ptr);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY),
            Err(VMError::NoritoInvalid)
        );
    }
    #[test]
    fn smartcontract_instruction_rejects_record_sccp_message_under_every_tag() {
        // specs/sccp.md §4.4: contracts record no SCCP messages. ABI v1 defines only tag
        // `1=SubmitBallot`, so the canonical encoded record fails under it, under the retired
        // tag 2 and under every other tag, without touching the mock world.
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(WsvHost::new_with_subject(MockWorldStateView::new(), caller));
        let record = iroha_data_model::isi::sccp::RecordSccpMessage {
            network: iroha_data_model::bridge::SccpNetworkV1::EthereumMainnet,
            expected_revision: 1,
            amount: Numeric::new(2_u32, 0),
            recipient: vec![0x22; 20],
        };
        let payload = encode_canonical_norito(&DMInstructionBox::from(record))
            .expect("encode canonical RecordSccpMessage");
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &payload))
            .expect("alloc canonical RecordSccpMessage");
        vm.set_register(10, ptr);
        for tag in [
            0,
            syscalls::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT,
            2,
            u64::MAX,
        ] {
            vm.set_register(11, tag);
            assert_eq!(
                call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION),
                Err(VMError::PermissionDenied),
                "tag {tag} must not execute RecordSccpMessage"
            );
        }
        let host = vm
            .host_mut_any()
            .expect("host")
            .downcast_ref::<WsvHost>()
            .expect("WsvHost");
        assert!(host.wsv.zk_events.is_empty() && host.wsv.elections.is_empty());
        assert!(host.state_overlay.is_empty() && host.fastpq_batch_entries.is_none());
    }
    #[test]
    fn smartcontract_instruction_accepts_only_canonical_instruction_box() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let vote_vk = VerifyingKeyId::new("mock/governance-fixture", "canonical-box-ballot");
        let mut wsv = MockWorldStateView::new();
        wsv.insert_verifying_key(vote_vk.clone(), vec![0x02]);
        assert!(wsv.create_election("canonical-box".to_owned(), 2, [0x42; 32], 0, u64::MAX));
        let mut host = WsvHost::new_with_subject(wsv, caller.clone());
        host.__test_push_verified_ballot([0xAB; 32]);
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let instruction = DMZk::SubmitBallot {
            election_id: "canonical-box".to_owned(),
            ciphertext: vec![0xCA, 0xFE],
            ballot_proof: ProofAttachment::new_ref(
                "mock/governance-fixture".into(),
                iroha_data_model::proof::ProofBox::new(
                    "mock/governance-fixture".into(),
                    vec![0x01],
                ),
                vote_vk,
            ),
            nullifier: [0x11; 32],
        };
        let boxed_payload = encode_canonical_norito(&DMInstructionBox::from(instruction.clone()))
            .expect("encode canonical InstructionBox");
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &boxed_payload))
            .expect("alloc canonical instruction");
        vm.set_register(10, ptr);
        vm.set_register(11, syscalls::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT);
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let ambient_guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_probe = vec!["ambient".to_owned(), "layout".to_owned()];
        let ambient_before = norito::to_bytes(&ambient_probe).expect("encode ambient probe");
        let gas = call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION)
            .expect("execute canonical InstructionBox");
        assert_eq!(gas, WsvHost::mutation_gas(boxed_payload.len()));
        assert_eq!(
            norito::to_bytes(&ambient_probe).expect("re-encode ambient probe"),
            ambient_before,
            "canonical instruction decoding must restore ambient Norito flags"
        );
        assert_eq!(
            vm.host_mut_any()
                .expect("host")
                .downcast_ref::<WsvHost>()
                .expect("WsvHost")
                .wsv
                .elections
                .get("canonical-box")
                .expect("election")
                .ciphertexts
                .len(),
            1
        );
        drop(ambient_guard);
        let direct_payload =
            encode_canonical_norito(&instruction).expect("encode direct concrete instruction");
        assert_ne!(direct_payload, boxed_payload);
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &direct_payload))
            .expect("alloc direct instruction");
        vm.set_register(10, ptr);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION),
            Err(VMError::NoritoInvalid)
        );
        let alternate_payload = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&DMInstructionBox::from(instruction.clone()))
                .expect("encode alternate-layout InstructionBox")
        };
        assert_ne!(alternate_payload, boxed_payload);
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &alternate_payload))
            .expect("alloc alternate-layout instruction");
        vm.set_register(10, ptr);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION),
            Err(VMError::NoritoInvalid)
        );
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &boxed_payload))
            .expect("alloc wrong pointer type");
        vm.set_register(10, ptr);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION),
            Err(VMError::NoritoInvalid)
        );
        let wrong_payload = encode_canonical_norito(&Json::from(norito::json::Value::Object(
            norito::json::Map::new(),
        )))
        .expect("encode wrong nominal type");
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &wrong_payload))
            .expect("alloc wrong payload type");
        vm.set_register(10, ptr);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION),
            Err(VMError::NoritoInvalid)
        );
        let canonical_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &boxed_payload))
            .expect("alloc canonical instruction for tag checks");
        vm.set_register(10, canonical_ptr);
        // Tag 2 was the retired contract-originated SCCP send; it is an unknown tag now.
        for tag in [0, 2, 99] {
            vm.set_register(11, tag);
            assert_eq!(
                call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION),
                Err(VMError::PermissionDenied),
                "tag {tag} must not authorize SubmitBallot"
            );
        }
        let other = DMZk::CreateElection {
            election_id: "unsupported".to_owned(),
            options: 2,
            eligible_root: [0x42; 32],
            start_ts: 1,
            end_ts: 2,
            vk_ballot: VerifyingKeyId::new("mock/governance-fixture", "ballot"),
            vk_tally: VerifyingKeyId::new("mock/governance-fixture", "tally"),
            domain_tag: "unsupported".to_owned(),
        };
        let other_payload = encode_canonical_norito(&DMInstructionBox::from(other))
            .expect("encode unsupported InstructionBox");
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &other_payload))
            .expect("alloc unsupported instruction");
        vm.set_register(10, ptr);
        vm.set_register(11, syscalls::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT);
        assert_eq!(
            call_syscall(&mut vm, syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION),
            Err(VMError::PermissionDenied)
        );
        assert_eq!(
            vm.host_mut_any()
                .expect("host")
                .downcast_ref::<WsvHost>()
                .expect("WsvHost")
                .wsv
                .elections
                .get("canonical-box")
                .expect("election")
                .ciphertexts
                .len(),
            1,
            "rejected frames must not mutate the election"
        );
        assert!(
            !vm.host_mut_any()
                .expect("host")
                .downcast_ref::<WsvHost>()
                .expect("WsvHost")
                .wsv
                .elections
                .contains_key("unsupported")
        );
    }
    #[test]
    fn fastpq_transfer_batch_syscalls_charge_per_entry_gas() {
        let alice: AccountId = test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "wonderland",
        );
        let bob: AccountId = test_account_id(
            "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
            "wonderland",
        );
        let carol: AccountId = test_account_id(
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245",
            "wonderland",
        );
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "rose".parse().expect("asset name"),
        );
        let mut wsv = MockWorldStateView::with_balances(&[
            ((alice.clone(), asset.clone()), Quantity::from(100_u64)),
            ((bob.clone(), asset.clone()), Quantity::zero()),
            ((carol.clone(), asset.clone()), Quantity::zero()),
        ]);
        wsv.grant_permission(&bob, PermissionToken::TransferAsset(asset.clone()));
        let mut host = WsvHost::new_with_subject(wsv, bob.clone());
        let mut vm = IVM::new(u64::MAX);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN, &mut vm),
            Ok(gas::G_FASTPQ_BATCH)
        );
        let alice_ptr = vm
            .alloc_input_tlv(&make_tlv(
                PointerType::AccountId,
                &encode_canonical_norito(&alice).expect("encode source account"),
            ))
            .expect("allocate source account");
        let bob_ptr = vm
            .alloc_input_tlv(&make_tlv(
                PointerType::AccountId,
                &encode_canonical_norito(&bob).expect("encode destination account"),
            ))
            .expect("allocate destination account");
        let asset_ptr = vm
            .alloc_input_tlv(&make_tlv(
                PointerType::AssetDefinitionId,
                &encode_canonical_norito(&asset).expect("encode asset definition"),
            ))
            .expect("allocate asset definition");
        vm.set_register(10, alice_ptr);
        vm.set_register(11, bob_ptr);
        vm.set_register(12, asset_ptr);
        let amount_tlv = ivm_abi::numeric_tlv::encode_quantity(&Quantity::from(10_u64))
            .expect("encode quantity pointer envelope");
        let amount_ptr = vm.alloc_input_tlv(&amount_tlv).expect("alloc amount");
        vm.set_register(13, amount_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_TRANSFER_V1, &mut vm),
            Ok(WsvHost::mutation_gas(0))
        );
        assert_eq!(
            host.syscall(syscalls::SYSCALL_TRANSFER_V1_BATCH_END, &mut vm),
            Ok(gas::G_FASTPQ_BATCH)
        );
        let mut apply_wsv = MockWorldStateView::with_balances(&[
            ((alice.clone(), asset.clone()), Quantity::from(100_u64)),
            ((bob.clone(), asset.clone()), Quantity::zero()),
            ((carol.clone(), asset.clone()), Quantity::zero()),
        ]);
        apply_wsv.grant_permission(&bob, PermissionToken::TransferAsset(asset.clone()));
        let mut apply_host = WsvHost::new_with_subject(apply_wsv, bob.clone());
        let mut apply_vm = IVM::new(u64::MAX);
        let batch = TransferAssetBatch::new(vec![
            iroha_data_model::isi::transfer::TransferAssetBatchEntry::new(
                alice.clone(),
                bob,
                asset.clone(),
                10_u64,
            ),
            iroha_data_model::isi::transfer::TransferAssetBatchEntry::new(
                alice, carol, asset, 5_u64,
            ),
        ]);
        let batch_payload = norito::to_bytes(&batch).expect("encode transfer batch");
        let batch_ptr = apply_vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &batch_payload))
            .expect("alloc transfer batch");
        apply_vm.set_register(10, batch_ptr);
        assert_eq!(
            apply_host.syscall(syscalls::SYSCALL_TRANSFER_V1_BATCH_APPLY, &mut apply_vm),
            Ok(WsvHost::mutation_batch_gas(2))
        );
    }
    #[test]
    fn scoped_transfer_requires_the_exact_contract_subject_source_bucket() {
        fn invoke(
            grant_to_app: bool,
            grant_source_matches: bool,
            grant_dataspace: u64,
            requested_dataspace: u64,
        ) -> Result<u64, VMError> {
            let source = test_account_id(
                "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
                "source",
            );
            let destination = test_account_id(
                "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
                "destination",
            );
            let contract_subject = test_account_id(
                "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245",
                "contract",
            );
            let app = test_account_id(
                "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
                "app",
            );
            let asset = AssetDefinitionId::derive_from_components(
                DomainId::try_new("currency", "sbp").expect("asset domain"),
                "pkr".parse().expect("asset name"),
            );
            let mut wsv = MockWorldStateView::with_balances(&[
                ((source.clone(), asset.clone()), Quantity::from(100_u64)),
                ((destination.clone(), asset.clone()), Quantity::zero()),
            ]);
            wsv.add_account_unchecked(contract_subject.clone());
            wsv.add_account_unchecked(app.clone());
            let granted_source = if grant_source_matches {
                source.clone()
            } else {
                destination.clone()
            };
            let permission = PermissionToken::TransferAssetBucket(AssetId::with_scope(
                asset.clone(),
                granted_source,
                AssetBalanceScope::Dataspace(DataSpaceId::new(grant_dataspace)),
            ));
            wsv.grant_permission(
                if grant_to_app {
                    &app
                } else {
                    &contract_subject
                },
                permission,
            );
            let host = WsvHost::new_with_subject(wsv, contract_subject);
            let mut vm = IVM::new(u64::MAX);
            vm.set_host(host);
            let source_ptr = vm
                .alloc_input_tlv(&make_tlv(
                    PointerType::AccountId,
                    &encode_canonical_norito(&source).expect("encode source account"),
                ))
                .expect("allocate source account");
            let destination_ptr = vm
                .alloc_input_tlv(&make_tlv(
                    PointerType::AccountId,
                    &encode_canonical_norito(&destination).expect("encode destination account"),
                ))
                .expect("allocate destination account");
            let asset_ptr = vm
                .alloc_input_tlv(&make_tlv(
                    PointerType::AssetDefinitionId,
                    &encode_canonical_norito(&asset).expect("encode asset definition"),
                ))
                .expect("allocate asset definition");
            vm.set_register(10, source_ptr);
            vm.set_register(11, destination_ptr);
            vm.set_register(12, asset_ptr);
            let quantity = QuantityValueV1::new(Quantity::from(10_u64))
                .encode_frame()
                .expect("encode quantity");
            let quantity_ptr = vm
                .alloc_input_tlv(&make_tlv(PointerType::Quantity, &quantity))
                .expect("allocate quantity");
            let dataspace =
                norito::to_bytes(&DataSpaceId::new(requested_dataspace)).expect("encode dataspace");
            let dataspace_ptr = vm
                .alloc_input_tlv(&make_tlv(PointerType::DataSpaceId, &dataspace))
                .expect("allocate dataspace");
            vm.set_register(13, quantity_ptr);
            vm.set_register(14, dataspace_ptr);
            call_syscall(&mut vm, syscalls::SYSCALL_TRANSFER_ASSET_SCOPED)
        }
        assert_eq!(invoke(true, true, 10, 10), Err(VMError::PermissionDenied));
        assert_eq!(invoke(false, false, 10, 10), Err(VMError::PermissionDenied));
        assert_eq!(invoke(false, true, 11, 10), Err(VMError::PermissionDenied));
        assert!(invoke(false, true, 10, 10).is_ok());
    }
    #[test]
    fn pointer_from_norito_accepts_full_width_int() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let value = iroha_primitives::bigint::BigInt::from_twos_bytes(&[0x7f; 64])
            .expect("wide signed integer");
        let inner = ivm_abi::numeric_tlv::encode_int(&value).expect("Int pointer");
        let outer = make_tlv(PointerType::NoritoBytes, &inner);
        let ptr = vm.alloc_input_tlv(&outer).expect("allocate wrapped Int");
        vm.set_register(10, ptr);
        vm.set_register(11, u64::from(PointerType::Int as u16));
        call_syscall(&mut vm, syscalls::SYSCALL_POINTER_FROM_NORITO)
            .expect("decode full-width Int");
        let decoded = vm.validate_tlv(vm.register(10)).expect("Int output");
        assert_eq!(
            crate::numeric_tlv::decode_int_bytes(&make_tlv(PointerType::Int, decoded.payload)),
            Ok(value)
        );
    }
    #[test]
    fn wsv_codec_helpers_charge_payload_bytes() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        load_int_state_map_schema(&mut vm, "orders");
        let value = iroha_primitives::bigint::BigInt::from_i128(42);
        let int_envelope = ivm_abi::numeric_tlv::encode_int(&value).expect("Int pointer");
        let int_ptr = vm.alloc_input_tlv(&int_envelope).expect("allocate Int");
        vm.set_register(10, int_ptr);
        let encode_gas = call_syscall_with_quote(&mut vm, syscalls::SYSCALL_POINTER_TO_NORITO)
            .expect("encode full-width Int pointer");
        let encoded_ptr = vm.register(10);
        let encoded = vm.validate_tlv(encoded_ptr).expect("encoded TLV");
        assert_eq!(encoded.payload, int_envelope);
        assert_eq!(encode_gas, WsvHost::pointer_gas(int_envelope.len()));
        vm.set_register(10, encoded_ptr);
        vm.set_register(11, u64::from(PointerType::Int as u16));
        assert_eq!(
            call_syscall_with_quote(&mut vm, syscalls::SYSCALL_POINTER_FROM_NORITO),
            Ok(WsvHost::pointer_gas(int_envelope.len()))
        );
        let restored = vm.validate_tlv(vm.register(10)).expect("restored Int");
        assert_eq!(
            crate::numeric_tlv::decode_int_bytes(&make_tlv(PointerType::Int, restored.payload)),
            Ok(value)
        );
        let base: Name = "orders".parse().expect("base name");
        let base_bytes = norito::to_bytes(&base).expect("encode base");
        let base_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &base_bytes))
            .expect("alloc base");
        let key_schema = crate::state_value_runtime::schema_for_embedded_state_type(
            &crate::metadata::EmbeddedStateType::Int,
        )
        .expect("scalar key schema");
        let key_schema_bytes = norito::to_bytes(&key_schema).expect("key schema frame");
        let key_record = ivm_abi::state_value::StateValueRecordV1 {
            schema_hash: ivm_abi::state_value::state_value_schema_hash_v1(&key_schema_bytes),
            atoms: vec![ivm_abi::state_value::StateValueAtomV1::Pointer(
                ivm_abi::numeric_tlv::encode_int(&iroha_primitives::bigint::BigInt::from_i128(7))
                    .expect("encode canonical int key"),
            )],
        };
        let key_bytes = norito::to_bytes(&key_record).expect("canonical key record");
        let key_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &key_bytes))
            .expect("alloc key");
        vm.set_register(10, base_ptr);
        vm.set_register(11, key_ptr);
        let path_norito_gas =
            call_syscall_with_quote(&mut vm, syscalls::SYSCALL_BUILD_PATH_KEY_NORITO)
                .expect("path norito");
        let path_norito_tlv = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("path norito tlv");
        assert_eq!(
            path_norito_gas,
            WsvHost::path_gas(
                base_bytes.len() + key_bytes.len(),
                path_norito_tlv.payload.len()
            )
        );
        let json = Json::from_str_norito(r#"{"qty":10}"#).expect("json");
        let json_bytes = norito::to_bytes(&json).expect("encode json");
        let json_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &json_bytes))
            .expect("alloc json");
        vm.set_register(10, json_ptr);
        let json_encode_gas =
            call_syscall_with_quote(&mut vm, syscalls::SYSCALL_JSON_ENCODE).expect("json encode");
        let json_encoded_ptr = vm.register(10);
        let json_encoded = vm
            .memory
            .validate_tlv(json_encoded_ptr)
            .expect("json encoded tlv");
        let json_encoded_len = json_encoded.payload.len();
        assert_eq!(
            json_encode_gas,
            WsvHost::json_gas(json_bytes.len(), json_encoded_len)
        );
        vm.set_register(10, json_encoded_ptr);
        let json_decode_gas =
            call_syscall_with_quote(&mut vm, syscalls::SYSCALL_JSON_DECODE).expect("json decode");
        let decoded_json_ptr = vm.register(10);
        let decoded_json = vm
            .memory
            .validate_tlv(decoded_json_ptr)
            .expect("decoded json tlv");
        assert_eq!(
            json_decode_gas,
            WsvHost::json_gas(json_encoded_len, decoded_json.payload.len())
        );
        let key: Name = "answer".parse().expect("json key");
        let key_name_bytes = norito::to_bytes(&key).expect("encode key name");
        let key_name_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &key_name_bytes))
            .expect("alloc key name");
        let object_gas =
            call_syscall_with_quote(&mut vm, syscalls::SYSCALL_JSON_OBJECT).expect("json object");
        let object_ptr = vm.register(10);
        let object = vm.validate_tlv(object_ptr).expect("object tlv");
        let object_len = object.payload.len();
        assert_eq!(object_gas, WsvHost::json_gas(0, object_len));
        vm.set_register(10, object_ptr);
        vm.set_register(11, key_name_ptr);
        vm.set_register(12, 99);
        let set_gas =
            call_syscall_with_quote(&mut vm, syscalls::SYSCALL_JSON_SET_I64).expect("json set");
        let object_with_value_ptr = vm.register(10);
        let object_with_value = vm
            .memory
            .validate_tlv(object_with_value_ptr)
            .expect("json set tlv");
        let object_with_value_len = object_with_value.payload.len();
        assert_eq!(
            set_gas,
            WsvHost::json_gas(
                object_len + key_name_bytes.len() + core::mem::size_of::<i64>(),
                object_with_value_len
            )
        );
        vm.set_register(10, object_with_value_ptr);
        vm.set_register(11, key_name_ptr);
        assert_eq!(
            call_syscall_with_quote(&mut vm, syscalls::SYSCALL_JSON_GET_INT),
            Err(VMError::DecodeError),
            "generic JSON_SET_I64 number tokens stay outside the exact-number surface"
        );
        let missing: Name = "missing".parse().expect("missing key");
        let missing_bytes = norito::to_bytes(&missing).expect("encode missing key");
        let missing_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &missing_bytes))
            .expect("alloc missing key");
        vm.set_register(10, object_with_value_ptr);
        vm.set_register(11, missing_ptr);
        let get_gas =
            call_syscall_with_quote(&mut vm, syscalls::SYSCALL_JSON_GET_INT).expect("json get");
        let (present, words) = crate::sum::read_words(
            &vm,
            vm.register(10),
            crate::sum::SumLayoutV1::option(1).expect("int Option layout"),
        )
        .expect("read int Option");
        assert!(!present, "an absent key reads as Option::none");
        assert!(words.is_empty());
        assert_eq!(
            get_gas,
            WsvHost::json_gas(object_with_value_len + missing_bytes.len(), 16)
        );
        let name: Name = "wonderland".parse().expect("name");
        let name_bytes = norito::to_bytes(&name).expect("encode name");
        let name_norito_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &name_bytes))
            .expect("alloc name bytes");
        vm.set_register(10, name_norito_ptr);
        let name_decode_gas =
            call_syscall_with_quote(&mut vm, syscalls::SYSCALL_NAME_DECODE).expect("name decode");
        let name_tlv = vm.validate_tlv(vm.register(10)).expect("name tlv");
        assert_eq!(
            name_decode_gas,
            WsvHost::name_decode_gas(name_bytes.len(), name_tlv.payload.len())
        );
    }
    #[test]
    fn int_pointer_transport_rejects_noncanonical_frames() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let cases = vec![
            ("utf8-decimal", b"-41".to_vec()),
            (
                "norito-string",
                norito::to_bytes(&"-8".to_string()).expect("encode string"),
            ),
        ];
        for (label, payload) in cases {
            let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
            let mut vm = IVM::new(u64::MAX);
            vm.set_host(host);
            let inner = make_tlv(PointerType::Int, &payload);
            let ptr = vm
                .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &inner))
                .expect("alloc wrapped Int");
            vm.set_register(10, ptr);
            vm.set_register(11, u64::from(PointerType::Int as u16));
            let err = call_syscall(&mut vm, syscalls::SYSCALL_POINTER_FROM_NORITO)
                .expect_err("pointer transport must reject a noncanonical Int frame");
            assert!(
                matches!(err, VMError::PointerAbiFault(_) | VMError::NoritoInvalid),
                "malformed numeric frame {label} yielded {err:?}"
            );
        }
    }
    #[test]
    fn name_decode_rejects_retired_and_noncanonical_payload_forms() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let name: Name = "canonical".parse().expect("name");
        let canonical = norito::to_bytes(&name).expect("encode canonical Name");
        let alternate_layout = {
            let _flags = norito::core::DecodeFlagsGuard::enter(0);
            norito::to_bytes(&name).expect("encode alternate Name layout")
        };
        assert_ne!(alternate_layout, canonical);
        for (label, payload) in [
            ("invalid bytes", vec![0xff, 0xfe, 0xfd]),
            ("raw UTF-8", name.as_ref().as_bytes().to_vec()),
            (
                "framed String",
                norito::to_bytes(&name.to_string()).expect("encode String"),
            ),
            ("alternate Name layout", alternate_layout),
        ] {
            let pointer = vm
                .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &payload))
                .unwrap_or_else(|error| panic!("allocate {label} payload: {error:?}"));
            vm.set_register(10, pointer);
            assert_eq!(
                call_syscall(&mut vm, syscalls::SYSCALL_NAME_DECODE),
                Err(VMError::DecodeError),
                "{label} must not be accepted as a first-release Name frame"
            );
            assert_eq!(vm.register(10), pointer);
        }
    }
    #[test]
    fn json_decode_rejects_retired_blob_payload_forms() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let json = Json::from_str_norito(
            r#"{"fastpq_binding":{"verified_effect_type":"aed_to_pkr_settlement"}}"#,
        )
        .expect("json");
        let encoded = norito::to_bytes(&json).expect("encode json");
        for payload in [json.get().as_bytes(), encoded.as_slice()] {
            let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
            let mut vm = IVM::new(u64::MAX);
            vm.set_host(host);
            let ptr = vm
                .alloc_input_tlv(&make_tlv(PointerType::Blob, payload))
                .expect("allocate retired blob carrier");
            vm.set_register(10, ptr);
            assert_eq!(
                call_syscall(&mut vm, syscalls::SYSCALL_JSON_DECODE),
                Err(VMError::NoritoInvalid)
            );
            assert_eq!(vm.register(10), ptr);
        }
    }
    #[test]
    fn get_public_input_reads_named_fixture_value() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let input_name: Name = "trigger_event_json".parse().expect("public input name");
        let input_value = make_tlv(PointerType::Json, br#"{"kind":"manual"}"#);
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone())
            .with_public_inputs(BTreeMap::from([(input_name.clone(), input_value.clone())]));
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let name_bytes = norito::to_bytes(&input_name).expect("encode name");
        let name_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &name_bytes))
            .expect("alloc name tlv");
        vm.set_register(10, name_ptr);
        let quote =
            quote_syscall(&mut vm, syscalls::SYSCALL_GET_PUBLIC_INPUT).expect("quote public input");
        let gas =
            call_syscall(&mut vm, syscalls::SYSCALL_GET_PUBLIC_INPUT).expect("get public input");
        let out = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("validate output tlv");
        assert_eq!(out.type_id, PointerType::Json);
        assert_eq!(out.payload, br#"{"kind":"manual"}"#);
        assert!(gas <= quote);
    }
    #[test]
    fn large_public_input_dispatch_spills_to_heap_within_reserved_quote() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let input_name: Name = "large_payload".parse().expect("public input name");
        let payload = vec![0x5a; (Memory::INPUT_SIZE as usize) * 2];
        let input_value = make_tlv(PointerType::Blob, &payload);
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller)
            .with_public_inputs(BTreeMap::from([(input_name.clone(), input_value)]));
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
        let name_payload = norito::to_bytes(&input_name).expect("encode input name");
        let name_pointer = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &name_payload))
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
    fn schema_decode_rejects_blob() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let schema: Name = "Order".parse().expect("schema name");
        let json = Json::from_str_norito(r#"{"qty":10,"side":"buy"}"#).expect("json");
        let schema_bytes = norito::to_bytes(&schema).expect("encode schema");
        let json_bytes = norito::to_bytes(&json).expect("encode json");
        let p_schema = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &schema_bytes))
            .expect("alloc schema");
        let p_json = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &json_bytes))
            .expect("alloc json");
        vm.set_register(10, p_schema);
        vm.set_register(11, p_json);
        call_syscall(&mut vm, syscalls::SYSCALL_SCHEMA_ENCODE).expect("encode ok");
        let encoded = vm.validate_tlv(vm.register(10)).expect("encoded");
        let p_blob = vm
            .alloc_input_tlv(&make_tlv(PointerType::Blob, encoded.payload))
            .expect("alloc blob");
        vm.set_register(10, p_schema);
        vm.set_register(11, p_blob);
        let err = call_syscall(&mut vm, syscalls::SYSCALL_SCHEMA_DECODE)
            .expect_err("blob should be rejected");
        assert!(matches!(err, VMError::NoritoInvalid));
    }
    #[test]
    fn wsv_schema_helpers_charge_payload_bytes() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller.clone());
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(host);
        let schema: Name = "Order".parse().expect("schema name");
        let json = Json::from_str_norito(r#"{"qty":10,"side":"buy"}"#).expect("json");
        let schema_bytes = norito::to_bytes(&schema).expect("encode schema");
        let json_bytes = norito::to_bytes(&json).expect("encode json");
        let schema_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &schema_bytes))
            .expect("alloc schema");
        let json_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &json_bytes))
            .expect("alloc json");
        vm.set_register(10, schema_ptr);
        vm.set_register(11, json_ptr);
        let encode_quote =
            quote_syscall(&mut vm, syscalls::SYSCALL_SCHEMA_ENCODE).expect("quote schema encode");
        let encode_gas =
            call_syscall(&mut vm, syscalls::SYSCALL_SCHEMA_ENCODE).expect("schema encode");
        let encoded_ptr = vm.register(10);
        let encoded = vm.validate_tlv(encoded_ptr).expect("encoded tlv");
        assert_eq!(encoded.type_id, PointerType::NoritoBytes);
        let encoded_len = encoded.payload.len();
        assert_eq!(
            encode_gas,
            WsvHost::schema_gas(json_bytes.len(), encoded_len)
        );
        assert!(encode_gas <= encode_quote);
        assert!(encode_quote <= 1_000_000);
        vm.set_register(10, schema_ptr);
        vm.set_register(11, encoded_ptr);
        let decode_quote =
            quote_syscall(&mut vm, syscalls::SYSCALL_SCHEMA_DECODE).expect("quote schema decode");
        let decode_gas =
            call_syscall(&mut vm, syscalls::SYSCALL_SCHEMA_DECODE).expect("schema decode");
        let decoded = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("decoded tlv");
        assert_eq!(decoded.type_id, PointerType::Json);
        assert_eq!(
            decode_gas,
            WsvHost::schema_gas(encoded_len, decoded.payload.len())
        );
        assert!(decode_gas <= decode_quote);
        assert!(decode_quote <= 1_000_000);
        vm.set_register(10, schema_ptr);
        let info_quote =
            quote_syscall(&mut vm, syscalls::SYSCALL_SCHEMA_INFO).expect("quote schema info");
        let info_gas = call_syscall(&mut vm, syscalls::SYSCALL_SCHEMA_INFO).expect("schema info");
        let info = vm.validate_tlv(vm.register(10)).expect("info tlv");
        assert_eq!(info.type_id, PointerType::Json);
        assert_eq!(
            info_gas,
            WsvHost::schema_gas(schema_bytes.len(), info.payload.len())
        );
        assert!(info_gas <= info_quote);
        assert!(info_quote <= 1_000_000);
    }
    #[test]
    fn prepare_codec_quote_is_bounded_and_side_effect_free_for_large_output() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(u64::MAX);
        let json = Json::from_str_norito(&format!(r#"{{"payload":"{}"}}"#, "ab".repeat(8 * 1024)))
            .expect("large json");
        let payload = norito::to_bytes(&json).expect("encode large json");
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &payload))
            .expect("allocate large JSON TLV");
        vm.set_register(10, ptr);
        let original_r10 = vm.register(10);
        let writes_before = vm
            .memory
            .try_write_log_snapshot()
            .expect("allocate write-log snapshot");
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_JSON_ENCODE, &vm)
            .expect("quote JSON_ENCODE");
        assert_eq!(
            vm.register(10),
            original_r10,
            "quoting must not mutate VM registers"
        );
        assert_eq!(
            vm.memory
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot"),
            writes_before
        );
        assert!(host.actual_access.read_keys.is_empty());
        assert!(host.actual_access.write_keys.is_empty());
        let mut execution_host = host.clone();
        let mut execution_vm = vm.try_clone_snapshot().expect("fund VM snapshot");
        let actual = execution_host
            .syscall(syscalls::SYSCALL_JSON_ENCODE, &mut execution_vm)
            .expect("execute JSON_ENCODE");
        assert!(actual <= quote);
        assert!(quote > u64::try_from(payload.len()).expect("payload length fits"));
    }
    #[test]
    fn prepare_codec_quote_does_not_decode_malformed_payload_before_debit() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(10_000);
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &[0xff, 0x00, 0x80]))
            .expect("allocate malformed JSON TLV");
        vm.set_register(10, ptr);
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_JSON_ENCODE, &vm)
            .expect("header-valid malformed JSON receives a conservative quote");
        assert!(quote > 3);
        assert_eq!(vm.register(10), ptr);
        assert!(host.actual_access.read_keys.is_empty());
        let mut execution_host = host.clone();
        let error = execution_host
            .syscall(syscalls::SYSCALL_JSON_ENCODE, &mut vm)
            .expect_err("malformed JSON is rejected after debit preparation");
        assert!(matches!(error, VMError::DecodeError));
    }
    #[test]
    fn bounded_prepare_rejects_forged_extent_without_cloning_or_mutation() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(1_000_000);
        let mut header = [0_u8; 7];
        header[..2].copy_from_slice(&(PointerType::Json as u16).to_be_bytes());
        header[2] = 1;
        header[3..].copy_from_slice(&u32::MAX.to_be_bytes());
        vm.memory
            .preload_input(0, &header)
            .expect("install forged header");
        vm.set_register(10, crate::memory::Memory::INPUT_START);
        let writes_before = vm
            .memory
            .try_write_log_snapshot()
            .expect("allocate write-log snapshot");
        assert!(
            host.prepare_syscall(syscalls::SYSCALL_JSON_ENCODE, &vm)
                .is_err()
        );
        assert_eq!(
            vm.memory
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot"),
            writes_before
        );
        assert_eq!(vm.register(10), crate::memory::Memory::INPUT_START);
    }
    #[test]
    fn bounded_prepare_accepts_maximal_practical_payload_under_default_budget() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(1_000_000);
        let payload = vec![b'x'; gas::HOST_CODEC_MAX_INPUT_BYTES];
        let pointer = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &payload))
            .expect("allocate maximum codec input");
        vm.set_register(10, pointer);
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_JSON_ENCODE, &vm)
            .expect("header-only quote");
        assert!(quote > u64::try_from(payload.len()).expect("length fits"));
        assert!(quote <= 1_000_000);
    }
    #[test]
    fn insufficient_gas_prevents_prepare_from_querying_or_allocating() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let input_name: Name = "trigger_event_json".parse().expect("public input name");
        let input_value = make_tlv(PointerType::Json, br#"{"kind":"manual"}"#);
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller)
            .with_public_inputs(BTreeMap::from([(input_name.clone(), input_value)]));
        let mut vm = IVM::new(1_000_000);
        let mut code = Vec::new();
        code.extend_from_slice(
            &crate::encoding::wide::encode_sys(
                crate::instruction::wide::system::SCALL,
                u8::try_from(syscalls::SYSCALL_GET_PUBLIC_INPUT).expect("syscall fits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_code(&code).expect("load test program");
        let name_payload = norito::to_bytes(&input_name).expect("encode input name");
        let name_pointer = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, &name_payload))
            .expect("allocate input name");
        vm.set_register(10, name_pointer);
        vm.set_host(host);
        vm.set_gas_limit(PUBLIC_INPUT_GAS_BASE.saturating_sub(1));
        let writes_before = vm
            .memory
            .try_write_log_snapshot()
            .expect("allocate write-log snapshot");
        let error = vm.run().expect_err("bounded quote must be unaffordable");
        assert_eq!(error, VMError::OutOfGas);
        assert_eq!(vm.register(10), name_pointer);
        assert_eq!(
            vm.memory
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot"),
            writes_before
        );
        let host = vm
            .host_mut_any()
            .expect("host remains installed")
            .downcast_mut::<WsvHost>()
            .expect("WSV host");
        assert!(host.actual_access.read_keys.is_empty());
        assert!(host.actual_access.write_keys.is_empty());
    }
    #[test]
    fn bounded_codec_quote_refunds_unused_reserve() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(1_000_000);
        let mut code = Vec::new();
        code.extend_from_slice(
            &crate::encoding::wide::encode_sys(
                crate::instruction::wide::system::SCALL,
                u8::try_from(syscalls::SYSCALL_JSON_ENCODE).expect("syscall fits"),
            )
            .to_le_bytes(),
        );
        code.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_code(&code).expect("load test program");
        let json = Json::from_str_norito(r#"{"answer":42}"#).expect("valid JSON");
        let payload = norito::to_bytes(&json).expect("encode JSON");
        let pointer = vm
            .alloc_input_tlv(&make_tlv(PointerType::Json, &payload))
            .expect("allocate JSON");
        vm.set_register(10, pointer);
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_JSON_ENCODE, &vm)
            .expect("quote JSON encode");
        let before = vm.remaining_gas();
        vm.set_host(host);
        vm.run().expect("execute quoted codec helper");
        assert!(
            vm.remaining_gas() > before.saturating_sub(quote),
            "unused conservative reserve must be refunded"
        );
    }
    #[test]
    fn json_quantity_getter_accepts_only_canonical_strings() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(1_000_000);
        let json = Json::from_str_norito(r#"{"amount":"1.25"}"#).expect("quantity JSON");
        let json_ptr = vm
            .alloc_input_tlv(&make_tlv(
                PointerType::Json,
                &norito::to_bytes(&json).expect("encode JSON"),
            ))
            .expect("allocate JSON");
        let key: Name = "amount".parse().expect("amount key");
        let key_ptr = vm
            .alloc_input_tlv(&make_tlv(
                PointerType::Name,
                &norito::to_bytes(&key).expect("encode key"),
            ))
            .expect("allocate key");
        vm.set_register(10, json_ptr);
        vm.set_register(11, key_ptr);
        host.syscall(syscalls::SYSCALL_JSON_GET_QUANTITY, &mut vm)
            .expect("get quantity");
        let (some, words) = crate::sum::read_words(
            &vm,
            vm.register(10),
            crate::sum::SumLayoutV1::option(1).expect("quantity option layout"),
        )
        .expect("quantity option");
        assert!(some);
        let tlv = vm.validate_tlv(words[0]).expect("quantity TLV");
        assert_eq!(tlv.type_id, PointerType::Quantity);
        let quantity = QuantityValueV1::decode_frame(tlv.payload)
            .expect("decode quantity frame")
            .into_quantity();
        assert_eq!(quantity.to_string(), "1.25");
        let negative = Json::from_str_norito(r#"{"amount":"-1"}"#).expect("negative JSON");
        let negative_ptr = vm
            .alloc_input_tlv(&make_tlv(
                PointerType::Json,
                &norito::to_bytes(&negative).expect("encode negative JSON"),
            ))
            .expect("allocate negative JSON");
        vm.set_register(10, negative_ptr);
        vm.set_register(11, key_ptr);
        // A present negative amount is malformed input, never an absent field.
        assert_eq!(
            host.syscall(syscalls::SYSCALL_JSON_GET_QUANTITY, &mut vm),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn asset_amount_decoder_requires_canonical_amount_pointer() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(1_000_000);
        let canonical: Quantity = "1.25".parse().expect("canonical quantity");
        let canonical_payload = QuantityValueV1::new(canonical.clone())
            .encode_frame()
            .expect("encode canonical quantity frame");
        let canonical_envelope = make_tlv(PointerType::Quantity, &canonical_payload);
        let canonical_ptr = vm
            .alloc_input_tlv(&canonical_envelope)
            .expect("allocate canonical quantity");
        vm.set_register(12, canonical_ptr);
        assert_eq!(host.decode_amount_reg(&vm, 12), Ok(canonical.clone()));
        let heap_ptr = vm
            .alloc_heap(u64::try_from(canonical_envelope.len()).expect("TLV length fits u64"))
            .expect("allocate canonical HEAP quantity");
        vm.store_bytes(heap_ptr, &canonical_envelope)
            .expect("store canonical HEAP quantity");
        vm.set_register(12, heap_ptr);
        assert_eq!(host.decode_amount_reg(&vm, 12), Ok(canonical.clone()));
        for (label, pointer) in [
            (
                "unallocated HEAP",
                Memory::HEAP_START + canonical_envelope.len() as u64 + 8,
            ),
            ("OUTPUT", Memory::OUTPUT_START),
            ("stack", Memory::STACK_START),
        ] {
            vm.store_bytes(pointer, &canonical_envelope)
                .unwrap_or_else(|error| panic!("store {label} quantity: {error:?}"));
            vm.set_register(12, pointer);
            assert_eq!(
                host.decode_amount_reg(&vm, 12),
                Err(VMError::NoritoInvalid),
                "{label} bytes must not acquire pointer provenance"
            );
        }
        let mut corrupted = canonical_envelope.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        let corrupted_ptr = vm
            .alloc_input_tlv(&corrupted)
            .expect("allocate corrupted quantity envelope");
        vm.set_register(12, corrupted_ptr);
        assert_eq!(host.decode_amount_reg(&vm, 12), Err(VMError::NoritoInvalid));
        let legacy_numeric = Numeric::new(125_u32, 2);
        let legacy_payload = norito::to_bytes(&legacy_numeric).expect("encode legacy Numeric");
        let legacy_ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &legacy_payload))
            .expect("allocate legacy Numeric pointer");
        vm.set_register(12, legacy_ptr);
        assert_eq!(host.decode_amount_reg(&vm, 12), Err(VMError::NoritoInvalid));
        let wrong_schema_numeric = Numeric::new(1_250_u32, 3);
        let wrong_schema_ptr = vm
            .alloc_input_tlv(&make_tlv(
                PointerType::Quantity,
                &norito::to_bytes(&wrong_schema_numeric).expect("encode hostile Numeric payload"),
            ))
            .expect("allocate Quantity-tagged Numeric payload");
        vm.set_register(12, wrong_schema_ptr);
        assert_eq!(host.decode_amount_reg(&vm, 12), Err(VMError::DecodeError));
    }
    #[test]
    fn state_count_quote_reserves_once_and_exact_execution_handles_large_prefix() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut wsv = MockWorldStateView::new();
        for index in 0..1_024_u16 {
            let path: StatePath = format!("orders/{index:04}")
                .parse()
                .expect("canonical state fixture");
            wsv.state_overlay
                .set(
                    &path,
                    vec![u8::try_from(index % 251).expect("byte fits"); 64],
                )
                .expect("insert state fixture");
        }
        let host = WsvHost::new_with_subject(wsv, caller);
        let mut vm = IVM::new(2_000_000);
        let prefix: StatePath = "orders".parse().expect("state prefix");
        let prefix_ptr = vm
            .alloc_input_tlv(&make_tlv(
                PointerType::NoritoBytes,
                &norito::to_bytes(&prefix).expect("encode prefix"),
            ))
            .expect("allocate prefix");
        vm.set_register(10, prefix_ptr);
        vm.set_register(11, u64::MAX);
        vm.set_register(12, syscalls::STATE_SCAN_MAX_ITEMS_V1);
        let available = vm.remaining_gas();
        assert_eq!(
            host.prepare_syscall(syscalls::SYSCALL_STATE_COUNT, &vm),
            Ok(available),
            "state cardinality is scanned once inside the reserved call"
        );
        assert!(host.actual_access.read_keys.is_empty());
        let mut execution_host = host.clone();
        let mut execution_vm = vm.try_clone_snapshot().expect("fund VM snapshot");
        let actual = execution_host
            .syscall(syscalls::SYSCALL_STATE_COUNT, &mut execution_vm)
            .expect("direct state count execution");
        assert_eq!(execution_vm.register(10), 1_024);
        assert!(actual <= available);
        assert_eq!(WsvHost::state_query_gas(usize::MAX), u64::MAX);
    }
    #[test]
    fn state_count_charges_text_prefix_candidates_and_merges_live_overlay() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut wsv = MockWorldStateView::new();
        for raw in ["orders-extra", "orders/00", "orders/02", "orders2/00"] {
            wsv.sc_set(raw, vec![1]).expect("insert state fixture");
        }
        let mut host = WsvHost::new_with_subject(wsv, caller);
        host.tx_active = true;
        host.state_overlay
            .insert("orders/00".parse().expect("tombstoned path"), None);
        host.state_overlay
            .insert("orders/01".parse().expect("inserted path"), Some(vec![2]));
        host.state_overlay
            .insert("orders/02".parse().expect("updated path"), Some(vec![3]));
        let prefix: StatePath = "orders".parse().expect("state prefix");
        let path_len = crate::host::state_path_payload_len(&prefix).expect("framed prefix length");
        let vm = IVM::new(u64::MAX);
        let (total, scan_work_gas) = host
            .state_count_with_prefix(&vm, &prefix, path_len)
            .expect("scan adversarial base and transaction overlays");
        assert_eq!(total, 2);
        let candidate_text = [
            "orders-extra",
            "orders/00",
            "orders/01",
            "orders/02",
            "orders2/00",
        ];
        let expected_scan_work = candidate_text.iter().fold(
            u64::try_from(path_len).expect("path length fits u64"),
            |gas, key| {
                gas.saturating_add(1)
                    .saturating_add(u64::try_from(key.len()).expect("key length fits u64"))
            },
        );
        assert_eq!(
            scan_work_gas, expected_scan_work,
            "segment mismatches, tombstones, and overlay duplicates must not escape scan gas"
        );
    }
    #[test]
    fn state_scan_quote_does_not_trust_malformed_state_path_payload() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(1_000);
        let pointer = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &[0xff, 0x80]))
            .expect("allocate malformed StatePath TLV");
        vm.set_register(10, pointer);
        assert_eq!(
            host.prepare_syscall(syscalls::SYSCALL_STATE_COUNT, &vm),
            Ok(vm.remaining_gas())
        );
        let mut execution_host = host.clone();
        let error = execution_host
            .syscall(syscalls::SYSCALL_STATE_COUNT, &mut vm)
            .expect_err("malformed StatePath must be rejected by the state scan");
        assert!(matches!(error, VMError::DecodeError));
        assert!(execution_host.actual_access.read_keys.is_empty());
    }
    #[test]
    fn wsv_host_tlv_eq_rejects_equal_invalid_raw_addresses() {
        let caller: AccountId = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let mut vm = IVM::new(u64::MAX);
        vm.set_register(10, Memory::OUTPUT_START);
        vm.set_register(11, Memory::OUTPUT_START);
        assert!(host.prepare_syscall(syscalls::SYSCALL_TLV_EQ, &vm).is_err());
        assert!(host.syscall(syscalls::SYSCALL_TLV_EQ, &mut vm).is_err());
        vm.set_register(10, 0);
        vm.set_register(11, Memory::OUTPUT_START);
        assert!(host.prepare_syscall(syscalls::SYSCALL_TLV_EQ, &vm).is_err());
        assert!(host.syscall(syscalls::SYSCALL_TLV_EQ, &mut vm).is_err());
    }
}

#[cfg(test)]
mod read_deferral_tests {
    use super::*;

    #[test]
    fn asset_registration_returns_read_refusal_without_retrying_an_alternate_decoder() {
        let caller = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let mut vm = IVM::try_new_with_memory_budget(1_000_000, &budget).unwrap();
        vm.set_register(10, crate::Memory::INPUT_START);
        budget.set_limit_bytes(budget.reserved_bytes());
        assert!(matches!(
            host.syscall(syscalls::SYSCALL_REGISTER_ASSET, &mut vm),
            Err(VMError::AllocationDeferred(_))
        ));
        assert_eq!(vm.register(10), crate::Memory::INPUT_START);
    }
}

#[cfg(test)]
mod tests_core_asset_definition {
    use super::*;
    use ivm_abi::core_query::CoreQueryEntityTagV1;

    fn fixture() -> (AccountId, AssetDefinitionId) {
        let account = AccountId::new(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
                .parse()
                .expect("public key"),
        );
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            "rose".parse().expect("asset name"),
        );
        (account, asset)
    }

    fn query(host: &mut WsvHost, vm: &mut IVM, id: &AssetDefinitionId) -> Vec<u64> {
        let bytes = encode_canonical_norito(id).expect("asset id encoding");
        let pointer = WsvHost::alloc_tlv_payload(vm, PointerType::AssetDefinitionId, &bytes)
            .expect("input pointer");
        vm.set_register(10, CoreQueryEntityTagV1::AssetDefinition.as_u64());
        vm.set_register(11, pointer);
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_CORE_QUERY_GET, vm)
            .expect("query gas");
        let charged = host
            .syscall(syscalls::SYSCALL_CORE_QUERY_GET, vm)
            .expect("definition query");
        assert!(charged <= quote);
        let (present, words) = crate::sum::read_words(
            vm,
            vm.register(10),
            crate::sum::SumLayoutV1::option(7).unwrap(),
        )
        .expect("native optional definition layout");
        assert_eq!(present, !words.is_empty());
        words
    }

    #[test]
    fn typed_definition_exposes_registered_owner_supply_and_integer_scale() {
        let (owner, asset) = fixture();
        let wsv = MockWorldStateView::with_balances(&[(
            (owner.clone(), asset.clone()),
            Quantity::from(7u64),
        )]);
        let mut host = WsvHost::new_with_subject(wsv, owner.clone());
        let mut vm = IVM::new(1_000_000);
        let words = query(&mut host, &mut vm, &asset);
        assert_eq!(words.len(), 7);
        assert_eq!(
            decode_canonical_norito::<AccountId>(vm.validate_tlv(words[3]).unwrap().payload)
                .unwrap(),
            owner
        );
        assert_eq!(
            vm.validate_tlv(words[4]).unwrap().payload,
            QuantityValueV1::new(Quantity::from(7u64))
                .encode_frame()
                .unwrap()
        );
        let (present, scale) =
            crate::sum::read_words(&vm, words[5], crate::sum::SumLayoutV1::option(1).unwrap())
                .unwrap();
        assert!(present);
        assert_eq!(
            vm.validate_tlv(scale[0]).unwrap().payload,
            iroha_primitives::numeric_abi::IntValueV1::try_new(0.into())
                .unwrap()
                .encode_frame()
                .unwrap()
        );
        assert_eq!(
            crate::sum::read_words(&vm, words[2], crate::sum::SumLayoutV1::option(1).unwrap())
                .unwrap(),
            (false, vec![])
        );
    }

    #[test]
    fn absent_definition_and_permission_checked_registration_have_distinct_results() {
        let (owner, asset) = fixture();
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), owner.clone());
        let mut vm = IVM::new(1_000_000);
        assert!(query(&mut host, &mut vm, &asset).is_empty());
        assert!(
            !host
                .wsv
                .register_asset_definition(&owner, asset.clone(), Mintable::Infinitely)
        );
        host.wsv
            .grant_permission(&owner, PermissionToken::RegisterAssetDefinition);
        assert!(
            host.wsv
                .register_asset_definition(&owner, asset.clone(), Mintable::Infinitely)
        );
        let words = query(&mut host, &mut vm, &asset);
        assert_eq!(
            decode_canonical_norito::<AccountId>(vm.validate_tlv(words[3]).unwrap().payload)
                .unwrap(),
            owner
        );
    }

    #[test]
    fn typed_definition_rejects_bad_tags_and_pointer_types_without_query_fallback() {
        let (owner, asset) = fixture();
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), owner);
        let mut vm = IVM::new(1_000_000);
        vm.set_register(10, 999);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_CORE_QUERY_GET, &mut vm),
            Err(VMError::DecodeError)
        );
        vm.set_register(10, CoreQueryEntityTagV1::Account.as_u64());
        assert!(
            host.syscall(syscalls::SYSCALL_CORE_QUERY_GET, &mut vm)
                .is_err()
        );
        let pointer = WsvHost::alloc_tlv_payload(
            &mut vm,
            PointerType::Blob,
            &encode_canonical_norito(&asset).unwrap(),
        )
        .unwrap();
        vm.set_register(10, CoreQueryEntityTagV1::AssetDefinition.as_u64());
        vm.set_register(11, pointer);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_CORE_QUERY_GET, &mut vm),
            Err(VMError::NoritoInvalid)
        );
        assert!(host.wsv.asset_definitions.is_empty());
    }
}

#[cfg(test)]
mod tests_asset_registration_and_scope {
    use super::*;
    use iroha_data_model::asset::definition::ivm_registration;

    fn tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
        out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
        out.push(1);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
        out.extend_from_slice(&hash);
        out
    }

    fn asset() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            "rose".parse().expect("asset name"),
        )
    }

    fn registering_host() -> WsvHost {
        let caller = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
        let subject = host.caller_subject();
        host.wsv
            .grant_permission(&subject, PermissionToken::RegisterAssetDefinition);
        host
    }

    fn register(
        host: &mut WsvHost,
        name: &[u8],
        spec_word: u64,
        mintable_word: u64,
    ) -> Result<u64, VMError> {
        let mut vm = IVM::new(u64::MAX);
        let asset_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::AssetDefinitionId,
                &norito::to_bytes(&asset()).expect("encode asset definition"),
            ))
            .expect("asset TLV");
        let name_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, name))
            .expect("name TLV");
        vm.set_register(10, asset_ptr);
        vm.set_register(11, name_ptr);
        vm.set_register(12, spec_word);
        vm.set_register(13, mintable_word);
        host.syscall(syscalls::SYSCALL_REGISTER_ASSET, &mut vm)
    }

    #[test]
    fn register_asset_records_the_display_name_spec_and_mintability() {
        let mut host = registering_host();
        let spec = NumericSpec::fractional(2);
        let mintable = Mintable::limited_from_u32(3).expect("token budget");
        register(
            &mut host,
            b"Rose",
            ivm_registration::numeric_spec_word(spec),
            ivm_registration::mintable_word(mintable),
        )
        .expect("register asset");
        assert_eq!(
            host.wsv.asset_definition_registration(&asset()),
            Some(("Rose", spec, mintable))
        );
    }

    #[test]
    fn register_asset_rejects_malformed_words_and_display_names() {
        // The same inputs trap with `DecodeError` on CoreHost
        // (`register_asset_syscall_rejects_malformed_registration_words`).
        for (name, spec_word, mintable_word) in [
            (&b"Rose"[..], 30, 0),
            (&b"Rose"[..], 0, 0b100),
            (&b"Rose"[..], 0, 3),
            (&b""[..], 0, 0),
            (&b"ro#se"[..], 0, 0),
            (&b"\xff"[..], 0, 0),
        ] {
            let mut host = registering_host();
            assert_eq!(
                register(&mut host, name, spec_word, mintable_word),
                Err(VMError::DecodeError)
            );
            assert_eq!(host.wsv.asset_definition_registration(&asset()), None);
            assert!(decode_asset_registration(name, spec_word, mintable_word).is_err());
        }
        let decoded = decode_asset_registration(
            b"Rose",
            ivm_registration::numeric_spec_word(NumericSpec::integer()),
            ivm_registration::mintable_word(Mintable::Not),
        )
        .expect("valid registration");
        assert_eq!(decoded.name, "Rose");
        assert_eq!(decoded.spec, NumericSpec::integer());
        assert_eq!(decoded.mintable, Mintable::Not);
    }

    #[test]
    fn minting_respects_the_registered_numeric_spec_and_mintability() {
        let mut wsv = MockWorldStateView::new();
        let owner = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        wsv.accounts
            .entry(MockWorldStateView::account_subject(&owner))
            .or_default();
        wsv.grant_permission(&owner, PermissionToken::RegisterAssetDefinition);
        wsv.grant_permission(&owner, PermissionToken::MintAsset(asset()));
        assert!(wsv.register_asset_definition_with_spec(
            &owner,
            asset(),
            "Rose".to_owned(),
            NumericSpec::integer(),
            Mintable::Once,
        ));
        assert!(wsv.mint(&owner, owner.clone(), asset(), Quantity::from(5_u64)));
        assert!(!wsv.mint(&owner, owner.clone(), asset(), Quantity::from(1_u64)));
    }

    #[test]
    fn transfer_without_dataspace_uses_the_global_bucket() {
        let caller = test_account_id(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
            "wonderland",
        );
        let wsv = MockWorldStateView::with_balances(&[(
            (caller.clone(), asset()),
            Quantity::from(3_u64),
        )]);
        let mut host = WsvHost::new_with_subject(wsv, caller.clone());
        let mut vm = IVM::new(u64::MAX);
        let account = norito::to_bytes(&caller).expect("encode account");
        let from = vm
            .alloc_input_tlv(&tlv(PointerType::AccountId, &account))
            .expect("from TLV");
        let to = vm
            .alloc_input_tlv(&tlv(PointerType::AccountId, &account))
            .expect("to TLV");
        let asset_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::AssetDefinitionId,
                &norito::to_bytes(&asset()).expect("encode asset definition"),
            ))
            .expect("asset TLV");
        let amount = vm
            .alloc_input_tlv(
                &ivm_abi::numeric_tlv::encode_quantity(&Quantity::from(1_u64))
                    .expect("quantity envelope"),
            )
            .expect("amount TLV");
        vm.set_register(10, from);
        vm.set_register(11, to);
        vm.set_register(12, asset_ptr);
        vm.set_register(13, amount);
        vm.set_register(14, 0);
        host.syscall(syscalls::SYSCALL_TRANSFER_ASSET_SCOPED, &mut vm)
            .expect("a global transfer needs no dataspace");
    }
}
