//! Protocol-native Ethereum consensus light-client primitives for SCCP v1 (`specs/sccp.md`
//! §4.13.3).
//!
//! The module models the fixed SSZ types used by Ethereum light-client bootstraps and updates,
//! validates a compiled fork schedule and genesis validators root, and checks one update or
//! bootstrap at a time without consulting a wall clock or any stored state. Every accepted update
//! carries a finality branch, satisfies `signature_slot > attested.slot >= finalized.slot` and the
//! mainnet two-thirds threshold (`3 * participants >= 2 * 512`, at least 342 positions), and is
//! verified by fast-aggregate BLS with the fork version of `max(signature_slot, 1) - 1`. A
//! `next_sync_committee` is accepted only when the attested and finalized headers share a period,
//! so committees are learned from finalized state only.
//!
//! Stored sets, freshness, fork bounds and checkpoints are applied by
//! [`crate::light_client::ethereum`], which composes these checks.
use core::fmt;
use iroha_crypto::{ethereum_bls_pop_fast_aggregate_verify, ethereum_bls_pop_validate_public_key};
use sha2::{Digest as _, Sha256};
/// A 32-byte Ethereum SSZ root.
pub type Root = [u8; 32];
/// Ethereum mainnet sync-committee size.
pub const SYNC_COMMITTEE_SIZE: usize = 512;
/// Number of bytes in a `Bitvector[512]`.
pub const SYNC_COMMITTEE_BITS_BYTES: usize = SYNC_COMMITTEE_SIZE / 8;
/// Minimum participant count satisfying `participants * 3 >= 512 * 2`.
pub const FINALITY_PARTICIPANT_THRESHOLD: usize = 342;
/// Slots in an Ethereum epoch.
pub const SLOTS_PER_EPOCH: u64 = 32;
/// Epochs in an Ethereum sync-committee period.
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
/// Slots in an Ethereum sync-committee period.
pub const SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 = SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
/// `DOMAIN_SYNC_COMMITTEE` from the Ethereum consensus specification.
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];
/// `finalized_checkpoint.root` generalized index before Electra.
pub const FINALIZED_ROOT_GINDEX_PRE_ELECTRA: u64 = 105;
/// `current_sync_committee` generalized index before Electra.
pub const CURRENT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA: u64 = 54;
/// `next_sync_committee` generalized index before Electra.
pub const NEXT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA: u64 = 55;
/// `finalized_checkpoint.root` generalized index from Electra onward.
pub const FINALIZED_ROOT_GINDEX_ELECTRA: u64 = 169;
/// `current_sync_committee` generalized index from Electra onward.
pub const CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 86;
/// `next_sync_committee` generalized index from Electra onward.
pub const NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 87;
/// `execution_payload` generalized index in `BeaconBlockBody`.
pub const EXECUTION_PAYLOAD_GINDEX: u64 = 25;
const ZERO_ROOT: Root = [0; 32];
/// Errors returned while validating Ethereum light-client data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthereumLightClientError {
    /// The compiled fork schedule is malformed.
    InvalidForkSchedule(&'static str),
    /// The compiled genesis validators root is the zero sentinel.
    ZeroGenesisValidatorsRoot,
    /// The slot precedes the first supported fork.
    UnsupportedSlot(u64),
    /// A header's closed fork variant disagrees with the compiled schedule.
    HeaderForkMismatch {
        /// Fork selected by the compiled schedule.
        expected: EthereumFork,
        /// Fork variant supplied by the update.
        actual: EthereumFork,
    },
    /// Execution payload extra data exceeded its SSZ `ByteList[32]` bound.
    ExtraDataTooLong(usize),
    /// A Capella-or-later execution payload branch was invalid.
    InvalidExecutionBranch,
    /// The bootstrap current-committee branch used the wrong fork shape.
    CurrentCommitteeBranchForkMismatch,
    /// The bootstrap current-committee proof was invalid.
    InvalidCurrentCommitteeBranch,
    /// The finality branch used the wrong fork shape.
    FinalityBranchForkMismatch,
    /// The finality proof was invalid.
    InvalidFinalityBranch,
    /// The next-committee branch used the wrong fork shape.
    NextCommitteeBranchForkMismatch,
    /// The next sync-committee proof was invalid.
    InvalidNextCommitteeBranch,
    /// A next sync committee was offered while the attested and finalized headers are in
    /// different periods, so it is not finalized.
    NextCommitteePeriodMismatch,
    /// A sync-committee public key failed BLS `KeyValidate`.
    InvalidCommitteePublicKey(usize),
    /// A sync committee's aggregate public key failed BLS `KeyValidate`.
    InvalidCommitteeAggregatePublicKey,
    /// Update slots did not satisfy `signature > attested >= finalized`.
    InvalidSlotOrder,
    /// The update did not meet the 342-of-512 finality threshold.
    InsufficientParticipation(usize),
    /// The standard Ethereum BLS aggregate signature was invalid.
    InvalidSyncCommitteeSignature,
}
impl fmt::Display for EthereumLightClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidForkSchedule(reason) => {
                write!(formatter, "invalid fork schedule: {reason}")
            }
            Self::ZeroGenesisValidatorsRoot => {
                formatter.write_str("genesis validators root must not be zero")
            }
            Self::UnsupportedSlot(slot) => write!(formatter, "unsupported pre-Altair slot {slot}"),
            Self::HeaderForkMismatch { expected, actual } => write!(
                formatter,
                "header fork mismatch: schedule requires {expected:?}, got {actual:?}"
            ),
            Self::ExtraDataTooLong(len) => {
                write!(
                    formatter,
                    "execution extra_data length {len} exceeds 32 bytes"
                )
            }
            Self::InvalidExecutionBranch => formatter.write_str("invalid execution payload branch"),
            Self::CurrentCommitteeBranchForkMismatch => {
                formatter.write_str("current committee branch does not match the active fork")
            }
            Self::InvalidCurrentCommitteeBranch => {
                formatter.write_str("invalid current sync committee branch")
            }
            Self::FinalityBranchForkMismatch => {
                formatter.write_str("finality branch does not match the active fork")
            }
            Self::InvalidFinalityBranch => formatter.write_str("invalid finality branch"),
            Self::NextCommitteeBranchForkMismatch => {
                formatter.write_str("next committee branch does not match the active fork")
            }
            Self::InvalidNextCommitteeBranch => {
                formatter.write_str("invalid next sync committee branch")
            }
            Self::NextCommitteePeriodMismatch => formatter.write_str(
                "next sync committee is accepted only when attested and finalized share a period",
            ),
            Self::InvalidCommitteePublicKey(position) => {
                write!(
                    formatter,
                    "invalid sync committee public key at position {position}"
                )
            }
            Self::InvalidCommitteeAggregatePublicKey => {
                formatter.write_str("invalid sync committee aggregate public key")
            }
            Self::InvalidSlotOrder => formatter.write_str("invalid light-client update slot order"),
            Self::InsufficientParticipation(actual) => write!(
                formatter,
                "sync committee participation {actual} is below the required 342"
            ),
            Self::InvalidSyncCommitteeSignature => {
                formatter.write_str("invalid Ethereum sync committee signature")
            }
        }
    }
}
impl std::error::Error for EthereumLightClientError {}
/// Closed set of Ethereum consensus forks understood by this verifier.
///
/// A future fork that changes any relevant SSZ type must be added explicitly;
/// unknown fork names cannot silently reuse an older layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EthereumFork {
    /// Altair.
    Altair,
    /// Bellatrix.
    Bellatrix,
    /// Capella.
    Capella,
    /// Deneb.
    Deneb,
    /// Electra.
    Electra,
    /// Fulu.
    Fulu,
}
impl EthereumFork {
    /// Every supported fork in activation order.
    pub const ALL: [Self; 6] = [
        Self::Altair,
        Self::Bellatrix,
        Self::Capella,
        Self::Deneb,
        Self::Electra,
        Self::Fulu,
    ];
    const fn uses_electra_state_layout(self) -> bool {
        matches!(self, Self::Electra | Self::Fulu)
    }
}
/// Activation parameters for one fixed Ethereum fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkActivation {
    epoch: u64,
    version: [u8; 4],
}
impl ForkActivation {
    /// Construct activation parameters.
    pub const fn new(epoch: u64, version: [u8; 4]) -> Self {
        Self { epoch, version }
    }
    /// Return the activation epoch.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
    /// Return the four-byte fork version.
    pub const fn version(self) -> [u8; 4] {
        self.version
    }
}
/// Validated Ethereum fork schedule and genesis validators root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkSchedule {
    genesis_validators_root: Root,
    activations: [ForkActivation; 6],
}
impl ForkSchedule {
    /// Validate and construct a complete Altair-through-Fulu schedule.
    ///
    /// Activation epochs must be nondecreasing (multiple forks at genesis are
    /// valid on development networks), and all fork versions must be unique.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero genesis root, unordered activations, or duplicate fork versions.
    pub fn new(
        genesis_validators_root: Root,
        activations: [ForkActivation; 6],
    ) -> Result<Self, EthereumLightClientError> {
        if genesis_validators_root == ZERO_ROOT {
            return Err(EthereumLightClientError::ZeroGenesisValidatorsRoot);
        }
        if activations
            .windows(2)
            .any(|pair| pair[0].epoch > pair[1].epoch)
        {
            return Err(EthereumLightClientError::InvalidForkSchedule(
                "activation epochs must be nondecreasing",
            ));
        }
        for (index, activation) in activations.iter().enumerate() {
            if activations[..index]
                .iter()
                .any(|prior| prior.version == activation.version)
            {
                return Err(EthereumLightClientError::InvalidForkSchedule(
                    "fork versions must be unique",
                ));
            }
        }
        Ok(Self {
            genesis_validators_root,
            activations,
        })
    }
    /// Return the genesis validators root.
    pub const fn genesis_validators_root(&self) -> Root {
        self.genesis_validators_root
    }
    /// Return the activation parameters for a supported fork.
    pub const fn activation(&self, fork: EthereumFork) -> ForkActivation {
        self.activations[fork as usize]
    }
    /// Return every activation in fork order.
    pub const fn activations(&self) -> [ForkActivation; 6] {
        self.activations
    }
    /// Select the active fork for a slot.
    ///
    /// # Errors
    ///
    /// Returns an error when the slot precedes the Altair activation.
    pub fn fork_at_slot(
        &self,
        slot: u64,
    ) -> Result<(EthereumFork, ForkActivation), EthereumLightClientError> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let mut selected = None;
        for (fork, activation) in EthereumFork::ALL.into_iter().zip(self.activations) {
            if activation.epoch <= epoch {
                selected = Some((fork, activation));
            }
        }
        selected.ok_or(EthereumLightClientError::UnsupportedSlot(slot))
    }
}
/// Fork-dependent Ethereum light-client generalized indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LightClientGeneralizedIndices {
    /// `finalized_checkpoint.root` generalized index.
    pub finalized_root: u64,
    /// `current_sync_committee` generalized index.
    pub current_sync_committee: u64,
    /// `next_sync_committee` generalized index.
    pub next_sync_committee: u64,
}
/// Return the light-client generalized indices for a supported fork.
pub const fn generalized_indices(fork: EthereumFork) -> LightClientGeneralizedIndices {
    if fork.uses_electra_state_layout() {
        LightClientGeneralizedIndices {
            finalized_root: FINALIZED_ROOT_GINDEX_ELECTRA,
            current_sync_committee: CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA,
            next_sync_committee: NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA,
        }
    } else {
        LightClientGeneralizedIndices {
            finalized_root: FINALIZED_ROOT_GINDEX_PRE_ELECTRA,
            current_sync_committee: CURRENT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA,
            next_sync_committee: NEXT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA,
        }
    }
}
/// Return the sync-committee period containing `slot`.
pub const fn sync_committee_period_at_slot(slot: u64) -> u64 {
    slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD
}
/// Official SSZ `BeaconBlockHeader`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    /// Beacon slot.
    pub slot: u64,
    /// Proposer validator index.
    pub proposer_index: u64,
    /// Parent beacon block root.
    pub parent_root: Root,
    /// Beacon state root.
    pub state_root: Root,
    /// Beacon block body root.
    pub body_root: Root,
}
impl BeaconBlockHeader {
    /// Compute the canonical SSZ `hash_tree_root`.
    pub fn hash_tree_root(&self) -> Root {
        merkleize(&[
            uint64_root(self.slot),
            uint64_root(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
        ])
    }
}
/// A bounded SSZ `ByteList[32]` used for execution payload extra data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExtraData {
    bytes: [u8; 32],
    len: u8,
}
impl ExtraData {
    /// Validate and construct bounded extra data.
    ///
    /// # Errors
    ///
    /// Returns an error when `bytes` exceeds the SSZ `ByteList[32]` limit.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, EthereumLightClientError> {
        let bytes = bytes.as_ref();
        if bytes.len() > 32 {
            return Err(EthereumLightClientError::ExtraDataTooLong(bytes.len()));
        }
        let mut backing = [0; 32];
        backing[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: backing,
            len: u8::try_from(bytes.len()).expect("SSZ extra data is at most 32 bytes"),
        })
    }
    /// Borrow the extra-data bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    fn hash_tree_root(&self) -> Root {
        hash_nodes(&self.bytes, &usize_root(usize::from(self.len)))
    }
}
/// Official Capella SSZ `ExecutionPayloadHeader`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapellaExecutionPayloadHeader {
    /// Parent execution block hash.
    pub parent_hash: Root,
    /// Execution fee recipient.
    pub fee_recipient: [u8; 20],
    /// Execution state root.
    pub state_root: Root,
    /// Execution receipts root.
    pub receipts_root: Root,
    /// Execution logs bloom.
    pub logs_bloom: [u8; 256],
    /// Previous RANDAO mix.
    pub prev_randao: Root,
    /// Execution block number.
    pub block_number: u64,
    /// Execution gas limit.
    pub gas_limit: u64,
    /// Execution gas used.
    pub gas_used: u64,
    /// Execution timestamp.
    pub timestamp: u64,
    /// Bounded execution extra data.
    pub extra_data: ExtraData,
    /// Base fee encoded as SSZ little-endian `uint256`.
    pub base_fee_per_gas: [u8; 32],
    /// Execution block hash.
    pub block_hash: Root,
    /// Transactions list root.
    pub transactions_root: Root,
    /// Withdrawals list root.
    pub withdrawals_root: Root,
}
impl CapellaExecutionPayloadHeader {
    fn leaves(&self) -> [Root; 15] {
        [
            self.parent_hash,
            byte_vector_root(&self.fee_recipient),
            self.state_root,
            self.receipts_root,
            byte_vector_root(&self.logs_bloom),
            self.prev_randao,
            uint64_root(self.block_number),
            uint64_root(self.gas_limit),
            uint64_root(self.gas_used),
            uint64_root(self.timestamp),
            self.extra_data.hash_tree_root(),
            self.base_fee_per_gas,
            self.block_hash,
            self.transactions_root,
            self.withdrawals_root,
        ]
    }
    /// Compute the canonical Capella SSZ `hash_tree_root`.
    pub fn hash_tree_root(&self) -> Root {
        merkleize(&self.leaves())
    }
}
/// Official Deneb SSZ `ExecutionPayloadHeader`, also used by Electra and Fulu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenebExecutionPayloadHeader {
    /// Capella-compatible fields.
    pub capella: CapellaExecutionPayloadHeader,
    /// Blob gas used by the execution block.
    pub blob_gas_used: u64,
    /// Excess blob gas after the execution block.
    pub excess_blob_gas: u64,
}
impl DenebExecutionPayloadHeader {
    /// Compute the canonical Deneb SSZ `hash_tree_root`.
    pub fn hash_tree_root(&self) -> Root {
        let mut leaves = [ZERO_ROOT; 17];
        leaves[..15].copy_from_slice(&self.capella.leaves());
        leaves[15] = uint64_root(self.blob_gas_used);
        leaves[16] = uint64_root(self.excess_blob_gas);
        merkleize(&leaves)
    }
}
/// Fixed execution-payload Merkle branch at generalized index 25.
pub type ExecutionBranch = [Root; 4];
/// Official fork-specific SSZ `LightClientHeader`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LightClientHeader {
    /// Altair header (beacon header only).
    Altair {
        /// Beacon header.
        beacon: BeaconBlockHeader,
    },
    /// Bellatrix header (beacon header only).
    Bellatrix {
        /// Beacon header.
        beacon: BeaconBlockHeader,
    },
    /// Capella header with its execution payload proof.
    Capella {
        /// Beacon header.
        beacon: BeaconBlockHeader,
        /// Capella execution payload header.
        execution: CapellaExecutionPayloadHeader,
        /// Execution payload branch in the beacon block body.
        execution_branch: ExecutionBranch,
    },
    /// Deneb header with its execution payload proof.
    Deneb {
        /// Beacon header.
        beacon: BeaconBlockHeader,
        /// Deneb execution payload header.
        execution: DenebExecutionPayloadHeader,
        /// Execution payload branch in the beacon block body.
        execution_branch: ExecutionBranch,
    },
    /// Electra header with the unchanged Deneb execution payload layout.
    Electra {
        /// Beacon header.
        beacon: BeaconBlockHeader,
        /// Deneb-format execution payload header.
        execution: DenebExecutionPayloadHeader,
        /// Execution payload branch in the beacon block body.
        execution_branch: ExecutionBranch,
    },
    /// Fulu header with the unchanged Deneb execution payload layout.
    Fulu {
        /// Beacon header.
        beacon: BeaconBlockHeader,
        /// Deneb-format execution payload header.
        execution: DenebExecutionPayloadHeader,
        /// Execution payload branch in the beacon block body.
        execution_branch: ExecutionBranch,
    },
}
/// Execution-layer fields authenticated by a Capella-or-later light-client header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedExecutionBlock {
    /// Consensus fork whose light-client header authenticated the payload.
    pub fork: EthereumFork,
    /// Parent execution block hash.
    pub parent_hash: Root,
    /// Execution state trie root.
    pub state_root: Root,
    /// Execution receipts trie root.
    pub receipts_root: Root,
    /// Execution block number.
    pub block_number: u64,
    /// Execution timestamp in seconds.
    pub timestamp: u64,
    /// Execution block hash.
    pub block_hash: Root,
}
impl LightClientHeader {
    /// Return the beacon header common to all fork variants.
    pub const fn beacon(&self) -> &BeaconBlockHeader {
        match self {
            Self::Altair { beacon }
            | Self::Bellatrix { beacon }
            | Self::Capella { beacon, .. }
            | Self::Deneb { beacon, .. }
            | Self::Electra { beacon, .. }
            | Self::Fulu { beacon, .. } => beacon,
        }
    }
    /// Return the closed fork variant carried by the header.
    pub const fn fork(&self) -> EthereumFork {
        match self {
            Self::Altair { .. } => EthereumFork::Altair,
            Self::Bellatrix { .. } => EthereumFork::Bellatrix,
            Self::Capella { .. } => EthereumFork::Capella,
            Self::Deneb { .. } => EthereumFork::Deneb,
            Self::Electra { .. } => EthereumFork::Electra,
            Self::Fulu { .. } => EthereumFork::Fulu,
        }
    }
    /// Return execution-layer fields authenticated by this header, if present.
    ///
    /// Altair and Bellatrix light-client headers do not carry an execution
    /// payload proof and therefore return `None`.
    pub fn authenticated_execution_block(&self) -> Option<AuthenticatedExecutionBlock> {
        let capella = match self {
            Self::Altair { .. } | Self::Bellatrix { .. } => return None,
            Self::Capella { execution, .. } => execution,
            Self::Deneb { execution, .. }
            | Self::Electra { execution, .. }
            | Self::Fulu { execution, .. } => &execution.capella,
        };
        Some(AuthenticatedExecutionBlock {
            fork: self.fork(),
            parent_hash: capella.parent_hash,
            state_root: capella.state_root,
            receipts_root: capella.receipts_root,
            block_number: capella.block_number,
            timestamp: capella.timestamp,
            block_hash: capella.block_hash,
        })
    }
    fn execution_root_and_branch(&self) -> Option<(Root, &ExecutionBranch)> {
        match self {
            Self::Altair { .. } | Self::Bellatrix { .. } => None,
            Self::Capella {
                execution,
                execution_branch,
                ..
            } => Some((execution.hash_tree_root(), execution_branch)),
            Self::Deneb {
                execution,
                execution_branch,
                ..
            }
            | Self::Electra {
                execution,
                execution_branch,
                ..
            }
            | Self::Fulu {
                execution,
                execution_branch,
                ..
            } => Some((execution.hash_tree_root(), execution_branch)),
        }
    }
    /// Compute the canonical fork-specific SSZ `hash_tree_root`.
    pub fn hash_tree_root(&self) -> Root {
        match self.execution_root_and_branch() {
            None => self.beacon().hash_tree_root(),
            Some((execution_root, execution_branch)) => merkleize(&[
                self.beacon().hash_tree_root(),
                execution_root,
                merkleize(execution_branch),
            ]),
        }
    }
    /// Check the fork variant against the schedule and the execution payload branch against the
    /// beacon body root.
    ///
    /// # Errors
    ///
    /// Returns an error when the slot precedes Altair, the fork variant differs from the
    /// schedule, or the execution branch does not prove the payload header.
    pub fn validate(&self, schedule: &ForkSchedule) -> Result<(), EthereumLightClientError> {
        let (expected, _) = schedule.fork_at_slot(self.beacon().slot)?;
        let actual = self.fork();
        if expected != actual {
            return Err(EthereumLightClientError::HeaderForkMismatch { expected, actual });
        }
        let Some((execution_root, execution_branch)) = self.execution_root_and_branch() else {
            return Ok(());
        };
        if merkle_root_from_branch(execution_root, EXECUTION_PAYLOAD_GINDEX, execution_branch)
            != Some(self.beacon().body_root)
        {
            return Err(EthereumLightClientError::InvalidExecutionBranch);
        }
        Ok(())
    }
}
/// Canonically encoded compressed BLS12-381 min-pk public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsPublicKey([u8; 48]);
impl BlsPublicKey {
    /// Wrap 48 compressed public-key bytes.
    ///
    /// Curve and subgroup validation is performed when the containing sync committee is admitted.
    pub const fn new(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }
    /// Return compressed public-key bytes.
    pub const fn to_bytes(self) -> [u8; 48] {
        self.0
    }
    fn hash_tree_root(self) -> Root {
        byte_vector_root(&self.0)
    }
}
/// Canonically encoded compressed BLS12-381 min-pk signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsSignature([u8; 96]);
impl BlsSignature {
    /// Wrap 96 compressed signature bytes.
    pub const fn new(bytes: [u8; 96]) -> Self {
        Self(bytes)
    }
    /// Return compressed signature bytes.
    pub const fn to_bytes(self) -> [u8; 96] {
        self.0
    }
    fn hash_tree_root(self) -> Root {
        byte_vector_root(&self.0)
    }
}
/// Official SSZ `SyncCommittee` with exactly 512 positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncCommittee {
    pubkeys: [BlsPublicKey; SYNC_COMMITTEE_SIZE],
    aggregate_pubkey: BlsPublicKey,
}
impl SyncCommittee {
    /// Construct a fixed-size sync committee.
    pub fn new(
        pubkeys: &[BlsPublicKey; SYNC_COMMITTEE_SIZE],
        aggregate_pubkey: BlsPublicKey,
    ) -> Self {
        Self {
            pubkeys: *pubkeys,
            aggregate_pubkey,
        }
    }
    /// Borrow all 512 committee positions in canonical order.
    pub fn pubkeys(&self) -> &[BlsPublicKey; SYNC_COMMITTEE_SIZE] {
        &self.pubkeys
    }
    /// Return the aggregate public key committed by the beacon state.
    pub const fn aggregate_pubkey(&self) -> BlsPublicKey {
        self.aggregate_pubkey
    }
    /// Compute the canonical SSZ `hash_tree_root`.
    pub fn hash_tree_root(&self) -> Root {
        let pubkey_root = merkleize_iter(
            self.pubkeys
                .iter()
                .copied()
                .map(BlsPublicKey::hash_tree_root),
            SYNC_COMMITTEE_SIZE,
        );
        hash_nodes(&pubkey_root, &self.aggregate_pubkey.hash_tree_root())
    }
    /// Run BLS `KeyValidate` over every position and the aggregate key.
    ///
    /// # Errors
    ///
    /// Returns the first invalid position, or the aggregate-key error.
    pub fn validate(&self) -> Result<(), EthereumLightClientError> {
        for (position, public_key) in self.pubkeys.iter().enumerate() {
            ethereum_bls_pop_validate_public_key(&public_key.0)
                .map_err(|_| EthereumLightClientError::InvalidCommitteePublicKey(position))?;
        }
        ethereum_bls_pop_validate_public_key(&self.aggregate_pubkey.0)
            .map_err(|_| EthereumLightClientError::InvalidCommitteeAggregatePublicKey)
    }
}
/// Official SSZ `SyncAggregate` (`Bitvector[512]` plus one BLS signature).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncAggregate {
    sync_committee_bits: [u8; SYNC_COMMITTEE_BITS_BYTES],
    sync_committee_signature: BlsSignature,
}
impl SyncAggregate {
    /// Construct a fixed-size sync aggregate.
    pub const fn new(
        sync_committee_bits: [u8; SYNC_COMMITTEE_BITS_BYTES],
        sync_committee_signature: BlsSignature,
    ) -> Self {
        Self {
            sync_committee_bits,
            sync_committee_signature,
        }
    }
    /// Return the SSZ bitvector bytes (least-significant bit first per byte).
    pub const fn bits(&self) -> &[u8; SYNC_COMMITTEE_BITS_BYTES] {
        &self.sync_committee_bits
    }
    /// Return the aggregate signature.
    pub const fn signature(&self) -> BlsSignature {
        self.sync_committee_signature
    }
    /// Count participating sync-committee positions.
    pub fn participant_count(&self) -> usize {
        self.sync_committee_bits
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }
    /// Compute the canonical SSZ `hash_tree_root`.
    pub fn hash_tree_root(&self) -> Root {
        hash_nodes(
            &byte_vector_root(&self.sync_committee_bits),
            &self.sync_committee_signature.hash_tree_root(),
        )
    }
}
/// Fork-shaped current sync-committee branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentSyncCommitteeBranch {
    /// Altair through Deneb (`floorlog2(54) == 5`).
    PreElectra([Root; 5]),
    /// Electra and Fulu (`floorlog2(86) == 6`).
    Electra([Root; 6]),
}
impl CurrentSyncCommitteeBranch {
    fn as_slice_for_fork(&self, fork: EthereumFork) -> Result<&[Root], EthereumLightClientError> {
        match (fork.uses_electra_state_layout(), self) {
            (false, Self::PreElectra(branch)) => Ok(branch),
            (true, Self::Electra(branch)) => Ok(branch),
            _ => Err(EthereumLightClientError::CurrentCommitteeBranchForkMismatch),
        }
    }
}
/// Fork-shaped finalized-checkpoint branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityBranch {
    /// Altair through Deneb (`floorlog2(105) == 6`).
    PreElectra([Root; 6]),
    /// Electra and Fulu (`floorlog2(169) == 7`).
    Electra([Root; 7]),
}
impl FinalityBranch {
    fn as_slice_for_fork(&self, fork: EthereumFork) -> Result<&[Root], EthereumLightClientError> {
        match (fork.uses_electra_state_layout(), self) {
            (false, Self::PreElectra(branch)) => Ok(branch),
            (true, Self::Electra(branch)) => Ok(branch),
            _ => Err(EthereumLightClientError::FinalityBranchForkMismatch),
        }
    }
}
/// Fork-shaped next sync-committee branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextSyncCommitteeBranch {
    /// Altair through Deneb (`floorlog2(55) == 5`).
    PreElectra([Root; 5]),
    /// Electra and Fulu (`floorlog2(87) == 6`).
    Electra([Root; 6]),
}
impl NextSyncCommitteeBranch {
    fn as_slice_for_fork(&self, fork: EthereumFork) -> Result<&[Root], EthereumLightClientError> {
        match (fork.uses_electra_state_layout(), self) {
            (false, Self::PreElectra(branch)) => Ok(branch),
            (true, Self::Electra(branch)) => Ok(branch),
            _ => Err(EthereumLightClientError::NextCommitteeBranchForkMismatch),
        }
    }
}
/// Official SSZ `LightClientBootstrap`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LightClientBootstrap {
    /// Header whose beacon state commits to the current committee.
    pub header: LightClientHeader,
    /// Current sync committee committed by the header's beacon state.
    pub current_sync_committee: SyncCommittee,
    /// Fork-shaped current sync-committee branch.
    pub current_sync_committee_branch: CurrentSyncCommitteeBranch,
}
impl LightClientBootstrap {
    /// Check the header, every committee key and the current-committee branch.
    ///
    /// The bootstrap's trust comes from the Parliament that enacts it; this check only proves
    /// that the committee belongs to the header's beacon state.
    ///
    /// # Errors
    ///
    /// Returns an error when the fork layout, a committee key or the branch is invalid.
    pub fn verify(&self, schedule: &ForkSchedule) -> Result<(), EthereumLightClientError> {
        self.header.validate(schedule)?;
        let fork = self.header.fork();
        let branch = self.current_sync_committee_branch.as_slice_for_fork(fork)?;
        if merkle_root_from_branch(
            self.current_sync_committee.hash_tree_root(),
            generalized_indices(fork).current_sync_committee,
            branch,
        ) != Some(self.header.beacon().state_root)
        {
            return Err(EthereumLightClientError::InvalidCurrentCommitteeBranch);
        }
        self.current_sync_committee.validate()
    }
}
/// A next sync committee and its branch in the attested beacon state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NextSyncCommitteeProof {
    /// Next sync committee committed by the attested beacon state.
    pub committee: SyncCommittee,
    /// Fork-shaped next sync-committee branch.
    pub branch: NextSyncCommitteeBranch,
}
/// Finalized SSZ `LightClientUpdate` subset admitted by SCCP.
///
/// The finality branch is mandatory; the next committee is optional (finality updates from
/// `/light_client/finality_update` carry none). The consensus type's zero-filled fields are not
/// accepted as substitutes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LightClientUpdate {
    /// Header signed by the sync committee.
    pub attested_header: LightClientHeader,
    /// Next sync committee committed by the attested beacon state, if carried.
    pub next_sync_committee: Option<NextSyncCommitteeProof>,
    /// Finalized header committed by the attested beacon state.
    pub finalized_header: LightClientHeader,
    /// Fork-shaped finalized-checkpoint branch.
    pub finality_branch: FinalityBranch,
    /// Sync committee participation and aggregate signature.
    pub sync_aggregate: SyncAggregate,
    /// Slot at which the aggregate signature was created.
    pub signature_slot: u64,
}
impl LightClientUpdate {
    /// Period of the committee that must have signed the update.
    pub const fn signature_period(&self) -> u64 {
        sync_committee_period_at_slot(self.signature_slot)
    }
    /// Check everything except the signature: header forks and execution branches, slot order,
    /// the participation threshold, the finality branch and, when present, the next committee
    /// (same-period rule, keys and branch).
    ///
    /// Cheap checks run before key validation.
    ///
    /// # Errors
    ///
    /// Returns the first violated rule.
    pub fn verify_structure(
        &self,
        schedule: &ForkSchedule,
    ) -> Result<(), EthereumLightClientError> {
        let attested_slot = self.attested_header.beacon().slot;
        let finalized_slot = self.finalized_header.beacon().slot;
        if self.signature_slot <= attested_slot || attested_slot < finalized_slot {
            return Err(EthereumLightClientError::InvalidSlotOrder);
        }
        let participants = self.sync_aggregate.participant_count();
        if participants < FINALITY_PARTICIPANT_THRESHOLD {
            return Err(EthereumLightClientError::InsufficientParticipation(
                participants,
            ));
        }
        self.attested_header.validate(schedule)?;
        self.finalized_header.validate(schedule)?;
        let attested_fork = self.attested_header.fork();
        let indices = generalized_indices(attested_fork);
        let finality_branch = self.finality_branch.as_slice_for_fork(attested_fork)?;
        if merkle_root_from_branch(
            self.finalized_header.beacon().hash_tree_root(),
            indices.finalized_root,
            finality_branch,
        ) != Some(self.attested_header.beacon().state_root)
        {
            return Err(EthereumLightClientError::InvalidFinalityBranch);
        }
        if let Some(next) = &self.next_sync_committee {
            if sync_committee_period_at_slot(attested_slot)
                != sync_committee_period_at_slot(finalized_slot)
            {
                return Err(EthereumLightClientError::NextCommitteePeriodMismatch);
            }
            let branch = next.branch.as_slice_for_fork(attested_fork)?;
            if merkle_root_from_branch(
                next.committee.hash_tree_root(),
                indices.next_sync_committee,
                branch,
            ) != Some(self.attested_header.beacon().state_root)
            {
                return Err(EthereumLightClientError::InvalidNextCommitteeBranch);
            }
            next.committee.validate()?;
        }
        Ok(())
    }
    /// Verify the aggregate signature against the committee of `period(signature_slot)`.
    ///
    /// # Errors
    ///
    /// Returns an error when no fork covers the signature domain slot or the fast-aggregate BLS
    /// check fails.
    pub fn verify_signature(
        &self,
        committee: &SyncCommittee,
        schedule: &ForkSchedule,
    ) -> Result<(), EthereumLightClientError> {
        #[expect(
            clippy::large_stack_arrays,
            reason = "The protocol fixes 512 keys; bounded stack scratch avoids unadmitted verifier allocations"
        )]
        let mut selected = [[0; 48]; SYNC_COMMITTEE_SIZE];
        let count =
            selected_participant_public_keys(committee, self.sync_aggregate.bits(), &mut selected);
        let signing_root =
            sync_committee_signing_root(&self.attested_header, self.signature_slot, schedule)?;
        let signature = self.sync_aggregate.signature().to_bytes();
        ethereum_bls_pop_fast_aggregate_verify(&selected[..count], &signing_root, &signature)
            .map_err(|_| EthereumLightClientError::InvalidSyncCommitteeSignature)
    }
}
/// Compute the native Ethereum `DOMAIN_SYNC_COMMITTEE` signing root.
///
/// The fork version is selected at `max(signature_slot, 1) - 1`, exactly as in
/// the consensus light-client specification. The returned root is
/// `hash_tree_root(SigningData{hash_tree_root(attested.beacon), domain})`.
///
/// # Errors
///
/// Returns an error when the schedule has no supported fork at the
/// signature domain's previous slot.
pub fn sync_committee_signing_root(
    attested_header: &LightClientHeader,
    signature_slot: u64,
    schedule: &ForkSchedule,
) -> Result<Root, EthereumLightClientError> {
    let fork_version_slot = signature_slot.max(1) - 1;
    let (_, activation) = schedule.fork_at_slot(fork_version_slot)?;
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        activation.version,
        schedule.genesis_validators_root,
    );
    Ok(hash_nodes(
        &attested_header.beacon().hash_tree_root(),
        &domain,
    ))
}
/// Compute an Ethereum consensus signature domain.
pub fn compute_domain(
    domain_type: [u8; 4],
    fork_version: [u8; 4],
    genesis_validators_root: Root,
) -> Root {
    let fork_data_root = hash_nodes(&byte_vector_root(&fork_version), &genesis_validators_root);
    let mut domain = [0; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}
fn selected_participant_public_keys(
    committee: &SyncCommittee,
    bits: &[u8; SYNC_COMMITTEE_BITS_BYTES],
    selected: &mut [[u8; 48]; SYNC_COMMITTEE_SIZE],
) -> usize {
    let mut count = 0;
    for (position, public_key) in committee.pubkeys.iter().enumerate() {
        let mask = 1_u8 << (position % 8);
        if bits[position / 8] & mask != 0 {
            selected[count] = public_key.to_bytes();
            count += 1;
        }
    }
    count
}
/// SSZ node hash: `sha256(left ‖ right)`.
pub fn hash_nodes(left: &Root, right: &Root) -> Root {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
fn uint64_root(value: u64) -> Root {
    let mut root = ZERO_ROOT;
    root[..8].copy_from_slice(&value.to_le_bytes());
    root
}
fn usize_root(value: usize) -> Root {
    let mut root = ZERO_ROOT;
    let bytes = value.to_le_bytes();
    root[..bytes.len()].copy_from_slice(&bytes);
    root
}
fn byte_vector_root(bytes: &[u8]) -> Root {
    let chunks = bytes.chunks(32).map(|chunk| {
        let mut root = ZERO_ROOT;
        root[..chunk.len()].copy_from_slice(chunk);
        root
    });
    merkleize_iter(chunks, bytes.len().div_ceil(32))
}
/// SSZ `merkleize` of `leaves`, padded with zero roots to the next power of two.
/// The binary frontier has a fixed native-word depth and allocates no heap backing.
pub fn merkleize(leaves: &[Root]) -> Root {
    merkleize_iter(leaves.iter().copied(), leaves.len())
}
fn merkleize_iter(leaves: impl Iterator<Item = Root>, count: usize) -> Root {
    if count == 0 {
        return ZERO_ROOT;
    }
    // A realizable byte/root slice is bounded by isize::MAX, so this rounding
    // cannot overflow usize for the concrete callers above.
    let width = count.next_power_of_two();
    let mut frontier = [ZERO_ROOT; usize::BITS as usize];
    for (index, mut node) in leaves
        .chain(std::iter::repeat(ZERO_ROOT))
        .take(width)
        .enumerate()
    {
        let mut position = index;
        let mut height = 0;
        while position & 1 == 1 {
            node = hash_nodes(&frontier[height], &node);
            position >>= 1;
            height += 1;
        }
        frontier[height] = node;
    }
    frontier[width.trailing_zeros() as usize]
}
/// Recompute the root proven by a single-leaf SSZ branch at generalized index `gindex`.
///
/// Returns `None` when the branch length differs from `floorlog2(gindex)`.
pub fn merkle_root_from_branch(leaf: Root, gindex: u64, branch: &[Root]) -> Option<Root> {
    if gindex < 2 {
        return None;
    }
    let depth = (u64::BITS - 1 - gindex.leading_zeros()) as usize;
    if branch.len() != depth {
        return None;
    }
    let mut root = leaf;
    for (height, sibling) in branch.iter().enumerate() {
        root = if (gindex >> height) & 1 == 0 {
            hash_nodes(&root, sibling)
        } else {
            hash_nodes(sibling, &root)
        };
    }
    Some(root)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    const GENERATOR_PUBLIC_KEY: [u8; 48] = [
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac,
        0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b,
        0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb,
        0x22, 0xc6, 0xbb,
    ];
    const FIXTURE_SIGNING_ROOT: Root = [
        0xd1, 0xeb, 0x73, 0x73, 0xa5, 0x5d, 0x8b, 0xf6, 0xd5, 0x10, 0x0d, 0x75, 0x36, 0x3d, 0x1d,
        0x01, 0x27, 0x22, 0xfe, 0x73, 0x57, 0x24, 0xd2, 0x3d, 0xc2, 0x39, 0x4a, 0x77, 0xc2, 0x5d,
        0xe8, 0xe9,
    ];
    // Standard POP-DST signature by secret key 1, added 342 times for 342
    // duplicate committee positions over `FIXTURE_SIGNING_ROOT`.
    const FIXTURE_AGGREGATE_SIGNATURE: [u8; 96] = [
        0xa6, 0x49, 0x4c, 0x5b, 0xc8, 0x3e, 0x50, 0xc9, 0x35, 0xa9, 0xb5, 0xac, 0x35, 0x8d, 0x53,
        0x24, 0x03, 0xad, 0x21, 0x6d, 0xad, 0xcb, 0x9e, 0xe8, 0x20, 0x9e, 0x43, 0xb1, 0x81, 0x6c,
        0xe1, 0xca, 0x50, 0x18, 0x42, 0x32, 0x14, 0xf2, 0x9e, 0x8a, 0x02, 0xfc, 0x9e, 0xa4, 0x3d,
        0xeb, 0x66, 0x6f, 0x01, 0x27, 0x6c, 0xb7, 0x9b, 0x6b, 0xcf, 0xdc, 0xb8, 0xf0, 0xcc, 0xf7,
        0x85, 0x0c, 0xa2, 0xb5, 0xc0, 0xc0, 0x5d, 0x14, 0x29, 0x65, 0x08, 0x38, 0xe2, 0xa4, 0xa8,
        0xa9, 0x01, 0xfd, 0x89, 0x7f, 0xca, 0x47, 0x82, 0x5d, 0xaa, 0x51, 0xc0, 0x13, 0x7a, 0xa5,
        0xb8, 0x66, 0x71, 0x96, 0xc9, 0x1a,
    ];
    fn root(tag: u8) -> Root {
        [tag; 32]
    }
    fn schedule_with_epochs(epochs: [u64; 6]) -> ForkSchedule {
        ForkSchedule::new(
            root(0xa5),
            [
                ForkActivation::new(epochs[0], [1, 0, 0, 0]),
                ForkActivation::new(epochs[1], [2, 0, 0, 0]),
                ForkActivation::new(epochs[2], [3, 0, 0, 0]),
                ForkActivation::new(epochs[3], [4, 0, 0, 0]),
                ForkActivation::new(epochs[4], [5, 0, 0, 0]),
                ForkActivation::new(epochs[5], [6, 0, 0, 0]),
            ],
        )
        .expect("valid test schedule")
    }
    fn altair_schedule() -> ForkSchedule {
        schedule_with_epochs([0, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX])
    }
    #[expect(
        clippy::large_stack_arrays,
        reason = "This test constructs the same fixed 512-key stack representation as the verifier"
    )]
    fn committee(public_key: [u8; 48]) -> SyncCommittee {
        SyncCommittee::new(
            &[BlsPublicKey::new(public_key); SYNC_COMMITTEE_SIZE],
            BlsPublicKey::new(public_key),
        )
    }
    fn sparse_node(gindex: u64, max_depth: usize, explicit: &BTreeMap<u64, Root>) -> Root {
        if let Some(value) = explicit.get(&gindex) {
            return *value;
        }
        let depth = (u64::BITS - 1 - gindex.leading_zeros()) as usize;
        if depth == max_depth {
            return ZERO_ROOT;
        }
        hash_nodes(
            &sparse_node(gindex * 2, max_depth, explicit),
            &sparse_node(gindex * 2 + 1, max_depth, explicit),
        )
    }
    fn sparse_branch(target: u64, max_depth: usize, explicit: &BTreeMap<u64, Root>) -> Vec<Root> {
        let depth = (u64::BITS - 1 - target.leading_zeros()) as usize;
        let mut branch = Vec::with_capacity(depth);
        let mut node = target;
        for _ in 0..depth {
            branch.push(sparse_node(node ^ 1, max_depth, explicit));
            node >>= 1;
        }
        branch
    }
    fn altair_header(slot: u64, state_root: Root) -> LightClientHeader {
        LightClientHeader::Altair {
            beacon: BeaconBlockHeader {
                slot,
                proposer_index: slot + 10,
                parent_root: root(0x31),
                state_root,
                body_root: root(0x32),
            },
        }
    }
    fn altair_bootstrap(current: &SyncCommittee) -> LightClientBootstrap {
        let mut explicit = BTreeMap::new();
        explicit.insert(
            CURRENT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA,
            current.hash_tree_root(),
        );
        let state_root = sparse_node(1, 5, &explicit);
        let branch: [Root; 5] =
            sparse_branch(CURRENT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA, 5, &explicit)
                .try_into()
                .expect("current branch length");
        LightClientBootstrap {
            header: altair_header(1, state_root),
            current_sync_committee: *current,
            current_sync_committee_branch: CurrentSyncCommitteeBranch::PreElectra(branch),
        }
    }
    fn participant_bits(count: usize) -> [u8; SYNC_COMMITTEE_BITS_BYTES] {
        let mut bits = [0; SYNC_COMMITTEE_BITS_BYTES];
        for position in 0..count {
            bits[position / 8] |= 1 << (position % 8);
        }
        bits
    }
    fn unsigned_update(
        finalized_slot: u64,
        attested_slot: u64,
        signature_slot: u64,
        next: &SyncCommittee,
        signature: [u8; 96],
    ) -> LightClientUpdate {
        let finalized_header = altair_header(finalized_slot, root(0x41));
        let mut explicit = BTreeMap::new();
        explicit.insert(
            FINALIZED_ROOT_GINDEX_PRE_ELECTRA,
            finalized_header.beacon().hash_tree_root(),
        );
        explicit.insert(
            NEXT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA,
            next.hash_tree_root(),
        );
        let state_root = sparse_node(1, 6, &explicit);
        let attested_header = altair_header(attested_slot, state_root);
        let finality_branch: [Root; 6] =
            sparse_branch(FINALIZED_ROOT_GINDEX_PRE_ELECTRA, 6, &explicit)
                .try_into()
                .expect("finality branch length");
        let next_branch: [Root; 5] =
            sparse_branch(NEXT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA, 6, &explicit)
                .try_into()
                .expect("next branch length");
        LightClientUpdate {
            attested_header,
            next_sync_committee: Some(NextSyncCommitteeProof {
                committee: *next,
                branch: NextSyncCommitteeBranch::PreElectra(next_branch),
            }),
            finalized_header,
            finality_branch: FinalityBranch::PreElectra(finality_branch),
            sync_aggregate: SyncAggregate::new(
                participant_bits(FINALITY_PARTICIPANT_THRESHOLD),
                BlsSignature::new(signature),
            ),
            signature_slot,
        }
    }
    fn blank_capella_execution() -> CapellaExecutionPayloadHeader {
        CapellaExecutionPayloadHeader {
            parent_hash: root(1),
            fee_recipient: [2; 20],
            state_root: root(3),
            receipts_root: root(4),
            logs_bloom: [5; 256],
            prev_randao: root(6),
            block_number: 7,
            gas_limit: 8,
            gas_used: 9,
            timestamp: 10,
            extra_data: ExtraData::new(vec![11, 12]).expect("bounded extra data"),
            base_fee_per_gas: root(13),
            block_hash: root(14),
            transactions_root: root(15),
            withdrawals_root: root(16),
        }
    }
    fn blank_deneb_execution() -> DenebExecutionPayloadHeader {
        DenebExecutionPayloadHeader {
            capella: blank_capella_execution(),
            blob_gas_used: 17,
            excess_blob_gas: 18,
        }
    }
    #[test]
    fn generalized_indices_switch_only_at_electra() {
        assert_eq!(
            generalized_indices(EthereumFork::Deneb),
            LightClientGeneralizedIndices {
                finalized_root: 105,
                current_sync_committee: 54,
                next_sync_committee: 55,
            }
        );
        assert_eq!(
            generalized_indices(EthereumFork::Electra),
            LightClientGeneralizedIndices {
                finalized_root: 169,
                current_sync_committee: 86,
                next_sync_committee: 87,
            }
        );
        assert_eq!(
            generalized_indices(EthereumFork::Fulu),
            generalized_indices(EthereumFork::Electra)
        );
        assert_eq!(sync_committee_period_at_slot(8_191), 0);
        assert_eq!(sync_committee_period_at_slot(8_192), 1);
    }
    #[test]
    fn ssz_roots_match_official_consensus_spec_vectors() {
        let beacon_header = BeaconBlockHeader {
            slot: 16_101_738_745_833_384_750,
            proposer_index: 15_310_703_651_237_606_601,
            parent_root: [
                0xca, 0xf0, 0xdb, 0x22, 0x47, 0x0a, 0x8e, 0x98, 0x7f, 0xef, 0x3d, 0x78, 0xce, 0x7a,
                0x14, 0xbb, 0xd7, 0x71, 0x45, 0x70, 0xb7, 0x8d, 0x5d, 0x5b, 0xc4, 0x42, 0x1e, 0xa2,
                0xb6, 0x57, 0xf9, 0x86,
            ],
            state_root: [
                0x77, 0x13, 0x4d, 0xe1, 0xd4, 0xdc, 0x7a, 0x8f, 0xfb, 0x09, 0x8e, 0x30, 0x5a, 0xe5,
                0xcc, 0xfb, 0x7c, 0xb2, 0x7c, 0xba, 0x58, 0x66, 0x71, 0x2f, 0x95, 0x75, 0x6d, 0xdb,
                0xc0, 0x44, 0xd3, 0x28,
            ],
            body_root: [
                0x93, 0x4a, 0xf8, 0x49, 0x56, 0xd1, 0xa2, 0x52, 0xaa, 0x76, 0x74, 0x06, 0xa8, 0xba,
                0xe9, 0xe2, 0x6b, 0x08, 0x3a, 0x81, 0xbe, 0x4b, 0x17, 0x03, 0xf1, 0x57, 0xa7, 0x0a,
                0xbc, 0xfb, 0x60, 0x85,
            ],
        };
        assert_eq!(
            beacon_header.hash_tree_root(),
            [
                0xa2, 0x67, 0x27, 0x69, 0x76, 0x3d, 0x19, 0xc7, 0x9d, 0xd7, 0xa5, 0x84, 0xf3, 0x7f,
                0xd3, 0x39, 0x1c, 0x05, 0x10, 0xc1, 0xfd, 0x6e, 0xba, 0x54, 0xec, 0x0c, 0xd7, 0x87,
                0x48, 0xa8, 0x48, 0x00,
            ]
        );
        let aggregate = SyncAggregate::new(
            [
                0x1a, 0x3c, 0x06, 0x9c, 0xd6, 0x2b, 0x40, 0x60, 0x7c, 0x5c, 0xff, 0xe6, 0xc1, 0xa4,
                0x49, 0x5e, 0x35, 0xa5, 0x92, 0xa4, 0x02, 0xc4, 0x48, 0x7e, 0x7a, 0xfc, 0x06, 0xa7,
                0x2a, 0x94, 0x52, 0xe1, 0xb9, 0x95, 0xb1, 0x6a, 0x15, 0xb8, 0x50, 0x8e, 0xe3, 0x56,
                0xec, 0xfa, 0xcd, 0x08, 0xc1, 0xa0, 0x6c, 0x7a, 0x03, 0xd6, 0x19, 0xd5, 0x5c, 0x9e,
                0x45, 0x3d, 0x14, 0xf3, 0xcf, 0x6f, 0x7e, 0x01,
            ],
            BlsSignature::new([
                0xf9, 0x8c, 0xbd, 0x1e, 0x49, 0x57, 0xd4, 0xb2, 0xd7, 0xdd, 0x0f, 0x50, 0x9e, 0x5e,
                0xe1, 0x56, 0x85, 0x91, 0xe5, 0x67, 0x44, 0xfe, 0xe3, 0x1d, 0x24, 0x48, 0xc9, 0xcb,
                0x81, 0xbe, 0xc4, 0x2d, 0x49, 0xc8, 0x06, 0xd8, 0xb0, 0xef, 0x8f, 0x18, 0x76, 0xb0,
                0x6c, 0xb0, 0xe1, 0xdd, 0xd9, 0xcf, 0x37, 0x82, 0x3a, 0xee, 0xc1, 0x55, 0xb0, 0x51,
                0x93, 0x0b, 0x36, 0x49, 0x50, 0xab, 0xa8, 0x5c, 0x9d, 0x96, 0x51, 0x2a, 0x7c, 0x42,
                0x15, 0x11, 0x8a, 0x5f, 0xba, 0x5f, 0x8e, 0x80, 0x49, 0xed, 0xb4, 0x71, 0xa8, 0x4d,
                0xed, 0x72, 0xc2, 0x65, 0xa7, 0x7b, 0x08, 0x2b, 0x35, 0x48, 0x40, 0x24,
            ]),
        );
        assert_eq!(
            aggregate.hash_tree_root(),
            [
                0xa9, 0x4d, 0x16, 0x49, 0x1c, 0x1a, 0x75, 0x69, 0x9d, 0x1b, 0xb7, 0xed, 0x7e, 0x37,
                0x79, 0x68, 0xfd, 0x99, 0xd7, 0x7c, 0x77, 0x13, 0xb2, 0xc1, 0xae, 0x13, 0x5f, 0x26,
                0x7b, 0x10, 0x70, 0xa6,
            ]
        );
    }
    #[test]
    fn fork_schedule_is_closed_ordered_and_validated() {
        assert_eq!(
            ForkSchedule::new(root(1), [ForkActivation::new(0, [0; 4]); 6]),
            Err(EthereumLightClientError::InvalidForkSchedule(
                "fork versions must be unique"
            ))
        );
        let mut activations = [ForkActivation::new(0, [0; 4]); 6];
        for (index, activation) in activations.iter_mut().enumerate() {
            let index = u8::try_from(index).expect("six fork activations fit in u8");
            *activation = ForkActivation::new(u64::from(index), [index, 0, 0, 1]);
        }
        activations[3] = ForkActivation::new(1, [3, 0, 0, 1]);
        assert_eq!(
            ForkSchedule::new(root(1), activations),
            Err(EthereumLightClientError::InvalidForkSchedule(
                "activation epochs must be nondecreasing"
            ))
        );
        assert_eq!(
            ForkSchedule::new(ZERO_ROOT, [ForkActivation::new(0, [1, 0, 0, 0]); 6]),
            Err(EthereumLightClientError::ZeroGenesisValidatorsRoot)
        );
        let schedule = schedule_with_epochs([1, 2, 3, 4, 5, 6]);
        assert_eq!(
            schedule.fork_at_slot(0),
            Err(EthereumLightClientError::UnsupportedSlot(0))
        );
        assert_eq!(
            schedule
                .fork_at_slot(6 * SLOTS_PER_EPOCH)
                .map(|(fork, _)| fork),
            Ok(EthereumFork::Fulu)
        );
        assert_eq!(schedule.activations()[2].epoch(), 3);
        assert_eq!(
            schedule.activation(EthereumFork::Deneb).version(),
            [4, 0, 0, 0]
        );
    }
    #[test]
    fn execution_header_is_bound_at_gindex_25() {
        let schedule = schedule_with_epochs([0, 1, 2, u64::MAX, u64::MAX, u64::MAX]);
        let execution = blank_capella_execution();
        let branch = [root(21), root(22), root(23), root(24)];
        let body_root = merkle_root_from_branch(
            execution.hash_tree_root(),
            EXECUTION_PAYLOAD_GINDEX,
            &branch,
        )
        .expect("fixed execution branch");
        let header = LightClientHeader::Capella {
            beacon: BeaconBlockHeader {
                slot: 2 * SLOTS_PER_EPOCH,
                proposer_index: 1,
                parent_root: root(25),
                state_root: root(26),
                body_root,
            },
            execution,
            execution_branch: branch,
        };
        // Consensus-spec Capella `LightClientHeader` is a three-field SSZ
        // container.  Its fourth padded leaf is zero; `execution` must not be
        // duplicated (which would produce a different root while leaving the
        // execution-payload branch itself apparently valid).
        let expected_header_root = hash_nodes(
            &hash_nodes(
                &header.beacon().hash_tree_root(),
                &blank_capella_execution().hash_tree_root(),
            ),
            &hash_nodes(&merkleize(&branch), &ZERO_ROOT),
        );
        assert_eq!(header.hash_tree_root(), expected_header_root);
        header.validate(&schedule).expect("valid execution branch");
        let block = header
            .authenticated_execution_block()
            .expect("Capella carries execution");
        assert_eq!(block.block_number, 7);
        assert_eq!(block.timestamp, 10);
        assert_eq!(block.parent_hash, root(1));
        let mut tampered = header;
        if let LightClientHeader::Capella { beacon, .. } = &mut tampered {
            beacon.body_root[0] ^= 1;
        }
        assert_eq!(
            tampered.validate(&schedule),
            Err(EthereumLightClientError::InvalidExecutionBranch)
        );
        let wrong_variant = altair_header(2 * SLOTS_PER_EPOCH, root(2));
        assert_eq!(
            wrong_variant.validate(&schedule),
            Err(EthereumLightClientError::HeaderForkMismatch {
                expected: EthereumFork::Capella,
                actual: EthereumFork::Altair,
            })
        );
        assert!(wrong_variant.authenticated_execution_block().is_none());
    }
    #[test]
    fn deneb_execution_root_extends_capella_leaves() {
        let deneb = blank_deneb_execution();
        let mut leaves = [ZERO_ROOT; 17];
        leaves[..15].copy_from_slice(&deneb.capella.leaves());
        leaves[15] = uint64_root(17);
        leaves[16] = uint64_root(18);
        assert_eq!(deneb.hash_tree_root(), merkleize(&leaves));
        assert_ne!(deneb.hash_tree_root(), deneb.capella.hash_tree_root());
    }
    #[test]
    fn electra_bootstrap_requires_the_electra_branch_shape_and_gindex() {
        let schedule = schedule_with_epochs([0, 0, 0, 0, 0, u64::MAX]);
        let current = committee(GENERATOR_PUBLIC_KEY);
        let mut explicit = BTreeMap::new();
        explicit.insert(
            CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA,
            current.hash_tree_root(),
        );
        let state_root = sparse_node(1, 6, &explicit);
        let execution = blank_deneb_execution();
        let execution_branch = [root(71), root(72), root(73), root(74)];
        let body_root = merkle_root_from_branch(
            execution.hash_tree_root(),
            EXECUTION_PAYLOAD_GINDEX,
            &execution_branch,
        )
        .expect("fixed execution branch");
        let header = LightClientHeader::Electra {
            beacon: BeaconBlockHeader {
                slot: 1,
                proposer_index: 2,
                parent_root: root(75),
                state_root,
                body_root,
            },
            execution,
            execution_branch,
        };
        let branch: [Root; 6] = sparse_branch(CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA, 6, &explicit)
            .try_into()
            .expect("Electra current branch length");
        LightClientBootstrap {
            header,
            current_sync_committee: current,
            current_sync_committee_branch: CurrentSyncCommitteeBranch::Electra(branch),
        }
        .verify(&schedule)
        .expect("Electra bootstrap validates with gindex 86");
        assert_eq!(
            LightClientBootstrap {
                header,
                current_sync_committee: current,
                current_sync_committee_branch: CurrentSyncCommitteeBranch::PreElectra(
                    [ZERO_ROOT; 5],
                ),
            }
            .verify(&schedule),
            Err(EthereumLightClientError::CurrentCommitteeBranchForkMismatch)
        );
    }
    #[test]
    fn extra_data_bound_is_strict() {
        assert!(ExtraData::new(vec![0; 32]).is_ok());
        assert_eq!(
            ExtraData::new(vec![0; 33]),
            Err(EthereumLightClientError::ExtraDataTooLong(33))
        );
        assert_eq!(
            ExtraData::new(vec![1, 2]).expect("bounded").as_slice(),
            &[1, 2]
        );
    }
    #[test]
    fn bootstrap_rejects_wrong_branch_and_key() {
        let schedule = altair_schedule();
        let bootstrap = altair_bootstrap(&committee(GENERATOR_PUBLIC_KEY));
        bootstrap.verify(&schedule).expect("valid bootstrap");
        let mut wrong_branch = bootstrap;
        wrong_branch.current_sync_committee_branch =
            CurrentSyncCommitteeBranch::PreElectra([ZERO_ROOT; 5]);
        assert_eq!(
            wrong_branch.verify(&schedule),
            Err(EthereumLightClientError::InvalidCurrentCommitteeBranch)
        );
        let invalid = altair_bootstrap(&committee([0xff; 48]));
        assert_eq!(
            invalid.verify(&schedule),
            Err(EthereumLightClientError::InvalidCommitteePublicKey(0))
        );
    }
    #[test]
    fn update_structure_rejects_threshold_slot_and_branch_attacks() {
        let schedule = altair_schedule();
        let mut update = unsigned_update(2, 3, 4, &committee(GENERATOR_PUBLIC_KEY), [0; 96]);
        update.verify_structure(&schedule).expect("valid structure");
        update.sync_aggregate = SyncAggregate::new(
            participant_bits(FINALITY_PARTICIPANT_THRESHOLD - 1),
            BlsSignature::new([0; 96]),
        );
        assert_eq!(
            update.verify_structure(&schedule),
            Err(EthereumLightClientError::InsufficientParticipation(341))
        );
        update.sync_aggregate = SyncAggregate::new(
            participant_bits(FINALITY_PARTICIPANT_THRESHOLD),
            BlsSignature::new([0; 96]),
        );
        update.signature_slot = update.attested_header.beacon().slot;
        assert_eq!(
            update.verify_structure(&schedule),
            Err(EthereumLightClientError::InvalidSlotOrder)
        );
        let finalized_after_attested =
            unsigned_update(4, 3, 5, &committee(GENERATOR_PUBLIC_KEY), [0; 96]);
        assert_eq!(
            finalized_after_attested.verify_structure(&schedule),
            Err(EthereumLightClientError::InvalidSlotOrder)
        );
        let mut bad_branch = unsigned_update(2, 3, 4, &committee(GENERATOR_PUBLIC_KEY), [0; 96]);
        if let FinalityBranch::PreElectra(branch) = &mut bad_branch.finality_branch {
            branch[0][0] ^= 1;
        }
        assert_eq!(
            bad_branch.verify_structure(&schedule),
            Err(EthereumLightClientError::InvalidFinalityBranch)
        );
        let mut wrong_shape = unsigned_update(2, 3, 4, &committee(GENERATOR_PUBLIC_KEY), [0; 96]);
        wrong_shape.finality_branch = FinalityBranch::Electra([ZERO_ROOT; 7]);
        assert_eq!(
            wrong_shape.verify_structure(&schedule),
            Err(EthereumLightClientError::FinalityBranchForkMismatch)
        );
        let mut bad_next_branch =
            unsigned_update(2, 3, 4, &committee(GENERATOR_PUBLIC_KEY), [0; 96]);
        if let Some(NextSyncCommitteeProof {
            branch: NextSyncCommitteeBranch::PreElectra(branch),
            ..
        }) = &mut bad_next_branch.next_sync_committee
        {
            branch[0][0] ^= 1;
        }
        assert_eq!(
            bad_next_branch.verify_structure(&schedule),
            Err(EthereumLightClientError::InvalidNextCommitteeBranch)
        );
        let invalid_key_update = unsigned_update(2, 3, 4, &committee([0xff; 48]), [0; 96]);
        assert_eq!(
            invalid_key_update.verify_structure(&schedule),
            Err(EthereumLightClientError::InvalidCommitteePublicKey(0))
        );
        let mut next_shape = unsigned_update(2, 3, 4, &committee(GENERATOR_PUBLIC_KEY), [0; 96]);
        if let Some(next) = &mut next_shape.next_sync_committee {
            next.branch = NextSyncCommitteeBranch::Electra([ZERO_ROOT; 6]);
        }
        assert_eq!(
            next_shape.verify_structure(&schedule),
            Err(EthereumLightClientError::NextCommitteeBranchForkMismatch)
        );
    }
    #[test]
    fn next_committee_requires_attested_and_finalized_in_one_period() {
        let schedule = altair_schedule();
        let boundary = SLOTS_PER_SYNC_COMMITTEE_PERIOD;
        let crossing = unsigned_update(
            boundary - 1,
            boundary,
            boundary + 1,
            &committee(GENERATOR_PUBLIC_KEY),
            [0; 96],
        );
        assert_eq!(
            crossing.verify_structure(&schedule),
            Err(EthereumLightClientError::NextCommitteePeriodMismatch)
        );
        let mut without_next = crossing;
        without_next.next_sync_committee = None;
        without_next
            .verify_structure(&schedule)
            .expect("a finality-only update may cross a period boundary");
    }
    #[test]
    fn exact_threshold_update_with_duplicate_positions_verifies() {
        let schedule = altair_schedule();
        let bootstrap = altair_bootstrap(&committee(GENERATOR_PUBLIC_KEY));
        let update = unsigned_update(
            2,
            3,
            4,
            &committee(GENERATOR_PUBLIC_KEY),
            FIXTURE_AGGREGATE_SIGNATURE,
        );
        assert_eq!(
            update.sync_aggregate.participant_count(),
            FINALITY_PARTICIPANT_THRESHOLD
        );
        assert_eq!(update.signature_period(), 0);
        update.verify_structure(&schedule).expect("valid structure");
        update
            .verify_signature(&bootstrap.current_sync_committee, &schedule)
            .expect("342 duplicate positions form a valid aggregate");
        let mut wrong_signature = update;
        wrong_signature.sync_aggregate = SyncAggregate::new(
            participant_bits(343),
            BlsSignature::new(FIXTURE_AGGREGATE_SIGNATURE),
        );
        assert_eq!(
            wrong_signature.verify_signature(&bootstrap.current_sync_committee, &schedule),
            Err(EthereumLightClientError::InvalidSyncCommitteeSignature)
        );
        let wrong_fork_version =
            schedule_with_epochs([0, 0, u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        // Bellatrix at genesis changes the domain, so the Altair-domain aggregate fails.
        let mut bellatrix = update;
        bellatrix.attested_header = LightClientHeader::Bellatrix {
            beacon: *bellatrix.attested_header.beacon(),
        };
        assert_eq!(
            bellatrix.verify_signature(&bootstrap.current_sync_committee, &wrong_fork_version),
            Err(EthereumLightClientError::InvalidSyncCommitteeSignature)
        );
    }
    #[test]
    fn signing_root_uses_previous_slot_fork_and_genesis_root() {
        let schedule = schedule_with_epochs([0, 1, u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        let header = LightClientHeader::Altair {
            beacon: BeaconBlockHeader {
                slot: 31,
                ..BeaconBlockHeader::default()
            },
        };
        let at_boundary = sync_committee_signing_root(&header, 32, &schedule)
            .expect("previous slot remains Altair");
        let after_boundary = sync_committee_signing_root(&header, 33, &schedule)
            .expect("previous slot selects Bellatrix");
        assert_ne!(at_boundary, after_boundary);
        let other_schedule =
            ForkSchedule::new(root(0xa6), schedule.activations).expect("second schedule");
        assert_ne!(
            at_boundary,
            sync_committee_signing_root(&header, 32, &other_schedule)
                .expect("different genesis root")
        );
    }
    #[test]
    fn fixture_signing_root_is_stable() {
        let update = unsigned_update(2, 3, 4, &committee(GENERATOR_PUBLIC_KEY), [0; 96]);
        let signing_root = sync_committee_signing_root(
            &update.attested_header,
            update.signature_slot,
            &altair_schedule(),
        )
        .expect("fixture root");
        assert_eq!(signing_root, FIXTURE_SIGNING_ROOT);
    }
    #[test]
    fn merkle_helpers_reject_bad_branch_lengths() {
        assert_eq!(merkle_root_from_branch(root(1), 1, &[]), None);
        assert_eq!(merkle_root_from_branch(root(1), 5, &[root(2)]), None);
        let branch = [root(2), root(3)];
        let proven = merkle_root_from_branch(root(1), 5, &branch).expect("depth 2");
        assert_eq!(
            proven,
            hash_nodes(&hash_nodes(&root(2), &root(1)), &root(3))
        );
        assert_eq!(merkleize(&[]), ZERO_ROOT);
        assert_eq!(merkleize(&[root(9)]), root(9));
    }
}
