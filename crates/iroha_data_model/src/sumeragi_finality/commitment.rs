//! Current consensus result commitments shared by execution and independent proof readers.
use super::{EpochValidationScope, NativeLaneStateProof, ScheduleOutcome};
use crate::{
    block::execution_output::ExecutionOutputV1, events::EventBox,
    parameter::system::SumeragiParameters, transaction::signed::TransactionEntrypoint,
};
use crate::{
    consensus::FinalizedGlobalThresholdBeaconPulseV1, parameter::system::ConsensusMode,
    sumeragi::epoch::BeaconEpochBindingV1,
};
use iroha_crypto::{Hash, MerkleTreeCommitment};
use iroha_sumeragi::{
    api::ConfigError,
    pacemaker::{FRAME_OVERHEAD, validate_chain},
    types::{ChainParams, Hash32},
};
use norito::{
    NoritoDeserialize, NoritoSerialize,
    derive::{JsonDeserialize, JsonSerialize},
};
use thiserror::Error;
/// Largest consensus frame every node's transport accepts, the chain-wide bound that on-chain
/// chain parameters are validated against (§9.4, O10): 16 MiB of payload plus the core's frame
/// overhead. It is a protocol constant, not node configuration, so validation is deterministic;
/// it is the driver's default frame limit.
// TODO(X.2): a payload limit above `CHAIN_TRANSPORT_FRAME_LIMIT - 2 * FRAME_OVERHEAD`
// (16,512,992 bytes) passes this validation but leaves no `sync_max_bytes` that both serves
// the block and fits this frame limit, so no node can start. Raise the frame limits for the
// 16 MiB payload default and reject such parameters here
// (`specs/zk_resource_contract.json`, `committed_payload_has_a_feasible_sync_setting`).
pub const CHAIN_TRANSPORT_FRAME_LIMIT: u64 = 16 * 1024 * 1024 + FRAME_OVERHEAD as u64;

/// Chain parameters of one height as stored in World and committed in `R` (§10.1, §12.4): the
/// Norito and JSON form of the core's [`ChainParams`].
#[derive(norito::NoritoSchema, iroha_schema::IntoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::ChainParamsRecord")]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
)]
pub struct ChainParamsRecord {
    /// Target block time in milliseconds (`block_cadence_ms`).
    pub block_time_ms: u64,
    /// Bounded payload rebuild retry interval in milliseconds.
    pub payload_retry_interval_ms: u64,
    /// Execution budget `E_max` in milliseconds.
    pub exec_budget_ms: u64,
    /// Apply budget `A_max` in milliseconds.
    pub apply_budget_ms: u64,
    /// Largest block payload in bytes.
    pub max_block_bytes: u32,
    /// Epoch length in heights.
    pub epoch_length_blocks: u64,
}

impl ChainParamsRecord {
    /// The chain parameters the on-chain Sumeragi parameters define.
    #[must_use]
    pub fn from_parameters(params: &SumeragiParameters) -> Self {
        Self {
            block_time_ms: params.block_cadence_ms.get(),
            payload_retry_interval_ms: params.payload_retry_interval_ms.get(),
            exec_budget_ms: params.exec_budget_ms.get(),
            apply_budget_ms: params.apply_budget_ms.get(),
            max_block_bytes: params.max_block_bytes.get(),
            epoch_length_blocks: params.epoch_length_blocks.get(),
        }
    }

    /// The core's chain parameters.
    #[must_use]
    pub fn to_core(&self) -> ChainParams {
        ChainParams {
            block_time: self.block_time_ms,
            payload_retry_interval: self.payload_retry_interval_ms,
            e_max: self.exec_budget_ms,
            a_max: self.apply_budget_ms,
            max_block_bytes: self.max_block_bytes,
            epoch_length: self.epoch_length_blocks,
        }
    }

    /// The record of the core's chain parameters.
    #[must_use]
    pub fn from_core(params: &ChainParams) -> Self {
        Self {
            block_time_ms: params.block_time,
            payload_retry_interval_ms: params.payload_retry_interval,
            exec_budget_ms: params.e_max,
            apply_budget_ms: params.a_max,
            max_block_bytes: params.max_block_bytes,
            epoch_length_blocks: params.epoch_length,
        }
    }

    /// §9.4 validation against [`CHAIN_TRANSPORT_FRAME_LIMIT`].
    ///
    /// # Errors
    /// The first violated rule.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_chain(&self.to_core(), CHAIN_TRANSPORT_FRAME_LIMIT)
    }
}

/// Domain tag of `R` (§4.1).
pub const RESULT_TAG: &[u8] = b"iroha/sumeragi/result/v1";

/// Hard bound for the canonical result preimage, including complete bounded epoch contexts.
pub const MAX_RESULT_PREIMAGE_BYTES: usize = 64 * 1024;

/// The chain hash `H` (§1): `iroha_crypto::Hash` as a core [`Hash32`].
#[must_use]
pub fn chain_hash(bytes: &[u8]) -> Hash32 {
    Hash32(<[u8; 32]>::from(Hash::new(bytes)))
}

/// `R` of a canonical result preimage: `H(RESULT_TAG ‖ preimage)`.
/// Streams the domain and borrowed preimage without allocating a second payload buffer.
#[must_use]
pub fn result_of_preimage(preimage: &[u8]) -> Hash32 {
    Hash32(Hash::new_from_chunks(&[RESULT_TAG, preimage]).into())
}

/// The deterministic outcome of executing one block: the complete World state before and after
/// it, the events it emitted, roots over its execution witness and the identity of the
/// result-bearing block (`specs/sumeragi.md` §4.1, Appendix E, E51).
#[derive(norito::NoritoSchema, iroha_schema::IntoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::ExecutionCommitment")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct ExecutionCommitment {
    /// Root of the witnessed pre-state values of the keys the block changed.
    pub parent_state_root: Hash,
    /// Post-state root of the witnessed writes (of the reads for a read-only block).
    pub post_state_root: Hash,
    /// Root of the canonical last-write-wins witnessed writes.
    pub ordinary_writes_root: Hash,
    /// Complete World state root the block executed on: every canonical World entry after the
    /// parent block's publication (the empty World for genesis, which absorbs everything).
    pub parent_world_state_root: Hash,
    /// Complete World state root after the block's execution (the post-state root of §4.1).
    pub world_state_root: Hash,
    /// Merkle root and count of the events the block's execution emitted, in emission order
    /// (the event root of §4.1); `None` when it emitted none.
    pub event_commitment: Option<MerkleTreeCommitment<EventBox>>,
    /// Byte length of the canonical result-bearing block wire.
    pub executed_block_wire_len: u64,
    /// Hash of the canonical result-bearing block wire (every transaction result and output).
    pub executed_block_wire_hash: Hash,
    /// Network-input Merkle commitment of the block.
    pub transaction_input_commitment: Option<MerkleTreeCommitment<TransactionEntrypoint>>,
    /// Typed-output Merkle commitment of the block, including internal invocations.
    pub transaction_output_commitment: Option<MerkleTreeCommitment<ExecutionOutputV1>>,
}

/// Protocol bound for the complete executed block wire, including outputs.
/// Portable proof transports may impose a tighter resource bound.
pub const MAX_EXECUTED_BLOCK_WIRE_BYTES: u64 = 256 * 1024 * 1024;

impl ExecutionCommitment {
    /// Validate exact executed-wire and output geometry.
    /// This checks shape only; authority requires the complete authenticated native result.
    ///
    /// # Errors
    /// Rejects invalid wire lengths or an output count below the input count.
    pub fn validate(&self) -> Result<(), CommitmentError> {
        if self.executed_block_wire_len == 0
            || self.executed_block_wire_len > MAX_EXECUTED_BLOCK_WIRE_BYTES
        {
            return Err(CommitmentError::WireLength(self.executed_block_wire_len));
        }
        if self.transaction_input_commitment.is_some_and(|inputs| {
            self.transaction_output_commitment
                .is_none_or(|outputs| outputs.leaf_count() < inputs.leaf_count())
        }) {
            return Err(CommitmentError::InvalidOutputs(
                "output count is below input count".into(),
            ));
        }
        Ok(())
    }
}

/// The canonical preimage of `R`: exact executed height, execution, complete native schedule
/// graph and the finalized beacon pulse consumed by this execution, when present.
#[derive(Clone, Debug, PartialEq, Eq, iroha_schema::IntoSchema)]
#[schema(transparent = "wire::OwnedResult")]
pub struct ExecutionResultCommitment {
    /// Exact height whose execution and schedule this result authenticates.
    pub height: u64,
    /// What executing the block produced.
    pub execution: ExecutionCommitment,
    /// Full current context and authenticated successor schedule, including boundary decisions.
    pub schedule: ScheduleOutcome,
    /// Finalized unique threshold-beacon pulse verified against execution prestate.
    /// Historical readers check its canonical public bindings; its threshold verification is
    /// attested by the exact current quorum, not reconstructed without the full session.
    pub beacon: Option<FinalizedGlobalThresholdBeaconPulseV1>,
    /// Complete native context-set proof bound to the same network, height and write root.
    pub native_lanes: NativeLaneStateProof,
}

// Ready slots carry only height and parameters on the result wire: their complete epoch is
// determined by the current context or the boundary's next context. The standalone schedule
// codec remains an owned graph; this projection is the sole canonical result layout.
mod wire;

impl norito::NoritoSchema for ExecutionResultCommitment {
    fn nominal_name() -> String {
        "iroha_data_model::sumeragi_finality::ExecutionResultCommitment".to_owned()
    }
    fn static_frame_name() -> Option<&'static str> {
        // Canonical streaming must not allocate a String merely to hash this declared identity.
        Some("iroha_data_model::sumeragi_finality::ExecutionResultCommitment")
    }
}

impl ExecutionResultCommitment {
    /// Bind an execution to its exact native epoch graph and finalized beacon pulse.
    ///
    /// # Errors
    /// The height, complete epoch contexts, schedule graph or public pulse bindings are invalid.
    pub fn new(
        height: u64,
        execution: ExecutionCommitment,
        schedule: ScheduleOutcome,
        beacon: Option<FinalizedGlobalThresholdBeaconPulseV1>,
        native_lanes: NativeLaneStateProof,
    ) -> Result<Self, CommitmentError> {
        let value = Self {
            height,
            execution,
            schedule,
            beacon,
            native_lanes,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate the complete graph and public pulse bindings before trusting its authority.
    /// This does not independently verify a threshold signature: execution must verify that
    /// signature with the authenticated complete beacon session before certifying this result.
    ///
    /// # Errors
    /// An inconsistent height, invalid graph, missing required pulse or malformed pulse.
    pub fn validate(&self) -> Result<(), CommitmentError> {
        self.validate_with_validation(&mut EpochValidationScope::new())
    }
    /// Validate this complete commitment with exact epoch work owned by one enclosing walk.
    ///
    /// # Errors
    /// The same execution, schedule, lane and beacon errors as [`Self::validate`]. This
    /// workspace does not replace certificate, signature or current source authentication.
    pub fn validate_with_validation(
        &self,
        validation: &mut EpochValidationScope,
    ) -> Result<(), CommitmentError> {
        self.execution.validate()?;
        if self.height == 0 || self.schedule.height != self.height {
            return Err(CommitmentError::Schedule(
                "result and schedule heights differ".into(),
            ));
        }
        self.schedule
            .validate_with_validation(validation)
            .map_err(|error| CommitmentError::Schedule(error.to_string()))?;
        let current = &self.schedule.current;
        if !self.native_lanes.verify(
            current.network_id,
            self.height,
            self.execution.ordinary_writes_root,
        ) {
            return Err(CommitmentError::NativeLaneState);
        }
        let required = current.mode == ConsensusMode::Npos
            && self.height > 1
            && self.height.checked_add(1) == Some(current.authorization.last_height);
        let Some(pulse) = self.beacon.as_ref() else {
            return if required {
                Err(CommitmentError::Beacon(
                    "missing boundary-selection pulse".into(),
                ))
            } else {
                Ok(())
            };
        };
        super::validate_beacon_pulse_shape(pulse)
            .map_err(|error| CommitmentError::Beacon(error.to_string()))?;
        if pulse.network_id != current.network_id
            || pulse.height != self.height
            || pulse.finalized_chain_anchor.height.checked_add(1) != Some(self.height)
        {
            return Err(CommitmentError::Beacon(
                "pulse belongs to another network, height or anchor".into(),
            ));
        }
        if let BeaconEpochBindingV1::Installed(binding) = current.authorization.beacon
            && (pulse.session_id != binding.session_id
                || pulse.transcript_hash != binding.transcript_hash)
        {
            return Err(CommitmentError::Beacon(
                "pulse differs from authenticated epoch session".into(),
            ));
        }
        Ok(())
    }

    /// The canonical preimage bytes (stored as `CommitCertificate.result_preimage`).
    ///
    /// # Errors
    /// A Norito serialization failure.
    pub fn preimage(&self) -> Result<Vec<u8>, CommitmentError> {
        let len = norito::canonical_frame_len(self)
            .map_err(|error| CommitmentError::Encoding(error.to_string()))?;
        if len > MAX_RESULT_PREIMAGE_BYTES {
            return Err(CommitmentError::PreimageLength(len));
        }
        norito::encode_canonical(self).map_err(|error| CommitmentError::Encoding(error.to_string()))
    }

    /// Decode a canonical preimage (e.g. from a stored or received certificate).
    ///
    /// # Errors
    /// The bytes are not one canonical frame of this type.
    pub fn decode(preimage: &[u8]) -> Result<Self, CommitmentError> {
        Self::decode_with_validation(preimage, &mut EpochValidationScope::new())
    }
    /// Decode and fully validate one canonical result using an enclosing walk's epoch work.
    ///
    /// # Errors
    /// Rejects the same noncanonical, oversized or malformed commitment as [`Self::decode`].
    pub fn decode_with_validation(
        preimage: &[u8],
        validation: &mut EpochValidationScope,
    ) -> Result<Self, CommitmentError> {
        Self::decode_with_validation_into(preimage, validation, |decoded| decoded)
    }

    /// Fully decode and validate the original canonical result before transferring it to a
    /// consuming owner. The consumer runs exactly once after all checks succeed, and never
    /// on a malformed frame or local decoder refusal. It confers no source or certificate trust.
    /// This permits a prepaid destination to receive the value without another large result
    /// return temporary in its caller.
    ///
    /// # Errors
    /// Preserves the same format bounds, inherited resource refusal and complete validation
    /// errors as [`Self::decode_with_validation`].
    pub fn decode_with_validation_into<Output>(
        preimage: &[u8],
        validation: &mut EpochValidationScope,
        finish: impl FnOnce(Self) -> Output,
    ) -> Result<Output, CommitmentError> {
        if preimage.len() > MAX_RESULT_PREIMAGE_BYTES {
            return Err(CommitmentError::PreimageLength(preimage.len()));
        }
        // The compact wire retains complete current/boundary/preparation credentials once;
        // decoding charges the reconstructed Ready-slot epochs to the same inherited budget.
        // Credential byte arrays need input-derived cumulative element/allocation limits at
        // 31 seats, alongside the tighter per-sequence, field and nesting caps. The 64 KiB
        // frame ceiling bounds both budgets; stricter original caller limits stay in force.
        // Decode accounting alone grants no production pool owner.
        // Intrinsic schema/protocol ceilings remain terminal without an inherited caller
        // scope. A local allocator failure is always operational, even at the outer boundary.
        let outer_scope = norito::core::decode_limits_active();
        let canonical = norito::canonical_decode_limits(preimage.len());
        let decoded: Self = norito::decode_canonical_with_limits(
            preimage,
            norito::DecodeLimits::new(
                96,
                MAX_RESULT_PREIMAGE_BYTES,
                canonical.max_total_elements(),
                canonical.max_total_allocated_bytes(),
                32,
            ),
        )
        .map_err(|error| {
            if (outer_scope || matches!(error, norito::Error::AllocationFailed { .. }))
                && let Some(resource) = error.decode_resource_error()
            {
                return CommitmentError::Resource(resource);
            }
            CommitmentError::Encoding(error.to_string())
        })?;
        decoded.validate_with_validation(validation)?;
        Ok(finish(decoded))
    }

    /// `R` of this commitment.
    ///
    /// # Errors
    /// A Norito serialization failure.
    pub fn result(&self) -> Result<Hash32, CommitmentError> {
        self.preimage().map(|bytes| result_of_preimage(&bytes))
    }
}

/// Why `R` could not be computed or its canonical preimage could not be decoded.
/// Local decoder resource refusals are distinct from deterministic invalid input.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CommitmentError {
    /// The executed block carries no execution result.
    #[error("the executed block has no execution result")]
    MissingResult,
    /// The executed block already carries a commit certificate.
    #[error("the executed block already carries a commit certificate")]
    CertifiedBlock,
    /// The block's outputs or their Merkle cache are malformed.
    #[error("malformed execution outputs: {0}")]
    InvalidOutputs(String),
    /// The result-bearing block wire is empty or above the protocol bound.
    #[error("the executed block wire length {0} is out of range")]
    WireLength(u64),
    /// The complete native epoch schedule is invalid.
    #[error("invalid epoch schedule: {0}")]
    Schedule(String),
    /// Complete context proof differs from the exact native execution carrier.
    #[error("invalid native context proof")]
    NativeLaneState,
    /// A finalized pulse has malformed or inconsistent public bindings.
    #[error("invalid finalized beacon pulse: {0}")]
    Beacon(String),
    /// A canonical result preimage exceeds the protocol byte bound.
    #[error("result preimage exceeds its byte bound: {0}")]
    PreimageLength(usize),
    /// A Norito encoding or decoding failure.
    #[error("encoding: {0}")]
    Encoding(String),
    /// The caller's original decoder scope or local allocator refused without a verdict.
    #[error("local result decoder resource refusal: {0}")]
    Resource(norito::core::DecodeResourceError),
}

#[cfg(test)]
mod execution_validation_tests {
    use super::*;
    use std::num::NonZeroU64;

    fn execution() -> ExecutionCommitment {
        ExecutionCommitment {
            parent_state_root: Hash::new(b"parent"),
            post_state_root: Hash::new(b"post"),
            ordinary_writes_root: Hash::new(b"writes"),
            parent_world_state_root: Hash::new(b"parent world"),
            world_state_root: Hash::new(b"world"),
            event_commitment: None,
            executed_block_wire_len: 1,
            executed_block_wire_hash: Hash::new(b"wire"),
            transaction_input_commitment: None,
            transaction_output_commitment: None,
        }
    }
    #[test]
    fn independent_roots_are_shape_only() {
        let valid = execution();
        valid.validate().unwrap();
        // Roots are authenticated by the complete native result, not by this shape check.
        let mut read_only = valid;
        read_only.post_state_root = Hash::new(b"witnessed reads");
        read_only.validate().unwrap();
    }
    #[test]
    fn executed_wire_and_output_geometry_are_bounded() {
        let valid = execution();
        for length in [0, MAX_EXECUTED_BLOCK_WIRE_BYTES + 1] {
            let mut bad = valid;
            bad.executed_block_wire_len = length;
            assert_eq!(bad.validate(), Err(CommitmentError::WireLength(length)));
        }
        let mut geometry = valid;
        geometry.transaction_input_commitment = Some(MerkleTreeCommitment::new(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"inputs")),
            NonZeroU64::new(2).unwrap(),
        ));
        assert!(geometry.validate().is_err());
        for count in [1, 2, 3] {
            geometry.transaction_output_commitment = Some(MerkleTreeCommitment::new(
                iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"outputs")),
                NonZeroU64::new(count).unwrap(),
            ));
            assert_eq!(geometry.validate().is_ok(), count >= 2);
        }
    }
    #[cfg(feature = "transparent_api")]
    #[test]
    fn complete_native_result_decode_rejects_invalid_execution_geometry() {
        let fixture = super::super::tests::Fixture::new();
        let mut commitment = fixture.second.decode_checked().unwrap().commitment;
        commitment.execution.executed_block_wire_len = 0;
        assert!(commitment.validate().is_err());
        let frame = norito::encode_canonical(&commitment).unwrap();
        assert!(matches!(
            ExecutionResultCommitment::decode(&frame),
            Err(CommitmentError::WireLength(0))
        ));
    }
}

#[cfg(test)]
#[path = "commitment/decode_budget_tests.rs"]
mod decode_budget_tests;
