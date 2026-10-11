//! Portable current-consensus proofs rooted in an independently authenticated signed genesis.
//!
//! Proofs carry the canonical block and its embedded commit certificate. A structural
//! decode is never an authenticated execution capability: only the contiguous verifier
//! constructs [`VerifiedSumeragiBlock`]. The receipt proves exact-quorum execution finality;
//! with the signed RS16 availability binding. Genesis has no quorum certificate; its
//! execution result is authenticated by a successor's parent-result binding or independent node
//! attestations, not by inventing a genesis quorum certificate.
//!
//! This module owns the sole canonical execution-result codec and authenticated epoch/schedule
//! graph shared with Core. Core produces execution witnesses, validates beacon signatures,
//! and publishes these same results; portable readers authenticate the
//! resulting commit-finality chain without introducing another result layout or authority source.

mod schedule;
pub use schedule::{
    GenesisCommitteeError, ScheduleError, ScheduleSourceError, consensus_key,
    genesis_registrations, global_committee,
};
mod epoch_graph;
pub use epoch_graph::{
    ConsensusSchedule, EpochValidationScope, ScheduleOutcome, ScheduledConfig, ScheduledSlot,
    core_epoch,
};
mod beacon;
pub use beacon::{
    BeaconPulseShapeError, GLOBAL_BEACON_PULSE_PAYLOAD_DOMAIN_V1,
    GLOBAL_BEACON_PULSE_PAYLOAD_LEN_V1, election_seed,
    global_threshold_beacon_npos_successor_seed_v1, global_threshold_beacon_pulse_id_v1,
    global_threshold_beacon_pulse_payload_v1, validate_beacon_pulse_shape,
};
mod genesis;
pub use genesis::{
    AuthenticatedGenesis, AuthenticatedSignedGenesisV1, GenesisReadError,
    MAX_SIGNED_GENESIS_BYTES_V1, OriginalGenesisRead, OriginalGenesisReadError,
    SignedGenesisPinsV1, authenticate_signed_genesis_v1, authenticated_genesis,
    signed_genesis_consensus_metadata,
};
mod genesis_dataspace;
pub use genesis_dataspace::{
    GENESIS_DATASPACE_VERIFICATION_SCHEMA_V1, GenesisDataspaceAuthorityV1, GenesisDataspaceError,
    GenesisDataspaceSelectorV1, VerifiedGenesisDataspaceCutV1, verify_genesis_dataspace_v1,
};
mod lane_state_commitment;
mod native_lanes;
pub use lane_state_commitment::SumeragiLaneStateCommitment;
pub use native_lanes::{
    NativeLaneStateProof, NativeLaneStateProofError, SUMERAGI_LANE_STATE_WITNESS_KEY,
};
mod commitment;
pub use commitment::*;
mod checkpoint;
pub use checkpoint::{MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint};
mod compact;
pub use compact::{
    MAX_COMMIT_CERTIFICATE_BYTES_V1, MAX_COMMIT_CHECKPOINT_BYTES, SumeragiCommitCertificateV1,
    SumeragiCommitCheckpointV1, SumeragiCommitVerifierV1, VerifiedSumeragiCommitV1,
};
mod page;
pub use page::{VerifiedFinalityPage, certified_block_context_id, verify_checkpoint_page};
mod world_state;
pub use world_state::{
    MAX_WORLD_STATE_SNAPSHOT_BYTES_V1, MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
    VerifiedWorldStateSnapshotV1, WORLD_STATE_ACCUMULATOR_LANES_V1, WorldStateElementKindV1,
    WorldStateSnapshotEntryV1, WorldStateSnapshotV1, world_state_element_v1,
    world_state_path_hash_v1, world_state_root_from_accumulator_v1, world_state_value_hash_v1,
};

use std::collections::BTreeMap;

use iroha_crypto::{
    Algorithm, BlsNormalPopVerifiedKey, Hash, HashOf, PublicKey, SignatureOf,
    bls_normal_aggregate_signatures, bls_normal_verify_preaggregated_multi_message,
};
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::{
    availability::AvailabilityFrame,
    crypto::Crypto,
    message::{BlockHeader as CoreHeader, Qc, VoteKind},
    preimage::{committee_digest_preimage, payload_hash},
    types::{AggregateSignature, Committee, Hash32, PublicKey as CoreKey, Signature},
};
use norito::{
    Decode, Encode,
    codec::Encode as _,
    derive::{JsonDeserialize, JsonSerialize},
};

use crate::{
    NetworkId,
    block::{BlockHeader, SignedBlock, decode_framed_signed_block},
    isi::SetParameter,
    parameter::{
        Parameter,
        system::{SumeragiParameter, SumeragiParameters},
    },
    query::CommittedTransaction,
    sumeragi::SumeragiStatus,
    transaction::{Executable, TransactionEntrypoint},
};
#[cfg(test)]
use iroha_sumeragi::preimage::{InstanceKind, instance_id};

/// Maximum canonical certified block accepted by a portable proof reader.
pub const MAX_FINALITY_BLOCK_BYTES: usize = 32 * 1024 * 1024;
/// Finite portable-reader scratch bound for availability codewords and field workspace.
/// Exceeding this local reader bound is not a native consensus invalidity verdict.
pub const MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES: usize = 64 * 1024 * 1024;
/// Domain of current node finality statements.
pub const FINALITY_ATTESTATION_DOMAIN: &[u8] = b"iroha:sumeragi-finality-attestation:v1\0";

/// A failed current proof, trust binding, certificate or node statement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("current finality: {0}")]
pub struct FinalityError(pub String);

/// A portable trust-root read that preserves original JSON and binary decoder failures.
///
/// Completed proof checks retain their existing verdict. Decoder errors remain typed so
/// callers can distinguish surviving local limits from intrinsic format ceilings before
/// projecting an external response.
#[derive(Debug, thiserror::Error)]
pub enum FinalityReadError {
    /// A completed trust-binding or cryptographic check failed.
    #[error(transparent)]
    Invalid(#[from] FinalityError),
    /// The original signed genesis could not be read or authenticated.
    #[error(transparent)]
    Genesis(#[from] GenesisReadError),
    /// Exact original canonical block decoder fields, before any caller locality classification.
    /// Intrinsic format ceilings are not automatically a retryable caller refusal.
    #[error("canonical block decoder resource: {0}")]
    DecodeResource(#[source] norito::core::DecodeAttemptError),
}

/// Authenticate signed genesis and fingerprint its exact native consensus configuration.
///
/// This binds protocol, initial epoch authority and all explicit signed Sumeragi parameters.
/// It is distinct from the reporting node's local resource and driver fingerprint.
///
/// # Errors
/// Preserves unfinished signed-parameter decoder errors and rejects invalid signatures,
/// omitted or repeated parameters, and invalid native parameter geometry.
pub fn consensus_configuration_fingerprint(
    genesis: &SignedBlock,
) -> Result<Hash, GenesisReadError> {
    let authenticated = authenticated_genesis(genesis)?;
    #[cfg(not(all(test, sumeragi_model_mutation = "DM13")))]
    let metadata = authenticated.metadata();
    let epoch = authenticated.into_parts().0;
    #[cfg(all(test, sumeragi_model_mutation = "DM13"))]
    let metadata = signed_genesis_consensus_metadata(genesis)?;
    let parameters = explicit_genesis_chain_parameters(genesis, metadata.block_cadence_ms)?;
    let encoded = norito::encode_canonical(&(crate::sumeragi::PROTOCOL_VERSION, epoch, parameters))
        .map_err(|error| error.to_string())?;
    Ok(Hash::new_from_chunks(&[
        b"iroha:native-config:v1",
        &encoded,
    ]))
}

// Both callers carry the cadence from their canonical authentication of this exact
// signed body. The same original instruction kernel still requires each explicit
// parameter exactly once; results and mutable World never supply these lag-two values.
fn explicit_genesis_chain_parameters(
    genesis: &SignedBlock,
    block_cadence_ms: std::num::NonZeroU64,
) -> Result<ChainParamsRecord, GenesisReadError> {
    let mut parameters = ExplicitParameters::new(block_cadence_ms);
    for transaction in genesis.external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err("native configuration requires explicit signed instructions".into());
        };
        for instruction in instructions {
            if let Some(set) = instruction.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Sumeragi(parameter) = set.inner()
            {
                parameters.insert(*parameter)?;
            }
        }
    }
    parameters.finish().map_err(Into::into)
}

struct ExplicitParameters {
    value: SumeragiParameters,
    seen: u8,
}
impl ExplicitParameters {
    fn new(cadence: std::num::NonZeroU64) -> Self {
        Self {
            value: SumeragiParameters {
                block_cadence_ms: cadence,
                ..SumeragiParameters::default()
            },
            seen: 0,
        }
    }
    fn insert(&mut self, parameter: SumeragiParameter) -> Result<(), String> {
        let bit = match parameter {
            SumeragiParameter::PayloadRetryIntervalMs(value) => {
                self.value.payload_retry_interval_ms = value;
                1
            }
            SumeragiParameter::ExecBudgetMs(value) => {
                self.value.exec_budget_ms = value;
                2
            }
            SumeragiParameter::ApplyBudgetMs(value) => {
                self.value.apply_budget_ms = value;
                4
            }
            SumeragiParameter::MaxBlockBytes(value) => {
                self.value.max_block_bytes = value;
                8
            }
            SumeragiParameter::EpochLengthBlocks(value) => {
                self.value.epoch_length_blocks = value;
                16
            }
            SumeragiParameter::MaxClockDriftMs(value) => {
                self.value.max_clock_drift_ms = value;
                32
            }
            SumeragiParameter::DemotionWindow(value) => {
                self.value.demotion_window = value;
                64
            }
        };
        if self.seen & bit != 0 {
            return Err("signed genesis repeats a native Sumeragi parameter".into());
        }
        self.seen |= bit;
        Ok(())
    }
    fn finish(self) -> Result<ChainParamsRecord, String> {
        if self.seen != 0x7f {
            return Err("signed genesis omits an explicit native Sumeragi parameter".into());
        }
        let parameters = ChainParamsRecord::from_parameters(&self.value);
        parameters.validate().map_err(|error| error.to_string())?;
        Ok(parameters)
    }
}

fn need(condition: bool, reason: &str) -> Result<(), FinalityError> {
    if condition {
        Ok(())
    } else {
        Err(FinalityError(reason.into()))
    }
}
fn malformed(error: impl std::fmt::Display) -> FinalityError {
    FinalityError(error.to_string())
}

// Stream the exact borrowed resultless view; never clone the executed block graph.
fn proposal_wire(block: &SignedBlock) -> Result<Vec<u8>, FinalityError> {
    let length = block.resultless_proposal_wire_len().map_err(malformed)?;
    need(
        length <= MAX_FINALITY_BLOCK_BYTES,
        "proposal exceeds portable reader bound",
    )?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(malformed)?;
    block
        .write_resultless_proposal_wire(&mut bytes)
        .map_err(malformed)?;
    need(bytes.len() == length, "canonical proposal length differs")?;
    Ok(bytes)
}

/// A signed availability failure or a local scratch-allocation refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadAvailabilityError {
    /// The signed source, payload or portable shape bound is invalid for this reader.
    #[error(transparent)]
    Invalid(#[from] FinalityError),
    /// The caller's original allocation scope or physical allocator refused scratch.
    /// This is not an invalidity verdict about the signed source.
    #[error("availability scratch resource: {0}")]
    Resource(norito::core::DecodeResourceError),
}

impl From<PayloadAvailabilityError> for FinalityError {
    fn from(error: PayloadAvailabilityError) -> Self {
        match error {
            PayloadAvailabilityError::Invalid(error) => error,
            PayloadAvailabilityError::Resource(error) => Self(error.to_string()),
        }
    }
}

/// Verify signed availability under the portable scratch bound.
///
/// This wrapper grants no request-pool allocation authority. Callers with a scoped
/// owner must use [`verify_payload_availability_with_admission`] and preserve its
/// typed local refusal; existing portable callers receive diagnostic errors only.
///
/// # Errors
/// Rejects invalid signatures, layout, payload, rows and physical allocation failures.
pub fn verify_payload_availability(
    instance: Hash32,
    config: &iroha_sumeragi::types::HeightConfig,
    header: &CoreHeader,
    availability: &AvailabilityFrame,
    payload: &[u8],
    crypto: &dyn Crypto,
) -> Result<(), FinalityError> {
    verify_payload_availability_with_admission(
        instance,
        config,
        header,
        availability,
        payload,
        crypto,
        |_| Ok(()),
    )
    .map_err(Into::into)
}

/// Verify signed availability after the caller admits exact scratch bytes.
///
/// The shared verifier derives the codeword and field-workspace sizes from the
/// authenticated row table and calls admission before either allocation. A local
/// refusal cannot turn the original signed source into invalid evidence. This
/// callback does not grant native body custody or a different allocation pool.
///
/// # Errors
/// Rejects invalid signed sources separately from local admission/allocation refusal.
pub fn verify_payload_availability_with_admission(
    instance: Hash32,
    config: &iroha_sumeragi::types::HeightConfig,
    header: &CoreHeader,
    availability: &AvailabilityFrame,
    payload: &[u8],
    crypto: &dyn Crypto,
    mut admit: impl FnMut(usize) -> Result<(), norito::core::DecodeResourceError>,
) -> Result<(), PayloadAvailabilityError> {
    let verified = iroha_sumeragi::availability::verify_availability(
        instance,
        config,
        header,
        availability.as_slice(),
        crypto,
    )
    .map_err(|error| FinalityError(format!("signed availability: {error:?}")))?;
    let shape = verified.shape();
    let scratch = shape
        .workspace_words()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|bytes| bytes.checked_add(shape.encoded_bytes()))
        .ok_or_else(|| FinalityError("availability scratch length overflow".into()))?;
    if scratch > MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES {
        return Err(PayloadAvailabilityError::Resource(
            norito::core::DecodeResourceError::TotalAllocationExceeded {
                attempted: scratch as u64,
                limit: MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES as u64,
            },
        ));
    }
    admit(scratch).map_err(PayloadAvailabilityError::Resource)?;
    let allocation_failed = |bytes| {
        PayloadAvailabilityError::Resource(norito::core::DecodeResourceError::AllocationFailed {
            bytes: bytes as u64,
        })
    };
    let mut codeword = Vec::new();
    codeword
        .try_reserve_exact(shape.encoded_bytes())
        .map_err(|_| allocation_failed(shape.encoded_bytes()))?;
    codeword.resize(shape.encoded_bytes(), 0);
    let mut workspace = Vec::new();
    workspace
        .try_reserve_exact(shape.workspace_words())
        .map_err(|_| allocation_failed(shape.workspace_words() * size_of::<u16>()))?;
    workspace.resize(shape.workspace_words(), 0);
    verified
        .verify_payload(payload, &mut codeword, &mut workspace, crypto)
        .map_err(|error| FinalityError(format!("availability payload: {error:?}")).into())
}

/// A consensus key and its proof of possession; its authority comes from the trusted schedule.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::FinalityValidator")]
pub struct FinalityValidator {
    /// BLS-normal validator key.
    pub public_key: PublicKey,
    /// Canonical proof of possession for this key.
    pub proof_of_possession: Vec<u8>,
}

/// The one canonical current block frame and the candidate committee of its height.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::SumeragiFinalityProof")]
pub struct SumeragiFinalityProof {
    /// Header, cross-checked against the complete canonical frame.
    pub block_header: BlockHeader,
    /// Result-bearing canonical `SignedBlockWire`, including the embedded current certificate.
    pub block_wire: Vec<u8>,
    /// Committee, admitted only against the signed genesis or an authenticated complete epoch context.
    pub committee: Vec<FinalityValidator>,
}

/// A network-qualified current proof, without a second consensus-context layout.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::SumeragiFinalityBundle")]
pub struct SumeragiFinalityBundle {
    /// Independently selected genesis-derived network identity.
    pub network_id: NetworkId,
    /// Current embedded-certificate proof.
    pub finality_proof: SumeragiFinalityProof,
}

/// Checked structure and certificate under a proof's candidate committee, without a trust root.
#[derive(Debug, Clone)]
pub struct DecodedSumeragiBlock {
    block: SignedBlock,
    header: Option<CoreHeader>,
    availability: Option<AvailabilityFrame>,
    core_hash: Hash32,
    result: Hash32,
    commitment: ExecutionResultCommitment,
    committee_digest: [u8; 32],
}

impl DecodedSumeragiBlock {
    /// Compare decoded decision data with an independently authenticated native execution.
    ///
    /// This pure equality check does not establish provenance for the offered arguments or
    /// admit the candidate committee. The Node consumer must obtain every argument from its
    /// actual consensus-visible committed reader and subsequently verify the portable proof.
    #[must_use]
    pub fn matches_native_execution_decision(
        &self,
        block_hash: &HashOf<BlockHeader>,
        core_hash: [u8; 32],
        result: [u8; 32],
        commitment: &ExecutionResultCommitment,
    ) -> bool {
        self.block.hash() == *block_hash
            && self.core_hash.0 == core_hash
            && self.result.0 == result
            && &self.commitment == commitment
    }

    /// Structurally checked execution under the proof's candidate committee.
    ///
    /// This accessor does not authenticate the committee or select a trust root.
    /// Remote consumers must use `SumeragiFinalityVerifier` before trusting it.
    #[must_use]
    pub fn execution(&self) -> &ExecutionCommitment {
        &self.commitment.execution
    }
}

impl SumeragiFinalityProof {
    /// One-based height claimed by the proof; a verifier checks its frame binding.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.block_header.height().get()
    }

    /// Decode and check canonical framing, exact execution identity and the candidate QC.
    /// This does not authenticate the committee or genesis. Use the contiguous verifier.
    ///
    /// # Errors
    /// Malformed, empty, inconsistent, oversized or cryptographically invalid material.
    pub fn decode_checked(&self) -> Result<DecodedSumeragiBlock, FinalityError> {
        self.decode_parts().map(|(decoded, _, _)| decoded)
    }

    // Preserve the exact proposal image and admitted proof-key context until the trusted
    // contiguous verifier has authenticated its schedule. The public structural reader
    // discards these; neither path manufactures native available-body custody.
    fn decode_parts(
        &self,
    ) -> Result<(DecodedSumeragiBlock, Option<Vec<u8>>, ProofCrypto), FinalityError> {
        self.decode_parts_with_validation(None)
    }

    // Enclosing checkpoint and attestation operations may supply a pure epoch workspace.
    // Independent proof readers preserve the original separate scopes and allocation charges.
    fn decode_parts_with_validation(
        &self,
        mut validation: Option<&mut EpochValidationScope>,
    ) -> Result<(DecodedSumeragiBlock, Option<Vec<u8>>, ProofCrypto), FinalityError> {
        need(
            !self.block_wire.is_empty() && self.block_wire.len() <= MAX_FINALITY_BLOCK_BYTES,
            "block frame exceeds its finite bound",
        )?;
        let block = norito::core::with_decode_limits_scope(
            norito::canonical_decode_limits(self.block_wire.len()),
            || decode_framed_signed_block(&self.block_wire),
        )
        .map_err(malformed)?;
        // The framed decoder already streams exact canonical equality under the original
        // limits. Retire payload/layout state before the independent certificate decoders,
        // without materializing another complete block frame.
        norito::core::reset_decode_state();
        need(
            block.header() == self.block_header && block.has_results(),
            "header or execution-result binding differs",
        )?;
        block.validate_proposal_commitments().map_err(malformed)?;
        block.validate_output_merkle_cache().map_err(malformed)?;
        let (crypto, committee) = ProofCrypto::new(&self.committee)?;
        let committee_digest = chain_hash(&committee_digest_preimage(&committee)).0;
        let certificate = block
            .commit_certificate()
            .ok_or_else(|| FinalityError("embedded commit certificate missing".into()))?;
        let commitment = validation
            .as_deref_mut()
            .map_or_else(
                || ExecutionResultCommitment::decode(certificate.result_preimage()),
                |validation| {
                    ExecutionResultCommitment::decode_with_validation(
                        certificate.result_preimage(),
                        validation,
                    )
                },
            )
            .map_err(malformed)?;
        need(
            commitment.height == self.height(),
            "result height differs from its block",
        )?;
        need(
            commitment.beacon.as_ref().is_none_or(|pulse| {
                Some(pulse.finalized_chain_anchor.block_hash) == block.header().prev_block_hash()
            }),
            "beacon pulse names another committed parent",
        )?;
        need(
            self.committee.len() == commitment.schedule.current.committee.len()
                && self
                    .committee
                    .iter()
                    .zip(&commitment.schedule.current.committee)
                    .all(|(proof, member)| {
                        proof.public_key == *member.validator.public_key()
                            && proof.proof_of_possession == member.proof_of_possession
                    }),
            "proof roster differs from its complete epoch context",
        )?;
        let epoch = validation
            .map_or_else(
                || core_epoch(&commitment.schedule.current),
                |validation| validation.core_epoch(&commitment.schedule.current),
            )
            .map_err(malformed)?;
        let result = result_of_preimage(certificate.result_preimage());
        let (len, hash) = block.executed_block_wire_identity().map_err(malformed)?;
        need(
            commitment.execution.executed_block_wire_len == len
                && commitment.execution.executed_block_wire_hash == hash
                && commitment.execution.transaction_input_commitment
                    == block.network_input_merkle_commitment()
                && commitment.execution.transaction_output_commitment
                    == block.output_merkle_commitment(),
            "execution commitment differs from canonical result-bearing block",
        )?;
        let (header, core_hash, availability, payload) = if self.height() == 1 {
            need(
                certificate.consensus_header().is_empty()
                    && certificate.commit_qc().is_empty()
                    && certificate.availability().is_empty(),
                "genesis requires a result-only certificate",
            )?;
            (None, Hash32(Hash::from(block.hash()).into()), None, None)
        } else {
            need(block.has_consensus_work(), "empty blocks are invalid")?;
            let header: CoreHeader =
                norito::decode_canonical(certificate.consensus_header()).map_err(malformed)?;
            let qc: Qc = norito::decode_canonical(certificate.commit_qc()).map_err(malformed)?;
            let availability: AvailabilityFrame =
                norito::decode_canonical(certificate.availability()).map_err(malformed)?;
            need(
                availability.has_valid_structure(),
                "availability table structure is invalid",
            )?;
            let payload = proposal_wire(&block)?;
            let core_hash = header.hash(&crypto);
            need(
                header.height == self.height()
                    && header.epoch == epoch.id
                    && qc.epoch == epoch.id
                    && usize::try_from(header.payload_len).ok() == Some(payload.len())
                    && header.payload_hash == payload_hash(&crypto, &payload)
                    && qc.kind == VoteKind::Commit
                    && qc.height == header.height
                    && qc.instance == header.instance
                    && qc.block_hash == core_hash
                    && qc.result == result,
                "current certificate does not bind this block and execution",
            )?;
            need(
                commitment.beacon.as_ref().is_none_or(|pulse| {
                    pulse.context.instance == header.instance.0
                        && pulse.context.epoch == commitment.schedule.current.authorization.epoch
                        && pulse.context.epoch_context_id == epoch.id.context.0
                        && pulse.context.parent_consensus_hash == header.parent_hash.0
                        && pulse.context.parent_result == header.parent_result.0
                }),
                "beacon pulse names another native consensus context",
            )?;
            // Exact quorum signatures authenticate the execution commitment.
            iroha_sumeragi::crypto::Verifier::new(&crypto, &header.instance, &epoch.id, &committee)
                .verify_qc(&qc)
                .map_err(|error| FinalityError(format!("commit certificate: {error:?}")))?;
            (Some(header), core_hash, Some(availability), Some(payload))
        };
        Ok((
            DecodedSumeragiBlock {
                block,
                header,
                availability,
                core_hash,
                result,
                commitment,
                committee_digest,
            },
            payload,
            crypto,
        ))
    }
}

/// Execution authenticated by the verifier's independently anchored contiguous prefix.
#[derive(Debug, Clone)]
pub struct VerifiedSumeragiBlock(DecodedSumeragiBlock);
impl VerifiedSumeragiBlock {
    /// The authenticated Iroha header.
    #[must_use]
    pub fn header(&self) -> BlockHeader {
        self.0.block.header()
    }
    /// The authenticated full frame (its certificate witness can differ between nodes).
    #[must_use]
    pub fn block(&self) -> &SignedBlock {
        &self.0.block
    }
    /// One-based authenticated height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.0.block.header().height().get()
    }
    /// The core header hash, or selected genesis hash at height one.
    #[must_use]
    pub fn core_hash(&self) -> Hash32 {
        self.0.core_hash
    }
    /// The certified execution-result hash.
    #[must_use]
    pub fn result(&self) -> Hash32 {
        self.0.result
    }
    /// Identity of this exact authenticated consensus header and execution result.
    #[must_use]
    pub fn context_id(&self) -> Hash {
        certified_block_context_id(&self.core_hash(), &self.result())
    }
    /// The authenticated execution commitment.
    #[must_use]
    pub fn execution(&self) -> &ExecutionCommitment {
        &self.0.commitment.execution
    }
    /// Complete current result and next schedule commitment.
    #[must_use]
    pub fn commitment(&self) -> &ExecutionResultCommitment {
        &self.0.commitment
    }
    /// Require the authenticated successor to belong to the exact selected Global root.
    ///
    /// This compares the native header's certified instance with the existing genesis/network,
    /// chain-label and Global-scope derivation. It introduces no trust root or new verification
    /// path; only an already authenticated successor can pass. Caller-supplied scope labels and
    /// publisher assertions cannot turn a private-root certificate into Global authority.
    /// # Errors
    /// Genesis, empty/oversized/control-containing chain labels, a different network or chain,
    /// or an authenticated private-root native instance.
    pub fn verify_global_scope(
        &self,
        expected_network: NetworkId,
        expected_chain: &str,
    ) -> Result<(), FinalityError> {
        need(
            !expected_chain.is_empty()
                && expected_chain.len() <= 1024
                && !expected_chain.chars().any(char::is_control),
            "Global scope requires a bounded canonical chain label",
        )?;
        need(
            self.height() >= 2 && self.commitment().schedule.current.network_id == expected_network,
            "Global scope requires an authenticated successor on the selected network",
        )?;
        let header = self.0.header.as_ref().ok_or_else(|| {
            FinalityError("Global scope requires a certified native header".into())
        })?;
        // Instance derivation calls only the existing hash operation. No key roster or
        // certificate-verification authority is created by this hash-only adapter value.
        let crypto = ProofCrypto {
            keys: BTreeMap::new(),
        };
        let expected = crate::block::consensus::SumeragiRootScope::Global
            .instance_id(&crypto, expected_network, expected_chain)
            .map_err(malformed)?;
        need(
            header.instance == expected,
            "Certified native instance differs from the selected Global network and chain",
        )
    }

    /// Join two already authenticated non-genesis Global receipts at one exact native edge.
    ///
    /// Both original verifiers have already authenticated their complete result/schedule and
    /// certificate witnesses. This compares those opaque decisions without re-decoding proofs,
    /// rechecking signatures, or making a fresh-currentness claim. Alternate valid local QC
    /// witnesses are equivalent; equal proposal hashes with different execution results are not.
    ///
    /// # Errors
    /// Rejects genesis, a foreign network/chain/root, a height gap, a changed native parent
    /// hash/result or Iroha predecessor, or inconsistent authenticated successor slots.
    pub fn verify_immediate_global_successor_of(
        &self,
        parent: &Self,
        expected_network: NetworkId,
        expected_chain: &str,
    ) -> Result<(), FinalityError> {
        parent.verify_global_scope(expected_network, expected_chain)?;
        self.verify_global_scope(expected_network, expected_chain)?;
        let header = self
            .0
            .header
            .as_ref()
            .ok_or_else(|| FinalityError("Global successor has no native header".into()))?;
        need(
            parent.height().checked_add(1) == Some(self.height())
                && header.parent_hash == parent.core_hash()
                && header.parent_result == parent.result()
                && self.header().prev_block_hash() == Some(parent.header().hash()),
            "Global successor differs from its exact authenticated native parent",
        )?;
        let previous = &parent.commitment().schedule;
        let current = &self.commitment().schedule;
        need(
            previous.height == parent.height() && current.height == self.height(),
            "Global successor schedule differs from its authenticated block heights",
        )?;
        // Both opaque receipts already passed the complete individual schedule/epoch and
        // QC/availability checks. Exact parent R joins the child's boundary/beacon authority
        // to this original commitment; the pure cross-result rule has one canonical owner.
        previous
            .validate_successor_relation(current)
            .map_err(malformed)
    }

    /// Canonical executed bytes with only the node-local certificate removed.
    ///
    /// # Errors
    /// Canonical wire encoding fails.
    pub fn canonical_executed_wire(&self) -> Result<Vec<u8>, FinalityError> {
        self.0
            .block
            .clone()
            .with_commit_certificate(None)
            .encode_wire()
            .map_err(malformed)
    }
    /// Verify a successful external transaction's exact input/output membership and signature.
    ///
    /// # Errors
    /// Rejection, foreign network, invalid signature, substituted output or invalid inclusion.
    pub fn verify_committed_transaction(
        &self,
        network: &NetworkId,
        committed: &CommittedTransaction,
    ) -> Result<(), FinalityError> {
        need(
            self.height() > 1,
            "genesis execution needs independent node attestations or a certified successor",
        )?;
        let TransactionEntrypoint::External(transaction) = committed.entrypoint() else {
            return Err(FinalityError(
                "expected external committed transaction".into(),
            ));
        };
        need(
            committed.result().is_ok()
                && transaction.network_id() == Some(network)
                && transaction.verify_signature().is_ok()
                && committed.verify_inclusion_in_block(&self.0.block),
            "transaction does not match successful authenticated execution",
        )
    }
}

#[derive(Debug, Clone)]
struct Decision {
    block_hash: HashOf<BlockHeader>,
    core_hash: Hash32,
    result: Hash32,
    committee_digest: [u8; 32],
    schedule: ScheduleOutcome,
    beacon: Option<crate::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
    executed_hash: Hash,
    executed_len: u64,
}

// Selected-roster and root-instance checks shared only by the two canonical genesis
// owners. Callers first run their original ProofCrypto/authentication order; this private
// borrowed kernel creates no authority token, body clone or second metadata decoder.
fn authenticated_genesis_instance(
    trusted_genesis: &SignedBlock,
    chain_id: &str,
    validators: &[FinalityValidator],
    crypto: &ProofCrypto,
    epoch: &crate::sumeragi::epoch::ValidatorEpochContextV1,
    root_scope: crate::block::consensus::SumeragiRootScope,
) -> Result<Hash32, FinalityError> {
    need(
        validators.len() == epoch.committee.len()
            && validators
                .iter()
                .zip(&epoch.committee)
                .all(|(selected, member)| {
                    selected.public_key == *member.validator.public_key()
                        && selected.proof_of_possession == member.proof_of_possession
                }),
        "selected roster differs from signed genesis authority",
    )?;
    root_scope
        .instance_id(
            crypto,
            crate::NetworkId::from_genesis_hash(trusted_genesis.hash()),
            chain_id,
        )
        .map_err(malformed)
}

/// Independent current-certificate verifier retaining only authenticated prefix decisions.
#[derive(Debug, Clone)]
pub struct SumeragiFinalityVerifier {
    genesis: SignedBlock,
    chain_id: String,
    genesis_committee: Vec<FinalityValidator>,
    instance: Hash32,
    genesis_committee_digest: [u8; 32],
    genesis_epoch: crate::sumeragi::epoch::ValidatorEpochContextV1,
    genesis_metadata: crate::parameter::system::ConsensusHandshakeMetadata,
    decisions: BTreeMap<u64, Decision>,
}
impl SumeragiFinalityVerifier {
    /// Begin with a caller-authenticated signed genesis and its independently selected roster.
    /// The caller must validate the genesis signature before selecting this trust root.
    ///
    /// # Errors
    /// The root is not genesis or its committee keys/PoPs are invalid.
    pub fn new(
        trusted_genesis: &SignedBlock,
        chain_id: &str,
        validators: Vec<FinalityValidator>,
    ) -> Result<Self, FinalityReadError> {
        Self::new_with_validation(trusted_genesis, chain_id, validators, None)
    }
    fn new_with_validation(
        trusted_genesis: &SignedBlock,
        chain_id: &str,
        validators: Vec<FinalityValidator>,
        validation: Option<&EpochValidationScope>,
    ) -> Result<Self, FinalityReadError> {
        need(
            trusted_genesis.header().is_genesis(),
            "trust root must be signed genesis",
        )?;
        let (crypto, committee) = ProofCrypto::new(&validators)?;
        let authenticated =
            genesis::authenticated_genesis_with_validation(trusted_genesis, validation)?;
        let genesis_metadata = authenticated.metadata();
        let (genesis_epoch, root_scope) = authenticated.into_parts();
        let instance = authenticated_genesis_instance(
            trusted_genesis,
            chain_id,
            &validators,
            &crypto,
            &genesis_epoch,
            root_scope,
        )?;
        Ok(Self {
            genesis: trusted_genesis.clone(),
            chain_id: chain_id.to_owned(),
            genesis_committee: validators,
            genesis_epoch,
            genesis_metadata,
            instance,
            genesis_committee_digest: chain_hash(&committee_digest_preimage(&committee)).0,
            decisions: BTreeMap::new(),
        })
    }
    /// Exact chain label selected with this owner's authenticated signed genesis.
    /// This immutable value participates in the consensus instance binding.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
    /// The selected current consensus instance.
    #[must_use]
    pub fn instance(&self) -> Hash32 {
        self.instance
    }
    /// Exact initial epoch reconstructed from this owner's authenticated signed
    /// genesis, including its network, generation and original ordered key `PoPs`.
    /// This does not authenticate any genesis execution result or later epoch.
    /// The installation owner must independently select and pin the genesis root.
    #[must_use]
    pub const fn initial_epoch(&self) -> &crate::sumeragi::epoch::ValidatorEpochContextV1 {
        &self.genesis_epoch
    }
    /// Initial lag-two chain parameters from the retained original signed body.
    /// All seven explicit Sumeragi instructions remain mandatory and unique;
    /// the block cadence comes from its unique signed consensus metadata. These
    /// values seed the native Ready slots for heights two and three, never from
    /// an unauthenticated genesis execution result or current mutable state.
    ///
    /// # Errors
    /// Rejects missing, duplicate or invalid original explicit parameters. The cadence
    /// is retained from construction's canonical authentication, with no further decoding.
    /// This never fills omitted fields with local defaults, changes the selected root,
    /// or grants global scope.
    pub fn initial_chain_parameters(&self) -> Result<ChainParamsRecord, GenesisReadError> {
        #[cfg(not(all(test, sumeragi_model_mutation = "DM14")))]
        let metadata = self.genesis_metadata;
        #[cfg(all(test, sumeragi_model_mutation = "DM14"))]
        let metadata = signed_genesis_consensus_metadata(&self.genesis)?;
        explicit_genesis_chain_parameters(&self.genesis, metadata.block_cadence_ms)
    }
    /// Immutable root ownership from the original independently selected signed genesis.
    ///
    /// Parent-network services must require [`crate::block::consensus::SumeragiRootScope::Global`]
    /// explicitly; a valid private-root certificate does not grant global parent authority.
    /// This returns the same constructor-authenticated scalar; it performs no decoding.
    #[must_use]
    pub const fn root_scope(&self) -> crate::block::consensus::SumeragiRootScope {
        self.genesis_metadata.sumeragi_context.root_scope
    }
    /// Admit exactly the next proof into the authenticated contiguous prefix.
    ///
    /// # Errors
    /// Gaps, altered roots, wrong committee/instance, or any invalid certificate/binding.
    pub fn verify(
        &mut self,
        proof: &SumeragiFinalityProof,
    ) -> Result<VerifiedSumeragiBlock, FinalityError> {
        let next = match self.decisions.last_key_value() {
            None => 1,
            Some((height, _)) => height
                .checked_add(1)
                .ok_or_else(|| FinalityError("authenticated height exhausted".into()))?,
        };
        need(
            proof.height() == next,
            "proof must immediately extend the authenticated prefix",
        )?;
        let decoded = self.check(proof)?;
        self.decisions.insert(next, Self::decision(&decoded));
        Ok(VerifiedSumeragiBlock(decoded))
    }
    /// Re-verify an alternate certificate witness for a decision already in this prefix.
    /// Equal inputs still undergo cryptographic verification and prefix-membership checks.
    ///
    /// # Errors
    /// Either proof is outside this prefix or carries a different decision or invalid witness.
    pub fn verify_same_decision(
        &self,
        retained: &SumeragiFinalityProof,
        candidate: &SumeragiFinalityProof,
    ) -> Result<VerifiedSumeragiBlock, FinalityError> {
        need(
            retained.height() == candidate.height(),
            "alternate proof height differs",
        )?;
        self.verify_retained_decision(retained)?;
        self.verify_retained_decision(candidate)
    }
    /// Verify a witness against this verifier's retained authenticated decision and parent.
    /// The candidate supplies no trust root; importing a checkpoint must already have selected
    /// its complete retained commitments independently of this proof.
    ///
    /// # Errors
    /// Missing retained decision or parent, invalid witness, or any changed decision field.
    pub fn verify_retained_decision(
        &self,
        candidate: &SumeragiFinalityProof,
    ) -> Result<VerifiedSumeragiBlock, FinalityError> {
        self.verify_retained_decision_with_validation(candidate, None)
    }

    // Checkpoint import and export borrow their lexical pure epoch work here, without
    // another owned proof return boundary. Standalone witness readers pass None.
    fn verify_retained_decision_with_validation(
        &self,
        candidate: &SumeragiFinalityProof,
        mut validation: Option<&mut EpochValidationScope>,
    ) -> Result<VerifiedSumeragiBlock, FinalityError> {
        let expected = self
            .decisions
            .get(&candidate.height())
            .ok_or_else(|| FinalityError("decision is outside authenticated prefix".into()))?;
        let (decoded, proposal, crypto) =
            candidate.decode_parts_with_validation(validation.as_deref_mut())?;
        self.check_trusted(
            candidate,
            &decoded,
            proposal.as_deref(),
            &crypto,
            validation,
        )?;
        // check() releases these original owners before returning its decoded graph. Preserve
        // that reverse-binding drop order before the retained comparison on this direct path.
        drop(crypto);
        drop(proposal);
        // Compare the checked graph in place; only new prefix insertion owns a decision copy.
        need(
            decoded.block.hash() == expected.block_hash
                && decoded.core_hash == expected.core_hash
                && decoded.result == expected.result
                && decoded.committee_digest == expected.committee_digest
                && decoded.commitment.schedule == expected.schedule
                && decoded.commitment.beacon == expected.beacon
                && decoded.commitment.execution.executed_block_wire_hash == expected.executed_hash
                && decoded.commitment.execution.executed_block_wire_len == expected.executed_len,
            "proof differs from retained authenticated decision",
        )?;
        Ok(VerifiedSumeragiBlock(decoded))
    }

    fn decision(value: &DecodedSumeragiBlock) -> Decision {
        Decision {
            block_hash: value.block.hash(),
            core_hash: value.core_hash,
            result: value.result,
            committee_digest: value.committee_digest,
            schedule: value.commitment.schedule.clone(),
            beacon: value.commitment.beacon,
            executed_hash: value.commitment.execution.executed_block_wire_hash,
            executed_len: value.commitment.execution.executed_block_wire_len,
        }
    }
    fn check(&self, proof: &SumeragiFinalityProof) -> Result<DecodedSumeragiBlock, FinalityError> {
        let (decoded, proposal, crypto) = proof.decode_parts()?;
        self.check_trusted(proof, &decoded, proposal.as_deref(), &crypto, None)?;
        Ok(decoded)
    }

    // Authenticate the original decoded graph against this verifier's selected root/prefix.
    // Borrow the original proposal and crypto owners through the same last RS16 check; callers
    // release them at the original check boundary before comparing retained decision fields.
    #[inline(never)]
    #[expect(
        clippy::suspicious_operation_groupings,
        reason = "the child header intentionally binds the parent's core hash and result"
    )]
    fn check_trusted(
        &self,
        proof: &SumeragiFinalityProof,
        decoded: &DecodedSumeragiBlock,
        proposal: Option<&[u8]>,
        crypto: &ProofCrypto,
        mut validation: Option<&mut EpochValidationScope>,
    ) -> Result<(), FinalityError> {
        let height = proof.height();
        if height == 1 {
            need(
                proof.block_header.hash() == self.genesis.hash()
                    && decoded
                        .block
                        .canonical_resultless_proposal()
                        .map_err(malformed)?
                        .encode_wire()
                        .map_err(malformed)?
                        == self
                            .genesis
                            .canonical_resultless_proposal()
                            .map_err(malformed)?
                            .encode_wire()
                            .map_err(malformed)?
                    && decoded.committee_digest == self.genesis_committee_digest
                    && decoded.commitment.schedule.current == self.genesis_epoch,
                "genesis proof differs from independently selected signed root",
            )?;
            validation
                .as_deref_mut()
                .map_or_else(
                    || ConsensusSchedule::from_genesis_outcome(&decoded.commitment.schedule),
                    |validation| {
                        ConsensusSchedule::from_genesis_outcome_with_validation(
                            &decoded.commitment.schedule,
                            validation,
                        )
                    },
                )
                .map_err(malformed)?;
        } else {
            let parent = self
                .decisions
                .get(&(height - 1))
                .ok_or_else(|| FinalityError("authenticated parent is missing".into()))?;
            validation
                .as_deref_mut()
                .map_or_else(
                    || {
                        parent
                            .schedule
                            .validate_successor(&decoded.commitment.schedule)
                    },
                    |validation| {
                        parent.schedule.validate_successor_with_validation(
                            &decoded.commitment.schedule,
                            validation,
                        )
                    },
                )
                .map_err(malformed)?;
            if let Some(boundary) = &decoded.commitment.schedule.boundary {
                need(
                    boundary.selection_anchor == parent.block_hash,
                    "boundary selection anchor differs from certified parent",
                )?;
                let pulse = parent.beacon.as_ref().ok_or_else(|| {
                    FinalityError("boundary predecessor omits its certified selection pulse".into())
                })?;
                need(
                    boundary.next.leader_seed
                        == global_threshold_beacon_npos_successor_seed_v1(
                            pulse,
                            height,
                            boundary.next.authorization.epoch,
                        ),
                    "boundary leader seed differs from certified fresh pulse",
                )?;
                if let Some(preparation) = &boundary.preparation {
                    need(
                        preparation.election_seed
                            == election_seed(
                                decoded.commitment.schedule.current.network_id,
                                decoded.commitment.schedule.current.authorization.epoch,
                                pulse,
                            )
                            .map_err(malformed)?,
                        "frozen election seed differs from certified fresh pulse",
                    )?;
                }
            }
            let header = decoded
                .header
                .as_ref()
                .ok_or_else(|| FinalityError("current header missing".into()))?;
            need(
                header.instance == self.instance
                    && header.parent_hash == parent.core_hash
                    && header.parent_result == parent.result
                    && decoded.block.header().prev_block_hash() == Some(parent.block_hash),
                "proof breaks authenticated instance, parent/result or authenticated epoch binding",
            )?;
            let ScheduledSlot::Ready(scheduled) = &parent.schedule.next else {
                return Err(FinalityError(
                    "parent has no authenticated next-height configuration".into(),
                ));
            };
            need(
                scheduled.height == height,
                "availability configuration height differs",
            )?;
            let config = validation
                .map_or_else(
                    || scheduled.height_config(),
                    |validation| scheduled.height_config_with_validation(validation),
                )
                .map_err(malformed)?;
            let availability = decoded
                .availability
                .as_ref()
                .ok_or_else(|| FinalityError("mandatory availability frame is absent".into()))?;
            let payload = proposal
                .ok_or_else(|| FinalityError("canonical proposal image is absent".into()))?;
            verify_payload_availability(
                self.instance,
                &config,
                header,
                availability,
                payload,
                crypto,
            )?;
        }
        Ok(())
    }
}

/// One current node's challenge-bound immutable tip capture and runtime identities.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::SumeragiFinalityAttestationBody")]
pub struct SumeragiFinalityAttestationBody {
    /// Fresh, nonzero caller challenge.
    pub challenge: [u8; 32],
    /// Fresh Unix milliseconds sampled by the installed reporting node immediately before signing.
    /// This is a signed software-clock observation, distinct from the certified block timestamp.
    pub observed_at_unix_ms: u64,
    /// Genesis-derived selected network.
    pub network_id: NetworkId,
    /// Signing node's BLS identity.
    pub node_id: PeerId,
    /// Hash of canonical encoded node identity.
    pub node_fingerprint: Hash,
    /// Installed executable identity.
    pub build_fingerprint: Hash,
    /// Effective consensus configuration identity.
    pub config_fingerprint: Hash,
    /// The captured state's genesis hash.
    pub genesis_block_hash: HashOf<BlockHeader>,
    /// Current result-only genesis frame.
    pub genesis_finality_proof: SumeragiFinalityProof,
    /// Live `NodeHandle` status captured for this tip.
    pub status: SumeragiStatus,
    /// Current committed tip frame and certificate.
    pub finality_proof: SumeragiFinalityProof,
}
impl SumeragiFinalityAttestationBody {
    /// Domain-separated hash signed by the reporting node.
    #[must_use]
    pub fn signing_hash(&self) -> HashOf<Self> {
        HashOf::from_untyped_unchecked(Hash::new_from_chunks(&[
            FINALITY_ATTESTATION_DOMAIN,
            &self.encode(),
        ]))
    }
    /// Validate structural duplicate bindings; authority still requires the selected node signature.
    ///
    /// # Errors
    /// Wrong challenge, runtime identity, status, genesis, height or certificate binding.
    pub fn validate_consistency(&self) -> Result<(), FinalityError> {
        need(
            self.challenge != [0; 32]
                && self.observed_at_unix_ms != 0
                && self.node_fingerprint == Hash::new(self.node_id.encode())
                && self.node_id.public_key().algorithm() == Algorithm::BlsNormal
                && self.network_id == NetworkId::from_genesis_hash(self.genesis_block_hash)
                && self.genesis_finality_proof.height() == 1
                && self.genesis_finality_proof.block_header.hash() == self.genesis_block_hash
                && self.status.protocol_version == crate::sumeragi::PROTOCOL_VERSION
                && self.status.halted.is_none()
                && self
                    .status
                    .signer
                    .as_ref()
                    .is_none_or(|key| key == self.node_id.public_key())
                && self.status.committed_height == self.finality_proof.height()
                && self.status.applied_height == self.status.committed_height,
            "attestation challenge, identity or durable-tip binding differs",
        )?;
        let (genesis, tip) = if norito::core::decode_limits_active() {
            // Preserve both independent decodes and every original cumulative admission.
            let genesis = self.genesis_finality_proof.decode_checked()?;
            let tip = self.finality_proof.decode_checked()?;
            (genesis, tip)
        } else {
            // Share only exact immutable epoch validation inside this one statement. Each
            // proof still decodes its full frame and checks its own roster and certificate.
            let mut validation = EpochValidationScope::new();
            let genesis = self
                .genesis_finality_proof
                .decode_parts_with_validation(Some(&mut validation))
                .map(|(decoded, _, _)| decoded)?;
            let tip = self
                .finality_proof
                .decode_parts_with_validation(Some(&mut validation))
                .map(|(decoded, _, _)| decoded)?;
            (genesis, tip)
        };
        if let Some(header) = tip.header.as_ref() {
            need(
                header.instance.0 == self.status.instance,
                "attestation status instance differs",
            )?;
        } else {
            need(
                tip.core_hash == genesis.core_hash
                    && tip.result == genesis.result
                    && tip.commitment == genesis.commitment,
                "height-one attestation carries different genesis execution",
            )?;
        }
        Ok(())
    }
}

/// BLS node signature over one exact current finality capture.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::SumeragiFinalityAttestation")]
pub struct SumeragiFinalityAttestation {
    /// Complete challenged statement.
    pub body: SumeragiFinalityAttestationBody,
    /// Reporting node's signature over the domain-separated body hash.
    pub signature: SignatureOf<SumeragiFinalityAttestationBody>,
}
impl SumeragiFinalityAttestation {
    /// Check body consistency and its declared node's signature; callers must select that node independently.
    ///
    /// # Errors
    /// Malformed body or invalid BLS signature.
    pub fn verify(&self) -> Result<(), FinalityError> {
        self.body.validate_consistency()?;
        self.signature
            .verify_hash(self.body.node_id.public_key(), self.body.signing_hash())
            .map_err(malformed)
    }
}

/// BLS-normal crypto over one proof-of-possession-verified committee, in canonical order.
/// Shared with the AMX foreign-committee tracker (`crate::sumeragi_amx`).
pub(crate) struct ProofCrypto {
    keys: BTreeMap<CoreKey, BlsNormalPopVerifiedKey>,
}
impl ProofCrypto {
    pub(crate) fn new(
        validators: &[FinalityValidator],
    ) -> Result<(Self, Committee), FinalityError> {
        need(
            crate::block::consensus::is_valid_committee_size(validators.len()),
            "committee must have exact first-release global voting geometry",
        )?;
        let mut keys = BTreeMap::new();
        let mut ordered = Vec::new();
        for validator in validators {
            let (algorithm, bytes) = validator.public_key.try_to_bytes().map_err(malformed)?;
            need(
                algorithm == Algorithm::BlsNormal,
                "committee key is not BLS-normal",
            )?;
            let key = CoreKey::new(bytes.to_vec()).map_err(malformed)?;
            let verified =
                BlsNormalPopVerifiedKey::new(&validator.public_key, &validator.proof_of_possession)
                    .map_err(malformed)?;
            need(
                keys.insert(key.clone(), verified).is_none(),
                "duplicate committee key",
            )?;
            ordered.push(key);
        }
        let committee = Committee::new(ordered.clone()).map_err(malformed)?;
        need(
            ordered == committee.members(),
            "committee is not in canonical consensus key order",
        )?;
        Ok((Self { keys }, committee))
    }
}
impl Crypto for ProofCrypto {
    fn hash(&self, bytes: &[u8]) -> Hash32 {
        chain_hash(bytes)
    }
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32 {
        Hash32(Hash::new_from_chunks(chunks).into())
    }
    fn verify(&self, pk: &CoreKey, msg: &[u8], signature: &Signature) -> bool {
        PublicKey::from_bytes(Algorithm::BlsNormal, pk.as_bytes()).is_ok_and(|key| {
            iroha_crypto::Signature::from_bytes(&signature.0)
                .verify(&key, msg)
                .is_ok()
        })
    }
    fn aggregate(&self, signatures: &[Signature]) -> AggregateSignature {
        let slices: Vec<&[u8]> = signatures
            .iter()
            .map(|signature| signature.0.as_slice())
            .collect();
        AggregateSignature(
            bls_normal_aggregate_signatures(&slices)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .unwrap_or([0; 96]),
        )
    }
    fn verify_aggregate(
        &self,
        keys: &[&CoreKey],
        message: &[u8],
        signature: &AggregateSignature,
    ) -> bool {
        self.verify_aggregate_multi(&[(keys.to_vec(), message.to_vec())], signature)
    }
    fn verify_aggregate_multi(
        &self,
        groups: &[(Vec<&CoreKey>, Vec<u8>)],
        signature: &AggregateSignature,
    ) -> bool {
        let Some(keys) = groups
            .iter()
            .map(|(keys, _)| {
                keys.iter()
                    .map(|key| self.keys.get(*key))
                    .collect::<Option<Vec<_>>>()
            })
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        let groups: Vec<(&[&BlsNormalPopVerifiedKey], &[u8])> = keys
            .iter()
            .zip(groups)
            .map(|(keys, (_, message))| (keys.as_slice(), message.as_slice()))
            .collect();
        bls_normal_verify_preaggregated_multi_message(&groups, &signature.0).is_ok()
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod attestation_validation_tests;

#[cfg(test)]
mod immediate_successor_tests;

#[cfg(all(test, feature = "transparent_api"))]
mod retained_decision_tests;

/// Fixed public signing material for native proof tests; never deployment trust or execution evidence.
#[cfg(any(test, all(feature = "test-fixtures", feature = "transparent_api")))]
pub mod test_fixtures;

#[cfg(all(test, feature = "transparent_api"))]
mod configuration_fingerprint_tests {
    use super::*;
    use crate::{
        account::AccountId,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use std::time::Duration;

    fn signed_parameters(
        original: &SignedBlock,
        parameters: Vec<SumeragiParameter>,
        cadence: Option<std::num::NonZeroU64>,
    ) -> SignedBlock {
        let mut instructions: Vec<crate::isi::InstructionBox> = original
            .external_transactions()
            .flat_map(|transaction| {
                let Executable::Instructions(instructions) = transaction.instructions() else {
                    panic!("fixture requires signed instructions");
                };
                instructions
                    .iter()
                    .filter(|instruction| {
                        !instruction
                            .as_any()
                            .downcast_ref::<SetParameter>()
                            .is_some_and(|set| matches!(set.inner(), Parameter::Sumeragi(_)))
                    })
                    .cloned()
            })
            .collect();
        if let Some(cadence) = cadence {
            use crate::parameter::{CustomParameter, system::consensus_metadata};
            let mut metadata = signed_genesis_consensus_metadata(original).unwrap();
            metadata.block_cadence_ms = cadence;
            instructions.retain(|instruction| {
                !instruction.as_any().downcast_ref::<SetParameter>().is_some_and(|set| {
                    matches!(set.inner(), Parameter::Custom(custom) if custom.id() == &consensus_metadata::handshake_meta_id())
                })
            });
            instructions.push(
                SetParameter::new(Parameter::Custom(CustomParameter::new(
                    consensus_metadata::handshake_meta_id(),
                    iroha_primitives::json::Json::new(metadata),
                )))
                .into(),
            );
        }
        instructions.extend(
            parameters
                .into_iter()
                .map(|parameter| SetParameter::new(Parameter::Sumeragi(parameter)).into()),
        );
        let authority = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
        let mut transaction = TransactionBuilder::new_genesis(
            AccountId::new(authority.public_key().clone()),
            FeePaymentIntent::authority(vec![], None),
        );
        transaction.set_creation_time(Duration::ZERO);
        let transaction = transaction
            .with_instructions(instructions)
            .sign(authority.private_key());
        SignedBlock::try_genesis(vec![transaction], authority.private_key(), None, None).unwrap()
    }

    #[test]
    fn explicit_parameters_reject_every_missing_and_repeated_signed_field() {
        let fixture = test_fixtures::NativeFinalityFixture::new_with_explicit_parameters();
        let parameters: Vec<_> = SumeragiParameters::default().parameters().collect();
        assert_eq!(parameters.len(), 7);
        let expected = consensus_configuration_fingerprint(fixture.genesis()).unwrap();
        assert_eq!(
            expected,
            consensus_configuration_fingerprint(&signed_parameters(
                fixture.genesis(),
                parameters.clone(),
                None,
            ))
            .unwrap()
        );
        for index in 0..parameters.len() {
            let mut missing = parameters.clone();
            missing.remove(index);
            let missing = signed_parameters(fixture.genesis(), missing, None);
            assert!(consensus_configuration_fingerprint(&missing).is_err());
            assert!(
                selected_verifier(&fixture, &missing)
                    .initial_chain_parameters()
                    .is_err()
            );
            let mut repeated = parameters.clone();
            repeated.push(parameters[index]);
            let repeated = signed_parameters(fixture.genesis(), repeated, None);
            assert!(consensus_configuration_fingerprint(&repeated).is_err());
            assert!(
                selected_verifier(&fixture, &repeated)
                    .initial_chain_parameters()
                    .is_err()
            );
        }
        assert!(
            consensus_configuration_fingerprint(
                test_fixtures::NativeFinalityFixture::new().genesis()
            )
            .is_err()
        );
    }

    fn selected_verifier(
        fixture: &test_fixtures::NativeFinalityFixture,
        genesis: &SignedBlock,
    ) -> SumeragiFinalityVerifier {
        SumeragiFinalityVerifier::new(
            genesis,
            fixture.chain_id(),
            fixture.genesis_proof().committee.clone(),
        )
        .unwrap()
    }

    #[test]
    fn initial_signed_values_seed_both_ready_slots_and_exact_fingerprint_bytes() {
        let fixture = test_fixtures::NativeFinalityFixture::new_with_explicit_parameters();
        let selected = selected_verifier(&fixture, fixture.genesis());
        let epoch = authenticated_genesis(fixture.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
        assert_eq!(selected.initial_epoch(), &epoch);
        assert_eq!(epoch.network_id, fixture.network_id());
        assert_eq!(epoch.authorization.epoch, 0);
        assert_eq!(epoch.authorization.first_height, 1);
        assert_eq!(
            selected.root_scope(),
            crate::block::consensus::SumeragiRootScope::Global
        );

        let mut authored = SumeragiParameters::default();
        authored.block_cadence_ms = std::num::NonZeroU64::new(1100).unwrap();
        authored.payload_retry_interval_ms =
            std::num::NonZeroU64::new(authored.payload_retry_interval_ms.get() + 1).unwrap();
        authored.exec_budget_ms =
            std::num::NonZeroU64::new(authored.exec_budget_ms.get() + 1).unwrap();
        authored.apply_budget_ms =
            std::num::NonZeroU64::new(authored.apply_budget_ms.get() + 1).unwrap();
        authored.max_block_bytes =
            std::num::NonZeroU32::new(authored.max_block_bytes.get() - 1).unwrap();
        authored.epoch_length_blocks =
            std::num::NonZeroU64::new(authored.epoch_length_blocks.get() + 1).unwrap();
        let changed = signed_parameters(
            fixture.genesis(),
            authored.parameters().collect(),
            Some(authored.block_cadence_ms),
        );
        let changed_owner = selected_verifier(&fixture, &changed);
        let expected = ChainParamsRecord::from_parameters(&authored);
        assert_eq!(changed_owner.initial_chain_parameters().unwrap(), expected);
        let schedule =
            ConsensusSchedule::from_genesis(changed_owner.initial_epoch().clone(), expected)
                .unwrap();
        for height in [2, 3] {
            let slot = schedule.ready(height).unwrap();
            assert_eq!(slot.height, height);
            assert_eq!(slot.epoch, *changed_owner.initial_epoch());
            assert_eq!(slot.params, expected);
        }

        // The fingerprint remains exactly the existing native tuple transcript,
        // including its unchanged domain and canonical encoding. The new owner
        // exposes fields; it introduces no alternate configuration wire layout.
        for (genesis, owner, expected) in [
            (
                fixture.genesis(),
                &selected,
                ChainParamsRecord::from_parameters(&SumeragiParameters::default()),
            ),
            (&changed, &changed_owner, expected),
        ] {
            let bytes = norito::encode_canonical(&(
                crate::sumeragi::PROTOCOL_VERSION,
                authenticated_genesis(genesis)
                    .map(|genesis| genesis.into_parts().0)
                    .unwrap(),
                expected,
            ))
            .unwrap();
            let owned_bytes = norito::encode_canonical(&(
                crate::sumeragi::PROTOCOL_VERSION,
                owner.initial_epoch().clone(),
                owner.initial_chain_parameters().unwrap(),
            ))
            .unwrap();
            assert_eq!(bytes, owned_bytes);
            assert_eq!(
                consensus_configuration_fingerprint(genesis).unwrap(),
                Hash::new_from_chunks(&[b"iroha:native-config:v1", &bytes])
            );
        }
        assert_eq!(
            selected.initial_chain_parameters().unwrap(),
            ChainParamsRecord::from_parameters(&SumeragiParameters::default())
        );
        assert_ne!(selected.instance(), changed_owner.instance());
    }

    #[test]
    fn initial_readers_require_the_original_signature_and_roster_owner() {
        let fixture = test_fixtures::NativeFinalityFixture::new_with_explicit_parameters();
        let mut wrong_pop = fixture.genesis_proof().committee.clone();
        wrong_pop[0].proof_of_possession[0] ^= 1;
        assert!(
            SumeragiFinalityVerifier::new(fixture.genesis(), fixture.chain_id(), wrong_pop)
                .is_err()
        );
        let mut tampered = fixture.genesis().clone();
        let foreign = KeyPair::from_seed(vec![0xA6; 32], Algorithm::Ed25519);
        tampered
            .replace_signatures(
                crate::block::BlockSignatures::try_from_iter([crate::block::BlockSignature::new(
                    0,
                    SignatureOf::new(foreign.private_key(), &tampered.header()),
                )])
                .unwrap(),
            )
            .unwrap();
        assert!(
            SumeragiFinalityVerifier::new(
                &tampered,
                fixture.chain_id(),
                fixture.genesis_proof().committee.clone()
            )
            .is_err()
        );
        let private = test_fixtures::NativeFinalityFixture::start_with_scope(
            fixture.chain_id(),
            crate::block::consensus::SumeragiRootScope::Dataspace {
                parent_network_id: fixture.network_id(),
                dataspace_id: iroha_model_base::topology::DataSpaceId::new(9),
            },
        );
        let owner = private.verifier();
        assert!(matches!(
            owner.root_scope(),
            crate::block::consensus::SumeragiRootScope::Dataspace { .. }
        ));
        assert_ne!(owner.initial_epoch().network_id, fixture.network_id());
        assert_ne!(owner.instance(), fixture.verifier().instance());
        assert!(
            owner.initial_chain_parameters().is_err(),
            "private roots also require explicit signed parameters; no defaults"
        );
    }

    #[test]
    fn signed_configuration_changes_bind_the_hash_and_invalid_signatures_refuse() {
        let fixture = test_fixtures::NativeFinalityFixture::new_with_explicit_parameters();
        let original = consensus_configuration_fingerprint(fixture.genesis()).unwrap();
        let mut parameters: Vec<_> = SumeragiParameters::default().parameters().collect();
        for parameter in &mut parameters {
            if let SumeragiParameter::PayloadRetryIntervalMs(value) = parameter {
                *value = std::num::NonZeroU64::new(value.get() + 1).unwrap();
            }
        }
        let changed = signed_parameters(fixture.genesis(), parameters, None);
        assert_ne!(
            original,
            consensus_configuration_fingerprint(&changed).unwrap()
        );
        let mut tampered = fixture.genesis().clone();
        let foreign = KeyPair::from_seed(vec![0xC9; 32], Algorithm::Ed25519);
        let signature = crate::block::BlockSignature::new(
            0,
            SignatureOf::new(foreign.private_key(), &tampered.header()),
        );
        tampered
            .replace_signatures(
                crate::block::BlockSignatures::try_from_iter([signature])
                    .expect("at most 31 block signatures"),
            )
            .unwrap();
        assert!(consensus_configuration_fingerprint(&tampered).is_err());
    }
}
