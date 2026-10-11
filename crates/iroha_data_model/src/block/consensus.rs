//! Norito-encoded consensus types shared across Sumeragi components.
//!
//! These types cover committee geometry, signed consensus genesis parameters and height
//! context identities, the signed RS16 layout, operator diagnostics, SORA Nexus fee and
//! settlement receipts, and execution witnesses. The consensus state machine, messages and
//! original-row availability verification live in `iroha_sumeragi`; certified block proofs
//! and execution commitments are owned by [`crate::sumeragi_finality`].
use super::Header as BlockHeader;
use iroha_sumeragi::availability::{DataAvailabilityLayout, recommended_data_availability_layout};

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use crate::{
    account::AccountId,
    asset::AssetDefinitionId,
    fastpq::{FastpqTransitionBatch, TransferTranscriptBundle},
    nexus::{FeeDebitSource, PublicLaneValidatorRecord},
};
use core::{fmt, num::NonZeroU64};
use iroha_crypto::{Hash, HashOf};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId, topology::LaneId};
use iroha_primitives::numeric::{Numeric, Quantity};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, DecodeAll, Encode};
use std::{string::String, vec::Vec};
/// Canonical genesis/handshake fingerprint projection.
pub mod fingerprint;
mod root_scope;
pub use root_scope::SumeragiRootScope;
mod private_root_fees;
pub use private_root_fees::{PrivateRootFeePolicy, PrivateRootFeePolicyError};
/// Height alias for consensus.
pub type Height = u64;
/// View/round number alias.
pub type View = u64;
/// Validator index within the active set.
pub type ValidatorIndex = u32;
/// Consensus-wide lower bound for one voting roster.
///
/// Every production committee has the exact `3f + 1` shape and tolerates at
/// least one Byzantine validator.
pub const MIN_VALIDATORS_PER_HEIGHT: usize = 4;
/// Maximum Byzantine validators tolerated by one frozen height context.
pub const MAX_FAULTS_PER_HEIGHT: usize = 10;
/// Consensus-wide upper bound for one voting roster.
///
/// This is a protocol admission limit, not a local resource-tuning knob.  It
/// must stay aligned with the production reducer and the formal Sumeragi
/// model so every admitted wire value has a representable verified state.
pub const MAX_VALIDATORS_PER_HEIGHT: usize = 3 * MAX_FAULTS_PER_HEIGHT + 1;
/// Returns whether `validator_count` has the production `3f + 1` geometry.
#[must_use]
pub const fn is_valid_committee_size(validator_count: usize) -> bool {
    validator_count >= MIN_VALIDATORS_PER_HEIGHT
        && validator_count <= MAX_VALIDATORS_PER_HEIGHT
        && (validator_count - 1).is_multiple_of(3)
}
/// Permissioned Sumeragi handshake and domain-separation tag.
pub const PERMISSIONED_TAG: &str = "iroha3-consensus::permissioned-sumeragi@v1";
/// `NPoS` Sumeragi handshake and domain-separation tag.
pub const NPOS_TAG: &str = "iroha3-consensus::npos-sumeragi@v1";
/// BLS domain selected by a permissioned genesis.
pub const PERMISSIONED_BLS_DOMAIN: &str = "bls-iroha3:permissioned-sumeragi:v1";
/// BLS domain selected by an `NPoS` genesis.
pub const NPOS_BLS_DOMAIN: &str = "bls-iroha3:npos-sumeragi:v1";
/// Consensus-wide upper bound for the canonical result-bearing block wire.
///
/// This is the protocol authority shared by execution-commitment admission and
/// durable canonical-block storage. It deliberately matches the first-release
/// Kura hard limit; runtime configuration may select a lower bound but must
/// never admit a larger consensus value.
pub const MAX_EXECUTED_BLOCK_WIRE_BYTES: u64 = 256 * 1024 * 1024;
/// Canonical Nexus/AMX context commitment for the repository's recommended
/// single-lane defaults and no staged public-lane validators.
///
/// `iroha_config` owns the projection and pins this value with a golden test.
/// Keeping the bytes here lets configuration-independent genesis builders emit
/// a valid signed template without introducing a data-model/config cycle.
pub const RECOMMENDED_NEXUS_AMX_CONTEXT_HASH: [u8; 32] = [
    184, 201, 137, 127, 132, 160, 253, 49, 98, 200, 33, 224, 106, 253, 214, 89, 70, 108, 60, 163,
    25, 61, 120, 83, 183, 110, 129, 158, 132, 13, 42, 75,
];
/// Canonical V1 boot execution-policy identity emitted by the recommended genesis template.
///
/// Genesis materialization replaces this template value with the identity derived from the
/// complete staged runtime policy before signing. Startup never treats it as a fallback.
pub const RECOMMENDED_EXECUTION_POLICY_HASH: [u8; 32] = [
    63, 148, 116, 83, 117, 143, 142, 233, 11, 44, 102, 67, 122, 18, 143, 194, 45, 147, 196, 210,
    224, 202, 96, 194, 97, 216, 40, 183, 224, 184, 151, 195,
];
pub use crate::parameter::system::ConsensusMode;
impl ConsensusMode {
    /// Return the canonical handshake and signing-domain tag for this mode.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Permissioned => PERMISSIONED_TAG,
            Self::Npos => NPOS_TAG,
        }
    }
    /// Return the canonical BLS domain for this mode.
    #[must_use]
    pub const fn bls_domain(self) -> &'static str {
        match self {
            Self::Permissioned => PERMISSIONED_BLS_DOMAIN,
            Self::Npos => NPOS_BLS_DOMAIN,
        }
    }
}
/// A validator and its consensus vote at one height.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::ValidatorPower")]
pub struct ValidatorPower {
    /// Validator identity and consensus public key.
    pub validator: PeerId,
    /// Consensus vote count. The native protocol requires this to be exactly one.
    pub power: u64,
}
/// Genesis-selected transport inputs needed to construct every Sumeragi
/// height context.
///
/// The value is embedded in the signed consensus-genesis parameters. Live
/// startup must reject a genesis which omits it; it must never reconstruct
/// these fields from a node's mutable runtime configuration.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::SumeragiGenesisContextParameters")]
pub struct SumeragiGenesisContextParameters {
    /// Immutable execution scope and native root-instance kind selected by signed genesis.
    pub root_scope: SumeragiRootScope,
    /// Mandatory deterministic data-availability layout for proposal bodies.
    pub da_layout: DataAvailabilityLayout,
    /// Canonical commitment to the staged Nexus/AMX consensus context.
    ///
    /// This binds enabled state, lane geometry and visibility, dataspace and
    /// routing policy, deterministic AMX budgets, and active public-lane
    /// validator records after staged genesis execution.
    pub nexus_amx_context_hash: [u8; 32],
    /// Canonical V1 identity of every process-local policy input which can affect execution.
    pub execution_policy_hash: [u8; 32],
}
impl SumeragiGenesisContextParameters {
    /// Recommended profile emitted by programmatic genesis builders.
    ///
    /// This value is serialized into, fingerprinted by, and signed with the
    /// genesis block. It is not a live-node fallback.
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            root_scope: SumeragiRootScope::Global,
            da_layout: recommended_data_availability_layout(),
            nexus_amx_context_hash: RECOMMENDED_NEXUS_AMX_CONTEXT_HASH,
            execution_policy_hash: RECOMMENDED_EXECUTION_POLICY_HASH,
        }
    }
    /// Validate the signed context parameters using the same structural rules
    /// enforced for a full height context.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidDataAvailabilityLayout`] for a zero
    /// limit or an encoding/shard mismatch, and rejects zero or non-canonical
    /// policy commitments.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.root_scope.validate()?;
        if self.nexus_amx_context_hash == [0; 32]
            || <[u8; Hash::LENGTH]>::from(Hash::prehashed(self.nexus_amx_context_hash))
                != self.nexus_amx_context_hash
        {
            return Err(ValidationError::InvalidNexusAmxContextHash);
        }
        if self.execution_policy_hash == [0; 32]
            || <[u8; Hash::LENGTH]>::from(Hash::prehashed(self.execution_policy_hash))
                != self.execution_policy_hash
        {
            return Err(ValidationError::InvalidExecutionPolicyHash);
        }
        self.da_layout
            .validate()
            .map_err(|_| ValidationError::InvalidDataAvailabilityLayout)
    }
}
/// Canonical staged active-lane record committed by genesis metadata.
pub type GenesisActiveNexusLaneRecord = ((LaneId, AccountId), PublicLaneValidatorRecord);
/// Typed identity of the native frozen chain parameters.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::HeightContextId")]
pub struct HeightContextId(
    /// Norito hash of the context's semantic identity projection.
    pub HashOf<crate::sumeragi_finality::ChainParamsRecord>,
);
/// Invalid signed consensus metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// A private root names the universal dataspace instead of a distinct child scope.
    InvalidRootScope,
    /// RS16 dimensions or resource bounds are invalid.
    InvalidDataAvailabilityLayout,
    /// The staged Nexus commitment is not a canonical nonzero hash.
    InvalidNexusAmxContextHash,
    /// The staged execution-policy commitment is not a canonical nonzero hash.
    InvalidExecutionPolicyHash,
}
impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRootScope => "invalid Sumeragi root scope",
            Self::InvalidDataAvailabilityLayout => "invalid data-availability layout",
            Self::InvalidNexusAmxContextHash => "invalid Nexus context hash",
            Self::InvalidExecutionPolicyHash => "invalid execution-policy hash",
        })
    }
}
impl std::error::Error for ValidationError {}
/// Build deterministic signed-genesis context parameters for unit tests.
#[cfg(test)]
pub(crate) fn test_genesis_context_parameters() -> SumeragiGenesisContextParameters {
    SumeragiGenesisContextParameters::recommended()
}

/// Canonical consensus parameters included in the genesis fingerprint.
///
/// These parameters are encoded with Norito (binary) in a fixed order to
/// guarantee determinism across peers and platforms.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::ConsensusGenesisParams")]
pub struct ConsensusGenesisParams {
    /// Signed, immutable interval between block-production opportunities.
    pub block_cadence_ms: NonZeroU64,
    /// Block sizing: max transactions per block.
    pub block_max_transactions: NonZeroU64,
    /// Type-safe mode-specific signed consensus parameters.
    pub mode: ConsensusGenesisModeParams,
    /// Explicit global consensus protocol revision.
    pub protocol_version: u32,
    /// Required signed inputs for constructing Sumeragi height contexts.
    pub sumeragi_context: SumeragiGenesisContextParameters,
}
/// Type-safe first-release consensus mode carrier.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::ConsensusGenesisModeParams")]
pub enum ConsensusGenesisModeParams {
    /// Permissioned consensus has no election parameters.
    Permissioned,
    /// Nominated proof-of-stake consensus and its signed election inputs.
    Npos(NposGenesisParams),
}
impl ConsensusGenesisParams {
    /// Validate every frozen first-release consensus input before fingerprinting or use.
    ///
    /// # Errors
    /// Returns a diagnostic for unsupported protocol revisions, invalid Sumeragi
    /// context geometry, or invalid `NPoS` election parameters.
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != u32::from(crate::sumeragi::PROTOCOL_VERSION) {
            return Err(format!(
                "unsupported consensus protocol version {}",
                self.protocol_version
            ));
        }
        self.sumeragi_context
            .validate()
            .map_err(|error| format!("invalid Sumeragi genesis context: {error}"))?;
        if let ConsensusGenesisModeParams::Npos(npos) = &self.mode {
            npos.validate().map_err(str::to_owned)?;
        }
        Ok(())
    }
}
/// `NPoS`-specific consensus parameters hashed into the genesis fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::NposGenesisParams")]
pub struct NposGenesisParams {
    /// Non-zero epoch length in blocks.
    pub epoch_length_blocks: NonZeroU64,
    /// Deterministic epoch seed for PRF-based leader and validator selection.
    pub epoch_seed: [u8; 32],
    /// Exact bounded `3f + 1` ceiling for the next epoch committee.
    pub max_validators: u32,
    /// Minimum self-bond required for validator eligibility.
    pub min_self_bond: Quantity,
    /// Minimum nomination bond required for delegators.
    pub min_nomination_bond: Quantity,
    /// Finality margin in blocks before activating a newly elected set.
    pub finality_margin_blocks: u64,
    /// Evidence retention horizon in blocks.
    pub evidence_horizon_blocks: u64,
    /// Activation lag in blocks for newly scheduled validator sets.
    pub activation_lag_blocks: u64,
    /// Slashing delay in blocks before evidence penalties apply.
    pub slashing_delay_blocks: u64,
}
impl NposGenesisParams {
    /// Validate signed `NPoS` election and reconfiguration inputs.
    ///
    /// # Errors
    /// Returns a stable diagnostic when a seed, bond, or
    /// reconfiguration bound is invalid.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.epoch_seed == [0; 32] {
            return Err("epoch_seed must not be all zero");
        }
        if usize::try_from(self.max_validators)
            .ok()
            .is_none_or(|count| !is_valid_committee_size(count))
        {
            return Err("max_validators must be a bounded 3f + 1 committee size (4..=31)");
        }
        if self.min_self_bond.is_zero() || self.min_nomination_bond.is_zero() {
            return Err("NPoS minimum bond values must be greater than zero");
        }
        if self.finality_margin_blocks == 0
            || self.evidence_horizon_blocks == 0
            || self.activation_lag_blocks == 0
            || self.slashing_delay_blocks == 0
        {
            return Err("NPoS finality and reconfiguration bounds must be greater than zero");
        }
        let accountability_window = self
            .evidence_horizon_blocks
            .checked_add(self.slashing_delay_blocks)
            .ok_or("NPoS evidence-and-slashing window overflows u64")?;
        let retained_roster_window = self
            .epoch_length_blocks
            .get()
            .checked_mul(3)
            .ok_or("NPoS three-epoch evidence capacity window overflows u64")?;
        if accountability_window > retained_roster_window {
            return Err(
                "evidence_horizon_blocks + slashing_delay_blocks must not exceed three epoch lengths",
            );
        }
        Ok(())
    }
}
/// Bounded original native signed evidence, without transported authority state.
///
/// Decode validates canonical native framing and pair ordering. Historical authority,
/// signatures and offender attribution must be verified independently before admission.
#[derive(Clone, Debug, PartialEq, Eq, Encode, IntoSchema, DeriveJsonSerialize)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::Evidence")]
pub struct Evidence {
    /// One exact canonical native evidence frame; no proposal body is permitted.
    pub native: Vec<u8>,
}
impl Evidence {
    /// Canonicalize paired original artifacts and retain their bounded native frame.
    ///
    /// # Errors
    /// Native shape, bound or canonical serialization failure.
    pub fn from_native(
        native: &iroha_sumeragi::message::Evidence,
    ) -> Result<Self, iroha_sumeragi::message::CodecError> {
        let mut canonical = native.clone();
        Self::canonicalize_pairs(&mut canonical)?;
        Ok(Self {
            native: canonical.encode()?,
        })
    }

    /// Decode the exact bounded native frame, rejecting a reversed pair.
    ///
    /// # Errors
    /// Malformed framing, oversized artifacts, proposal bodies or noncanonical order.
    pub fn decode_native(
        &self,
    ) -> Result<iroha_sumeragi::message::Evidence, iroha_sumeragi::message::CodecError> {
        Self::decode_native_frame(self.native_frame())
    }

    /// Decode borrowed original frame bytes through the sole canonical proof validator.
    ///
    /// This creates no replacement owned Evidence or source buffer. Decoded native
    /// artifacts and pair-comparison scratch keep their existing independent custody.
    /// Historical signer authority is not supplied by this syntax operation.
    ///
    /// # Errors
    /// Preserves the same bounded framing, artifact and pair-order error as `decode_native`.
    pub fn decode_native_frame(
        bytes: &[u8],
    ) -> Result<iroha_sumeragi::message::Evidence, iroha_sumeragi::message::CodecError> {
        let native = iroha_sumeragi::message::Evidence::decode(bytes)?;
        let mut canonical = native.clone();
        Self::canonicalize_pairs(&mut canonical)?;
        if canonical != native {
            return Err(iroha_sumeragi::message::CodecError::Norito(
                "native evidence artifact pair is not in canonical frame order".into(),
            ));
        }
        Ok(native)
    }

    /// Borrow the original canonical native evidence bytes.
    #[must_use]
    pub fn native_frame(&self) -> &[u8] {
        &self.native
    }

    fn canonicalize_pairs(
        native: &mut iroha_sumeragi::message::Evidence,
    ) -> Result<(), iroha_sumeragi::message::CodecError> {
        use iroha_sumeragi::message::{CodecError, Evidence as NativeEvidence};
        fn order<T: norito::NoritoSerialize>(
            first: &mut T,
            second: &mut T,
        ) -> Result<(), CodecError> {
            let left = norito::encode_canonical(first).map_err(CodecError::from)?;
            let right = norito::encode_canonical(second).map_err(CodecError::from)?;
            if left > right {
                core::mem::swap(first, second);
            }
            Ok(())
        }
        native.check_limits()?;
        match native {
            NativeEvidence::ProposalEquivocation(first, second) => {
                order(first.as_mut(), second.as_mut())
            }
            NativeEvidence::VoteEquivocation(first, second) => order(first, second),
            NativeEvidence::TimeoutEquivocation(first, second) => {
                order(first.as_mut(), second.as_mut())
            }
            NativeEvidence::ConflictingCertificates(first, second) => order(first, second),
            NativeEvidence::InvalidProposal { .. } => Ok(()),
        }
    }
}
#[derive(Decode, DeriveJsonDeserialize)]
#[norito(deny_unknown_fields)]
struct EvidenceWire {
    native: Vec<u8>,
}
impl<'de> norito::core::DeserializePayload<'de> for Evidence {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical native evidence invariant")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let wire =
            <EvidenceWire as norito::core::DeserializePayload>::try_deserialize(archived.cast())?;
        let evidence = Self {
            native: wire.native,
        };
        evidence
            .decode_native()
            .map_err(norito::core::Error::from)?;
        Ok(evidence)
    }
}
impl norito::json::JsonDeserialize for Evidence {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let wire = <EvidenceWire as norito::json::JsonDeserialize>::json_deserialize(parser)?;
        let evidence = Self {
            native: wire.native,
        };
        evidence.decode_native().map_err(|error| match error {
            iroha_sumeragi::message::CodecError::Resource(resource) => {
                norito::json::Error::from_decode_resource(resource.into())
            }
            other => norito::json::Error::Message(other.to_string()),
        })?;
        Ok(evidence)
    }
}
impl Ord for Evidence {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.native.cmp(&other.native)
    }
}
impl PartialOrd for Evidence {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// One offender resolved from the exact historical native committee.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::block::consensus::EvidenceOffender")]
pub struct EvidenceOffender {
    /// Equal-weight signer index in the authenticated historical committee.
    pub signer: u32,
    /// Original historical peer bound to that signer index.
    pub peer_id: PeerId,
    /// Exact creation-time monetary binding for a lane signer; absent for root reports or
    /// lane members whose original creation had no genuine positive staking custody.
    pub lane_stake: Option<crate::sumeragi_lanes::SumeragiLaneStakeBinding>,
}

/// Original root-chain execution cut that admitted one native lane report.
/// Native subject heights remain in [`EvidenceAttribution::height`]; none of these fields
/// asserts a global occurrence height for the offence.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::block::consensus::LaneEvidenceScope")]
pub struct LaneEvidenceScope {
    /// Physical lane selected by the independently authenticated creation record.
    pub lane: LaneId,
    /// Exact original incarnation, independent of later lane-ID reuse.
    pub incarnation: [u8; 32],
    /// Creation height on the root carrier chain, not a signed native offence height.
    pub created_at: u64,
    /// Original parent of the root carrier that first admitted this report.
    pub admission_parent_height: u64,
    /// Canonical carrier hash of that original parent.
    pub admission_parent_hash: HashOf<BlockHeader>,
    /// Native root consensus hash of that original parent.
    pub admission_parent_core_hash: [u8; 32],
    /// Certified original execution result of that parent.
    pub admission_parent_result: [u8; 32],
}

/// Clock and historical authority of an independently authenticated native report.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_data_model::block::consensus::EvidenceScope")]
pub enum EvidenceScope {
    /// The executing State's root instance; its signed height uses the carrier clock.
    Root,
    /// A pinned native lane instance, authenticated beneath an original root execution cut.
    Lane(LaneEvidenceScope),
}

/// Independently authenticated historical attribution retained with a committed report.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::block::consensus::EvidenceAttribution")]
pub struct EvidenceAttribution {
    /// Distinguishes the root carrier clock from native lane heights and original custody.
    pub scope: EvidenceScope,
    /// Exact native consensus instance.
    pub instance: [u8; 32],
    /// Native height at which the original artifacts were signed.
    pub height: u64,
    /// Scheduling epoch bound by the signatures.
    pub epoch: u64,
    /// Complete authenticated epoch context identity.
    pub context_id: [u8; 32],
    /// Historical signing generation, independently resolved from state.
    pub authority_generation: [u8; 32],
    /// Exact original offenders in increasing signer-index order.
    pub offenders: Vec<EvidenceOffender>,
    /// Whether admission established conflicting finalized values.
    pub safety_violation: bool,
}

/// Closed penalty lifecycle for one committed evidence record.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Decode, Encode, DeriveJsonSerialize, DeriveJsonDeserialize,
)]
#[norito(
    tag = "status",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::EvidencePenaltyStatus")]
pub enum EvidencePenaltyStatus {
    /// The immutable consensus penalty delay has not elapsed.
    Pending,
    /// Consensus applied the penalty at the stated canonical block height.
    Applied {
        /// Canonical height that applied the penalty.
        height: Height,
    },
}
impl EvidencePenaltyStatus {
    /// Return whether this status can no longer produce a penalty action.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}
/// Persisted evidence entry annotated with commit metadata.
///
/// Every record has already been admitted by a committed block. Node-local
/// pending observations use no data-model representation and never enter WSV.
/// Shortened records are rejected instead of receiving implicit penalty state.
/// Penalty state admits only pending and finality-applied records. Governance cannot
/// cancel mandatory consensus penalties; unsupported states fail canonical decoding.
/// Endpoint JSON still uses a purpose-built audit projection; this closed JSON
/// layout is reserved for canonical state snapshots.
#[derive(
    Clone, Debug, PartialEq, Eq, Decode, Encode, DeriveJsonSerialize, DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::EvidenceRecord")]
pub struct EvidenceRecord {
    /// Slashing material captured for governance processing.
    pub evidence: Evidence,
    /// Required attribution authenticated independently at original evidence admission.
    pub attribution: EvidenceAttribution,
    /// Block height at which this evidence record was appended to WSV.
    pub recorded_at_height: Height,
    /// Consensus view (round) of the block carrying the record.
    pub recorded_at_view: View,
    /// Block creation timestamp in milliseconds since UNIX epoch.
    pub recorded_at_ms: u64,
    /// Exact pending or applied penalty state.
    pub penalty_status: EvidencePenaltyStatus,
}
/// Deterministic settlement receipt emitted for audit and reconciliation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::LaneSettlementReceipt")]
pub struct LaneSettlementReceipt {
    /// Caller-specified identifier linking the receipt to the originating transaction.
    pub source_id: [u8; 32],
    /// Exact local gas-token amount debited from the payer.
    pub local_amount: Quantity,
    /// Exact XOR amount booked immediately after inclusion.
    pub xor_due: Quantity,
    /// Exact XOR amount expected post-haircut.
    pub xor_after_haircut: Quantity,
    /// Safety margin consumed by this receipt (`xor_due - xor_after_haircut`).
    pub xor_variance: Quantity,
    /// UTC timestamp in milliseconds when the receipt was generated.
    pub timestamp_ms: u64,
}
/// Exact deterministic inputs used by the actual Nexus settlement.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::NexusFeeScheduleInputs")]
pub struct NexusFeeScheduleInputs {
    /// Serialized signed transaction payload length used for fee metering.
    pub tx_bytes_len: u64,
    /// Number of native instructions included in the transaction fee calculation.
    pub instruction_count: u64,
    /// Gas units used by the transaction.
    pub gas_used: u64,
    /// Base fee from `nexus.fees.base_fee`.
    pub base_fee: Quantity,
    /// Per-byte fee from `nexus.fees.per_byte_fee`.
    pub per_byte_fee: Quantity,
    /// Per-instruction fee from `nexus.fees.per_instruction_fee`.
    pub per_instruction_fee: Quantity,
    /// Per-gas-unit fee from `nexus.fees.per_gas_unit_fee`.
    pub per_gas_unit_fee: Quantity,
}
/// Actual native settlement performed for one Nexus charge.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::block::consensus::NexusFeeSettlementV1")]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NexusFeeSettlementV1 {
    /// The charged global fee asset and its total supply were actually burned.
    Burn,
}
/// Versioned Nexus fee receipt committed by a finalized lane block.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::NexusFeeReceipt")]
pub struct NexusFeeReceipt {
    /// Receipt format version.
    pub version: u16,
    /// Source transaction hash/id.
    pub source_id: [u8; 32],
    /// DPN dataspace that finalized the source transaction.
    pub dataspace_id: DataSpaceId,
    /// DPN lane that finalized the source transaction.
    pub lane_id: LaneId,
    /// DPN block height that finalized the source transaction.
    pub block_height: u64,
    /// Exact account or sponsor-program vault charged by settlement.
    pub debit_source: FeeDebitSource,
    /// Canonical fee asset definition charged by settlement.
    pub fee_asset_id: AssetDefinitionId,
    /// Immutable sponsor-program revision charged by this receipt, when sponsored.
    #[norito(required)]
    pub program_revision: Option<u64>,
    /// Proof-bound cross-lane spend lease, when relay settlement is used.
    #[norito(required)]
    pub lease_id: Option<Hash>,
    /// Exact nonzero fee amount actually settled by this execution output.
    pub fee_amount: Quantity,
    /// Native balance/supply effect that completed before receipt publication.
    pub settlement: NexusFeeSettlementV1,
    /// Fee schedule inputs needed to recompute [`Self::fee_amount`].
    pub schedule: NexusFeeScheduleInputs,
}
impl NexusFeeReceipt {
    /// Clean-break receipt version carrying typed debit sources and canonical assets.
    pub const VERSION: u16 = 2;
}
#[path = "nexus_fee_receipt.rs"]
mod nexus_fee_receipt;
pub use nexus_fee_receipt::MAX_NEXUS_FEE_RECEIPT_BYTES;
/// Liquidity profile applied when computing XOR conversions.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "profile", content = "state")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::LaneLiquidityProfile")]
pub enum LaneLiquidityProfile {
    /// Deep pools with negligible slippage.
    Tier1,
    /// Medium depth pools with moderate slippage.
    Tier2,
    /// Thin pools or credit-constrained venues.
    Tier3,
}
/// Volatility bucket applied when computing the safety margin.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    Default,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "bucket", content = "state")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::LaneVolatilityClass")]
pub enum LaneVolatilityClass {
    /// Normal operating conditions.
    #[default]
    Stable,
    /// Elevated but healthy volatility.
    Elevated,
    /// Dislocated markets requiring maximal margin.
    Dislocated,
}
/// Swap metadata describing the deterministic conversion parameters.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::LaneSwapMetadata")]
pub struct LaneSwapMetadata {
    /// Basis-point safety margin applied on top of the TWAP.
    pub epsilon_bps: u16,
    /// TWAP window length in seconds.
    pub twap_window_seconds: u32,
    /// Liquidity profile guiding haircut selection.
    pub liquidity_profile: LaneLiquidityProfile,
    /// Canonical exact TWAP value (`local_token / XOR`).
    pub twap_local_per_xor: Numeric,
    /// Volatility bucket recorded when applying the epsilon.
    pub volatility_class: LaneVolatilityClass,
}
impl<'a> norito::core::DecodeFromSlice<'a> for LaneSwapMetadata {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        decode_from_slice_canonical(bytes)
    }
}
/// Runtime-upgrade governance hook snapshot.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::block::consensus::SumeragiRuntimeUpgradeHook")]
pub struct SumeragiRuntimeUpgradeHook {
    /// Whether runtime-upgrade instructions are allowed.
    pub allow: bool,
    /// Whether runtime-upgrade instructions must include metadata.
    pub require_metadata: bool,
    /// Metadata key enforced by the manifest, if specified.
    #[norito(default)]
    pub metadata_key: Option<String>,
    /// Allowed metadata values when an allowlist is configured.
    #[norito(default)]
    pub allowed_ids: Vec<String>,
}
/// Governance manifest readiness snapshot for a lane.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::block::consensus::SumeragiLaneGovernance")]
pub struct SumeragiLaneGovernance {
    /// Numeric lane identifier.
    pub lane_id: LaneId,
    /// Human-readable lane alias.
    pub alias: String,
    /// Governance module configured for the lane, if any.
    #[norito(default)]
    pub governance: Option<String>,
    /// Whether the lane requires a governance manifest.
    pub manifest_required: bool,
    /// Whether a manifest has been loaded and validated.
    pub manifest_ready: bool,
    /// Path of the loaded manifest (best-effort; operator visibility).
    #[norito(default)]
    pub manifest_path: Option<String>,
    /// Validator identifiers derived from the manifest.
    #[norito(default)]
    pub validator_ids: Vec<String>,
    /// Quorum threshold configured by the manifest.
    #[norito(default)]
    pub quorum: Option<u32>,
    /// Protected namespaces enforced by the manifest.
    #[norito(default)]
    pub protected_namespaces: Vec<String>,
    /// Runtime-upgrade governance hook configuration.
    #[norito(default)]
    pub runtime_upgrade: Option<SumeragiRuntimeUpgradeHook>,
}
/// Current `NPoS` epoch schedule for operator diagnostics.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, DeriveJsonSerialize, DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::SumeragiNposDiagnostics")]
pub struct SumeragiNposDiagnostics {
    /// Length of the active epoch in blocks.
    pub epoch_length_blocks: NonZeroU64,
    /// Non-zero epoch seed used for deterministic leader and validator election.
    pub epoch_seed: [u8; 32],
}
impl SumeragiNposDiagnostics {
    /// Validate cross-field invariants that scalar wire types cannot express.
    ///
    /// # Errors
    ///
    /// Returns a stable reason when the epoch seed is zero.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.epoch_seed == [0; 32] {
            return Err("NPoS diagnostics epoch seed must be non-zero");
        }
        Ok(())
    }
}
/// Operator and lane diagnostics returned by `/v1/sumeragi/diagnostics`.
///
/// This payload deliberately excludes reducer phase, height, view, leader, certificates, mode, and
/// timing. `/v1/sumeragi/status` is the sole source of authoritative consensus state.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DeriveJsonSerialize, DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "operator diagnostics expose independent queue-pressure flags"
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::SumeragiDiagnosticsStatus")]
pub struct SumeragiDiagnosticsStatus {
    /// Current transaction queue depth.
    pub tx_queue_depth: u64,
    /// Configured transaction queue capacity.
    pub tx_queue_capacity: u64,
    /// Estimated retained transaction queue bytes.
    pub tx_queue_retained_bytes: u64,
    /// Configured retained transaction queue byte budget.
    pub tx_queue_max_retained_bytes: u64,
    /// Whether the transaction queue is saturated.
    pub tx_queue_saturated: bool,
    /// Whether saturation is caused by transaction count.
    pub tx_queue_saturated_by_count: bool,
    /// Whether saturation is caused by retained bytes.
    pub tx_queue_saturated_by_bytes: bool,
    /// Whether the oldest queued transaction exceeded the age budget.
    pub tx_queue_saturated_by_age: bool,
    /// Oldest queued transaction age in milliseconds.
    pub tx_queue_oldest_queued_age_ms: u64,
    /// `NPoS`-only diagnostics; absent in permissioned mode.
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub npos: Option<SumeragiNposDiagnostics>,
    /// Count of lanes that still require a governance manifest.
    pub lane_governance_sealed_total: u32,
    /// Aliases of lanes that remain sealed.
    pub lane_governance_sealed_aliases: Vec<String>,
    /// Governance manifest readiness per lane.
    pub lane_governance: Vec<SumeragiLaneGovernance>,
}
/// Minimal execution witness KV pair for SBV-AM prototypes.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::block::consensus::ExecKv")]
pub struct ExecKv {
    /// Raw key bytes.
    pub key: Vec<u8>,
    /// Raw value bytes.
    pub value: Vec<u8>,
}
/// Execution witness containing reads and writes for SMT recomputation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Default,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::block::consensus::ExecWitness")]
pub struct ExecWitness {
    /// Witnessed reads during execution (key,value).
    pub reads: Vec<ExecKv>,
    /// Writes performed during execution (key,value). Overrides reads on conflict.
    pub writes: Vec<ExecKv>,
    /// FASTPQ transfer transcripts grouped per entry hash.
    pub fastpq_transcripts: Vec<TransferTranscriptBundle>,
    /// FASTPQ transition batches prepared for prover ingestion.
    pub fastpq_batches: Vec<FastpqTransitionBatch>,
}
/// Execution witness message bound to a specific block and round. Used on-wire.
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::ExecWitnessMsg")]
pub struct ExecWitnessMsg {
    /// Hash of the block the witness applies to.
    pub block_hash: HashOf<BlockHeader>,
    /// Height of the block.
    pub height: Height,
    /// View/round for which the witness applies.
    pub view: View,
    /// Epoch index (0 in permissioned mode).
    pub epoch: u64,
    /// The execution witness payload.
    pub witness: ExecWitness,
}
// --- Helpers for Norito slice decoding bridges ---
fn decode_from_slice_canonical<T>(bytes: &[u8]) -> Result<(T, usize), norito::core::Error>
where
    T: DecodeAll + Encode,
{
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let (value, used) = norito::core::decode_field_prefix::<T>(bytes)
        .map_err(|e| norito::core::Error::Message(format!("codec decode error: {e}")))?;
    let canonical = value.encode();
    if used != canonical.len() || bytes.len() < used {
        return Err(norito::core::Error::LengthMismatch);
    }
    if bytes[..used] != canonical {
        return Err(norito::core::Error::Message("payload mismatch".into()));
    }
    Ok((value, used))
}
macro_rules! impl_decode_from_slice_via_codec {
    ($t:ty) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $t {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                decode_from_slice_canonical(bytes)
            }
        }
    };
}
impl_decode_from_slice_via_codec!(ExecKv);
impl_decode_from_slice_via_codec!(ExecWitness);
impl_decode_from_slice_via_codec!(ExecWitnessMsg);
impl_decode_from_slice_via_codec!(ConsensusGenesisParams);
impl_decode_from_slice_via_codec!(NposGenesisParams);
impl_decode_from_slice_via_codec!(SumeragiNposDiagnostics);
impl_decode_from_slice_via_codec!(SumeragiDiagnosticsStatus);
impl_decode_from_slice_via_codec!(SumeragiRuntimeUpgradeHook);
impl_decode_from_slice_via_codec!(SumeragiLaneGovernance);
impl<'a> norito::core::DecodeFromSlice<'a> for LaneSettlementReceipt {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        decode_from_slice_canonical(bytes)
    }
}
#[cfg(test)]
#[path = "consensus_model_tests.rs"]
mod tests;

#[cfg(test)]
mod parameter_tests;

#[cfg(test)]
mod captured_consensus_schema_tests;
