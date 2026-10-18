//! Shared aggregate SHA3-384 byte/Goldilocks STARK commitment and opening core.
//!
//! Relation modules supply their exact transcript suite, profile digest,
//! public-input digest, trace columns, constraint-composition values, and an
//! [`AggregateOpenedRowEvaluatorV1`]. This module owns the canonical ordered
//! trace-group layout, exact proof codec, SHA3-384 byte vector-row commitments,
//! minimal batched Merkle multiproofs, shared binary FRI, and opened-query
//! verification. It deliberately contains no X.509, private-note, or PQ-MASP
//! policy.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "aggregate_stark/joined_trace.rs"]
pub mod joined_trace;
use super::privacy_outer_hash::PRIVACY_OUTER_DIGEST_BYTES_V1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::privacy_outer_hash::{PrivacyOuterDomainPrefixV1, PrivacyOuterLastFieldStreamV1};
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub mod retained_commitment;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "aggregate_stark/streaming_commitment.rs"]
mod streaming_commitment;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::transparent_stark::map_digest_stream_error_v1;
use super::transparent_stark::{
    ExactProofReaderV1, GOLDILOCKS_GENERATOR_V1, GoldilocksFieldV1 as F, GoldilocksFp4V1 as E,
    PrivacyOuterDigestV1, PrivacyOuterMerkleTreeV1, TransparentStarkDigestContextV1,
    TransparentStarkErrorV1, TransparentTranscriptV1, append_u16_v1, append_u32_v1, append_u64_v1,
    derive_unique_query_indices_v1, ensure_fri_terminal_degree_fp4_v1, fri_fold_pair_fp4_v1,
    fri_fold_pair_with_inverse_x_fp4_v1, goldilocks_batch_invert_v1,
    goldilocks_fp4_evaluate_coset_v1, goldilocks_fp4_ifft_v1, goldilocks_primitive_root_v1,
    privacy_outer_digest_frame_v1, privacy_outer_merkle_node_v1, random_goldilocks_fp4_v1,
};
#[cfg(test)]
use super::transparent_stark::{
    ReplayableTraceMaskV1, goldilocks_ifft_v1, masked_trace_coefficients_on_coset_v1,
    masked_trace_coefficients_with_mask_v1, masked_trace_lde_column_with_mask_v1,
    privacy_outer_last_field_stream_v1, sample_trace_mask_v1,
};
use fastpq_isi::FASTPQ_QUERY_COUNT_V1;
#[cfg(test)]
use iroha_data_model::privacy::PrivacyProtocolIdV1;
use rand::TryRngCore;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
const FRI_MASK_LEAF_DOMAIN_V1: &[u8] = b"iroha:privacy:aggregate-stark:fri-mask-oracle-leaf:v1";
const FRI_MASK_NODE_DOMAIN_V1: &[u8] = b"iroha:privacy:aggregate-stark:fri-mask-oracle-node:v1";
const FRI_MASK_ROOT_LABEL_V1: &[u8] = b"iroha:privacy:aggregate-stark:fri-mask-oracle-root:v1";
const DEEP_POINT_LABEL_V1: &[u8] = b"iroha:privacy:aggregate-stark:deep-point:v1";
const DEEP_OPENINGS_LABEL_V1: &[u8] = b"iroha:privacy:aggregate-stark:deep-openings:v1";
const AGGREGATE_STARK_RESERVED_DOMAINS_V1: [&[u8]; 5] = [
    DEEP_POINT_LABEL_V1,
    DEEP_OPENINGS_LABEL_V1,
    FRI_MASK_LEAF_DOMAIN_V1,
    FRI_MASK_NODE_DOMAIN_V1,
    FRI_MASK_ROOT_LABEL_V1,
];

/// Whether a relation-supplied domain collides with an aggregate-core role.
///
/// Relation layers validate their own transcript labels separately from the
/// aggregate domain bundle. Keeping this predicate in the aggregate core
/// prevents those outer labels from silently reusing a fixed DEEP or FRI-mask
/// role that is not present in [`AggregateStarkDomainsV1`].
pub fn aggregate_stark_domain_is_reserved_v1(domain: &[u8]) -> bool {
    AGGREGATE_STARK_RESERVED_DOMAINS_V1.contains(&domain)
}
/// Return every fixed aggregate-core role for cross-layer uniqueness tests.
#[cfg(test)]
pub const fn aggregate_stark_reserved_domains_v1() -> [&'static [u8]; 5] {
    AGGREGATE_STARK_RESERVED_DOMAINS_V1
}
/// Rows processed per bounded DEEP/FRI denominator-inversion batch.
pub const DEEP_FRI_BASE_BATCH_ROWS_V1: usize = 1 << 12;
/// Canonical independent row batch used by materialized FRI folding.
const FRI_FOLD_PARALLEL_BATCH_ROWS_V1: usize = 1 << 12;
/// Exact maximum number of independent LDE columns resident in one parallel dispatch.
///
/// Callers process these source-ordered batches sequentially. Peak transform scratch therefore
/// remains bounded by this protocol-source constant even when Rayon's global pool is wider or is
/// configured differently by the surrounding process. The historical `MASKED_TRACE` name is
/// retained because release-readiness certificates bind it directly; the same ceiling now covers
/// verifier-fixed and DEEP-opening column transforms too.
pub const MASKED_TRACE_LDE_COLUMN_BATCH_V1: usize = 8;
/// Shared aggregate-STARK failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AggregateStarkErrorV1 {
    /// A verifier-derived protocol parameter or ordered layout is invalid.
    #[error("aggregate STARK layout is invalid")]
    InvalidLayout,
    /// A proof has the wrong exact statement-derived shape.
    #[error("aggregate STARK proof shape is invalid")]
    InvalidProofShape,
    /// Proof bytes are empty, truncated, trailing, or otherwise malformed.
    #[error("aggregate STARK proof wire is malformed")]
    MalformedProof,
    /// Proof bytes exceed the engine-fixed ceiling.
    #[error("aggregate STARK proof exceeds its byte ceiling")]
    ProofTooLarge,
    /// A proof field is not a canonical Goldilocks residue.
    #[error("aggregate STARK proof contains a non-canonical field")]
    NonCanonicalField,
    /// A committed trace opening is invalid.
    #[error("aggregate STARK trace opening is invalid")]
    TraceOpening,
    /// A composition opening or relation callback result is invalid.
    #[error("aggregate STARK composition opening is invalid")]
    ConstraintOpening,
    /// An out-of-domain point or DEEP opening/quotient identity is invalid.
    #[error("aggregate STARK DEEP opening is invalid")]
    DeepOpening,
    /// A FRI opening or fold is invalid.
    #[error("aggregate STARK FRI opening is invalid")]
    FriOpening,
    /// A FRI terminal violates its degree bound.
    #[error("aggregate STARK FRI terminal degree is invalid")]
    FriDegree,
    /// Transcript order or derived query positions do not match.
    #[error("aggregate STARK transcript is invalid")]
    TranscriptMismatch,
    /// A bounded allocation failed.
    #[error("aggregate STARK bounded allocation failed")]
    AllocationFailure,
    /// Required prover randomness was unavailable or failed its health checks.
    #[error("aggregate STARK prover randomness is unavailable")]
    RandomnessUnavailable,
    /// A checked implementation invariant failed.
    #[error("aggregate STARK internal invariant failed")]
    InternalInvariant,
}
/// Preserve shared arithmetic and allocation failures at the aggregate boundary.
pub fn map_transparent_error_v1(error: TransparentStarkErrorV1) -> AggregateStarkErrorV1 {
    match error {
        TransparentStarkErrorV1::RandomnessUnavailable => {
            AggregateStarkErrorV1::RandomnessUnavailable
        }
        TransparentStarkErrorV1::AllocationFailure => AggregateStarkErrorV1::AllocationFailure,
        TransparentStarkErrorV1::NonCanonicalField => AggregateStarkErrorV1::NonCanonicalField,
        TransparentStarkErrorV1::FriDegree => AggregateStarkErrorV1::FriDegree,
        TransparentStarkErrorV1::MalformedProof => AggregateStarkErrorV1::MalformedProof,
        TransparentStarkErrorV1::InvalidDigestDomain
        | TransparentStarkErrorV1::FrameLengthOverflow => AggregateStarkErrorV1::InvalidLayout,
        TransparentStarkErrorV1::InvalidMerkleShape => AggregateStarkErrorV1::TraceOpening,
        TransparentStarkErrorV1::ChallengeSamplingExhausted
        | TransparentStarkErrorV1::QuerySamplingExhausted
        | TransparentStarkErrorV1::InvalidGrinding => AggregateStarkErrorV1::TranscriptMismatch,
        _ => AggregateStarkErrorV1::InternalInvariant,
    }
}
/// Immutable relation-owned FRI commitment geometry, never selected by proof bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateFriCommitmentLayoutV1 {
    /// Each leaf authenticates one extension-field evaluation.
    Scalar,
    /// Each leaf authenticates the ordered low/high evaluations of one binary fold.
    Paired,
}
impl AggregateFriCommitmentLayoutV1 {
    /// Number of Merkle leaves for an exact power-of-two FRI evaluation layer.
    fn leaf_count(self, layer_size: usize) -> Result<usize, AggregateStarkErrorV1> {
        if !layer_size.is_power_of_two() {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        match self {
            Self::Scalar => Ok(layer_size),
            Self::Paired if layer_size >= 2 => Ok(layer_size / 2),
            Self::Paired => Err(AggregateStarkErrorV1::InvalidLayout),
        }
    }
}
/// Immutable proof-system dimensions used by the generic aggregate core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateStarkParametersV1 {
    /// Four-byte exact wire magic.
    pub(crate) proof_magic: [u8; 4],
    /// Exact proof version.
    pub(crate) proof_version: u16,
    /// Relation-fixed leaf geometry for every FRI layer, including the terminal.
    pub(crate) fri_commitment_layout: AggregateFriCommitmentLayoutV1,
    /// Number of independent composition/FRI lanes.
    pub(crate) security_lanes: usize,
    /// Number of unique post-grinding queries.
    pub(crate) query_count: usize,
    /// Binary logarithm of the trace-to-LDE blow-up.
    pub(crate) blowup_log2: u8,
    /// Binary logarithm of the terminal FRI vector length.
    pub(crate) terminal_log2: u8,
    /// Maximum degree of the terminal polynomial.
    pub(crate) terminal_degree_bound: usize,
    /// Number of low-degree coefficient chunks per composition lane.
    pub(crate) composition_degree_chunks: usize,
    /// Minimum native trace logarithm.
    pub(crate) minimum_trace_log2: u8,
    /// Maximum native trace logarithm.
    pub(crate) maximum_trace_log2: u8,
    /// Maximum ordered trace-group count.
    pub(crate) maximum_trace_groups: usize,
    /// Maximum total segment instances.
    pub(crate) maximum_segment_instances: usize,
    /// Maximum base columns per segment instance.
    pub(crate) maximum_base_columns_per_instance: usize,
    /// Maximum auxiliary columns per segment instance.
    pub(crate) maximum_aux_columns_per_instance: usize,
    /// Exact proof-byte ceiling.
    pub(crate) maximum_proof_bytes: usize,
}
impl AggregateStarkParametersV1 {
    /// Terminal vector length.
    pub(crate) fn terminal_size(self) -> Result<usize, AggregateStarkErrorV1> {
        1_usize
            .checked_shl(u32::from(self.terminal_log2))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
    /// Exact trace-hiding dimension for all current/next query openings.
    ///
    /// Every query can expose two distinct positions in each trace group, so
    /// the mask polynomial needs two independent coefficients per query.
    pub(crate) fn trace_hiding_coefficients(self) -> Result<usize, AggregateStarkErrorV1> {
        self.query_count
            .checked_mul(2)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
    /// Exact reviewed CA padding reduction. This does not offer arbitrary
    /// relation layouts a larger native-to-LDE ratio. Thirteen trace chunks
    /// contain base695/aux128; four separate chunks contain composition values.
    fn compact_ca_private_padding_v1(self) -> bool {
        self.proof_magic == *b"X5C2"
            && self.proof_version == 1
            && self.fri_commitment_layout == AggregateFriCommitmentLayoutV1::Paired
            && self.security_lanes == 1
            && self.query_count == 136
            && self.blowup_log2 == 4
            && self.terminal_log2 == 10
            && self.terminal_degree_bound == 143
            && self.composition_degree_chunks == 4
            && self.minimum_trace_log2 == 12
            && self.maximum_trace_log2 == 12
            && self.maximum_trace_groups == 1
            && self.maximum_segment_instances == 13
            && self.maximum_base_columns_per_instance == 64
            && self.maximum_aux_columns_per_instance == 64
            && self.maximum_proof_bytes == 1_498_816
    }
    /// Validate every closed proof-system dimension.
    pub(crate) fn validate(self) -> Result<(), AggregateStarkErrorV1> {
        let terminal_size = self.terminal_size()?;
        self.fri_commitment_layout.leaf_count(terminal_size)?;
        let maximum_lde_log2 = self
            .maximum_trace_log2
            .checked_add(self.blowup_log2)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        if self.proof_magic == [0; 4]
            || self.proof_version == 0
            || self.security_lanes == 0
            || self.query_count
                != usize::try_from(FASTPQ_QUERY_COUNT_V1)
                    .expect("the frozen query count fits usize")
            || if self.proof_magic == *b"X5C2" {
                !self.compact_ca_private_padding_v1()
            } else {
                self.blowup_log2 != 3
            }
            || self.terminal_degree_bound >= terminal_size
            || self.composition_degree_chunks == 0
            || self.composition_degree_chunks > usize::from(u16::MAX)
            || maximum_lde_log2 > u32::BITS as u8
            || maximum_lde_log2 >= usize::BITS as u8
            || self.minimum_trace_log2 > self.maximum_trace_log2
            || self.security_lanes > usize::from(u16::MAX)
            || self.maximum_trace_groups == 0
            || self.maximum_trace_groups > usize::from(u16::MAX)
            || self.maximum_segment_instances == 0
            || self.maximum_base_columns_per_instance == 0
            || self.maximum_aux_columns_per_instance == 0
            || self.maximum_proof_bytes == 0
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        Ok(())
    }
}
/// SHA3-384 Merkle and transcript domains supplied by one relation profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateStarkDomainsV1 {
    /// Exact final catalog/protocol/profile digest context.
    pub(crate) digest_context: TransparentStarkDigestContextV1,
    /// Base-row leaf domain.
    pub(crate) base_leaf: &'static [u8],
    /// Base-tree node domain.
    pub(crate) base_node: &'static [u8],
    /// Auxiliary-row leaf domain.
    pub(crate) aux_leaf: &'static [u8],
    /// Auxiliary-tree node domain.
    pub(crate) aux_node: &'static [u8],
    /// Composition leaf domain.
    pub(crate) composition_leaf: &'static [u8],
    /// Composition-tree node domain.
    pub(crate) composition_node: &'static [u8],
    /// FRI leaf domain.
    pub(crate) fri_leaf: &'static [u8],
    /// FRI-tree node domain.
    pub(crate) fri_node: &'static [u8],
    /// Transcript label for the ordered layout.
    pub(crate) layout_label: &'static [u8],
    /// Transcript label for base roots.
    pub(crate) base_root_label: &'static [u8],
    /// Transcript label for auxiliary roots.
    pub(crate) aux_root_label: &'static [u8],
    /// Transcript label for composition roots.
    pub(crate) composition_root_label: &'static [u8],
    /// Transcript label for FRI roots.
    pub(crate) fri_root_label: &'static [u8],
    /// Transcript challenge label for FRI folds.
    pub(crate) fri_beta_label: &'static [u8],
    /// Query-seed frame domain.
    pub(crate) query_seed: &'static [u8],
}
impl AggregateStarkDomainsV1 {
    /// Reject missing or duplicate cryptographic domains and labels.
    pub(crate) fn validate(&self) -> Result<(), AggregateStarkErrorV1> {
        self.digest_context
            .validate()
            .map_err(map_transparent_error_v1)?;
        let values = [
            DEEP_POINT_LABEL_V1,
            DEEP_OPENINGS_LABEL_V1,
            FRI_MASK_LEAF_DOMAIN_V1,
            FRI_MASK_NODE_DOMAIN_V1,
            FRI_MASK_ROOT_LABEL_V1,
            self.base_leaf,
            self.base_node,
            self.aux_leaf,
            self.aux_node,
            self.composition_leaf,
            self.composition_node,
            self.fri_leaf,
            self.fri_node,
            self.layout_label,
            self.base_root_label,
            self.aux_root_label,
            self.composition_root_label,
            self.fri_root_label,
            self.fri_beta_label,
            self.query_seed,
        ];
        if values
            .iter()
            .any(|value| value.is_empty() || u16::try_from(value.len()).is_err())
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        for (index, value) in values.iter().enumerate() {
            if values[..index].contains(value) {
                return Err(AggregateStarkErrorV1::InvalidLayout);
            }
        }
        Ok(())
    }
}
fn ensure_transcript_context_v1(
    transcript: &TransparentTranscriptV1,
    domains: &AggregateStarkDomainsV1,
) -> Result<(), AggregateStarkErrorV1> {
    domains.validate()?;
    if transcript.context() != domains.digest_context {
        return Err(AggregateStarkErrorV1::TranscriptMismatch);
    }
    Ok(())
}
/// One canonical group of equal-native-stride trace segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateTraceGroupLayoutV1 {
    /// Native trace-size logarithm shared by every segment in this group.
    pub(crate) native_trace_log2: u8,
    /// Number of segment instances concatenated into each vector row.
    pub(crate) segment_instances: usize,
    /// Total committed base width across the group.
    pub(crate) base_width: usize,
    /// Total committed auxiliary width across the group.
    pub(crate) aux_width: usize,
}
impl AggregateTraceGroupLayoutV1 {
    /// Derive the sole legal next-row stride on a common LDE domain.
    pub(crate) fn next_stride(self, common_lde_log2: u8) -> Result<usize, AggregateStarkErrorV1> {
        let shift = common_lde_log2
            .checked_sub(self.native_trace_log2)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        1_usize
            .checked_shl(u32::from(shift))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
}
/// Immutable physical commitment and queried-row layout selected by the relation.
/// DEEP current/next openings are unchanged in every case. A reduced layout is
/// never selected by proof bytes, and the generic relation verifier rejects it
/// until the caller supplies complete OODS enforcement through a dedicated API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateTraceLayoutV1 {
    /// One base/aux root per logical group and current/next query rows.
    GroupedCurrentNext,
    /// One base/aux root per logical group and current query rows only.
    GroupedCurrent,
    /// One joined base root and one joined aux root; current query rows only.
    JoinedCurrent,
}
impl AggregateTraceLayoutV1 {
    fn next_width_v1(self, width: usize) -> usize {
        match self {
            Self::GroupedCurrentNext => width,
            Self::GroupedCurrent | Self::JoinedCurrent => 0,
        }
    }
    fn query_rows_v1(self) -> usize {
        match self {
            Self::GroupedCurrentNext => 2,
            Self::GroupedCurrent | Self::JoinedCurrent => 1,
        }
    }
}
/// Disjoint row identity: a valid individual group index is always smaller.
const JOINED_TRACE_GROUP_MARKER_V1: usize = u16::MAX as usize;
/// Verifier-derived ordered aggregate commitment layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateProofLayoutV1 {
    common_lde_log2: u8,
    trace_layout: AggregateTraceLayoutV1,
    trace_groups: Vec<AggregateTraceGroupLayoutV1>,
}
impl AggregateProofLayoutV1 {
    /// Construct from canonically ordered, non-empty group descriptors.
    ///
    /// Native trace logarithms are nondecreasing. Multiple independently
    /// committed adapters may use the same native domain; their verifier-fixed
    /// order is preserved in the transcript and proof vectors.
    pub(crate) fn new(
        parameters: AggregateStarkParametersV1,
        trace_groups: Vec<AggregateTraceGroupLayoutV1>,
    ) -> Result<Self, AggregateStarkErrorV1> {
        Self::new_with_trace_layout_v1(
            parameters,
            trace_groups,
            AggregateTraceLayoutV1::GroupedCurrentNext,
        )
    }
    /// Construct a relation-fixed physical layout; proof bytes cannot change it.
    pub(crate) fn new_with_trace_layout_v1(
        parameters: AggregateStarkParametersV1,
        trace_groups: Vec<AggregateTraceGroupLayoutV1>,
        trace_layout: AggregateTraceLayoutV1,
    ) -> Result<Self, AggregateStarkErrorV1> {
        parameters.validate()?;
        let maximum_native_log2 = trace_groups
            .last()
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?
            .native_trace_log2;
        let common_lde_log2 = maximum_native_log2
            .checked_add(parameters.blowup_log2)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let layout = Self {
            common_lde_log2,
            trace_layout,
            trace_groups,
        };
        layout.validate(parameters)?;
        Ok(layout)
    }
    /// Common LDE logarithm.
    pub(crate) const fn common_lde_log2(&self) -> u8 {
        self.common_lde_log2
    }
    /// Common LDE row count.
    pub(crate) fn common_lde_size(&self) -> usize {
        1_usize
            .checked_shl(u32::from(self.common_lde_log2))
            .unwrap_or(0)
    }
    /// Ordered trace-group descriptors.
    pub(crate) fn trace_groups(&self) -> &[AggregateTraceGroupLayoutV1] {
        &self.trace_groups
    }
    /// Number of physical base/aux root pairs in this relation's exact wire.
    pub(crate) fn trace_commitment_count_v1(&self) -> usize {
        match self.trace_layout {
            AggregateTraceLayoutV1::JoinedCurrent => 1,
            _ => self.trace_groups.len(),
        }
    }
    /// Number of binary FRI rounds.
    pub(crate) fn fri_rounds(
        &self,
        parameters: AggregateStarkParametersV1,
    ) -> Result<usize, AggregateStarkErrorV1> {
        self.common_lde_log2
            .checked_sub(parameters.terminal_log2)
            .map(usize::from)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
    /// Maximum polynomial degree accepted by the terminal FRI check.
    pub(crate) fn maximum_fri_input_degree(
        &self,
        parameters: AggregateStarkParametersV1,
    ) -> Result<usize, AggregateStarkErrorV1> {
        let fold_factor = 1_usize
            .checked_shl(
                u32::try_from(self.fri_rounds(parameters)?)
                    .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
            )
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        parameters
            .terminal_degree_bound
            .checked_add(1)
            .and_then(|coefficients| coefficients.checked_mul(fold_factor))
            .and_then(|coefficients| coefficients.checked_sub(1))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
    /// Exclusive degree cap shared by traces, composition chunks, and FRI masks.
    pub(crate) fn fri_degree_cap(
        &self,
        parameters: AggregateStarkParametersV1,
    ) -> Result<usize, AggregateStarkErrorV1> {
        self.maximum_fri_input_degree(parameters)?
            .checked_add(1)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
    /// Maximum unsplit composition degree represented by all coefficient chunks.
    pub(crate) fn maximum_composition_degree(
        &self,
        parameters: AggregateStarkParametersV1,
    ) -> Result<usize, AggregateStarkErrorV1> {
        self.fri_degree_cap(parameters)?
            .checked_mul(parameters.composition_degree_chunks)
            .and_then(|coefficients| coefficients.checked_sub(1))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
    /// Exact coefficient count of each independent Protocol-2 FRI mask.
    ///
    /// The paper's minimum hiding space is
    /// `F[X]^{< |H| + h - 1}`. This implementation samples from the larger
    /// normalized space `F[X]^{< D - 1}`, where `D` is the one exclusive
    /// degree cap enforced by the shared FRI. One top-degree slot remains
    /// unused, matching the protocol's strict inequality and preventing an
    /// off-by-one reinterpretation of the terminal bound.
    pub(crate) fn fri_mask_coefficient_count(
        &self,
        parameters: AggregateStarkParametersV1,
    ) -> Result<usize, AggregateStarkErrorV1> {
        self.maximum_fri_input_degree(parameters)
    }
    fn minimum_protocol_fri_mask_coefficients(
        &self,
        parameters: AggregateStarkParametersV1,
    ) -> Result<usize, AggregateStarkErrorV1> {
        let largest_native_rows = self
            .common_lde_size()
            .checked_shr(u32::from(parameters.blowup_log2))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        largest_native_rows
            .checked_add(parameters.trace_hiding_coefficients()?)
            .and_then(|count| count.checked_sub(1))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
    /// Validate ordering, widths, instance count, common domain, and strides.
    pub(crate) fn validate(
        &self,
        parameters: AggregateStarkParametersV1,
    ) -> Result<(), AggregateStarkErrorV1> {
        parameters.validate()?;
        if parameters.compact_ca_private_padding_v1()
            && (self.trace_layout != AggregateTraceLayoutV1::GroupedCurrent
                || self.common_lde_log2 != 16
                || self.trace_groups.as_slice()
                    != [AggregateTraceGroupLayoutV1 {
                        native_trace_log2: 12,
                        base_width: 695,
                        aux_width: 128,
                        segment_instances: 13,
                    }])
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let fri_mask_coefficients = self.fri_mask_coefficient_count(parameters)?;
        let minimum_fri_mask_coefficients =
            self.minimum_protocol_fri_mask_coefficients(parameters)?;
        let maximum_fri_input_degree = self.maximum_fri_input_degree(parameters)?;
        if self.trace_groups.is_empty()
            || self.trace_groups.len() > parameters.maximum_trace_groups
            || self.trace_groups.len() > usize::from(u16::MAX)
            || self.common_lde_size() < parameters.query_count
            || (self.common_lde_size() >> self.fri_rounds(parameters)?)
                != parameters.terminal_size()?
            || fri_mask_coefficients == 0
            || fri_mask_coefficients < minimum_fri_mask_coefficients
            || fri_mask_coefficients
                .checked_sub(1)
                .is_none_or(|degree| degree > maximum_fri_input_degree)
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let mut previous_log2 = None;
        let mut total_instances = 0_usize;
        for group in &self.trace_groups {
            let maximum_base = group
                .segment_instances
                .checked_mul(parameters.maximum_base_columns_per_instance)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
            let maximum_aux = group
                .segment_instances
                .checked_mul(parameters.maximum_aux_columns_per_instance)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
            if group.native_trace_log2 < parameters.minimum_trace_log2
                || group.native_trace_log2 > parameters.maximum_trace_log2
                || previous_log2.is_some_and(|previous| previous > group.native_trace_log2)
                || group.segment_instances == 0
                || group.segment_instances > usize::from(u16::MAX)
                || group.base_width == 0
                || group.aux_width == 0
                || group.base_width > usize::from(u16::MAX)
                || group.aux_width > usize::from(u16::MAX)
                || group.base_width > maximum_base
                || group.aux_width > maximum_aux
                || group.next_stride(self.common_lde_log2)? == 0
            {
                return Err(AggregateStarkErrorV1::InvalidLayout);
            }
            total_instances = total_instances
                .checked_add(group.segment_instances)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
            previous_log2 = Some(group.native_trace_log2);
        }
        if self.trace_layout == AggregateTraceLayoutV1::JoinedCurrent {
            for base in [true, false] {
                self.trace_groups.iter().try_fold(0_usize, |sum, group| {
                    sum.checked_add(if base {
                        group.base_width
                    } else {
                        group.aux_width
                    })
                    .filter(|&width| width <= usize::from(u16::MAX))
                    .ok_or(AggregateStarkErrorV1::InvalidLayout)
                })?;
            }
        }
        let expected_common = self
            .trace_groups
            .last()
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?
            .native_trace_log2
            .checked_add(parameters.blowup_log2)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        if total_instances > parameters.maximum_segment_instances
            || self.common_lde_log2 != expected_common
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        Ok(())
    }
}
/// Exact release certificate for the affine-batched binary-FRI theorem.
///
/// `affine_coefficient_*` represents the affine-batching coefficient `3/2`
/// replacing the general theorem's `L - 1/2`. `rho_*` bounds the code rate.
/// `binary_fold_arity` repeated `fold_count` times specifies the complete
/// reduction schedule whose arity sum enters the commitment error. Other fields bind
/// the smooth domain, Fp4 field-size lower bound, fold/terminal geometry, and
/// the implementation's distinct-query schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateFriTheorem2CertificateV1 {
    /// Numerator of the affine-batching coefficient `3/2`.
    pub(crate) affine_coefficient_numerator: u8,
    /// Denominator of the affine-batching coefficient `3/2`.
    pub(crate) affine_coefficient_denominator: u8,
    /// Affine batching parameter `m`.
    pub(crate) batching_parameter_m: u8,
    /// Numerator of a proved upper bound on the code rate.
    pub(crate) rho_numerator: u8,
    /// Denominator of a proved upper bound on the code rate.
    pub(crate) rho_denominator: u8,
    /// Arity of every reduction in the complete binary fold schedule.
    pub(crate) binary_fold_arity: u8,
    /// Binary logarithm of the evaluation domain `|D|`.
    pub(crate) domain_log2: u8,
    /// Proven lower-bound exponent for `|F_{p^4}|`.
    pub(crate) extension_field_lower_bound_bits: u16,
    /// Binary two-adicity available to the base-field FFT domain.
    pub(crate) base_field_two_adicity: u8,
    /// Every native trace domain is a power-of-two multiplicative subgroup.
    pub(crate) trace_domains_are_smooth_subgroups: bool,
    /// The evaluation domain is the fixed primitive-generator coset of a
    /// power-of-two subgroup.
    pub(crate) evaluation_domain_is_smooth_generator_coset: bool,
    /// The evaluation coset is disjoint from every native trace subgroup.
    pub(crate) evaluation_domain_is_disjoint_from_trace_domains: bool,
    /// Exact binary fold count.
    pub(crate) fold_count: u8,
    /// Exact terminal-domain logarithm.
    pub(crate) terminal_log2: u8,
    /// Exact terminal polynomial degree bound.
    pub(crate) terminal_degree_bound: u16,
    /// Exact number of query invocations.
    pub(crate) query_count: u8,
    /// Query sampler draws distinct indices without replacement.
    pub(crate) distinct_queries_without_replacement: bool,
    /// Rejection sampling is uniform over every as-yet-unselected index.
    pub(crate) uniform_rejection_sampling: bool,
    /// Claimed floor for the query-error exponent.
    pub(crate) claimed_query_error_bits: u16,
}
/// Machine-checked error exponents for one FRI subproof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateFriTheorem2BoundV1 {
    /// Query error is strictly below `2^-query_error_bits`.
    pub(crate) query_error_bits: u16,
    /// Sum of both commitment-error terms is below
    /// `2^-commitment_error_bits`.
    pub(crate) commitment_error_bits: u16,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct U512V1([u64; 8]);
impl U512V1 {
    fn one() -> Self {
        Self([1, 0, 0, 0, 0, 0, 0, 0])
    }
    fn checked_mul_small(mut self, multiplier: u64) -> Option<Self> {
        let mut carry = 0_u128;
        for limb in &mut self.0 {
            let product = u128::from(*limb)
                .checked_mul(u128::from(multiplier))?
                .checked_add(carry)?;
            *limb = product as u64;
            carry = product >> 64;
        }
        (carry == 0).then_some(self)
    }
    fn checked_pow_small(base: u64, exponent: u8) -> Option<Self> {
        (0..exponent).try_fold(Self::one(), |value, _| value.checked_mul_small(base))
    }
    fn checked_shl(self, shift: u16) -> Option<Self> {
        if shift >= 512 {
            return None;
        }
        let word_shift = usize::from(shift / 64);
        let bit_shift = u32::from(shift % 64);
        let mut shifted = [0_u64; 8];
        for (source, limb) in self.0.into_iter().enumerate() {
            if limb == 0 {
                continue;
            }
            let target = source.checked_add(word_shift)?;
            if target >= shifted.len() {
                return None;
            }
            shifted[target] |= limb.checked_shl(bit_shift).unwrap_or(0);
            if bit_shift != 0 {
                let high = limb >> (64 - bit_shift);
                if high != 0 {
                    let high_target = target.checked_add(1)?;
                    if high_target >= shifted.len() {
                        return None;
                    }
                    shifted[high_target] |= high;
                }
            }
        }
        Some(Self(shifted))
    }
    fn strictly_less_than(self, rhs: Self) -> bool {
        self.0
            .iter()
            .rev()
            .zip(rhs.0.iter().rev())
            .find_map(|(left, right)| (left != right).then_some(left < right))
            .unwrap_or(false)
    }
}
const fn gcd_u64_v1(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}
/// Validate every precondition and both error terms of the affine-batched
/// binary-FRI theorem used by the release.
///
/// For distinct queries, a bad set of size `b` in a domain of size `N` is hit
/// in every query with probability `(b)_q/(N)_q`. Every factor satisfies
/// `(b-i)/(N-i) <= b/N`, so sampling without replacement is no worse than the
/// theorem's with-replacement power bound. Rejection sampling therefore
/// changes neither the bound nor its exponent, provided all indices are
/// unique and `q <= N`; both are verifier-enforced.
pub fn validate_affine_batched_fri_theorem2_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    certificate: AggregateFriTheorem2CertificateV1,
) -> Result<AggregateFriTheorem2BoundV1, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let domain_size = layout.common_lde_size();
    let terminal_size = parameters.terminal_size()?;
    let fold_count = layout.fri_rounds(parameters)?;
    let degree_coefficients = layout.fri_degree_cap(parameters)?;
    let fold_arity_sum = u16::from(certificate.binary_fold_arity)
        .checked_mul(u16::from(certificate.fold_count))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    if parameters.security_lanes != 1
        || certificate.affine_coefficient_numerator != 3
        || certificate.affine_coefficient_denominator != 2
        || certificate.batching_parameter_m != 3
        || certificate.rho_numerator != 1
        || certificate.rho_denominator != 7
        || certificate.binary_fold_arity != 2
        || fold_count == 0
        || fold_count > 12
        || usize::from(fold_arity_sum) != 2 * fold_count
        || certificate.domain_log2 != layout.common_lde_log2
        || certificate.extension_field_lower_bound_bits != 252
        || certificate.base_field_two_adicity != 32
        || layout.common_lde_log2 > certificate.base_field_two_adicity
        || !certificate.trace_domains_are_smooth_subgroups
        || !certificate.evaluation_domain_is_smooth_generator_coset
        || !certificate.evaluation_domain_is_disjoint_from_trace_domains
        || usize::from(certificate.fold_count) != fold_count
        || certificate.terminal_log2 != parameters.terminal_log2
        || usize::from(certificate.terminal_degree_bound) != parameters.terminal_degree_bound
        || usize::from(certificate.query_count) != parameters.query_count
        || !certificate.distinct_queries_without_replacement
        || !certificate.uniform_rejection_sampling
        || parameters.query_count > domain_size
        || certificate.claimed_query_error_bits == 0
        || terminal_size
            .checked_shl(u32::from(certificate.fold_count))
            .filter(|size| *size == domain_size)
            .is_none()
        || (parameters.terminal_degree_bound + 1)
            .checked_mul(usize::from(certificate.rho_denominator))
            .zip(terminal_size.checked_mul(usize::from(certificate.rho_numerator)))
            .is_none_or(|(actual, upper)| actual > upper)
        // The loose algebraic constant below uses 1/8 <= the actual rate.
        || degree_coefficients
            .checked_mul(8)
            .is_none_or(|lower| lower < domain_size)
        || degree_coefficients
            .checked_mul(usize::from(certificate.rho_denominator))
            .zip(domain_size.checked_mul(usize::from(certificate.rho_numerator)))
            .is_none_or(|(actual, upper)| actual > upper)
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    // The eta/delta regime requires
    // `sqrt(rho) * (1 + 1/(2m)) < 1`. Squaring and clearing
    // denominators gives this exact integer inequality.
    let twice_m = u32::from(certificate.batching_parameter_m) * 2;
    let eta_numerator = u32::from(certificate.rho_numerator)
        .checked_mul(
            twice_m
                .checked_add(1)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?
                .pow(2),
        )
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let eta_denominator = u32::from(certificate.rho_denominator)
        .checked_mul(twice_m.pow(2))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    if eta_numerator >= eta_denominator {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    // For m=3, an even q gives the exact rational query term
    // `(rho * 49/36)^(q/2)`. Reduce the rational before exponentiation and
    // compare it to the claimed power of two with fixed 512-bit integers.
    if certificate.query_count % 2 != 0 {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let half_queries = certificate.query_count / 2;
    let query_base_numerator = u64::from(certificate.rho_numerator)
        .checked_mul(49)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let query_base_denominator = u64::from(certificate.rho_denominator)
        .checked_mul(36)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let common = gcd_u64_v1(query_base_numerator, query_base_denominator);
    let query_numerator = U512V1::checked_pow_small(query_base_numerator / common, half_queries)
        .and_then(|value| value.checked_shl(certificate.claimed_query_error_bits))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let query_denominator =
        U512V1::checked_pow_small(query_base_denominator / common, half_queries)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    if !query_numerator.strictly_less_than(query_denominator) {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    // These are interactive FRI algebraic errors; they do not include outer-hash
    // collision or Fiat--Shamir/QROM composition reductions.
    // Exact canonical constants conservatively bound the first commitment
    // term by `7^7 * |D|^2 / 2^252 < 2^-(252-2log|D|-20)`.
    // The actual rate is in [1/8, 1/7], so 1/sqrt(rho) < 3. With at
    // most twelve binary folds, the second coefficient is bounded by
    // `7 * 3 * sum(arities) <= 7 * 3 * 24 = 504 < 2^9`.
    // Also `|D| + 1 < 2|D|`, giving `2^9 * 2^(log|D|+1) / 2^252`.
    // The affine coefficient is 3/2, not the general theorem's L - 1/2.
    let first_commitment_bits = certificate
        .extension_field_lower_bound_bits
        .checked_sub(u16::from(certificate.domain_log2) * 2)
        .and_then(|bits| bits.checked_sub(20))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let second_commitment_bits = certificate
        .extension_field_lower_bound_bits
        .checked_sub(u16::from(certificate.domain_log2))
        .and_then(|bits| bits.checked_sub(10))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let commitment_error_bits = first_commitment_bits
        .min(second_commitment_bits)
        .checked_sub(1)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    Ok(AggregateFriTheorem2BoundV1 {
        query_error_bits: certificate.claimed_query_error_bits,
        commitment_error_bits,
    })
}
/// One group commitment and its two canonical multiproof frontiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateTraceGroupProofV1 {
    /// Base vector-row Merkle root.
    pub(crate) base_root: PrivacyOuterDigestV1,
    /// Auxiliary vector-row Merkle root.
    pub(crate) aux_root: PrivacyOuterDigestV1,
    /// Minimal base-tree multiproof frontier.
    pub(crate) base_frontier: Vec<PrivacyOuterDigestV1>,
    /// Minimal auxiliary-tree multiproof frontier.
    pub(crate) aux_frontier: Vec<PrivacyOuterDigestV1>,
}
/// One FRI round's low/high opening pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateFriRoundOpeningV1 {
    /// Canonical low-half quartic-extension value.
    pub(crate) low: [u64; 4],
    /// Canonical high-half quartic-extension value.
    pub(crate) high: [u64; 4],
}
/// All FRI round openings for one lane/query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateFriLaneQueryV1 {
    /// Round openings in folding order.
    pub(crate) rounds: Vec<AggregateFriRoundOpeningV1>,
}
/// Current and next vector rows for one trace group/query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateTraceGroupQueryV1 {
    /// Current base row.
    pub(crate) base_current: Vec<u64>,
    /// Next base row at the verifier-derived group stride.
    pub(crate) base_next: Vec<u64>,
    /// Current auxiliary row.
    pub(crate) aux_current: Vec<u64>,
    /// Next auxiliary row at the verifier-derived group stride.
    pub(crate) aux_next: Vec<u64>,
}
/// All opened values at one shared common-domain query index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateQueryProofV1 {
    /// Common-domain index.
    pub(crate) index: u32,
    /// Ordered trace-group openings.
    pub(crate) trace_groups: Vec<AggregateTraceGroupQueryV1>,
    /// Low-degree composition-chunk values in lane-major order.
    pub(crate) composition_values: Vec<Vec<[u64; 4]>>,
    /// Authenticated independent FRI-mask-oracle value per lane.
    pub(crate) fri_mask_values: Vec<[u64; 4]>,
    /// Shared FRI openings per lane.
    pub(crate) fri_lanes: Vec<AggregateFriLaneQueryV1>,
}
/// One complete shared FRI lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateFriLaneProofV1 {
    /// Layer roots, including the terminal layer.
    pub(crate) roots: Vec<PrivacyOuterDigestV1>,
    /// Exact terminal evaluations.
    pub(crate) terminal_values: Vec<[u64; 4]>,
    /// Minimal multiproof frontier for each non-terminal layer.
    pub(crate) round_frontiers: Vec<Vec<PrivacyOuterDigestV1>>,
}
/// Exact aggregate proof object before/after canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateStarkProofV1 {
    /// Exact proof version.
    pub(crate) version: u16,
    /// Ordered trace-group roots/frontiers.
    pub(crate) trace_groups: Vec<AggregateTraceGroupProofV1>,
    /// Aggregate composition roots.
    pub(crate) composition_roots: Vec<PrivacyOuterDigestV1>,
    /// Aggregate composition multiproof frontiers.
    pub(crate) composition_frontiers: Vec<Vec<PrivacyOuterDigestV1>>,
    /// Independent low-degree FRI-mask-oracle roots in lane order.
    pub(crate) fri_mask_roots: Vec<PrivacyOuterDigestV1>,
    /// Canonical FRI-mask-oracle multiproof frontiers in lane order.
    pub(crate) fri_mask_frontiers: Vec<Vec<PrivacyOuterDigestV1>>,
    /// Shared FRI lanes.
    pub(crate) fri_lanes: Vec<AggregateFriLaneProofV1>,
    /// Shared post-grinding queries.
    pub(crate) queries: Vec<AggregateQueryProofV1>,
    /// Relation-verified grinding nonce.
    pub(crate) grinding_nonce: u64,
}
/// Current and next out-of-domain evaluations for one trace group.
///
/// Each base trace polynomial is evaluated in Fp4 even though its committed
/// codeword lies in the base field. `*_next` is the same polynomial evaluated
/// at `z * omega_H`, where `omega_H` is that group's native trace generator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateDeepTraceGroupOpeningV1 {
    /// Base-column evaluations at `z`.
    pub(crate) base_current: Vec<[u64; 4]>,
    /// Base-column evaluations at `z * omega_H`.
    pub(crate) base_next: Vec<[u64; 4]>,
    /// Auxiliary-column evaluations at `z`.
    pub(crate) aux_current: Vec<[u64; 4]>,
    /// Auxiliary-column evaluations at `z * omega_H`.
    pub(crate) aux_next: Vec<[u64; 4]>,
}
/// Exact out-of-domain opening payload carried by a DEEP-enabled aggregate.
///
/// The point itself is not encoded: prover and verifier derive it uniformly
/// from the transcript after all trace/composition/mask roots are bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateDeepProofV1 {
    /// Ordered current/next trace openings.
    pub(crate) trace_groups: Vec<AggregateDeepTraceGroupOpeningV1>,
    /// Composition-chunk evaluations in lane-major order.
    pub(crate) composition_values: Vec<Vec<[u64; 4]>>,
}
/// Canonically decoded DEEP trace openings supplied to relation verifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateOpenedDeepTraceGroupV1 {
    /// Base-column evaluations at `z`.
    pub(crate) base_current: Vec<E>,
    /// Base-column evaluations at `z * omega_H`.
    pub(crate) base_next: Vec<E>,
    /// Auxiliary-column evaluations at `z`.
    pub(crate) aux_current: Vec<E>,
    /// Auxiliary-column evaluations at `z * omega_H`.
    pub(crate) aux_next: Vec<E>,
}
/// DEEP batching coefficients for one ordered trace group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateDeepTraceGroupMixV1 {
    /// Coefficients for `(base(x) - base(z)) / (x - z)`.
    pub(crate) base_current: Vec<E>,
    /// Coefficients for `(base(x) - base(omega_H z)) / (x - omega_H z)`.
    pub(crate) base_next: Vec<E>,
    /// Coefficients for `(aux(x) - aux(z)) / (x - z)`.
    pub(crate) aux_current: Vec<E>,
    /// Coefficients for `(aux(x) - aux(omega_H z)) / (x - omega_H z)`.
    pub(crate) aux_next: Vec<E>,
}
/// Complete DEEP batching coefficients for one FRI lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateDeepLaneMixV1 {
    /// Ordered trace-group mixes.
    pub(crate) trace_groups: Vec<AggregateDeepTraceGroupMixV1>,
    /// Composition-chunk mixes.
    pub(crate) composition: Vec<E>,
}
/// Original authenticated trace commitment selected by a supplemental opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateSupplementalColumnV1 {
    /// Column in the original base commitment.
    Base(usize),
    /// Column in the original auxiliary commitment.
    Auxiliary(usize),
}
/// A caller-derived additional opening of an existing authenticated trace column.
/// The caller binds the immutable family/point/column plan and all values before mixing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateSupplementalDeepOpeningV1 {
    /// Logical trace-group index.
    pub(crate) group: usize,
    /// Original commitment family and column inside the logical group.
    pub(crate) column: AggregateSupplementalColumnV1,
    /// Nonzero out-of-domain point derived by the owning relation.
    pub(crate) point: E,
    /// Canonical claimed column value at that point.
    pub(crate) value: E,
    /// Independent post-opening batching coefficient for the sole FRI lane.
    pub(crate) mix: E,
}
/// Canonical opened fields passed to a relation evaluator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateOpenedTraceGroupV1 {
    /// Current base row.
    pub(crate) base_current: Vec<F>,
    /// Next base row.
    pub(crate) base_next: Vec<F>,
    /// Current auxiliary row.
    pub(crate) aux_current: Vec<F>,
    /// Next auxiliary row.
    pub(crate) aux_next: Vec<F>,
}
/// Relation-evaluated values that the shared verifier binds to composition/FRI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateExpectedOpeningV1 {
    /// Expected aggregate composition value.
    pub(crate) composition: E,
    /// Expected base value for the selected FRI lane.
    pub(crate) fri_base: E,
}
/// Relation-specific opened-row algebra called by the shared verifier.
pub trait AggregateOpenedRowEvaluatorV1 {
    /// Evaluate one query/lane after canonical field decoding.
    fn evaluate_opened_row_v1(
        &mut self,
        query_index: usize,
        lane: usize,
        trace_groups: &[AggregateOpenedTraceGroupV1],
        composition_chunks: &[E],
    ) -> Result<AggregateExpectedOpeningV1, AggregateStarkErrorV1>;
}
/// Decode an exact vector of canonical Goldilocks residues.
pub fn canonical_fields_v1(
    values: &[u64],
    expected: usize,
) -> Result<Vec<F>, AggregateStarkErrorV1> {
    if values.len() != expected {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    values
        .iter()
        .copied()
        .map(|value| F::canonical(value).ok_or(AggregateStarkErrorV1::NonCanonicalField))
        .collect()
}
/// Decode an exact vector of canonical Goldilocks-quartic residues.
pub fn canonical_fp4_fields_v1(
    values: &[[u64; 4]],
    expected: usize,
) -> Result<Vec<E>, AggregateStarkErrorV1> {
    if values.len() != expected {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    values
        .iter()
        .copied()
        .map(|value| E::canonical(value).ok_or(AggregateStarkErrorV1::NonCanonicalField))
        .collect()
}
fn fp4_is_in_trace_subgroup_v1(point: E, trace_size: usize) -> bool {
    point.pow(trace_size as u128) == E::ONE
}
fn fp4_is_in_evaluation_coset_v1(point: E, evaluation_size: usize) -> bool {
    let shift_power = F(GOLDILOCKS_GENERATOR_V1).pow(evaluation_size as u128);
    point.pow(evaluation_size as u128) == E::from_base(shift_power)
}
/// Check the complete public exclusion predicate for a shared DEEP point.
pub fn deep_point_is_admissible_v1(
    point: E,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<bool, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    // At zero every translated opening `z * omega_H` collapses to the same
    // point. The proof carries independently mixed current/next openings, so
    // the sampler must preserve their advertised distinct-point geometry.
    if point == E::ZERO {
        return Ok(false);
    }
    let evaluation_size = layout.common_lde_size();
    for group in &layout.trace_groups {
        let next_root = goldilocks_primitive_root_v1(group.native_trace_log2)
            .map_err(map_transparent_error_v1)?;
        for candidate in [point, point.mul_base(next_root)] {
            if fp4_is_in_evaluation_coset_v1(candidate, evaluation_size) {
                return Ok(false);
            }
            for trace_group in &layout.trace_groups {
                if fp4_is_in_trace_subgroup_v1(
                    candidate,
                    checked_domain_size_v1(trace_group.native_trace_log2)?,
                ) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}
/// Derive the sole uniform DEEP point outside every trace, evaluation, and
/// query domain used by an aggregate proof.
///
/// Zero is excluded even though it is outside every multiplicative domain:
/// otherwise every translated point `z * omega_H` would equal `z`, collapsing
/// the independently mixed current/next opening geometry. For every trace
/// group the predicate also excludes `z * omega_H`, because the next-row
/// opening is evaluated at that point. Query positions are elements of the
/// common evaluation coset, so excluding the complete coset also excludes
/// every possible query point before grinding fixes the concrete index set.
pub fn derive_deep_point_v1(
    transcript: &mut TransparentTranscriptV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<E, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    transcript
        .challenge_fp4_where(DEEP_POINT_LABEL_V1, |point| {
            deep_point_is_admissible_v1(point, parameters, layout).unwrap_or(false)
        })
        .map_err(map_transparent_error_v1)
}
/// Validate the exact statement-derived shape and canonicality of a DEEP
/// opening payload.
pub fn validate_deep_proof_shape_v1(
    deep: &AggregateDeepProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<(), AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    if deep.trace_groups.len() != layout.trace_groups.len()
        || deep.composition_values.len() != parameters.security_lanes
        || deep
            .composition_values
            .iter()
            .any(|values| values.len() != parameters.composition_degree_chunks)
    {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    for (opening, group) in deep.trace_groups.iter().zip(&layout.trace_groups) {
        if opening.base_current.len() != group.base_width
            || opening.base_next.len() != group.base_width
            || opening.aux_current.len() != group.aux_width
            || opening.aux_next.len() != group.aux_width
        {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        ensure_canonical_fp4_fields_v1(&opening.base_current)?;
        ensure_canonical_fp4_fields_v1(&opening.base_next)?;
        ensure_canonical_fp4_fields_v1(&opening.aux_current)?;
        ensure_canonical_fp4_fields_v1(&opening.aux_next)?;
    }
    for values in &deep.composition_values {
        ensure_canonical_fp4_fields_v1(values)?;
    }
    Ok(())
}
/// Canonically decode all DEEP trace openings for relation-specific checks.
pub fn canonical_deep_trace_groups_v1(
    deep: &AggregateDeepProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<AggregateOpenedDeepTraceGroupV1>, AggregateStarkErrorV1> {
    validate_deep_proof_shape_v1(deep, parameters, layout)?;
    deep.trace_groups
        .iter()
        .zip(&layout.trace_groups)
        .map(|(opening, group)| {
            Ok(AggregateOpenedDeepTraceGroupV1 {
                base_current: canonical_fp4_fields_v1(&opening.base_current, group.base_width)?,
                base_next: canonical_fp4_fields_v1(&opening.base_next, group.base_width)?,
                aux_current: canonical_fp4_fields_v1(&opening.aux_current, group.aux_width)?,
                aux_next: canonical_fp4_fields_v1(&opening.aux_next, group.aux_width)?,
            })
        })
        .collect()
}
/// Absorb all DEEP values in their sole group/lane/column order.
///
/// This must run after the point is sampled and before any FRI batching or fold
/// challenge is derived.
pub fn absorb_deep_openings_v1(
    transcript: &mut TransparentTranscriptV1,
    deep: &AggregateDeepProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<(), AggregateStarkErrorV1> {
    validate_deep_proof_shape_v1(deep, parameters, layout)?;
    let mut encoding = Vec::new();
    encoding
        .try_reserve_exact(exact_deep_opening_bytes_v1(parameters, layout)?)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for group in &deep.trace_groups {
        append_fp4_fields_v1(&mut encoding, &group.base_current);
        append_fp4_fields_v1(&mut encoding, &group.base_next);
        append_fp4_fields_v1(&mut encoding, &group.aux_current);
        append_fp4_fields_v1(&mut encoding, &group.aux_next);
    }
    for values in &deep.composition_values {
        append_fp4_fields_v1(&mut encoding, values);
    }
    transcript
        .absorb(DEEP_OPENINGS_LABEL_V1, &[&encoding])
        .map_err(map_transparent_error_v1)
}
fn ensure_canonical_base_fields_v1(values: &[u64]) -> Result<(), AggregateStarkErrorV1> {
    if values
        .iter()
        .copied()
        .any(|value| F::canonical(value).is_none())
    {
        return Err(AggregateStarkErrorV1::NonCanonicalField);
    }
    Ok(())
}
fn ensure_canonical_fp4_fields_v1(values: &[[u64; 4]]) -> Result<(), AggregateStarkErrorV1> {
    if values
        .iter()
        .copied()
        .any(|value| E::canonical(value).is_none())
    {
        return Err(AggregateStarkErrorV1::NonCanonicalField);
    }
    Ok(())
}
fn row_at_v1(columns: &[Vec<F>], index: usize) -> Result<Vec<F>, AggregateStarkErrorV1> {
    columns
        .iter()
        .map(|column| {
            column
                .get(index)
                .copied()
                .ok_or(AggregateStarkErrorV1::InternalInvariant)
        })
        .collect()
}
/// Hash one vector-row leaf with its ordered group index and exact width.
pub fn row_leaf_hash_v1(
    context: TransparentStarkDigestContextV1,
    role: &[u8],
    group: usize,
    row_index: usize,
    values: &[F],
) -> Result<PrivacyOuterDigestV1, AggregateStarkErrorV1> {
    let group = u16::try_from(group)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let width = u16::try_from(values.len())
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let mut fields = zeroize::Zeroizing::new(Vec::new());
    fields
        .try_reserve_exact(
            values
                .len()
                .checked_mul(core::mem::size_of::<u64>())
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for value in values {
        let packed = zeroize::Zeroizing::new(value.0.to_be_bytes());
        fields.extend_from_slice(&packed[..]);
    }
    privacy_outer_digest_frame_v1(
        context,
        role,
        b"vector-row-leaf",
        0,
        u64::try_from(row_index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        u64::from(u16::from_be_bytes(group)),
        &[&group, &width, &fields],
    )
    .map_err(map_transparent_error_v1)
}
fn composition_leaf_hash_unchecked_v1(
    domains: &AggregateStarkDomainsV1,
    lane: usize,
    row_index: usize,
    values: &[E],
) -> Result<PrivacyOuterDigestV1, AggregateStarkErrorV1> {
    if values.is_empty() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let width = u16::try_from(values.len())
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let mut fields = Vec::new();
    fields
        .try_reserve_exact(
            values
                .len()
                .checked_mul(core::mem::size_of::<[u64; 4]>())
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for value in values {
        fields.extend_from_slice(&value.to_be_bytes());
    }
    privacy_outer_digest_frame_v1(
        domains.digest_context,
        domains.composition_leaf,
        b"composition-vector-leaf",
        0,
        u64::try_from(row_index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        u64::from(u16::from_be_bytes(lane)),
        &[&lane, &width, &fields],
    )
    .map_err(map_transparent_error_v1)
}
/// Prover-only material for one independently sampled FRI mask oracle.
///
/// The polynomial evaluations and Merkle tree are retained until the
/// transcript fixes all query positions. They are never serialized wholesale.
pub struct AggregateFriMaskOracleMaterialV1 {
    /// Coset evaluations on the common LDE domain.
    pub(crate) evaluations: Vec<E>,
    /// Authenticated oracle commitment.
    pub(crate) tree: PrivacyOuterMerkleTreeV1,
}
impl Drop for AggregateFriMaskOracleMaterialV1 {
    fn drop(&mut self) {
        zeroize_extension_field_column_v1(&mut self.evaluations);
    }
}
fn fri_mask_leaf_hash_v1(
    domains: &AggregateStarkDomainsV1,
    lane: usize,
    row_index: usize,
    value: E,
) -> Result<PrivacyOuterDigestV1, AggregateStarkErrorV1> {
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    privacy_outer_digest_frame_v1(
        domains.digest_context,
        FRI_MASK_LEAF_DOMAIN_V1,
        b"fri-mask-leaf",
        0,
        u64::try_from(row_index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        u64::from(u16::from_be_bytes(lane)),
        &[&lane, &value.to_be_bytes()],
    )
    .map_err(map_transparent_error_v1)
}
fn fri_mask_tree_v1(
    domains: &AggregateStarkDomainsV1,
    lane: usize,
    evaluations: &[E],
) -> Result<PrivacyOuterMerkleTreeV1, AggregateStarkErrorV1> {
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    commit_serialized_rows_v1(
        domains.digest_context,
        FRI_MASK_LEAF_DOMAIN_V1,
        FRI_MASK_NODE_DOMAIN_V1,
        b"fri-mask-leaf",
        0,
        u64::from(u16::from_be_bytes(lane)),
        &[&lane],
        evaluations.len(),
        32,
        |row, bytes| bytes.extend_from_slice(&evaluations[row].to_be_bytes()),
    )
}
/// Sample and commit all independent Protocol-2 FRI mask polynomials.
///
/// Each lane samples the normalized `D - 1` coefficients, which contains the
/// required `|H| + h - 1`-coefficient hiding space and stays strictly inside
/// the one FRI-enforced exclusive cap `D`. The resulting root must be
/// transcript-bound before any challenge that batches the lane's trace and
/// composition polynomials.
pub fn build_fri_mask_oracles_v1<R: TryRngCore>(
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    layout: &AggregateProofLayoutV1,
    rng: &mut R,
) -> Result<Vec<AggregateFriMaskOracleMaterialV1>, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    domains.validate()?;
    let coefficient_count = layout.fri_mask_coefficient_count(parameters)?;
    let lde_size = layout.common_lde_size();
    let lde_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).map_err(map_transparent_error_v1)?;
    let mut oracles = Vec::new();
    oracles
        .try_reserve_exact(parameters.security_lanes)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for lane in 0..parameters.security_lanes {
        let mut coefficients = ZeroizingExtensionFieldColumnV1(Vec::new());
        coefficients
            .0
            .try_reserve_exact(lde_size)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        for _ in 0..coefficient_count {
            coefficients
                .0
                .push(random_goldilocks_fp4_v1(rng).map_err(map_transparent_error_v1)?);
        }
        coefficients.0.resize(lde_size, E::ZERO);
        let evaluations = ZeroizingExtensionFieldColumnV1(
            goldilocks_fp4_evaluate_coset_v1(
                &coefficients,
                lde_size,
                lde_root,
                F(GOLDILOCKS_GENERATOR_V1),
            )
            .map_err(map_transparent_error_v1)?,
        );
        let tree = fri_mask_tree_v1(domains, lane, &evaluations)?;
        oracles.push(AggregateFriMaskOracleMaterialV1 {
            evaluations: evaluations.into_vec_v1(),
            tree,
        });
    }
    Ok(oracles)
}
/// Add the independently committed mask oracle to one batched FRI lane.
pub fn add_fri_mask_oracle_v1(
    base_values: &mut [E],
    mask: &AggregateFriMaskOracleMaterialV1,
) -> Result<(), AggregateStarkErrorV1> {
    if base_values.len() != mask.evaluations.len() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    for (base, randomizer) in base_values.iter_mut().zip(&mask.evaluations) {
        *base = base.add(*randomizer);
    }
    Ok(())
}
fn fri_leaf_hash_unchecked_v1(
    domains: &AggregateStarkDomainsV1,
    lane: usize,
    round: usize,
    row_index: usize,
    value: E,
) -> Result<PrivacyOuterDigestV1, AggregateStarkErrorV1> {
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let round = u16::try_from(round)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    privacy_outer_digest_frame_v1(
        domains.digest_context,
        domains.fri_leaf,
        b"fri-layer-leaf",
        u64::from(u16::from_be_bytes(round)),
        u64::try_from(row_index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        u64::from(u16::from_be_bytes(lane)),
        &[&lane, &round, &value.to_be_bytes()],
    )
    .map_err(map_transparent_error_v1)
}
/// Authenticate both evaluations consumed by a binary fold in one ordered leaf.
fn fri_pair_leaf_hash_v1(
    domains: &AggregateStarkDomainsV1,
    lane: usize,
    round: usize,
    pair_index: usize,
    low: E,
    high: E,
) -> Result<PrivacyOuterDigestV1, AggregateStarkErrorV1> {
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let round = u16::try_from(round)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    // Non-query streaming commitments can still contain private masked values.
    // Clear every owned encoding buffer; Copy field arguments/register spills
    // are outside the erasure guarantee provided by these storage owners.
    let mut pair = zeroize::Zeroizing::new([0_u8; 64]);
    let low_encoding = zeroize::Zeroizing::new(low.to_be_bytes());
    let high_encoding = zeroize::Zeroizing::new(high.to_be_bytes());
    pair[..32].copy_from_slice(&low_encoding[..]);
    pair[32..].copy_from_slice(&high_encoding[..]);
    privacy_outer_digest_frame_v1(
        domains.digest_context,
        domains.fri_leaf,
        b"fri-layer-pair-leaf",
        u64::from(u16::from_be_bytes(round)),
        u64::try_from(pair_index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        u64::from(u16::from_be_bytes(lane)),
        &[&lane, &round, &pair[..]],
    )
    .map_err(map_transparent_error_v1)
}
/// Maximum live serialized private-row payload bytes before canonical framing.
const PRIVATE_ROW_PAYLOAD_BUDGET_BYTES_V1: usize = 32 * 1024 * 1024;

fn private_row_preparation_rows_v1(
    domain: crate::privacy_engines::privacy_outer_hash::PrivacyOuterDomainV1<'_>,
    prefix_fields: &[&[u8]],
    payload_bytes: usize,
    frame_limit: usize,
) -> Result<usize, AggregateStarkErrorV1> {
    if payload_bytes == 0
        || frame_limit == 0
        || frame_limit
            > crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_FRAMES_V1
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let field_count = prefix_fields
        .len()
        .checked_add(1)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let mut lengths = Vec::new();
    lengths
        .try_reserve_exact(field_count)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    lengths.extend(prefix_fields.iter().map(|field| field.len()));
    lengths.push(payload_bytes);
    let words =
        crate::privacy_engines::privacy_outer_hash::PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(domain, &lengths)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let framed_byte_rows =
        crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_BYTES_V1
            .checked_div(words)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let rows = (PRIVATE_ROW_PAYLOAD_BUDGET_BYTES_V1 / payload_bytes)
        .min(frame_limit)
        .min(framed_byte_rows);
    if rows == 0 {
        return Err(AggregateStarkErrorV1::AllocationFailure);
    }
    Ok(rows)
}

/// Serialize bounded private rows into canonical frames and hash them in ordered CPU batches.
/// The caller fixes the exact ordered non-payload fields; this helper appends one payload.
fn commit_serialized_rows_v1(
    context: TransparentStarkDigestContextV1,
    leaf_role: &[u8],
    node_role: &'static [u8],
    phase: &[u8],
    level: u64,
    counter: u64,
    prefix_fields: &[&[u8]],
    rows: usize,
    payload_bytes: usize,
    serialize_row: impl FnMut(usize, &mut Vec<u8>),
) -> Result<PrivacyOuterMerkleTreeV1, AggregateStarkErrorV1> {
    commit_serialized_rows_with_preparation_limit_v1(
        context,
        leaf_role,
        node_role,
        phase,
        level,
        counter,
        prefix_fields,
        rows,
        payload_bytes,
        crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_FRAMES_V1,
        serialize_row,
    )
}

fn commit_serialized_rows_with_preparation_limit_v1(
    context: TransparentStarkDigestContextV1,
    leaf_role: &[u8],
    node_role: &'static [u8],
    phase: &[u8],
    level: u64,
    counter: u64,
    prefix_fields: &[&[u8]],
    rows: usize,
    payload_bytes: usize,
    preparation_frame_limit: usize,
    mut serialize_row: impl FnMut(usize, &mut Vec<u8>),
) -> Result<PrivacyOuterMerkleTreeV1, AggregateStarkErrorV1> {
    if rows == 0 || !rows.is_power_of_two() || payload_bytes == 0 {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    context.validate().map_err(map_transparent_error_v1)?;
    let catalog = context.catalog_v1();
    let leaf_domain = context
        .domain_v1(&catalog, leaf_role, phase, level, 0, counter)
        .map_err(map_transparent_error_v1)?;
    let batch_rows = private_row_preparation_rows_v1(
        leaf_domain,
        prefix_fields,
        payload_bytes,
        preparation_frame_limit,
    )?;
    let mut leaves = Vec::new();
    leaves
        .try_reserve_exact(rows)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for start in (0..rows).step_by(batch_rows) {
        let end = start.saturating_add(batch_rows).min(rows);
        let mut payloads = zeroize::Zeroizing::new(Vec::<Vec<u8>>::new());
        payloads
            .try_reserve_exact(end - start)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        for row in start..end {
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            bytes
                .try_reserve_exact(payload_bytes)
                .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
            serialize_row(row, &mut bytes);
            if bytes.len() != payload_bytes {
                return Err(AggregateStarkErrorV1::InvalidLayout);
            }
            payloads.push(core::mem::take(&mut *bytes));
        }
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(payloads.len())
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        for payload in payloads.iter() {
            let mut row_fields = Vec::new();
            row_fields
                .try_reserve_exact(
                    prefix_fields
                        .len()
                        .checked_add(1)
                        .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
                )
                .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
            row_fields.extend_from_slice(prefix_fields);
            row_fields.push(payload.as_slice());
            fields.push(row_fields);
        }
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(fields.len())
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        for (local, row_fields) in fields.iter().enumerate() {
            let domain = context
                .domain_v1(
                    &catalog,
                    leaf_role,
                    phase,
                    level,
                    u64::try_from(start + local)
                        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
                    counter,
                )
                .map_err(map_transparent_error_v1)?;
            frames.push(
                crate::privacy_engines::privacy_outer_hash::PrivacyOuterFrameV1::new(
                    domain, row_fields,
                )
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
            );
        }
        leaves.extend(
            frames
                .par_iter()
                .map(|frame| frame.hash())
                .collect::<Vec<_>>(),
        );
    }
    PrivacyOuterMerkleTreeV1::from_leaves(leaves, context, node_role)
        .map_err(map_transparent_error_v1)
}

/// Commit vector-row columns on a common power-of-two domain.
pub fn row_tree_v1(
    context: TransparentStarkDigestContextV1,
    leaf_role: &[u8],
    node_role: &'static [u8],
    group: usize,
    columns: &[Vec<F>],
    rows: usize,
) -> Result<PrivacyOuterMerkleTreeV1, AggregateStarkErrorV1> {
    if rows == 0
        || !rows.is_power_of_two()
        || columns.is_empty()
        || columns.iter().any(|column| column.len() != rows)
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let group = u16::try_from(group)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let width = u16::try_from(columns.len())
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let payload_bytes = columns
        .len()
        .checked_mul(8)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    commit_serialized_rows_v1(
        context,
        leaf_role,
        node_role,
        b"vector-row-leaf",
        0,
        u64::from(u16::from_be_bytes(group)),
        &[&group, &width],
        rows,
        payload_bytes,
        |row, bytes| {
            for column in columns {
                bytes.extend_from_slice(&column[row].0.to_be_bytes());
            }
        },
    )
}
/// Root and canonical minimal frontier produced without retaining a Merkle tree.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamingMerkleCommitmentV1 {
    /// Root of the complete power-of-two leaf stream.
    pub(crate) root: PrivacyOuterDigestV1,
    /// Canonically ordered minimal frontier for the requested leaves.
    pub(crate) frontier: Vec<PrivacyOuterDigestV1>,
}
/// Incremental binary Merkle accumulator with a query-aware frontier plan.
///
/// Leaves must be appended in ascending index order. The accumulator retains
/// one pending subtree per level and only those sibling hashes required by the
/// requested canonical multiproof. Its memory is therefore
/// `O(log(leaf_count) + frontier_len)` rather than `O(leaf_count)`.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct StreamingMerkleAccumulatorV1 {
    node_prefixes: Vec<PrivacyOuterDomainPrefixV1>,
    leaf_count: usize,
    next_leaf: usize,
    pending: Vec<Option<PrivacyOuterDigestV1>>,
    frontier_positions: BTreeMap<(usize, usize), usize>,
    frontier: Vec<Option<PrivacyOuterDigestV1>>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl StreamingMerkleAccumulatorV1 {
    /// Create an accumulator for an exact leaf count and sorted unique opening set.
    ///
    /// An empty opening set is permitted for the transcript's root-only
    /// commitment pass.
    pub(crate) fn new(
        context: TransparentStarkDigestContextV1,
        node_role: &'static [u8],
        leaf_count: usize,
        opening_indices: &[usize],
    ) -> Result<Self, AggregateStarkErrorV1> {
        context.validate().map_err(map_transparent_error_v1)?;
        if node_role.is_empty()
            || u16::try_from(node_role.len()).is_err()
            || leaf_count == 0
            || !leaf_count.is_power_of_two()
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        if !opening_indices.is_empty() {
            validate_canonical_index_set_v1(leaf_count, opening_indices)?;
        }
        let height = usize::try_from(leaf_count.ilog2())
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?;
        let mut node_prefixes = Vec::new();
        node_prefixes
            .try_reserve_exact(height)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        if node_prefixes.capacity() > usize::BITS as usize {
            return Err(AggregateStarkErrorV1::AllocationFailure);
        }
        let catalog = context.catalog_v1();
        for level in 1..=height {
            let domain = context
                .domain_v1(
                    &catalog,
                    node_role,
                    b"binary-merkle-node",
                    level as u64,
                    0,
                    0,
                )
                .map_err(map_transparent_error_v1)?;
            node_prefixes.push(
                PrivacyOuterDomainPrefixV1::new(domain)
                    .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
            );
        }
        let mut frontier_positions = BTreeMap::new();
        let mut current = opening_indices.iter().copied().collect::<BTreeSet<_>>();
        let mut level_size = leaf_count;
        let mut level = 0_usize;
        let mut frontier_len = 0_usize;
        while level_size > 1 && !current.is_empty() {
            for &index in &current {
                if !current.contains(&(index ^ 1)) {
                    if frontier_positions
                        .insert((level, index ^ 1), frontier_len)
                        .is_some()
                    {
                        return Err(AggregateStarkErrorV1::InternalInvariant);
                    }
                    frontier_len = frontier_len
                        .checked_add(1)
                        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
                }
            }
            current = current.into_iter().map(|index| index >> 1).collect();
            level_size >>= 1;
            level += 1;
        }
        if !opening_indices.is_empty()
            && (current.len() != 1
                || !current.contains(&0)
                || frontier_len != multiproof_frontier_len_v1(leaf_count, opening_indices)?)
        {
            return Err(AggregateStarkErrorV1::InternalInvariant);
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(
                height
                    .checked_add(1)
                    .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
            )
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        pending.resize(height + 1, None);
        let mut frontier = Vec::new();
        frontier
            .try_reserve_exact(frontier_len)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        frontier.resize(frontier_len, None);
        Ok(Self {
            node_prefixes,
            leaf_count,
            next_leaf: 0,
            pending,
            frontier_positions,
            frontier,
        })
    }
    fn capture(
        &mut self,
        level: usize,
        index: usize,
        node: PrivacyOuterDigestV1,
    ) -> Result<(), AggregateStarkErrorV1> {
        let Some(position) = self.frontier_positions.get(&(level, index)).copied() else {
            return Ok(());
        };
        let slot = self
            .frontier
            .get_mut(position)
            .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
        if slot.replace(node).is_some() {
            return Err(AggregateStarkErrorV1::InternalInvariant);
        }
        Ok(())
    }
    /// Append one complete aligned subtree whose lower frontier was captured.
    fn append_subtree_v1(
        &mut self,
        mut level: usize,
        mut node: PrivacyOuterDigestV1,
    ) -> Result<(), AggregateStarkErrorV1> {
        let subtree_leaves = 1usize
            .checked_shl(
                u32::try_from(level).map_err(|_| AggregateStarkErrorV1::InvalidProofShape)?,
            )
            .ok_or(AggregateStarkErrorV1::InvalidProofShape)?;
        if !self.next_leaf.is_multiple_of(subtree_leaves)
            || self
                .next_leaf
                .checked_add(subtree_leaves)
                .is_none_or(|end| end > self.leaf_count)
            || self
                .pending
                .get(..level)
                .is_none_or(|slots| slots.iter().any(Option::is_some))
        {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        let mut index = self.next_leaf >> level;
        self.capture(level, index, node)?;
        loop {
            let slot = self
                .pending
                .get_mut(level)
                .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
            if index & 1 == 0 {
                if slot.replace(node).is_some() {
                    return Err(AggregateStarkErrorV1::InternalInvariant);
                }
                break;
            }
            let left = slot
                .take()
                .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
            let parent_index = index >> 1;
            node = self
                .node_prefixes
                .get(level)
                .ok_or(AggregateStarkErrorV1::InternalInvariant)?
                .hash_at_with_counter(parent_index as u64, 0, &[left.as_bytes(), node.as_bytes()])
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
            index = parent_index;
            level += 1;
            self.capture(level, index, node)?;
        }
        self.next_leaf = self
            .next_leaf
            .checked_add(subtree_leaves)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        Ok(())
    }
    /// Finish the exact stream and return its root and requested frontier.
    pub(crate) fn finish(mut self) -> Result<StreamingMerkleCommitmentV1, AggregateStarkErrorV1> {
        if self.next_leaf != self.leaf_count {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        let height = usize::try_from(self.leaf_count.ilog2())
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?;
        if self.pending[..height].iter().any(Option::is_some) {
            return Err(AggregateStarkErrorV1::InternalInvariant);
        }
        if self.frontier.iter().any(Option::is_none) {
            return Err(AggregateStarkErrorV1::InternalInvariant);
        }
        let root = self.pending[height]
            .take()
            .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
        let frontier = core::mem::take(&mut self.frontier)
            .into_iter()
            .map(|node| node.ok_or(AggregateStarkErrorV1::InternalInvariant))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(StreamingMerkleCommitmentV1 { root, frontier })
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for StreamingMerkleAccumulatorV1 {
    fn drop(&mut self) {
        for node in self.pending.iter_mut().chain(&mut self.frontier).flatten() {
            node.zeroize_v1();
        }
    }
}
/// Commit an exact leaf iterator with logarithmic tree memory.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn streaming_merkle_commitment_v1<I>(
    context: TransparentStarkDigestContextV1,
    node_role: &'static [u8],
    leaf_count: usize,
    opening_indices: &[usize],
    leaves: I,
) -> Result<StreamingMerkleCommitmentV1, AggregateStarkErrorV1>
where
    I: IntoIterator<Item = Result<PrivacyOuterDigestV1, AggregateStarkErrorV1>>,
{
    let mut accumulator =
        StreamingMerkleAccumulatorV1::new(context, node_role, leaf_count, opening_indices)?;
    streaming_commitment::append_leaves_v1(&mut accumulator, leaves.into_iter())?;
    accumulator.finish()
}
/// Fixed finalization scratch, including named worker temporaries and prefixes.
/// The row-state allocation itself remains charged separately by its caller.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn streaming_row_finalization_payload_bound_v1() -> Result<usize, AggregateStarkErrorV1> {
    streaming_commitment::payload_bound_v1()
}
/// Result of one column-streamed vector-row commitment pass.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamingRowCommitmentResultV1 {
    /// Root and canonical frontier of the committed vector rows.
    pub(crate) commitment: StreamingMerkleCommitmentV1,
    /// Exact requested vector rows keyed by ascending LDE index.
    pub(crate) opened_rows: BTreeMap<usize, Vec<F>>,
}
/// Bounded column-batch vector-row commitment builder.
///
/// This is the bounded-memory replacement for retaining every LDE column.
/// Each row owns one incremental SHA3-384 byte state while columns are supplied in
/// canonical order. The final leaf digests are immediately consumed by
/// [`StreamingMerkleAccumulatorV1`], so neither leaves nor tree levels are
/// retained. A second deterministic pass after Fiat–Shamir query derivation
/// supplies the canonical frontier and the small set of opened rows.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct StreamingRowCommitmentV1 {
    rows: usize,
    width: usize,
    received_columns: usize,
    failed: bool,
    context: TransparentStarkDigestContextV1,
    node_role: &'static [u8],
    digest_streams: Vec<PrivacyOuterLastFieldStreamV1>,
    opening_indices: Vec<usize>,
    opened_rows: BTreeMap<usize, Vec<F>>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl StreamingRowCommitmentV1 {
    /// Start an exact row commitment pass.
    pub(crate) fn new(
        context: TransparentStarkDigestContextV1,
        leaf_role: &[u8],
        node_role: &'static [u8],
        group: usize,
        rows: usize,
        width: usize,
        opening_indices: &[usize],
    ) -> Result<Self, AggregateStarkErrorV1> {
        context.validate().map_err(map_transparent_error_v1)?;
        if leaf_role.is_empty()
            || node_role.is_empty()
            || rows == 0
            || !rows.is_power_of_two()
            || width == 0
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        if !opening_indices.is_empty() {
            validate_canonical_index_set_v1(rows, opening_indices)
                .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?;
        }
        let group = u16::try_from(group)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
            .to_be_bytes();
        let width_u16 = u16::try_from(width)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
            .to_be_bytes();
        let value_bytes = width
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let mut digest_streams = Vec::new();
        digest_streams
            .try_reserve_exact(rows)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        if digest_streams.capacity() != rows {
            return Err(AggregateStarkErrorV1::AllocationFailure);
        }
        {
            let catalog = context.catalog_v1();
            let domain = context
                .domain_v1(&catalog, leaf_role, b"vector-row-leaf", 0, 0, 0)
                .map_err(map_transparent_error_v1)?;
            let prefix = PrivacyOuterDomainPrefixV1::new(domain)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
            for row_index in 0..rows {
                digest_streams.push(
                    prefix
                        .last_field_stream_at_with_counter(
                            row_index as u64,
                            u64::from(u16::from_be_bytes(group)),
                            &[&group, &width_u16],
                            value_bytes,
                        )
                        .map_err(map_digest_stream_error_v1)
                        .map_err(map_transparent_error_v1)?,
                );
            }
        }
        let mut opened_rows = BTreeMap::new();
        for &index in opening_indices {
            let mut values = Vec::new();
            values
                .try_reserve_exact(width)
                .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
            if opened_rows.insert(index, values).is_some() {
                return Err(AggregateStarkErrorV1::InvalidLayout);
            }
        }
        Ok(Self {
            rows,
            width,
            received_columns: 0,
            failed: false,
            context,
            node_role,
            digest_streams,
            opening_indices: opening_indices.to_vec(),
            opened_rows,
        })
    }
    /// Absorb one complete LDE column in canonical column order.
    #[cfg(test)]
    pub(crate) fn absorb_column(&mut self, column: &[F]) -> Result<(), AggregateStarkErrorV1> {
        self.absorb_columns_v1(&[column])
    }
    /// Absorb at most eight adjacent columns, with exact row-major byte order.
    ///
    /// Independent row states run in parallel. Each active row chunk owns one
    /// clearing 64-byte packing buffer; no row matrix or result vector is
    /// allocated. The complete batch is checked before any hash state changes.
    /// An unexpected stream failure poisons the builder and selects the error
    /// at the earliest row, independently of worker completion order.
    pub(crate) fn absorb_columns_v1<C: AsRef<[F]> + Sync>(
        &mut self,
        columns: &[C],
    ) -> Result<(), AggregateStarkErrorV1> {
        if self.failed
            || columns.is_empty()
            || columns.len() > MASKED_TRACE_LDE_COLUMN_BATCH_V1
            || self
                .received_columns
                .checked_add(columns.len())
                .is_none_or(|end| end > self.width)
            || columns
                .iter()
                .any(|column| column.as_ref().len() != self.rows)
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        if columns.iter().any(|column| {
            column
                .as_ref()
                .iter()
                .any(|value| F::canonical(value.0).is_none())
        }) {
            return Err(AggregateStarkErrorV1::NonCanonicalField);
        }
        self.failed = true;
        const ROWS_PER_CHUNK: usize = 1024;
        let failure = self
            .digest_streams
            .par_chunks_mut(ROWS_PER_CHUNK)
            .enumerate()
            .map(|(chunk_index, streams)| {
                let mut packed = zeroize::Zeroizing::new(
                    [0_u8; MASKED_TRACE_LDE_COLUMN_BATCH_V1 * core::mem::size_of::<u64>()],
                );
                for (offset, stream) in streams.iter_mut().enumerate() {
                    let row = chunk_index * ROWS_PER_CHUNK + offset;
                    for (column, values) in columns.iter().enumerate() {
                        packed[column * 8..(column + 1) * 8]
                            .copy_from_slice(&values.as_ref()[row].0.to_be_bytes());
                    }
                    if let Err(error) = stream.update(&packed[..columns.len() * 8]) {
                        return Some((row, error));
                    }
                }
                None
            })
            .reduce(
                || None,
                |left, right| match (left, right) {
                    (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
                    (left, right) => left.or(right),
                },
            );
        if let Some((_, error)) = failure {
            return Err(map_transparent_error_v1(map_digest_stream_error_v1(error)));
        }
        for &index in &self.opening_indices {
            let row = self
                .opened_rows
                .get_mut(&index)
                .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
            for column in columns {
                row.push(column.as_ref()[index]);
            }
        }
        self.received_columns += columns.len();
        self.failed = false;
        Ok(())
    }
    fn clear_private_opened_rows_v1(&mut self) {
        for row in self.opened_rows.values_mut() {
            zeroize_field_column_v1(row);
        }
    }
    /// Retain a clearing level-four cut during the original root-only pass.
    pub(crate) fn finish_retaining_cut_v1(
        mut self,
    ) -> Result<
        (
            StreamingRowCommitmentResultV1,
            retained_commitment::RetainedMerkleCutV1,
        ),
        AggregateStarkErrorV1,
    > {
        if self.failed
            || self.digest_streams.capacity() != self.rows
            || self.received_columns != self.width
            || !self.opening_indices.is_empty()
            || !self.opened_rows.is_empty()
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let mut cut = retained_commitment::RetainedMerkleCutV1::new_v1(self.rows)?;
        let mut accumulator =
            StreamingMerkleAccumulatorV1::new(self.context, self.node_role, self.rows, &[])?;
        streaming_commitment::finish_rows_retaining_v1(
            &mut accumulator,
            &mut self.digest_streams,
            &mut cut,
        )?;
        let commitment = accumulator.finish()?;
        cut.bind_root_v1(commitment.root)?;
        Ok((
            StreamingRowCommitmentResultV1 {
                commitment,
                opened_rows: BTreeMap::new(),
            },
            cut,
        ))
    }
    /// Finalize the exact-width vector rows into a streaming Merkle commitment.
    #[cfg(test)]
    pub(crate) fn finish(
        mut self,
    ) -> Result<StreamingRowCommitmentResultV1, AggregateStarkErrorV1> {
        if self.failed
            || self.digest_streams.capacity() != self.rows
            || self.received_columns != self.width
            || self
                .opened_rows
                .values()
                .any(|values| values.len() != self.width)
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let mut accumulator = StreamingMerkleAccumulatorV1::new(
            self.context,
            self.node_role,
            self.rows,
            &self.opening_indices,
        )?;
        streaming_commitment::finish_rows_v1(&mut accumulator, &mut self.digest_streams)?;
        let commitment = accumulator.finish()?;
        Ok(StreamingRowCommitmentResultV1 {
            commitment,
            opened_rows: core::mem::take(&mut self.opened_rows),
        })
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for StreamingRowCommitmentV1 {
    fn drop(&mut self) {
        // Failed/incomplete passes have not released these rows as proof data.
        // Successful finalization transfers them to the public-opening result.
        self.clear_private_opened_rows_v1();
    }
}

/// Secret replay material for one exact ordered set of streamed trace columns.
///
/// This type deliberately implements neither `Clone` nor `Debug`. Dropping it
/// recursively overwrites every mask coefficient through
/// [`ReplayableTraceMaskV1`].
#[cfg(test)]
pub struct StreamingTraceMaskSetV1 {
    native_trace_log2: u8,
    lde_log2: u8,
    masks: Vec<ReplayableTraceMaskV1>,
}
/// Owner of one secret-bearing field column that overwrites every cell on
/// every return path.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct ZeroizingFieldColumnV1(Vec<F>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZeroizingFieldColumnV1 {
    /// Transfer an already allocated private column into its clearing owner.
    pub(crate) fn from_vec_v1(values: Vec<F>) -> Self {
        Self(values)
    }

    fn zeroize_v1(&mut self) {
        zeroize_field_column_v1(&mut self.0);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::ops::Deref for ZeroizingFieldColumnV1 {
    type Target = [F];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl AsRef<[F]> for ZeroizingFieldColumnV1 {
    fn as_ref(&self) -> &[F] {
        &self.0
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZeroizingFieldColumnV1 {
    fn drop(&mut self) {
        self.zeroize_v1();
    }
}
fn zeroize_field_column_v1(values: &mut [F]) {
    for value in values {
        value.zeroize_v1();
    }
}
/// Owner of one secret-bearing quartic-extension column that overwrites every
/// base-field coefficient on every return path.
struct ZeroizingExtensionFieldColumnV1(Vec<E>);
impl ZeroizingExtensionFieldColumnV1 {
    fn into_vec_v1(mut self) -> Vec<E> {
        core::mem::take(&mut self.0)
    }

    fn zeroize_v1(&mut self) {
        zeroize_extension_field_column_v1(&mut self.0);
    }
}
impl core::ops::Deref for ZeroizingExtensionFieldColumnV1 {
    type Target = [E];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for ZeroizingExtensionFieldColumnV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ZeroizingExtensionFieldColumnV1 {
    fn drop(&mut self) {
        self.zeroize_v1();
    }
}
/// Clone-preserving owner for prover-only extension matrices that recursively wipes on drop.
#[derive(Clone)]
pub struct ZeroizingExtensionFieldMatrixV1(Vec<Vec<E>>);
impl ZeroizingExtensionFieldMatrixV1 {
    fn into_vec_v1(mut self) -> Vec<Vec<E>> {
        core::mem::take(&mut self.0)
    }

    fn zeroize_v1(&mut self) {
        for column in &mut self.0 {
            zeroize_extension_field_column_v1(column);
        }
    }
}
impl core::ops::Deref for ZeroizingExtensionFieldMatrixV1 {
    type Target = Vec<Vec<E>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for ZeroizingExtensionFieldMatrixV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ZeroizingExtensionFieldMatrixV1 {
    fn drop(&mut self) {
        self.zeroize_v1();
    }
}
fn zeroize_extension_field_column_v1(values: &mut [E]) {
    for value in values {
        value.zeroize_v1();
    }
}
#[cfg(test)]
impl StreamingTraceMaskSetV1 {
    /// Number of committed columns.
    pub(crate) fn width(&self) -> usize {
        self.masks.len()
    }
}
/// Secret retained masked polynomials for one exact streamed trace commitment.
///
/// Each column stores ascending coefficients of
/// `T(X) + r(X) * (X^n - 1)`, rather than a common-domain LDE. This lets a
/// prover evaluate the same committed polynomial on its large commitment
/// domain, a smaller quotient domain, and transcript-derived DEEP points
/// without anonymous matrix scratch. The type implements neither `Clone` nor
/// `Debug`; every coefficient is overwritten recursively on drop.
#[cfg(test)]
pub struct MaskedTracePolynomialSetV1 {
    native_trace_log2: u8,
    commitment_lde_log2: u8,
    columns: Vec<ZeroizingFieldColumnV1>,
}
#[cfg(test)]
impl MaskedTracePolynomialSetV1 {
    /// Sample and retain native masked polynomials before their physical row
    /// commitment is chosen. The caller owns the immutable logical layout;
    /// this does not derive challenges or expose unmasked witness coefficients.
    /// Shape checks and retained-column-list reservation precede witness callbacks;
    /// per-column allocations fail through the same clearing owners.
    pub(crate) fn sample_columns_v1<R, S>(
        native_trace_log2: u8,
        commitment_lde_log2: u8,
        width: usize,
        mask_degree: usize,
        rng: &mut R,
        mut source: S,
    ) -> Result<Self, AggregateStarkErrorV1>
    where
        R: TryRngCore,
        S: FnMut(usize) -> Result<Vec<F>, AggregateStarkErrorV1>,
    {
        let native_rows = checked_domain_size_v1(native_trace_log2)?;
        let commitment_rows = checked_domain_size_v1(commitment_lde_log2)?;
        if native_trace_log2 >= commitment_lde_log2
            || width == 0
            || u16::try_from(width).is_err()
            || native_rows
                .checked_add(mask_degree)
                .is_none_or(|highest| highest >= commitment_rows)
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(width)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        for column_index in 0..width {
            let native = ZeroizingFieldColumnV1(source(column_index)?);
            if native.len() != native_rows {
                return Err(AggregateStarkErrorV1::InvalidLayout);
            }
            let mask = sample_trace_mask_v1(mask_degree, rng).map_err(map_transparent_error_v1)?;
            let coefficients = ZeroizingFieldColumnV1(
                masked_trace_coefficients_with_mask_v1(
                    &native,
                    native_trace_log2,
                    mask.coefficients(),
                )
                .map_err(map_transparent_error_v1)?,
            );
            columns.push(coefficients);
        }

        let polynomials = Self {
            native_trace_log2,
            commitment_lde_log2,
            columns,
        };
        polynomials.validate_v1()?;
        Ok(polynomials)
    }

    fn validate_v1(&self) -> Result<(usize, usize), AggregateStarkErrorV1> {
        let native_rows = checked_domain_size_v1(self.native_trace_log2)?;
        let commitment_rows = checked_domain_size_v1(self.commitment_lde_log2)?;
        let coefficient_count = self
            .columns
            .first()
            .map(|column| column.len())
            .filter(|count| *count > native_rows && *count <= commitment_rows)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        if self.native_trace_log2 >= self.commitment_lde_log2
            || self.columns.iter().any(|column| {
                column.len() != coefficient_count
                    || column.iter().any(|value| F::canonical(value.0).is_none())
            })
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        Ok((native_rows, commitment_rows))
    }
    /// Number of committed columns.
    pub(crate) fn width(&self) -> usize {
        self.columns.len()
    }
    /// Native trace-domain logarithm shared by every retained polynomial.
    pub(crate) const fn native_trace_log2(&self) -> u8 {
        self.native_trace_log2
    }
    /// Logarithm of the domain used by the transcript-bound commitment.
    pub(crate) const fn commitment_lde_log2(&self) -> u8 {
        self.commitment_lde_log2
    }
    /// Exact ascending coefficients of one retained masked polynomial.
    pub(crate) fn column_coefficients_v1(
        &self,
        column: usize,
    ) -> Result<&[F], AggregateStarkErrorV1> {
        self.validate_v1()?;
        self.columns
            .get(column)
            .map(|values| values.0.as_slice())
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
    /// Evaluate one retained column on a canonical generator coset.
    pub(crate) fn evaluate_column_on_coset_v1(
        &self,
        column: usize,
        evaluation_log2: u8,
    ) -> Result<ZeroizingFieldColumnV1, AggregateStarkErrorV1> {
        let coefficients = self.column_coefficients_v1(column)?;
        Ok(ZeroizingFieldColumnV1(
            masked_trace_coefficients_on_coset_v1(
                coefficients,
                self.native_trace_log2,
                evaluation_log2,
            )
            .map_err(map_transparent_error_v1)?,
        ))
    }
    /// Evaluate every retained column on one verifier-derived coset.
    #[cfg(test)]
    pub(crate) fn evaluate_columns_on_coset_v1(
        &self,
        evaluation_log2: u8,
    ) -> Result<Vec<ZeroizingFieldColumnV1>, AggregateStarkErrorV1> {
        self.validate_v1()?;
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(self.width())
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        for column in 0..self.width() {
            columns.push(self.evaluate_column_on_coset_v1(column, evaluation_log2)?);
        }
        Ok(columns)
    }
}
fn checked_domain_size_v1(log2: u8) -> Result<usize, AggregateStarkErrorV1> {
    1_usize
        .checked_shl(u32::from(log2))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
#[cfg(test)]
fn validate_masked_trace_commitment_shape_v1(
    leaf_domain: &[u8],
    node_domain: &[u8],
    group: usize,
    native_trace_log2: u8,
    lde_log2: u8,
    width: usize,
    mask_degree: usize,
    opening_indices: &[usize],
) -> Result<(usize, usize), AggregateStarkErrorV1> {
    let native_rows = checked_domain_size_v1(native_trace_log2)?;
    let lde_rows = checked_domain_size_v1(lde_log2)?;
    if leaf_domain.is_empty()
        || node_domain.is_empty()
        || native_trace_log2 >= lde_log2
        || width == 0
        || u16::try_from(group).is_err()
        || u16::try_from(width).is_err()
        || u16::try_from(leaf_domain.len()).is_err()
        || native_rows
            .checked_add(mask_degree)
            .is_none_or(|highest| highest >= lde_rows)
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    if !opening_indices.is_empty() {
        validate_canonical_index_set_v1(lde_rows, opening_indices)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?;
    }
    Ok((native_rows, lde_rows))
}
/// Sample replayable masks and commit columns generated one at a time.
#[cfg(test)]
pub fn commit_masked_trace_columns_v1<R, S>(
    context: TransparentStarkDigestContextV1,
    leaf_domain: &[u8],
    node_domain: &'static [u8],
    group: usize,
    native_trace_log2: u8,
    lde_log2: u8,
    width: usize,
    mask_degree: usize,
    opening_indices: &[usize],
    rng: &mut R,
    mut source: S,
) -> Result<(StreamingRowCommitmentResultV1, StreamingTraceMaskSetV1), AggregateStarkErrorV1>
where
    R: TryRngCore,
    S: FnMut(usize) -> Result<Vec<F>, AggregateStarkErrorV1>,
{
    let (native_rows, lde_rows) = validate_masked_trace_commitment_shape_v1(
        leaf_domain,
        node_domain,
        group,
        native_trace_log2,
        lde_log2,
        width,
        mask_degree,
        opening_indices,
    )?;
    let mut commitment = StreamingRowCommitmentV1::new(
        context,
        leaf_domain,
        node_domain,
        group,
        lde_rows,
        width,
        opening_indices,
    )?;
    let mut masks = Vec::new();
    masks
        .try_reserve_exact(width)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for column_index in 0..width {
        let native = ZeroizingFieldColumnV1(source(column_index)?);
        if native.len() != native_rows {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let mask = sample_trace_mask_v1(mask_degree, rng).map_err(map_transparent_error_v1)?;
        let lde = ZeroizingFieldColumnV1(
            masked_trace_lde_column_with_mask_v1(
                &native,
                native_trace_log2,
                lde_log2,
                mask.coefficients(),
            )
            .map_err(map_transparent_error_v1)?,
        );
        commitment.absorb_column(&lde)?;
        masks.push(mask);
    }
    Ok((
        commitment.finish()?,
        StreamingTraceMaskSetV1 {
            native_trace_log2,
            lde_log2,
            masks,
        },
    ))
}
/// Deterministically replay one streamed trace commitment with the original
/// secret masks after Fiat–Shamir queries are fixed.
#[cfg(test)]
pub fn replay_masked_trace_columns_v1<S>(
    context: TransparentStarkDigestContextV1,
    leaf_domain: &[u8],
    node_domain: &'static [u8],
    group: usize,
    masks: &StreamingTraceMaskSetV1,
    opening_indices: &[usize],
    mut source: S,
) -> Result<StreamingRowCommitmentResultV1, AggregateStarkErrorV1>
where
    S: FnMut(usize) -> Result<Vec<F>, AggregateStarkErrorV1>,
{
    let native_rows = checked_domain_size_v1(masks.native_trace_log2)?;
    let lde_rows = checked_domain_size_v1(masks.lde_log2)?;
    let mut commitment = StreamingRowCommitmentV1::new(
        context,
        leaf_domain,
        node_domain,
        group,
        lde_rows,
        masks.width(),
        opening_indices,
    )?;
    for (column_index, mask) in masks.masks.iter().enumerate() {
        let native = ZeroizingFieldColumnV1(source(column_index)?);
        if native.len() != native_rows {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let lde = ZeroizingFieldColumnV1(
            masked_trace_lde_column_with_mask_v1(
                &native,
                masks.native_trace_log2,
                masks.lde_log2,
                mask.coefficients(),
            )
            .map_err(map_transparent_error_v1)?,
        );
        commitment.absorb_column(&lde)?;
    }
    commitment.finish()
}
/// Sample masks, commit their LDEs, and retain only the masked coefficients.
///
/// All verifier-derived shape checks and commitment allocations finish before
/// the witness source is called. The retained coefficient set is sufficient
/// to replay the exact commitment, evaluate smaller quotient cosets, and
/// construct DEEP openings without materializing anonymous common-domain
/// scratch.
#[cfg(test)]
pub fn commit_masked_trace_polynomial_columns_v1<R, S>(
    context: TransparentStarkDigestContextV1,
    leaf_domain: &[u8],
    node_domain: &'static [u8],
    group: usize,
    native_trace_log2: u8,
    commitment_lde_log2: u8,
    width: usize,
    mask_degree: usize,
    opening_indices: &[usize],
    rng: &mut R,
    source: S,
) -> Result<(StreamingRowCommitmentResultV1, MaskedTracePolynomialSetV1), AggregateStarkErrorV1>
where
    R: TryRngCore,
    S: FnMut(usize) -> Result<Vec<F>, AggregateStarkErrorV1>,
{
    let (_, commitment_rows) = validate_masked_trace_commitment_shape_v1(
        leaf_domain,
        node_domain,
        group,
        native_trace_log2,
        commitment_lde_log2,
        width,
        mask_degree,
        opening_indices,
    )?;
    let mut commitment = StreamingRowCommitmentV1::new(
        context,
        leaf_domain,
        node_domain,
        group,
        commitment_rows,
        width,
        opening_indices,
    )?;
    let polynomials = MaskedTracePolynomialSetV1::sample_columns_v1(
        native_trace_log2,
        commitment_lde_log2,
        width,
        mask_degree,
        rng,
        source,
    )?;
    // The profile's eight-column batch is a memory ceiling as well as a
    // throughput choice. Coefficients and masks are sampled serially above,
    // preserving the byte-exact transcript, while independent LDEs within
    // each bounded batch may use the active Rayon pool. No pool setting can
    // make more than eight transforms resident, and roots are still absorbed
    // in canonical column order.
    for batch in polynomials.columns.chunks(MASKED_TRACE_LDE_COLUMN_BATCH_V1) {
        let evaluations = batch
            .par_iter()
            .map(|coefficients| {
                masked_trace_coefficients_on_coset_v1(
                    coefficients,
                    native_trace_log2,
                    commitment_lde_log2,
                )
                .map(ZeroizingFieldColumnV1)
                .map_err(map_transparent_error_v1)
            })
            .collect::<Result<Vec<_>, _>>()?;
        commitment.absorb_columns_v1(&evaluations)?;
    }
    Ok((commitment.finish()?, polynomials))
}
/// Replay a retained masked-polynomial commitment and requested row frontier.
///
/// No native witness source or mask RNG is needed: the exact committed
/// polynomials, including canonical trailing zero coefficients, are owned by
/// `polynomials`.
#[cfg(test)]
pub fn replay_masked_trace_polynomial_columns_v1(
    context: TransparentStarkDigestContextV1,
    leaf_domain: &[u8],
    node_domain: &'static [u8],
    group: usize,
    polynomials: &MaskedTracePolynomialSetV1,
    opening_indices: &[usize],
) -> Result<StreamingRowCommitmentResultV1, AggregateStarkErrorV1> {
    let (_, commitment_rows) = polynomials.validate_v1()?;
    let mut commitment = StreamingRowCommitmentV1::new(
        context,
        leaf_domain,
        node_domain,
        group,
        commitment_rows,
        polynomials.width(),
        opening_indices,
    )?;
    for batch_start in (0..polynomials.width()).step_by(MASKED_TRACE_LDE_COLUMN_BATCH_V1) {
        let batch_end = batch_start
            .checked_add(MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .map_or(polynomials.width(), |end| end.min(polynomials.width()));
        let evaluations = (batch_start..batch_end)
            .into_par_iter()
            .map(|column| {
                polynomials.evaluate_column_on_coset_v1(column, polynomials.commitment_lde_log2)
            })
            .collect::<Result<Vec<_>, _>>()?;
        commitment.absorb_columns_v1(&evaluations)?;
    }
    commitment.finish()
}
/// Commit one aggregate composition lane.
pub fn composition_tree_v1(
    domains: &AggregateStarkDomainsV1,
    lane: usize,
    chunks: &[Vec<E>],
) -> Result<PrivacyOuterMerkleTreeV1, AggregateStarkErrorV1> {
    domains.validate()?;
    let rows = chunks
        .first()
        .map(Vec::len)
        .filter(|rows| *rows != 0 && rows.is_power_of_two())
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    if chunks.iter().any(|chunk| chunk.len() != rows) {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let width = u16::try_from(chunks.len())
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let payload_bytes = chunks
        .len()
        .checked_mul(32)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    commit_serialized_rows_v1(
        domains.digest_context,
        domains.composition_leaf,
        domains.composition_node,
        b"composition-vector-leaf",
        0,
        u64::from(u16::from_be_bytes(lane)),
        &[&lane, &width],
        rows,
        payload_bytes,
        |row, bytes| {
            for chunk in chunks {
                bytes.extend_from_slice(&chunk[row].to_be_bytes());
            }
        },
    )
}
/// Commit one aggregate composition lane without retaining a Merkle tree.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn streaming_composition_commitment_v1(
    domains: &AggregateStarkDomainsV1,
    lane: usize,
    chunks: &[Vec<E>],
    opening_indices: &[usize],
) -> Result<StreamingMerkleCommitmentV1, AggregateStarkErrorV1> {
    domains.validate()?;
    let rows = chunks
        .first()
        .map(Vec::len)
        .filter(|rows| *rows != 0 && rows.is_power_of_two())
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    if chunks.iter().any(|chunk| chunk.len() != rows) {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    streaming_merkle_commitment_v1(
        domains.digest_context,
        domains.composition_node,
        rows,
        opening_indices,
        (0..rows).map(|index| {
            let values = chunks.iter().map(|chunk| chunk[index]).collect::<Vec<_>>();
            composition_leaf_hash_unchecked_v1(domains, lane, index, &values)
        }),
    )
}
fn composition_chunks_from_coefficients_v1(
    coefficients: &[E],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<Vec<E>>, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let lde_size = layout.common_lde_size();
    if coefficients
        .iter()
        .any(|coefficient| !coefficient.is_canonical())
    {
        return Err(AggregateStarkErrorV1::NonCanonicalField);
    }
    let root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).map_err(map_transparent_error_v1)?;
    let chunk_size = layout.fri_degree_cap(parameters)?;
    let mut chunks = ZeroizingExtensionFieldMatrixV1(Vec::new());
    chunks
        .try_reserve_exact(parameters.composition_degree_chunks)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for chunk in 0..parameters.composition_degree_chunks {
        let start = chunk
            .checked_mul(chunk_size)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let coefficient_chunk = if start >= coefficients.len() {
            &[]
        } else {
            let end = start
                .checked_add(chunk_size)
                .map(|end| end.min(coefficients.len()))
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
            coefficients
                .get(start..end)
                .ok_or(AggregateStarkErrorV1::InternalInvariant)?
        };
        chunks.push(
            goldilocks_fp4_evaluate_coset_v1(
                coefficient_chunk,
                lde_size,
                root,
                F(GOLDILOCKS_GENERATOR_V1),
            )
            .map_err(map_transparent_error_v1)?,
        );
    }
    Ok(chunks.into_vec_v1())
}
/// Split one common-domain quotient codeword into canonical FRI chunks.
pub fn split_composition_evaluations_v1(
    evaluations: &[E],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<Vec<E>>, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let lde_size = layout.common_lde_size();
    if evaluations.len() != lde_size {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let coefficients = fp4_coset_coefficients_v1(evaluations, layout.common_lde_log2)?;
    let covered_coefficients = layout
        .fri_degree_cap(parameters)?
        .checked_mul(parameters.composition_degree_chunks)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    if coefficients
        .0
        .get(covered_coefficients..)
        .is_some_and(|high| high.iter().any(|coefficient| *coefficient != E::ZERO))
    {
        return Err(AggregateStarkErrorV1::FriDegree);
    }
    composition_chunks_from_coefficients_v1(&coefficients, parameters, layout)
}
/// Divide extension coefficients exactly by the trace vanishing polynomial.
///
/// Synthetic division is performed by the monic polynomial `X^n - 1`. The
/// complete remainder is checked to be zero before the quotient is returned;
/// a numerator that is only pointwise divisible on some evaluation set is
/// therefore rejected.
#[cfg(test)]
pub fn divide_extension_polynomial_by_trace_vanishing_v1(
    numerator_coefficients: &[E],
    trace_log2: u8,
) -> Result<Vec<E>, AggregateStarkErrorV1> {
    let trace_size = checked_domain_size_v1(trace_log2)?;
    if numerator_coefficients.len() <= trace_size {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    if numerator_coefficients
        .iter()
        .any(|coefficient| !coefficient.is_canonical())
    {
        return Err(AggregateStarkErrorV1::NonCanonicalField);
    }
    let quotient_len = numerator_coefficients
        .len()
        .checked_sub(trace_size)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let mut work = ZeroizingExtensionFieldColumnV1(Vec::new());
    work.0
        .try_reserve_exact(numerator_coefficients.len())
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    work.0.extend_from_slice(numerator_coefficients);
    let mut quotient = ZeroizingExtensionFieldColumnV1(Vec::new());
    quotient
        .0
        .try_reserve_exact(quotient_len)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    quotient.0.resize(quotient_len, E::ZERO);
    for degree in (trace_size..work.len()).rev() {
        let factor = work[degree];
        let quotient_degree = degree
            .checked_sub(trace_size)
            .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
        quotient.0[quotient_degree] = factor;
        work.0[degree] = E::ZERO;
        let remainder_coefficient = work[quotient_degree].add(factor);
        work.0[quotient_degree] = remainder_coefficient;
    }
    if work.iter().any(|coefficient| *coefficient != E::ZERO) {
        return Err(AggregateStarkErrorV1::ConstraintOpening);
    }
    Ok(core::mem::take(&mut quotient.0))
}
/// Inverses of `X^n - 1` over one period of a shifted power-of-two coset.
///
/// For `x_i = shift * root^i`, `x_i^n` repeats every `coset_size / n` rows.
/// Reject malformed geometry and shifts in either evaluation subgroup before
/// allocation; one shared batch inversion then serves every repeated period.
pub fn trace_vanishing_inverse_period_v1(
    trace_log2: u8,
    coset_log2: u8,
    shift: F,
) -> Result<Vec<F>, AggregateStarkErrorV1> {
    let trace_size = checked_domain_size_v1(trace_log2)?;
    let coset_size = checked_domain_size_v1(coset_log2)?;
    if trace_size >= coset_size || shift == F::ZERO {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    if F::canonical(shift.0).is_none() {
        return Err(AggregateStarkErrorV1::NonCanonicalField);
    }
    let root = goldilocks_primitive_root_v1(coset_log2)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?;
    let shift_to_trace_size = shift.pow(trace_size as u128);
    if shift_to_trace_size == F::ONE || shift.pow(coset_size as u128) == F::ONE {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let period = coset_size
        .checked_div(trace_size)
        .filter(|period| *period != 0)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let step = root.pow(trace_size as u128);
    let mut inverses = Vec::new();
    inverses
        .try_reserve_exact(period)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    let mut point_to_trace_size = shift_to_trace_size;
    for _ in 0..period {
        inverses.push(point_to_trace_size.sub(F::ONE));
        point_to_trace_size = point_to_trace_size.mul(step);
    }
    goldilocks_batch_invert_v1(&mut inverses).map_err(map_transparent_error_v1)?;
    Ok(inverses)
}
/// Divide a constraint-numerator codeword by `X^n - 1` on a quotient coset.
///
/// The generator shift is checked to be disjoint from both the native trace
/// subgroup and the quotient evaluation subgroup. Only `Q / n` denominators
/// are materialized and batch-inverted because the vanishing values repeat
/// with that exact period. Every pointwise division is multiplied back as an
/// implementation invariant.
#[cfg(test)]
pub fn quotient_evaluations_from_constraint_coset_v1(
    numerator_evaluations: &[E],
    trace_log2: u8,
    quotient_coset_log2: u8,
) -> Result<Vec<E>, AggregateStarkErrorV1> {
    let trace_size = checked_domain_size_v1(trace_log2)?;
    let quotient_size = checked_domain_size_v1(quotient_coset_log2)?;
    if trace_size >= quotient_size || numerator_evaluations.len() != quotient_size {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    if numerator_evaluations
        .iter()
        .any(|evaluation| !evaluation.is_canonical())
    {
        return Err(AggregateStarkErrorV1::NonCanonicalField);
    }
    let shift = F(GOLDILOCKS_GENERATOR_V1);
    let inverses = trace_vanishing_inverse_period_v1(trace_log2, quotient_coset_log2, shift)?;
    let quotient_root = goldilocks_primitive_root_v1(quotient_coset_log2)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?;
    let mut point = shift;
    let mut quotient = Vec::new();
    quotient
        .try_reserve_exact(quotient_size)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for (index, numerator) in numerator_evaluations.iter().copied().enumerate() {
        let value = numerator.mul_base(inverses[index % inverses.len()]);
        // Independent scalar evaluation keeps the test-only multiply-back
        // invariant separate from the shared periodic-table construction.
        let denominator = point.pow(trace_size as u128).sub(F::ONE);
        if value.mul_base(denominator) != numerator {
            return Err(AggregateStarkErrorV1::InternalInvariant);
        }
        quotient.push(value);
        point = point.mul(quotient_root);
    }
    Ok(quotient)
}
/// Convert a minimal quotient-coset codeword into common-domain FRI chunks.
///
/// `maximum_quotient_degree` is the relation's exact inclusive `q_max`, not
/// the looser aggregate layout capacity. After interpolation, every
/// coefficient above that bound must be exactly zero. The canonical
/// coefficient chunks are then evaluated on the common commitment coset, so
/// the resulting proof wire remains independent of the prover's smaller
/// quotient domain.
#[cfg(test)]
pub fn composition_chunks_from_quotient_coset_v1(
    quotient_evaluations: &[E],
    quotient_coset_log2: u8,
    maximum_quotient_degree: usize,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<Vec<E>>, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let quotient_size = checked_domain_size_v1(quotient_coset_log2)?;
    if quotient_evaluations.len() != quotient_size
        || maximum_quotient_degree >= quotient_size
        || maximum_quotient_degree > layout.maximum_composition_degree(parameters)?
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    if quotient_evaluations
        .iter()
        .any(|evaluation| !evaluation.is_canonical())
    {
        return Err(AggregateStarkErrorV1::NonCanonicalField);
    }
    let coefficients = fp4_coset_coefficients_v1(quotient_evaluations, quotient_coset_log2)?;
    let first_forbidden = maximum_quotient_degree
        .checked_add(1)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    if coefficients
        .get(first_forbidden..)
        .is_some_and(|tail| tail.iter().any(|coefficient| *coefficient != E::ZERO))
    {
        return Err(AggregateStarkErrorV1::FriDegree);
    }
    composition_chunks_from_coefficients_v1(&coefficients, parameters, layout)
}
/// Divide one constraint coset and canonically chunk the exact quotient.
#[cfg(test)]
pub fn composition_chunks_from_constraint_coset_v1(
    numerator_evaluations: &[E],
    trace_log2: u8,
    quotient_coset_log2: u8,
    maximum_quotient_degree: usize,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<Vec<E>>, AggregateStarkErrorV1> {
    let quotient = ZeroizingExtensionFieldColumnV1(quotient_evaluations_from_constraint_coset_v1(
        numerator_evaluations,
        trace_log2,
        quotient_coset_log2,
    )?);
    composition_chunks_from_quotient_coset_v1(
        &quotient,
        quotient_coset_log2,
        maximum_quotient_degree,
        parameters,
        layout,
    )
}
/// Reconstruct one unsplit quotient value from its authenticated chunks.
pub fn recompose_composition_value_v1(
    chunks: &[E],
    x: F,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<E, AggregateStarkErrorV1> {
    if chunks.len() != parameters.composition_degree_chunks {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    let chunk_power = x.pow(layout.fri_degree_cap(parameters)? as u128);
    let mut power = F::ONE;
    let mut value = E::ZERO;
    for chunk in chunks {
        value = value.add(chunk.mul_base(power));
        power = power.mul(chunk_power);
    }
    Ok(value)
}
#[cfg(test)]
fn evaluate_base_coefficients_at_fp4_v1(coefficients: &[F], point: E) -> E {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(E::ZERO, |value, coefficient| {
            value.mul(point).add(E::from_base(coefficient))
        })
}
fn evaluate_fp4_coefficients_at_fp4_v1(coefficients: &[E], point: E) -> E {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(E::ZERO, |value, coefficient| {
            value.mul(point).add(coefficient)
        })
}
#[cfg(test)]
fn base_coset_coefficients_v1(
    evaluations: &[F],
    lde_log2: u8,
) -> Result<ZeroizingFieldColumnV1, AggregateStarkErrorV1> {
    if evaluations.len() != checked_domain_size_v1(lde_log2)? {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let root = goldilocks_primitive_root_v1(lde_log2).map_err(map_transparent_error_v1)?;
    let inverse_shift = F(GOLDILOCKS_GENERATOR_V1)
        .inv()
        .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
    let mut coefficients = ZeroizingFieldColumnV1(evaluations.to_vec());
    goldilocks_ifft_v1(&mut coefficients.0, root).map_err(map_transparent_error_v1)?;
    let mut inverse_shift_power = F::ONE;
    for coefficient in &mut coefficients.0 {
        *coefficient = coefficient.mul(inverse_shift_power);
        inverse_shift_power = inverse_shift_power.mul(inverse_shift);
    }
    Ok(coefficients)
}
fn fp4_coset_coefficients_v1(
    evaluations: &[E],
    lde_log2: u8,
) -> Result<ZeroizingExtensionFieldColumnV1, AggregateStarkErrorV1> {
    if evaluations.len() != checked_domain_size_v1(lde_log2)? {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let root = goldilocks_primitive_root_v1(lde_log2).map_err(map_transparent_error_v1)?;
    let inverse_shift = F(GOLDILOCKS_GENERATOR_V1)
        .inv()
        .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
    let mut coefficients = ZeroizingExtensionFieldColumnV1(evaluations.to_vec());
    goldilocks_fp4_ifft_v1(&mut coefficients.0, root).map_err(map_transparent_error_v1)?;
    let mut inverse_shift_power = F::ONE;
    for coefficient in &mut coefficients.0 {
        *coefficient = coefficient.mul_base(inverse_shift_power);
        inverse_shift_power = inverse_shift_power.mul(inverse_shift);
    }
    Ok(coefficients)
}
/// Evaluate one committed base-field coset codeword at arbitrary Fp4 points.
#[cfg(test)]
pub fn evaluate_base_coset_polynomial_at_fp4_points_v1(
    evaluations: &[F],
    lde_log2: u8,
    points: &[E],
) -> Result<Vec<E>, AggregateStarkErrorV1> {
    if points.is_empty() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let coefficients = base_coset_coefficients_v1(evaluations, lde_log2)?;
    Ok(points
        .iter()
        .copied()
        .map(|point| evaluate_base_coefficients_at_fp4_v1(&coefficients, point))
        .collect())
}
/// Evaluate one committed Fp4 coset codeword at an arbitrary Fp4 point.
pub fn evaluate_fp4_coset_polynomial_at_point_v1(
    evaluations: &[E],
    lde_log2: u8,
    point: E,
) -> Result<E, AggregateStarkErrorV1> {
    let coefficients = fp4_coset_coefficients_v1(evaluations, lde_log2)?;
    Ok(evaluate_fp4_coefficients_at_fp4_v1(&coefficients, point))
}
#[cfg(test)]
fn evaluate_masked_native_column_at_points_v1(
    native: &[F],
    native_trace_log2: u8,
    mask: &ReplayableTraceMaskV1,
    points: &[E],
) -> Result<Vec<E>, AggregateStarkErrorV1> {
    if native.len() != checked_domain_size_v1(native_trace_log2)? || points.is_empty() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let root = goldilocks_primitive_root_v1(native_trace_log2).map_err(map_transparent_error_v1)?;
    let mut coefficients = ZeroizingFieldColumnV1(native.to_vec());
    goldilocks_ifft_v1(&mut coefficients.0, root).map_err(map_transparent_error_v1)?;
    let trace_size = native.len();
    Ok(points
        .iter()
        .copied()
        .map(|point| {
            let trace = evaluate_base_coefficients_at_fp4_v1(&coefficients, point);
            let randomizer = evaluate_base_coefficients_at_fp4_v1(mask.coefficients(), point);
            trace.add(point.pow(trace_size as u128).sub(E::ONE).mul(randomizer))
        })
        .collect())
}
/// Evaluate all replayable masked-native columns at `z` and
/// `z * omega_H` without retaining their common-domain LDEs.
#[cfg(test)]
pub fn evaluate_masked_native_columns_at_deep_v1<S>(
    masks: &StreamingTraceMaskSetV1,
    point: E,
    mut source: S,
) -> Result<(Vec<E>, Vec<E>), AggregateStarkErrorV1>
where
    S: FnMut(usize) -> Result<Vec<F>, AggregateStarkErrorV1>,
{
    if masks.width() == 0 {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let next_root =
        goldilocks_primitive_root_v1(masks.native_trace_log2).map_err(map_transparent_error_v1)?;
    let next_point = point.mul_base(next_root);
    let mut current = Vec::new();
    let mut next = Vec::new();
    current
        .try_reserve_exact(masks.width())
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    next.try_reserve_exact(masks.width())
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for (column, mask) in masks.masks.iter().enumerate() {
        let native = ZeroizingFieldColumnV1(source(column)?);
        let values = evaluate_masked_native_column_at_points_v1(
            &native,
            masks.native_trace_log2,
            mask,
            &[point, next_point],
        )?;
        current.push(values[0]);
        next.push(values[1]);
    }
    Ok((current, next))
}
/// Evaluate every retained masked polynomial at `z` and `z * omega_H`.
///
/// The DEEP point must be canonical and outside the native trace subgroup.
/// Evaluation is direct from the retained coefficients, so neither the native
/// witness columns nor a commitment-domain codeword are reconstructed.
#[cfg(test)]
pub fn evaluate_masked_trace_polynomial_columns_at_deep_v1(
    polynomials: &MaskedTracePolynomialSetV1,
    point: E,
) -> Result<(Vec<E>, Vec<E>), AggregateStarkErrorV1> {
    let (native_rows, _) = polynomials.validate_v1()?;
    if !point.is_canonical() || fp4_is_in_trace_subgroup_v1(point, native_rows) {
        return Err(AggregateStarkErrorV1::DeepOpening);
    }
    let next_root = goldilocks_primitive_root_v1(polynomials.native_trace_log2)
        .map_err(map_transparent_error_v1)?;
    let next_point = point.mul_base(next_root);
    let mut current = Vec::new();
    let mut next = Vec::new();
    current
        .try_reserve_exact(polynomials.width())
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    next.try_reserve_exact(polynomials.width())
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for column in &polynomials.columns {
        current.push(evaluate_base_coefficients_at_fp4_v1(column, point));
        next.push(evaluate_base_coefficients_at_fp4_v1(column, next_point));
    }
    Ok((current, next))
}
/// Evaluate all composition chunks at the transcript-derived DEEP point.
pub fn evaluate_composition_chunks_at_deep_v1(
    compositions: &[Vec<Vec<E>>],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    point: E,
) -> Result<Vec<Vec<E>>, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    if compositions.len() != parameters.security_lanes
        || compositions.iter().any(|lane| {
            lane.len() != parameters.composition_degree_chunks
                || lane
                    .iter()
                    .any(|chunk| chunk.len() != layout.common_lde_size())
        })
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    compositions
        .iter()
        .map(|lane| {
            lane.iter()
                .map(|chunk| {
                    evaluate_fp4_coset_polynomial_at_point_v1(chunk, layout.common_lde_log2, point)
                })
                .collect()
        })
        .collect()
}
/// Build a DEEP payload from retained materialized common-domain codewords.
#[cfg(test)]
pub fn build_materialized_deep_proof_v1(
    trace_groups: &[AggregateTraceGroupMaterialV1],
    compositions: &[Vec<Vec<E>>],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    point: E,
) -> Result<AggregateDeepProofV1, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    if trace_groups.len() != layout.trace_groups.len() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let mut deep_groups = Vec::new();
    deep_groups
        .try_reserve_exact(trace_groups.len())
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for (material, descriptor) in trace_groups.iter().zip(&layout.trace_groups) {
        if material.base_lde.len() != descriptor.base_width
            || material.aux_lde.len() != descriptor.aux_width
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let root = goldilocks_primitive_root_v1(descriptor.native_trace_log2)
            .map_err(map_transparent_error_v1)?;
        let next_point = point.mul_base(root);
        let mut base_current = Vec::with_capacity(descriptor.base_width);
        let mut base_next = Vec::with_capacity(descriptor.base_width);
        let mut aux_current = Vec::with_capacity(descriptor.aux_width);
        let mut aux_next = Vec::with_capacity(descriptor.aux_width);
        for column in &material.base_lde {
            let values = evaluate_base_coset_polynomial_at_fp4_points_v1(
                column,
                layout.common_lde_log2,
                &[point, next_point],
            )?;
            base_current.push(values[0].coefficients().map(F::value));
            base_next.push(values[1].coefficients().map(F::value));
        }
        for column in &material.aux_lde {
            let values = evaluate_base_coset_polynomial_at_fp4_points_v1(
                column,
                layout.common_lde_log2,
                &[point, next_point],
            )?;
            aux_current.push(values[0].coefficients().map(F::value));
            aux_next.push(values[1].coefficients().map(F::value));
        }
        deep_groups.push(AggregateDeepTraceGroupOpeningV1 {
            base_current,
            base_next,
            aux_current,
            aux_next,
        });
    }
    let composition_values =
        evaluate_composition_chunks_at_deep_v1(compositions, parameters, layout, point)?
            .into_iter()
            .map(|lane| {
                lane.into_iter()
                    .map(|value| value.coefficients().map(F::value))
                    .collect()
            })
            .collect();
    let deep = AggregateDeepProofV1 {
        trace_groups: deep_groups,
        composition_values,
    };
    validate_deep_proof_shape_v1(&deep, parameters, layout)?;
    Ok(deep)
}
/// Batch-invert canonical nonzero Fp4 values using one extension-field
/// inversion.
///
/// DEEP code calls this on bounded row chunks so constructing quotient
/// codewords does not perform one expensive inversion per domain element or
/// allocate an evaluation-domain-sized prefix buffer.
pub fn batch_invert_fp4_nonzero_v1(values: &mut [E]) -> Result<(), AggregateStarkErrorV1> {
    if values.is_empty() {
        return Err(AggregateStarkErrorV1::DeepOpening);
    }
    let mut prefixes = Vec::new();
    prefixes
        .try_reserve_exact(values.len())
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    let mut product = E::ONE;
    for value in values.iter().copied() {
        if !value.is_canonical() || value == E::ZERO {
            return Err(AggregateStarkErrorV1::DeepOpening);
        }
        prefixes.push(product);
        product = product.mul(value);
    }
    let mut inverse = product.inv().ok_or(AggregateStarkErrorV1::DeepOpening)?;
    for index in (0..values.len()).rev() {
        let value = values[index];
        values[index] = inverse.mul(prefixes[index]);
        inverse = inverse.mul(value);
    }
    Ok(())
}
/// Validate verifier-derived DEEP batching dimensions.
pub fn validate_deep_lane_mixes_v1(
    mixes: &[AggregateDeepLaneMixV1],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<(), AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    if mixes.len() != parameters.security_lanes {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    for mix in mixes {
        if mix.trace_groups.len() != layout.trace_groups.len()
            || mix.composition.len() != parameters.composition_degree_chunks
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        for (group_mix, group) in mix.trace_groups.iter().zip(&layout.trace_groups) {
            if group_mix.base_current.len() != group.base_width
                || group_mix.base_next.len() != group.base_width
                || group_mix.aux_current.len() != group.aux_width
                || group_mix.aux_next.len() != group.aux_width
            {
                return Err(AggregateStarkErrorV1::InvalidLayout);
            }
        }
    }
    Ok(())
}
fn accumulate_fp4_deep_quotients_v1(
    mut accumulator: E,
    query: &[E],
    deep: &[E],
    coefficients: &[E],
    inverse_denominator: E,
) -> Result<E, AggregateStarkErrorV1> {
    if query.len() != deep.len() || query.len() != coefficients.len() {
        return Err(AggregateStarkErrorV1::DeepOpening);
    }
    for ((query, deep), coefficient) in query.iter().zip(deep).zip(coefficients) {
        accumulator = accumulator.add(query.sub(*deep).mul(inverse_denominator).mul(*coefficient));
    }
    Ok(accumulator)
}
fn accumulate_base_deep_quotients_v1(
    mut accumulator: E,
    query: &[F],
    deep: &[E],
    coefficients: &[E],
    inverse_denominator: E,
) -> Result<E, AggregateStarkErrorV1> {
    if query.len() != deep.len() || query.len() != coefficients.len() {
        return Err(AggregateStarkErrorV1::DeepOpening);
    }
    for ((query, deep), coefficient) in query.iter().zip(deep).zip(coefficients) {
        accumulator = accumulator.add(
            E::from_base(*query)
                .sub(*deep)
                .mul(inverse_denominator)
                .mul(*coefficient),
        );
    }
    Ok(accumulator)
}
/// Evaluate the complete batched DEEP-ALI quotient at one authenticated query
/// row.
pub fn deep_ali_mixed_opening_v1(
    query_point: E,
    deep_point: E,
    layout: &AggregateProofLayoutV1,
    trace_groups: &[AggregateOpenedTraceGroupV1],
    deep_trace_groups: &[AggregateOpenedDeepTraceGroupV1],
    composition_chunks: &[E],
    deep_composition_chunks: &[E],
    mix: &AggregateDeepLaneMixV1,
) -> Result<E, AggregateStarkErrorV1> {
    if trace_groups.len() != deep_trace_groups.len()
        || trace_groups.len() != mix.trace_groups.len()
        || composition_chunks.len() != deep_composition_chunks.len()
        || composition_chunks.len() != mix.composition.len()
    {
        return Err(AggregateStarkErrorV1::DeepOpening);
    }
    let current_inverse = query_point
        .sub(deep_point)
        .inv()
        .ok_or(AggregateStarkErrorV1::DeepOpening)?;
    let mut quotient = E::ZERO;
    for (group_index, ((query, deep), coefficients)) in trace_groups
        .iter()
        .zip(deep_trace_groups)
        .zip(&mix.trace_groups)
        .enumerate()
    {
        let group = layout
            .trace_groups
            .get(group_index)
            .ok_or(AggregateStarkErrorV1::DeepOpening)?;
        let next_root = goldilocks_primitive_root_v1(group.native_trace_log2)
            .map_err(map_transparent_error_v1)?;
        let next_inverse = query_point
            .sub(deep_point.mul_base(next_root))
            .inv()
            .ok_or(AggregateStarkErrorV1::DeepOpening)?;
        quotient = accumulate_base_deep_quotients_v1(
            quotient,
            &query.base_current,
            &deep.base_current,
            &coefficients.base_current,
            current_inverse,
        )?;
        quotient = accumulate_base_deep_quotients_v1(
            quotient,
            &query.base_current,
            &deep.base_next,
            &coefficients.base_next,
            next_inverse,
        )?;
        quotient = accumulate_base_deep_quotients_v1(
            quotient,
            &query.aux_current,
            &deep.aux_current,
            &coefficients.aux_current,
            current_inverse,
        )?;
        quotient = accumulate_base_deep_quotients_v1(
            quotient,
            &query.aux_current,
            &deep.aux_next,
            &coefficients.aux_next,
            next_inverse,
        )?;
    }
    quotient = accumulate_fp4_deep_quotients_v1(
        quotient,
        composition_chunks,
        deep_composition_chunks,
        &mix.composition,
        current_inverse,
    )?;
    Ok(quotient)
}
/// Commit one shared FRI layer.
pub fn fri_tree_v1(
    domains: &AggregateStarkDomainsV1,
    commitment_layout: AggregateFriCommitmentLayoutV1,
    lane: usize,
    round: usize,
    values: &[E],
) -> Result<PrivacyOuterMerkleTreeV1, AggregateStarkErrorV1> {
    domains.validate()?;
    let leaf_count = commitment_layout.leaf_count(values.len())?;
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let round = u16::try_from(round)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    commit_serialized_rows_v1(
        domains.digest_context,
        domains.fri_leaf,
        domains.fri_node,
        match commitment_layout {
            AggregateFriCommitmentLayoutV1::Scalar => b"fri-layer-leaf",
            AggregateFriCommitmentLayoutV1::Paired => b"fri-layer-pair-leaf",
        },
        u64::from(u16::from_be_bytes(round)),
        u64::from(u16::from_be_bytes(lane)),
        &[&lane, &round],
        leaf_count,
        match commitment_layout {
            AggregateFriCommitmentLayoutV1::Scalar => 32,
            AggregateFriCommitmentLayoutV1::Paired => 64,
        },
        |row, bytes| {
            bytes.extend_from_slice(&values[row].to_be_bytes());
            if commitment_layout == AggregateFriCommitmentLayoutV1::Paired {
                bytes.extend_from_slice(&values[row + leaf_count].to_be_bytes());
            }
        },
    )
}
/// Commit one FRI layer without retaining a Merkle tree.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn streaming_fri_commitment_v1(
    domains: &AggregateStarkDomainsV1,
    commitment_layout: AggregateFriCommitmentLayoutV1,
    lane: usize,
    round: usize,
    values: &[E],
    opening_indices: &[usize],
) -> Result<StreamingMerkleCommitmentV1, AggregateStarkErrorV1> {
    domains.validate()?;
    let leaf_count = commitment_layout.leaf_count(values.len())?;
    streaming_merkle_commitment_v1(
        domains.digest_context,
        domains.fri_node,
        leaf_count,
        opening_indices,
        (0..leaf_count).map(|index| match commitment_layout {
            AggregateFriCommitmentLayoutV1::Scalar => {
                fri_leaf_hash_unchecked_v1(domains, lane, round, index, values[index])
            }
            AggregateFriCommitmentLayoutV1::Paired => fri_pair_leaf_hash_v1(
                domains,
                lane,
                round,
                index,
                values[index],
                values[index + leaf_count],
            ),
        }),
    )
}
/// Absorb the complete relation domain and ordered group layout before roots.
pub fn absorb_layout_v1(
    transcript: &mut TransparentTranscriptV1,
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    relation_layout_domain: &[u8],
    layout: &AggregateProofLayoutV1,
) -> Result<(), AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    ensure_transcript_context_v1(transcript, domains)?;
    if relation_layout_domain.is_empty() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let mut encoding = Vec::new();
    encoding.extend_from_slice(relation_layout_domain);
    if parameters.fri_commitment_layout == AggregateFriCommitmentLayoutV1::Paired {
        encoding.extend_from_slice(b":fri-ordered-low-high-pair-leaves:v1");
    }
    match layout.trace_layout {
        AggregateTraceLayoutV1::GroupedCurrentNext => {}
        AggregateTraceLayoutV1::GroupedCurrent => {
            encoding.extend_from_slice(b":trace-grouped-current-only:v1")
        }
        AggregateTraceLayoutV1::JoinedCurrent => {
            encoding.extend_from_slice(b":trace-joined-current-only:v1")
        }
    }
    encoding.push(layout.common_lde_log2);
    append_u16_v1(
        &mut encoding,
        u16::try_from(parameters.composition_degree_chunks)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
    );
    append_u16_v1(
        &mut encoding,
        u16::try_from(layout.trace_groups.len())
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
    );
    for group in &layout.trace_groups {
        encoding.push(group.native_trace_log2);
        append_u16_v1(
            &mut encoding,
            u16::try_from(group.segment_instances)
                .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        );
        append_u32_v1(
            &mut encoding,
            u32::try_from(group.base_width).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        );
        append_u32_v1(
            &mut encoding,
            u32::try_from(group.aux_width).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        );
        append_u32_v1(
            &mut encoding,
            u32::try_from(group.next_stride(layout.common_lde_log2)?)
                .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        );
    }
    transcript
        .absorb(domains.layout_label, &[&encoding])
        .map_err(map_transparent_error_v1)
}
/// Absorb all ordered base roots before any relation auxiliary challenge.
pub fn absorb_base_roots_v1(
    transcript: &mut TransparentTranscriptV1,
    domains: &AggregateStarkDomainsV1,
    groups: &[AggregateTraceGroupProofV1],
) -> Result<(), AggregateStarkErrorV1> {
    ensure_transcript_context_v1(transcript, domains)?;
    absorb_group_roots_v1(transcript, domains.base_root_label, groups, true)
}
/// Absorb all ordered auxiliary roots before constraint-composition challenges.
pub fn absorb_aux_roots_v1(
    transcript: &mut TransparentTranscriptV1,
    domains: &AggregateStarkDomainsV1,
    groups: &[AggregateTraceGroupProofV1],
) -> Result<(), AggregateStarkErrorV1> {
    ensure_transcript_context_v1(transcript, domains)?;
    absorb_group_roots_v1(transcript, domains.aux_root_label, groups, false)
}
fn absorb_group_roots_v1(
    transcript: &mut TransparentTranscriptV1,
    label: &[u8],
    groups: &[AggregateTraceGroupProofV1],
    base: bool,
) -> Result<(), AggregateStarkErrorV1> {
    if groups.is_empty() || label.is_empty() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    for (group, proof) in groups.iter().enumerate() {
        let group = u16::try_from(group)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
            .to_be_bytes();
        let root = if base {
            proof.base_root
        } else {
            proof.aux_root
        };
        let root = root.to_bytes();
        transcript
            .absorb(label, &[&group, &root])
            .map_err(map_transparent_error_v1)?;
    }
    Ok(())
}
/// Absorb all aggregate composition roots in fixed lane order.
pub fn absorb_composition_roots_v1(
    transcript: &mut TransparentTranscriptV1,
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    roots: &[PrivacyOuterDigestV1],
) -> Result<(), AggregateStarkErrorV1> {
    parameters.validate()?;
    ensure_transcript_context_v1(transcript, domains)?;
    if roots.len() != parameters.security_lanes {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    for (lane, root) in roots.iter().enumerate() {
        let lane = u16::try_from(lane)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
            .to_be_bytes();
        let root = root.to_bytes();
        transcript
            .absorb(domains.composition_root_label, &[&lane, &root])
            .map_err(map_transparent_error_v1)?;
    }
    Ok(())
}
/// Bind all independently committed FRI-mask roots before batching challenges.
pub fn absorb_fri_mask_roots_v1(
    transcript: &mut TransparentTranscriptV1,
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    roots: &[PrivacyOuterDigestV1],
) -> Result<(), AggregateStarkErrorV1> {
    parameters.validate()?;
    ensure_transcript_context_v1(transcript, domains)?;
    if roots.len() != parameters.security_lanes {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    for (lane, root) in roots.iter().enumerate() {
        let lane = u16::try_from(lane)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
            .to_be_bytes();
        let root = root.to_bytes();
        transcript
            .absorb(FRI_MASK_ROOT_LABEL_V1, &[&lane, &root])
            .map_err(map_transparent_error_v1)?;
    }
    Ok(())
}
/// Absorb one FRI root in fixed lane/round order.
pub fn absorb_fri_root_v1(
    transcript: &mut TransparentTranscriptV1,
    domains: &AggregateStarkDomainsV1,
    lane: usize,
    round: usize,
    root: &PrivacyOuterDigestV1,
) -> Result<(), AggregateStarkErrorV1> {
    ensure_transcript_context_v1(transcript, domains)?;
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let round = u16::try_from(round)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let root = root.to_bytes();
    transcript
        .absorb(domains.fri_root_label, &[&lane, &round, &root])
        .map_err(map_transparent_error_v1)
}
/// Derive the shared unique query positions from the post-grinding transcript.
pub fn query_indices_v1(
    transcript: &TransparentTranscriptV1,
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<usize>, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    ensure_transcript_context_v1(transcript, domains)?;
    let seed = privacy_outer_digest_frame_v1(
        domains.digest_context,
        domains.query_seed,
        b"post-grinding-query-seed",
        0,
        u64::from(layout.common_lde_log2),
        0,
        &[&transcript.state().to_bytes()],
    )
    .map_err(map_transparent_error_v1)?;
    derive_unique_query_indices_v1(
        domains.digest_context,
        &seed,
        layout.common_lde_size(),
        parameters.query_count,
    )
    .map_err(map_transparent_error_v1)
}
fn validate_canonical_index_set_v1(
    leaf_count: usize,
    indices: &[usize],
) -> Result<(), AggregateStarkErrorV1> {
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || indices.is_empty()
        || indices.iter().any(|index| *index >= leaf_count)
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    Ok(())
}
/// Derive the sorted current/next leaf set for one trace group.
pub fn trace_group_opening_indices_v1(
    queries: &[AggregateQueryProofV1],
    layout: &AggregateProofLayoutV1,
    group: usize,
) -> Result<Vec<usize>, AggregateStarkErrorV1> {
    if group >= layout.trace_commitment_count_v1() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    if layout.trace_layout != AggregateTraceLayoutV1::GroupedCurrentNext {
        return composition_opening_indices_v1(queries, layout);
    }
    let group = *layout
        .trace_groups
        .get(group)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let next_stride = group.next_stride(layout.common_lde_log2)?;
    let mut indices = BTreeSet::new();
    for query in queries {
        let current =
            usize::try_from(query.index).map_err(|_| AggregateStarkErrorV1::InvalidProofShape)?;
        if current >= layout.common_lde_size() {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        indices.insert(current);
        indices.insert((current + next_stride) % layout.common_lde_size());
    }
    Ok(indices.into_iter().collect())
}
/// Derive the sorted unique aggregate-composition leaf set.
pub fn composition_opening_indices_v1(
    queries: &[AggregateQueryProofV1],
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<usize>, AggregateStarkErrorV1> {
    let mut indices = BTreeSet::new();
    for query in queries {
        let index =
            usize::try_from(query.index).map_err(|_| AggregateStarkErrorV1::InvalidProofShape)?;
        if index >= layout.common_lde_size() || !indices.insert(index) {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
    }
    Ok(indices.into_iter().collect())
}
/// Derive the sorted low/high leaf set for one shared FRI round.
pub fn fri_opening_indices_v1(
    queries: &[AggregateQueryProofV1],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    round: usize,
) -> Result<Vec<usize>, AggregateStarkErrorV1> {
    if round >= layout.fri_rounds(parameters)? {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    let layer_size = layout.common_lde_size() >> round;
    let half = layer_size / 2;
    let mut indices = BTreeSet::new();
    for query in queries {
        let query_index =
            usize::try_from(query.index).map_err(|_| AggregateStarkErrorV1::InvalidProofShape)?;
        if query_index >= layout.common_lde_size() {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        let low = query_index % half;
        indices.insert(low);
        if parameters.fri_commitment_layout == AggregateFriCommitmentLayoutV1::Scalar {
            indices.insert(low + half);
        }
    }
    Ok(indices.into_iter().collect())
}
/// Exact number of hashes in the unique canonical minimal frontier.
pub fn multiproof_frontier_len_v1(
    leaf_count: usize,
    indices: &[usize],
) -> Result<usize, AggregateStarkErrorV1> {
    validate_canonical_index_set_v1(leaf_count, indices)?;
    let mut current = indices.iter().copied().collect::<BTreeSet<_>>();
    let mut frontier_len = 0_usize;
    let mut level_size = leaf_count;
    while level_size > 1 {
        for index in &current {
            if !current.contains(&(index ^ 1)) {
                frontier_len = frontier_len
                    .checked_add(1)
                    .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
            }
        }
        current = current.into_iter().map(|index| index >> 1).collect();
        level_size >>= 1;
    }
    Ok(frontier_len)
}
/// Construct the unique sorted minimal batched Merkle frontier.
pub fn canonical_multiproof_frontier_v1(
    tree: &PrivacyOuterMerkleTreeV1,
    leaf_count: usize,
    indices: &[usize],
) -> Result<Vec<PrivacyOuterDigestV1>, AggregateStarkErrorV1> {
    validate_canonical_index_set_v1(leaf_count, indices)?;
    let expected_len = multiproof_frontier_len_v1(leaf_count, indices)?;
    let mut frontier = Vec::new();
    frontier
        .try_reserve_exact(expected_len)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    let mut current = indices
        .iter()
        .copied()
        .map(|index| (index, index))
        .collect::<BTreeMap<_, _>>();
    let mut level_size = leaf_count;
    let mut level = 0_usize;
    while level_size > 1 {
        let mut parents = BTreeMap::new();
        for (&index, &representative_leaf) in &current {
            if !current.contains_key(&(index ^ 1)) {
                let path = tree
                    .path(representative_leaf)
                    .map_err(map_transparent_error_v1)?;
                frontier.push(
                    *path
                        .get(level)
                        .ok_or(AggregateStarkErrorV1::InternalInvariant)?,
                );
            }
            parents.entry(index >> 1).or_insert(representative_leaf);
        }
        current = parents;
        level_size >>= 1;
        level += 1;
    }
    if frontier.len() != expected_len || current.len() != 1 || !current.contains_key(&0) {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    Ok(frontier)
}
/// Verify one exact canonical minimal batched Merkle multiproof.
pub fn verify_canonical_multiproof_v1(
    context: TransparentStarkDigestContextV1,
    node_role: &[u8],
    root: &PrivacyOuterDigestV1,
    leaf_count: usize,
    leaves: &BTreeMap<usize, PrivacyOuterDigestV1>,
    frontier: &[PrivacyOuterDigestV1],
) -> Result<(), AggregateStarkErrorV1> {
    context.validate().map_err(map_transparent_error_v1)?;
    if node_role.is_empty() || u16::try_from(node_role.len()).is_err() {
        return Err(AggregateStarkErrorV1::TraceOpening);
    }
    let indices = leaves.keys().copied().collect::<Vec<_>>();
    validate_canonical_index_set_v1(leaf_count, &indices)?;
    if multiproof_frontier_len_v1(leaf_count, &indices)? != frontier.len() {
        return Err(AggregateStarkErrorV1::TraceOpening);
    }
    let mut current = leaves.clone();
    let mut cursor = 0_usize;
    let mut level_size = leaf_count;
    let mut level = 0_usize;
    while level_size > 1 {
        let mut parents = BTreeMap::new();
        let mut consumed = BTreeSet::new();
        for (&index, &node) in &current {
            if consumed.contains(&index) {
                continue;
            }
            let sibling_index = index ^ 1;
            let sibling = if let Some(sibling) = current.get(&sibling_index) {
                consumed.insert(sibling_index);
                *sibling
            } else {
                let sibling = *frontier
                    .get(cursor)
                    .ok_or(AggregateStarkErrorV1::TraceOpening)?;
                cursor += 1;
                sibling
            };
            consumed.insert(index);
            let parent_index = index >> 1;
            let parent = if index & 1 == 0 {
                privacy_outer_merkle_node_v1(
                    context,
                    node_role,
                    u64::try_from(level + 1).map_err(|_| AggregateStarkErrorV1::TraceOpening)?,
                    u64::try_from(parent_index).map_err(|_| AggregateStarkErrorV1::TraceOpening)?,
                    node,
                    sibling,
                )
            } else {
                privacy_outer_merkle_node_v1(
                    context,
                    node_role,
                    u64::try_from(level + 1).map_err(|_| AggregateStarkErrorV1::TraceOpening)?,
                    u64::try_from(parent_index).map_err(|_| AggregateStarkErrorV1::TraceOpening)?,
                    sibling,
                    node,
                )
            }
            .map_err(map_transparent_error_v1)?;
            if parents.insert(parent_index, parent).is_some() {
                return Err(AggregateStarkErrorV1::TraceOpening);
            }
        }
        current = parents;
        level_size >>= 1;
        level += 1;
    }
    if cursor != frontier.len() || current.len() != 1 || current.get(&0).copied() != Some(*root) {
        return Err(AggregateStarkErrorV1::TraceOpening);
    }
    Ok(())
}
fn insert_opened_leaf_v1(
    leaves: &mut BTreeMap<usize, PrivacyOuterDigestV1>,
    index: usize,
    leaf: PrivacyOuterDigestV1,
) -> Result<(), AggregateStarkErrorV1> {
    if leaves
        .insert(index, leaf)
        .is_some_and(|previous| previous != leaf)
    {
        return Err(AggregateStarkErrorV1::TraceOpening);
    }
    Ok(())
}
/// Exact worst-case minimal-frontier length for at most `maximum_opened_leaves`.
pub fn maximum_multiproof_frontier_len_v1(
    leaf_count: usize,
    maximum_opened_leaves: usize,
) -> Result<usize, AggregateStarkErrorV1> {
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || maximum_opened_leaves == 0
        || maximum_opened_leaves > leaf_count
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let height =
        usize::try_from(leaf_count.ilog2()).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?;
    let mut previous = vec![None; maximum_opened_leaves + 1];
    previous[1] = Some(0_usize);
    let mut maximum = 0_usize;
    for current_height in 1..=height {
        let half_capacity = 1_usize
            .checked_shl(
                u32::try_from(current_height - 1)
                    .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
            )
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let capacity = half_capacity
            .checked_mul(2)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let row_limit = maximum_opened_leaves.min(capacity);
        let mut current = vec![None; maximum_opened_leaves + 1];
        let mut row_maximum = 0_usize;
        for opened in 1..=row_limit {
            let minimum_left = opened.saturating_sub(half_capacity);
            let maximum_left = opened.min(half_capacity);
            let mut best = None;
            for left in minimum_left..=maximum_left {
                let right = opened - left;
                let candidate = match (left, right) {
                    (0, right) => previous
                        .get(right)
                        .and_then(|value| *value)
                        .and_then(|value| value.checked_add(1)),
                    (left, 0) => previous
                        .get(left)
                        .and_then(|value| *value)
                        .and_then(|value| value.checked_add(1)),
                    (left, right) => previous
                        .get(left)
                        .and_then(|value| *value)
                        .zip(previous.get(right).and_then(|value| *value))
                        .and_then(|(left, right)| left.checked_add(right)),
                };
                if let Some(candidate) = candidate {
                    best = Some(best.map_or(candidate, |prior: usize| prior.max(candidate)));
                }
            }
            current[opened] = best;
            row_maximum = row_maximum.max(best.ok_or(AggregateStarkErrorV1::InternalInvariant)?);
        }
        previous = current;
        maximum = row_maximum;
    }
    Ok(maximum)
}
/// Validate the entire statement-derived proof shape and canonical frontier sizes.
pub fn validate_proof_shape_v1(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<(), AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    if proof.version != parameters.proof_version
        || proof.trace_groups.len() != layout.trace_commitment_count_v1()
        || proof.composition_roots.len() != parameters.security_lanes
        || proof.composition_frontiers.len() != parameters.security_lanes
        || proof.fri_mask_roots.len() != parameters.security_lanes
        || proof.fri_mask_frontiers.len() != parameters.security_lanes
        || proof.fri_lanes.len() != parameters.security_lanes
        || proof.queries.len() != parameters.query_count
    {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    let fri_rounds = layout.fri_rounds(parameters)?;
    for query in &proof.queries {
        if query.trace_groups.len() != layout.trace_groups.len()
            || query.composition_values.len() != parameters.security_lanes
            || query
                .composition_values
                .iter()
                .any(|chunks| chunks.len() != parameters.composition_degree_chunks)
            || query.fri_mask_values.len() != parameters.security_lanes
            || query.fri_lanes.len() != parameters.security_lanes
            || query
                .fri_lanes
                .iter()
                .any(|lane| lane.rounds.len() != fri_rounds)
        {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        for (opening, group) in query.trace_groups.iter().zip(&layout.trace_groups) {
            if opening.base_current.len() != group.base_width
                || opening.base_next.len() != layout.trace_layout.next_width_v1(group.base_width)
                || opening.aux_current.len() != group.aux_width
                || opening.aux_next.len() != layout.trace_layout.next_width_v1(group.aux_width)
            {
                return Err(AggregateStarkErrorV1::InvalidProofShape);
            }
            ensure_canonical_base_fields_v1(&opening.base_current)?;
            ensure_canonical_base_fields_v1(&opening.base_next)?;
            ensure_canonical_base_fields_v1(&opening.aux_current)?;
            ensure_canonical_base_fields_v1(&opening.aux_next)?;
        }
        for values in &query.composition_values {
            ensure_canonical_fp4_fields_v1(values)?;
        }
        ensure_canonical_fp4_fields_v1(&query.fri_mask_values)?;
        for lane in &query.fri_lanes {
            for opening in &lane.rounds {
                ensure_canonical_fp4_fields_v1(core::slice::from_ref(&opening.low))?;
                ensure_canonical_fp4_fields_v1(core::slice::from_ref(&opening.high))?;
            }
        }
    }
    for (group_index, group_proof) in proof.trace_groups.iter().enumerate() {
        let trace_indices = trace_group_opening_indices_v1(&proof.queries, layout, group_index)?;
        let expected = multiproof_frontier_len_v1(layout.common_lde_size(), &trace_indices)?;
        if group_proof.base_frontier.len() != expected || group_proof.aux_frontier.len() != expected
        {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
    }
    let composition_indices = composition_opening_indices_v1(&proof.queries, layout)?;
    let composition_expected =
        multiproof_frontier_len_v1(layout.common_lde_size(), &composition_indices)?;
    if proof
        .composition_frontiers
        .iter()
        .any(|frontier| frontier.len() != composition_expected)
        || proof
            .fri_mask_frontiers
            .iter()
            .any(|frontier| frontier.len() != composition_expected)
    {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    for lane in &proof.fri_lanes {
        if lane.roots.len() != fri_rounds + 1
            || lane.terminal_values.len() != parameters.terminal_size()?
            || lane.round_frontiers.len() != fri_rounds
        {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        ensure_canonical_fp4_fields_v1(&lane.terminal_values)?;
        for (round, frontier) in lane.round_frontiers.iter().enumerate() {
            let indices = fri_opening_indices_v1(&proof.queries, parameters, layout, round)?;
            let expected = multiproof_frontier_len_v1(
                parameters
                    .fri_commitment_layout
                    .leaf_count(layout.common_lde_size() >> round)?,
                &indices,
            )?;
            if frontier.len() != expected {
                return Err(AggregateStarkErrorV1::InvalidProofShape);
            }
        }
    }
    Ok(())
}
fn append_hash_v1(bytes: &mut Vec<u8>, hash: &PrivacyOuterDigestV1) {
    bytes.extend_from_slice(&hash.to_bytes());
}
fn append_hashes_v1(bytes: &mut Vec<u8>, hashes: &[PrivacyOuterDigestV1]) {
    for hash in hashes {
        append_hash_v1(bytes, hash);
    }
}
fn append_base_fields_v1(bytes: &mut Vec<u8>, fields: &[u64]) {
    for field in fields {
        append_u64_v1(bytes, *field);
    }
}
fn append_fp4_fields_v1(bytes: &mut Vec<u8>, fields: &[[u64; 4]]) {
    for field in fields {
        for coefficient in field {
            append_u64_v1(bytes, *coefficient);
        }
    }
}
/// Exact byte count of the statement-shaped DEEP opening payload.
pub fn exact_deep_opening_bytes_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let trace_fields = layout
        .trace_groups
        .iter()
        .try_fold(0_usize, |total, group| {
            group
                .base_width
                .checked_add(group.aux_width)
                .and_then(|width| width.checked_mul(2))
                .and_then(|fields| total.checked_add(fields))
                .ok_or(AggregateStarkErrorV1::InvalidLayout)
        })?;
    let composition_fields = parameters
        .security_lanes
        .checked_mul(parameters.composition_degree_chunks)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    trace_fields
        .checked_add(composition_fields)
        .and_then(|fields| fields.checked_mul(core::mem::size_of::<[u64; 4]>()))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
fn deep_insertion_offset_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let header_bytes = parameters
        .proof_magic
        .len()
        .checked_add(core::mem::size_of::<u16>() * 2)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let roots = layout
        .trace_commitment_count_v1()
        .checked_mul(2)
        .and_then(|roots| roots.checked_add(parameters.security_lanes))
        .and_then(|roots| roots.checked_add(parameters.security_lanes))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    header_bytes
        .checked_add(
            roots
                .checked_mul(PRIVACY_OUTER_DIGEST_BYTES_V1)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
fn encode_deep_openings_raw_v1(
    deep: &AggregateDeepProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<u8>, AggregateStarkErrorV1> {
    validate_deep_proof_shape_v1(deep, parameters, layout)?;
    let expected = exact_deep_opening_bytes_v1(parameters, layout)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for group in &deep.trace_groups {
        append_fp4_fields_v1(&mut bytes, &group.base_current);
        append_fp4_fields_v1(&mut bytes, &group.base_next);
        append_fp4_fields_v1(&mut bytes, &group.aux_current);
        append_fp4_fields_v1(&mut bytes, &group.aux_next);
    }
    for values in &deep.composition_values {
        append_fp4_fields_v1(&mut bytes, values);
    }
    if bytes.len() != expected {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    Ok(bytes)
}
fn decode_deep_openings_raw_v1(
    bytes: &[u8],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<AggregateDeepProofV1, AggregateStarkErrorV1> {
    if bytes.len() != exact_deep_opening_bytes_v1(parameters, layout)? {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    let mut reader = ExactProofReaderV1::new(bytes);
    let trace_groups = layout
        .trace_groups
        .iter()
        .map(|group| {
            Ok(AggregateDeepTraceGroupOpeningV1 {
                base_current: take_fp4_fields_v1(&mut reader, group.base_width)?,
                base_next: take_fp4_fields_v1(&mut reader, group.base_width)?,
                aux_current: take_fp4_fields_v1(&mut reader, group.aux_width)?,
                aux_next: take_fp4_fields_v1(&mut reader, group.aux_width)?,
            })
        })
        .collect::<Result<Vec<_>, AggregateStarkErrorV1>>()?;
    let composition_values = (0..parameters.security_lanes)
        .map(|_| take_fp4_fields_v1(&mut reader, parameters.composition_degree_chunks))
        .collect::<Result<Vec<_>, _>>()?;
    reader.finish().map_err(reader_error_v1)?;
    let deep = AggregateDeepProofV1 {
        trace_groups,
        composition_values,
    };
    validate_deep_proof_shape_v1(&deep, parameters, layout)?;
    Ok(deep)
}
fn encoded_non_frontier_bytes_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let terminal_size = parameters.terminal_size()?;
    let hash_bytes = PRIVACY_OUTER_DIGEST_BYTES_V1;
    let base_field_bytes = core::mem::size_of::<u64>();
    let extension_field_bytes = core::mem::size_of::<[u64; 4]>();
    let mut bytes = parameters
        .proof_magic
        .len()
        .checked_add(core::mem::size_of::<u16>() * 2)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let trace_roots = layout
        .trace_commitment_count_v1()
        .checked_mul(2)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let fri_roots = parameters
        .security_lanes
        .checked_mul(
            layout
                .fri_rounds(parameters)?
                .checked_add(1)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let root_count = trace_roots
        .checked_add(parameters.security_lanes)
        .and_then(|value| value.checked_add(parameters.security_lanes))
        .and_then(|value| value.checked_add(fri_roots))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    bytes = bytes
        .checked_add(
            root_count
                .checked_mul(hash_bytes)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .and_then(|value| {
            value.checked_add(
                parameters
                    .security_lanes
                    .checked_mul(terminal_size)?
                    .checked_mul(extension_field_bytes)?,
            )
        })
        .and_then(|value| value.checked_add(core::mem::size_of::<u64>()))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let total_width = layout
        .trace_groups
        .iter()
        .try_fold(0_usize, |total, group| {
            total
                .checked_add(
                    group
                        .base_width
                        .checked_add(group.aux_width)
                        .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
                )
                .ok_or(AggregateStarkErrorV1::InvalidLayout)
        })?;
    let trace_fields = total_width
        .checked_mul(layout.trace_layout.query_rows_v1())
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let fri_fields = parameters
        .security_lanes
        .checked_mul(layout.fri_rounds(parameters)?)
        .and_then(|value| value.checked_mul(2))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let composition_fields = parameters
        .security_lanes
        .checked_mul(parameters.composition_degree_chunks)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let trace_bytes = trace_fields
        .checked_mul(base_field_bytes)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let extension_fields_per_query = composition_fields
        .checked_add(parameters.security_lanes)
        .and_then(|value| value.checked_add(fri_fields))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let extension_bytes = extension_fields_per_query
        .checked_mul(extension_field_bytes)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let fields_bytes_per_query = trace_bytes
        .checked_add(extension_bytes)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let query_bytes = core::mem::size_of::<u32>()
        .checked_add(fields_bytes_per_query)
        .and_then(|value| value.checked_mul(parameters.query_count))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    bytes
        .checked_add(query_bytes)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
/// Exact occupied prefix length before canonical public-profile zero padding.
fn minimal_encoded_proof_bytes_v1(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    validate_proof_shape_v1(proof, parameters, layout)?;
    let trace_hashes = proof
        .trace_groups
        .iter()
        .try_fold(0_usize, |total, group| {
            total
                .checked_add(group.base_frontier.len())
                .and_then(|value| value.checked_add(group.aux_frontier.len()))
                .ok_or(AggregateStarkErrorV1::InvalidLayout)
        })?;
    let composition_hashes =
        proof
            .composition_frontiers
            .iter()
            .try_fold(0_usize, |total, frontier| {
                total
                    .checked_add(frontier.len())
                    .ok_or(AggregateStarkErrorV1::InvalidLayout)
            })?;
    let fri_mask_hashes =
        proof
            .fri_mask_frontiers
            .iter()
            .try_fold(0_usize, |total, frontier| {
                total
                    .checked_add(frontier.len())
                    .ok_or(AggregateStarkErrorV1::InvalidLayout)
            })?;
    let fri_hashes = proof
        .fri_lanes
        .iter()
        .flat_map(|lane| &lane.round_frontiers)
        .try_fold(0_usize, |total, frontier| {
            total
                .checked_add(frontier.len())
                .ok_or(AggregateStarkErrorV1::InvalidLayout)
        })?;
    let frontier_hashes = trace_hashes
        .checked_add(composition_hashes)
        .and_then(|value| value.checked_add(fri_mask_hashes))
        .and_then(|value| value.checked_add(fri_hashes))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    encoded_non_frontier_bytes_v1(parameters, layout)?
        .checked_add(
            frontier_hashes
                .checked_mul(PRIVACY_OUTER_DIGEST_BYTES_V1)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
/// Exact canonical wire length for one validated proof object.
///
/// Query-dependent minimal frontiers occupy a prefix of the public layout's
/// maximum; the remaining bytes are canonical zeros, never optional suffixes.
pub fn exact_encoded_proof_bytes_v1(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    let used = minimal_encoded_proof_bytes_v1(proof, parameters, layout)?;
    let expected = maximum_encoded_proof_bytes_v1(parameters, layout)?;
    if used > expected {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    Ok(expected)
}
/// Exact encoded byte length of one validated DEEP-enabled proof.
pub fn exact_encoded_proof_with_deep_bytes_v1(
    proof: &AggregateStarkProofV1,
    deep: &AggregateDeepProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    validate_deep_proof_shape_v1(deep, parameters, layout)?;
    exact_encoded_proof_bytes_v1(proof, parameters, layout)?
        .checked_add(exact_deep_opening_bytes_v1(parameters, layout)?)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
/// Hard maximum encoded length over all legal query/frontier arrangements.
pub fn maximum_encoded_proof_bytes_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    let non_frontier = encoded_non_frontier_bytes_v1(parameters, layout)?;
    let trace_opened = parameters
        .query_count
        .checked_mul(layout.trace_layout.query_rows_v1())
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?
        .min(layout.common_lde_size());
    let trace_frontier =
        maximum_multiproof_frontier_len_v1(layout.common_lde_size(), trace_opened)?;
    let composition_frontier = maximum_multiproof_frontier_len_v1(
        layout.common_lde_size(),
        parameters.query_count.min(layout.common_lde_size()),
    )?;
    let mut fri_frontiers = 0_usize;
    for round in 0..layout.fri_rounds(parameters)? {
        let leaf_count = parameters
            .fri_commitment_layout
            .leaf_count(layout.common_lde_size() >> round)?;
        let opened = match parameters.fri_commitment_layout {
            AggregateFriCommitmentLayoutV1::Scalar => parameters
                .query_count
                .checked_mul(2)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
            AggregateFriCommitmentLayoutV1::Paired => parameters.query_count,
        };
        fri_frontiers = fri_frontiers
            .checked_add(maximum_multiproof_frontier_len_v1(
                leaf_count,
                opened.min(leaf_count),
            )?)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    }
    let frontier_hashes = layout
        .trace_commitment_count_v1()
        .checked_mul(2)
        .and_then(|groups| groups.checked_mul(trace_frontier))
        .and_then(|value| {
            parameters
                .security_lanes
                .checked_mul(composition_frontier)
                .and_then(|composition| value.checked_add(composition))
        })
        .and_then(|value| {
            parameters
                .security_lanes
                .checked_mul(composition_frontier)
                .and_then(|fri_mask| value.checked_add(fri_mask))
        })
        .and_then(|value| {
            parameters
                .security_lanes
                .checked_mul(fri_frontiers)
                .and_then(|fri| value.checked_add(fri))
        })
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    non_frontier
        .checked_add(
            frontier_hashes
                .checked_mul(PRIVACY_OUTER_DIGEST_BYTES_V1)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
/// Hard maximum encoded length of a DEEP-enabled proof.
pub fn maximum_encoded_proof_with_deep_bytes_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    maximum_encoded_proof_bytes_v1(parameters, layout)?
        .checked_add(exact_deep_opening_bytes_v1(parameters, layout)?)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
/// Encode the sole canonical exact aggregate proof wire.
pub fn encode_proof_v1(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<u8>, AggregateStarkErrorV1> {
    validate_proof_shape_v1(proof, parameters, layout)?;
    let expected = exact_encoded_proof_bytes_v1(proof, parameters, layout)?;
    if expected > parameters.maximum_proof_bytes {
        return Err(AggregateStarkErrorV1::ProofTooLarge);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    bytes.extend_from_slice(&parameters.proof_magic);
    append_u16_v1(&mut bytes, proof.version);
    append_u16_v1(
        &mut bytes,
        u16::try_from(proof.trace_groups.len())
            .map_err(|_| AggregateStarkErrorV1::InvalidProofShape)?,
    );
    for group in &proof.trace_groups {
        append_hash_v1(&mut bytes, &group.base_root);
    }
    for group in &proof.trace_groups {
        append_hash_v1(&mut bytes, &group.aux_root);
    }
    append_hashes_v1(&mut bytes, &proof.composition_roots);
    append_hashes_v1(&mut bytes, &proof.fri_mask_roots);
    for lane in &proof.fri_lanes {
        append_hashes_v1(&mut bytes, &lane.roots);
        append_fp4_fields_v1(&mut bytes, &lane.terminal_values);
    }
    append_u64_v1(&mut bytes, proof.grinding_nonce);
    for query in &proof.queries {
        append_u32_v1(&mut bytes, query.index);
        for group in &query.trace_groups {
            append_base_fields_v1(&mut bytes, &group.base_current);
            append_base_fields_v1(&mut bytes, &group.base_next);
            append_base_fields_v1(&mut bytes, &group.aux_current);
            append_base_fields_v1(&mut bytes, &group.aux_next);
        }
        for lane in &query.composition_values {
            append_fp4_fields_v1(&mut bytes, lane);
        }
        append_fp4_fields_v1(&mut bytes, &query.fri_mask_values);
        for lane in &query.fri_lanes {
            for opening in &lane.rounds {
                append_fp4_fields_v1(&mut bytes, core::slice::from_ref(&opening.low));
                append_fp4_fields_v1(&mut bytes, core::slice::from_ref(&opening.high));
            }
        }
    }
    for group in &proof.trace_groups {
        append_hashes_v1(&mut bytes, &group.base_frontier);
        append_hashes_v1(&mut bytes, &group.aux_frontier);
    }
    for frontier in &proof.composition_frontiers {
        append_hashes_v1(&mut bytes, frontier);
    }
    for frontier in &proof.fri_mask_frontiers {
        append_hashes_v1(&mut bytes, frontier);
    }
    for lane in &proof.fri_lanes {
        for frontier in &lane.round_frontiers {
            append_hashes_v1(&mut bytes, frontier);
        }
    }
    if bytes.len() != minimal_encoded_proof_bytes_v1(proof, parameters, layout)? {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    bytes.resize(expected, 0);
    Ok(bytes)
}
/// Encode the sole canonical DEEP-enabled aggregate wire.
///
/// DEEP values are inserted after every trace/composition/mask root and before
/// the first FRI root. This fixed position mirrors transcript order and leaves
/// no tag, count, or alternate representation for a decoder to reinterpret.
pub fn encode_proof_with_deep_v1(
    proof: &AggregateStarkProofV1,
    deep: &AggregateDeepProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<u8>, AggregateStarkErrorV1> {
    let expected = exact_encoded_proof_with_deep_bytes_v1(proof, deep, parameters, layout)?;
    if expected > parameters.maximum_proof_bytes {
        return Err(AggregateStarkErrorV1::ProofTooLarge);
    }
    let mut bytes = encode_proof_v1(proof, parameters, layout)?;
    let deep_bytes = encode_deep_openings_raw_v1(deep, parameters, layout)?;
    let insertion = deep_insertion_offset_v1(parameters, layout)?;
    if insertion > bytes.len() {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    bytes
        .try_reserve_exact(deep_bytes.len())
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    bytes.splice(insertion..insertion, deep_bytes);
    if bytes.len() != expected {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    Ok(bytes)
}
fn reader_error_v1(error: TransparentStarkErrorV1) -> AggregateStarkErrorV1 {
    match error {
        TransparentStarkErrorV1::NonCanonicalField => AggregateStarkErrorV1::NonCanonicalField,
        _ => AggregateStarkErrorV1::MalformedProof,
    }
}
fn take_hash_v1(
    reader: &mut ExactProofReaderV1<'_>,
) -> Result<PrivacyOuterDigestV1, AggregateStarkErrorV1> {
    let bytes: [u8; PRIVACY_OUTER_DIGEST_BYTES_V1] = reader.take().map_err(reader_error_v1)?;
    Ok(PrivacyOuterDigestV1::from_bytes(bytes))
}
fn take_hashes_v1(
    reader: &mut ExactProofReaderV1<'_>,
    count: usize,
) -> Result<Vec<PrivacyOuterDigestV1>, AggregateStarkErrorV1> {
    (0..count).map(|_| take_hash_v1(reader)).collect()
}
fn take_base_fields_v1(
    reader: &mut ExactProofReaderV1<'_>,
    count: usize,
) -> Result<Vec<u64>, AggregateStarkErrorV1> {
    (0..count)
        .map(|_| reader.field().map(|field| field.0).map_err(reader_error_v1))
        .collect()
}
fn take_fp4_fields_v1(
    reader: &mut ExactProofReaderV1<'_>,
    count: usize,
) -> Result<Vec<[u64; 4]>, AggregateStarkErrorV1> {
    (0..count)
        .map(|_| {
            reader
                .fp4()
                .map(|field| field.coefficients().map(F::value))
                .map_err(reader_error_v1)
        })
        .collect()
}
/// Consume only the required canonical zero tail, then require exact end-of-input.
fn finish_zero_padding_v1(
    mut reader: ExactProofReaderV1<'_>,
    mut padding: usize,
) -> Result<(), AggregateStarkErrorV1> {
    while padding >= 64 {
        if reader.take::<64>().map_err(reader_error_v1)? != [0; 64] {
            return Err(AggregateStarkErrorV1::MalformedProof);
        }
        padding -= 64;
    }
    for _ in 0..padding {
        if reader.take::<1>().map_err(reader_error_v1)? != [0] {
            return Err(AggregateStarkErrorV1::MalformedProof);
        }
    }
    reader.finish().map_err(reader_error_v1)
}
/// Decode the exact public-profile wire and reject nonzero padding or any suffix.
pub fn decode_proof_v1(
    bytes: &[u8],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<AggregateStarkProofV1, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let expected = maximum_encoded_proof_bytes_v1(parameters, layout)?;
    if expected > parameters.maximum_proof_bytes || bytes.len() > parameters.maximum_proof_bytes {
        return Err(AggregateStarkErrorV1::ProofTooLarge);
    }
    if bytes.len() != expected {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    let mut reader = ExactProofReaderV1::new(bytes);
    if reader.take::<4>().map_err(reader_error_v1)? != parameters.proof_magic {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    let version = reader.u16().map_err(reader_error_v1)?;
    let group_count = usize::from(reader.u16().map_err(reader_error_v1)?);
    if group_count != layout.trace_commitment_count_v1() {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    let base_roots = take_hashes_v1(&mut reader, group_count)?;
    let aux_roots = take_hashes_v1(&mut reader, group_count)?;
    let mut trace_groups = base_roots
        .into_iter()
        .zip(aux_roots)
        .map(|(base_root, aux_root)| AggregateTraceGroupProofV1 {
            base_root,
            aux_root,
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        })
        .collect::<Vec<_>>();
    let composition_roots = take_hashes_v1(&mut reader, parameters.security_lanes)?;
    let fri_mask_roots = take_hashes_v1(&mut reader, parameters.security_lanes)?;
    let fri_rounds = layout.fri_rounds(parameters)?;
    let mut fri_lanes = Vec::with_capacity(parameters.security_lanes);
    for _ in 0..parameters.security_lanes {
        fri_lanes.push(AggregateFriLaneProofV1 {
            roots: take_hashes_v1(&mut reader, fri_rounds + 1)?,
            terminal_values: take_fp4_fields_v1(&mut reader, parameters.terminal_size()?)?,
            round_frontiers: Vec::new(),
        });
    }
    let grinding_nonce = reader.u64().map_err(reader_error_v1)?;
    let queries = (0..parameters.query_count)
        .map(|_| {
            let index = reader.u32().map_err(reader_error_v1)?;
            let trace_groups = layout
                .trace_groups
                .iter()
                .map(|group| {
                    Ok(AggregateTraceGroupQueryV1 {
                        base_current: take_base_fields_v1(&mut reader, group.base_width)?,
                        base_next: take_base_fields_v1(
                            &mut reader,
                            layout.trace_layout.next_width_v1(group.base_width),
                        )?,
                        aux_current: take_base_fields_v1(&mut reader, group.aux_width)?,
                        aux_next: take_base_fields_v1(
                            &mut reader,
                            layout.trace_layout.next_width_v1(group.aux_width),
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, AggregateStarkErrorV1>>()?;
            let composition_values = (0..parameters.security_lanes)
                .map(|_| take_fp4_fields_v1(&mut reader, parameters.composition_degree_chunks))
                .collect::<Result<Vec<_>, _>>()?;
            let fri_mask_values = take_fp4_fields_v1(&mut reader, parameters.security_lanes)?;
            let fri_lanes = (0..parameters.security_lanes)
                .map(|_| {
                    let rounds = (0..fri_rounds)
                        .map(|_| {
                            Ok(AggregateFriRoundOpeningV1 {
                                low: reader
                                    .fp4()
                                    .map_err(reader_error_v1)?
                                    .coefficients()
                                    .map(F::value),
                                high: reader
                                    .fp4()
                                    .map_err(reader_error_v1)?
                                    .coefficients()
                                    .map(F::value),
                            })
                        })
                        .collect::<Result<Vec<_>, AggregateStarkErrorV1>>()?;
                    Ok(AggregateFriLaneQueryV1 { rounds })
                })
                .collect::<Result<Vec<_>, AggregateStarkErrorV1>>()?;
            Ok(AggregateQueryProofV1 {
                index,
                trace_groups,
                composition_values,
                fri_mask_values,
                fri_lanes,
            })
        })
        .collect::<Result<Vec<_>, AggregateStarkErrorV1>>()?;
    let composition_indices = composition_opening_indices_v1(&queries, layout)?;
    for (group_index, group) in trace_groups.iter_mut().enumerate() {
        let indices = trace_group_opening_indices_v1(&queries, layout, group_index)?;
        let count = multiproof_frontier_len_v1(layout.common_lde_size(), &indices)?;
        group.base_frontier = take_hashes_v1(&mut reader, count)?;
        group.aux_frontier = take_hashes_v1(&mut reader, count)?;
    }
    let composition_count =
        multiproof_frontier_len_v1(layout.common_lde_size(), &composition_indices)?;
    let composition_frontiers = (0..parameters.security_lanes)
        .map(|_| take_hashes_v1(&mut reader, composition_count))
        .collect::<Result<Vec<_>, _>>()?;
    let fri_mask_frontiers = (0..parameters.security_lanes)
        .map(|_| take_hashes_v1(&mut reader, composition_count))
        .collect::<Result<Vec<_>, _>>()?;
    for lane in &mut fri_lanes {
        lane.round_frontiers = (0..fri_rounds)
            .map(|round| {
                let indices = fri_opening_indices_v1(&queries, parameters, layout, round)?;
                let count = multiproof_frontier_len_v1(
                    parameters
                        .fri_commitment_layout
                        .leaf_count(layout.common_lde_size() >> round)?,
                    &indices,
                )?;
                take_hashes_v1(&mut reader, count)
            })
            .collect::<Result<Vec<_>, _>>()?;
    }
    let proof = AggregateStarkProofV1 {
        version,
        trace_groups,
        composition_roots,
        composition_frontiers,
        fri_mask_roots,
        fri_mask_frontiers,
        fri_lanes,
        queries,
        grinding_nonce,
    };
    let used = minimal_encoded_proof_bytes_v1(&proof, parameters, layout)?;
    let padding = expected
        .checked_sub(used)
        .ok_or(AggregateStarkErrorV1::MalformedProof)?;
    finish_zero_padding_v1(reader, padding)?;
    Ok(proof)
}
/// Decode the sole canonical DEEP-enabled aggregate wire.
pub fn decode_proof_with_deep_v1(
    bytes: &[u8],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<(AggregateStarkProofV1, AggregateDeepProofV1), AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let expected = maximum_encoded_proof_with_deep_bytes_v1(parameters, layout)?;
    if expected > parameters.maximum_proof_bytes || bytes.len() > parameters.maximum_proof_bytes {
        return Err(AggregateStarkErrorV1::ProofTooLarge);
    }
    if bytes.len() != expected {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    let insertion = deep_insertion_offset_v1(parameters, layout)?;
    let deep_len = exact_deep_opening_bytes_v1(parameters, layout)?;
    let deep_end = insertion
        .checked_add(deep_len)
        .ok_or(AggregateStarkErrorV1::MalformedProof)?;
    if deep_end > bytes.len() {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    let mut base_bytes = Vec::new();
    base_bytes
        .try_reserve_exact(
            bytes
                .len()
                .checked_sub(deep_len)
                .ok_or(AggregateStarkErrorV1::MalformedProof)?,
        )
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    base_bytes.extend_from_slice(&bytes[..insertion]);
    base_bytes.extend_from_slice(&bytes[deep_end..]);
    let proof = decode_proof_v1(&base_bytes, parameters, layout)?;
    let deep = decode_deep_openings_raw_v1(&bytes[insertion..deep_end], parameters, layout)?;
    Ok((proof, deep))
}
/// Prover material for one ordered trace group on the common LDE domain.
#[derive(Clone)]
pub struct AggregateTraceGroupMaterialV1 {
    /// Masked base LDE columns.
    pub(crate) base_lde: Vec<Vec<F>>,
    /// Masked auxiliary LDE columns.
    pub(crate) aux_lde: Vec<Vec<F>>,
    /// Base vector-row Merkle tree.
    pub(crate) base_tree: PrivacyOuterMerkleTreeV1,
    /// Auxiliary vector-row Merkle tree.
    pub(crate) aux_tree: PrivacyOuterMerkleTreeV1,
}
impl Drop for AggregateTraceGroupMaterialV1 {
    fn drop(&mut self) {
        for column in &mut self.base_lde {
            zeroize_field_column_v1(column);
        }
        for column in &mut self.aux_lde {
            zeroize_field_column_v1(column);
        }
    }
}
/// Prover material for one shared FRI lane.
#[derive(Clone)]
pub struct AggregateFriLaneMaterialV1 {
    /// Every FRI layer including the terminal vector.
    pub(crate) layers: ZeroizingExtensionFieldMatrixV1,
    /// Merkle tree for every layer including the terminal vector.
    pub(crate) trees: Vec<PrivacyOuterMerkleTreeV1>,
    /// Root for every layer including the terminal vector.
    pub(crate) roots: Vec<PrivacyOuterDigestV1>,
    /// Exact terminal evaluations.
    pub(crate) terminal_values: Vec<E>,
}
fn fold_fri_layer_v1(
    current: &[E],
    beta: E,
    domain_shift: F,
    domain_root: F,
) -> Result<Vec<E>, AggregateStarkErrorV1> {
    if current.len() < 2 || !current.len().is_power_of_two() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let half = current.len() / 2;
    let inverse_root = domain_root
        .inv()
        .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
    let initial_inverse_x = domain_shift
        .inv()
        .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
    let mut next = ZeroizingExtensionFieldColumnV1(Vec::new());
    next.0
        .try_reserve_exact(half)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    next.0.resize(half, E::ZERO);
    // A batch derives the same first inverse-domain point as the serial recurrence, then keeps
    // that recurrence unchanged within the batch. Disjoint indexed slices make the final layer
    // independent of Rayon scheduling and worker count.
    next.0
        .par_chunks_mut(FRI_FOLD_PARALLEL_BATCH_ROWS_V1)
        .enumerate()
        .try_for_each(
            |(batch_index, output)| -> Result<(), AggregateStarkErrorV1> {
                let start = batch_index
                    .checked_mul(FRI_FOLD_PARALLEL_BATCH_ROWS_V1)
                    .ok_or(AggregateStarkErrorV1::AllocationFailure)?;
                let exponent =
                    u128::try_from(start).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?;
                let mut inverse_x = initial_inverse_x.mul(inverse_root.pow(exponent));
                for (local_index, folded) in output.iter_mut().enumerate() {
                    let index = start
                        .checked_add(local_index)
                        .ok_or(AggregateStarkErrorV1::AllocationFailure)?;
                    *folded = fri_fold_pair_with_inverse_x_fp4_v1(
                        current[index],
                        current[index + half],
                        beta,
                        inverse_x,
                    )
                    .map_err(map_transparent_error_v1)?;
                    inverse_x = inverse_x.mul(inverse_root);
                }
                Ok(())
            },
        )?;
    Ok(next.into_vec_v1())
}
/// Build and transcript-bind one complete shared binary-FRI lane.
pub fn build_fri_lane_v1(
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    layout: &AggregateProofLayoutV1,
    lane: usize,
    base_values: Vec<E>,
    transcript: &mut TransparentTranscriptV1,
) -> Result<AggregateFriLaneMaterialV1, AggregateStarkErrorV1> {
    let base_values = ZeroizingExtensionFieldColumnV1(base_values);
    layout.validate(parameters)?;
    domains.validate()?;
    if lane >= parameters.security_lanes || base_values.len() != layout.common_lde_size() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let fri_rounds = layout.fri_rounds(parameters)?;
    let mut layers = ZeroizingExtensionFieldMatrixV1(Vec::new());
    layers
        .try_reserve_exact(
            fri_rounds
                .checked_add(1)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    layers.push(base_values.into_vec_v1());
    let mut trees = Vec::with_capacity(fri_rounds + 1);
    let mut roots = Vec::with_capacity(fri_rounds + 1);
    let mut domain_shift = F(GOLDILOCKS_GENERATOR_V1);
    let mut domain_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).map_err(map_transparent_error_v1)?;
    for round in 0..fri_rounds {
        let current = layers
            .last()
            .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
        let tree = fri_tree_v1(
            domains,
            parameters.fri_commitment_layout,
            lane,
            round,
            current,
        )?;
        let root = tree.root();
        absorb_fri_root_v1(transcript, domains, lane, round, &root)?;
        let beta = transcript
            .challenge_fp4(domains.fri_beta_label)
            .map_err(map_transparent_error_v1)?;
        let next = ZeroizingExtensionFieldColumnV1(fold_fri_layer_v1(
            current,
            beta,
            domain_shift,
            domain_root,
        )?);
        trees.push(tree);
        roots.push(root);
        layers.push(next.into_vec_v1());
        domain_shift = domain_shift.mul(domain_shift);
        domain_root = domain_root.mul(domain_root);
    }
    let terminal_values = layers
        .last()
        .ok_or(AggregateStarkErrorV1::InternalInvariant)?
        .clone();
    if terminal_values.len() != parameters.terminal_size()? {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    ensure_fri_terminal_degree_fp4_v1(
        &terminal_values,
        parameters.terminal_log2,
        parameters.terminal_degree_bound,
    )
    .map_err(map_transparent_error_v1)?;
    let terminal_tree = fri_tree_v1(
        domains,
        parameters.fri_commitment_layout,
        lane,
        fri_rounds,
        &terminal_values,
    )?;
    let terminal_root = terminal_tree.root();
    absorb_fri_root_v1(transcript, domains, lane, fri_rounds, &terminal_root)?;
    roots.push(terminal_root);
    trees.push(terminal_tree);
    Ok(AggregateFriLaneMaterialV1 {
        layers,
        trees,
        roots,
        terminal_values,
    })
}
/// Bounded-memory transcript material for one FRI lane.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateStreamingFriLaneMaterialV1 {
    /// Layer roots, including the terminal layer.
    pub(crate) roots: Vec<PrivacyOuterDigestV1>,
    /// Fiat–Shamir folding challenge for each non-terminal layer.
    pub(crate) betas: Vec<E>,
    /// Exact terminal evaluations.
    pub(crate) terminal_values: Vec<E>,
}
/// Post-query openings and frontiers for one streamed FRI lane.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateStreamingFriLaneOpeningsV1 {
    /// Openings in the caller's canonical transcript-query order.
    pub(crate) queries: Vec<AggregateFriLaneQueryV1>,
    /// Canonical minimal frontier for each non-terminal layer.
    pub(crate) round_frontiers: Vec<Vec<PrivacyOuterDigestV1>>,
}
/// Commit and transcript-bind a complete FRI lane while retaining only one
/// current layer and one half-sized successor layer.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_streaming_fri_lane_v1(
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    layout: &AggregateProofLayoutV1,
    lane: usize,
    base_values: Vec<E>,
    transcript: &mut TransparentTranscriptV1,
) -> Result<AggregateStreamingFriLaneMaterialV1, AggregateStarkErrorV1> {
    let base_values = ZeroizingExtensionFieldColumnV1(base_values);
    layout.validate(parameters)?;
    domains.validate()?;
    if lane >= parameters.security_lanes || base_values.len() != layout.common_lde_size() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let fri_rounds = layout.fri_rounds(parameters)?;
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(
            fri_rounds
                .checked_add(1)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    let mut betas = Vec::new();
    betas
        .try_reserve_exact(fri_rounds)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    let mut current = base_values;
    let mut domain_shift = F(GOLDILOCKS_GENERATOR_V1);
    let mut domain_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).map_err(map_transparent_error_v1)?;
    for round in 0..fri_rounds {
        let commitment = streaming_fri_commitment_v1(
            domains,
            parameters.fri_commitment_layout,
            lane,
            round,
            &current,
            &[],
        )?;
        absorb_fri_root_v1(transcript, domains, lane, round, &commitment.root)?;
        let beta = transcript
            .challenge_fp4(domains.fri_beta_label)
            .map_err(map_transparent_error_v1)?;
        let next = ZeroizingExtensionFieldColumnV1(fold_fri_layer_v1(
            &current,
            beta,
            domain_shift,
            domain_root,
        )?);
        roots.push(commitment.root);
        betas.push(beta);
        current = next;
        domain_shift = domain_shift.mul(domain_shift);
        domain_root = domain_root.mul(domain_root);
    }
    if current.len() != parameters.terminal_size()? {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    ensure_fri_terminal_degree_fp4_v1(
        &current,
        parameters.terminal_log2,
        parameters.terminal_degree_bound,
    )
    .map_err(map_transparent_error_v1)?;
    let terminal = streaming_fri_commitment_v1(
        domains,
        parameters.fri_commitment_layout,
        lane,
        fri_rounds,
        &current,
        &[],
    )?;
    absorb_fri_root_v1(transcript, domains, lane, fri_rounds, &terminal.root)?;
    roots.push(terminal.root);
    Ok(AggregateStreamingFriLaneMaterialV1 {
        roots,
        betas,
        terminal_values: current.into_vec_v1(),
    })
}
/// Replay a committed FRI lane after transcript queries are fixed, retaining
/// only the exact opened pairs and canonical minimal frontiers.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn open_streaming_fri_lane_v1(
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    layout: &AggregateProofLayoutV1,
    lane: usize,
    base_values: Vec<E>,
    material: &AggregateStreamingFriLaneMaterialV1,
    query_indices: &[usize],
) -> Result<AggregateStreamingFriLaneOpeningsV1, AggregateStarkErrorV1> {
    let base_values = ZeroizingExtensionFieldColumnV1(base_values);
    layout.validate(parameters)?;
    domains.validate()?;
    let fri_rounds = layout.fri_rounds(parameters)?;
    if lane >= parameters.security_lanes
        || base_values.len() != layout.common_lde_size()
        || material.roots.len() != fri_rounds + 1
        || material.betas.len() != fri_rounds
        || material.terminal_values.len() != parameters.terminal_size()?
        || query_indices.len() != parameters.query_count
        || query_indices
            .iter()
            .any(|index| *index >= layout.common_lde_size())
        || query_indices.iter().copied().collect::<BTreeSet<_>>().len() != query_indices.len()
    {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    let mut queries = Vec::new();
    queries
        .try_reserve_exact(query_indices.len())
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for _ in query_indices {
        let mut rounds = Vec::new();
        rounds
            .try_reserve_exact(fri_rounds)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        queries.push(AggregateFriLaneQueryV1 { rounds });
    }
    let mut round_frontiers = Vec::new();
    round_frontiers
        .try_reserve_exact(fri_rounds)
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    let mut layer_indices = query_indices.to_vec();
    let mut current = base_values;
    let mut domain_shift = F(GOLDILOCKS_GENERATOR_V1);
    let mut domain_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).map_err(map_transparent_error_v1)?;
    for round in 0..fri_rounds {
        let half = current.len() / 2;
        let opening_indices = layer_indices
            .iter()
            .flat_map(|index| {
                let low = *index % half;
                match parameters.fri_commitment_layout {
                    AggregateFriCommitmentLayoutV1::Scalar => vec![low, low + half],
                    AggregateFriCommitmentLayoutV1::Paired => vec![low],
                }
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let commitment = streaming_fri_commitment_v1(
            domains,
            parameters.fri_commitment_layout,
            lane,
            round,
            &current,
            &opening_indices,
        )?;
        if commitment.root != material.roots[round] {
            return Err(AggregateStarkErrorV1::InternalInvariant);
        }
        for (query, index) in queries.iter_mut().zip(&layer_indices) {
            let low = *index % half;
            query.rounds.push(AggregateFriRoundOpeningV1 {
                low: current[low].coefficients().map(F::value),
                high: current[low + half].coefficients().map(F::value),
            });
        }
        let next = ZeroizingExtensionFieldColumnV1(fold_fri_layer_v1(
            &current,
            material.betas[round],
            domain_shift,
            domain_root,
        )?);
        for index in &mut layer_indices {
            *index %= half;
        }
        round_frontiers.push(commitment.frontier);
        current = next;
        domain_shift = domain_shift.mul(domain_shift);
        domain_root = domain_root.mul(domain_root);
    }
    if current.0.as_slice() != material.terminal_values.as_slice() {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    let terminal = streaming_fri_commitment_v1(
        domains,
        parameters.fri_commitment_layout,
        lane,
        fri_rounds,
        &current,
        &[],
    )?;
    if terminal.root != material.roots[fri_rounds] {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    Ok(AggregateStreamingFriLaneOpeningsV1 {
        queries,
        round_frontiers,
    })
}
/// Construct all exact opened values for one shared query index.
pub fn build_query_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    index: usize,
    trace_groups: &[AggregateTraceGroupMaterialV1],
    compositions: &[Vec<Vec<E>>],
    fri_masks: &[AggregateFriMaskOracleMaterialV1],
    fri_lanes: &[AggregateFriLaneMaterialV1],
) -> Result<AggregateQueryProofV1, AggregateStarkErrorV1> {
    if layout.trace_layout == AggregateTraceLayoutV1::JoinedCurrent {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    layout.validate(parameters)?;
    if index >= layout.common_lde_size()
        || trace_groups.len() != layout.trace_groups.len()
        || compositions.len() != parameters.security_lanes
        || fri_masks.len() != parameters.security_lanes
        || fri_lanes.len() != parameters.security_lanes
        || compositions.iter().any(|lane| {
            lane.len() != parameters.composition_degree_chunks
                || lane
                    .iter()
                    .any(|chunk| chunk.len() != layout.common_lde_size())
        })
        || fri_masks
            .iter()
            .any(|mask| mask.evaluations.len() != layout.common_lde_size())
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let mut group_queries = Vec::with_capacity(trace_groups.len());
    for (material, descriptor) in trace_groups.iter().zip(&layout.trace_groups) {
        if material.base_lde.len() != descriptor.base_width
            || material.aux_lde.len() != descriptor.aux_width
            || material
                .base_lde
                .iter()
                .chain(&material.aux_lde)
                .any(|column| column.len() != layout.common_lde_size())
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let next =
            (index + descriptor.next_stride(layout.common_lde_log2)?) % layout.common_lde_size();
        group_queries.push(AggregateTraceGroupQueryV1 {
            base_current: row_at_v1(&material.base_lde, index)?
                .into_iter()
                .map(|value| value.0)
                .collect(),
            base_next: if layout.trace_layout == AggregateTraceLayoutV1::GroupedCurrentNext {
                row_at_v1(&material.base_lde, next)?
                    .into_iter()
                    .map(|value| value.0)
                    .collect()
            } else {
                Vec::new()
            },
            aux_current: row_at_v1(&material.aux_lde, index)?
                .into_iter()
                .map(|value| value.0)
                .collect(),
            aux_next: if layout.trace_layout == AggregateTraceLayoutV1::GroupedCurrentNext {
                row_at_v1(&material.aux_lde, next)?
                    .into_iter()
                    .map(|value| value.0)
                    .collect()
            } else {
                Vec::new()
            },
        });
    }
    let composition_values = compositions
        .iter()
        .map(|lane| {
            lane.iter()
                .map(|chunk| chunk[index].coefficients().map(F::value))
                .collect()
        })
        .collect();
    let fri_mask_values = fri_masks
        .iter()
        .map(|mask| mask.evaluations[index].coefficients().map(F::value))
        .collect();
    let mut fri_queries = Vec::with_capacity(parameters.security_lanes);
    let fri_rounds = layout.fri_rounds(parameters)?;
    for fri in fri_lanes {
        if fri.layers.len() != fri_rounds + 1 {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let mut layer_index = index;
        let mut rounds = Vec::with_capacity(fri_rounds);
        for round in 0..fri_rounds {
            let layer = &fri.layers[round];
            let half = layer.len() / 2;
            let low_index = layer_index % half;
            rounds.push(AggregateFriRoundOpeningV1 {
                low: layer[low_index].coefficients().map(F::value),
                high: layer[low_index + half].coefficients().map(F::value),
            });
            layer_index = low_index;
        }
        fri_queries.push(AggregateFriLaneQueryV1 { rounds });
    }
    Ok(AggregateQueryProofV1 {
        index: u32::try_from(index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        trace_groups: group_queries,
        composition_values,
        fri_mask_values,
        fri_lanes: fri_queries,
    })
}
/// Build every canonical trace/composition/FRI frontier after queries are fixed.
pub fn build_all_frontiers_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    queries: &[AggregateQueryProofV1],
    trace_groups: &[AggregateTraceGroupMaterialV1],
    composition_trees: &[PrivacyOuterMerkleTreeV1],
    fri_masks: &[AggregateFriMaskOracleMaterialV1],
    fri_lanes: &[AggregateFriLaneMaterialV1],
) -> Result<
    (
        Vec<(Vec<PrivacyOuterDigestV1>, Vec<PrivacyOuterDigestV1>)>,
        Vec<Vec<PrivacyOuterDigestV1>>,
        Vec<Vec<PrivacyOuterDigestV1>>,
        Vec<Vec<Vec<PrivacyOuterDigestV1>>>,
    ),
    AggregateStarkErrorV1,
> {
    if layout.trace_layout == AggregateTraceLayoutV1::JoinedCurrent {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    layout.validate(parameters)?;
    if queries.len() != parameters.query_count
        || trace_groups.len() != layout.trace_groups.len()
        || composition_trees.len() != parameters.security_lanes
        || fri_masks.len() != parameters.security_lanes
        || fri_lanes.len() != parameters.security_lanes
    {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    let trace_frontiers = trace_groups
        .iter()
        .enumerate()
        .map(|(group, material)| {
            let indices = trace_group_opening_indices_v1(queries, layout, group)?;
            Ok((
                canonical_multiproof_frontier_v1(
                    &material.base_tree,
                    layout.common_lde_size(),
                    &indices,
                )?,
                canonical_multiproof_frontier_v1(
                    &material.aux_tree,
                    layout.common_lde_size(),
                    &indices,
                )?,
            ))
        })
        .collect::<Result<Vec<_>, AggregateStarkErrorV1>>()?;
    let composition_indices = composition_opening_indices_v1(queries, layout)?;
    let composition_frontiers = composition_trees
        .iter()
        .map(|tree| {
            canonical_multiproof_frontier_v1(tree, layout.common_lde_size(), &composition_indices)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fri_mask_frontiers = fri_masks
        .iter()
        .map(|mask| {
            canonical_multiproof_frontier_v1(
                &mask.tree,
                layout.common_lde_size(),
                &composition_indices,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fri_frontiers = fri_lanes
        .iter()
        .map(|lane| {
            (0..layout.fri_rounds(parameters)?)
                .map(|round| {
                    let indices = fri_opening_indices_v1(queries, parameters, layout, round)?;
                    canonical_multiproof_frontier_v1(
                        &lane.trees[round],
                        parameters
                            .fri_commitment_layout
                            .leaf_count(layout.common_lde_size() >> round)?,
                        &indices,
                    )
                })
                .collect::<Result<Vec<_>, AggregateStarkErrorV1>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        trace_frontiers,
        composition_frontiers,
        fri_mask_frontiers,
        fri_frontiers,
    ))
}
/// Bound public query leaf-hash scratch independently of the supplied Rayon pool.
const OPENED_QUERY_HASH_BATCH_V1: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpenedLeafTargetV1 {
    Base(usize),
    Auxiliary(usize),
    Composition(usize),
    FriMask(usize),
    Fri { lane: usize, round: usize },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OpenedQueryLeafV1 {
    target: OpenedLeafTargetV1,
    index: usize,
    digest: PrivacyOuterDigestV1,
}
/// Only disclosed proof openings and public hashes enter this package.
/// Earlier leaf events survive a later hash/validation error so ordered map
/// insertion can report an earlier duplicate mismatch before that later error.
#[derive(Debug, PartialEq, Eq)]
struct OpenedQueryHashesV1 {
    leaves: Vec<OpenedQueryLeafV1>,
    outcome: Result<(), AggregateStarkErrorV1>,
}
/// Exact joined-row framing over already disclosed logical group slices.
fn joined_query_trace_leaf_v1(
    query: &AggregateQueryProofV1,
    layout: &AggregateProofLayoutV1,
    domains: &AggregateStarkDomainsV1,
    index: usize,
    base: bool,
) -> Result<PrivacyOuterDigestV1, AggregateStarkErrorV1> {
    let width = layout.trace_groups.iter().try_fold(0_usize, |sum, group| {
        sum.checked_add(if base {
            group.base_width
        } else {
            group.aux_width
        })
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
    })?;
    let mut fields = zeroize::Zeroizing::new(Vec::new());
    fields
        .try_reserve_exact(
            width
                .checked_mul(8)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for opening in &query.trace_groups {
        let values = if base {
            &opening.base_current
        } else {
            &opening.aux_current
        };
        for &value in values {
            F::canonical(value).ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
            let packed = zeroize::Zeroizing::new(value.to_be_bytes());
            fields.extend_from_slice(&packed[..]);
        }
    }
    if fields.len() != width * 8 {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    let group = u16::try_from(JOINED_TRACE_GROUP_MARKER_V1)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let width = u16::try_from(width)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    privacy_outer_digest_frame_v1(
        domains.digest_context,
        if base {
            domains.base_leaf
        } else {
            domains.aux_leaf
        },
        b"vector-row-leaf",
        0,
        u64::try_from(index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
        u64::from(u16::MAX),
        &[&group, &width, &fields],
    )
    .map_err(map_transparent_error_v1)
}
/// Called only after complete proof-shape and domain validation by the verifier.
fn hash_opened_query_leaves_v1(
    query: &AggregateQueryProofV1,
    expected_index: Option<usize>,
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    layout: &AggregateProofLayoutV1,
    fri_rounds: usize,
) -> OpenedQueryHashesV1 {
    let mut leaves = Vec::new();
    let outcome = (|| {
        let index =
            usize::try_from(query.index).map_err(|_| AggregateStarkErrorV1::TranscriptMismatch)?;
        if expected_index != Some(index) || index >= layout.common_lde_size() {
            return Err(AggregateStarkErrorV1::TranscriptMismatch);
        }
        let leaves_per_lane = fri_rounds
            .checked_mul(2)
            .and_then(|count| count.checked_add(2))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let leaf_capacity = parameters
            .security_lanes
            .checked_mul(leaves_per_lane)
            .and_then(|count| {
                layout
                    .trace_commitment_count_v1()
                    .checked_mul(2 * layout.trace_layout.query_rows_v1())
                    .and_then(|trace_count| count.checked_add(trace_count))
            })
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        leaves
            .try_reserve_exact(leaf_capacity)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        if layout.trace_layout == AggregateTraceLayoutV1::JoinedCurrent {
            for base in [true, false] {
                leaves.push(OpenedQueryLeafV1 {
                    target: if base {
                        OpenedLeafTargetV1::Base(0)
                    } else {
                        OpenedLeafTargetV1::Auxiliary(0)
                    },
                    index,
                    digest: joined_query_trace_leaf_v1(query, layout, domains, index, base)?,
                });
            }
        } else {
            for (group_index, (opening, descriptor)) in query
                .trace_groups
                .iter()
                .zip(&layout.trace_groups)
                .enumerate()
            {
                let next = (index + descriptor.next_stride(layout.common_lde_log2)?)
                    % layout.common_lde_size();
                let base_current =
                    canonical_fields_v1(&opening.base_current, descriptor.base_width)?;
                let base_next = canonical_fields_v1(
                    &opening.base_next,
                    layout.trace_layout.next_width_v1(descriptor.base_width),
                )?;
                let aux_current = canonical_fields_v1(&opening.aux_current, descriptor.aux_width)?;
                let aux_next = canonical_fields_v1(
                    &opening.aux_next,
                    layout.trace_layout.next_width_v1(descriptor.aux_width),
                )?;
                leaves.push(OpenedQueryLeafV1 {
                    target: OpenedLeafTargetV1::Base(group_index),
                    index,
                    digest: row_leaf_hash_v1(
                        domains.digest_context,
                        domains.base_leaf,
                        group_index,
                        index,
                        &base_current,
                    )?,
                });
                if layout.trace_layout == AggregateTraceLayoutV1::GroupedCurrentNext {
                    leaves.push(OpenedQueryLeafV1 {
                        target: OpenedLeafTargetV1::Base(group_index),
                        index: next,
                        digest: row_leaf_hash_v1(
                            domains.digest_context,
                            domains.base_leaf,
                            group_index,
                            next,
                            &base_next,
                        )?,
                    });
                }

                leaves.push(OpenedQueryLeafV1 {
                    target: OpenedLeafTargetV1::Auxiliary(group_index),
                    index,
                    digest: row_leaf_hash_v1(
                        domains.digest_context,
                        domains.aux_leaf,
                        group_index,
                        index,
                        &aux_current,
                    )?,
                });
                if layout.trace_layout == AggregateTraceLayoutV1::GroupedCurrentNext {
                    leaves.push(OpenedQueryLeafV1 {
                        target: OpenedLeafTargetV1::Auxiliary(group_index),
                        index: next,
                        digest: row_leaf_hash_v1(
                            domains.digest_context,
                            domains.aux_leaf,
                            group_index,
                            next,
                            &aux_next,
                        )?,
                    });
                }
            }
        }
        for lane in 0..parameters.security_lanes {
            let composition = canonical_fp4_fields_v1(
                &query.composition_values[lane],
                parameters.composition_degree_chunks,
            )?;
            leaves.push(OpenedQueryLeafV1 {
                target: OpenedLeafTargetV1::Composition(lane),
                index,
                digest: composition_leaf_hash_unchecked_v1(domains, lane, index, &composition)?,
            });
            let fri_mask = E::canonical(query.fri_mask_values[lane])
                .ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
            leaves.push(OpenedQueryLeafV1 {
                target: OpenedLeafTargetV1::FriMask(lane),
                index,
                digest: fri_mask_leaf_hash_v1(domains, lane, index, fri_mask)?,
            });
            let mut layer_index = index;
            let mut layer_size = layout.common_lde_size();
            for round in 0..fri_rounds {
                let opening = query.fri_lanes[lane].rounds[round];
                let low =
                    E::canonical(opening.low).ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
                let high =
                    E::canonical(opening.high).ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
                let half = layer_size / 2;
                let low_index = layer_index % half;
                leaves.push(OpenedQueryLeafV1 {
                    target: OpenedLeafTargetV1::Fri { lane, round },
                    index: low_index,
                    digest: match parameters.fri_commitment_layout {
                        AggregateFriCommitmentLayoutV1::Scalar => {
                            fri_leaf_hash_unchecked_v1(domains, lane, round, low_index, low)?
                        }
                        AggregateFriCommitmentLayoutV1::Paired => {
                            fri_pair_leaf_hash_v1(domains, lane, round, low_index, low, high)?
                        }
                    },
                });
                if parameters.fri_commitment_layout == AggregateFriCommitmentLayoutV1::Scalar {
                    leaves.push(OpenedQueryLeafV1 {
                        target: OpenedLeafTargetV1::Fri { lane, round },
                        index: low_index + half,
                        digest: fri_leaf_hash_unchecked_v1(
                            domains,
                            lane,
                            round,
                            low_index + half,
                            high,
                        )?,
                    });
                }
                layer_index = low_index;
                layer_size = half;
            }
        }
        Ok(())
    })();
    OpenedQueryHashesV1 { leaves, outcome }
}
/// Verify all base, auxiliary, composition, and non-terminal FRI multiproofs.
pub fn verify_all_merkle_openings_v1(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    layout: &AggregateProofLayoutV1,
    expected_indices: &[usize],
) -> Result<(), AggregateStarkErrorV1> {
    validate_proof_shape_v1(proof, parameters, layout)?;
    domains.validate()?;
    if expected_indices.len() != parameters.query_count {
        return Err(AggregateStarkErrorV1::TranscriptMismatch);
    }
    let mut base_leaves = (0..layout.trace_commitment_count_v1())
        .map(|_| BTreeMap::new())
        .collect::<Vec<_>>();
    let mut aux_leaves = (0..layout.trace_commitment_count_v1())
        .map(|_| BTreeMap::new())
        .collect::<Vec<_>>();
    let mut composition_leaves = (0..parameters.security_lanes)
        .map(|_| BTreeMap::new())
        .collect::<Vec<_>>();
    let mut fri_mask_leaves = (0..parameters.security_lanes)
        .map(|_| BTreeMap::new())
        .collect::<Vec<_>>();
    let fri_rounds = layout.fri_rounds(parameters)?;
    let mut fri_leaves = (0..parameters.security_lanes)
        .map(|_| (0..fri_rounds).map(|_| BTreeMap::new()).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    // Hash at most eight public query packages on the caller's Rayon pool.
    // Retain the original query/group/lane/round insertion order and first error.
    for (batch_number, queries) in proof.queries.chunks(OPENED_QUERY_HASH_BATCH_V1).enumerate() {
        let batch_start = batch_number * OPENED_QUERY_HASH_BATCH_V1;
        let hashed = queries
            .par_iter()
            .enumerate()
            .map(|(offset, query)| {
                hash_opened_query_leaves_v1(
                    query,
                    expected_indices.get(batch_start + offset).copied(),
                    parameters,
                    domains,
                    layout,
                    fri_rounds,
                )
            })
            .collect::<Vec<_>>();
        for query in hashed {
            for leaf in query.leaves {
                let (target, error_mapping) = match leaf.target {
                    OpenedLeafTargetV1::Base(group) => (&mut base_leaves[group], None),
                    OpenedLeafTargetV1::Auxiliary(group) => (&mut aux_leaves[group], None),
                    OpenedLeafTargetV1::Composition(lane) => (
                        &mut composition_leaves[lane],
                        Some(AggregateStarkErrorV1::ConstraintOpening),
                    ),
                    OpenedLeafTargetV1::FriMask(lane) => (
                        &mut fri_mask_leaves[lane],
                        Some(AggregateStarkErrorV1::FriOpening),
                    ),
                    OpenedLeafTargetV1::Fri { lane, round } => (
                        &mut fri_leaves[lane][round],
                        Some(AggregateStarkErrorV1::FriOpening),
                    ),
                };
                insert_opened_leaf_v1(target, leaf.index, leaf.digest)
                    .map_err(|error| error_mapping.unwrap_or(error))?;
            }
            query.outcome?;
        }
    }
    let mut jobs = Vec::new();
    for group in 0..layout.trace_commitment_count_v1() {
        jobs.push(MerkleVerificationJobV1 {
            node_role: domains.base_node,
            root: &proof.trace_groups[group].base_root,
            leaf_count: layout.common_lde_size(),
            leaves: &base_leaves[group],
            frontier: &proof.trace_groups[group].base_frontier,
            error_mapping: None,
        });
        jobs.push(MerkleVerificationJobV1 {
            node_role: domains.aux_node,
            root: &proof.trace_groups[group].aux_root,
            leaf_count: layout.common_lde_size(),
            leaves: &aux_leaves[group],
            frontier: &proof.trace_groups[group].aux_frontier,
            error_mapping: None,
        });
    }
    for lane in 0..parameters.security_lanes {
        jobs.push(MerkleVerificationJobV1 {
            node_role: domains.composition_node,
            root: &proof.composition_roots[lane],
            leaf_count: layout.common_lde_size(),
            leaves: &composition_leaves[lane],
            frontier: &proof.composition_frontiers[lane],
            error_mapping: Some(AggregateStarkErrorV1::ConstraintOpening),
        });
        jobs.push(MerkleVerificationJobV1 {
            node_role: FRI_MASK_NODE_DOMAIN_V1,
            root: &proof.fri_mask_roots[lane],
            leaf_count: layout.common_lde_size(),
            leaves: &fri_mask_leaves[lane],
            frontier: &proof.fri_mask_frontiers[lane],
            error_mapping: Some(AggregateStarkErrorV1::FriOpening),
        });
        for round in 0..fri_rounds {
            jobs.push(MerkleVerificationJobV1 {
                node_role: domains.fri_node,
                root: &proof.fri_lanes[lane].roots[round],
                leaf_count: parameters
                    .fri_commitment_layout
                    .leaf_count(layout.common_lde_size() >> round)?,
                leaves: &fri_leaves[lane][round],
                frontier: &proof.fri_lanes[lane].round_frontiers[round],
                error_mapping: Some(AggregateStarkErrorV1::FriOpening),
            });
        }
    }
    verify_merkle_jobs_v1(domains.digest_context, &jobs)
}
/// One independently checkable canonical Merkle multiproof.
struct MerkleVerificationJobV1<'a> {
    node_role: &'a [u8],
    root: &'a PrivacyOuterDigestV1,
    leaf_count: usize,
    leaves: &'a BTreeMap<usize, PrivacyOuterDigestV1>,
    frontier: &'a [PrivacyOuterDigestV1],
    error_mapping: Option<AggregateStarkErrorV1>,
}
/// Bound concurrent cloned frontier maps independently of the host worker count.
const MERKLE_VERIFICATION_BATCH_V1: usize = 8;
/// Check every multiproof in each bounded batch and return its first ordered error.
fn verify_merkle_jobs_v1(
    context: TransparentStarkDigestContextV1,
    jobs: &[MerkleVerificationJobV1<'_>],
) -> Result<(), AggregateStarkErrorV1> {
    for batch in jobs.chunks(MERKLE_VERIFICATION_BATCH_V1) {
        // Indexed parallel collection preserves the serial protocol order.
        // Do not use try_for_each: its first reported error depends on scheduling.
        let results = batch
            .par_iter()
            .map(|job| {
                verify_canonical_multiproof_v1(
                    context,
                    job.node_role,
                    job.root,
                    job.leaf_count,
                    job.leaves,
                    job.frontier,
                )
                .map_err(|error| job.error_mapping.unwrap_or(error))
            })
            .collect::<Vec<_>>();
        for result in results {
            result?;
        }
    }
    Ok(())
}
/// Verify and transcript-bind terminal FRI vectors, returning fold challenges.
pub fn verify_fri_commitments_v1(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    domains: &AggregateStarkDomainsV1,
    layout: &AggregateProofLayoutV1,
    transcript: &mut TransparentTranscriptV1,
) -> Result<(Vec<Vec<E>>, Vec<Vec<E>>), AggregateStarkErrorV1> {
    validate_proof_shape_v1(proof, parameters, layout)?;
    let fri_rounds = layout.fri_rounds(parameters)?;
    let mut all_betas = Vec::with_capacity(parameters.security_lanes);
    let mut all_terminals = Vec::with_capacity(parameters.security_lanes);
    for lane in 0..parameters.security_lanes {
        let lane_proof = &proof.fri_lanes[lane];
        let terminal =
            canonical_fp4_fields_v1(&lane_proof.terminal_values, parameters.terminal_size()?)?;
        let terminal_tree = fri_tree_v1(
            domains,
            parameters.fri_commitment_layout,
            lane,
            fri_rounds,
            &terminal,
        )?;
        if terminal_tree.root() != lane_proof.roots[fri_rounds] {
            return Err(AggregateStarkErrorV1::FriOpening);
        }
        ensure_fri_terminal_degree_fp4_v1(
            &terminal,
            parameters.terminal_log2,
            parameters.terminal_degree_bound,
        )
        .map_err(map_transparent_error_v1)?;
        let mut betas = Vec::with_capacity(fri_rounds);
        for round in 0..fri_rounds {
            absorb_fri_root_v1(transcript, domains, lane, round, &lane_proof.roots[round])?;
            betas.push(
                transcript
                    .challenge_fp4(domains.fri_beta_label)
                    .map_err(map_transparent_error_v1)?,
            );
        }
        absorb_fri_root_v1(
            transcript,
            domains,
            lane,
            fri_rounds,
            &lane_proof.roots[fri_rounds],
        )?;
        all_betas.push(betas);
        all_terminals.push(terminal);
    }
    Ok((all_betas, all_terminals))
}
fn verify_fri_query_v1(
    query_index: usize,
    expected_base: E,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    query: &AggregateFriLaneQueryV1,
    betas: &[E],
    terminal: &[E],
) -> Result<(), AggregateStarkErrorV1> {
    let fri_rounds = layout.fri_rounds(parameters)?;
    if betas.len() != fri_rounds
        || query.rounds.len() != fri_rounds
        || terminal.len() != parameters.terminal_size()?
    {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    let mut layer_index = query_index;
    let mut layer_size = layout.common_lde_size();
    let mut domain_shift = F(GOLDILOCKS_GENERATOR_V1);
    let mut domain_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).map_err(map_transparent_error_v1)?;
    let mut expected = expected_base;
    for round in 0..fri_rounds {
        let opening = query.rounds[round];
        let low = E::canonical(opening.low).ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
        let high = E::canonical(opening.high).ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
        let half = layer_size / 2;
        let low_index = layer_index % half;
        let selected = if layer_index < half { low } else { high };
        if selected != expected {
            return Err(AggregateStarkErrorV1::FriOpening);
        }
        let x = domain_shift.mul(domain_root.pow(low_index as u128));
        expected = fri_fold_pair_fp4_v1(low, high, betas[round], x)
            .map_err(|_| AggregateStarkErrorV1::FriOpening)?;
        layer_index = low_index;
        layer_size = half;
        domain_shift = domain_shift.mul(domain_shift);
        domain_root = domain_root.mul(domain_root);
    }
    if layer_size != parameters.terminal_size()?
        || terminal.get(layer_index).copied() != Some(expected)
    {
        return Err(AggregateStarkErrorV1::FriOpening);
    }
    Ok(())
}
/// Invoke the relation callback for every opened row and bind its results to FRI.
#[cfg(test)]
pub fn verify_opened_query_relations_v1<Evaluator: AggregateOpenedRowEvaluatorV1>(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    expected_indices: &[usize],
    fri_betas: &[Vec<E>],
    terminals: &[Vec<E>],
    evaluator: &mut Evaluator,
) -> Result<(), AggregateStarkErrorV1> {
    if layout.trace_layout != AggregateTraceLayoutV1::GroupedCurrentNext {
        // TODO: reduced query rows require a dedicated, complete-OODS-checked
        // relation entry point. A codec/commitment descriptor is insufficient.
        return Err(AggregateStarkErrorV1::ConstraintOpening);
    }
    validate_proof_shape_v1(proof, parameters, layout)?;
    if expected_indices.len() != parameters.query_count
        || fri_betas.len() != parameters.security_lanes
        || terminals.len() != parameters.security_lanes
    {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    for (position, query) in proof.queries.iter().enumerate() {
        let index =
            usize::try_from(query.index).map_err(|_| AggregateStarkErrorV1::TranscriptMismatch)?;
        if expected_indices.get(position).copied() != Some(index)
            || index >= layout.common_lde_size()
        {
            return Err(AggregateStarkErrorV1::TranscriptMismatch);
        }
        let opened_groups = query
            .trace_groups
            .iter()
            .zip(&layout.trace_groups)
            .map(|(opening, descriptor)| {
                Ok(AggregateOpenedTraceGroupV1 {
                    base_current: canonical_fields_v1(
                        &opening.base_current,
                        descriptor.base_width,
                    )?,
                    base_next: canonical_fields_v1(&opening.base_next, descriptor.base_width)?,
                    aux_current: canonical_fields_v1(&opening.aux_current, descriptor.aux_width)?,
                    aux_next: canonical_fields_v1(&opening.aux_next, descriptor.aux_width)?,
                })
            })
            .collect::<Result<Vec<_>, AggregateStarkErrorV1>>()?;
        for lane in 0..parameters.security_lanes {
            let composition_chunks = canonical_fp4_fields_v1(
                &query.composition_values[lane],
                parameters.composition_degree_chunks,
            )?;
            let lde_root = goldilocks_primitive_root_v1(layout.common_lde_log2)
                .map_err(map_transparent_error_v1)?;
            let x = F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(index as u128));
            let composition =
                recompose_composition_value_v1(&composition_chunks, x, parameters, layout)?;
            let expected = evaluator.evaluate_opened_row_v1(
                index,
                lane,
                &opened_groups,
                &composition_chunks,
            )?;
            if composition != expected.composition {
                return Err(AggregateStarkErrorV1::ConstraintOpening);
            }
            let fri_mask = E::canonical(query.fri_mask_values[lane])
                .ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
            verify_fri_query_v1(
                index,
                expected.fri_base.add(fri_mask),
                parameters,
                layout,
                &query.fri_lanes[lane],
                &fri_betas[lane],
                &terminals[lane],
            )?;
        }
    }
    Ok(())
}
/// Verify opened AIR constraints and the complete DEEP-ALI quotient before
/// binding every query to FRI.
///
/// The relation callback still recomputes the constraint quotient from the
/// authenticated current/next trace rows. The FRI base is no longer that raw
/// row mix: it is the verifier-computed random linear combination of all
/// current, next, and composition differences divided by `x - z`. Consequently
/// every encoded out-of-domain value is tied to a committed low-degree
/// polynomial, rather than being an unauthenticated transcript decoration.
#[allow(clippy::too_many_arguments)]
pub fn verify_opened_query_relations_with_deep_v1<Evaluator: AggregateOpenedRowEvaluatorV1>(
    proof: &AggregateStarkProofV1,
    deep: &AggregateDeepProofV1,
    deep_point: E,
    deep_mixes: &[AggregateDeepLaneMixV1],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    expected_indices: &[usize],
    fri_betas: &[Vec<E>],
    terminals: &[Vec<E>],
    evaluator: &mut Evaluator,
) -> Result<(), AggregateStarkErrorV1> {
    if layout.trace_layout != AggregateTraceLayoutV1::GroupedCurrentNext {
        // TODO: reduced query rows require a dedicated, complete-OODS-checked
        // relation entry point. A codec/commitment descriptor is insufficient.
        return Err(AggregateStarkErrorV1::ConstraintOpening);
    }
    verify_deep_query_bindings_v1(
        proof,
        deep,
        deep_point,
        deep_mixes,
        parameters,
        layout,
        expected_indices,
        fri_betas,
        terminals,
        Some(evaluator),
        &[],
    )
}
/// Bind every full DEEP trace/composition claim to authenticated current-only
/// query rows and the committed FRI polynomial after the relation has checked
/// its complete extension-field AIR at the transcript-derived DEEP point.
///
/// The caller must perform that complete relation check first. This entry is
/// restricted to an immutable reduced-row layout and cannot invoke a partial
/// scalar row callback as a substitute for the full OODS relation.
#[allow(clippy::too_many_arguments)]
pub fn verify_opened_query_relations_after_complete_oods_v1(
    proof: &AggregateStarkProofV1,
    deep: &AggregateDeepProofV1,
    deep_point: E,
    deep_mixes: &[AggregateDeepLaneMixV1],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    expected_indices: &[usize],
    fri_betas: &[Vec<E>],
    terminals: &[Vec<E>],
    supplemental: &[AggregateSupplementalDeepOpeningV1],
) -> Result<(), AggregateStarkErrorV1> {
    if layout.trace_layout == AggregateTraceLayoutV1::GroupedCurrentNext {
        return Err(AggregateStarkErrorV1::ConstraintOpening);
    }
    verify_deep_query_bindings_v1(
        proof,
        deep,
        deep_point,
        deep_mixes,
        parameters,
        layout,
        expected_indices,
        fri_betas,
        terminals,
        None,
        supplemental,
    )
}
#[allow(clippy::too_many_arguments)]
fn verify_deep_query_bindings_v1(
    proof: &AggregateStarkProofV1,
    deep: &AggregateDeepProofV1,
    deep_point: E,
    deep_mixes: &[AggregateDeepLaneMixV1],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    expected_indices: &[usize],
    fri_betas: &[Vec<E>],
    terminals: &[Vec<E>],
    mut evaluator: Option<&mut dyn AggregateOpenedRowEvaluatorV1>,
    supplemental: &[AggregateSupplementalDeepOpeningV1],
) -> Result<(), AggregateStarkErrorV1> {
    if (!supplemental.is_empty() && parameters.security_lanes != 1)
        || supplemental.iter().any(|opening| {
            opening.point == E::ZERO
                || !opening.point.is_canonical()
                || !opening.value.is_canonical()
                || !opening.mix.is_canonical()
                || layout
                    .trace_groups
                    .get(opening.group)
                    .is_none_or(|group| match opening.column {
                        AggregateSupplementalColumnV1::Base(column) => column >= group.base_width,
                        AggregateSupplementalColumnV1::Auxiliary(column) => {
                            column >= group.aux_width
                        }
                    })
        })
    {
        return Err(AggregateStarkErrorV1::DeepOpening);
    }
    validate_proof_shape_v1(proof, parameters, layout)?;
    validate_deep_proof_shape_v1(deep, parameters, layout)?;
    validate_deep_lane_mixes_v1(deep_mixes, parameters, layout)?;
    let deep_trace_groups = canonical_deep_trace_groups_v1(deep, parameters, layout)?;
    let deep_compositions = deep
        .composition_values
        .iter()
        .map(|values| canonical_fp4_fields_v1(values, parameters.composition_degree_chunks))
        .collect::<Result<Vec<_>, _>>()?;
    if expected_indices.len() != parameters.query_count
        || fri_betas.len() != parameters.security_lanes
        || terminals.len() != parameters.security_lanes
    {
        return Err(AggregateStarkErrorV1::InvalidProofShape);
    }
    let lde_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).map_err(map_transparent_error_v1)?;
    for (position, query) in proof.queries.iter().enumerate() {
        let index =
            usize::try_from(query.index).map_err(|_| AggregateStarkErrorV1::TranscriptMismatch)?;
        if expected_indices.get(position).copied() != Some(index)
            || index >= layout.common_lde_size()
        {
            return Err(AggregateStarkErrorV1::TranscriptMismatch);
        }
        let opened_groups = query
            .trace_groups
            .iter()
            .zip(&layout.trace_groups)
            .map(|(opening, descriptor)| {
                Ok(AggregateOpenedTraceGroupV1 {
                    base_current: canonical_fields_v1(
                        &opening.base_current,
                        descriptor.base_width,
                    )?,
                    base_next: canonical_fields_v1(
                        &opening.base_next,
                        layout.trace_layout.next_width_v1(descriptor.base_width),
                    )?,
                    aux_current: canonical_fields_v1(&opening.aux_current, descriptor.aux_width)?,
                    aux_next: canonical_fields_v1(
                        &opening.aux_next,
                        layout.trace_layout.next_width_v1(descriptor.aux_width),
                    )?,
                })
            })
            .collect::<Result<Vec<_>, AggregateStarkErrorV1>>()?;
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(index as u128));
        let query_point = E::from_base(x);
        for lane in 0..parameters.security_lanes {
            let composition_chunks = canonical_fp4_fields_v1(
                &query.composition_values[lane],
                parameters.composition_degree_chunks,
            )?;
            if let Some(evaluator) = evaluator.as_deref_mut() {
                let composition =
                    recompose_composition_value_v1(&composition_chunks, x, parameters, layout)?;
                let expected = evaluator.evaluate_opened_row_v1(
                    index,
                    lane,
                    &opened_groups,
                    &composition_chunks,
                )?;
                if composition != expected.composition {
                    return Err(AggregateStarkErrorV1::ConstraintOpening);
                }
            }
            let mut fri_base = deep_ali_mixed_opening_v1(
                query_point,
                deep_point,
                layout,
                &opened_groups,
                &deep_trace_groups,
                &composition_chunks,
                &deep_compositions[lane],
                &deep_mixes[lane],
            )?;
            for extra in supplemental {
                let value = opened_groups
                    .get(extra.group)
                    .and_then(|group| match extra.column {
                        AggregateSupplementalColumnV1::Base(column) => {
                            group.base_current.get(column)
                        }
                        AggregateSupplementalColumnV1::Auxiliary(column) => {
                            group.aux_current.get(column)
                        }
                    })
                    .copied()
                    .ok_or(AggregateStarkErrorV1::DeepOpening)?;
                let inverse = query_point
                    .sub(extra.point)
                    .inv()
                    .ok_or(AggregateStarkErrorV1::DeepOpening)?;
                fri_base = fri_base.add(
                    extra
                        .mix
                        .mul(E::from_base(value).sub(extra.value))
                        .mul(inverse),
                );
            }
            let fri_mask = E::canonical(query.fri_mask_values[lane])
                .ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
            verify_fri_query_v1(
                index,
                fri_base.add(fri_mask),
                parameters,
                layout,
                &query.fri_lanes[lane],
                &fri_betas[lane],
                &terminals[lane],
            )?;
        }
    }
    Ok(())
}
#[cfg(test)]
#[path = "aggregate_stark/reduced_trace_tests.rs"]
mod reduced_trace_tests;
#[cfg(test)]
#[path = "aggregate_stark/retained_polynomial_tests.rs"]
mod retained_polynomial_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng as _, rngs::StdRng};
    pub(super) const PARAMETERS: AggregateStarkParametersV1 = AggregateStarkParametersV1 {
        proof_magic: *b"AGG1",
        proof_version: 1,
        fri_commitment_layout: AggregateFriCommitmentLayoutV1::Scalar,
        security_lanes: 2,
        query_count: FASTPQ_QUERY_COUNT_V1 as usize,
        blowup_log2: 3,
        terminal_log2: 3,
        terminal_degree_bound: 3,
        composition_degree_chunks: 3,
        minimum_trace_log2: 8,
        maximum_trace_log2: 8,
        maximum_trace_groups: 4,
        maximum_segment_instances: 4,
        maximum_base_columns_per_instance: 4,
        maximum_aux_columns_per_instance: 4,
        maximum_proof_bytes: 1 << 20,
    };
    pub(super) const DOMAINS: AggregateStarkDomainsV1 = AggregateStarkDomainsV1 {
        digest_context: TransparentStarkDigestContextV1::new(
            PrivacyProtocolIdV1::PqMaspStarkV1,
            b"aggregate-test-profile-v1",
        ),
        base_leaf: b"aggregate-test-base-leaf",
        base_node: b"aggregate-test-base-node",
        aux_leaf: b"aggregate-test-aux-leaf",
        aux_node: b"aggregate-test-aux-node",
        composition_leaf: b"aggregate-test-composition-leaf",
        composition_node: b"aggregate-test-composition-node",
        fri_leaf: b"aggregate-test-fri-leaf",
        fri_node: b"aggregate-test-fri-node",
        layout_label: b"aggregate-test-layout-label",
        base_root_label: b"aggregate-test-base-root-label",
        aux_root_label: b"aggregate-test-aux-root-label",
        composition_root_label: b"aggregate-test-composition-root-label",
        fri_root_label: b"aggregate-test-fri-root-label",
        fri_beta_label: b"aggregate-test-fri-beta-label",
        query_seed: b"aggregate-test-query-seed",
    };
    fn assert_scalar_commitment_parity_v1(
        tree: PrivacyOuterMerkleTreeV1,
        leaves: Vec<PrivacyOuterDigestV1>,
        node: &'static [u8],
    ) {
        let expected = PrivacyOuterMerkleTreeV1::from_leaves(leaves, DOMAINS.digest_context, node)
            .expect("scalar leaf tree");
        assert_eq!(tree.root(), expected.root());
        for row in [0, 4095, 4096, 8191] {
            assert_eq!(
                tree.path(row).expect("path"),
                expected.path(row).expect("scalar path")
            );
        }
    }
    #[test]
    fn explicit_commitment_preparation_geometry_retains_payload_and_frame_bounds() {
        let limit = crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_FRAMES_V1;
        let budget = PRIVATE_ROW_PAYLOAD_BUDGET_BYTES_V1;
        let catalog = DOMAINS.digest_context.catalog_v1();
        let domain = DOMAINS
            .digest_context
            .domain_v1(&catalog, DOMAINS.base_leaf, b"vector-row-leaf", 0, 0, 0)
            .unwrap();
        for payload in [1, 512, 513, 4448] {
            let words = crate::privacy_engines::privacy_outer_hash::PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
                domain,
                &[payload],
            )
            .unwrap();
            let rows = private_row_preparation_rows_v1(domain, &[], payload, limit).unwrap();
            assert_eq!(
                rows,
                (budget / payload).min(limit).min(
                    crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_BYTES_V1
                        / words
                )
            );
            assert!(rows * payload <= budget);
            assert!(
                rows * words
                    <= crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_BYTES_V1
            );
        }
        assert_eq!(private_row_preparation_rows_v1(domain, &[], 8, 3), Ok(3));
        for payload in [budget, budget + 1] {
            assert_eq!(
                private_row_preparation_rows_v1(domain, &[], payload, limit),
                Err(AggregateStarkErrorV1::AllocationFailure)
            );
        }
        for (payload, cap) in [(0, limit), (8, 0), (8, limit + 1)] {
            assert_eq!(
                private_row_preparation_rows_v1(domain, &[], payload, cap),
                Err(AggregateStarkErrorV1::InvalidLayout)
            );
        }
    }

    #[test]
    fn explicit_commitment_556_column_geometry_bounds_cpu_preparation() {
        let context = TransparentStarkDigestContextV1::new(
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            b"atomic-private-settlement-stark-profile-v1",
        );
        let catalog = context.catalog_v1();
        let domain = context
            .domain_v1(
                &catalog,
                b"atomic-private-settlement-stark-base-leaf-v1",
                b"vector-row-leaf",
                0,
                0,
                0,
            )
            .unwrap();
        let group = 0_u16.to_be_bytes();
        let width = 556_u16.to_be_bytes();
        let payload_bytes = 556 * 8;
        let words = crate::privacy_engines::privacy_outer_hash::PrivacyOuterFrameV1::byte_count_for_field_lengths_v1(
            domain,
            &[group.len(), width.len(), payload_bytes],
        )
        .unwrap();
        assert_eq!(words, 4730, "actual APS byte-frame geometry");
        let rows = private_row_preparation_rows_v1(
            domain,
            &[&group, &width],
            payload_bytes,
            crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_FRAMES_V1,
        )
        .unwrap();
        assert_eq!(rows, 4096);
        assert_eq!(131_072_usize.div_ceil(rows), 32);
        assert!(rows * payload_bytes <= PRIVATE_ROW_PAYLOAD_BUDGET_BYTES_V1);
        assert!(
            rows * words
                <= crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_BYTES_V1
        );
        assert!(
            rows + 1
                > crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_FRAMES_V1
        );
    }

    #[test]
    fn explicit_commitment_small_preparation_chunks_preserve_scalar_root_and_paths() {
        let columns: Vec<Vec<F>> = (0..3)
            .map(|column| (0..8).map(|row| F(column * 101 + row * 17)).collect())
            .collect();
        let leaves = (0..8)
            .map(|row| {
                row_leaf_hash_v1(
                    DOMAINS.digest_context,
                    DOMAINS.base_leaf,
                    7,
                    row,
                    &row_at_v1(&columns, row).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let expected = PrivacyOuterMerkleTreeV1::from_leaves(
            leaves,
            DOMAINS.digest_context,
            DOMAINS.base_node,
        )
        .unwrap();
        let group = 7_u16.to_be_bytes();
        let width = 3_u16.to_be_bytes();
        for cap in [
            1,
            3,
            crate::privacy_engines::privacy_outer_hash::MAX_PRIVACY_OUTER_BATCH_FRAMES_V1,
        ] {
            let mut serialized = Vec::new();
            let tree = commit_serialized_rows_with_preparation_limit_v1(
                DOMAINS.digest_context,
                DOMAINS.base_leaf,
                DOMAINS.base_node,
                b"vector-row-leaf",
                0,
                7,
                &[&group, &width],
                8,
                24,
                cap,
                |row, bytes| {
                    serialized.push(row);
                    for column in &columns {
                        bytes.extend_from_slice(&column[row].0.to_be_bytes());
                    }
                },
            )
            .unwrap();
            assert_eq!(serialized, (0..8).collect::<Vec<_>>());
            assert_eq!(tree.root(), expected.root());
            for row in 0..8 {
                assert_eq!(tree.path(row).unwrap(), expected.path(row).unwrap());
            }
        }
    }

    #[test]
    fn explicit_commitment_rows_match_scalar_across_batch_boundary() {
        let columns = (0..3)
            .map(|column| {
                (0..8192)
                    .map(|row| F((column * 101 + row * 17) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let tree = row_tree_v1(
            DOMAINS.digest_context,
            DOMAINS.base_leaf,
            DOMAINS.base_node,
            7,
            &columns,
            8192,
        )
        .expect("batched rows");
        let leaves = (0..8192)
            .into_par_iter()
            .map(|row| {
                row_leaf_hash_v1(
                    DOMAINS.digest_context,
                    DOMAINS.base_leaf,
                    7,
                    row,
                    &row_at_v1(&columns, row).expect("row"),
                )
                .expect("scalar leaf")
            })
            .collect();
        assert_scalar_commitment_parity_v1(tree, leaves, DOMAINS.base_node);
    }
    #[test]
    fn explicit_commitment_composition_matches_scalar_across_batch_boundary() {
        let chunks = (0..3)
            .map(|column| {
                (0..8192)
                    .map(|row| E::canonical([row as u64, column + 1, 3, 7]).expect("field"))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let tree = composition_tree_v1(&DOMAINS, 3, &chunks).expect("batched composition");
        let leaves = (0..8192)
            .into_par_iter()
            .map(|row| {
                let values = chunks.iter().map(|chunk| chunk[row]).collect::<Vec<_>>();
                composition_leaf_hash_unchecked_v1(&DOMAINS, 3, row, &values)
                    .expect("scalar composition")
            })
            .collect();
        assert_scalar_commitment_parity_v1(tree, leaves, DOMAINS.composition_node);
    }
    #[test]
    fn explicit_commitment_fri_and_mask_match_scalar_across_batch_boundary() {
        let values = (0..8192)
            .map(|row| E::canonical([row, 2, 3, 7]).expect("field"))
            .collect::<Vec<_>>();
        let tree = fri_tree_v1(
            &DOMAINS,
            AggregateFriCommitmentLayoutV1::Scalar,
            3,
            5,
            &values,
        )
        .expect("batched FRI");
        let leaves = values
            .par_iter()
            .enumerate()
            .map(|(row, value)| {
                fri_leaf_hash_unchecked_v1(&DOMAINS, 3, 5, row, *value).expect("scalar FRI")
            })
            .collect();
        assert_scalar_commitment_parity_v1(tree, leaves, DOMAINS.fri_node);
        let tree = fri_mask_tree_v1(&DOMAINS, 3, &values).expect("batched mask");
        let leaves = values
            .par_iter()
            .enumerate()
            .map(|(row, value)| {
                fri_mask_leaf_hash_v1(&DOMAINS, 3, row, *value).expect("scalar mask")
            })
            .collect();
        assert_scalar_commitment_parity_v1(tree, leaves, FRI_MASK_NODE_DOMAIN_V1);
    }
    #[test]
    fn explicit_commitment_staging_rejects_invalid_geometry_and_payload_before_hashing() {
        for rows in [0, 3] {
            assert!(
                commit_serialized_rows_v1(
                    DOMAINS.digest_context,
                    DOMAINS.base_leaf,
                    DOMAINS.base_node,
                    b"vector-row-leaf",
                    0,
                    0,
                    &[],
                    rows,
                    8,
                    |_, _| panic!("must preflight")
                )
                .is_err()
            );
        }
        for bytes in [0, 32 * 1024 * 1024 + 1] {
            assert!(
                commit_serialized_rows_v1(
                    DOMAINS.digest_context,
                    DOMAINS.base_leaf,
                    DOMAINS.base_node,
                    b"vector-row-leaf",
                    0,
                    0,
                    &[],
                    2,
                    bytes,
                    |_, _| panic!("must preflight")
                )
                .is_err()
            );
        }
        assert!(
            commit_serialized_rows_v1(
                DOMAINS.digest_context,
                DOMAINS.base_leaf,
                DOMAINS.base_node,
                b"vector-row-leaf",
                0,
                0,
                &[],
                2,
                8,
                |_, bytes| bytes.push(0)
            )
            .is_err()
        );
        assert!(composition_tree_v1(&DOMAINS, usize::MAX, &[vec![E::ZERO; 2]]).is_err());
        assert!(
            fri_tree_v1(
                &DOMAINS,
                AggregateFriCommitmentLayoutV1::Scalar,
                0,
                usize::MAX,
                &[E::ZERO; 2]
            )
            .is_err()
        );
        assert!(fri_mask_tree_v1(&DOMAINS, 0, &[]).is_err());
    }

    pub(super) fn transcript() -> TransparentTranscriptV1 {
        let profile = PrivacyOuterDigestV1::from_bytes([7; 48]);
        let public = PrivacyOuterDigestV1::from_bytes([9; 48]);
        TransparentTranscriptV1::new(
            DOMAINS.digest_context,
            b"aggregate-test-suite",
            &profile,
            &public,
        )
        .expect("transcript")
    }
    fn mutate_digest_v1(digest: PrivacyOuterDigestV1) -> PrivacyOuterDigestV1 {
        let mut words = digest.to_bytes();
        words[0] ^= 1;
        PrivacyOuterDigestV1::from_bytes(words)
    }
    #[test]
    fn borrowed_domains_preserve_refusal_order_and_exact_transcript_framing() {
        let domains = DOMAINS;
        let original = domains;
        let mut actual = transcript();
        let initial_state = actual.state();
        let mut invalid = domains;
        invalid.digest_context = TransparentStarkDigestContextV1::new(
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            b"borrowed-domain-other-profile-v1",
        );
        invalid.query_seed = invalid.base_leaf;
        assert_eq!(
            absorb_base_roots_v1(&mut actual, &invalid, &[]),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        assert_eq!(actual.state(), initial_state);
        invalid.query_seed = domains.query_seed;
        assert_eq!(
            absorb_base_roots_v1(&mut actual, &invalid, &[]),
            Err(AggregateStarkErrorV1::TranscriptMismatch)
        );
        assert_eq!(actual.state(), initial_state);
        let root = PrivacyOuterDigestV1::from_bytes([11; 48]);
        let group = AggregateTraceGroupProofV1 {
            base_root: root,
            aux_root: PrivacyOuterDigestV1::from_bytes([13; 48]),
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        };
        absorb_base_roots_v1(&mut actual, &domains, &[group]).unwrap();
        let mut expected = transcript();
        expected
            .absorb(
                domains.base_root_label,
                &[&0_u16.to_be_bytes(), &root.to_bytes()],
            )
            .unwrap();
        assert_eq!(actual.state(), expected.state());
        assert_eq!(domains, original);
    }

    #[test]
    fn aggregate_domains_cannot_alias_fixed_core_roles() {
        assert!(DOMAINS.validate().is_ok());
        for reserved in AGGREGATE_STARK_RESERVED_DOMAINS_V1 {
            assert_eq!(
                AggregateStarkDomainsV1 {
                    query_seed: reserved,
                    ..DOMAINS
                }
                .validate(),
                Err(AggregateStarkErrorV1::InvalidLayout)
            );
        }
        let mut substituted = TransparentTranscriptV1::new(
            TransparentStarkDigestContextV1::new(
                PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
                b"aggregate-test-profile-v1",
            ),
            b"aggregate-test-suite",
            &PrivacyOuterDigestV1::from_bytes([7; 48]),
            &PrivacyOuterDigestV1::from_bytes([9; 48]),
        )
        .expect("substituted transcript");
        assert_eq!(
            absorb_layout_v1(
                &mut substituted,
                PARAMETERS,
                &DOMAINS,
                b"aggregate-test-relation-layout",
                &layout(),
            ),
            Err(AggregateStarkErrorV1::TranscriptMismatch)
        );
    }
    fn layout() -> AggregateProofLayoutV1 {
        AggregateProofLayoutV1::new(
            PARAMETERS,
            vec![AggregateTraceGroupLayoutV1 {
                native_trace_log2: 8,
                segment_instances: 1,
                base_width: 1,
                aux_width: 1,
            }],
        )
        .expect("layout")
    }
    fn release_fri_parameters_v1() -> AggregateStarkParametersV1 {
        AggregateStarkParametersV1 {
            proof_magic: *b"FRI2",
            proof_version: 1,
            fri_commitment_layout: AggregateFriCommitmentLayoutV1::Scalar,
            security_lanes: 1,
            query_count: FASTPQ_QUERY_COUNT_V1 as usize,
            blowup_log2: 3,
            terminal_log2: 10,
            terminal_degree_bound: 128,
            composition_degree_chunks: 4,
            minimum_trace_log2: 19,
            maximum_trace_log2: 19,
            maximum_trace_groups: 1,
            maximum_segment_instances: 1,
            maximum_base_columns_per_instance: 1,
            maximum_aux_columns_per_instance: 1,
            maximum_proof_bytes: 8 << 20,
        }
    }
    fn release_fri_layout_v1(parameters: AggregateStarkParametersV1) -> AggregateProofLayoutV1 {
        AggregateProofLayoutV1::new(
            parameters,
            vec![AggregateTraceGroupLayoutV1 {
                native_trace_log2: 19,
                segment_instances: 1,
                base_width: 1,
                aux_width: 1,
            }],
        )
        .expect("release FRI layout")
    }
    fn release_fri_certificate_v1() -> AggregateFriTheorem2CertificateV1 {
        AggregateFriTheorem2CertificateV1 {
            affine_coefficient_numerator: 3,
            affine_coefficient_denominator: 2,
            batching_parameter_m: 3,
            rho_numerator: 1,
            rho_denominator: 7,
            binary_fold_arity: 2,
            domain_log2: 22,
            extension_field_lower_bound_bits: 252,
            base_field_two_adicity: 32,
            trace_domains_are_smooth_subgroups: true,
            evaluation_domain_is_smooth_generator_coset: true,
            evaluation_domain_is_disjoint_from_trace_domains: true,
            fold_count: 12,
            terminal_log2: 10,
            terminal_degree_bound: 128,
            query_count: FASTPQ_QUERY_COUNT_V1 as u8,
            distinct_queries_without_replacement: true,
            uniform_rejection_sampling: true,
            claimed_query_error_bits: 160,
        }
    }
    #[test]
    fn affine_fri_bound_uses_every_binary_fold_and_rejects_uncovered_rates() {
        for folds in [3_u8, 4, 5, 6, 7, 12] {
            let native = folds + 7;
            let mut parameters = release_fri_parameters_v1();
            parameters.minimum_trace_log2 = native;
            parameters.maximum_trace_log2 = native;
            parameters.terminal_degree_bound = 143;
            let layout = AggregateProofLayoutV1::new(
                parameters,
                vec![AggregateTraceGroupLayoutV1 {
                    native_trace_log2: native,
                    segment_instances: 1,
                    base_width: 1,
                    aux_width: 1,
                }],
            );
            // At three/four folds the terminal cap cannot hold the existing
            // native-row plus 272-query-mask minimum. Five folds is the first
            // valid geometry; keep the smaller layouts as rejection controls.
            if folds < 5 {
                assert_eq!(layout, Err(AggregateStarkErrorV1::InvalidLayout));
                continue;
            }
            let layout = layout.expect("mask-admitted release FRI layout");
            let mut certificate = release_fri_certificate_v1();
            certificate.domain_log2 = native + 3;
            certificate.fold_count = folds;
            certificate.terminal_degree_bound = 143;
            let bound =
                validate_affine_batched_fri_theorem2_v1(parameters, &layout, certificate).unwrap();
            assert_eq!(
                bound.commitment_error_bits,
                252 - 2 * u16::from(native + 3) - 21
            );
            let mut wrong = certificate;
            wrong.binary_fold_arity = 3;
            assert!(validate_affine_batched_fri_theorem2_v1(parameters, &layout, wrong).is_err());
            wrong = certificate;
            wrong.fold_count += 1;
            assert!(validate_affine_batched_fri_theorem2_v1(parameters, &layout, wrong).is_err());
            parameters.terminal_degree_bound = 126;
            certificate.terminal_degree_bound = 126;
            assert!(
                validate_affine_batched_fri_theorem2_v1(parameters, &layout, certificate).is_err()
            );
        }
    }

    #[test]
    fn affine_batched_fri_theorem_certificate_checks_every_precondition() {
        let parameters = release_fri_parameters_v1();
        let layout = release_fri_layout_v1(parameters);
        let certificate = release_fri_certificate_v1();
        assert_eq!(
            validate_affine_batched_fri_theorem2_v1(parameters, &layout, certificate)
                .expect("canonical theorem certificate"),
            AggregateFriTheorem2BoundV1 {
                query_error_bits: 160,
                commitment_error_bits: 187,
            }
        );
        let mutations = [
            AggregateFriTheorem2CertificateV1 {
                affine_coefficient_numerator: 2,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                batching_parameter_m: 2,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                rho_denominator: 6,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                binary_fold_arity: 1,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                domain_log2: 24,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                extension_field_lower_bound_bits: 251,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                base_field_two_adicity: 24,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                trace_domains_are_smooth_subgroups: false,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                evaluation_domain_is_smooth_generator_coset: false,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                evaluation_domain_is_disjoint_from_trace_domains: false,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                fold_count: 11,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                terminal_log2: 9,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                terminal_degree_bound: 127,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                query_count: 128,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                distinct_queries_without_replacement: false,
                ..certificate
            },
            AggregateFriTheorem2CertificateV1 {
                uniform_rejection_sampling: false,
                ..certificate
            },
        ];
        for (index, mutation) in mutations.into_iter().enumerate() {
            assert!(
                validate_affine_batched_fri_theorem2_v1(parameters, &layout, mutation).is_err(),
                "theorem-precondition mutation {index} must fail closed"
            );
        }
        let weak_certificate = AggregateFriTheorem2CertificateV1 {
            claimed_query_error_bits: 161,
            ..certificate
        };
        assert!(
            validate_affine_batched_fri_theorem2_v1(parameters, &layout, weak_certificate).is_err(),
            "q=136 cannot substantiate a 161-bit query term"
        );
    }
    fn fixture() -> (
        AggregateProofLayoutV1,
        AggregateStarkProofV1,
        Vec<Vec<Vec<E>>>,
        Vec<Vec<E>>,
    ) {
        fixture_with_parameters(PARAMETERS)
    }
    pub(super) fn fixture_with_parameters(
        parameters: AggregateStarkParametersV1,
    ) -> (
        AggregateProofLayoutV1,
        AggregateStarkProofV1,
        Vec<Vec<Vec<E>>>,
        Vec<Vec<E>>,
    ) {
        let layout = layout();
        let rows = layout.common_lde_size();
        let base_lde = vec![(0..rows).map(|index| F(index as u64)).collect()];
        let aux_lde = vec![
            (0..rows)
                .map(|index| F((index as u64).wrapping_mul(3)))
                .collect(),
        ];
        let base_tree = row_tree_v1(
            DOMAINS.digest_context,
            DOMAINS.base_leaf,
            DOMAINS.base_node,
            0,
            &base_lde,
            rows,
        )
        .expect("base tree");
        let aux_tree = row_tree_v1(
            DOMAINS.digest_context,
            DOMAINS.aux_leaf,
            DOMAINS.aux_node,
            0,
            &aux_lde,
            rows,
        )
        .expect("aux tree");
        let mut group_proofs = vec![AggregateTraceGroupProofV1 {
            base_root: base_tree.root(),
            aux_root: aux_tree.root(),
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        }];
        let compositions = vec![
            vec![vec![E::ZERO; rows]; parameters.composition_degree_chunks];
            parameters.security_lanes
        ];
        let composition_trees = (0..parameters.security_lanes)
            .map(|lane| composition_tree_v1(&DOMAINS, lane, &compositions[lane]))
            .collect::<Result<Vec<_>, _>>()
            .expect("composition trees");
        let composition_roots = composition_trees
            .iter()
            .map(PrivacyOuterMerkleTreeV1::root)
            .collect::<Vec<_>>();
        let mut fri_mask_rng = StdRng::seed_from_u64(0x4652_494d_4153_4b31);
        let fri_masks = build_fri_mask_oracles_v1(parameters, &DOMAINS, &layout, &mut fri_mask_rng)
            .expect("FRI mask oracles");
        let fri_mask_roots = fri_masks
            .iter()
            .map(|mask| mask.tree.root())
            .collect::<Vec<_>>();
        let mut prover_transcript = transcript();
        absorb_layout_v1(
            &mut prover_transcript,
            parameters,
            &DOMAINS,
            b"aggregate-test-relation-layout",
            &layout,
        )
        .expect("layout absorption");
        absorb_base_roots_v1(&mut prover_transcript, &DOMAINS, &group_proofs)
            .expect("base absorption");
        absorb_aux_roots_v1(&mut prover_transcript, &DOMAINS, &group_proofs)
            .expect("aux absorption");
        absorb_composition_roots_v1(
            &mut prover_transcript,
            parameters,
            &DOMAINS,
            &composition_roots,
        )
        .expect("composition absorption");
        absorb_fri_mask_roots_v1(
            &mut prover_transcript,
            parameters,
            &DOMAINS,
            &fri_mask_roots,
        )
        .expect("FRI mask absorption");
        let fri_lanes = (0..parameters.security_lanes)
            .map(|lane| {
                let mut fri_base = vec![E::ZERO; rows];
                add_fri_mask_oracle_v1(&mut fri_base, &fri_masks[lane]).expect("add FRI mask");
                build_fri_lane_v1(
                    parameters,
                    &DOMAINS,
                    &layout,
                    lane,
                    fri_base,
                    &mut prover_transcript,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("FRI");
        let trace_material = vec![AggregateTraceGroupMaterialV1 {
            base_lde,
            aux_lde,
            base_tree,
            aux_tree,
        }];
        let query_positions = query_indices_v1(&prover_transcript, parameters, &DOMAINS, &layout)
            .expect("transcript-derived queries");
        let queries = query_positions
            .into_iter()
            .map(|index| {
                build_query_v1(
                    parameters,
                    &layout,
                    index,
                    &trace_material,
                    &compositions,
                    &fri_masks,
                    &fri_lanes,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("queries");
        let (trace_frontiers, composition_frontiers, fri_mask_frontiers, fri_frontiers) =
            build_all_frontiers_v1(
                parameters,
                &layout,
                &queries,
                &trace_material,
                &composition_trees,
                &fri_masks,
                &fri_lanes,
            )
            .expect("frontiers");
        for (proof, (base, aux)) in group_proofs.iter_mut().zip(trace_frontiers) {
            proof.base_frontier = base;
            proof.aux_frontier = aux;
        }
        let proof = AggregateStarkProofV1 {
            version: parameters.proof_version,
            trace_groups: group_proofs,
            composition_roots,
            composition_frontiers,
            fri_mask_roots,
            fri_mask_frontiers,
            fri_lanes: fri_lanes
                .into_iter()
                .zip(fri_frontiers)
                .map(|(lane, round_frontiers)| AggregateFriLaneProofV1 {
                    roots: lane.roots,
                    terminal_values: lane
                        .terminal_values
                        .into_iter()
                        .map(|value| value.coefficients().map(F::value))
                        .collect(),
                    round_frontiers,
                })
                .collect(),
            queries,
            grinding_nonce: 0,
        };
        (layout, proof, compositions, vec![vec![E::ZERO; rows]; 2])
    }
    pub(super) fn deep_fixture(layout: &AggregateProofLayoutV1) -> AggregateDeepProofV1 {
        let mut next_value = 1_u64;
        let mut values = |count: usize| {
            (0..count)
                .map(|_| {
                    let value = [
                        next_value,
                        next_value + 10_000,
                        next_value + 20_000,
                        next_value + 30_000,
                    ];
                    next_value += 1;
                    value
                })
                .collect::<Vec<_>>()
        };
        let trace_groups = layout
            .trace_groups
            .iter()
            .map(|group| AggregateDeepTraceGroupOpeningV1 {
                base_current: values(group.base_width),
                base_next: values(group.base_width),
                aux_current: values(group.aux_width),
                aux_next: values(group.aux_width),
            })
            .collect();
        let composition_values = (0..PARAMETERS.security_lanes)
            .map(|_| values(PARAMETERS.composition_degree_chunks))
            .collect();
        AggregateDeepProofV1 {
            trace_groups,
            composition_values,
        }
    }
    #[test]
    fn paired_fri_leaf_authenticates_both_values_and_context() {
        let values = (0..16)
            .map(|index| E::canonical([index, index + 1, 2, 3]).unwrap())
            .collect::<Vec<_>>();
        let mode = AggregateFriCommitmentLayoutV1::Paired;
        let tree = fri_tree_v1(&DOMAINS, mode, 3, 5, &values).unwrap();
        // Construct the framing independently of the pair-hash helper.
        let leaves = (0..8)
            .map(|index| {
                let payload = values[index]
                    .to_be_bytes()
                    .into_iter()
                    .chain(values[index + 8].to_be_bytes())
                    .collect::<Vec<_>>();
                privacy_outer_digest_frame_v1(
                    DOMAINS.digest_context,
                    DOMAINS.fri_leaf,
                    b"fri-layer-pair-leaf",
                    5,
                    index as u64,
                    3,
                    &[&3_u16.to_be_bytes(), &5_u16.to_be_bytes(), &payload],
                )
                .unwrap()
            })
            .collect();
        let expected =
            PrivacyOuterMerkleTreeV1::from_leaves(leaves, DOMAINS.digest_context, DOMAINS.fri_node)
                .unwrap();
        assert_eq!(tree.root(), expected.root());
        let indices = [0, 3, 7];
        let streamed =
            streaming_fri_commitment_v1(&DOMAINS, mode, 3, 5, &values, &indices).unwrap();
        assert_eq!(streamed.root, tree.root());
        assert_eq!(
            streamed.frontier,
            canonical_multiproof_frontier_v1(&tree, 8, &indices).unwrap()
        );
        let opening = fri_pair_leaf_hash_v1(&DOMAINS, 3, 5, 0, values[0], values[8]).unwrap();
        for altered in [
            fri_pair_leaf_hash_v1(&DOMAINS, 3, 5, 0, values[0].add(E::ONE), values[8]),
            fri_pair_leaf_hash_v1(&DOMAINS, 3, 5, 0, values[0], values[8].add(E::ONE)),
            fri_pair_leaf_hash_v1(&DOMAINS, 3, 5, 0, values[8], values[0]),
            fri_pair_leaf_hash_v1(&DOMAINS, 4, 5, 0, values[0], values[8]),
            fri_pair_leaf_hash_v1(&DOMAINS, 3, 6, 0, values[0], values[8]),
            fri_pair_leaf_hash_v1(&DOMAINS, 3, 5, 1, values[0], values[8]),
        ] {
            assert_ne!(opening, altered.unwrap());
        }
        for size in [0, 1, 3] {
            assert_eq!(
                fri_tree_v1(&DOMAINS, mode, 0, 0, &values[..size]).err(),
                Some(AggregateStarkErrorV1::InvalidLayout)
            );
            assert!(
                streaming_fri_commitment_v1(&DOMAINS, mode, 0, 0, &values[..size], &[]).is_err()
            );
        }
        assert!(fri_pair_leaf_hash_v1(&DOMAINS, usize::MAX, 0, 0, E::ZERO, E::ZERO).is_err());
        assert!(fri_pair_leaf_hash_v1(&DOMAINS, 0, usize::MAX, 0, E::ZERO, E::ZERO).is_err());
        let singleton = fri_tree_v1(&DOMAINS, mode, 0, 0, &values[..2]).unwrap();
        let leaf = fri_pair_leaf_hash_v1(&DOMAINS, 0, 0, 0, values[0], values[1]).unwrap();
        assert_eq!(singleton.root(), leaf);
        let streamed =
            streaming_fri_commitment_v1(&DOMAINS, mode, 0, 0, &values[..2], &[0]).unwrap();
        assert_eq!(streamed.root, leaf);
        assert!(streamed.frontier.is_empty());
        verify_canonical_multiproof_v1(
            DOMAINS.digest_context,
            DOMAINS.fri_node,
            &leaf,
            1,
            &BTreeMap::from([(0, leaf)]),
            &[],
        )
        .unwrap();
    }
    #[test]
    fn paired_fri_codec_and_verifier_have_no_scalar_fallback() {
        let parameters = AggregateStarkParametersV1 {
            fri_commitment_layout: AggregateFriCommitmentLayoutV1::Paired,
            ..PARAMETERS
        };
        let (layout, proof, _, _) = fixture_with_parameters(parameters);
        let indices = proof_query_indices_v1(&proof);
        verify_all_merkle_openings_v1(&proof, parameters, &DOMAINS, &layout, &indices).unwrap();
        let wire = encode_proof_v1(&proof, parameters, &layout).unwrap();
        let decoded = decode_proof_v1(&wire, parameters, &layout).unwrap();
        assert_eq!(decoded, proof);
        assert!(decode_proof_v1(&wire, PARAMETERS, &layout).is_err());
        let (_, scalar_proof, _, _) = fixture();
        let scalar_wire = encode_proof_v1(&scalar_proof, PARAMETERS, &layout).unwrap();
        assert!(decode_proof_v1(&scalar_wire, parameters, &layout).is_err());
        assert!(wire.len() < scalar_wire.len());
        for which in 0..4 {
            let mut changed = proof.clone();
            match which {
                0 => changed.queries[0].fri_lanes[0].rounds[0].low[0] ^= 1,
                1 => changed.queries[0].fri_lanes[0].rounds[0].high[0] ^= 1,
                2 => {
                    let pair = &mut changed.queries[0].fri_lanes[0].rounds[0];
                    core::mem::swap(&mut pair.low, &mut pair.high);
                }
                _ => changed.fri_lanes[0].roots[0] = PrivacyOuterDigestV1::default(),
            }
            assert_eq!(
                verify_all_merkle_openings_v1(&changed, parameters, &DOMAINS, &layout, &indices),
                Err(AggregateStarkErrorV1::FriOpening)
            );
        }
        let mut scalar_transcript = transcript();
        let mut paired_transcript = transcript();
        absorb_layout_v1(
            &mut scalar_transcript,
            PARAMETERS,
            &DOMAINS,
            b"same-relation",
            &layout,
        )
        .unwrap();
        absorb_layout_v1(
            &mut paired_transcript,
            parameters,
            &DOMAINS,
            b"same-relation",
            &layout,
        )
        .unwrap();
        assert_ne!(scalar_transcript.state(), paired_transcript.state());
    }
    fn proof_query_indices_v1(proof: &AggregateStarkProofV1) -> Vec<usize> {
        proof
            .queries
            .iter()
            .map(|query| usize::try_from(query.index).expect("fixture query fits usize"))
            .collect()
    }
    #[test]
    fn deep_point_exclusion_covers_trace_evaluation_query_and_next_domains() {
        let layout = layout();
        assert!(
            !deep_point_is_admissible_v1(E::ONE, PARAMETERS, &layout)
                .expect("trace-domain predicate")
        );
        let evaluation_shift = F(GOLDILOCKS_GENERATOR_V1);
        assert!(
            !deep_point_is_admissible_v1(E::from_base(evaluation_shift), PARAMETERS, &layout)
                .expect("evaluation-domain predicate")
        );
        let native_root = goldilocks_primitive_root_v1(layout.trace_groups[0].native_trace_log2)
            .expect("native root");
        let next_collision = evaluation_shift.mul(native_root.inv().expect("root inverse"));
        assert!(
            !deep_point_is_admissible_v1(E::from_base(next_collision), PARAMETERS, &layout)
                .expect("next-point predicate")
        );
        assert!(
            !deep_point_is_admissible_v1(E::ZERO, PARAMETERS, &layout)
                .expect("zero must not collapse translated DEEP points")
        );
        let mut transcript = transcript();
        let derived =
            derive_deep_point_v1(&mut transcript, PARAMETERS, &layout).expect("derived DEEP point");
        assert!(
            deep_point_is_admissible_v1(derived, PARAMETERS, &layout)
                .expect("derived-point predicate")
        );
    }
    #[test]
    fn deep_codec_is_exact_and_every_value_is_transcript_bound() {
        let (layout, proof, _, _) = fixture();
        let deep = deep_fixture(&layout);
        let bytes =
            encode_proof_with_deep_v1(&proof, &deep, PARAMETERS, &layout).expect("DEEP encoding");
        let (decoded_proof, decoded_deep) =
            decode_proof_with_deep_v1(&bytes, PARAMETERS, &layout).expect("DEEP decoding");
        assert_eq!(decoded_proof, proof);
        assert_eq!(decoded_deep, deep);
        assert_eq!(
            bytes.len(),
            exact_encoded_proof_with_deep_bytes_v1(&proof, &deep, PARAMETERS, &layout)
                .expect("exact DEEP wire length")
        );
        assert_eq!(
            bytes.len(),
            encode_proof_v1(&proof, PARAMETERS, &layout)
                .expect("base encoding")
                .len()
                + exact_deep_opening_bytes_v1(PARAMETERS, &layout)
                    .expect("exact DEEP payload length")
        );
        let insertion = deep_insertion_offset_v1(PARAMETERS, &layout).expect("DEEP offset");
        let deep_len = exact_deep_opening_bytes_v1(PARAMETERS, &layout).expect("DEEP bytes");
        let field_count = deep_len / core::mem::size_of::<[u64; 4]>();
        let mut canonical_transcript = transcript();
        let canonical_point = derive_deep_point_v1(&mut canonical_transcript, PARAMETERS, &layout)
            .expect("canonical point");
        absorb_deep_openings_v1(&mut canonical_transcript, &deep, PARAMETERS, &layout)
            .expect("canonical DEEP absorption");
        let canonical_state = canonical_transcript.state();
        for field in 0..field_count {
            let mut changed_bytes = bytes.clone();
            let coefficient_offset = insertion + field * core::mem::size_of::<[u64; 4]>();
            let coefficient = u64::from_be_bytes(
                changed_bytes[coefficient_offset..coefficient_offset + 8]
                    .try_into()
                    .expect("coefficient bytes"),
            );
            changed_bytes[coefficient_offset..coefficient_offset + 8]
                .copy_from_slice(&(coefficient + 1).to_be_bytes());
            let (_, changed_deep) = decode_proof_with_deep_v1(&changed_bytes, PARAMETERS, &layout)
                .expect("canonical changed DEEP field");
            let mut changed_transcript = transcript();
            assert_eq!(
                derive_deep_point_v1(&mut changed_transcript, PARAMETERS, &layout)
                    .expect("changed point"),
                canonical_point
            );
            absorb_deep_openings_v1(&mut changed_transcript, &changed_deep, PARAMETERS, &layout)
                .expect("changed DEEP absorption");
            assert_ne!(
                changed_transcript.state(),
                canonical_state,
                "DEEP field {field} must affect the transcript"
            );
        }
        let mut reordered = bytes.clone();
        let first = reordered[insertion..insertion + 32].to_vec();
        let second = reordered[insertion + 32..insertion + 64].to_vec();
        reordered[insertion..insertion + 32].copy_from_slice(&second);
        reordered[insertion + 32..insertion + 64].copy_from_slice(&first);
        let (_, reordered_deep) = decode_proof_with_deep_v1(&reordered, PARAMETERS, &layout)
            .expect("shape-preserving reorder decodes");
        let mut reordered_transcript = transcript();
        derive_deep_point_v1(&mut reordered_transcript, PARAMETERS, &layout)
            .expect("reordered point");
        absorb_deep_openings_v1(
            &mut reordered_transcript,
            &reordered_deep,
            PARAMETERS,
            &layout,
        )
        .expect("reordered absorption");
        assert_ne!(reordered_transcript.state(), canonical_state);
        let mut omitted = bytes.clone();
        omitted.drain(insertion..insertion + 32);
        assert!(decode_proof_with_deep_v1(&omitted, PARAMETERS, &layout).is_err());
        let mut duplicated = bytes.clone();
        duplicated.splice(
            insertion..insertion,
            bytes[insertion..insertion + 32].iter().copied(),
        );
        assert!(decode_proof_with_deep_v1(&duplicated, PARAMETERS, &layout).is_err());
        let mut noncanonical = bytes;
        noncanonical[insertion..insertion + 8].copy_from_slice(
            &crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1.to_be_bytes(),
        );
        assert_eq!(
            decode_proof_with_deep_v1(&noncanonical, PARAMETERS, &layout),
            Err(AggregateStarkErrorV1::NonCanonicalField)
        );
    }
    #[test]
    fn fp4_batch_inversion_is_exact_and_rejects_zero_or_empty_inputs() {
        let original = [
            E::canonical([3, 5, 7, 11]).expect("field"),
            E::canonical([13, 17, 19, 23]).expect("field"),
            E::canonical([29, 31, 37, 41]).expect("field"),
        ];
        let mut inverses = original;
        batch_invert_fp4_nonzero_v1(&mut inverses).expect("batch inversion");
        for (value, inverse) in original.into_iter().zip(inverses) {
            assert_eq!(value.mul(inverse), E::ONE);
        }
        assert_eq!(
            batch_invert_fp4_nonzero_v1(&mut []),
            Err(AggregateStarkErrorV1::DeepOpening)
        );
        let mut contains_zero = [E::ONE, E::ZERO];
        assert_eq!(
            batch_invert_fp4_nonzero_v1(&mut contains_zero),
            Err(AggregateStarkErrorV1::DeepOpening)
        );
    }
    pub(super) struct ZeroEvaluator;
    impl AggregateOpenedRowEvaluatorV1 for ZeroEvaluator {
        fn evaluate_opened_row_v1(
            &mut self,
            _query_index: usize,
            _lane: usize,
            _trace_groups: &[AggregateOpenedTraceGroupV1],
            _composition_chunks: &[E],
        ) -> Result<AggregateExpectedOpeningV1, AggregateStarkErrorV1> {
            Ok(AggregateExpectedOpeningV1 {
                composition: E::ZERO,
                fri_base: E::ZERO,
            })
        }
    }
    #[test]
    fn streaming_merkle_matches_materialized_tree_and_canonical_frontier() {
        let leaves = (0_u64..64)
            .map(|index| {
                privacy_outer_digest_frame_v1(
                    DOMAINS.digest_context,
                    b"aggregate-streaming-leaf",
                    b"test-leaf",
                    0,
                    index,
                    0,
                    &[&index.to_be_bytes()],
                )
                .expect("leaf")
            })
            .collect::<Vec<_>>();
        let tree = PrivacyOuterMerkleTreeV1::from_leaves(
            leaves.clone(),
            DOMAINS.digest_context,
            b"aggregate-streaming-node",
        )
        .expect("tree");
        for indices in [
            Vec::new(),
            vec![0],
            vec![63],
            vec![0, 1],
            vec![1, 2, 7, 19, 32, 62],
            (0..64).step_by(3).collect::<Vec<_>>(),
            (0..64).collect::<Vec<_>>(),
        ] {
            let streamed = streaming_merkle_commitment_v1(
                DOMAINS.digest_context,
                b"aggregate-streaming-node",
                leaves.len(),
                &indices,
                leaves.iter().copied().map(Ok),
            )
            .expect("streamed commitment");
            assert_eq!(streamed.root, tree.root());
            if indices.is_empty() {
                assert!(streamed.frontier.is_empty());
                continue;
            }
            assert_eq!(
                streamed.frontier,
                canonical_multiproof_frontier_v1(&tree, leaves.len(), &indices)
                    .expect("materialized frontier")
            );
            let opened = indices
                .iter()
                .copied()
                .map(|index| (index, leaves[index]))
                .collect::<BTreeMap<_, _>>();
            verify_canonical_multiproof_v1(
                DOMAINS.digest_context,
                b"aggregate-streaming-node",
                &streamed.root,
                leaves.len(),
                &opened,
                &streamed.frontier,
            )
            .expect("streaming frontier verifies");
        }
    }
    #[test]
    fn streaming_merkle_rejects_noncanonical_or_inexact_streams() {
        let leaves = (0_u64..8)
            .map(|index| {
                privacy_outer_digest_frame_v1(
                    DOMAINS.digest_context,
                    b"aggregate-streaming-hostile-leaf",
                    b"test-leaf",
                    0,
                    index,
                    0,
                    &[&index.to_be_bytes()],
                )
                .expect("leaf")
            })
            .collect::<Vec<_>>();
        for indices in [vec![1, 1], vec![2, 1], vec![8]] {
            assert!(
                StreamingMerkleAccumulatorV1::new(
                    DOMAINS.digest_context,
                    b"aggregate-streaming-hostile-node",
                    leaves.len(),
                    &indices,
                )
                .is_err()
            );
        }
        assert!(
            StreamingMerkleAccumulatorV1::new(DOMAINS.digest_context, b"", leaves.len(), &[],)
                .is_err()
        );
        assert!(
            StreamingMerkleAccumulatorV1::new(
                DOMAINS.digest_context,
                b"aggregate-streaming-hostile-node",
                leaves.len() - 1,
                &[],
            )
            .is_err()
        );
        let missing = streaming_merkle_commitment_v1(
            DOMAINS.digest_context,
            b"aggregate-streaming-hostile-node",
            leaves.len(),
            &[1],
            leaves[..leaves.len() - 1].iter().copied().map(Ok),
        );
        assert_eq!(missing, Err(AggregateStarkErrorV1::InvalidProofShape));
        let trailing = streaming_merkle_commitment_v1(
            DOMAINS.digest_context,
            b"aggregate-streaming-hostile-node",
            leaves.len(),
            &[1],
            leaves
                .iter()
                .copied()
                .chain(core::iter::once(leaves[0]))
                .map(Ok),
        );
        assert_eq!(trailing, Err(AggregateStarkErrorV1::InvalidProofShape));
    }
    #[test]
    fn column_streamed_vector_rows_match_exact_leaf_framing_and_openings() {
        let rows = 64;
        let columns = (0_u64..7)
            .map(|column| {
                (0_u64..u64::try_from(rows).expect("rows"))
                    .map(|row| F::reduce(u128::from(column + 3) * u128::from(row + 11)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let indices = vec![0, 1, 7, 31, 63];
        let tree = row_tree_v1(
            DOMAINS.digest_context,
            b"aggregate-streaming-row-leaf",
            b"aggregate-streaming-row-node",
            2,
            &columns,
            rows,
        )
        .expect("materialized row tree");
        let mut streamed = StreamingRowCommitmentV1::new(
            DOMAINS.digest_context,
            b"aggregate-streaming-row-leaf",
            b"aggregate-streaming-row-node",
            2,
            rows,
            columns.len(),
            &indices,
        )
        .expect("streaming row builder");
        for column in &columns {
            streamed.absorb_column(column).expect("column");
        }
        let result = streamed.finish().expect("streaming rows");
        assert_eq!(result.commitment.root, tree.root());
        assert_eq!(
            result.commitment.frontier,
            canonical_multiproof_frontier_v1(&tree, rows, &indices).expect("materialized frontier")
        );
        for index in indices {
            let expected = columns
                .iter()
                .map(|column| column[index])
                .collect::<Vec<_>>();
            assert_eq!(result.opened_rows.get(&index), Some(&expected));
            assert_eq!(
                row_leaf_hash_v1(
                    DOMAINS.digest_context,
                    b"aggregate-streaming-row-leaf",
                    2,
                    index,
                    result.opened_rows.get(&index).expect("opened row"),
                )
                .expect("leaf"),
                row_leaf_hash_v1(
                    DOMAINS.digest_context,
                    b"aggregate-streaming-row-leaf",
                    2,
                    index,
                    &expected,
                )
                .expect("reference leaf")
            );
        }
    }
    #[test]
    fn batched_streamed_rows_preserve_scalar_frames_frontiers_and_worker_parity() {
        let rows = 2048;
        let indices = [0, 1, 1023, 1024, 2047];
        for width in [1, 8, 11, 17] {
            let columns = (0..width)
                .map(|column| {
                    (0..rows)
                        .map(|row| match (row + column) % 3 {
                            0 => F::ZERO,
                            1 => F(
                                crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1
                                    - 1,
                            ),
                            _ => F((row * 31 + column * 17) as u64),
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            // Independent full-row framing does not use the incremental stream.
            let expected = row_tree_v1(
                DOMAINS.digest_context,
                DOMAINS.base_leaf,
                DOMAINS.base_node,
                65_535,
                &columns,
                rows,
            )
            .unwrap();
            let frontier = canonical_multiproof_frontier_v1(&expected, rows, &indices).unwrap();
            for threads in [1, 4] {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap()
                    .install(|| {
                        for batch_width in [1, MASKED_TRACE_LDE_COLUMN_BATCH_V1] {
                            let mut actual = StreamingRowCommitmentV1::new(
                                DOMAINS.digest_context,
                                DOMAINS.base_leaf,
                                DOMAINS.base_node,
                                65_535,
                                rows,
                                width,
                                &indices,
                            )
                            .unwrap();
                            for batch in columns.chunks(batch_width) {
                                actual.absorb_columns_v1(batch).unwrap();
                            }
                            let actual = actual.finish().unwrap();
                            assert_eq!(actual.commitment.root, expected.root());
                            assert_eq!(actual.commitment.frontier, frontier);
                            for index in indices {
                                assert_eq!(
                                    actual.opened_rows[&index],
                                    columns
                                        .iter()
                                        .map(|column| column[index])
                                        .collect::<Vec<_>>()
                                );
                            }
                        }
                    });
            }
        }
    }

    #[test]
    fn batched_streamed_rows_validate_all_columns_before_changing_state() {
        let rows = 8;
        let columns = vec![vec![F(3); rows], vec![F(7); rows]];
        let mut actual = StreamingRowCommitmentV1::new(
            DOMAINS.digest_context,
            DOMAINS.base_leaf,
            DOMAINS.base_node,
            0,
            rows,
            2,
            &[1],
        )
        .unwrap();
        assert_eq!(
            actual.absorb_columns_v1::<Vec<F>>(&[]),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        let too_many = vec![vec![F::ZERO; rows]; MASKED_TRACE_LDE_COLUMN_BATCH_V1 + 1];
        assert_eq!(
            actual.absorb_columns_v1(&too_many),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        let wrong_rows = vec![columns[0].clone(), vec![F(11); rows - 1]];
        assert_eq!(
            actual.absorb_columns_v1(&wrong_rows),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        let mut invalid = columns.clone();
        invalid[1][rows - 1] = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
        assert_eq!(
            actual.absorb_columns_v1(&invalid),
            Err(AggregateStarkErrorV1::NonCanonicalField)
        );
        assert_eq!(actual.received_columns, 0);
        assert!(!actual.failed);
        assert!(actual.opened_rows[&1].is_empty());
        actual.absorb_columns_v1(&columns).unwrap();
        assert_eq!(
            actual.absorb_columns_v1(&columns[..1]),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        let expected = row_tree_v1(
            DOMAINS.digest_context,
            DOMAINS.base_leaf,
            DOMAINS.base_node,
            0,
            &columns,
            rows,
        )
        .unwrap();
        assert_eq!(actual.finish().unwrap().commitment.root, expected.root());
    }

    #[test]
    fn batched_streamed_rows_poison_on_partial_hash_failure() {
        for threads in [1, 4] {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    let mut actual = StreamingRowCommitmentV1::new(
                        DOMAINS.digest_context,
                        DOMAINS.aux_leaf,
                        DOMAINS.aux_node,
                        0,
                        2048,
                        2,
                        &[0, 2047],
                    )
                    .unwrap();
                    // Internal corruption models an unexpected late hasher error.
                    // The public preflight succeeds; other row chunks may finish.
                    actual.digest_streams[1025].update(&[0; 8]).unwrap();
                    let columns = [vec![F(3); 2048], vec![F(5); 2048]];
                    assert!(actual.absorb_columns_v1(&columns).is_err());
                    assert!(actual.failed);
                    assert_eq!(actual.received_columns, 0);
                    assert!(actual.opened_rows.values().all(Vec::is_empty));
                    assert_eq!(
                        actual.absorb_columns_v1(&columns),
                        Err(AggregateStarkErrorV1::InvalidLayout)
                    );
                    assert_eq!(actual.finish(), Err(AggregateStarkErrorV1::InvalidLayout));
                });
        }
    }

    #[test]
    fn column_streamed_vector_rows_reject_shape_and_order_abuse() {
        assert!(
            StreamingRowCommitmentV1::new(
                DOMAINS.digest_context,
                b"aggregate-streaming-row-leaf",
                b"aggregate-streaming-row-node",
                0,
                8,
                2,
                &[2, 1],
            )
            .is_err()
        );
        let mut incomplete = StreamingRowCommitmentV1::new(
            DOMAINS.digest_context,
            b"aggregate-streaming-row-leaf",
            b"aggregate-streaming-row-node",
            0,
            8,
            2,
            &[1],
        )
        .expect("builder");
        assert_eq!(
            incomplete.absorb_column(&[F::ZERO; 7]),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        incomplete
            .absorb_column(&[F::ZERO; 8])
            .expect("first column");
        assert_eq!(
            incomplete.finish(),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        let mut overfull = StreamingRowCommitmentV1::new(
            DOMAINS.digest_context,
            b"aggregate-streaming-row-leaf",
            b"aggregate-streaming-row-node",
            0,
            8,
            1,
            &[],
        )
        .expect("builder");
        overfull.absorb_column(&[F::ZERO; 8]).expect("sole column");
        assert_eq!(
            overfull.absorb_column(&[F::ZERO; 8]),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
    }
    #[test]
    fn replayable_masked_column_commitment_matches_materialized_lde() {
        let native_columns = (0_u64..5)
            .map(|column| {
                (0_u64..8)
                    .map(|row| F::reduce(u128::from(column + 7) * u128::from(row + 13)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut rng = StdRng::from_seed([0x42; 32]);
        let (root_only, masks) = commit_masked_trace_columns_v1(
            DOMAINS.digest_context,
            b"aggregate-streaming-masked-leaf",
            b"aggregate-streaming-masked-node",
            3,
            3,
            6,
            native_columns.len(),
            7,
            &[],
            &mut rng,
            |column| Ok(native_columns[column].clone()),
        )
        .expect("initial masked commitment");
        let indices = [0, 1, 7, 31, 63];
        let replay = replay_masked_trace_columns_v1(
            DOMAINS.digest_context,
            b"aggregate-streaming-masked-leaf",
            b"aggregate-streaming-masked-node",
            3,
            &masks,
            &indices,
            |column| Ok(native_columns[column].clone()),
        )
        .expect("masked replay");
        assert_eq!(replay.commitment.root, root_only.commitment.root);
        let materialized = native_columns
            .iter()
            .zip(&masks.masks)
            .map(|(column, mask)| {
                masked_trace_lde_column_with_mask_v1(column, 3, 6, mask.coefficients())
                    .expect("materialized masked LDE")
            })
            .collect::<Vec<_>>();
        let tree = row_tree_v1(
            DOMAINS.digest_context,
            b"aggregate-streaming-masked-leaf",
            b"aggregate-streaming-masked-node",
            3,
            &materialized,
            64,
        )
        .expect("materialized tree");
        assert_eq!(replay.commitment.root, tree.root());
        assert_eq!(
            replay.commitment.frontier,
            canonical_multiproof_frontier_v1(&tree, 64, &indices).expect("materialized frontier")
        );
        for index in indices {
            assert_eq!(
                replay.opened_rows.get(&index),
                Some(
                    &materialized
                        .iter()
                        .map(|column| column[index])
                        .collect::<Vec<_>>()
                )
            );
        }
    }
    #[test]
    fn replayable_masked_column_commitment_rejects_shape_substitution() {
        let columns = [vec![F::ZERO; 8], vec![F::ONE; 8]];
        let mut rng = StdRng::from_seed([0x24; 32]);
        assert!(
            commit_masked_trace_columns_v1(
                DOMAINS.digest_context,
                b"aggregate-streaming-masked-leaf",
                b"aggregate-streaming-masked-node",
                0,
                3,
                6,
                columns.len(),
                7,
                &[],
                &mut rng,
                |column| Ok(columns[column][..7].to_vec()),
            )
            .is_err()
        );
        let (_, masks) = commit_masked_trace_columns_v1(
            DOMAINS.digest_context,
            b"aggregate-streaming-masked-leaf",
            b"aggregate-streaming-masked-node",
            0,
            3,
            6,
            columns.len(),
            7,
            &[],
            &mut rng,
            |column| Ok(columns[column].clone()),
        )
        .expect("commitment");
        assert_eq!(
            replay_masked_trace_columns_v1(
                DOMAINS.digest_context,
                b"aggregate-streaming-masked-leaf",
                b"aggregate-streaming-masked-node",
                0,
                &masks,
                &[2, 1],
                |column| Ok(columns[column].clone()),
            ),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        assert!(
            replay_masked_trace_columns_v1(
                DOMAINS.digest_context,
                b"aggregate-streaming-masked-leaf",
                b"aggregate-streaming-masked-node",
                0,
                &masks,
                &[1],
                |_column| Ok(vec![F::ZERO; 7]),
            )
            .is_err()
        );
    }
    #[test]
    fn retained_masked_polynomials_are_exact_commitment_coset_and_deep_replays() {
        let native_columns = (0_u64..3)
            .map(|column| {
                (0_u64..8)
                    .map(|row| F::reduce(u128::from(column + 11) * u128::from(row + 17) + 5))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let commitment_indices = [1, 9, 31];
        let mut replayable_rng = StdRng::from_seed([0xD1; 32]);
        let (replayable_commitment, masks) = commit_masked_trace_columns_v1(
            DOMAINS.digest_context,
            b"aggregate-retained-polynomial-leaf",
            b"aggregate-retained-polynomial-node",
            2,
            3,
            6,
            native_columns.len(),
            3,
            &commitment_indices,
            &mut replayable_rng,
            |column| Ok(native_columns[column].clone()),
        )
        .expect("replayable-mask commitment");
        let mut retained_rng = StdRng::from_seed([0xD1; 32]);
        let (retained_commitment, polynomials) = commit_masked_trace_polynomial_columns_v1(
            DOMAINS.digest_context,
            b"aggregate-retained-polynomial-leaf",
            b"aggregate-retained-polynomial-node",
            2,
            3,
            6,
            native_columns.len(),
            3,
            &commitment_indices,
            &mut retained_rng,
            |column| Ok(native_columns[column].clone()),
        )
        .expect("retained-polynomial commitment");
        assert_eq!(retained_commitment, replayable_commitment);
        assert_eq!(polynomials.width(), native_columns.len());
        assert_eq!(polynomials.native_trace_log2(), 3);
        assert_eq!(polynomials.commitment_lde_log2(), 6);
        for (column, mask) in masks.masks.iter().enumerate() {
            let expected = masked_trace_coefficients_with_mask_v1(
                &native_columns[column],
                3,
                mask.coefficients(),
            )
            .expect("reference coefficients");
            assert_eq!(
                polynomials
                    .column_coefficients_v1(column)
                    .expect("retained coefficients"),
                expected
            );
        }
        let replay_indices = [0, 7, 17, 63];
        let replayable = replay_masked_trace_columns_v1(
            DOMAINS.digest_context,
            b"aggregate-retained-polynomial-leaf",
            b"aggregate-retained-polynomial-node",
            2,
            &masks,
            &replay_indices,
            |column| Ok(native_columns[column].clone()),
        )
        .expect("mask replay");
        let retained = replay_masked_trace_polynomial_columns_v1(
            DOMAINS.digest_context,
            b"aggregate-retained-polynomial-leaf",
            b"aggregate-retained-polynomial-node",
            2,
            &polynomials,
            &replay_indices,
        )
        .expect("coefficient replay");
        assert_eq!(retained, replayable);
        assert_eq!(
            replay_masked_trace_polynomial_columns_v1(
                DOMAINS.digest_context,
                b"aggregate-retained-polynomial-leaf",
                b"aggregate-retained-polynomial-node",
                2,
                &polynomials,
                &[2, 1],
            ),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        let reduced_coset = polynomials
            .evaluate_columns_on_coset_v1(4)
            .expect("reduced quotient coset");
        for (column, mask) in masks.masks.iter().enumerate() {
            let expected = masked_trace_lde_column_with_mask_v1(
                &native_columns[column],
                3,
                4,
                mask.coefficients(),
            )
            .expect("reference reduced coset");
            assert_eq!(&*reduced_coset[column], &expected);
        }
        let point = E::canonical([7, 1, 2, 3]).expect("canonical extension point");
        let replayable_deep = evaluate_masked_native_columns_at_deep_v1(&masks, point, |column| {
            Ok(native_columns[column].clone())
        })
        .expect("mask DEEP values");
        let retained_deep =
            evaluate_masked_trace_polynomial_columns_at_deep_v1(&polynomials, point)
                .expect("retained DEEP values");
        assert_eq!(retained_deep, replayable_deep);
        assert_eq!(
            evaluate_masked_trace_polynomial_columns_at_deep_v1(&polynomials, E::ONE),
            Err(AggregateStarkErrorV1::DeepOpening)
        );
    }
    #[test]
    fn retained_polynomial_shape_and_secret_zeroizers_reject_mutation() {
        let columns = [vec![F::ONE; 8], vec![F(2); 8]];
        let mut rng = StdRng::from_seed([0xD4; 32]);
        let (_, mut polynomials) = commit_masked_trace_polynomial_columns_v1(
            DOMAINS.digest_context,
            b"aggregate-retained-mutation-leaf",
            b"aggregate-retained-mutation-node",
            0,
            3,
            6,
            columns.len(),
            3,
            &[],
            &mut rng,
            |column| Ok(columns[column].clone()),
        )
        .expect("retained polynomial set");
        polynomials.columns[1].0.pop();
        assert_eq!(
            replay_masked_trace_polynomial_columns_v1(
                DOMAINS.digest_context,
                b"aggregate-retained-mutation-leaf",
                b"aggregate-retained-mutation-node",
                0,
                &polynomials,
                &[],
            ),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        let mut base_values = vec![F(9), F(17), F(33)];
        zeroize_field_column_v1(&mut base_values);
        assert!(base_values.iter().all(|value| *value == F::ZERO));
        let mut extension_values = vec![
            E::canonical([1, 2, 3, 4]).expect("extension"),
            E::canonical([5, 6, 7, 8]).expect("extension"),
        ];
        zeroize_extension_field_column_v1(&mut extension_values);
        assert!(extension_values.iter().all(|value| *value == E::ZERO));
    }
    #[test]
    fn trace_vanishing_period_matches_every_scalar_coset_inverse() {
        for (trace_log2, coset_log2) in [(0, 1), (3, 5), (8, 11), (14, 17)] {
            let trace_size = 1_usize << trace_log2;
            let coset_size = 1_usize << coset_log2;
            let shift = F(GOLDILOCKS_GENERATOR_V1);
            let inverses = trace_vanishing_inverse_period_v1(trace_log2, coset_log2, shift)
                .expect("disjoint quotient coset");
            assert_eq!(inverses.len(), coset_size / trace_size);
            let root = goldilocks_primitive_root_v1(coset_log2).expect("coset root");
            let mut point = shift;
            for index in 0..coset_size {
                let denominator = point.pow(trace_size as u128).sub(F::ONE);
                let inverse = inverses[index % inverses.len()];
                assert_eq!(Some(inverse), denominator.inv(), "row {index}");
                assert_eq!(denominator.mul(inverse), F::ONE, "row {index}");
                point = point.mul(root);
            }
            assert_eq!(point, shift);
        }
    }
    #[test]
    fn trace_vanishing_period_rejects_invalid_geometry_and_cosets() {
        for (trace_log2, coset_log2) in [(3, 3), (4, 3), (0, 33), (33, 34), (255, 255)] {
            assert_eq!(
                trace_vanishing_inverse_period_v1(
                    trace_log2,
                    coset_log2,
                    F(GOLDILOCKS_GENERATOR_V1)
                ),
                Err(AggregateStarkErrorV1::InvalidLayout)
            );
        }
        for shift in [
            F::ZERO,
            F::ONE,
            goldilocks_primitive_root_v1(3).expect("trace subgroup"),
            goldilocks_primitive_root_v1(5).expect("expanded subgroup"),
        ] {
            assert_eq!(
                trace_vanishing_inverse_period_v1(3, 5, shift),
                Err(AggregateStarkErrorV1::InvalidLayout)
            );
        }
        let noncanonical = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1);
        assert_eq!(
            trace_vanishing_inverse_period_v1(3, 5, noncanonical),
            Err(AggregateStarkErrorV1::NonCanonicalField)
        );
    }
    #[test]
    fn reduced_quotient_coset_chunks_match_common_domain_and_exact_division() {
        let layout = layout();
        let quotient_log2 = 5;
        let quotient_size = 1_usize << quotient_log2;
        let quotient_root = goldilocks_primitive_root_v1(quotient_log2).expect("quotient root");
        let common_root =
            goldilocks_primitive_root_v1(layout.common_lde_log2).expect("common root");
        let quotient_coefficients = (0_u64..20)
            .map(|index| {
                E::canonical([index + 1, index * 3 + 2, index * 5 + 3, index * 7 + 4])
                    .expect("canonical quotient coefficient")
            })
            .collect::<Vec<_>>();
        let quotient_evaluations = goldilocks_fp4_evaluate_coset_v1(
            &quotient_coefficients,
            quotient_size,
            quotient_root,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("minimal quotient coset");
        let common_evaluations = goldilocks_fp4_evaluate_coset_v1(
            &quotient_coefficients,
            layout.common_lde_size(),
            common_root,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("common quotient coset");
        let expected = split_composition_evaluations_v1(&common_evaluations, PARAMETERS, &layout)
            .expect("legacy common-domain chunks");
        let reduced = composition_chunks_from_quotient_coset_v1(
            &quotient_evaluations,
            quotient_log2,
            quotient_coefficients.len() - 1,
            PARAMETERS,
            &layout,
        )
        .expect("reduced quotient chunks");
        assert_eq!(reduced, expected);
        let trace_log2 = 3;
        let trace_size = 1_usize << trace_log2;
        let mut numerator_coefficients = vec![E::ZERO; quotient_coefficients.len() + trace_size];
        for (degree, coefficient) in quotient_coefficients.iter().copied().enumerate() {
            numerator_coefficients[degree] = numerator_coefficients[degree].sub(coefficient);
            numerator_coefficients[degree + trace_size] =
                numerator_coefficients[degree + trace_size].add(coefficient);
        }
        assert_eq!(
            divide_extension_polynomial_by_trace_vanishing_v1(&numerator_coefficients, trace_log2,)
                .expect("exact polynomial division"),
            quotient_coefficients
        );
        let numerator_evaluations = goldilocks_fp4_evaluate_coset_v1(
            &numerator_coefficients,
            quotient_size,
            quotient_root,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("constraint numerator coset");
        assert_eq!(
            quotient_evaluations_from_constraint_coset_v1(
                &numerator_evaluations,
                trace_log2,
                quotient_log2,
            )
            .expect("pointwise quotient division"),
            quotient_evaluations
        );
        assert_eq!(
            composition_chunks_from_constraint_coset_v1(
                &numerator_evaluations,
                trace_log2,
                quotient_log2,
                quotient_coefficients.len() - 1,
                PARAMETERS,
                &layout,
            )
            .expect("constraint-to-composition chunks"),
            expected
        );
    }
    #[test]
    fn quotient_coset_rejects_tail_remainder_shape_and_adversarial_mutations() {
        let layout = layout();
        let quotient_log2 = 5;
        let quotient_size = 1_usize << quotient_log2;
        let quotient_root = goldilocks_primitive_root_v1(quotient_log2).expect("quotient root");
        let mut coefficients = (0_u64..20)
            .map(|index| E::from_base(F(index + 1)))
            .collect::<Vec<_>>();
        let evaluations = goldilocks_fp4_evaluate_coset_v1(
            &coefficients,
            quotient_size,
            quotient_root,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("quotient evaluations");
        coefficients.resize(quotient_size, E::ZERO);
        coefficients[20] = E::ONE;
        let forbidden_tail = goldilocks_fp4_evaluate_coset_v1(
            &coefficients,
            quotient_size,
            quotient_root,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("forbidden-tail evaluations");
        assert_eq!(
            composition_chunks_from_quotient_coset_v1(
                &forbidden_tail,
                quotient_log2,
                19,
                PARAMETERS,
                &layout,
            ),
            Err(AggregateStarkErrorV1::FriDegree)
        );
        let mut single_evaluation_mutation = evaluations.clone();
        single_evaluation_mutation[7] = single_evaluation_mutation[7].add(E::ONE);
        assert_eq!(
            composition_chunks_from_quotient_coset_v1(
                &single_evaluation_mutation,
                quotient_log2,
                19,
                PARAMETERS,
                &layout,
            ),
            Err(AggregateStarkErrorV1::FriDegree)
        );
        assert_eq!(
            composition_chunks_from_quotient_coset_v1(
                &evaluations[..quotient_size - 1],
                quotient_log2,
                19,
                PARAMETERS,
                &layout,
            ),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        assert_eq!(
            composition_chunks_from_quotient_coset_v1(
                &evaluations,
                quotient_log2,
                quotient_size,
                PARAMETERS,
                &layout,
            ),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        assert_eq!(
            composition_chunks_from_quotient_coset_v1(
                &vec![E::ZERO; 128],
                7,
                layout.maximum_composition_degree(PARAMETERS).expect("cap") + 1,
                PARAMETERS,
                &layout,
            ),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        assert_eq!(
            quotient_evaluations_from_constraint_coset_v1(
                &evaluations,
                quotient_log2,
                quotient_log2,
            ),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        assert_eq!(
            quotient_evaluations_from_constraint_coset_v1(
                &evaluations[..quotient_size - 1],
                3,
                quotient_log2,
            ),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        let trace_size = 8;
        let quotient_coefficients = coefficients[..20].to_vec();
        let mut numerator = vec![E::ZERO; quotient_coefficients.len() + trace_size];
        for (degree, coefficient) in quotient_coefficients.iter().copied().enumerate() {
            numerator[degree] = numerator[degree].sub(coefficient);
            numerator[degree + trace_size] = numerator[degree + trace_size].add(coefficient);
        }
        numerator[0] = numerator[0].add(E::ONE);
        assert_eq!(
            divide_extension_polynomial_by_trace_vanishing_v1(&numerator, 3),
            Err(AggregateStarkErrorV1::ConstraintOpening)
        );
        assert_eq!(
            divide_extension_polynomial_by_trace_vanishing_v1(&[E::ZERO; 8], 3),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
    }
    #[test]
    fn fri_fold_is_identical_across_rayon_widths() {
        let log2 = 14_u8;
        let values = (0_u64..(1_u64 << log2))
            .map(|index| {
                E::from_coefficients([
                    F::reduce(u128::from(index + 3) * 5),
                    F::reduce(u128::from(index + 7) * 11),
                    F::reduce(u128::from(index + 13) * 17),
                    F::reduce(u128::from(index + 19) * 23),
                ])
                .expect("canonical extension-field value")
            })
            .collect::<Vec<_>>();
        let beta =
            E::from_coefficients([F(29), F(31), F(37), F(41)]).expect("canonical FRI challenge");
        let domain_root = goldilocks_primitive_root_v1(log2).expect("FRI domain root");
        let run = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("private test thread pool")
                .install(|| {
                    fold_fri_layer_v1(&values, beta, F(GOLDILOCKS_GENERATOR_V1), domain_root)
                        .expect("FRI fold")
                })
        };
        let half = values.len() / 2;
        let inverse_root = domain_root.inv().expect("inverse FRI root");
        let mut inverse_x = F(GOLDILOCKS_GENERATOR_V1).inv().expect("inverse FRI shift");
        let expected = (0..half)
            .map(|index| {
                let folded = fri_fold_pair_with_inverse_x_fp4_v1(
                    values[index],
                    values[index + half],
                    beta,
                    inverse_x,
                )
                .expect("reference serial FRI fold");
                inverse_x = inverse_x.mul(inverse_root);
                folded
            })
            .collect::<Vec<_>>();
        assert_eq!(run(1), expected);
        assert_eq!(run(4), expected);
    }
    #[test]
    fn fri_fold_partial_batch_matches_serial_recurrence() {
        let log2 = 11_u8;
        let values = (0_u64..(1_u64 << log2))
            .map(|index| {
                E::from_coefficients([
                    F::reduce(u128::from(index + 3) * 5),
                    F::reduce(u128::from(index + 7) * 11),
                    F::reduce(u128::from(index + 13) * 17),
                    F::reduce(u128::from(index + 19) * 23),
                ])
                .expect("canonical extension-field value")
            })
            .collect::<Vec<_>>();
        let beta =
            E::from_coefficients([F(29), F(31), F(37), F(41)]).expect("canonical FRI challenge");
        let domain_root = goldilocks_primitive_root_v1(log2).expect("FRI domain root");
        let actual = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("private FRI pool")
            .install(|| {
                fold_fri_layer_v1(&values, beta, F(GOLDILOCKS_GENERATOR_V1), domain_root)
                    .expect("partial-batch FRI fold")
            });
        assert!(actual.len() < FRI_FOLD_PARALLEL_BATCH_ROWS_V1);
        let half = values.len() / 2;
        let inverse_root = domain_root.inv().expect("inverse FRI root");
        let mut inverse_x = F(GOLDILOCKS_GENERATOR_V1).inv().expect("inverse FRI shift");
        let expected = (0..half)
            .map(|index| {
                let folded = fri_fold_pair_with_inverse_x_fp4_v1(
                    values[index],
                    values[index + half],
                    beta,
                    inverse_x,
                )
                .expect("reference serial FRI fold");
                inverse_x = inverse_x.mul(inverse_root);
                folded
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
    #[test]
    fn secret_material_wipe_routines_cover_owned_columns_and_layers() {
        let mut base = ZeroizingFieldColumnV1(vec![F::ONE; 4]);
        base.zeroize_v1();
        assert!(base.iter().all(|value| *value == F::ZERO));
        let mut extension = ZeroizingExtensionFieldColumnV1(vec![E::ONE; 4]);
        extension.zeroize_v1();
        assert!(extension.iter().all(|value| *value == E::ZERO));
        let mut layers = ZeroizingExtensionFieldMatrixV1(vec![vec![E::ONE; 4]; 3]);
        layers.zeroize_v1();
        assert!(layers.iter().flatten().all(|value| *value == E::ZERO));
        assert!(core::mem::needs_drop::<AggregateTraceGroupMaterialV1>());
        assert!(core::mem::needs_drop::<AggregateFriMaskOracleMaterialV1>());
        assert!(core::mem::needs_drop::<AggregateFriLaneMaterialV1>());
        fn assert_clone<T: Clone>() {}
        assert_clone::<AggregateTraceGroupMaterialV1>();
        assert_clone::<AggregateFriLaneMaterialV1>();
    }
    #[test]
    fn streaming_composition_and_fri_match_materialized_commitments_and_openings() {
        for commitment_layout in [
            AggregateFriCommitmentLayoutV1::Scalar,
            AggregateFriCommitmentLayoutV1::Paired,
        ] {
            let parameters = AggregateStarkParametersV1 {
                fri_commitment_layout: commitment_layout,
                ..PARAMETERS
            };
            let layout = layout();
            let rows = layout.common_lde_size();
            let root =
                goldilocks_primitive_root_v1(layout.common_lde_log2).expect("common-domain root");
            let mut point = F(GOLDILOCKS_GENERATOR_V1);
            let values = (0..rows)
                .map(|_| {
                    let value = F(5).add(F(3).mul(point)).add(F(2).mul(point.mul(point)));
                    point = point.mul(root);
                    E::from_base(value)
                })
                .collect::<Vec<_>>();
            let indices = (0..parameters.query_count)
                .map(|index| index * 3 + 1)
                .collect::<Vec<_>>();
            let composition_chunks = vec![values.clone()];
            let composition_tree =
                composition_tree_v1(&DOMAINS, 0, &composition_chunks).expect("composition tree");
            let streamed_composition =
                streaming_composition_commitment_v1(&DOMAINS, 0, &composition_chunks, &indices)
                    .expect("streaming composition");
            assert_eq!(streamed_composition.root, composition_tree.root());
            assert_eq!(
                streamed_composition.frontier,
                canonical_multiproof_frontier_v1(&composition_tree, rows, &indices)
                    .expect("composition frontier")
            );
            let mut materialized_transcript = transcript();
            let materialized = build_fri_lane_v1(
                parameters,
                &DOMAINS,
                &layout,
                0,
                values.clone(),
                &mut materialized_transcript,
            )
            .expect("materialized FRI");
            let mut streaming_transcript = transcript();
            let streamed = build_streaming_fri_lane_v1(
                parameters,
                &DOMAINS,
                &layout,
                0,
                values.clone(),
                &mut streaming_transcript,
            )
            .expect("streaming FRI");
            assert_eq!(streamed.roots, materialized.roots);
            assert_eq!(streamed.terminal_values, materialized.terminal_values);
            assert_eq!(
                streaming_transcript.state(),
                materialized_transcript.state()
            );
            let openings = open_streaming_fri_lane_v1(
                parameters, &DOMAINS, &layout, 0, values, &streamed, &indices,
            )
            .expect("streaming FRI openings");
            let rounds = layout.fri_rounds(parameters).expect("FRI rounds");
            let mut layer_indices = indices.clone();
            for round in 0..rounds {
                let half = materialized.layers[round].len() / 2;
                let opening_indices = layer_indices
                    .iter()
                    .flat_map(|index| {
                        let low = *index % half;
                        match commitment_layout {
                            AggregateFriCommitmentLayoutV1::Scalar => vec![low, low + half],
                            AggregateFriCommitmentLayoutV1::Paired => vec![low],
                        }
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                assert_eq!(
                    openings.round_frontiers[round],
                    canonical_multiproof_frontier_v1(
                        &materialized.trees[round],
                        commitment_layout
                            .leaf_count(materialized.layers[round].len())
                            .unwrap(),
                        &opening_indices,
                    )
                    .expect("materialized FRI frontier")
                );
                for (position, index) in layer_indices.iter_mut().enumerate() {
                    let low = *index % half;
                    assert_eq!(
                        openings.queries[position].rounds[round],
                        AggregateFriRoundOpeningV1 {
                            low: materialized.layers[round][low].coefficients().map(F::value),
                            high: materialized.layers[round][low + half]
                                .coefficients()
                                .map(F::value),
                        }
                    );
                    *index = low;
                }
            }
        }
    }
    #[test]
    fn streaming_fri_replay_rejects_material_and_query_substitution() {
        let layout = layout();
        let root =
            goldilocks_primitive_root_v1(layout.common_lde_log2).expect("common-domain root");
        let mut point = F(GOLDILOCKS_GENERATOR_V1);
        let values = (0..layout.common_lde_size())
            .map(|_| {
                let value = F(5).add(F(3).mul(point)).add(F(2).mul(point.mul(point)));
                point = point.mul(root);
                E::from_base(value)
            })
            .collect::<Vec<_>>();
        let mut prover_transcript = transcript();
        let material = build_streaming_fri_lane_v1(
            PARAMETERS,
            &DOMAINS,
            &layout,
            0,
            values.clone(),
            &mut prover_transcript,
        )
        .expect("streaming FRI");
        let indices = (0..PARAMETERS.query_count)
            .map(|index| index * 3 + 1)
            .collect::<Vec<_>>();
        let mut changed = material.clone();
        changed.roots[0] = mutate_digest_v1(changed.roots[0]);
        assert!(
            open_streaming_fri_lane_v1(
                PARAMETERS,
                &DOMAINS,
                &layout,
                0,
                values.clone(),
                &changed,
                &indices,
            )
            .is_err()
        );
        changed = material.clone();
        changed.betas[0] = changed.betas[0].add(E::ONE);
        assert!(
            open_streaming_fri_lane_v1(
                PARAMETERS,
                &DOMAINS,
                &layout,
                0,
                values.clone(),
                &changed,
                &indices,
            )
            .is_err()
        );
        changed = material.clone();
        changed.terminal_values[0] = E::ONE;
        assert!(
            open_streaming_fri_lane_v1(
                PARAMETERS,
                &DOMAINS,
                &layout,
                0,
                values.clone(),
                &changed,
                &indices,
            )
            .is_err()
        );
        let mut missing = indices.clone();
        missing.pop();
        let mut duplicate = indices.clone();
        let first = duplicate[0];
        *duplicate.last_mut().expect("nonempty query fixture") = first;
        let mut out_of_range = indices.clone();
        *out_of_range.last_mut().expect("nonempty query fixture") = layout.common_lde_size();
        for hostile in [missing, duplicate, out_of_range] {
            assert!(
                open_streaming_fri_lane_v1(
                    PARAMETERS,
                    &DOMAINS,
                    &layout,
                    0,
                    values.clone(),
                    &material,
                    &hostile,
                )
                .is_err()
            );
        }
    }

    fn opened_leaf_fixture_v1() -> &'static (AggregateProofLayoutV1, AggregateStarkProofV1) {
        static FIXTURE: std::sync::OnceLock<(AggregateProofLayoutV1, AggregateStarkProofV1)> =
            std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            let (layout, proof, _, _) = fixture();
            (layout, proof)
        })
    }

    #[test]
    fn opened_query_hashes_match_sequential_bytes_and_bound_each_batch() {
        let (layout, proof) = opened_leaf_fixture_v1();
        let indices = proof_query_indices_v1(proof);
        let rounds = layout.fri_rounds(PARAMETERS).expect("fixture rounds");
        let count = OPENED_QUERY_HASH_BATCH_V1 + 1;
        assert!(proof.queries.len() >= count);
        let sequential = proof.queries[..count]
            .iter()
            .enumerate()
            .map(|(position, query)| {
                hash_opened_query_leaves_v1(
                    query,
                    Some(indices[position]),
                    PARAMETERS,
                    &DOMAINS,
                    layout,
                    rounds,
                )
            })
            .collect::<Vec<_>>();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .expect("eight-worker pool");
        let mut parallel = Vec::new();
        for (batch_number, queries) in proof.queries[..count]
            .chunks(OPENED_QUERY_HASH_BATCH_V1)
            .enumerate()
        {
            assert!(queries.len() <= 8);
            let batch_start = batch_number * OPENED_QUERY_HASH_BATCH_V1;
            let batch = pool.install(|| {
                queries
                    .par_iter()
                    .enumerate()
                    .map(|(offset, query)| {
                        hash_opened_query_leaves_v1(
                            query,
                            Some(indices[batch_start + offset]),
                            PARAMETERS,
                            &DOMAINS,
                            layout,
                            rounds,
                        )
                    })
                    .collect::<Vec<_>>()
            });
            parallel.extend(batch);
        }
        assert_eq!(parallel, sequential);
        let expected_per_query =
            layout.trace_groups.len() * 4 + PARAMETERS.security_lanes * (2 + 2 * rounds);
        for query in &parallel {
            assert_eq!(query.outcome, Ok(()));
            assert_eq!(query.leaves.len(), expected_per_query);
        }
        assert!(
            parallel
                .iter()
                .flat_map(|query| &query.leaves)
                .any(|leaf| matches!(leaf.target, OpenedLeafTargetV1::Base(_)))
        );
        assert!(
            parallel
                .iter()
                .flat_map(|query| &query.leaves)
                .any(|leaf| matches!(leaf.target, OpenedLeafTargetV1::Auxiliary(_)))
        );
        assert!(
            parallel
                .iter()
                .flat_map(|query| &query.leaves)
                .any(|leaf| matches!(leaf.target, OpenedLeafTargetV1::Composition(_)))
        );
        assert!(
            parallel
                .iter()
                .flat_map(|query| &query.leaves)
                .any(|leaf| matches!(leaf.target, OpenedLeafTargetV1::FriMask(_)))
        );
        assert!(
            parallel
                .iter()
                .flat_map(|query| &query.leaves)
                .any(|leaf| matches!(leaf.target, OpenedLeafTargetV1::Fri { .. }))
        );
    }

    #[test]
    fn opened_leaf_parallel_verifier_matches_original_on_valid_and_malformed_proofs() {
        let (layout, proof) = opened_leaf_fixture_v1();
        let indices = proof_query_indices_v1(proof);
        let pools = [1, 8].map(|threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("verifier test pool")
        });
        let compare =
            |candidate: &AggregateStarkProofV1, expected_indices: &[usize], expected_error| {
                let original = verify_all_merkle_openings_serial_reference_v1(
                    candidate,
                    PARAMETERS,
                    &DOMAINS,
                    layout,
                    expected_indices,
                );
                assert_eq!(original, expected_error);
                for pool in &pools {
                    assert_eq!(
                        pool.install(|| verify_all_merkle_openings_v1(
                            candidate,
                            PARAMETERS,
                            &DOMAINS,
                            layout,
                            expected_indices,
                        )),
                        original
                    );
                }
            };
        compare(proof, &indices, Ok(()));
        compare(
            proof,
            &indices[..indices.len() - 1],
            Err(AggregateStarkErrorV1::TranscriptMismatch),
        );
        let mut wrong_indices = indices.clone();
        wrong_indices[0] = (wrong_indices[0] + 1) % layout.common_lde_size();
        compare(
            proof,
            &wrong_indices,
            Err(AggregateStarkErrorV1::TranscriptMismatch),
        );
        let mut changed = proof.clone();
        changed.queries[0].trace_groups[0].base_current.pop();
        compare(
            &changed,
            &wrong_indices,
            Err(AggregateStarkErrorV1::InvalidProofShape),
        );
        let mut changed = proof.clone();
        changed.queries.last_mut().expect("queries").fri_lanes[0].rounds[0].high[0] =
            crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;
        compare(
            &changed,
            &wrong_indices,
            Err(AggregateStarkErrorV1::NonCanonicalField),
        );
    }

    #[test]
    fn opened_leaf_duplicate_error_precedes_a_later_parallel_query_error() {
        let (layout, proof) = opened_leaf_fixture_v1();
        let indices = proof_query_indices_v1(proof);
        let rounds = layout.fri_rounds(PARAMETERS).expect("rounds");
        let round = rounds - 1;
        let half = layout.common_lde_size() >> (round + 1);
        let mut seen = BTreeSet::new();
        let duplicate_position = proof
            .queries
            .iter()
            .enumerate()
            .find_map(|(position, query)| {
                let low_index = usize::try_from(query.index).expect("fixture index") % half;
                (!seen.insert(low_index)).then_some(position)
            })
            .expect("more queries than final low indices guarantee a duplicate");
        assert!(duplicate_position + 1 < proof.queries.len());
        let mut changed = proof.clone();
        let value = &mut changed.queries[duplicate_position].fri_lanes[0].rounds[round].low[0];
        *value = F::canonical(*value)
            .expect("canonical original")
            .add(F::ONE)
            .value();
        let mut changed_indices = indices;
        changed_indices[duplicate_position + 1] =
            (changed_indices[duplicate_position + 1] + 1) % layout.common_lde_size();
        assert_eq!(
            verify_all_merkle_openings_serial_reference_v1(
                &changed,
                PARAMETERS,
                &DOMAINS,
                layout,
                &changed_indices,
            ),
            Err(AggregateStarkErrorV1::FriOpening)
        );
        for threads in [1, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("pool");
            assert_eq!(
                pool.install(|| verify_all_merkle_openings_v1(
                    &changed,
                    PARAMETERS,
                    &DOMAINS,
                    layout,
                    &changed_indices,
                )),
                Err(AggregateStarkErrorV1::FriOpening)
            );
        }
    }

    fn verify_all_merkle_openings_serial_reference_v1(
        proof: &AggregateStarkProofV1,
        parameters: AggregateStarkParametersV1,
        domains: &AggregateStarkDomainsV1,
        layout: &AggregateProofLayoutV1,
        expected_indices: &[usize],
    ) -> Result<(), AggregateStarkErrorV1> {
        validate_proof_shape_v1(proof, parameters, layout)?;
        domains.validate()?;
        if expected_indices.len() != parameters.query_count {
            return Err(AggregateStarkErrorV1::TranscriptMismatch);
        }
        let mut base_leaves = (0..layout.trace_groups.len())
            .map(|_| BTreeMap::new())
            .collect::<Vec<_>>();
        let mut aux_leaves = (0..layout.trace_groups.len())
            .map(|_| BTreeMap::new())
            .collect::<Vec<_>>();
        let mut composition_leaves = (0..parameters.security_lanes)
            .map(|_| BTreeMap::new())
            .collect::<Vec<_>>();
        let mut fri_mask_leaves = (0..parameters.security_lanes)
            .map(|_| BTreeMap::new())
            .collect::<Vec<_>>();
        let fri_rounds = layout.fri_rounds(parameters)?;
        let mut fri_leaves = (0..parameters.security_lanes)
            .map(|_| (0..fri_rounds).map(|_| BTreeMap::new()).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        for (position, query) in proof.queries.iter().enumerate() {
            let index = usize::try_from(query.index)
                .map_err(|_| AggregateStarkErrorV1::TranscriptMismatch)?;
            if expected_indices.get(position).copied() != Some(index)
                || index >= layout.common_lde_size()
            {
                return Err(AggregateStarkErrorV1::TranscriptMismatch);
            }
            for (group_index, (opening, descriptor)) in query
                .trace_groups
                .iter()
                .zip(&layout.trace_groups)
                .enumerate()
            {
                let next = (index + descriptor.next_stride(layout.common_lde_log2)?)
                    % layout.common_lde_size();
                let base_current =
                    canonical_fields_v1(&opening.base_current, descriptor.base_width)?;
                let base_next = canonical_fields_v1(&opening.base_next, descriptor.base_width)?;
                let aux_current = canonical_fields_v1(&opening.aux_current, descriptor.aux_width)?;
                let aux_next = canonical_fields_v1(&opening.aux_next, descriptor.aux_width)?;
                insert_opened_leaf_v1(
                    &mut base_leaves[group_index],
                    index,
                    row_leaf_hash_v1(
                        domains.digest_context,
                        domains.base_leaf,
                        group_index,
                        index,
                        &base_current,
                    )?,
                )?;
                insert_opened_leaf_v1(
                    &mut base_leaves[group_index],
                    next,
                    row_leaf_hash_v1(
                        domains.digest_context,
                        domains.base_leaf,
                        group_index,
                        next,
                        &base_next,
                    )?,
                )?;
                insert_opened_leaf_v1(
                    &mut aux_leaves[group_index],
                    index,
                    row_leaf_hash_v1(
                        domains.digest_context,
                        domains.aux_leaf,
                        group_index,
                        index,
                        &aux_current,
                    )?,
                )?;
                insert_opened_leaf_v1(
                    &mut aux_leaves[group_index],
                    next,
                    row_leaf_hash_v1(
                        domains.digest_context,
                        domains.aux_leaf,
                        group_index,
                        next,
                        &aux_next,
                    )?,
                )?;
            }
            for lane in 0..parameters.security_lanes {
                let composition = canonical_fp4_fields_v1(
                    &query.composition_values[lane],
                    parameters.composition_degree_chunks,
                )?;
                insert_opened_leaf_v1(
                    &mut composition_leaves[lane],
                    index,
                    composition_leaf_hash_unchecked_v1(domains, lane, index, &composition)?,
                )
                .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
                let fri_mask = E::canonical(query.fri_mask_values[lane])
                    .ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
                insert_opened_leaf_v1(
                    &mut fri_mask_leaves[lane],
                    index,
                    fri_mask_leaf_hash_v1(domains, lane, index, fri_mask)?,
                )
                .map_err(|_| AggregateStarkErrorV1::FriOpening)?;
                let mut layer_index = index;
                let mut layer_size = layout.common_lde_size();
                for round in 0..fri_rounds {
                    let opening = query.fri_lanes[lane].rounds[round];
                    let low = E::canonical(opening.low)
                        .ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
                    let high = E::canonical(opening.high)
                        .ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
                    let half = layer_size / 2;
                    let low_index = layer_index % half;
                    insert_opened_leaf_v1(
                        &mut fri_leaves[lane][round],
                        low_index,
                        match parameters.fri_commitment_layout {
                            AggregateFriCommitmentLayoutV1::Scalar => {
                                fri_leaf_hash_unchecked_v1(domains, lane, round, low_index, low)?
                            }
                            AggregateFriCommitmentLayoutV1::Paired => {
                                fri_pair_leaf_hash_v1(domains, lane, round, low_index, low, high)?
                            }
                        },
                    )
                    .map_err(|_| AggregateStarkErrorV1::FriOpening)?;
                    if parameters.fri_commitment_layout == AggregateFriCommitmentLayoutV1::Scalar {
                        insert_opened_leaf_v1(
                            &mut fri_leaves[lane][round],
                            low_index + half,
                            fri_leaf_hash_unchecked_v1(
                                domains,
                                lane,
                                round,
                                low_index + half,
                                high,
                            )?,
                        )
                        .map_err(|_| AggregateStarkErrorV1::FriOpening)?;
                    }
                    layer_index = low_index;
                    layer_size = half;
                }
            }
        }
        let mut jobs = Vec::new();
        for group in 0..layout.trace_groups.len() {
            jobs.push(MerkleVerificationJobV1 {
                node_role: domains.base_node,
                root: &proof.trace_groups[group].base_root,
                leaf_count: layout.common_lde_size(),
                leaves: &base_leaves[group],
                frontier: &proof.trace_groups[group].base_frontier,
                error_mapping: None,
            });
            jobs.push(MerkleVerificationJobV1 {
                node_role: domains.aux_node,
                root: &proof.trace_groups[group].aux_root,
                leaf_count: layout.common_lde_size(),
                leaves: &aux_leaves[group],
                frontier: &proof.trace_groups[group].aux_frontier,
                error_mapping: None,
            });
        }
        for lane in 0..parameters.security_lanes {
            jobs.push(MerkleVerificationJobV1 {
                node_role: domains.composition_node,
                root: &proof.composition_roots[lane],
                leaf_count: layout.common_lde_size(),
                leaves: &composition_leaves[lane],
                frontier: &proof.composition_frontiers[lane],
                error_mapping: Some(AggregateStarkErrorV1::ConstraintOpening),
            });
            jobs.push(MerkleVerificationJobV1 {
                node_role: FRI_MASK_NODE_DOMAIN_V1,
                root: &proof.fri_mask_roots[lane],
                leaf_count: layout.common_lde_size(),
                leaves: &fri_mask_leaves[lane],
                frontier: &proof.fri_mask_frontiers[lane],
                error_mapping: Some(AggregateStarkErrorV1::FriOpening),
            });
            for round in 0..fri_rounds {
                jobs.push(MerkleVerificationJobV1 {
                    node_role: domains.fri_node,
                    root: &proof.fri_lanes[lane].roots[round],
                    leaf_count: parameters
                        .fri_commitment_layout
                        .leaf_count(layout.common_lde_size() >> round)?,
                    leaves: &fri_leaves[lane][round],
                    frontier: &proof.fri_lanes[lane].round_frontiers[round],
                    error_mapping: Some(AggregateStarkErrorV1::FriOpening),
                });
            }
        }
        verify_merkle_jobs_v1(domains.digest_context, &jobs)
    }

    #[test]
    fn merkle_verification_jobs_preserve_validity_and_first_error_across_workers() {
        let (layout, proof, _, _) = fixture();
        let indices = proof_query_indices_v1(&proof);
        let pools = [1, 2, 4].map(|threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("test pool")
        });
        for pool in &pools {
            assert_eq!(
                pool.install(|| verify_all_merkle_openings_v1(
                    &proof, PARAMETERS, &DOMAINS, &layout, &indices
                )),
                Ok(())
            );
        }
        let mut changed = proof.clone();
        changed.trace_groups[0].base_root = PrivacyOuterDigestV1::default();
        changed.composition_roots[0] = PrivacyOuterDigestV1::default();
        for pool in &pools {
            assert_eq!(
                pool.install(|| verify_all_merkle_openings_v1(
                    &changed, PARAMETERS, &DOMAINS, &layout, &indices
                )),
                Err(AggregateStarkErrorV1::TraceOpening)
            );
        }
        changed = proof.clone();
        changed.composition_roots[0] = PrivacyOuterDigestV1::default();
        changed.fri_mask_roots[0] = PrivacyOuterDigestV1::default();
        for pool in &pools {
            assert_eq!(
                pool.install(|| verify_all_merkle_openings_v1(
                    &changed, PARAMETERS, &DOMAINS, &layout, &indices
                )),
                Err(AggregateStarkErrorV1::ConstraintOpening)
            );
        }
        changed = proof;
        changed.fri_mask_roots[0] = PrivacyOuterDigestV1::default();
        for pool in &pools {
            assert_eq!(
                pool.install(|| verify_all_merkle_openings_v1(
                    &changed, PARAMETERS, &DOMAINS, &layout, &indices
                )),
                Err(AggregateStarkErrorV1::FriOpening)
            );
        }
    }
    // Codec-shape fixtures deliberately retain no claim of transcript validity;
    // the existing full Merkle/FRI/callback roundtrip verifies the real fixture.
    fn codec_shape_with_query_stride_v1(
        template: &AggregateStarkProofV1,
        layout: &AggregateProofLayoutV1,
        stride: usize,
    ) -> AggregateStarkProofV1 {
        let mut proof = template.clone();
        for (index, query) in proof.queries.iter_mut().enumerate() {
            query.index = u32::try_from(index * stride).expect("bounded fixture index");
        }
        for (index, group) in proof.trace_groups.iter_mut().enumerate() {
            let indices = trace_group_opening_indices_v1(&proof.queries, layout, index)
                .expect("canonical fixture indices");
            let count = multiproof_frontier_len_v1(layout.common_lde_size(), &indices)
                .expect("canonical fixture frontier");
            group.base_frontier.resize(count, group.base_root);
            group.aux_frontier.resize(count, group.aux_root);
        }
        let indices = composition_opening_indices_v1(&proof.queries, layout)
            .expect("canonical composition indices");
        let count = multiproof_frontier_len_v1(layout.common_lde_size(), &indices)
            .expect("canonical composition frontier");
        for (frontier, root) in proof
            .composition_frontiers
            .iter_mut()
            .zip(&proof.composition_roots)
        {
            frontier.resize(count, *root);
        }
        for (frontier, root) in proof
            .fri_mask_frontiers
            .iter_mut()
            .zip(&proof.fri_mask_roots)
        {
            frontier.resize(count, *root);
        }
        for lane in &mut proof.fri_lanes {
            for (round, frontier) in lane.round_frontiers.iter_mut().enumerate() {
                let indices = fri_opening_indices_v1(&proof.queries, PARAMETERS, layout, round)
                    .expect("canonical FRI indices");
                let count = multiproof_frontier_len_v1(layout.common_lde_size() >> round, &indices)
                    .expect("canonical FRI frontier");
                frontier.resize(count, lane.roots[round]);
            }
        }
        validate_proof_shape_v1(&proof, PARAMETERS, layout).expect("valid codec shape");
        proof
    }
    #[test]
    fn fixed_wire_length_preserves_distinct_minimal_frontier_shapes() {
        let (layout, template, _, _) = fixture();
        let clustered = codec_shape_with_query_stride_v1(&template, &layout, 1);
        let scattered = codec_shape_with_query_stride_v1(
            &template,
            &layout,
            layout.common_lde_size() / PARAMETERS.query_count,
        );
        let clustered_used = minimal_encoded_proof_bytes_v1(&clustered, PARAMETERS, &layout)
            .expect("clustered prefix");
        let scattered_used = minimal_encoded_proof_bytes_v1(&scattered, PARAMETERS, &layout)
            .expect("scattered prefix");
        assert_ne!(clustered_used, scattered_used);
        let deep = deep_fixture(&layout);
        for proof in [&clustered, &scattered] {
            let base = encode_proof_v1(proof, PARAMETERS, &layout).expect("base wire");
            assert_eq!(
                base.len(),
                maximum_encoded_proof_bytes_v1(PARAMETERS, &layout).unwrap()
            );
            assert_eq!(decode_proof_v1(&base, PARAMETERS, &layout).unwrap(), *proof);
            let wire = encode_proof_with_deep_v1(proof, &deep, PARAMETERS, &layout).unwrap();
            assert_eq!(
                wire.len(),
                maximum_encoded_proof_with_deep_bytes_v1(PARAMETERS, &layout).unwrap()
            );
            assert_eq!(
                decode_proof_with_deep_v1(&wire, PARAMETERS, &layout).unwrap(),
                (proof.clone(), deep.clone())
            );
        }
    }
    #[test]
    fn fixed_base_wire_rejects_short_form_and_nonzero_padding() {
        let (layout, proof, _, _) = fixture();
        let wire = encode_proof_v1(&proof, PARAMETERS, &layout).expect("base wire");
        let used = minimal_encoded_proof_bytes_v1(&proof, PARAMETERS, &layout).unwrap();
        assert!(used < wire.len(), "fixture must exercise padding");
        assert!(wire[used..].iter().all(|byte| *byte == 0));
        assert!(decode_proof_v1(&wire[..used], PARAMETERS, &layout).is_err());
        for offset in [used, used + (wire.len() - used) / 2, wire.len() - 1] {
            let mut nonzero = wire.clone();
            nonzero[offset] = 1;
            assert_eq!(
                decode_proof_v1(&nonzero, PARAMETERS, &layout),
                Err(AggregateStarkErrorV1::MalformedProof)
            );
        }
        assert_eq!(
            encode_proof_v1(
                &decode_proof_v1(&wire, PARAMETERS, &layout).unwrap(),
                PARAMETERS,
                &layout
            )
            .unwrap(),
            wire
        );
    }
    #[test]
    fn fixed_deep_wire_rejects_short_form_nonzero_and_extra_tail() {
        let (layout, proof, _, _) = fixture();
        let deep = deep_fixture(&layout);
        let wire = encode_proof_with_deep_v1(&proof, &deep, PARAMETERS, &layout).unwrap();
        let used = minimal_encoded_proof_bytes_v1(&proof, PARAMETERS, &layout).unwrap()
            + exact_deep_opening_bytes_v1(PARAMETERS, &layout).unwrap();
        assert!(used < wire.len());
        assert!(wire[used..].iter().all(|byte| *byte == 0));
        for size in [0, used, wire.len() - 1] {
            assert!(decode_proof_with_deep_v1(&wire[..size], PARAMETERS, &layout).is_err());
        }
        for offset in [used, used + (wire.len() - used) / 2, wire.len() - 1] {
            let mut nonzero = wire.clone();
            nonzero[offset] = 1;
            assert_eq!(
                decode_proof_with_deep_v1(&nonzero, PARAMETERS, &layout),
                Err(AggregateStarkErrorV1::MalformedProof)
            );
        }
        let mut extra = wire.clone();
        extra.push(0);
        assert!(decode_proof_with_deep_v1(&extra, PARAMETERS, &layout).is_err());
        let (decoded, decoded_deep) =
            decode_proof_with_deep_v1(&wire, PARAMETERS, &layout).unwrap();
        assert_eq!(
            encode_proof_with_deep_v1(&decoded, &decoded_deep, PARAMETERS, &layout).unwrap(),
            wire
        );
    }
    #[test]
    fn fixed_wire_refuses_a_budget_that_only_fits_minimal_frontiers() {
        let (layout, proof, _, _) = fixture();
        let deep = deep_fixture(&layout);
        let base = encode_proof_v1(&proof, PARAMETERS, &layout).unwrap();
        let wire = encode_proof_with_deep_v1(&proof, &deep, PARAMETERS, &layout).unwrap();
        let mut bounded = PARAMETERS;
        bounded.maximum_proof_bytes = base.len() - 1;
        assert!(
            minimal_encoded_proof_bytes_v1(&proof, bounded, &layout).unwrap()
                <= bounded.maximum_proof_bytes
        );
        assert_eq!(
            encode_proof_v1(&proof, bounded, &layout),
            Err(AggregateStarkErrorV1::ProofTooLarge)
        );
        assert_eq!(
            decode_proof_v1(&base, bounded, &layout),
            Err(AggregateStarkErrorV1::ProofTooLarge)
        );
        bounded.maximum_proof_bytes = wire.len() - 1;
        assert_eq!(
            encode_proof_with_deep_v1(&proof, &deep, bounded, &layout),
            Err(AggregateStarkErrorV1::ProofTooLarge)
        );
        assert_eq!(
            decode_proof_with_deep_v1(&wire, bounded, &layout),
            Err(AggregateStarkErrorV1::ProofTooLarge)
        );
    }
    #[test]
    fn fixed_wire_rejects_duplicate_and_out_of_range_query_indices() {
        let (layout, proof, _, _) = fixture();
        let deep = deep_fixture(&layout);
        let rounds = layout.fri_rounds(PARAMETERS).unwrap();
        let roots = layout.trace_groups.len() * 2 + PARAMETERS.security_lanes * (2 + rounds + 1);
        let first_query = 8
            + roots * PRIVACY_OUTER_DIGEST_BYTES_V1
            + PARAMETERS.security_lanes * PARAMETERS.terminal_size().unwrap() * 32
            + 8;
        let stride = (encoded_non_frontier_bytes_v1(PARAMETERS, &layout).unwrap() - first_query)
            / PARAMETERS.query_count;
        let base = encode_proof_v1(&proof, PARAMETERS, &layout).unwrap();
        let deep_wire = encode_proof_with_deep_v1(&proof, &deep, PARAMETERS, &layout).unwrap();
        for with_deep in [false, true] {
            let (wire, offset) = if with_deep {
                (
                    &deep_wire,
                    first_query + exact_deep_opening_bytes_v1(PARAMETERS, &layout).unwrap(),
                )
            } else {
                (&base, first_query)
            };
            let mut duplicate = wire.clone();
            duplicate[offset + stride..offset + stride + 4]
                .copy_from_slice(&wire[offset..offset + 4]);
            let mut outside = wire.clone();
            outside[offset..offset + 4].copy_from_slice(
                &u32::try_from(layout.common_lde_size())
                    .unwrap()
                    .to_be_bytes(),
            );
            for invalid in [duplicate, outside] {
                let error = if with_deep {
                    decode_proof_with_deep_v1(&invalid, PARAMETERS, &layout).unwrap_err()
                } else {
                    decode_proof_v1(&invalid, PARAMETERS, &layout).unwrap_err()
                };
                assert_eq!(error, AggregateStarkErrorV1::InvalidProofShape);
            }
        }
    }
    #[test]
    fn required_zero_tail_checks_cursor_length_and_every_chunk_boundary() {
        for padding in [0, 1, 63, 64, 65, 128] {
            let mut bytes = vec![7];
            bytes.resize(padding + 1, 0);
            let mut reader = ExactProofReaderV1::new(&bytes);
            assert_eq!(reader.take::<1>().unwrap(), [7]);
            finish_zero_padding_v1(reader, padding).expect("exact zero padding");
            assert!(finish_zero_padding_v1(ExactProofReaderV1::new(&bytes), padding).is_err());
            let mut reader = ExactProofReaderV1::new(&bytes);
            reader.take::<1>().unwrap();
            assert!(finish_zero_padding_v1(reader, padding + 1).is_err());
        }
    }
    #[test]
    fn settlement_fixed_wire_bound_is_derived_from_the_public_profile() {
        use crate::privacy_engines::{
            ivm_private_note as note, proof_managed_note_stark as shared,
        };
        let parameters = AggregateStarkParametersV1 {
            proof_magic: *b"APZ1",
            proof_version: 1,
            fri_commitment_layout: AggregateFriCommitmentLayoutV1::Scalar,
            security_lanes: shared::PROOF_MANAGED_NOTE_SECURITY_LANES_V1,
            query_count: shared::PROOF_MANAGED_NOTE_QUERY_COUNT_V1,
            blowup_log2: shared::PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1,
            terminal_log2: shared::PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1,
            terminal_degree_bound: shared::PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1,
            composition_degree_chunks: shared::PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1,
            minimum_trace_log2: note::PRIVATE_NOTE_TRACE_LOG2_V1,
            maximum_trace_log2: note::PRIVATE_NOTE_TRACE_LOG2_V1,
            maximum_trace_groups: 1,
            maximum_segment_instances: 1,
            maximum_base_columns_per_instance: note::PRIVATE_NOTE_BASE_WIDTH_V1,
            maximum_aux_columns_per_instance: shared::NOTE_COPY_AUX_WIDTH_V1
                + note::PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1,
            maximum_proof_bytes: note::IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1,
        };
        let layout = AggregateProofLayoutV1::new(
            parameters,
            vec![AggregateTraceGroupLayoutV1 {
                native_trace_log2: note::PRIVATE_NOTE_TRACE_LOG2_V1,
                segment_instances: 1,
                base_width: note::PRIVATE_NOTE_BASE_WIDTH_V1,
                aux_width: shared::NOTE_COPY_AUX_WIDTH_V1 + note::PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1,
            }],
        )
        .unwrap();
        assert_eq!(
            maximum_encoded_proof_bytes_v1(parameters, &layout).unwrap(),
            2_483_952
        );
        assert_eq!(
            exact_deep_opening_bytes_v1(parameters, &layout).unwrap(),
            43_328
        );
        let fixed = maximum_encoded_proof_with_deep_bytes_v1(parameters, &layout).unwrap();
        assert_eq!(fixed, 2_527_280);
        assert!(fixed < parameters.maximum_proof_bytes);
    }
    #[test]
    fn exact_codec_multiproofs_fri_and_callback_roundtrip() {
        for commitment_layout in [
            AggregateFriCommitmentLayoutV1::Scalar,
            AggregateFriCommitmentLayoutV1::Paired,
        ] {
            let parameters = AggregateStarkParametersV1 {
                fri_commitment_layout: commitment_layout,
                ..PARAMETERS
            };
            let (layout, proof, _, _) = fixture_with_parameters(parameters);
            let encoded = encode_proof_v1(&proof, parameters, &layout).expect("encode");
            assert_eq!(
                encoded.len(),
                exact_encoded_proof_bytes_v1(&proof, parameters, &layout).expect("exact size")
            );
            assert_eq!(
                encoded.len(),
                maximum_encoded_proof_bytes_v1(parameters, &layout).expect("public-profile size")
            );
            let decoded = decode_proof_v1(&encoded, parameters, &layout).expect("decode");
            assert_eq!(decoded, proof);
            let expected_indices = proof_query_indices_v1(&decoded);
            verify_all_merkle_openings_v1(
                &decoded,
                parameters,
                &DOMAINS,
                &layout,
                &expected_indices,
            )
            .expect("multiproofs");
            let mut verifier_transcript = transcript();
            absorb_layout_v1(
                &mut verifier_transcript,
                parameters,
                &DOMAINS,
                b"aggregate-test-relation-layout",
                &layout,
            )
            .expect("layout");
            absorb_base_roots_v1(&mut verifier_transcript, &DOMAINS, &decoded.trace_groups)
                .expect("base");
            absorb_aux_roots_v1(&mut verifier_transcript, &DOMAINS, &decoded.trace_groups)
                .expect("aux");
            absorb_composition_roots_v1(
                &mut verifier_transcript,
                parameters,
                &DOMAINS,
                &decoded.composition_roots,
            )
            .expect("composition");
            absorb_fri_mask_roots_v1(
                &mut verifier_transcript,
                parameters,
                &DOMAINS,
                &decoded.fri_mask_roots,
            )
            .expect("FRI masks");
            let (betas, terminals) = verify_fri_commitments_v1(
                &decoded,
                parameters,
                &DOMAINS,
                &layout,
                &mut verifier_transcript,
            )
            .expect("FRI commitments");
            verify_opened_query_relations_v1(
                &decoded,
                parameters,
                &layout,
                &expected_indices,
                &betas,
                &terminals,
                &mut ZeroEvaluator,
            )
            .expect("callback");
            let mut changed_betas = betas.clone();
            changed_betas[0][0] = changed_betas[0][0].add(E::ONE);
            assert!(
                verify_opened_query_relations_v1(
                    &decoded,
                    parameters,
                    &layout,
                    &expected_indices,
                    &changed_betas,
                    &terminals,
                    &mut ZeroEvaluator
                )
                .is_err()
            );
            let terminal_round = layout.fri_rounds(parameters).unwrap();
            for mutation in 0..3 {
                let mut changed = decoded.clone();
                if mutation == 0 {
                    changed.fri_lanes[0].roots[terminal_round] = PrivacyOuterDigestV1::default();
                } else {
                    let value = E::canonical(changed.fri_lanes[0].terminal_values[0])
                        .unwrap()
                        .add(E::ONE);
                    changed.fri_lanes[0].terminal_values[0] = value.coefficients().map(F::value);
                    if mutation == 2 {
                        let altered_terminal = canonical_fp4_fields_v1(
                            &changed.fri_lanes[0].terminal_values,
                            parameters.terminal_size().unwrap(),
                        )
                        .unwrap();
                        changed.fri_lanes[0].roots[terminal_round] = fri_tree_v1(
                            &DOMAINS,
                            commitment_layout,
                            0,
                            terminal_round,
                            &altered_terminal,
                        )
                        .unwrap()
                        .root();
                    }
                }
                assert_eq!(
                    verify_fri_commitments_v1(
                        &changed,
                        parameters,
                        &DOMAINS,
                        &layout,
                        &mut transcript()
                    )
                    .err(),
                    Some(if mutation == 2 {
                        AggregateStarkErrorV1::FriDegree
                    } else {
                        AggregateStarkErrorV1::FriOpening
                    })
                );
            }
            for length in [0, 1, encoded.len() / 2, encoded.len() - 1] {
                assert!(decode_proof_v1(&encoded[..length], parameters, &layout).is_err());
            }
            let mut trailing = encoded;
            trailing.push(0);
            assert!(decode_proof_v1(&trailing, parameters, &layout).is_err());
        }
    }
    #[test]
    fn exact_codec_accepts_opaque_digest_roots_and_rejects_short_width() {
        let (layout, proof, _, _) = fixture();
        let encoded = encode_proof_v1(&proof, PARAMETERS, &layout).expect("encode");
        let root_offset = PARAMETERS.proof_magic.len() + core::mem::size_of::<u16>() * 2;
        let mut old_width = encoded.clone();
        old_width.drain(root_offset + 32..root_offset + PRIVACY_OUTER_DIGEST_BYTES_V1);
        assert!(
            decode_proof_v1(&old_width, PARAMETERS, &layout).is_err(),
            "a truncated 32-byte root cannot decode as an exact 48-byte root"
        );
        let mut noncanonical = encoded;
        noncanonical[root_offset..root_offset + 8].copy_from_slice(
            &crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1.to_le_bytes(),
        );
        let decoded = decode_proof_v1(&noncanonical, PARAMETERS, &layout)
            .expect("opaque outer root is not a field");
        assert_eq!(
            decoded.trace_groups[0].base_root.to_bytes()[..8],
            crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1.to_le_bytes()
        );
    }
    #[test]
    fn exact_codec_rejects_noncanonical_base_and_every_extension_opening_class() {
        let (layout, proof, _, _) = fixture();
        let noncanonical = crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;
        let mut changed = proof.clone();
        changed.queries[0].trace_groups[0].base_current[0] = noncanonical;
        assert_eq!(
            encode_proof_v1(&changed, PARAMETERS, &layout),
            Err(AggregateStarkErrorV1::NonCanonicalField)
        );
        changed = proof.clone();
        changed.queries[0].composition_values[0][0][1] = noncanonical;
        assert_eq!(
            encode_proof_v1(&changed, PARAMETERS, &layout),
            Err(AggregateStarkErrorV1::NonCanonicalField)
        );
        changed = proof.clone();
        changed.queries[0].fri_mask_values[0][2] = noncanonical;
        assert_eq!(
            encode_proof_v1(&changed, PARAMETERS, &layout),
            Err(AggregateStarkErrorV1::NonCanonicalField)
        );
        changed = proof.clone();
        changed.queries[0].fri_lanes[0].rounds[0].low[3] = noncanonical;
        assert_eq!(
            encode_proof_v1(&changed, PARAMETERS, &layout),
            Err(AggregateStarkErrorV1::NonCanonicalField)
        );
        changed = proof;
        changed.fri_lanes[0].terminal_values[0][0] = noncanonical;
        assert_eq!(
            encode_proof_v1(&changed, PARAMETERS, &layout),
            Err(AggregateStarkErrorV1::NonCanonicalField)
        );
    }
    #[test]
    fn layout_domains_and_frontiers_are_fail_closed() {
        let mut multi_group_parameters = PARAMETERS;
        multi_group_parameters.minimum_trace_log2 = 7;
        let mut groups = vec![
            AggregateTraceGroupLayoutV1 {
                native_trace_log2: 7,
                segment_instances: 1,
                base_width: 1,
                aux_width: 1,
            },
            AggregateTraceGroupLayoutV1 {
                native_trace_log2: 8,
                segment_instances: 1,
                base_width: 1,
                aux_width: 1,
            },
        ];
        AggregateProofLayoutV1::new(multi_group_parameters, groups.clone()).expect("ordered");
        groups.swap(0, 1);
        assert!(AggregateProofLayoutV1::new(multi_group_parameters, groups.clone()).is_err());
        groups[1].native_trace_log2 = groups[0].native_trace_log2;
        AggregateProofLayoutV1::new(multi_group_parameters, groups)
            .expect("independent equal-domain groups remain distinct");
        assert!(AggregateProofLayoutV1::new(PARAMETERS, Vec::new()).is_err());
        let mut domains = DOMAINS;
        domains.fri_node = domains.fri_leaf;
        assert!(domains.validate().is_err());
        domains = DOMAINS;
        domains.fri_leaf = FRI_MASK_LEAF_DOMAIN_V1;
        assert!(domains.validate().is_err());
        domains = DOMAINS;
        domains.fri_node = FRI_MASK_NODE_DOMAIN_V1;
        assert!(domains.validate().is_err());
        domains = DOMAINS;
        domains.fri_root_label = FRI_MASK_ROOT_LABEL_V1;
        assert!(domains.validate().is_err());
        domains = DOMAINS;
        let oversized_domain: &'static [u8] =
            Box::leak(vec![0_u8; usize::from(u16::MAX) + 1].into_boxed_slice());
        domains.base_node = oversized_domain;
        assert_eq!(
            domains.validate(),
            Err(AggregateStarkErrorV1::InvalidLayout)
        );
        assert!(matches!(
            StreamingMerkleAccumulatorV1::new(DOMAINS.digest_context, oversized_domain, 2, &[0],),
            Err(AggregateStarkErrorV1::InvalidLayout)
        ));
        assert_eq!(
            verify_canonical_multiproof_v1(
                DOMAINS.digest_context,
                oversized_domain,
                &PrivacyOuterDigestV1::default(),
                1,
                &BTreeMap::from([(0, PrivacyOuterDigestV1::default())]),
                &[],
            ),
            Err(AggregateStarkErrorV1::TraceOpening)
        );
        let (layout, proof, _, _) = fixture();
        let mut changed = proof.clone();
        changed.trace_groups[0].base_frontier.pop();
        assert!(encode_proof_v1(&changed, PARAMETERS, &layout).is_err());
        changed = proof.clone();
        changed.trace_groups[0].base_frontier.swap(0, 1);
        let encoded = encode_proof_v1(&changed, PARAMETERS, &layout).expect("shape-valid");
        let decoded = decode_proof_v1(&encoded, PARAMETERS, &layout).expect("decode");
        let expected_indices = proof_query_indices_v1(&decoded);
        assert!(
            verify_all_merkle_openings_v1(
                &decoded,
                PARAMETERS,
                &DOMAINS,
                &layout,
                &expected_indices,
            )
            .is_err()
        );
    }
}

#[cfg(test)]
#[path = "aggregate_stark_compact_ca_geometry_tests.rs"]
mod compact_ca_geometry_tests;
