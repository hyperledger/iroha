//! Native execution proof driver; privacy proofs use their separate implementation.
//! Shared aggregate six-lane Goldilocks Poseidon-x7 STARK commitment and opening core.
//!
//! Relation modules supply their exact transcript suite, profile digest,
//! public-input digest, trace columns, constraint-composition values, and an
//! [`AggregateOpenedRowEvaluatorV1`]. This module owns the canonical ordered
//! trace-group layout, exact proof codec, six-lane Goldilocks Poseidon-x7 vector-row commitments,
//! minimal batched Merkle multiproofs, shared binary FRI, and opened-query
//! verification. It deliberately contains no X.509, private-note, or PQ-MASP
//! policy.
use super::transparent_stark::{
    ExactProofReaderV1, GOLDILOCKS_GENERATOR_V1, GoldilocksDigest384V1, GoldilocksFieldV1 as F,
    GoldilocksFp4V1 as E, GoldilocksMerkleTreeV1, TransparentStarkDigestContextV1,
    TransparentStarkErrorV1, TransparentTranscriptV1, append_u16_v1, append_u32_v1, append_u64_v1,
    derive_unique_query_indices_v1, ensure_fri_terminal_degree_fp4_v1, fri_fold_pair_fp4_v1,
    fri_fold_pair_with_inverse_x_fp4_v1, goldilocks_digest384_frame_v1,
    goldilocks_fp4_evaluate_coset_v1, goldilocks_fp4_ifft_v1, goldilocks_merkle_node_v1,
    goldilocks_primitive_root_v1, random_goldilocks_fp4_v1,
};
#[cfg(test)]
use super::transparent_stark::{
    goldilocks_digest384_last_field_stream_v1, map_digest_stream_error_v1,
    masked_trace_coefficients_on_coset_v1, masked_trace_coefficients_with_mask_v1,
    sample_trace_mask_v1,
};
#[cfg(test)]
use fastpq_isi::GoldilocksDigest384LastFieldStreamV1;
use fastpq_isi::{FASTPQ_QUERY_COUNT_V1, GOLDILOCKS_DIGEST384_BYTES_V1};
use rand::TryRngCore;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
const FRI_MASK_LEAF_DOMAIN_V1: &[u8] = b"iroha:execution:aggregate-stark:fri-mask-oracle-leaf:v1";
const FRI_MASK_NODE_DOMAIN_V1: &[u8] = b"iroha:execution:aggregate-stark:fri-mask-oracle-node:v1";
const FRI_MASK_ROOT_LABEL_V1: &[u8] = b"iroha:execution:aggregate-stark:fri-mask-oracle-root:v1";
const DEEP_POINT_LABEL_V1: &[u8] = b"iroha:execution:aggregate-stark:deep-point:v1";
const DEEP_OPENINGS_LABEL_V1: &[u8] = b"iroha:execution:aggregate-stark:deep-openings:v1";
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
pub(crate) fn aggregate_stark_domain_is_reserved_v1(domain: &[u8]) -> bool {
    AGGREGATE_STARK_RESERVED_DOMAINS_V1.contains(&domain)
}
/// Rows processed per bounded DEEP/FRI denominator-inversion batch.
pub(crate) const DEEP_FRI_BASE_BATCH_ROWS_V1: usize = 1 << 12;
/// Canonical independent row batch used by materialized FRI folding.
const FRI_FOLD_PARALLEL_BATCH_ROWS_V1: usize = 1 << 12;
/// Exact maximum number of independent LDE columns resident in one parallel dispatch.
///
/// Callers process these source-ordered batches sequentially. Peak transform scratch therefore
/// remains bounded by this protocol-source constant even when Rayon's global pool is wider or is
/// configured differently by the surrounding process. The historical `MASKED_TRACE` name is
/// retained because release-readiness certificates bind it directly; the same ceiling now covers
/// verifier-fixed and DEEP-opening column transforms too.
pub(crate) const MASKED_TRACE_LDE_COLUMN_BATCH_V1: usize = 8;
/// Shared aggregate-STARK failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum AggregateStarkErrorV1 {
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
fn map_transparent_error_v1(error: TransparentStarkErrorV1) -> AggregateStarkErrorV1 {
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
/// Immutable proof-system dimensions used by the generic aggregate core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AggregateStarkParametersV1 {
    /// Four-byte exact wire magic.
    pub(crate) proof_magic: [u8; 4],
    /// Exact proof version.
    pub(crate) proof_version: u16,
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
    /// Validate every closed proof-system dimension.
    pub(crate) fn validate(self) -> Result<(), AggregateStarkErrorV1> {
        let terminal_size = self.terminal_size()?;
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
            || self.blowup_log2 != 3
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
/// Poseidon and transcript domains supplied by one relation profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AggregateStarkDomainsV1 {
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
    pub(crate) fn validate(self) -> Result<(), AggregateStarkErrorV1> {
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
    domains: AggregateStarkDomainsV1,
) -> Result<(), AggregateStarkErrorV1> {
    domains.validate()?;
    if transcript.context() != domains.digest_context {
        return Err(AggregateStarkErrorV1::TranscriptMismatch);
    }
    Ok(())
}
/// One canonical group of equal-native-stride trace segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AggregateTraceGroupLayoutV1 {
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
/// Verifier-derived ordered aggregate commitment layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AggregateProofLayoutV1 {
    common_lde_log2: u8,
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
/// `l_minus_one_*` represents the theorem's rational `L - 1`. `rho_*`
/// represents the exact code rate, and `affine_arities` is the complete list
/// whose sum appears in the commitment-error term. The remaining fields bind
/// the smooth domain, Fp4 field-size lower bound, fold/terminal geometry, and
/// the implementation's distinct-query schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AggregateFriTheorem2CertificateV1 {
    /// Numerator of `L - 1`.
    pub(crate) l_minus_one_numerator: u8,
    /// Denominator of `L - 1`.
    pub(crate) l_minus_one_denominator: u8,
    /// Affine batching parameter `m`.
    pub(crate) batching_parameter_m: u8,
    /// Numerator of a proved upper bound on the code rate.
    pub(crate) rho_numerator: u8,
    /// Denominator of a proved upper bound on the code rate.
    pub(crate) rho_denominator: u8,
    /// Affine arities whose sum occurs in the theorem.
    pub(crate) affine_arities: Vec<u8>,
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
pub(crate) struct AggregateFriTheorem2BoundV1 {
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
pub(crate) fn validate_affine_batched_fri_theorem2_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    certificate: AggregateFriTheorem2CertificateV1,
) -> Result<AggregateFriTheorem2BoundV1, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let domain_size = layout.common_lde_size();
    let terminal_size = parameters.terminal_size()?;
    let fold_count = layout.fri_rounds(parameters)?;
    let degree_coefficients = layout.fri_degree_cap(parameters)?;
    let affine_arity_sum = certificate
        .affine_arities
        .iter()
        .try_fold(0_u16, |sum, arity| sum.checked_add(u16::from(*arity)))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    if parameters.security_lanes != 1
        || certificate.l_minus_one_numerator != 3
        || certificate.l_minus_one_denominator != 2
        || certificate.batching_parameter_m != 3
        || certificate.rho_numerator != 1
        || certificate.rho_denominator != 7
        || certificate.affine_arities.len() != fold_count
        || certificate.affine_arities.iter().any(|arity| *arity != 2)
        || fold_count > 12
        || usize::from(affine_arity_sum) != 2 * fold_count
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
    // Exact canonical constants conservatively bound the first commitment
    // term by `7^7 * |D|^2 / 2^252 < 2^-(252-2log|D|-20)`.
    // The second is below
    // `2^9 * 2^(log|D|+1) / 2^252`: with at most twelve binary folds,
    // 7 * sqrt(7) * sum(arities) < 7 * 3 * 24 = 504 < 512.
    // The complete fold schedule above is reconstructed from the actual domain.
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
pub(crate) struct AggregateTraceGroupProofV1 {
    /// Base vector-row Merkle root.
    pub(crate) base_root: GoldilocksDigest384V1,
    /// Auxiliary vector-row Merkle root.
    pub(crate) aux_root: GoldilocksDigest384V1,
    /// Minimal base-tree multiproof frontier.
    pub(crate) base_frontier: Vec<GoldilocksDigest384V1>,
    /// Minimal auxiliary-tree multiproof frontier.
    pub(crate) aux_frontier: Vec<GoldilocksDigest384V1>,
}
/// One FRI round's low/high opening pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AggregateFriRoundOpeningV1 {
    /// Canonical low-half quartic-extension value.
    pub(crate) low: [u64; 4],
    /// Canonical high-half quartic-extension value.
    pub(crate) high: [u64; 4],
}
/// All FRI round openings for one lane/query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AggregateFriLaneQueryV1 {
    /// Round openings in folding order.
    pub(crate) rounds: Vec<AggregateFriRoundOpeningV1>,
}
/// Current and next vector rows for one trace group/query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AggregateTraceGroupQueryV1 {
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
pub(crate) struct AggregateQueryProofV1 {
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
pub(crate) struct AggregateFriLaneProofV1 {
    /// Layer roots, including the terminal layer.
    pub(crate) roots: Vec<GoldilocksDigest384V1>,
    /// Exact terminal evaluations.
    pub(crate) terminal_values: Vec<[u64; 4]>,
    /// Minimal multiproof frontier for each non-terminal layer.
    pub(crate) round_frontiers: Vec<Vec<GoldilocksDigest384V1>>,
}
/// Exact aggregate proof object before/after canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AggregateStarkProofV1 {
    /// Exact proof version.
    pub(crate) version: u16,
    /// Ordered trace-group roots/frontiers.
    pub(crate) trace_groups: Vec<AggregateTraceGroupProofV1>,
    /// Aggregate composition roots.
    pub(crate) composition_roots: Vec<GoldilocksDigest384V1>,
    /// Aggregate composition multiproof frontiers.
    pub(crate) composition_frontiers: Vec<Vec<GoldilocksDigest384V1>>,
    /// Independent low-degree FRI-mask-oracle roots in lane order.
    pub(crate) fri_mask_roots: Vec<GoldilocksDigest384V1>,
    /// Canonical FRI-mask-oracle multiproof frontiers in lane order.
    pub(crate) fri_mask_frontiers: Vec<Vec<GoldilocksDigest384V1>>,
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
pub(crate) struct AggregateDeepTraceGroupOpeningV1 {
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
pub(crate) struct AggregateDeepProofV1 {
    /// Ordered current/next trace openings.
    pub(crate) trace_groups: Vec<AggregateDeepTraceGroupOpeningV1>,
    /// Composition-chunk evaluations in lane-major order.
    pub(crate) composition_values: Vec<Vec<[u64; 4]>>,
}
/// Canonically decoded DEEP trace openings supplied to relation verifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AggregateOpenedDeepTraceGroupV1 {
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
pub(crate) struct AggregateDeepTraceGroupMixV1 {
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
pub(crate) struct AggregateDeepLaneMixV1 {
    /// Ordered trace-group mixes.
    pub(crate) trace_groups: Vec<AggregateDeepTraceGroupMixV1>,
    /// Composition-chunk mixes.
    pub(crate) composition: Vec<E>,
}
/// Canonical opened fields passed to a relation evaluator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AggregateOpenedTraceGroupV1 {
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
pub(crate) struct AggregateExpectedOpeningV1 {
    /// Expected aggregate composition value.
    pub(crate) composition: E,
    /// Expected base value for the selected FRI lane.
    pub(crate) fri_base: E,
}
/// Relation-specific opened-row algebra called by the shared verifier.
pub(crate) trait AggregateOpenedRowEvaluatorV1 {
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
pub(crate) fn canonical_fields_v1(
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
pub(crate) fn canonical_fp4_fields_v1(
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
pub(crate) fn deep_point_is_admissible_v1(
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
pub(crate) fn derive_deep_point_v1(
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
pub(crate) fn validate_deep_proof_shape_v1(
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
pub(crate) fn canonical_deep_trace_groups_v1(
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
pub(crate) fn absorb_deep_openings_v1(
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
pub(crate) fn row_leaf_hash_v1(
    context: TransparentStarkDigestContextV1,
    role: &[u8],
    group: usize,
    row_index: usize,
    values: &[F],
) -> Result<GoldilocksDigest384V1, AggregateStarkErrorV1> {
    let group = u16::try_from(group)
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
                .checked_mul(core::mem::size_of::<u64>())
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
    for value in values {
        fields.extend_from_slice(&value.0.to_be_bytes());
    }
    goldilocks_digest384_frame_v1(
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
    domains: AggregateStarkDomainsV1,
    lane: usize,
    row_index: usize,
    values: &[E],
) -> Result<GoldilocksDigest384V1, AggregateStarkErrorV1> {
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
    goldilocks_digest384_frame_v1(
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
pub(crate) struct AggregateFriMaskOracleMaterialV1 {
    /// Coset evaluations on the common LDE domain.
    pub(crate) evaluations: Vec<E>,
    /// Authenticated oracle commitment.
    pub(crate) tree: GoldilocksMerkleTreeV1,
}
impl Drop for AggregateFriMaskOracleMaterialV1 {
    fn drop(&mut self) {
        zeroize_extension_field_column_v1(&mut self.evaluations);
    }
}
fn fri_mask_leaf_hash_v1(
    domains: AggregateStarkDomainsV1,
    lane: usize,
    row_index: usize,
    value: E,
) -> Result<GoldilocksDigest384V1, AggregateStarkErrorV1> {
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    goldilocks_digest384_frame_v1(
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
    domains: AggregateStarkDomainsV1,
    lane: usize,
    evaluations: &[E],
) -> Result<GoldilocksMerkleTreeV1, AggregateStarkErrorV1> {
    if evaluations.is_empty() || !evaluations.len().is_power_of_two() {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let leaves = evaluations
        .par_iter()
        .copied()
        .enumerate()
        .map(|(index, value)| fri_mask_leaf_hash_v1(domains, lane, index, value))
        .collect::<Result<Vec<_>, _>>()?;
    GoldilocksMerkleTreeV1::from_leaves(leaves, domains.digest_context, FRI_MASK_NODE_DOMAIN_V1)
        .map_err(map_transparent_error_v1)
}
/// Sample and commit all independent Protocol-2 FRI mask polynomials.
///
/// Each lane samples the normalized `D - 1` coefficients, which contains the
/// required `|H| + h - 1`-coefficient hiding space and stays strictly inside
/// the one FRI-enforced exclusive cap `D`. The resulting root must be
/// transcript-bound before any challenge that batches the lane's trace and
/// composition polynomials.
pub(crate) fn build_fri_mask_oracles_v1<R: TryRngCore>(
    parameters: AggregateStarkParametersV1,
    domains: AggregateStarkDomainsV1,
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
pub(crate) fn add_fri_mask_oracle_v1(
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
    domains: AggregateStarkDomainsV1,
    lane: usize,
    round: usize,
    row_index: usize,
    value: E,
) -> Result<GoldilocksDigest384V1, AggregateStarkErrorV1> {
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let round = u16::try_from(round)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    goldilocks_digest384_frame_v1(
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
/// Commit vector-row columns on a common power-of-two domain.
pub(crate) fn row_tree_v1(
    context: TransparentStarkDigestContextV1,
    leaf_role: &[u8],
    node_role: &'static [u8],
    group: usize,
    columns: &[Vec<F>],
    rows: usize,
) -> Result<GoldilocksMerkleTreeV1, AggregateStarkErrorV1> {
    if rows == 0
        || !rows.is_power_of_two()
        || columns.is_empty()
        || columns.iter().any(|column| column.len() != rows)
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let leaves = (0..rows)
        .into_par_iter()
        .map(|index| {
            row_leaf_hash_v1(
                context,
                leaf_role,
                group,
                index,
                &row_at_v1(columns, index)?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    GoldilocksMerkleTreeV1::from_leaves(leaves, context, node_role)
        .map_err(map_transparent_error_v1)
}
/// Root and canonical minimal frontier produced without retaining a Merkle tree.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StreamingMerkleCommitmentV1 {
    /// Root of the complete power-of-two leaf stream.
    pub(crate) root: GoldilocksDigest384V1,
    /// Canonically ordered minimal frontier for the requested leaves.
    pub(crate) frontier: Vec<GoldilocksDigest384V1>,
}
/// Incremental binary Merkle accumulator with a query-aware frontier plan.
///
/// Leaves must be appended in ascending index order. The accumulator retains
/// one pending subtree per level and only those sibling hashes required by the
/// requested canonical multiproof. Its memory is therefore
/// `O(log(leaf_count) + frontier_len)` rather than `O(leaf_count)`.
#[cfg(test)]
pub(crate) struct StreamingMerkleAccumulatorV1 {
    context: TransparentStarkDigestContextV1,
    node_role: &'static [u8],
    leaf_count: usize,
    next_leaf: usize,
    pending: Vec<Option<GoldilocksDigest384V1>>,
    frontier_positions: BTreeMap<(usize, usize), usize>,
    frontier: Vec<Option<GoldilocksDigest384V1>>,
}
#[cfg(test)]
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
            context,
            node_role,
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
        node: GoldilocksDigest384V1,
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
    /// Append the next leaf digest.
    pub(crate) fn append_leaf(
        &mut self,
        mut node: GoldilocksDigest384V1,
    ) -> Result<(), AggregateStarkErrorV1> {
        if self.next_leaf >= self.leaf_count {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        let mut index = self.next_leaf;
        let mut level = 0_usize;
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
            node = goldilocks_merkle_node_v1(
                self.context,
                self.node_role,
                u64::try_from(level + 1).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
                u64::try_from(parent_index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
                left,
                node,
            )
            .map_err(map_transparent_error_v1)?;
            index = parent_index;
            level += 1;
            self.capture(level, index, node)?;
        }
        self.next_leaf = self
            .next_leaf
            .checked_add(1)
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
        let root = self.pending[height]
            .take()
            .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
        let frontier = self
            .frontier
            .into_iter()
            .map(|node| node.ok_or(AggregateStarkErrorV1::InternalInvariant))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(StreamingMerkleCommitmentV1 { root, frontier })
    }
}
/// Commit an exact leaf iterator with logarithmic tree memory.
#[cfg(test)]
pub(crate) fn streaming_merkle_commitment_v1<I>(
    context: TransparentStarkDigestContextV1,
    node_role: &'static [u8],
    leaf_count: usize,
    opening_indices: &[usize],
    leaves: I,
) -> Result<StreamingMerkleCommitmentV1, AggregateStarkErrorV1>
where
    I: IntoIterator<Item = Result<GoldilocksDigest384V1, AggregateStarkErrorV1>>,
{
    let mut accumulator =
        StreamingMerkleAccumulatorV1::new(context, node_role, leaf_count, opening_indices)?;
    for leaf in leaves {
        accumulator.append_leaf(leaf?)?;
    }
    accumulator.finish()
}
/// Result of one column-streamed vector-row commitment pass.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StreamingRowCommitmentResultV1 {
    /// Root and canonical frontier of the committed vector rows.
    pub(crate) commitment: StreamingMerkleCommitmentV1,
    /// Exact requested vector rows keyed by ascending LDE index.
    pub(crate) opened_rows: BTreeMap<usize, Vec<F>>,
}
/// Column-at-a-time vector-row commitment builder.
///
/// This is the bounded-memory replacement for retaining every LDE column.
/// Each row owns one incremental six-lane Goldilocks digest stream while columns are supplied in
/// canonical order. The final leaf digests are immediately consumed by
/// [`StreamingMerkleAccumulatorV1`], so neither leaves nor tree levels are
/// retained. A second deterministic pass after Fiat–Shamir query derivation
/// supplies the canonical frontier and the small set of opened rows.
#[cfg(test)]
pub(crate) struct StreamingRowCommitmentV1 {
    rows: usize,
    width: usize,
    received_columns: usize,
    context: TransparentStarkDigestContextV1,
    node_role: &'static [u8],
    digest_streams: Vec<GoldilocksDigest384LastFieldStreamV1>,
    opening_indices: Vec<usize>,
    opened_rows: BTreeMap<usize, Vec<F>>,
}
#[cfg(test)]
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
        for row_index in 0..rows {
            digest_streams.push(
                goldilocks_digest384_last_field_stream_v1(
                    context,
                    leaf_role,
                    b"vector-row-leaf",
                    0,
                    u64::try_from(row_index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
                    u64::from(u16::from_be_bytes(group)),
                    &[&group, &width_u16],
                    value_bytes,
                )
                .map_err(map_transparent_error_v1)?,
            );
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
            context,
            node_role,
            digest_streams,
            opening_indices: opening_indices.to_vec(),
            opened_rows,
        })
    }
    /// Absorb the next complete LDE column in canonical column order.
    pub(crate) fn absorb_column(&mut self, column: &[F]) -> Result<(), AggregateStarkErrorV1> {
        if self.received_columns >= self.width || column.len() != self.rows {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        for (stream, value) in self.digest_streams.iter_mut().zip(column) {
            stream
                .update(&value.0.to_be_bytes())
                .map_err(map_digest_stream_error_v1)
                .map_err(map_transparent_error_v1)?;
        }
        for &index in &self.opening_indices {
            self.opened_rows
                .get_mut(&index)
                .ok_or(AggregateStarkErrorV1::InternalInvariant)?
                .push(column[index]);
        }
        self.received_columns += 1;
        Ok(())
    }
    /// Finalize the exact-width vector rows into a streaming Merkle commitment.
    pub(crate) fn finish(self) -> Result<StreamingRowCommitmentResultV1, AggregateStarkErrorV1> {
        if self.received_columns != self.width
            || self
                .opened_rows
                .values()
                .any(|values| values.len() != self.width)
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let leaves = self.digest_streams.into_iter().map(|stream| {
            stream
                .finalize()
                .map_err(map_digest_stream_error_v1)
                .map_err(map_transparent_error_v1)
        });
        let commitment = streaming_merkle_commitment_v1(
            self.context,
            self.node_role,
            self.rows,
            &self.opening_indices,
            leaves,
        )?;
        Ok(StreamingRowCommitmentResultV1 {
            commitment,
            opened_rows: self.opened_rows,
        })
    }
}
/// Owner of one secret-bearing field column that overwrites every cell on
/// every return path.
#[cfg(test)]
pub(crate) struct ZeroizingFieldColumnV1(Vec<F>);
#[cfg(test)]
impl ZeroizingFieldColumnV1 {
    fn zeroize_v1(&mut self) {
        zeroize_field_column_v1(&mut self.0);
    }
}
#[cfg(test)]
impl core::ops::Deref for ZeroizingFieldColumnV1 {
    type Target = [F];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(test)]
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
pub(crate) struct ZeroizingExtensionFieldMatrixV1(Vec<Vec<E>>);
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
/// Secret retained masked polynomials for one exact streamed trace commitment.
///
/// Each column stores ascending coefficients of
/// `T(X) + r(X) * (X^n - 1)`, rather than a common-domain LDE. This lets a
/// prover evaluate the same committed polynomial on its large commitment
/// domain, a smaller quotient domain, and transcript-derived DEEP points
/// without anonymous matrix scratch. The type implements neither `Clone` nor
/// `Debug`; every coefficient is overwritten recursively on drop.
#[cfg(test)]
pub(crate) struct MaskedTracePolynomialSetV1 {
    native_trace_log2: u8,
    commitment_lde_log2: u8,
    columns: Vec<ZeroizingFieldColumnV1>,
}
#[cfg(test)]
impl MaskedTracePolynomialSetV1 {
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
/// Sample masks, commit their LDEs, and retain only the masked coefficients.
///
/// All verifier-derived shape checks and commitment allocations finish before
/// the witness source is called. The retained coefficient set is sufficient
/// to replay the exact commitment, evaluate smaller quotient cosets, and
/// construct DEEP openings without materializing anonymous common-domain
/// scratch.
#[cfg(test)]
pub(crate) fn commit_masked_trace_polynomial_columns_v1<R, S>(
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
    mut source: S,
) -> Result<(StreamingRowCommitmentResultV1, MaskedTracePolynomialSetV1), AggregateStarkErrorV1>
where
    R: TryRngCore,
    S: FnMut(usize) -> Result<Vec<F>, AggregateStarkErrorV1>,
{
    let (native_rows, commitment_rows) = validate_masked_trace_commitment_shape_v1(
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
            masked_trace_coefficients_with_mask_v1(&native, native_trace_log2, mask.coefficients())
                .map_err(map_transparent_error_v1)?,
        );
        columns.push(coefficients);
    }
    // The profile's eight-column batch is a memory ceiling as well as a
    // throughput choice. Coefficients and masks are sampled serially above,
    // preserving the byte-exact transcript, while independent LDEs within
    // each bounded batch may use the active Rayon pool. No pool setting can
    // make more than eight transforms resident, and roots are still absorbed
    // in canonical column order.
    for batch in columns.chunks(MASKED_TRACE_LDE_COLUMN_BATCH_V1) {
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
        for evaluation in &evaluations {
            commitment.absorb_column(evaluation)?;
        }
    }
    let polynomials = MaskedTracePolynomialSetV1 {
        native_trace_log2,
        commitment_lde_log2,
        columns,
    };
    polynomials.validate_v1()?;
    Ok((commitment.finish()?, polynomials))
}
/// Replay a retained masked-polynomial commitment and requested row frontier.
///
/// No native witness source or mask RNG is needed: the exact committed
/// polynomials, including canonical trailing zero coefficients, are owned by
/// `polynomials`.
#[cfg(test)]
pub(crate) fn replay_masked_trace_polynomial_columns_v1(
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
        for evaluation in &evaluations {
            commitment.absorb_column(evaluation)?;
        }
    }
    commitment.finish()
}
/// Commit one aggregate composition lane.
pub(crate) fn composition_tree_v1(
    domains: AggregateStarkDomainsV1,
    lane: usize,
    chunks: &[Vec<E>],
) -> Result<GoldilocksMerkleTreeV1, AggregateStarkErrorV1> {
    domains.validate()?;
    let rows = chunks
        .first()
        .map(Vec::len)
        .filter(|rows| *rows != 0 && rows.is_power_of_two())
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    if chunks.iter().any(|chunk| chunk.len() != rows) {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let leaves = (0..rows)
        .into_par_iter()
        .map(|index| {
            let values = chunks.iter().map(|chunk| chunk[index]).collect::<Vec<_>>();
            composition_leaf_hash_unchecked_v1(domains, lane, index, &values)
        })
        .collect::<Result<Vec<_>, _>>()?;
    GoldilocksMerkleTreeV1::from_leaves(leaves, domains.digest_context, domains.composition_node)
        .map_err(map_transparent_error_v1)
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
pub(crate) fn split_composition_evaluations_v1(
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
/// Reconstruct one unsplit quotient value from its authenticated chunks.
pub(crate) fn recompose_composition_value_v1(
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
fn evaluate_fp4_coefficients_at_fp4_v1(coefficients: &[E], point: E) -> E {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(E::ZERO, |value, coefficient| {
            value.mul(point).add(coefficient)
        })
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
/// Evaluate one committed Fp4 coset codeword at an arbitrary Fp4 point.
pub(crate) fn evaluate_fp4_coset_polynomial_at_point_v1(
    evaluations: &[E],
    lde_log2: u8,
    point: E,
) -> Result<E, AggregateStarkErrorV1> {
    let coefficients = fp4_coset_coefficients_v1(evaluations, lde_log2)?;
    Ok(evaluate_fp4_coefficients_at_fp4_v1(&coefficients, point))
}
/// Evaluate all composition chunks at the transcript-derived DEEP point.
pub(crate) fn evaluate_composition_chunks_at_deep_v1(
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
/// Batch-invert canonical nonzero Fp4 values using one extension-field
/// inversion.
///
/// DEEP code calls this on bounded row chunks so constructing quotient
/// codewords does not perform one expensive inversion per domain element or
/// allocate an evaluation-domain-sized prefix buffer.
pub(crate) fn batch_invert_fp4_nonzero_v1(values: &mut [E]) -> Result<(), AggregateStarkErrorV1> {
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
pub(crate) fn validate_deep_lane_mixes_v1(
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
pub(crate) fn deep_ali_mixed_opening_v1(
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
pub(crate) fn fri_tree_v1(
    domains: AggregateStarkDomainsV1,
    lane: usize,
    round: usize,
    values: &[E],
) -> Result<GoldilocksMerkleTreeV1, AggregateStarkErrorV1> {
    domains.validate()?;
    let leaves = values
        .par_iter()
        .copied()
        .enumerate()
        .map(|(index, value)| fri_leaf_hash_unchecked_v1(domains, lane, round, index, value))
        .collect::<Result<Vec<_>, _>>()?;
    GoldilocksMerkleTreeV1::from_leaves(leaves, domains.digest_context, domains.fri_node)
        .map_err(map_transparent_error_v1)
}
/// Absorb the complete relation domain and ordered group layout before roots.
pub(crate) fn absorb_layout_v1(
    transcript: &mut TransparentTranscriptV1,
    parameters: AggregateStarkParametersV1,
    domains: AggregateStarkDomainsV1,
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
pub(crate) fn absorb_base_roots_v1(
    transcript: &mut TransparentTranscriptV1,
    domains: AggregateStarkDomainsV1,
    groups: &[AggregateTraceGroupProofV1],
) -> Result<(), AggregateStarkErrorV1> {
    ensure_transcript_context_v1(transcript, domains)?;
    absorb_group_roots_v1(transcript, domains.base_root_label, groups, true)
}
/// Absorb all ordered auxiliary roots before constraint-composition challenges.
pub(crate) fn absorb_aux_roots_v1(
    transcript: &mut TransparentTranscriptV1,
    domains: AggregateStarkDomainsV1,
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
        let root = root.to_le_bytes();
        transcript
            .absorb(label, &[&group, &root])
            .map_err(map_transparent_error_v1)?;
    }
    Ok(())
}
/// Absorb all aggregate composition roots in fixed lane order.
pub(crate) fn absorb_composition_roots_v1(
    transcript: &mut TransparentTranscriptV1,
    parameters: AggregateStarkParametersV1,
    domains: AggregateStarkDomainsV1,
    roots: &[GoldilocksDigest384V1],
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
        let root = root.to_le_bytes();
        transcript
            .absorb(domains.composition_root_label, &[&lane, &root])
            .map_err(map_transparent_error_v1)?;
    }
    Ok(())
}
/// Bind all independently committed FRI-mask roots before batching challenges.
pub(crate) fn absorb_fri_mask_roots_v1(
    transcript: &mut TransparentTranscriptV1,
    parameters: AggregateStarkParametersV1,
    domains: AggregateStarkDomainsV1,
    roots: &[GoldilocksDigest384V1],
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
        let root = root.to_le_bytes();
        transcript
            .absorb(FRI_MASK_ROOT_LABEL_V1, &[&lane, &root])
            .map_err(map_transparent_error_v1)?;
    }
    Ok(())
}
/// Absorb one FRI root in fixed lane/round order.
pub(crate) fn absorb_fri_root_v1(
    transcript: &mut TransparentTranscriptV1,
    domains: AggregateStarkDomainsV1,
    lane: usize,
    round: usize,
    root: &GoldilocksDigest384V1,
) -> Result<(), AggregateStarkErrorV1> {
    ensure_transcript_context_v1(transcript, domains)?;
    let lane = u16::try_from(lane)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let round = u16::try_from(round)
        .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
        .to_be_bytes();
    let root = root.to_le_bytes();
    transcript
        .absorb(domains.fri_root_label, &[&lane, &round, &root])
        .map_err(map_transparent_error_v1)
}
/// Derive the shared unique query positions from the post-grinding transcript.
pub(crate) fn query_indices_v1(
    transcript: &TransparentTranscriptV1,
    parameters: AggregateStarkParametersV1,
    domains: AggregateStarkDomainsV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<usize>, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    ensure_transcript_context_v1(transcript, domains)?;
    let seed = goldilocks_digest384_frame_v1(
        domains.digest_context,
        domains.query_seed,
        b"post-grinding-query-seed",
        0,
        u64::from(layout.common_lde_log2),
        0,
        &[&transcript.state().to_le_bytes()],
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
pub(crate) fn trace_group_opening_indices_v1(
    queries: &[AggregateQueryProofV1],
    layout: &AggregateProofLayoutV1,
    group: usize,
) -> Result<Vec<usize>, AggregateStarkErrorV1> {
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
pub(crate) fn composition_opening_indices_v1(
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
pub(crate) fn fri_opening_indices_v1(
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
        indices.insert(low + half);
    }
    Ok(indices.into_iter().collect())
}
/// Exact number of hashes in the unique canonical minimal frontier.
pub(crate) fn multiproof_frontier_len_v1(
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
pub(crate) fn canonical_multiproof_frontier_v1(
    tree: &GoldilocksMerkleTreeV1,
    leaf_count: usize,
    indices: &[usize],
) -> Result<Vec<GoldilocksDigest384V1>, AggregateStarkErrorV1> {
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
pub(crate) fn verify_canonical_multiproof_v1(
    context: TransparentStarkDigestContextV1,
    node_role: &[u8],
    root: &GoldilocksDigest384V1,
    leaf_count: usize,
    leaves: &BTreeMap<usize, GoldilocksDigest384V1>,
    frontier: &[GoldilocksDigest384V1],
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
                goldilocks_merkle_node_v1(
                    context,
                    node_role,
                    u64::try_from(level + 1).map_err(|_| AggregateStarkErrorV1::TraceOpening)?,
                    u64::try_from(parent_index).map_err(|_| AggregateStarkErrorV1::TraceOpening)?,
                    node,
                    sibling,
                )
            } else {
                goldilocks_merkle_node_v1(
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
    leaves: &mut BTreeMap<usize, GoldilocksDigest384V1>,
    index: usize,
    leaf: GoldilocksDigest384V1,
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
pub(crate) fn maximum_multiproof_frontier_len_v1(
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
pub(crate) fn validate_proof_shape_v1(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<(), AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    let expected_proof_version = parameters.proof_version;
    if proof.version != expected_proof_version
        || proof.trace_groups.len() != layout.trace_groups.len()
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
                || opening.base_next.len() != group.base_width
                || opening.aux_current.len() != group.aux_width
                || opening.aux_next.len() != group.aux_width
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
            let expected = multiproof_frontier_len_v1(layout.common_lde_size() >> round, &indices)?;
            if frontier.len() != expected {
                return Err(AggregateStarkErrorV1::InvalidProofShape);
            }
        }
    }
    Ok(())
}
fn append_hash_v1(bytes: &mut Vec<u8>, hash: &GoldilocksDigest384V1) {
    bytes.extend_from_slice(&hash.to_le_bytes());
}
fn append_hashes_v1(bytes: &mut Vec<u8>, hashes: &[GoldilocksDigest384V1]) {
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
pub(crate) fn exact_deep_opening_bytes_v1(
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
        .trace_groups
        .len()
        .checked_mul(2)
        .and_then(|roots| roots.checked_add(parameters.security_lanes))
        .and_then(|roots| roots.checked_add(parameters.security_lanes))
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    header_bytes
        .checked_add(
            roots
                .checked_mul(GOLDILOCKS_DIGEST384_BYTES_V1)
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
    let hash_bytes = GOLDILOCKS_DIGEST384_BYTES_V1;
    let base_field_bytes = core::mem::size_of::<u64>();
    let extension_field_bytes = core::mem::size_of::<[u64; 4]>();
    let mut bytes = parameters
        .proof_magic
        .len()
        .checked_add(core::mem::size_of::<u16>() * 2)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let trace_roots = layout
        .trace_groups
        .len()
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
        .checked_mul(2)
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
/// Exact encoded byte length for one validated proof object.
pub(crate) fn exact_encoded_proof_bytes_v1(
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
                .checked_mul(GOLDILOCKS_DIGEST384_BYTES_V1)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
/// Exact encoded byte length of one validated DEEP-enabled proof.
pub(crate) fn exact_encoded_proof_with_deep_bytes_v1(
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
pub(crate) fn maximum_encoded_proof_bytes_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    let non_frontier = encoded_non_frontier_bytes_v1(parameters, layout)?;
    let trace_opened = parameters
        .query_count
        .checked_mul(2)
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
        let layer_size = layout.common_lde_size() >> round;
        fri_frontiers = fri_frontiers
            .checked_add(maximum_multiproof_frontier_len_v1(
                layer_size,
                trace_opened.min(layer_size),
            )?)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    }
    let frontier_hashes = layout
        .trace_groups
        .len()
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
                .checked_mul(GOLDILOCKS_DIGEST384_BYTES_V1)
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
/// Hard maximum encoded length of a DEEP-enabled proof.
pub(crate) fn maximum_encoded_proof_with_deep_bytes_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, AggregateStarkErrorV1> {
    maximum_encoded_proof_bytes_v1(parameters, layout)?
        .checked_add(exact_deep_opening_bytes_v1(parameters, layout)?)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)
}
/// Encode the sole canonical exact aggregate proof wire.
pub(crate) fn encode_proof_v1(
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
    if bytes.len() != expected {
        return Err(AggregateStarkErrorV1::InternalInvariant);
    }
    Ok(bytes)
}
/// Encode the sole canonical DEEP-enabled aggregate wire.
///
/// DEEP values are inserted after every trace/composition/mask root and before
/// the first FRI root. This fixed position mirrors transcript order and leaves
/// no tag, count, or alternate representation for a decoder to reinterpret.
pub(crate) fn encode_proof_with_deep_v1(
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
) -> Result<GoldilocksDigest384V1, AggregateStarkErrorV1> {
    let bytes: [u8; GOLDILOCKS_DIGEST384_BYTES_V1] = reader.take().map_err(reader_error_v1)?;
    GoldilocksDigest384V1::from_le_bytes(bytes).ok_or(AggregateStarkErrorV1::NonCanonicalField)
}
fn take_hashes_v1(
    reader: &mut ExactProofReaderV1<'_>,
    count: usize,
) -> Result<Vec<GoldilocksDigest384V1>, AggregateStarkErrorV1> {
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
/// Decode one exact statement-shaped proof and reject every suffix.
pub(crate) fn decode_proof_v1(
    bytes: &[u8],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<AggregateStarkProofV1, AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    if bytes.is_empty() {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    if bytes.len() > parameters.maximum_proof_bytes {
        return Err(AggregateStarkErrorV1::ProofTooLarge);
    }
    let mut reader = ExactProofReaderV1::new(bytes);
    if reader.take::<4>().map_err(reader_error_v1)? != parameters.proof_magic {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    let version = reader.u16().map_err(reader_error_v1)?;
    let group_count = usize::from(reader.u16().map_err(reader_error_v1)?);
    if group_count != layout.trace_groups.len() {
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
                        base_next: take_base_fields_v1(&mut reader, group.base_width)?,
                        aux_current: take_base_fields_v1(&mut reader, group.aux_width)?,
                        aux_next: take_base_fields_v1(&mut reader, group.aux_width)?,
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
    for (group_index, group) in trace_groups.iter_mut().enumerate() {
        let indices = trace_group_opening_indices_v1(&queries, layout, group_index)?;
        let count = multiproof_frontier_len_v1(layout.common_lde_size(), &indices)?;
        group.base_frontier = take_hashes_v1(&mut reader, count)?;
        group.aux_frontier = take_hashes_v1(&mut reader, count)?;
    }
    let composition_indices = composition_opening_indices_v1(&queries, layout)?;
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
                let count =
                    multiproof_frontier_len_v1(layout.common_lde_size() >> round, &indices)?;
                take_hashes_v1(&mut reader, count)
            })
            .collect::<Result<Vec<_>, _>>()?;
    }
    reader.finish().map_err(reader_error_v1)?;
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
    validate_proof_shape_v1(&proof, parameters, layout)?;
    if exact_encoded_proof_bytes_v1(&proof, parameters, layout)? != bytes.len() {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    Ok(proof)
}
/// Decode the sole canonical DEEP-enabled aggregate wire.
pub(crate) fn decode_proof_with_deep_v1(
    bytes: &[u8],
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
) -> Result<(AggregateStarkProofV1, AggregateDeepProofV1), AggregateStarkErrorV1> {
    layout.validate(parameters)?;
    if bytes.is_empty() {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    if bytes.len() > parameters.maximum_proof_bytes {
        return Err(AggregateStarkErrorV1::ProofTooLarge);
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
    if exact_encoded_proof_with_deep_bytes_v1(&proof, &deep, parameters, layout)? != bytes.len() {
        return Err(AggregateStarkErrorV1::MalformedProof);
    }
    Ok((proof, deep))
}
/// Prover material for one ordered trace group on the common LDE domain.
#[derive(Clone)]
pub(crate) struct AggregateTraceGroupMaterialV1 {
    /// Masked base LDE columns.
    pub(crate) base_lde: Vec<Vec<F>>,
    /// Masked auxiliary LDE columns.
    pub(crate) aux_lde: Vec<Vec<F>>,
    /// Base vector-row Merkle tree.
    pub(crate) base_tree: GoldilocksMerkleTreeV1,
    /// Auxiliary vector-row Merkle tree.
    pub(crate) aux_tree: GoldilocksMerkleTreeV1,
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
pub(crate) struct AggregateFriLaneMaterialV1 {
    /// Every FRI layer including the terminal vector.
    pub(crate) layers: ZeroizingExtensionFieldMatrixV1,
    /// Merkle tree for every layer including the terminal vector.
    pub(crate) trees: Vec<GoldilocksMerkleTreeV1>,
    /// Root for every layer including the terminal vector.
    pub(crate) roots: Vec<GoldilocksDigest384V1>,
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
pub(crate) fn build_fri_lane_v1(
    parameters: AggregateStarkParametersV1,
    domains: AggregateStarkDomainsV1,
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
        let tree = fri_tree_v1(domains, lane, round, current)?;
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
    let terminal_tree = fri_tree_v1(domains, lane, fri_rounds, &terminal_values)?;
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
/// Construct all exact opened values for one shared query index.
pub(crate) fn build_query_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    index: usize,
    trace_groups: &[AggregateTraceGroupMaterialV1],
    compositions: &[Vec<Vec<E>>],
    fri_masks: &[AggregateFriMaskOracleMaterialV1],
    fri_lanes: &[AggregateFriLaneMaterialV1],
) -> Result<AggregateQueryProofV1, AggregateStarkErrorV1> {
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
            base_next: row_at_v1(&material.base_lde, next)?
                .into_iter()
                .map(|value| value.0)
                .collect(),
            aux_current: row_at_v1(&material.aux_lde, index)?
                .into_iter()
                .map(|value| value.0)
                .collect(),
            aux_next: row_at_v1(&material.aux_lde, next)?
                .into_iter()
                .map(|value| value.0)
                .collect(),
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
pub(crate) fn build_all_frontiers_v1(
    parameters: AggregateStarkParametersV1,
    layout: &AggregateProofLayoutV1,
    queries: &[AggregateQueryProofV1],
    trace_groups: &[AggregateTraceGroupMaterialV1],
    composition_trees: &[GoldilocksMerkleTreeV1],
    fri_masks: &[AggregateFriMaskOracleMaterialV1],
    fri_lanes: &[AggregateFriLaneMaterialV1],
) -> Result<
    (
        Vec<(Vec<GoldilocksDigest384V1>, Vec<GoldilocksDigest384V1>)>,
        Vec<Vec<GoldilocksDigest384V1>>,
        Vec<Vec<GoldilocksDigest384V1>>,
        Vec<Vec<Vec<GoldilocksDigest384V1>>>,
    ),
    AggregateStarkErrorV1,
> {
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
                        layout.common_lde_size() >> round,
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
/// Verify all base, auxiliary, composition, and non-terminal FRI multiproofs.
pub(crate) fn verify_all_merkle_openings_v1(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    domains: AggregateStarkDomainsV1,
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
        let index =
            usize::try_from(query.index).map_err(|_| AggregateStarkErrorV1::TranscriptMismatch)?;
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
            let base_current = canonical_fields_v1(&opening.base_current, descriptor.base_width)?;
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
                let low =
                    E::canonical(opening.low).ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
                let high =
                    E::canonical(opening.high).ok_or(AggregateStarkErrorV1::NonCanonicalField)?;
                let half = layer_size / 2;
                let low_index = layer_index % half;
                insert_opened_leaf_v1(
                    &mut fri_leaves[lane][round],
                    low_index,
                    fri_leaf_hash_unchecked_v1(domains, lane, round, low_index, low)?,
                )
                .map_err(|_| AggregateStarkErrorV1::FriOpening)?;
                insert_opened_leaf_v1(
                    &mut fri_leaves[lane][round],
                    low_index + half,
                    fri_leaf_hash_unchecked_v1(domains, lane, round, low_index + half, high)?,
                )
                .map_err(|_| AggregateStarkErrorV1::FriOpening)?;
                layer_index = low_index;
                layer_size = half;
            }
        }
    }
    for group in 0..layout.trace_groups.len() {
        verify_canonical_multiproof_v1(
            domains.digest_context,
            domains.base_node,
            &proof.trace_groups[group].base_root,
            layout.common_lde_size(),
            &base_leaves[group],
            &proof.trace_groups[group].base_frontier,
        )?;
        verify_canonical_multiproof_v1(
            domains.digest_context,
            domains.aux_node,
            &proof.trace_groups[group].aux_root,
            layout.common_lde_size(),
            &aux_leaves[group],
            &proof.trace_groups[group].aux_frontier,
        )?;
    }
    for lane in 0..parameters.security_lanes {
        verify_canonical_multiproof_v1(
            domains.digest_context,
            domains.composition_node,
            &proof.composition_roots[lane],
            layout.common_lde_size(),
            &composition_leaves[lane],
            &proof.composition_frontiers[lane],
        )
        .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        verify_canonical_multiproof_v1(
            domains.digest_context,
            FRI_MASK_NODE_DOMAIN_V1,
            &proof.fri_mask_roots[lane],
            layout.common_lde_size(),
            &fri_mask_leaves[lane],
            &proof.fri_mask_frontiers[lane],
        )
        .map_err(|_| AggregateStarkErrorV1::FriOpening)?;
        for round in 0..fri_rounds {
            verify_canonical_multiproof_v1(
                domains.digest_context,
                domains.fri_node,
                &proof.fri_lanes[lane].roots[round],
                layout.common_lde_size() >> round,
                &fri_leaves[lane][round],
                &proof.fri_lanes[lane].round_frontiers[round],
            )
            .map_err(|_| AggregateStarkErrorV1::FriOpening)?;
        }
    }
    Ok(())
}
/// Verify and transcript-bind terminal FRI vectors, returning fold challenges.
pub(crate) fn verify_fri_commitments_v1(
    proof: &AggregateStarkProofV1,
    parameters: AggregateStarkParametersV1,
    domains: AggregateStarkDomainsV1,
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
        let terminal_tree = fri_tree_v1(domains, lane, fri_rounds, &terminal)?;
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
pub(crate) fn verify_opened_query_relations_with_deep_v1<
    Evaluator: AggregateOpenedRowEvaluatorV1,
>(
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
                    base_next: canonical_fields_v1(&opening.base_next, descriptor.base_width)?,
                    aux_current: canonical_fields_v1(&opening.aux_current, descriptor.aux_width)?,
                    aux_next: canonical_fields_v1(&opening.aux_next, descriptor.aux_width)?,
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
            let fri_base = deep_ali_mixed_opening_v1(
                query_point,
                deep_point,
                layout,
                &opened_groups,
                &deep_trace_groups,
                &composition_chunks,
                &deep_compositions[lane],
                &deep_mixes[lane],
            )?;
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
#[path = "aggregate_stark/retained_polynomial_tests.rs"]
mod retained_polynomial_tests;
