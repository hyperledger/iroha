//! Shared transparent STARK substrate for proof-managed private-note pools.
//!
//! This module owns proof-system mechanics and relation-neutral note chips: canonical byte range
//! checks, a three-lane byte-copy permutation, masked trace LDEs, verifier-fixed preprocessing,
//! quotient composition, SHA3-384 vector-row commitments, binary FRI, grinding, and the exact
//! aggregate proof codec. Protocol adapters retain their statement policy, ordered hash schedule,
//! profile-only rows, public-input digest, and error mapping.
//!
//! The substrate deliberately has no activation or ledger-effect API. A profile is not safe to
//! expose until its extension-domain residue evaluator, strict proof adversaries, native
//! differential tests, and typed state transition are all complete.
use super::{
    aggregate_stark::{self as aggregate, AggregateOpenedRowEvaluatorV1},
    proof_phase_diagnostics::{ManagedNotePhaseCursorV1, ProofPhaseInvocationV1, ProofPhaseV1},
    transparent_stark::{
        GOLDILOCKS_GENERATOR_V1, GoldilocksFieldV1 as F, GoldilocksFp4V1 as E,
        PrivacyOuterDigestV1, ReplayableTraceMaskV1, TransparentStarkErrorV1,
        TransparentTranscriptV1, goldilocks_fft_v1, goldilocks_ifft_v1,
        goldilocks_primitive_root_v1, grind_nonce_v1, masked_trace_lde_column_with_mask_v1,
        privacy_outer_digest_frame_v1, sample_trace_mask_v1, transparent_stark_zk_mask_geometry_v1,
        verify_grinding_nonce_v1,
    },
};
#[cfg(test)]
use iroha_data_model::privacy::{PrivacyProtocolIdV1, TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1};

use rand::TryRngCore;
use rayon::prelude::*;
use std::collections::BTreeSet;
use thiserror::Error;
#[path = "proof_managed_note_stark_fixed_queries.rs"]
mod fixed_queries;
/// Number of byte-copy cells in every shared note row.
pub const NOTE_COPY_WIDTH_V1: usize = 8;
/// Independent copy-permutation lanes.
pub const NOTE_COPY_LANES_V1: usize = 3;
/// Byte decomposition columns in the copy auxiliary trace.
pub const NOTE_COPY_BIT_COLUMNS_V1: usize = NOTE_COPY_WIDTH_V1 * 8;
/// Dual running products and product-tree columns per copy lane.
pub const NOTE_COPY_PRODUCT_COLUMNS_PER_LANE_V1: usize = 18;
/// Complete shared copy auxiliary width.
pub const NOTE_COPY_AUX_WIDTH_V1: usize =
    NOTE_COPY_BIT_COLUMNS_V1 + NOTE_COPY_LANES_V1 * NOTE_COPY_PRODUCT_COLUMNS_PER_LANE_V1;
/// Verifier-fixed copy columns: identity, sigma, policy, and boundaries.
pub const NOTE_COPY_FIXED_WIDTH_V1: usize = NOTE_COPY_WIDTH_V1 * 5 + 3;
/// Maximum algebraic degree of every shared copy-chip constraint.
pub const NOTE_COPY_CONSTRAINT_DEGREE_V1: u8 = 2;
/// Number of shared copy constraints before profile-only residues.
pub const NOTE_COPY_CONSTRAINT_COUNT_V1: usize =
    NOTE_COPY_BIT_COLUMNS_V1 + 3 * NOTE_COPY_WIDTH_V1 + 21 * NOTE_COPY_LANES_V1;
const COPY_FIXED_IDENTITY_OFFSET: usize = 0;
const COPY_FIXED_SIGMA_OFFSET: usize = COPY_FIXED_IDENTITY_OFFSET + NOTE_COPY_WIDTH_V1;
const COPY_FIXED_INACTIVE_OFFSET: usize = COPY_FIXED_SIGMA_OFFSET + NOTE_COPY_WIDTH_V1;
const COPY_FIXED_CONSTANT_SELECTOR_OFFSET: usize = COPY_FIXED_INACTIVE_OFFSET + NOTE_COPY_WIDTH_V1;
const COPY_FIXED_CONSTANT_VALUE_OFFSET: usize =
    COPY_FIXED_CONSTANT_SELECTOR_OFFSET + NOTE_COPY_WIDTH_V1;
const COPY_FIXED_FIRST: usize = COPY_FIXED_CONSTANT_VALUE_OFFSET + NOTE_COPY_WIDTH_V1;
const COPY_FIXED_LAST: usize = COPY_FIXED_FIRST + 1;
const COPY_FIXED_TRANSITION: usize = COPY_FIXED_LAST + 1;
const COPY_AUX_BITS_OFFSET: usize = 0;
const COPY_AUX_PRODUCTS_OFFSET: usize = COPY_AUX_BITS_OFFSET + NOTE_COPY_BIT_COLUMNS_V1;
const COPY_NUMERATOR_BEFORE: usize = 0;
const COPY_NUMERATOR_AFTER: usize = 1;
const COPY_DENOMINATOR_BEFORE: usize = 2;
const COPY_DENOMINATOR_AFTER: usize = 3;
const COPY_NUMERATOR_PAIRS: usize = 4;
const COPY_NUMERATOR_QUADS: usize = 8;
const COPY_NUMERATOR_TOTAL: usize = 10;
const COPY_DENOMINATOR_PAIRS: usize = 11;
const COPY_DENOMINATOR_QUADS: usize = 15;
const COPY_DENOMINATOR_TOTAL: usize = 17;
const NOTE_CONSTRAINT_ALPHA_LABEL_V1: &[u8] = b"proof-managed-note-stark-constraint-alpha-v1";
const NOTE_DEEP_BASE_CURRENT_MIX_LABEL_V1: &[u8] =
    b"proof-managed-note-stark-deep-base-current-mix-v1";
const NOTE_DEEP_BASE_NEXT_MIX_LABEL_V1: &[u8] = b"proof-managed-note-stark-deep-base-next-mix-v1";
const NOTE_DEEP_AUX_CURRENT_MIX_LABEL_V1: &[u8] =
    b"proof-managed-note-stark-deep-aux-current-mix-v1";
const NOTE_DEEP_AUX_NEXT_MIX_LABEL_V1: &[u8] = b"proof-managed-note-stark-deep-aux-next-mix-v1";
const NOTE_DEEP_COMPOSITION_MIX_LABEL_V1: &[u8] =
    b"proof-managed-note-stark-deep-composition-mix-v1";
const NOTE_GRINDING_LABEL_V1: &[u8] = b"proof-managed-note-stark-grinding-nonce-v1";
const NOTE_COPY_BETA_LABEL_V1: &[u8] = b"proof-managed-note-stark-copy-beta-v1";
const NOTE_COPY_GAMMA_LABEL_V1: &[u8] = b"proof-managed-note-stark-copy-gamma-v1";
const NOTE_SHARED_PROFILE_BINDING_LABEL_V1: &[u8] =
    b"proof-managed-note-stark-shared-profile-binding-v1";
const NOTE_COMBINED_PROFILE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.privacy.proof-managed-note-stark.combined-profile.v1";
/// Sole first-release proof-system identity for proof-managed note pools.
pub const PROOF_MANAGED_NOTE_STARK_SUITE_V1: &[u8] = b"StarkFriSha3_384Goldilocks";
/// Independent composition and FRI lanes in the first-release profile.
pub const PROOF_MANAGED_NOTE_SECURITY_LANES_V1: usize = 1;
/// Unique shared extension-domain queries in the first-release profile.
pub const PROOF_MANAGED_NOTE_QUERY_COUNT_V1: usize = 136;
/// Trace-to-LDE blow-up logarithm in the first-release profile.
pub const PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1: u8 = 3;
/// Terminal FRI vector logarithm in the first-release profile.
pub const PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1: u8 = 10;
/// Exact terminal FRI polynomial-degree bound.
pub const PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1: usize = 143;
/// Coefficient chunks used to normalize degree-four quotient polynomials.
pub const PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1: usize = 4;
/// One out-of-domain DEEP-ALI query binds each neighboring-row AIR.
pub const PROOF_MANAGED_NOTE_DEEP_QUERY_COUNT_V1: usize = 1;
/// Largest native trace supported by the shared first-release soundness proof.
pub const PROOF_MANAGED_NOTE_MAX_NATIVE_TRACE_LOG2_V1: u8 = 14;
/// Inclusive trace zero-knowledge mask degree.
pub const PROOF_MANAGED_NOTE_MASK_DEGREE_V1: usize = 975;
/// Largest constraint degree supported by the first-release FRI profile.
pub const PROOF_MANAGED_NOTE_MAX_CONSTRAINT_DEGREE_V1: u8 = 4;
/// Exact transcript grinding target.
pub const PROOF_MANAGED_NOTE_GRINDING_BITS_V1: u8 = 20;
/// Required non-grinding soundness floor for every proof-managed note profile.
pub const PROOF_MANAGED_NOTE_TARGET_SOUNDNESS_BITS_V1: u16 = 128;
/// Machine-checked affine-batched FRI query-error exponent at 136 queries.
pub const PROOF_MANAGED_NOTE_FRI_QUERY_ERROR_BITS_V1: u16 = 160;
/// Worst-case interactive FRI algebraic commitment-error exponent at the maximum native trace.
/// This excludes outer-hash collision and Fiat--Shamir/QROM composition reductions.
pub const PROOF_MANAGED_NOTE_FRI_COMMITMENT_ERROR_BITS_MIN_V1: u16 = 197;
/// Affine batching parameter in the sole first-release FRI theorem instance.
pub const PROOF_MANAGED_NOTE_FRI_BATCHING_PARAMETER_M_V1: u8 = 3;
/// Exact effective FRI code-rate numerator.
pub const PROOF_MANAGED_NOTE_FRI_RATE_NUMERATOR_V1: u8 = 1;
/// Exact effective FRI code-rate denominator.
pub const PROOF_MANAGED_NOTE_FRI_RATE_DENOMINATOR_V1: u8 = 7;
/// Arity repeated for every actual binary FRI reduction.
pub const PROOF_MANAGED_NOTE_FRI_BINARY_FOLD_ARITY_V1: u8 = 2;
/// Proven lower-bound exponent for the Goldilocks quartic extension field.
pub const PROOF_MANAGED_NOTE_EXTENSION_FIELD_LOWER_BOUND_BITS_V1: u16 = 252;
/// Complete relation-neutral first-release proof-driver geometry.
///
/// Protocol adapters bind a separate relation descriptor. The canonical
/// profile digest frames this shared descriptor first and the relation
/// descriptor second, so neither layer can silently restate stale geometry.
pub const PROOF_MANAGED_NOTE_STARK_GEOMETRY_DESCRIPTOR_V1: &[u8] = b"proof-managed-note-stark-geometry-v1:proof=StarkFriSha3_384Goldilocks:base-field=goldilocks:challenge-field=goldilocks-fp4:merkle=sha3-384:transcript=sha3-384:copy-width=8:copy-lanes=3:copy-aux-width=118:copy-fixed-width=43:copy-constraints=151:copy-constraint-degree=2:security-lanes=1:queries=136:lde-blowup=8:composition-degree-chunks=4:deep-points=1:deep-openings=base-current,base-next,aux-current,aux-next,composition:deep-mixes=independent:max-native-trace-log2=14:trace-mask-degree=975:trace-mask-coefficients=976:max-constraint-degree=4:fri-terminal=1024:fri-degree=143:fri-input=deep-ali:fri-theorem=affine-batched-theorem2:affine-batching-coefficient=3/2:batching-m=3:rho-upper-bound=1/7:binary-fold-arity=2:extension-field-lower-bound-bits=252:query-error-bits=160:fri-algebraic-commitment-error-bits-min=197:target-soundness-bits=128:grinding=20-nonadditive:frame=privacy-sha3-384-be-v1:scalar-fp4=bounded-be-u64-rejection:query-source=2^64:codec=fixed-public-profile-length-opaque-digest48-canonical-be-fields:frontiers=canonical-minimal:padding=required-zero-tail-to-maximum-encoded-proof-with-deep-v1";
/// Derive the canonical digest of shared proof geometry plus one relation.
pub fn proof_managed_note_stark_profile_digest_v1(
    domains: &aggregate::AggregateStarkDomainsV1,
    relation_descriptor: &[u8],
) -> Result<PrivacyOuterDigestV1, ProofManagedNoteStarkErrorV1> {
    privacy_outer_digest_frame_v1(
        domains.digest_context,
        NOTE_COMBINED_PROFILE_DIGEST_DOMAIN_V1,
        b"compiled-profile",
        0,
        0,
        0,
        &[
            PROOF_MANAGED_NOTE_STARK_GEOMETRY_DESCRIPTOR_V1,
            relation_descriptor,
        ],
    )
    .map_err(map_transparent_error_v1)
}
/// Derive the protocol-bound digest of the shared proof geometry.
pub fn proof_managed_note_stark_geometry_digest_v1(
    domains: &aggregate::AggregateStarkDomainsV1,
) -> Result<PrivacyOuterDigestV1, ProofManagedNoteStarkErrorV1> {
    privacy_outer_digest_frame_v1(
        domains.digest_context,
        NOTE_COMBINED_PROFILE_DIGEST_DOMAIN_V1,
        b"shared-geometry",
        0,
        0,
        0,
        &[PROOF_MANAGED_NOTE_STARK_GEOMETRY_DESCRIPTOR_V1],
    )
    .map_err(map_transparent_error_v1)
}
/// Shared proof-driver or copy-chip failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ProofManagedNoteStarkErrorV1 {
    /// The compiled profile or verifier-derived trace shape is invalid.
    #[error("proof-managed note STARK profile is invalid")]
    InvalidProfile,
    /// A prover trace does not have the exact compiled shape.
    #[error("proof-managed note STARK trace shape is invalid")]
    InvalidTrace,
    /// A byte-copy policy, permutation, or product relation is invalid.
    #[error("proof-managed note STARK copy relation is invalid")]
    Copy,
    /// A profile-specific algebraic residue failed.
    #[error("proof-managed note STARK relation constraint is invalid")]
    Constraint,
    /// The proof wire is empty, malformed, non-canonical, or oversized.
    #[error("proof-managed note STARK proof wire is invalid")]
    ProofWire,
    /// A committed trace opening failed.
    #[error("proof-managed note STARK trace opening is invalid")]
    TraceOpening,
    /// A quotient or composition opening failed.
    #[error("proof-managed note STARK composition opening is invalid")]
    Composition,
    /// A FRI opening or degree check failed.
    #[error("proof-managed note STARK FRI relation is invalid")]
    Fri,
    /// Transcript challenges, grinding, or query positions differ.
    #[error("proof-managed note STARK transcript is invalid")]
    Transcript,
    /// Masking entropy is unavailable.
    #[error("proof-managed note STARK masking entropy is unavailable")]
    Randomness,
    /// A bounded allocation or checked dimension calculation failed.
    #[error("proof-managed note STARK resource bound is exceeded")]
    Resource,
    /// A checked internal invariant failed.
    #[error("proof-managed note STARK internal invariant failed")]
    Internal,
}
fn map_transparent_error_v1(error: TransparentStarkErrorV1) -> ProofManagedNoteStarkErrorV1 {
    match error {
        TransparentStarkErrorV1::RandomnessUnavailable => ProofManagedNoteStarkErrorV1::Randomness,
        TransparentStarkErrorV1::AllocationFailure => ProofManagedNoteStarkErrorV1::Resource,
        TransparentStarkErrorV1::NonCanonicalField | TransparentStarkErrorV1::MalformedProof => {
            ProofManagedNoteStarkErrorV1::ProofWire
        }
        TransparentStarkErrorV1::FriDegree => ProofManagedNoteStarkErrorV1::Fri,
        TransparentStarkErrorV1::InvalidMerkleShape => ProofManagedNoteStarkErrorV1::TraceOpening,
        TransparentStarkErrorV1::ChallengeSamplingExhausted
        | TransparentStarkErrorV1::QuerySamplingExhausted
        | TransparentStarkErrorV1::InvalidGrinding => ProofManagedNoteStarkErrorV1::Transcript,
        _ => ProofManagedNoteStarkErrorV1::Internal,
    }
}
fn map_aggregate_error_v1(error: aggregate::AggregateStarkErrorV1) -> ProofManagedNoteStarkErrorV1 {
    match error {
        aggregate::AggregateStarkErrorV1::InvalidLayout => {
            ProofManagedNoteStarkErrorV1::InvalidProfile
        }
        aggregate::AggregateStarkErrorV1::InvalidProofShape => {
            ProofManagedNoteStarkErrorV1::ProofWire
        }
        aggregate::AggregateStarkErrorV1::MalformedProof
        | aggregate::AggregateStarkErrorV1::ProofTooLarge
        | aggregate::AggregateStarkErrorV1::NonCanonicalField => {
            ProofManagedNoteStarkErrorV1::ProofWire
        }
        aggregate::AggregateStarkErrorV1::TraceOpening => {
            ProofManagedNoteStarkErrorV1::TraceOpening
        }
        aggregate::AggregateStarkErrorV1::ConstraintOpening => {
            ProofManagedNoteStarkErrorV1::Composition
        }
        aggregate::AggregateStarkErrorV1::DeepOpening => ProofManagedNoteStarkErrorV1::Composition,
        aggregate::AggregateStarkErrorV1::FriOpening
        | aggregate::AggregateStarkErrorV1::FriDegree => ProofManagedNoteStarkErrorV1::Fri,
        aggregate::AggregateStarkErrorV1::TranscriptMismatch => {
            ProofManagedNoteStarkErrorV1::Transcript
        }
        aggregate::AggregateStarkErrorV1::AllocationFailure => {
            ProofManagedNoteStarkErrorV1::Resource
        }
        aggregate::AggregateStarkErrorV1::RandomnessUnavailable => {
            ProofManagedNoteStarkErrorV1::Randomness
        }
        aggregate::AggregateStarkErrorV1::InternalInvariant => {
            ProofManagedNoteStarkErrorV1::Internal
        }
    }
}
/// Closed protocol data supplied by one compiled private-note profile.
///
/// The generic driver fixes every cryptographic primitive and security dimension. A profile may
/// only choose its exact wire magic/version, bounded trace range, widths, byte ceiling, transcript
/// domains, and compiled descriptor/digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofManagedNoteStarkProtocolV1 {
    /// Exact aggregate proof dimensions and wire limits.
    pub(crate) parameters: aggregate::AggregateStarkParametersV1,
    /// Complete SHA3-384 Merkle and transcript domains.
    pub(crate) domains: aggregate::AggregateStarkDomainsV1,
    /// Maximum algebraic degree across shared and profile constraints.
    pub(crate) maximum_constraint_degree: u8,
    /// Transcript label binding the human-auditable compiled descriptor.
    pub(crate) profile_binding_label: &'static [u8],
    /// Complete immutable profile descriptor.
    pub(crate) profile_descriptor: &'static [u8],
    /// Relation-specific domain embedded in the ordered layout frame.
    pub(crate) relation_layout_domain: &'static [u8],
}
fn validate_note_fri_soundness_v1(
    parameters: aggregate::AggregateStarkParametersV1,
) -> Result<aggregate::AggregateFriTheorem2BoundV1, ProofManagedNoteStarkErrorV1> {
    let layout = aggregate::AggregateProofLayoutV1::new(
        parameters,
        vec![aggregate::AggregateTraceGroupLayoutV1 {
            native_trace_log2: parameters.maximum_trace_log2,
            segment_instances: 1,
            base_width: parameters.maximum_base_columns_per_instance,
            aux_width: parameters.maximum_aux_columns_per_instance,
        }],
    )
    .map_err(map_aggregate_error_v1)?;
    let fold_count = u8::try_from(
        layout
            .fri_rounds(parameters)
            .map_err(map_aggregate_error_v1)?,
    )
    .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    let terminal_degree_bound = u16::try_from(parameters.terminal_degree_bound)
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    let query_count = u8::try_from(parameters.query_count)
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    let certificate = aggregate::AggregateFriTheorem2CertificateV1 {
        affine_coefficient_numerator: 3,
        affine_coefficient_denominator: 2,
        batching_parameter_m: PROOF_MANAGED_NOTE_FRI_BATCHING_PARAMETER_M_V1,
        rho_numerator: PROOF_MANAGED_NOTE_FRI_RATE_NUMERATOR_V1,
        rho_denominator: PROOF_MANAGED_NOTE_FRI_RATE_DENOMINATOR_V1,
        binary_fold_arity: PROOF_MANAGED_NOTE_FRI_BINARY_FOLD_ARITY_V1,
        domain_log2: layout.common_lde_log2(),
        extension_field_lower_bound_bits: PROOF_MANAGED_NOTE_EXTENSION_FIELD_LOWER_BOUND_BITS_V1,
        base_field_two_adicity: 32,
        trace_domains_are_smooth_subgroups: true,
        evaluation_domain_is_smooth_generator_coset: true,
        evaluation_domain_is_disjoint_from_trace_domains: true,
        fold_count,
        terminal_log2: parameters.terminal_log2,
        terminal_degree_bound,
        query_count,
        distinct_queries_without_replacement: true,
        uniform_rejection_sampling: true,
        claimed_query_error_bits: PROOF_MANAGED_NOTE_FRI_QUERY_ERROR_BITS_V1,
    };
    aggregate::validate_affine_batched_fri_theorem2_v1(parameters, &layout, certificate)
        .map_err(map_aggregate_error_v1)
}
impl ProofManagedNoteStarkProtocolV1 {
    /// Enforce the sole first-release security profile and unique domains.
    pub(crate) fn validate(self) -> Result<(), ProofManagedNoteStarkErrorV1> {
        self.parameters.validate().map_err(map_aggregate_error_v1)?;
        self.domains.validate().map_err(map_aggregate_error_v1)?;
        // Reject caller-controlled degrees before deriving mask geometry, whose
        // zero-degree error would otherwise be misclassified as internal.
        if !(NOTE_COPY_CONSTRAINT_DEGREE_V1..=PROOF_MANAGED_NOTE_MAX_CONSTRAINT_DEGREE_V1)
            .contains(&self.maximum_constraint_degree)
        {
            return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
        }
        let fri_soundness = validate_note_fri_soundness_v1(self.parameters)?;
        let mask_geometry = transparent_stark_zk_mask_geometry_v1(
            usize::from(
                self.maximum_constraint_degree
                    .checked_sub(1)
                    .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?,
            ),
            4,
            PROOF_MANAGED_NOTE_DEEP_QUERY_COUNT_V1,
            self.parameters.query_count,
        )
        .map_err(map_transparent_error_v1)?;
        let consensus_proof_cap = self.domains.digest_context.maximum_proof_bytes_v1();
        let _combined_profile_digest =
            proof_managed_note_stark_profile_digest_v1(&self.domains, self.profile_descriptor)?;
        if self.parameters.security_lanes != PROOF_MANAGED_NOTE_SECURITY_LANES_V1
            || self.parameters.query_count != PROOF_MANAGED_NOTE_QUERY_COUNT_V1
            || self.parameters.blowup_log2 != PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1
            || self.parameters.terminal_log2 != PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1
            || self.parameters.terminal_degree_bound != PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1
            || self.parameters.composition_degree_chunks
                != PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1
            || self.parameters.maximum_trace_log2 > PROOF_MANAGED_NOTE_MAX_NATIVE_TRACE_LOG2_V1
            || self.parameters.maximum_trace_groups != 1
            || self.parameters.maximum_segment_instances != 1
            || self.parameters.maximum_proof_bytes > consensus_proof_cap
            || PROOF_MANAGED_NOTE_MASK_DEGREE_V1 < mask_geometry.minimum_mask_degree
            || fri_soundness.query_error_bits != PROOF_MANAGED_NOTE_FRI_QUERY_ERROR_BITS_V1
            || fri_soundness.commitment_error_bits
                < PROOF_MANAGED_NOTE_FRI_COMMITMENT_ERROR_BITS_MIN_V1
            || fri_soundness.query_error_bits < PROOF_MANAGED_NOTE_TARGET_SOUNDNESS_BITS_V1
            || fri_soundness.commitment_error_bits < PROOF_MANAGED_NOTE_TARGET_SOUNDNESS_BITS_V1
            || self.profile_binding_label.is_empty()
            || self.profile_descriptor.is_empty()
            || self.relation_layout_domain.is_empty()
        {
            return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
        }
        let extra_domains = [
            NOTE_SHARED_PROFILE_BINDING_LABEL_V1,
            self.profile_binding_label,
            self.relation_layout_domain,
            NOTE_CONSTRAINT_ALPHA_LABEL_V1,
            NOTE_DEEP_BASE_CURRENT_MIX_LABEL_V1,
            NOTE_DEEP_BASE_NEXT_MIX_LABEL_V1,
            NOTE_DEEP_AUX_CURRENT_MIX_LABEL_V1,
            NOTE_DEEP_AUX_NEXT_MIX_LABEL_V1,
            NOTE_DEEP_COMPOSITION_MIX_LABEL_V1,
            NOTE_GRINDING_LABEL_V1,
            NOTE_COPY_BETA_LABEL_V1,
            NOTE_COPY_GAMMA_LABEL_V1,
        ];
        if extra_domains
            .iter()
            .any(|domain| domain.is_empty() || u16::try_from(domain.len()).is_err())
        {
            return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
        }
        for (index, domain) in extra_domains.iter().enumerate() {
            if extra_domains[..index].contains(domain) {
                return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
            }
        }
        let aggregate_domains = [
            self.domains.base_leaf,
            self.domains.base_node,
            self.domains.aux_leaf,
            self.domains.aux_node,
            self.domains.composition_leaf,
            self.domains.composition_node,
            self.domains.fri_leaf,
            self.domains.fri_node,
            self.domains.layout_label,
            self.domains.base_root_label,
            self.domains.aux_root_label,
            self.domains.composition_root_label,
            self.domains.fri_root_label,
            self.domains.fri_beta_label,
            self.domains.query_seed,
        ];
        if extra_domains.iter().any(|domain| {
            aggregate_domains.contains(domain)
                || aggregate::aggregate_stark_domain_is_reserved_v1(domain)
        }) {
            return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
        }
        Ok(())
    }
}
/// Statement-derived relation adapter consumed by the shared proof driver.
///
/// Base columns always begin with the eight byte-copy cells. Auxiliary columns
/// begin with [`NOTE_COPY_AUX_WIDTH_V1`] shared columns, and fixed columns begin
/// with [`NOTE_COPY_FIXED_WIDTH_V1`] shared columns. Profile methods receive
/// those complete, prefix-stable rows so they can reuse shared byte
/// decompositions without duplicating range checks. Adapters and their derived
/// challenges are immutable and `Sync` because quotient rows are evaluated in
/// deterministic parallel batches.
pub trait ProofManagedNoteStarkAdapterV1: Sync {
    /// Profile-specific Fiat-Shamir challenges derived after copy challenges.
    type ProfileChallenges: Clone + Sync;
    /// Closed proof protocol.
    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1;
    /// Exact digest of all public statement fields.
    fn public_input_digest_v1(&self) -> Result<PrivacyOuterDigestV1, ProofManagedNoteStarkErrorV1>;
    /// Binary logarithm of the sole native trace group.
    fn trace_log2_v1(&self) -> u8;
    /// Exact base-trace width, including the eight copy cells.
    fn base_width_v1(&self) -> usize;
    /// Profile-only auxiliary width after the shared prefix.
    fn profile_aux_width_v1(&self) -> usize;
    /// Profile-only verifier-fixed width after the shared prefix.
    fn profile_fixed_width_v1(&self) -> usize;
    /// Profile-only algebraic residue count after shared copy residues.
    fn profile_constraint_count_v1(&self) -> usize;
    /// Reconstruct the complete verifier-fixed copy policy.
    fn copy_schedule_v1(&self) -> Result<NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1>;
    /// Reconstruct profile-only fixed columns on the native domain.
    fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1>;
    /// Derive profile challenges after the shared copy challenges.
    fn derive_profile_challenges_v1(
        &self,
        transcript: &mut TransparentTranscriptV1,
        copy_challenges: NoteCopyChallengesV1,
    ) -> Result<Self::ProfileChallenges, ProofManagedNoteStarkErrorV1>;
    /// Build profile-only auxiliary columns on the native domain.
    fn build_profile_aux_columns_v1(
        &self,
        base_columns: &[Vec<F>],
        copy_aux_columns: &[Vec<F>],
        fixed_columns: &[Vec<F>],
        copy_challenges: NoteCopyChallengesV1,
        profile_challenges: &Self::ProfileChallenges,
    ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1>;
    /// Evaluate profile-only polynomial residues at one current/next row pair.
    fn profile_constraint_residues_v1(
        &self,
        current_base: &[F],
        next_base: &[F],
        current_aux: &[F],
        next_aux: &[F],
        fixed: &[F],
        copy_challenges: NoteCopyChallengesV1,
        profile_challenges: &Self::ProfileChallenges,
    ) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1>;
}
/// Fixed policy for one byte-copy cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteCopyCellPolicyV1 {
    /// The cell is fixed to zero and does not join a variable cycle.
    Inactive,
    /// The cell is fixed to this exact byte.
    Constant(u8),
    /// The cell belongs to a verifier-fixed variable cycle.
    Variable,
}
/// Verifier-fixed copy policy and permutation for a complete note trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteCopyScheduleV1 {
    /// Per-row cell policy.
    pub(crate) policies: Vec<[NoteCopyCellPolicyV1; NOTE_COPY_WIDTH_V1]>,
    /// One-based target label for every copy cell.
    pub(crate) sigma: Vec<[u32; NOTE_COPY_WIDTH_V1]>,
}
impl NoteCopyScheduleV1 {
    /// Validate the exact size, label permutation, and policy separation.
    pub(crate) fn validate(&self, trace_size: usize) -> Result<(), ProofManagedNoteStarkErrorV1> {
        if trace_size == 0
            || !trace_size.is_power_of_two()
            || self.policies.len() != trace_size
            || self.sigma.len() != trace_size
        {
            return Err(ProofManagedNoteStarkErrorV1::Copy);
        }
        let labels = trace_size
            .checked_mul(NOTE_COPY_WIDTH_V1)
            .ok_or(ProofManagedNoteStarkErrorV1::Resource)?;
        if labels > u32::MAX as usize {
            return Err(ProofManagedNoteStarkErrorV1::Resource);
        }
        let mut seen = BTreeSet::new();
        for row in 0..trace_size {
            for column in 0..NOTE_COPY_WIDTH_V1 {
                let identity = row
                    .checked_mul(NOTE_COPY_WIDTH_V1)
                    .and_then(|value| value.checked_add(column))
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ProofManagedNoteStarkErrorV1::Resource)?;
                let target = usize::try_from(self.sigma[row][column])
                    .map_err(|_| ProofManagedNoteStarkErrorV1::Copy)?;
                if target == 0 || target > labels || !seen.insert(target) {
                    return Err(ProofManagedNoteStarkErrorV1::Copy);
                }
                let target_zero = target - 1;
                let target_row = target_zero / NOTE_COPY_WIDTH_V1;
                let target_column = target_zero % NOTE_COPY_WIDTH_V1;
                match self.policies[row][column] {
                    NoteCopyCellPolicyV1::Variable => {
                        if !matches!(
                            self.policies[target_row][target_column],
                            NoteCopyCellPolicyV1::Variable
                        ) {
                            return Err(ProofManagedNoteStarkErrorV1::Copy);
                        }
                    }
                    NoteCopyCellPolicyV1::Inactive | NoteCopyCellPolicyV1::Constant(_) => {
                        if target != identity {
                            return Err(ProofManagedNoteStarkErrorV1::Copy);
                        }
                    }
                }
            }
        }
        if seen.len() != labels {
            return Err(ProofManagedNoteStarkErrorV1::Copy);
        }
        Ok(())
    }
    /// Compile the fixed copy preprocessing columns on the native domain.
    pub(crate) fn fixed_columns_v1(
        &self,
        trace_size: usize,
    ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        self.validate(trace_size)?;
        let mut columns = vec![vec![F::ZERO; trace_size]; NOTE_COPY_FIXED_WIDTH_V1];
        for row in 0..trace_size {
            for column in 0..NOTE_COPY_WIDTH_V1 {
                let identity = row
                    .checked_mul(NOTE_COPY_WIDTH_V1)
                    .and_then(|value| value.checked_add(column))
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ProofManagedNoteStarkErrorV1::Resource)?;
                columns[COPY_FIXED_IDENTITY_OFFSET + column][row] =
                    F(u64::try_from(identity)
                        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?);
                columns[COPY_FIXED_SIGMA_OFFSET + column][row] =
                    F(u64::from(self.sigma[row][column]));
                match self.policies[row][column] {
                    NoteCopyCellPolicyV1::Inactive => {
                        columns[COPY_FIXED_INACTIVE_OFFSET + column][row] = F::ONE;
                    }
                    NoteCopyCellPolicyV1::Constant(value) => {
                        columns[COPY_FIXED_CONSTANT_SELECTOR_OFFSET + column][row] = F::ONE;
                        columns[COPY_FIXED_CONSTANT_VALUE_OFFSET + column][row] =
                            F(u64::from(value));
                    }
                    NoteCopyCellPolicyV1::Variable => {}
                }
            }
            columns[COPY_FIXED_FIRST][row] = F(u64::from(row == 0));
            columns[COPY_FIXED_LAST][row] = F(u64::from(row + 1 == trace_size));
            columns[COPY_FIXED_TRANSITION][row] = F(u64::from(row + 1 < trace_size));
        }
        Ok(columns)
    }
}
/// One copy-permutation lane's transcript challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteCopyLaneChallengesV1 {
    /// Cell-label mixing challenge.
    pub(crate) beta: F,
    /// Additive nonzero shift.
    pub(crate) gamma: F,
}
/// Three independent copy-permutation challenge lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteCopyChallengesV1 {
    /// Closed three-lane challenge set.
    pub(crate) lanes: [NoteCopyLaneChallengesV1; NOTE_COPY_LANES_V1],
}
/// Derive the shared copy challenges after all base roots are committed.
pub fn derive_note_copy_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<NoteCopyChallengesV1, ProofManagedNoteStarkErrorV1> {
    let mut lanes = [NoteCopyLaneChallengesV1 {
        beta: F::ZERO,
        gamma: F::ZERO,
    }; NOTE_COPY_LANES_V1];
    for lane in lanes.iter_mut() {
        lane.beta = transcript
            .challenge_field(NOTE_COPY_BETA_LABEL_V1)
            .map_err(map_transparent_error_v1)?;
        lane.gamma = transcript
            .challenge_field(NOTE_COPY_GAMMA_LABEL_V1)
            .map_err(map_transparent_error_v1)?;
    }
    if lanes.iter().any(|lane| {
        lane.beta == F::ZERO
            || lane.gamma == F::ZERO
            || lane.beta == lane.gamma
            || F::canonical(lane.beta.0).is_none()
            || F::canonical(lane.gamma.0).is_none()
    }) || lanes
        .iter()
        .enumerate()
        .any(|(index, lane)| lanes[..index].contains(lane))
    {
        return Err(ProofManagedNoteStarkErrorV1::Transcript);
    }
    Ok(NoteCopyChallengesV1 { lanes })
}
fn columns_to_rows_v1(
    columns: &[Vec<F>],
    rows: usize,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    if columns.is_empty() || columns.iter().any(|column| column.len() != rows) {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let mut output = ZeroizingBaseFieldMatrixV1::from(Vec::new());
    output
        .try_reserve_exact(rows)
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    for row in 0..rows {
        let mut values = ZeroizingBaseFieldValuesV1::from(Vec::new());
        values
            .0
            .try_reserve_exact(columns.len())
            .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
        for column in columns {
            values.0.push(
                column
                    .get(row)
                    .copied()
                    .ok_or(ProofManagedNoteStarkErrorV1::InvalidTrace)?,
            );
        }
        output.push(values.into_inner());
    }
    Ok(output.into_inner())
}
fn rows_to_columns_v1(
    rows: &[Vec<F>],
    width: usize,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    if rows.is_empty() || width == 0 || rows.iter().any(|row| row.len() != width) {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let mut columns = ZeroizingBaseFieldMatrixV1::from(Vec::new());
    columns
        .try_reserve_exact(width)
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    for column in 0..width {
        let mut values = ZeroizingBaseFieldValuesV1::from(Vec::new());
        values
            .0
            .try_reserve_exact(rows.len())
            .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
        for row in rows {
            values.0.push(row[column]);
        }
        columns.push(values.into_inner());
    }
    Ok(columns.into_inner())
}
fn copy_factor_v1(value: F, label: F, challenge: NoteCopyLaneChallengesV1) -> F {
    value.add(challenge.beta.mul(label)).add(challenge.gamma)
}
fn write_product_tree_v1(target: &mut [F], offset: usize, factors: [F; NOTE_COPY_WIDTH_V1]) {
    let pairs = [
        factors[0].mul(factors[1]),
        factors[2].mul(factors[3]),
        factors[4].mul(factors[5]),
        factors[6].mul(factors[7]),
    ];
    target[offset..offset + 4].copy_from_slice(&pairs);
    let quads = [pairs[0].mul(pairs[1]), pairs[2].mul(pairs[3])];
    target[offset + 4..offset + 6].copy_from_slice(&quads);
    target[offset + 6] = quads[0].mul(quads[1]);
}
/// Build byte decompositions and all three copy grand-product lanes.
pub fn build_note_copy_aux_columns_v1(
    base_columns: &[Vec<F>],
    fixed_columns: &[Vec<F>],
    challenges: NoteCopyChallengesV1,
    trace_size: usize,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    if base_columns.len() < NOTE_COPY_WIDTH_V1
        || fixed_columns.len() < NOTE_COPY_FIXED_WIDTH_V1
        || base_columns.iter().any(|column| column.len() != trace_size)
        || fixed_columns
            .iter()
            .any(|column| column.len() != trace_size)
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let base_rows = ZeroizingBaseFieldMatrixV1::from(columns_to_rows_v1(base_columns, trace_size)?);
    let fixed_rows = columns_to_rows_v1(fixed_columns, trace_size)?;
    let mut rows =
        ZeroizingBaseFieldMatrixV1::from(vec![vec![F::ZERO; NOTE_COPY_AUX_WIDTH_V1]; trace_size]);
    let mut running_numerator = [F::ONE; NOTE_COPY_LANES_V1];
    let mut running_denominator = [F::ONE; NOTE_COPY_LANES_V1];
    for row_index in 0..trace_size {
        let base = &base_rows[row_index];
        let fixed = &fixed_rows[row_index];
        let row = &mut rows[row_index];
        for cell in 0..NOTE_COPY_WIDTH_V1 {
            let value =
                u8::try_from(base[cell].0).map_err(|_| ProofManagedNoteStarkErrorV1::Copy)?;
            for bit in 0..8 {
                row[COPY_AUX_BITS_OFFSET + cell * 8 + bit] = F(u64::from((value >> bit) & 1));
            }
        }
        for (lane, challenge) in challenges.lanes.iter().copied().enumerate() {
            let lane_offset =
                COPY_AUX_PRODUCTS_OFFSET + lane * NOTE_COPY_PRODUCT_COLUMNS_PER_LANE_V1;
            row[lane_offset + COPY_NUMERATOR_BEFORE] = running_numerator[lane];
            row[lane_offset + COPY_DENOMINATOR_BEFORE] = running_denominator[lane];
            let numerator = core::array::from_fn(|cell| {
                copy_factor_v1(
                    base[cell],
                    fixed[COPY_FIXED_IDENTITY_OFFSET + cell],
                    challenge,
                )
            });
            let denominator = core::array::from_fn(|cell| {
                copy_factor_v1(base[cell], fixed[COPY_FIXED_SIGMA_OFFSET + cell], challenge)
            });
            write_product_tree_v1(row, lane_offset + COPY_NUMERATOR_PAIRS, numerator);
            write_product_tree_v1(row, lane_offset + COPY_DENOMINATOR_PAIRS, denominator);
            running_numerator[lane] =
                running_numerator[lane].mul(row[lane_offset + COPY_NUMERATOR_TOTAL]);
            running_denominator[lane] =
                running_denominator[lane].mul(row[lane_offset + COPY_DENOMINATOR_TOTAL]);
            row[lane_offset + COPY_NUMERATOR_AFTER] = running_numerator[lane];
            row[lane_offset + COPY_DENOMINATOR_AFTER] = running_denominator[lane];
        }
    }
    if running_numerator != running_denominator {
        return Err(ProofManagedNoteStarkErrorV1::Copy);
    }
    let columns =
        ZeroizingBaseFieldMatrixV1::from(rows_to_columns_v1(&rows, NOTE_COPY_AUX_WIDTH_V1)?);
    Ok(columns.into_inner())
}
fn push_boolean_residue_v1(residues: &mut Vec<F>, value: F) {
    residues.push(value.mul(value.sub(F::ONE)));
}
/// Evaluate all shared byte-range, fixed-policy, and copy-product residues.
pub fn note_copy_constraint_residues_v1(
    current_base: &[F],
    current_aux: &[F],
    next_aux: &[F],
    fixed: &[F],
    challenges: NoteCopyChallengesV1,
) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
    if current_base.len() < NOTE_COPY_WIDTH_V1
        || current_aux.len() < NOTE_COPY_AUX_WIDTH_V1
        || next_aux.len() < NOTE_COPY_AUX_WIDTH_V1
        || fixed.len() < NOTE_COPY_FIXED_WIDTH_V1
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let mut residues = Vec::with_capacity(NOTE_COPY_CONSTRAINT_COUNT_V1);
    for cell in 0..NOTE_COPY_WIDTH_V1 {
        let bits =
            &current_aux[COPY_AUX_BITS_OFFSET + cell * 8..COPY_AUX_BITS_OFFSET + (cell + 1) * 8];
        for bit in bits {
            push_boolean_residue_v1(&mut residues, *bit);
        }
        let packed = bits
            .iter()
            .copied()
            .enumerate()
            .fold(F::ZERO, |sum, (bit, value)| {
                sum.add(value.mul(F(1_u64 << bit)))
            });
        residues.push(current_base[cell].sub(packed));
        residues.push(fixed[COPY_FIXED_INACTIVE_OFFSET + cell].mul(current_base[cell]));
        residues.push(
            fixed[COPY_FIXED_CONSTANT_SELECTOR_OFFSET + cell]
                .mul(current_base[cell].sub(fixed[COPY_FIXED_CONSTANT_VALUE_OFFSET + cell])),
        );
    }
    for (lane, challenge) in challenges.lanes.iter().copied().enumerate() {
        let offset = COPY_AUX_PRODUCTS_OFFSET + lane * NOTE_COPY_PRODUCT_COLUMNS_PER_LANE_V1;
        let numerator: [F; NOTE_COPY_WIDTH_V1] = core::array::from_fn(|cell| {
            copy_factor_v1(
                current_base[cell],
                fixed[COPY_FIXED_IDENTITY_OFFSET + cell],
                challenge,
            )
        });
        let denominator: [F; NOTE_COPY_WIDTH_V1] = core::array::from_fn(|cell| {
            copy_factor_v1(
                current_base[cell],
                fixed[COPY_FIXED_SIGMA_OFFSET + cell],
                challenge,
            )
        });
        for (pair, factors) in numerator.chunks_exact(2).enumerate() {
            residues.push(
                current_aux[offset + COPY_NUMERATOR_PAIRS + pair].sub(factors[0].mul(factors[1])),
            );
        }
        for quad in 0..2 {
            residues.push(
                current_aux[offset + COPY_NUMERATOR_QUADS + quad].sub(
                    current_aux[offset + COPY_NUMERATOR_PAIRS + quad * 2]
                        .mul(current_aux[offset + COPY_NUMERATOR_PAIRS + quad * 2 + 1]),
                ),
            );
        }
        residues.push(
            current_aux[offset + COPY_NUMERATOR_TOTAL].sub(
                current_aux[offset + COPY_NUMERATOR_QUADS]
                    .mul(current_aux[offset + COPY_NUMERATOR_QUADS + 1]),
            ),
        );
        for (pair, factors) in denominator.chunks_exact(2).enumerate() {
            residues.push(
                current_aux[offset + COPY_DENOMINATOR_PAIRS + pair].sub(factors[0].mul(factors[1])),
            );
        }
        for quad in 0..2 {
            residues.push(
                current_aux[offset + COPY_DENOMINATOR_QUADS + quad].sub(
                    current_aux[offset + COPY_DENOMINATOR_PAIRS + quad * 2]
                        .mul(current_aux[offset + COPY_DENOMINATOR_PAIRS + quad * 2 + 1]),
                ),
            );
        }
        residues.push(
            current_aux[offset + COPY_DENOMINATOR_TOTAL].sub(
                current_aux[offset + COPY_DENOMINATOR_QUADS]
                    .mul(current_aux[offset + COPY_DENOMINATOR_QUADS + 1]),
            ),
        );
        residues.push(
            fixed[COPY_FIXED_FIRST].mul(current_aux[offset + COPY_NUMERATOR_BEFORE].sub(F::ONE)),
        );
        residues.push(
            fixed[COPY_FIXED_FIRST].mul(current_aux[offset + COPY_DENOMINATOR_BEFORE].sub(F::ONE)),
        );
        residues.push(
            fixed[COPY_FIXED_TRANSITION].mul(
                next_aux[offset + COPY_NUMERATOR_BEFORE]
                    .sub(current_aux[offset + COPY_NUMERATOR_AFTER]),
            ),
        );
        residues.push(
            fixed[COPY_FIXED_TRANSITION].mul(
                next_aux[offset + COPY_DENOMINATOR_BEFORE]
                    .sub(current_aux[offset + COPY_DENOMINATOR_AFTER]),
            ),
        );
        residues.push(
            fixed[COPY_FIXED_LAST].mul(
                current_aux[offset + COPY_NUMERATOR_AFTER]
                    .sub(current_aux[offset + COPY_DENOMINATOR_AFTER]),
            ),
        );
        residues.push(
            current_aux[offset + COPY_NUMERATOR_AFTER].sub(
                current_aux[offset + COPY_NUMERATOR_BEFORE]
                    .mul(current_aux[offset + COPY_NUMERATOR_TOTAL]),
            ),
        );
        residues.push(
            current_aux[offset + COPY_DENOMINATOR_AFTER].sub(
                current_aux[offset + COPY_DENOMINATOR_BEFORE]
                    .mul(current_aux[offset + COPY_DENOMINATOR_TOTAL]),
            ),
        );
    }
    if residues.len() != NOTE_COPY_CONSTRAINT_COUNT_V1 {
        return Err(ProofManagedNoteStarkErrorV1::Internal);
    }
    Ok(residues)
}
#[derive(Clone)]
struct PreparedNoteProfileV1 {
    protocol: ProofManagedNoteStarkProtocolV1,
    trace_log2: u8,
    trace_size: usize,
    base_width: usize,
    aux_width: usize,
    fixed_width: usize,
    constraint_count: usize,
    layout: aggregate::AggregateProofLayoutV1,
    fixed_columns: Vec<Vec<F>>,
}
fn canonical_columns_v1(
    columns: &[Vec<F>],
    width: usize,
    rows: usize,
) -> Result<(), ProofManagedNoteStarkErrorV1> {
    if columns.len() != width
        || columns.iter().any(|column| {
            column.len() != rows || column.iter().any(|value| F::canonical(value.0).is_none())
        })
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    Ok(())
}
fn checked_trace_size_v1(trace_log2: u8) -> Result<usize, ProofManagedNoteStarkErrorV1> {
    1_usize
        .checked_shl(u32::from(trace_log2))
        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)
}
fn maximum_masked_trace_degree_v1(
    trace_size: usize,
) -> Result<usize, ProofManagedNoteStarkErrorV1> {
    trace_size
        .checked_add(PROOF_MANAGED_NOTE_MASK_DEGREE_V1)
        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)
}
fn maximum_quotient_degree_v1(
    trace_size: usize,
    constraint_degree: u8,
) -> Result<usize, ProofManagedNoteStarkErrorV1> {
    usize::from(constraint_degree)
        .checked_mul(maximum_masked_trace_degree_v1(trace_size)?)
        .and_then(|degree| degree.checked_sub(trace_size))
        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)
}
fn maximum_fri_input_degree_v1(
    layout: &aggregate::AggregateProofLayoutV1,
    parameters: aggregate::AggregateStarkParametersV1,
) -> Result<usize, ProofManagedNoteStarkErrorV1> {
    let fri_rounds = layout
        .fri_rounds(parameters)
        .map_err(map_aggregate_error_v1)?;
    let shift =
        u32::try_from(fri_rounds).map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    let fold_factor = 1_usize
        .checked_shl(shift)
        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    parameters
        .terminal_degree_bound
        .checked_add(1)
        .and_then(|terminal_coefficients| terminal_coefficients.checked_mul(fold_factor))
        .and_then(|coefficient_capacity| coefficient_capacity.checked_sub(1))
        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)
}
fn prepare_note_profile_v1<A: ProofManagedNoteStarkAdapterV1>(
    adapter: &A,
) -> Result<PreparedNoteProfileV1, ProofManagedNoteStarkErrorV1> {
    prepare_note_profile_with_fixed_v1(adapter, true)
}
fn prepare_note_profile_with_fixed_v1<A: ProofManagedNoteStarkAdapterV1>(
    adapter: &A,
    materialize_fixed: bool,
) -> Result<PreparedNoteProfileV1, ProofManagedNoteStarkErrorV1> {
    let protocol = adapter.protocol_v1();
    protocol.validate()?;
    let trace_log2 = adapter.trace_log2_v1();
    let trace_size = checked_trace_size_v1(trace_log2)?;
    let base_width = adapter.base_width_v1();
    let aux_width = NOTE_COPY_AUX_WIDTH_V1
        .checked_add(adapter.profile_aux_width_v1())
        .ok_or(ProofManagedNoteStarkErrorV1::Resource)?;
    let fixed_width = NOTE_COPY_FIXED_WIDTH_V1
        .checked_add(adapter.profile_fixed_width_v1())
        .ok_or(ProofManagedNoteStarkErrorV1::Resource)?;
    let constraint_count = NOTE_COPY_CONSTRAINT_COUNT_V1
        .checked_add(adapter.profile_constraint_count_v1())
        .ok_or(ProofManagedNoteStarkErrorV1::Resource)?;
    if base_width < NOTE_COPY_WIDTH_V1
        || adapter.profile_constraint_count_v1() == 0
        || fixed_width > usize::from(u16::MAX)
        || constraint_count > usize::from(u16::MAX)
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
    }
    let layout = aggregate::AggregateProofLayoutV1::new(
        protocol.parameters,
        vec![aggregate::AggregateTraceGroupLayoutV1 {
            native_trace_log2: trace_log2,
            segment_instances: 1,
            base_width,
            aux_width,
        }],
    )
    .map_err(map_aggregate_error_v1)?;
    if layout.common_lde_log2()
        != trace_log2
            .checked_add(PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1)
            .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
    }
    let maximum_trace_degree = maximum_masked_trace_degree_v1(trace_size)?;
    let maximum_quotient_degree =
        maximum_quotient_degree_v1(trace_size, protocol.maximum_constraint_degree)?;
    let maximum_fri_input_degree = maximum_fri_input_degree_v1(&layout, protocol.parameters)?;
    let maximum_composition_degree = layout
        .maximum_composition_degree(protocol.parameters)
        .map_err(map_aggregate_error_v1)?;
    let maximum_encoded_proof_bytes =
        aggregate::maximum_encoded_proof_with_deep_bytes_v1(protocol.parameters, &layout)
            .map_err(map_aggregate_error_v1)?;
    if maximum_trace_degree > maximum_fri_input_degree
        || maximum_quotient_degree > maximum_composition_degree
        || maximum_encoded_proof_bytes > protocol.parameters.maximum_proof_bytes
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
    }
    let fixed_columns = if materialize_fixed {
        prepare_fixed_columns_v1(adapter, trace_size, fixed_width)?
    } else {
        Vec::new()
    };
    Ok(PreparedNoteProfileV1 {
        protocol,
        trace_log2,
        trace_size,
        base_width,
        aux_width,
        fixed_width,
        constraint_count,
        layout,
        fixed_columns,
    })
}
fn prepare_fixed_columns_v1<A: ProofManagedNoteStarkAdapterV1>(
    adapter: &A,
    trace_size: usize,
    fixed_width: usize,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    let schedule = adapter.copy_schedule_v1()?;
    let mut fixed_columns = schedule.fixed_columns_v1(trace_size)?;
    let profile_fixed = adapter.profile_fixed_columns_v1()?;
    canonical_columns_v1(&profile_fixed, adapter.profile_fixed_width_v1(), trace_size)?;
    fixed_columns.extend(profile_fixed);
    canonical_columns_v1(&fixed_columns, fixed_width, trace_size)?;
    Ok(fixed_columns)
}
fn row_at_columns_v1(
    columns: &[Vec<F>],
    row: usize,
) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
    let mut values = ZeroizingBaseFieldValuesV1::from(Vec::new());
    values
        .0
        .try_reserve_exact(columns.len())
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    for column in columns {
        values.0.push(
            column
                .get(row)
                .copied()
                .ok_or(ProofManagedNoteStarkErrorV1::InvalidTrace)?,
        );
    }
    Ok(values.into_inner())
}
struct ZeroizingBaseFieldValuesV1(Vec<F>);
impl From<Vec<F>> for ZeroizingBaseFieldValuesV1 {
    fn from(values: Vec<F>) -> Self {
        Self(values)
    }
}
impl ZeroizingBaseFieldValuesV1 {
    fn into_inner(mut self) -> Vec<F> {
        core::mem::take(&mut self.0)
    }

    fn zeroize_v1(&mut self) {
        for value in &mut self.0 {
            value.zeroize_v1();
        }
    }
}
impl core::ops::Deref for ZeroizingBaseFieldValuesV1 {
    type Target = [F];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for ZeroizingBaseFieldValuesV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ZeroizingBaseFieldValuesV1 {
    fn drop(&mut self) {
        self.zeroize_v1();
    }
}
struct ZeroizingBaseFieldMatrixV1(Vec<Vec<F>>);
impl From<Vec<Vec<F>>> for ZeroizingBaseFieldMatrixV1 {
    fn from(values: Vec<Vec<F>>) -> Self {
        Self(values)
    }
}
impl ZeroizingBaseFieldMatrixV1 {
    fn into_inner(mut self) -> Vec<Vec<F>> {
        core::mem::take(&mut self.0)
    }

    fn append(&mut self, other: &mut Self) {
        self.0.append(&mut other.0);
    }

    fn zeroize_v1(&mut self) {
        for column in &mut self.0 {
            for value in column {
                value.zeroize_v1();
            }
        }
    }
}
impl core::ops::Deref for ZeroizingBaseFieldMatrixV1 {
    type Target = Vec<Vec<F>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for ZeroizingBaseFieldMatrixV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ZeroizingBaseFieldMatrixV1 {
    fn drop(&mut self) {
        self.zeroize_v1();
    }
}
struct ZeroizingExtensionFieldValuesV1(Vec<E>);
impl From<Vec<E>> for ZeroizingExtensionFieldValuesV1 {
    fn from(values: Vec<E>) -> Self {
        Self(values)
    }
}
impl ZeroizingExtensionFieldValuesV1 {
    fn into_inner(mut self) -> Vec<E> {
        core::mem::take(&mut self.0)
    }

    fn zeroize_v1(&mut self) {
        for value in &mut self.0 {
            value.zeroize_v1();
        }
    }
}
impl core::ops::Deref for ZeroizingExtensionFieldValuesV1 {
    type Target = [E];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for ZeroizingExtensionFieldValuesV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ZeroizingExtensionFieldValuesV1 {
    fn drop(&mut self) {
        self.zeroize_v1();
    }
}
struct ZeroizingExtensionFieldMatrixV1(Vec<Vec<E>>);
impl From<Vec<Vec<E>>> for ZeroizingExtensionFieldMatrixV1 {
    fn from(values: Vec<Vec<E>>) -> Self {
        Self(values)
    }
}
impl ZeroizingExtensionFieldMatrixV1 {
    fn zeroize_v1(&mut self) {
        for column in &mut self.0 {
            for value in column {
                value.zeroize_v1();
            }
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
struct ZeroizingExtensionFieldCubeV1(Vec<Vec<Vec<E>>>);
impl From<Vec<Vec<Vec<E>>>> for ZeroizingExtensionFieldCubeV1 {
    fn from(values: Vec<Vec<Vec<E>>>) -> Self {
        Self(values)
    }
}
impl ZeroizingExtensionFieldCubeV1 {
    fn into_inner(mut self) -> Vec<Vec<Vec<E>>> {
        core::mem::take(&mut self.0)
    }

    fn zeroize_v1(&mut self) {
        for matrix in &mut self.0 {
            for column in matrix {
                for value in column {
                    value.zeroize_v1();
                }
            }
        }
    }
}
impl core::ops::Deref for ZeroizingExtensionFieldCubeV1 {
    type Target = Vec<Vec<Vec<E>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for ZeroizingExtensionFieldCubeV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ZeroizingExtensionFieldCubeV1 {
    fn drop(&mut self) {
        self.zeroize_v1();
    }
}
struct ZeroizingExtensionFieldRowV1<const N: usize>([E; N]);
impl<const N: usize> ZeroizingExtensionFieldRowV1<N> {
    fn iter(&self) -> core::slice::Iter<'_, E> {
        self.0.iter()
    }

    fn zeroize_v1(&mut self) {
        for value in &mut self.0 {
            value.zeroize_v1();
        }
    }
}
impl<const N: usize> Drop for ZeroizingExtensionFieldRowV1<N> {
    fn drop(&mut self) {
        self.zeroize_v1();
    }
}
fn collect_bounded_parallel_columns_v1<T, Transform>(
    column_count: usize,
    transform: Transform,
) -> Result<Vec<T>, ProofManagedNoteStarkErrorV1>
where
    T: Send,
    Transform: Fn(usize) -> Result<T, ProofManagedNoteStarkErrorV1> + Sync,
{
    let mut output = Vec::new();
    output
        .try_reserve_exact(column_count)
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    // Sequential source-ordered batches make the resident transform count independent of the
    // process-global Rayon width. Indexed collection and serial reduction preserve both output
    // order and the lowest-column error.
    for batch_start in (0..column_count).step_by(aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1) {
        let batch_end = batch_start
            .checked_add(aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .map_or(column_count, |end| end.min(column_count));
        let batch = (batch_start..batch_end)
            .into_par_iter()
            .map(&transform)
            .collect::<Vec<_>>();
        for transformed in batch {
            output.push(transformed?);
        }
    }
    Ok(output)
}
fn fixed_lde_columns_v1(
    columns: &[Vec<F>],
    trace_log2: u8,
    lde_log2: u8,
) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
    let trace_size = checked_trace_size_v1(trace_log2)?;
    let lde_size = checked_trace_size_v1(lde_log2)?;
    if columns.is_empty()
        || lde_size <= trace_size
        || columns.iter().any(|column| column.len() != trace_size)
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
    }
    let trace_root = goldilocks_primitive_root_v1(trace_log2).map_err(map_transparent_error_v1)?;
    let lde_root = goldilocks_primitive_root_v1(lde_log2).map_err(map_transparent_error_v1)?;
    let shift = F(GOLDILOCKS_GENERATOR_V1);
    collect_bounded_parallel_columns_v1(columns.len(), |column_index| {
        let column = &columns[column_index];
        let mut coefficients = column.clone();
        goldilocks_ifft_v1(&mut coefficients, trace_root).map_err(map_transparent_error_v1)?;
        coefficients.resize(lde_size, F::ZERO);
        let mut shift_power = F::ONE;
        for coefficient in &mut coefficients {
            *coefficient = coefficient.mul(shift_power);
            shift_power = shift_power.mul(shift);
        }
        goldilocks_fft_v1(&mut coefficients, lde_root).map_err(map_transparent_error_v1)?;
        Ok(coefficients)
    })
}
fn masked_lde_columns_v1<R: TryRngCore>(
    columns: &[Vec<F>],
    trace_log2: u8,
    lde_log2: u8,
    rng: &mut R,
) -> Result<(Vec<Vec<F>>, Vec<ReplayableTraceMaskV1>), ProofManagedNoteStarkErrorV1> {
    if columns.is_empty() {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    // Reject every semantic transform failure before consuming masking entropy. Once these
    // checks pass, the generated masks are canonical and every worker has the same valid FFT/coset
    // geometry; only a bounded allocation failure can still stop an individual transform.
    let trace_size = checked_trace_size_v1(trace_log2)?;
    let lde_size = checked_trace_size_v1(lde_log2)?;
    let mask_len = PROOF_MANAGED_NOTE_MASK_DEGREE_V1
        .checked_add(1)
        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    let coefficient_count = trace_size
        .checked_add(mask_len)
        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    if lde_size <= trace_size
        || coefficient_count > lde_size
        || columns.iter().any(|column| column.len() != trace_size)
    {
        return Err(map_transparent_error_v1(
            TransparentStarkErrorV1::InvalidDomain,
        ));
    }
    if columns
        .iter()
        .flatten()
        .any(|value| F::canonical(value.0).is_none())
    {
        return Err(map_transparent_error_v1(
            TransparentStarkErrorV1::NonCanonicalField,
        ));
    }
    goldilocks_primitive_root_v1(trace_log2).map_err(map_transparent_error_v1)?;
    goldilocks_primitive_root_v1(lde_log2).map_err(map_transparent_error_v1)?;
    let shift = F(GOLDILOCKS_GENERATOR_V1);
    if shift.pow(trace_size as u128) == F::ONE || shift.pow(lde_size as u128) == F::ONE {
        return Err(map_transparent_error_v1(
            TransparentStarkErrorV1::InvalidDomain,
        ));
    }
    let mut masks = Vec::new();
    masks
        .try_reserve_exact(columns.len())
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    // Preserve the exact canonical RNG-consumption order before any parallel work begins.
    for _ in columns {
        masks.push(
            sample_trace_mask_v1(PROOF_MANAGED_NOTE_MASK_DEGREE_V1, rng)
                .map_err(map_transparent_error_v1)?,
        );
    }
    // Masks live until every bounded transform succeeds, so their Drop implementation wipes the
    // sampled coefficients on success, ordinary error, and unwind. The transform itself likewise
    // guards and wipes the witness-interpolating coefficient vector.
    let lde_columns = collect_bounded_parallel_columns_v1(columns.len(), |column_index| {
        masked_trace_lde_column_with_mask_v1(
            &columns[column_index],
            trace_log2,
            lde_log2,
            masks[column_index].coefficients(),
        )
        .map(ZeroizingBaseFieldValuesV1::from)
        .map_err(map_transparent_error_v1)
    })?;
    let mut protected_columns = ZeroizingBaseFieldMatrixV1(Vec::new());
    protected_columns
        .try_reserve_exact(lde_columns.len())
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    for column in lde_columns {
        protected_columns.push(column.into_inner());
    }
    Ok((protected_columns.into_inner(), masks))
}
fn evaluate_base_coefficients_at_fp4_v1(coefficients: &[F], point: E) -> E {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(E::ZERO, |value, coefficient| {
            value.mul(point).add(E::from_base(coefficient))
        })
}
fn evaluate_masked_native_columns_at_deep_v1(
    columns: &[Vec<F>],
    masks: &[ReplayableTraceMaskV1],
    trace_log2: u8,
    point: E,
) -> Result<(Vec<E>, Vec<E>), ProofManagedNoteStarkErrorV1> {
    let trace_size = checked_trace_size_v1(trace_log2)?;
    if columns.is_empty()
        || columns.len() != masks.len()
        || columns.iter().any(|column| column.len() != trace_size)
        || masks
            .iter()
            .any(|mask| mask.coefficients().len() != PROOF_MANAGED_NOTE_MASK_DEGREE_V1 + 1)
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let native_root = goldilocks_primitive_root_v1(trace_log2).map_err(map_transparent_error_v1)?;
    let next_point = point.mul_base(native_root);
    let mut current = Vec::new();
    let mut next = Vec::new();
    current
        .try_reserve_exact(columns.len())
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    next.try_reserve_exact(columns.len())
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    // Columns are independent and occupy fixed output indices. The temporary coefficient copy is
    // owned by one worker and is zeroized before that worker returns on both success and failure.
    // Results are reduced serially in column order so malformed inputs retain deterministic error
    // precedence as well as deterministic successful output.
    let evaluations = collect_bounded_parallel_columns_v1(columns.len(), |column_index| {
        let column = &columns[column_index];
        let mask = &masks[column_index];
        let mut trace_coefficients = ZeroizingBaseFieldValuesV1::from(Vec::new());
        trace_coefficients
            .0
            .try_reserve_exact(column.len())
            .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
        trace_coefficients.0.extend_from_slice(column);
        goldilocks_ifft_v1(&mut trace_coefficients, native_root)
            .map_err(map_transparent_error_v1)?;
        let evaluate = |evaluation_point| {
            let trace = evaluate_base_coefficients_at_fp4_v1(&trace_coefficients, evaluation_point);
            let randomizer =
                evaluate_base_coefficients_at_fp4_v1(mask.coefficients(), evaluation_point);
            trace.add(
                evaluation_point
                    .pow(trace_size as u128)
                    .sub(E::ONE)
                    .mul(randomizer),
            )
        };
        Ok((evaluate(point), evaluate(next_point)))
    })?;
    for (current_value, next_value) in evaluations {
        current.push(current_value);
        next.push(next_value);
    }
    Ok((current, next))
}
fn new_note_transcript_v1(
    prepared: &PreparedNoteProfileV1,
    public_digest: &PrivacyOuterDigestV1,
) -> Result<TransparentTranscriptV1, ProofManagedNoteStarkErrorV1> {
    let profile_digest = proof_managed_note_stark_profile_digest_v1(
        &prepared.protocol.domains,
        prepared.protocol.profile_descriptor,
    )?;
    let geometry_digest = proof_managed_note_stark_geometry_digest_v1(&prepared.protocol.domains)?;
    let geometry_digest = geometry_digest.to_bytes();
    let mut transcript = TransparentTranscriptV1::new(
        prepared.protocol.domains.digest_context,
        PROOF_MANAGED_NOTE_STARK_SUITE_V1,
        &profile_digest,
        public_digest,
    )
    .map_err(map_transparent_error_v1)?;
    let maximum_constraint_degree = [prepared.protocol.maximum_constraint_degree];
    transcript
        .absorb(
            NOTE_SHARED_PROFILE_BINDING_LABEL_V1,
            &[
                PROOF_MANAGED_NOTE_STARK_GEOMETRY_DESCRIPTOR_V1,
                &geometry_digest,
            ],
        )
        .map_err(map_transparent_error_v1)?;
    transcript
        .absorb(
            prepared.protocol.profile_binding_label,
            &[
                prepared.protocol.profile_descriptor,
                &maximum_constraint_degree,
            ],
        )
        .map_err(map_transparent_error_v1)?;
    aggregate::absorb_layout_v1(
        &mut transcript,
        prepared.protocol.parameters,
        &prepared.protocol.domains,
        prepared.protocol.relation_layout_domain,
        &prepared.layout,
    )
    .map_err(map_aggregate_error_v1)?;
    Ok(transcript)
}
fn challenge_extension_vector_v1(
    transcript: &mut TransparentTranscriptV1,
    label: &[u8],
    count: usize,
) -> Result<Vec<E>, ProofManagedNoteStarkErrorV1> {
    transcript
        .challenge_fp4_sequence(label, count)
        .map_err(map_transparent_error_v1)
}
fn derive_constraint_alphas_v1(
    transcript: &mut TransparentTranscriptV1,
    constraint_count: usize,
) -> Result<Vec<Vec<E>>, ProofManagedNoteStarkErrorV1> {
    (0..PROOF_MANAGED_NOTE_SECURITY_LANES_V1)
        .map(|_| {
            challenge_extension_vector_v1(
                transcript,
                NOTE_CONSTRAINT_ALPHA_LABEL_V1,
                constraint_count,
            )
        })
        .collect()
}
fn derive_deep_mixes_v1(
    transcript: &mut TransparentTranscriptV1,
    base_width: usize,
    aux_width: usize,
    composition_degree_chunks: usize,
    parameters: aggregate::AggregateStarkParametersV1,
    layout: &aggregate::AggregateProofLayoutV1,
) -> Result<Vec<aggregate::AggregateDeepLaneMixV1>, ProofManagedNoteStarkErrorV1> {
    let mixes = (0..PROOF_MANAGED_NOTE_SECURITY_LANES_V1)
        .map(|_| {
            Ok(aggregate::AggregateDeepLaneMixV1 {
                trace_groups: vec![aggregate::AggregateDeepTraceGroupMixV1 {
                    base_current: challenge_extension_vector_v1(
                        transcript,
                        NOTE_DEEP_BASE_CURRENT_MIX_LABEL_V1,
                        base_width,
                    )?,
                    base_next: challenge_extension_vector_v1(
                        transcript,
                        NOTE_DEEP_BASE_NEXT_MIX_LABEL_V1,
                        base_width,
                    )?,
                    aux_current: challenge_extension_vector_v1(
                        transcript,
                        NOTE_DEEP_AUX_CURRENT_MIX_LABEL_V1,
                        aux_width,
                    )?,
                    aux_next: challenge_extension_vector_v1(
                        transcript,
                        NOTE_DEEP_AUX_NEXT_MIX_LABEL_V1,
                        aux_width,
                    )?,
                }],
                composition: challenge_extension_vector_v1(
                    transcript,
                    NOTE_DEEP_COMPOSITION_MIX_LABEL_V1,
                    composition_degree_chunks,
                )?,
            })
        })
        .collect::<Result<Vec<_>, ProofManagedNoteStarkErrorV1>>()?;
    aggregate::validate_deep_lane_mixes_v1(&mixes, parameters, layout)
        .map_err(map_aggregate_error_v1)?;
    Ok(mixes)
}
fn all_constraint_residues_v1<A: ProofManagedNoteStarkAdapterV1>(
    adapter: &A,
    prepared: &PreparedNoteProfileV1,
    current_base: &[F],
    next_base: &[F],
    current_aux: &[F],
    next_aux: &[F],
    fixed: &[F],
    copy_challenges: NoteCopyChallengesV1,
    profile_challenges: &A::ProfileChallenges,
) -> Result<ZeroizingBaseFieldValuesV1, ProofManagedNoteStarkErrorV1> {
    if current_base.len() != prepared.base_width
        || next_base.len() != prepared.base_width
        || current_aux.len() != prepared.aux_width
        || next_aux.len() != prepared.aux_width
        || fixed.len() != prepared.fixed_width
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let shared = ZeroizingBaseFieldValuesV1::from(note_copy_constraint_residues_v1(
        current_base,
        current_aux,
        next_aux,
        fixed,
        copy_challenges,
    )?);
    let profile = ZeroizingBaseFieldValuesV1::from(adapter.profile_constraint_residues_v1(
        current_base,
        next_base,
        current_aux,
        next_aux,
        fixed,
        copy_challenges,
        profile_challenges,
    )?);
    if profile.len()
        != prepared
            .constraint_count
            .checked_sub(NOTE_COPY_CONSTRAINT_COUNT_V1)
            .ok_or(ProofManagedNoteStarkErrorV1::Internal)?
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
    }
    let mut residues = ZeroizingBaseFieldValuesV1::from(Vec::new());
    residues
        .0
        .try_reserve_exact(prepared.constraint_count)
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    residues.0.extend_from_slice(&shared);
    residues.0.extend_from_slice(&profile);
    if residues.len() != prepared.constraint_count {
        return Err(ProofManagedNoteStarkErrorV1::Internal);
    }
    Ok(residues)
}
fn validate_native_constraints_v1<A: ProofManagedNoteStarkAdapterV1>(
    adapter: &A,
    prepared: &PreparedNoteProfileV1,
    base_columns: &[Vec<F>],
    aux_columns: &[Vec<F>],
    copy_challenges: NoteCopyChallengesV1,
    profile_challenges: &A::ProfileChallenges,
) -> Result<(), ProofManagedNoteStarkErrorV1> {
    // Native rows are immutable and independently constrained. Indexed collection plus serial
    // reduction retains the lowest-row error while successful validation has no output ordering
    // to perturb.
    let results = (0..prepared.trace_size)
        .into_par_iter()
        .map(|row| -> Result<(), ProofManagedNoteStarkErrorV1> {
            let next = (row + 1) % prepared.trace_size;
            let current_base =
                ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(base_columns, row)?);
            let next_base =
                ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(base_columns, next)?);
            let current_aux =
                ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(aux_columns, row)?);
            let next_aux = ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(aux_columns, next)?);
            let fixed =
                ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(&prepared.fixed_columns, row)?);
            let residues = all_constraint_residues_v1(
                adapter,
                prepared,
                &current_base,
                &next_base,
                &current_aux,
                &next_aux,
                &fixed,
                copy_challenges,
                profile_challenges,
            )?;
            if residues.iter().any(|residue| *residue != F::ZERO) {
                return Err(ProofManagedNoteStarkErrorV1::Constraint);
            }
            Ok(())
        })
        .collect::<Vec<_>>();
    results.into_iter().collect()
}
fn composition_lanes_v1<A: ProofManagedNoteStarkAdapterV1>(
    adapter: &A,
    prepared: &PreparedNoteProfileV1,
    base_lde: &[Vec<F>],
    aux_lde: &[Vec<F>],
    fixed_lde: &[Vec<F>],
    copy_challenges: NoteCopyChallengesV1,
    profile_challenges: &A::ProfileChallenges,
    alphas: &[Vec<E>],
) -> Result<Vec<Vec<Vec<E>>>, ProofManagedNoteStarkErrorV1> {
    if alphas.len() != PROOF_MANAGED_NOTE_SECURITY_LANES_V1
        || alphas
            .iter()
            .any(|lane| lane.len() != prepared.constraint_count)
    {
        return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
    }
    let lde_size = prepared.layout.common_lde_size();
    canonical_columns_v1(base_lde, prepared.base_width, lde_size)?;
    canonical_columns_v1(aux_lde, prepared.aux_width, lde_size)?;
    canonical_columns_v1(fixed_lde, prepared.fixed_width, lde_size)?;
    let inverse_vanishing_period = aggregate::trace_vanishing_inverse_period_v1(
        prepared.trace_log2,
        prepared.layout.common_lde_log2(),
        F(GOLDILOCKS_GENERATOR_V1),
    )
    .map_err(map_aggregate_error_v1)?;
    let next_stride = prepared
        .layout
        .trace_groups()
        .first()
        .ok_or(ProofManagedNoteStarkErrorV1::Internal)?
        .next_stride(prepared.layout.common_lde_log2())
        .map_err(map_aggregate_error_v1)?;
    let mut lanes = ZeroizingExtensionFieldMatrixV1::from(
        (0..PROOF_MANAGED_NOTE_SECURITY_LANES_V1)
            .map(|_| Vec::new())
            .collect::<Vec<_>>(),
    );
    for lane in lanes.iter_mut() {
        lane.try_reserve_exact(lde_size)
            .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    }
    // Keep one canonical row batch at a time. The shared vanishing table has
    // one entry per blowup coordinate; every row retains the same quotient
    // divisor without a domain-point buffer or per-row exponentiation/inversion.
    // Indexed collection and serial reduction preserve lane and error order.
    for batch_start in (0..lde_size).step_by(aggregate::DEEP_FRI_BASE_BATCH_ROWS_V1) {
        let batch_end = batch_start
            .checked_add(aggregate::DEEP_FRI_BASE_BATCH_ROWS_V1)
            .map_or(lde_size, |end| end.min(lde_size));
        let rows = (batch_start..batch_end)
            .into_par_iter()
            .map(|index| {
                let next = (index + next_stride) % lde_size;
                let current_base =
                    ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(base_lde, index)?);
                let next_base =
                    ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(base_lde, next)?);
                let current_aux =
                    ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(aux_lde, index)?);
                let next_aux = ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(aux_lde, next)?);
                let fixed = ZeroizingBaseFieldValuesV1::from(row_at_columns_v1(fixed_lde, index)?);
                let residues = all_constraint_residues_v1(
                    adapter,
                    prepared,
                    &current_base,
                    &next_base,
                    &current_aux,
                    &next_aux,
                    &fixed,
                    copy_challenges,
                    profile_challenges,
                )?;
                let inverse_vanishing =
                    inverse_vanishing_period[index % inverse_vanishing_period.len()];
                let mut row = [E::ZERO; PROOF_MANAGED_NOTE_SECURITY_LANES_V1];
                for (lane, value) in row.iter_mut().enumerate() {
                    let numerator = residues
                        .iter()
                        .zip(&alphas[lane])
                        .fold(E::ZERO, |sum, (residue, alpha)| {
                            sum.add(alpha.mul_base(*residue))
                        });
                    *value = numerator.mul_base(inverse_vanishing);
                }
                Ok(ZeroizingExtensionFieldRowV1(row))
            })
            .collect::<Vec<Result<_, ProofManagedNoteStarkErrorV1>>>();
        for row in rows {
            let row = row?;
            for (lane, value) in lanes.iter_mut().zip(row.iter().copied()) {
                lane.push(value);
            }
        }
    }
    let mut compositions = ZeroizingExtensionFieldCubeV1(Vec::new());
    compositions
        .try_reserve_exact(lanes.len())
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    for lane in lanes.iter() {
        compositions.push(
            aggregate::split_composition_evaluations_v1(
                lane,
                prepared.protocol.parameters,
                &prepared.layout,
            )
            .map_err(map_aggregate_error_v1)?,
        );
    }
    Ok(compositions.into_inner())
}
fn try_for_each_ordered_deep_batch_v1<Batch>(
    rows: usize,
    mut batch: Batch,
) -> Result<(), ProofManagedNoteStarkErrorV1>
where
    Batch: FnMut(usize, usize) -> Result<(), ProofManagedNoteStarkErrorV1>,
{
    let mut start = 0_usize;
    while start < rows {
        let end = start
            .checked_add(aggregate::DEEP_FRI_BASE_BATCH_ROWS_V1)
            .map_or(rows, |end| end.min(rows));
        if end <= start {
            return Err(ProofManagedNoteStarkErrorV1::Resource);
        }
        batch(start, end)?;
        start = end;
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn mixed_deep_fri_base_v1(
    base_lde: &[Vec<F>],
    aux_lde: &[Vec<F>],
    composition: &[Vec<E>],
    deep: &aggregate::AggregateDeepProofV1,
    deep_point: E,
    mix: &aggregate::AggregateDeepLaneMixV1,
    lane: usize,
    parameters: aggregate::AggregateStarkParametersV1,
    layout: &aggregate::AggregateProofLayoutV1,
) -> Result<Vec<E>, ProofManagedNoteStarkErrorV1> {
    aggregate::validate_deep_proof_shape_v1(deep, parameters, layout)
        .map_err(map_aggregate_error_v1)?;
    let deep_trace = aggregate::canonical_deep_trace_groups_v1(deep, parameters, layout)
        .map_err(map_aggregate_error_v1)?
        .into_iter()
        .next()
        .ok_or(ProofManagedNoteStarkErrorV1::Internal)?;
    let deep_composition = aggregate::canonical_fp4_fields_v1(
        deep.composition_values
            .get(lane)
            .ok_or(ProofManagedNoteStarkErrorV1::Internal)?,
        parameters.composition_degree_chunks,
    )
    .map_err(map_aggregate_error_v1)?;
    let trace_mix = mix
        .trace_groups
        .first()
        .filter(|_| mix.trace_groups.len() == 1)
        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    let rows = composition
        .first()
        .map(Vec::len)
        .ok_or(ProofManagedNoteStarkErrorV1::Internal)?;
    if base_lde.len() != trace_mix.base_current.len()
        || base_lde.len() != trace_mix.base_next.len()
        || aux_lde.len() != trace_mix.aux_current.len()
        || aux_lde.len() != trace_mix.aux_next.len()
        || composition.len() != mix.composition.len()
        || deep_trace.base_current.len() != base_lde.len()
        || deep_trace.base_next.len() != base_lde.len()
        || deep_trace.aux_current.len() != aux_lde.len()
        || deep_trace.aux_next.len() != aux_lde.len()
        || deep_composition.len() != composition.len()
        || rows != layout.common_lde_size()
        || composition.iter().any(|chunk| chunk.len() != rows)
        || base_lde
            .iter()
            .chain(aux_lde)
            .any(|column| column.len() != rows)
    {
        return Err(ProofManagedNoteStarkErrorV1::Internal);
    }
    let native_log2 = layout
        .trace_groups()
        .first()
        .filter(|_| layout.trace_groups().len() == 1)
        .ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?
        .native_trace_log2;
    let native_root =
        goldilocks_primitive_root_v1(native_log2).map_err(map_transparent_error_v1)?;
    let deep_next_point = deep_point.mul_base(native_root);
    let lde_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2()).map_err(map_transparent_error_v1)?;
    let mut result = ZeroizingExtensionFieldValuesV1(Vec::new());
    result
        .0
        .try_reserve_exact(rows)
        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
    result.0.resize(rows, E::ZERO);
    // Distributivity permits one denominator multiplication per current/next sum.
    // The DEEP openings and mix coefficients are public and invariant across rows.
    // Keep them outside the row loop; base-field trace values need only mul_base.
    let current_offset = deep_trace
        .base_current
        .iter()
        .zip(&trace_mix.base_current)
        .chain(deep_trace.aux_current.iter().zip(&trace_mix.aux_current))
        .chain(deep_composition.iter().zip(&mix.composition))
        .fold(E::ZERO, |sum, (value, coefficient)| {
            sum.add(value.mul(*coefficient))
        });
    let next_offset = deep_trace
        .base_next
        .iter()
        .zip(&trace_mix.base_next)
        .chain(deep_trace.aux_next.iter().zip(&trace_mix.aux_next))
        .fold(E::ZERO, |sum, (value, coefficient)| {
            sum.add(value.mul(*coefficient))
        });
    // Fallible denominator construction and inversion run one canonical batch at a time. Only the
    // now-infallible row arithmetic is parallel, preserving the earliest batch error while keeping
    // denominator and prefix scratch bounded to one 4,096-row batch.
    try_for_each_ordered_deep_batch_v1(rows, |start, end| {
        let output = &mut result.0[start..end];
        let denominator_count = output
            .len()
            .checked_mul(2)
            .ok_or(ProofManagedNoteStarkErrorV1::Resource)?;
        let mut inverse_denominators = Vec::new();
        inverse_denominators
            .try_reserve_exact(denominator_count)
            .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
        let exponent = u128::try_from(start).map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
        let mut x = F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(exponent));
        for _ in output.iter() {
            let query_point = E::from_base(x);
            inverse_denominators.push(query_point.sub(deep_point));
            inverse_denominators.push(query_point.sub(deep_next_point));
            x = x.mul(lde_root);
        }
        aggregate::batch_invert_fp4_nonzero_v1(&mut inverse_denominators)
            .map_err(map_aggregate_error_v1)?;
        output
            .par_iter_mut()
            .enumerate()
            .for_each(|(local_index, quotient_slot)| {
                let index = start + local_index;
                let current_inverse = inverse_denominators[2 * local_index];
                let next_inverse = inverse_denominators[2 * local_index + 1];
                let mut current = E::ZERO;
                let mut next = E::ZERO;
                for (column_index, column) in base_lde.iter().enumerate() {
                    let value = column[index];
                    current = current.add(trace_mix.base_current[column_index].mul_base(value));
                    next = next.add(trace_mix.base_next[column_index].mul_base(value));
                }
                for (column_index, column) in aux_lde.iter().enumerate() {
                    let value = column[index];
                    current = current.add(trace_mix.aux_current[column_index].mul_base(value));
                    next = next.add(trace_mix.aux_next[column_index].mul_base(value));
                }
                for (chunk, coefficient) in composition.iter().zip(&mix.composition) {
                    current = current.add(chunk[index].mul(*coefficient));
                }
                *quotient_slot = current
                    .sub(current_offset)
                    .mul(current_inverse)
                    .add(next.sub(next_offset).mul(next_inverse));
            });
        Ok(())
    })?;
    Ok(result.into_inner())
}
fn absorb_grinding_nonce_v1(
    transcript: &mut TransparentTranscriptV1,
    nonce: u64,
) -> Result<(), ProofManagedNoteStarkErrorV1> {
    transcript
        .absorb(NOTE_GRINDING_LABEL_V1, &[&nonce.to_be_bytes()])
        .map_err(map_transparent_error_v1)
}
/// Opaque proof construction output that has not passed independent verification.
///
/// Only the shared builder can create this value. Releasing its owned wire bytes
/// consumes it and runs the complete verifier against the caller's public adapter.
pub struct ProofManagedNoteCandidateV1 {
    encoded: Vec<u8>,
}
impl core::fmt::Debug for ProofManagedNoteCandidateV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProofManagedNoteCandidateV1")
            .field("encoded_len", &self.encoded.len())
            .finish_non_exhaustive()
    }
}
impl ProofManagedNoteCandidateV1 {
    /// Verify the candidate against independently reconstructed public inputs.
    ///
    /// No bytes are returned on failure. This is the sole owned-byte extraction
    /// operation, with no unchecked conversion or verification skip mode.
    pub(crate) fn verify_into_bytes_v1<A: ProofManagedNoteStarkAdapterV1>(
        self,
        adapter: &A,
    ) -> Result<Vec<u8>, ProofManagedNoteStarkErrorV1> {
        verify_proof_managed_note_stark_v1(adapter, &self.encoded)?;
        Ok(self.encoded)
    }
}
/// Construct an opaque canonical proof candidate with injected masking entropy.
///
/// The caller supplies exact native base columns; the adapter reconstructs all
/// statement-derived fixed policy and deterministic auxiliary columns. The
/// emitted candidate must pass independent verification before owned bytes can be extracted.
pub fn prove_proof_managed_note_stark_v1_with_rng<
    A: ProofManagedNoteStarkAdapterV1,
    R: TryRngCore,
>(
    adapter: &A,
    base_columns: &[Vec<F>],
    rng: &mut R,
) -> Result<ProofManagedNoteCandidateV1, ProofManagedNoteStarkErrorV1> {
    let phase_invocation = ProofPhaseInvocationV1::new_managed_note();
    let mut phases = ManagedNotePhaseCursorV1::new(phase_invocation.as_ref());
    // Keep the original statement, RNG and ownership order in one synchronous scope.
    let result = (|| {
        phases.advance(ProofPhaseV1::ProfilePreparation);
        let prepared = prepare_note_profile_v1(adapter)?;
        canonical_columns_v1(base_columns, prepared.base_width, prepared.trace_size)?;
        let public_digest = adapter.public_input_digest_v1()?;
        let lde_log2 = prepared.layout.common_lde_log2();
        let lde_size = prepared.layout.common_lde_size();
        phases.advance(ProofPhaseV1::BaseLde);
        let (base_lde, base_masks) =
            masked_lde_columns_v1(base_columns, prepared.trace_log2, lde_log2, rng)?;
        let base_lde = ZeroizingBaseFieldMatrixV1::from(base_lde);
        phases.advance(ProofPhaseV1::BaseCommitment);
        let base_tree = aggregate::row_tree_v1(
            prepared.protocol.domains.digest_context,
            prepared.protocol.domains.base_leaf,
            prepared.protocol.domains.base_node,
            0,
            &base_lde,
            lde_size,
        )
        .map_err(map_aggregate_error_v1)?;
        phases.advance(ProofPhaseV1::AuxiliaryConstruction);
        let mut transcript = new_note_transcript_v1(&prepared, &public_digest)?;
        let mut trace_group_proofs = vec![aggregate::AggregateTraceGroupProofV1 {
            base_root: base_tree.root(),
            aux_root: PrivacyOuterDigestV1::default(),
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        }];
        aggregate::absorb_base_roots_v1(
            &mut transcript,
            &prepared.protocol.domains,
            &trace_group_proofs,
        )
        .map_err(map_aggregate_error_v1)?;
        let copy_challenges = derive_note_copy_challenges_v1(&mut transcript)?;
        let profile_challenges =
            adapter.derive_profile_challenges_v1(&mut transcript, copy_challenges)?;
        let copy_aux = ZeroizingBaseFieldMatrixV1::from(build_note_copy_aux_columns_v1(
            base_columns,
            &prepared.fixed_columns,
            copy_challenges,
            prepared.trace_size,
        )?);
        let mut profile_aux =
            ZeroizingBaseFieldMatrixV1::from(adapter.build_profile_aux_columns_v1(
                base_columns,
                &copy_aux,
                &prepared.fixed_columns,
                copy_challenges,
                &profile_challenges,
            )?);
        canonical_columns_v1(
            &profile_aux,
            adapter.profile_aux_width_v1(),
            prepared.trace_size,
        )?;
        let mut aux_columns = copy_aux;
        aux_columns.append(&mut profile_aux);
        canonical_columns_v1(&aux_columns, prepared.aux_width, prepared.trace_size)?;
        phases.advance(ProofPhaseV1::NativeConstraints);
        validate_native_constraints_v1(
            adapter,
            &prepared,
            base_columns,
            &aux_columns,
            copy_challenges,
            &profile_challenges,
        )?;
        phases.advance(ProofPhaseV1::AuxiliaryLde);
        let (aux_lde, aux_masks) =
            masked_lde_columns_v1(&aux_columns, prepared.trace_log2, lde_log2, rng)?;
        let aux_lde = ZeroizingBaseFieldMatrixV1::from(aux_lde);
        phases.advance(ProofPhaseV1::AuxiliaryCommitment);
        let aux_tree = aggregate::row_tree_v1(
            prepared.protocol.domains.digest_context,
            prepared.protocol.domains.aux_leaf,
            prepared.protocol.domains.aux_node,
            0,
            &aux_lde,
            lde_size,
        )
        .map_err(map_aggregate_error_v1)?;
        phases.advance(ProofPhaseV1::FixedLdeAndChallenges);
        trace_group_proofs[0].aux_root = aux_tree.root();
        aggregate::absorb_aux_roots_v1(
            &mut transcript,
            &prepared.protocol.domains,
            &trace_group_proofs,
        )
        .map_err(map_aggregate_error_v1)?;
        let alphas = derive_constraint_alphas_v1(&mut transcript, prepared.constraint_count)?;
        let fixed_lde =
            fixed_lde_columns_v1(&prepared.fixed_columns, prepared.trace_log2, lde_log2)?;
        phases.advance(ProofPhaseV1::CompositionValues);
        let compositions = ZeroizingExtensionFieldCubeV1::from(composition_lanes_v1(
            adapter,
            &prepared,
            &base_lde,
            &aux_lde,
            &fixed_lde,
            copy_challenges,
            &profile_challenges,
            &alphas,
        )?);
        phases.advance(ProofPhaseV1::CompositionCommitments);
        let mut composition_trees = Vec::with_capacity(PROOF_MANAGED_NOTE_SECURITY_LANES_V1);
        let mut composition_roots = Vec::with_capacity(PROOF_MANAGED_NOTE_SECURITY_LANES_V1);
        for lane in 0..PROOF_MANAGED_NOTE_SECURITY_LANES_V1 {
            let tree = aggregate::composition_tree_v1(
                &prepared.protocol.domains,
                lane,
                &compositions[lane],
            )
            .map_err(map_aggregate_error_v1)?;
            composition_roots.push(tree.root());
            composition_trees.push(tree);
        }
        aggregate::absorb_composition_roots_v1(
            &mut transcript,
            prepared.protocol.parameters,
            &prepared.protocol.domains,
            &composition_roots,
        )
        .map_err(map_aggregate_error_v1)?;
        phases.advance(ProofPhaseV1::FriMaskOracles);
        let fri_masks = aggregate::build_fri_mask_oracles_v1(
            prepared.protocol.parameters,
            &prepared.protocol.domains,
            &prepared.layout,
            rng,
        )
        .map_err(map_aggregate_error_v1)?;
        let fri_mask_roots = fri_masks
            .iter()
            .map(|mask| mask.tree.root())
            .collect::<Vec<_>>();
        aggregate::absorb_fri_mask_roots_v1(
            &mut transcript,
            prepared.protocol.parameters,
            &prepared.protocol.domains,
            &fri_mask_roots,
        )
        .map_err(map_aggregate_error_v1)?;
        phases.advance(ProofPhaseV1::DeepEvaluations);
        let trace_materials = vec![aggregate::AggregateTraceGroupMaterialV1 {
            base_lde: base_lde.into_inner(),
            aux_lde: aux_lde.into_inner(),
            base_tree,
            aux_tree,
        }];
        let deep_point = aggregate::derive_deep_point_v1(
            &mut transcript,
            prepared.protocol.parameters,
            &prepared.layout,
        )
        .map_err(map_aggregate_error_v1)?;
        let (base_current, base_next) = evaluate_masked_native_columns_at_deep_v1(
            base_columns,
            &base_masks,
            prepared.trace_log2,
            deep_point,
        )?;
        let (aux_current, aux_next) = evaluate_masked_native_columns_at_deep_v1(
            &aux_columns,
            &aux_masks,
            prepared.trace_log2,
            deep_point,
        )?;
        let deep_compositions = aggregate::evaluate_composition_chunks_at_deep_v1(
            &compositions,
            prepared.protocol.parameters,
            &prepared.layout,
            deep_point,
        )
        .map_err(map_aggregate_error_v1)?;
        let deep = aggregate::AggregateDeepProofV1 {
            trace_groups: vec![aggregate::AggregateDeepTraceGroupOpeningV1 {
                base_current: base_current
                    .into_iter()
                    .map(|value| value.coefficients().map(F::value))
                    .collect(),
                base_next: base_next
                    .into_iter()
                    .map(|value| value.coefficients().map(F::value))
                    .collect(),
                aux_current: aux_current
                    .into_iter()
                    .map(|value| value.coefficients().map(F::value))
                    .collect(),
                aux_next: aux_next
                    .into_iter()
                    .map(|value| value.coefficients().map(F::value))
                    .collect(),
            }],
            composition_values: deep_compositions
                .into_iter()
                .map(|lane| {
                    lane.into_iter()
                        .map(|value| value.coefficients().map(F::value))
                        .collect()
                })
                .collect(),
        };
        aggregate::validate_deep_proof_shape_v1(
            &deep,
            prepared.protocol.parameters,
            &prepared.layout,
        )
        .map_err(map_aggregate_error_v1)?;
        drop(base_masks);
        drop(aux_masks);
        aggregate::absorb_deep_openings_v1(
            &mut transcript,
            &deep,
            prepared.protocol.parameters,
            &prepared.layout,
        )
        .map_err(map_aggregate_error_v1)?;
        let mixes = derive_deep_mixes_v1(
            &mut transcript,
            prepared.base_width,
            prepared.aux_width,
            prepared.protocol.parameters.composition_degree_chunks,
            prepared.protocol.parameters,
            &prepared.layout,
        )?;
        phases.advance(ProofPhaseV1::FriLayers);
        let mut fri_lanes = Vec::with_capacity(PROOF_MANAGED_NOTE_SECURITY_LANES_V1);
        for lane in 0..PROOF_MANAGED_NOTE_SECURITY_LANES_V1 {
            let mut fri_base = ZeroizingExtensionFieldValuesV1::from(mixed_deep_fri_base_v1(
                &trace_materials[0].base_lde,
                &trace_materials[0].aux_lde,
                &compositions[lane],
                &deep,
                deep_point,
                &mixes[lane],
                lane,
                prepared.protocol.parameters,
                &prepared.layout,
            )?);
            aggregate::add_fri_mask_oracle_v1(&mut fri_base, &fri_masks[lane])
                .map_err(map_aggregate_error_v1)?;
            fri_lanes.push(
                aggregate::build_fri_lane_v1(
                    prepared.protocol.parameters,
                    &prepared.protocol.domains,
                    &prepared.layout,
                    lane,
                    fri_base.into_inner(),
                    &mut transcript,
                )
                .map_err(map_aggregate_error_v1)?,
            );
        }
        phases.advance(ProofPhaseV1::Nonce);
        let grinding_state = transcript.state();
        let grinding_nonce = grind_nonce_v1(
            prepared.protocol.domains.digest_context,
            &grinding_state,
            PROOF_MANAGED_NOTE_GRINDING_BITS_V1,
        )
        .map_err(map_transparent_error_v1)?;
        absorb_grinding_nonce_v1(&mut transcript, grinding_nonce)?;
        phases.advance(ProofPhaseV1::Openings);
        let query_indices = aggregate::query_indices_v1(
            &transcript,
            prepared.protocol.parameters,
            &prepared.protocol.domains,
            &prepared.layout,
        )
        .map_err(map_aggregate_error_v1)?;
        let queries = query_indices
            .into_iter()
            .map(|index| {
                aggregate::build_query_v1(
                    prepared.protocol.parameters,
                    &prepared.layout,
                    index,
                    &trace_materials,
                    &compositions,
                    &fri_masks,
                    &fri_lanes,
                )
                .map_err(map_aggregate_error_v1)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (trace_frontiers, composition_frontiers, fri_mask_frontiers, fri_round_frontiers) =
            aggregate::build_all_frontiers_v1(
                prepared.protocol.parameters,
                &prepared.layout,
                &queries,
                &trace_materials,
                &composition_trees,
                &fri_masks,
                &fri_lanes,
            )
            .map_err(map_aggregate_error_v1)?;
        for (group, (base_frontier, aux_frontier)) in
            trace_group_proofs.iter_mut().zip(trace_frontiers)
        {
            group.base_frontier = base_frontier;
            group.aux_frontier = aux_frontier;
        }
        let proof = aggregate::AggregateStarkProofV1 {
            version: prepared.protocol.parameters.proof_version,
            trace_groups: trace_group_proofs,
            composition_roots,
            composition_frontiers,
            fri_mask_roots,
            fri_mask_frontiers,
            fri_lanes: fri_lanes
                .into_iter()
                .zip(fri_round_frontiers)
                .map(
                    |(lane, round_frontiers)| aggregate::AggregateFriLaneProofV1 {
                        roots: lane.roots,
                        terminal_values: lane
                            .terminal_values
                            .into_iter()
                            .map(|value| value.coefficients().map(F::value))
                            .collect(),
                        round_frontiers,
                    },
                )
                .collect(),
            queries,
            grinding_nonce,
        };
        phases.advance(ProofPhaseV1::Encode);
        let encoded = aggregate::encode_proof_with_deep_v1(
            &proof,
            &deep,
            prepared.protocol.parameters,
            &prepared.layout,
        )
        .map_err(map_aggregate_error_v1)?;
        let candidate = ProofManagedNoteCandidateV1 { encoded };
        phases.finish(true);
        Ok(candidate)
    })();
    if result.is_err() {
        // Normal failure includes cleanup of the closure's locals. Unwind stays incomplete.
        phases.finish(false);
    }
    result
}
struct NoteOpenedRowEvaluatorV1<'a, A: ProofManagedNoteStarkAdapterV1> {
    adapter: &'a A,
    prepared: &'a PreparedNoteProfileV1,
    fixed_openings: &'a std::collections::BTreeMap<usize, Vec<F>>,
    copy_challenges: NoteCopyChallengesV1,
    profile_challenges: &'a A::ProfileChallenges,
    alphas: &'a [Vec<E>],
    lde_root: F,
}
impl<A: ProofManagedNoteStarkAdapterV1> AggregateOpenedRowEvaluatorV1
    for NoteOpenedRowEvaluatorV1<'_, A>
{
    fn evaluate_opened_row_v1(
        &mut self,
        query_index: usize,
        lane: usize,
        trace_groups: &[aggregate::AggregateOpenedTraceGroupV1],
        _composition_chunks: &[E],
    ) -> Result<aggregate::AggregateExpectedOpeningV1, aggregate::AggregateStarkErrorV1> {
        let opening = trace_groups
            .first()
            .filter(|_| trace_groups.len() == 1)
            .ok_or(aggregate::AggregateStarkErrorV1::ConstraintOpening)?;
        let alphas = self
            .alphas
            .get(lane)
            .filter(|alphas| alphas.len() == self.prepared.constraint_count)
            .ok_or(aggregate::AggregateStarkErrorV1::ConstraintOpening)?;
        let fixed = self
            .fixed_openings
            .get(&query_index)
            .ok_or(aggregate::AggregateStarkErrorV1::ConstraintOpening)?;
        let residues = all_constraint_residues_v1(
            self.adapter,
            self.prepared,
            &opening.base_current,
            &opening.base_next,
            &opening.aux_current,
            &opening.aux_next,
            fixed,
            self.copy_challenges,
            self.profile_challenges,
        )
        .map_err(|_| aggregate::AggregateStarkErrorV1::ConstraintOpening)?;
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(self.lde_root.pow(query_index as u128));
        let inverse_vanishing = x
            .pow(self.prepared.trace_size as u128)
            .sub(F::ONE)
            .inv()
            .ok_or(aggregate::AggregateStarkErrorV1::ConstraintOpening)?;
        let composition = residues
            .iter()
            .zip(alphas)
            .fold(E::ZERO, |sum, (residue, alpha)| {
                sum.add(alpha.mul_base(*residue))
            })
            .mul_base(inverse_vanishing);
        Ok(aggregate::AggregateExpectedOpeningV1 {
            composition,
            // The DEEP verifier derives the FRI base from all authenticated
            // trace/composition openings after this callback has checked the
            // AIR quotient. Returning zero prevents a stale raw-row mix from
            // becoming an accidental second FRI relation.
            fri_base: E::ZERO,
        })
    }
}
/// Verify the exact canonical proof wire against one statement-derived adapter.
pub fn verify_proof_managed_note_stark_v1<A: ProofManagedNoteStarkAdapterV1>(
    adapter: &A,
    proof_bytes: &[u8],
) -> Result<(), ProofManagedNoteStarkErrorV1> {
    // Fixed columns come only from the compiled adapter. Reject malformed wire,
    // transcript and Merkle openings before reconstructing their native matrix;
    // all profiles then evaluate exactly the authenticated query positions.
    let prepared = prepare_note_profile_with_fixed_v1(adapter, false)?;
    let (proof, deep) = aggregate::decode_proof_with_deep_v1(
        proof_bytes,
        prepared.protocol.parameters,
        &prepared.layout,
    )
    .map_err(map_aggregate_error_v1)?;
    let public_digest = adapter.public_input_digest_v1()?;
    let mut transcript = new_note_transcript_v1(&prepared, &public_digest)?;
    aggregate::absorb_base_roots_v1(
        &mut transcript,
        &prepared.protocol.domains,
        &proof.trace_groups,
    )
    .map_err(map_aggregate_error_v1)?;
    let copy_challenges = derive_note_copy_challenges_v1(&mut transcript)?;
    let profile_challenges =
        adapter.derive_profile_challenges_v1(&mut transcript, copy_challenges)?;
    aggregate::absorb_aux_roots_v1(
        &mut transcript,
        &prepared.protocol.domains,
        &proof.trace_groups,
    )
    .map_err(map_aggregate_error_v1)?;
    let alphas = derive_constraint_alphas_v1(&mut transcript, prepared.constraint_count)?;
    aggregate::absorb_composition_roots_v1(
        &mut transcript,
        prepared.protocol.parameters,
        &prepared.protocol.domains,
        &proof.composition_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_fri_mask_roots_v1(
        &mut transcript,
        prepared.protocol.parameters,
        &prepared.protocol.domains,
        &proof.fri_mask_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let deep_point = aggregate::derive_deep_point_v1(
        &mut transcript,
        prepared.protocol.parameters,
        &prepared.layout,
    )
    .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_deep_openings_v1(
        &mut transcript,
        &deep,
        prepared.protocol.parameters,
        &prepared.layout,
    )
    .map_err(map_aggregate_error_v1)?;
    let mixes = derive_deep_mixes_v1(
        &mut transcript,
        prepared.base_width,
        prepared.aux_width,
        prepared.protocol.parameters.composition_degree_chunks,
        prepared.protocol.parameters,
        &prepared.layout,
    )?;
    let (fri_betas, terminals) = aggregate::verify_fri_commitments_v1(
        &proof,
        prepared.protocol.parameters,
        &prepared.protocol.domains,
        &prepared.layout,
        &mut transcript,
    )
    .map_err(map_aggregate_error_v1)?;
    let grinding_state = transcript.state();
    verify_grinding_nonce_v1(
        prepared.protocol.domains.digest_context,
        &grinding_state,
        PROOF_MANAGED_NOTE_GRINDING_BITS_V1,
        proof.grinding_nonce,
    )
    .map_err(|_| ProofManagedNoteStarkErrorV1::Transcript)?;
    absorb_grinding_nonce_v1(&mut transcript, proof.grinding_nonce)?;
    let expected_indices = aggregate::query_indices_v1(
        &transcript,
        prepared.protocol.parameters,
        &prepared.protocol.domains,
        &prepared.layout,
    )
    .map_err(map_aggregate_error_v1)?;
    aggregate::verify_all_merkle_openings_v1(
        &proof,
        prepared.protocol.parameters,
        &prepared.protocol.domains,
        &prepared.layout,
        &expected_indices,
    )
    .map_err(map_aggregate_error_v1)?;
    let fixed_openings = fixed_queries::query_rows_v1(
        prepare_fixed_columns_v1(adapter, prepared.trace_size, prepared.fixed_width)?,
        prepared.trace_log2,
        prepared.layout.common_lde_log2(),
        &expected_indices,
    )?;
    let lde_root = goldilocks_primitive_root_v1(prepared.layout.common_lde_log2())
        .map_err(map_transparent_error_v1)?;
    let mut evaluator = NoteOpenedRowEvaluatorV1 {
        adapter,
        prepared: &prepared,
        fixed_openings: &fixed_openings,
        copy_challenges,
        profile_challenges: &profile_challenges,
        alphas: &alphas,
        lde_root,
    };
    aggregate::verify_opened_query_relations_with_deep_v1(
        &proof,
        &deep,
        deep_point,
        &mixes,
        prepared.protocol.parameters,
        &prepared.layout,
        &expected_indices,
        &fri_betas,
        &terminals,
        &mut evaluator,
    )
    .map_err(map_aggregate_error_v1)
}
/// Independent full-LDE oracles and explicitly selected component measurements.
#[cfg(test)]
pub mod fixed_query_audit {
    use super::*;
    use std::{collections::BTreeMap, time::Duration};

    fn fixture_geometry<A: ProofManagedNoteStarkAdapterV1>(
        adapter: &A,
    ) -> (PreparedNoteProfileV1, Vec<usize>) {
        let prepared = prepare_note_profile_with_fixed_v1(adapter, false).expect("real geometry");
        let seed = adapter
            .public_input_digest_v1()
            .expect("real public binding");
        // These are deterministic component-test coordinates derived from the
        // actual statement. They are not represented as an authenticated proof.
        let indices = crate::privacy_engines::transparent_stark::derive_unique_query_indices_v1(
            prepared.protocol.domains.digest_context,
            &seed,
            prepared.layout.common_lde_size(),
            prepared.protocol.parameters.query_count,
        )
        .expect("complete legal query set");
        assert_eq!(indices.len(), PROOF_MANAGED_NOTE_QUERY_COUNT_V1);
        (prepared, indices)
    }

    fn assert_rows<A: ProofManagedNoteStarkAdapterV1>(
        adapter: &A,
        prepared: &PreparedNoteProfileV1,
        indices: &[usize],
    ) {
        let columns = prepare_fixed_columns_v1(adapter, prepared.trace_size, prepared.fixed_width)
            .expect("actual adapter fixed columns");
        let reference = fixed_lde_columns_v1(
            &columns,
            prepared.trace_log2,
            prepared.layout.common_lde_log2(),
        )
        .expect("unchanged full-LDE oracle");
        let selected = fixed_queries::query_rows_v1(
            columns.clone(),
            prepared.trace_log2,
            prepared.layout.common_lde_log2(),
            indices,
        )
        .expect("selected fixed rows");
        assert_eq!(selected.len(), indices.len());
        for index in indices {
            assert_eq!(
                selected[index],
                row_at_columns_v1(&reference, *index).expect("full oracle row")
            );
        }
        let boundaries = [0, prepared.layout.common_lde_size() - 1];
        let selected = fixed_queries::query_rows_v1(
            columns,
            prepared.trace_log2,
            prepared.layout.common_lde_log2(),
            &boundaries,
        )
        .expect("legal boundary rows");
        for index in boundaries {
            assert_eq!(
                selected[&index],
                row_at_columns_v1(&reference, index).expect("boundary oracle row")
            );
        }
    }

    /// Compare all fixed columns at 136 public fixture coordinates and both ends.
    pub fn assert_profile_matches_full_lde_v1<A: ProofManagedNoteStarkAdapterV1>(adapter: &A) {
        let (prepared, indices) = fixture_geometry(adapter);
        assert_rows(adapter, &prepared, &indices);
    }

    /// Authenticate an actual proof, then compare every opened fixed row to the oracle.
    pub fn assert_proof_queries_match_full_lde_v1<A: ProofManagedNoteStarkAdapterV1>(
        adapter: &A,
        proof: &[u8],
    ) {
        verify_proof_managed_note_stark_v1(adapter, proof).expect("authenticated proof");
        let prepared = prepare_note_profile_with_fixed_v1(adapter, false).expect("geometry");
        let (decoded, _) = aggregate::decode_proof_with_deep_v1(
            proof,
            prepared.protocol.parameters,
            &prepared.layout,
        )
        .expect("exact proof wire");
        let indices = decoded
            .queries
            .iter()
            .map(|query| query.index as usize)
            .collect::<Vec<_>>();
        assert_eq!(indices.len(), PROOF_MANAGED_NOTE_QUERY_COUNT_V1);
        assert_rows(adapter, &prepared, &indices);
    }

    struct RejectFixed<'a, A>(&'a A);
    impl<A: ProofManagedNoteStarkAdapterV1> ProofManagedNoteStarkAdapterV1 for RejectFixed<'_, A> {
        type ProfileChallenges = A::ProfileChallenges;
        fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
            self.0.protocol_v1()
        }
        fn public_input_digest_v1(
            &self,
        ) -> Result<PrivacyOuterDigestV1, ProofManagedNoteStarkErrorV1> {
            self.0.public_input_digest_v1()
        }
        fn trace_log2_v1(&self) -> u8 {
            self.0.trace_log2_v1()
        }
        fn base_width_v1(&self) -> usize {
            self.0.base_width_v1()
        }
        fn profile_aux_width_v1(&self) -> usize {
            self.0.profile_aux_width_v1()
        }
        fn profile_fixed_width_v1(&self) -> usize {
            self.0.profile_fixed_width_v1()
        }
        fn profile_constraint_count_v1(&self) -> usize {
            self.0.profile_constraint_count_v1()
        }
        fn copy_schedule_v1(&self) -> Result<NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1> {
            panic!("malformed proof reached actual adapter copy-schedule allocation")
        }
        fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
            panic!("malformed proof reached actual adapter fixed-column allocation")
        }
        fn derive_profile_challenges_v1(
            &self,
            transcript: &mut TransparentTranscriptV1,
            copy: NoteCopyChallengesV1,
        ) -> Result<Self::ProfileChallenges, ProofManagedNoteStarkErrorV1> {
            self.0.derive_profile_challenges_v1(transcript, copy)
        }
        fn build_profile_aux_columns_v1(
            &self,
            base: &[Vec<F>],
            copy_aux: &[Vec<F>],
            fixed: &[Vec<F>],
            copy: NoteCopyChallengesV1,
            profile: &Self::ProfileChallenges,
        ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
            self.0
                .build_profile_aux_columns_v1(base, copy_aux, fixed, copy, profile)
        }
        fn profile_constraint_residues_v1(
            &self,
            base: &[F],
            next_base: &[F],
            aux: &[F],
            next_aux: &[F],
            fixed: &[F],
            copy: NoteCopyChallengesV1,
            profile: &Self::ProfileChallenges,
        ) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
            self.0.profile_constraint_residues_v1(
                base, next_base, aux, next_aux, fixed, copy, profile,
            )
        }
    }

    /// Prove a real adapter's malformed-wire path does not construct its fixed matrix.
    pub fn assert_malformed_rejected_before_fixed_v1<A: ProofManagedNoteStarkAdapterV1>(
        adapter: &A,
    ) {
        adapter
            .public_input_digest_v1()
            .expect("valid real public binding");
        let guarded = RejectFixed(adapter);
        for bytes in [
            vec![],
            adapter.protocol_v1().parameters.proof_magic.to_vec(),
            vec![0; 32],
        ] {
            assert_eq!(
                verify_proof_managed_note_stark_v1(&guarded, &bytes),
                Err(ProofManagedNoteStarkErrorV1::ProofWire)
            );
        }
    }

    struct MeasuredRows {
        rows: BTreeMap<usize, Vec<F>>,
        prepare: Duration,
        evaluate: Duration,
        complete: Duration,
    }
    fn full_rows<A: ProofManagedNoteStarkAdapterV1>(
        adapter: &A,
        prepared: &PreparedNoteProfileV1,
        indices: &[usize],
    ) -> MeasuredRows {
        let started = std::time::Instant::now();
        let columns = prepare_fixed_columns_v1(adapter, prepared.trace_size, prepared.fixed_width)
            .expect("fixed preparation");
        let prepare = started.elapsed();
        let begin = std::time::Instant::now();
        let full = fixed_lde_columns_v1(
            &columns,
            prepared.trace_log2,
            prepared.layout.common_lde_log2(),
        )
        .expect("full LDE");
        let evaluate = begin.elapsed();
        // Reference row extraction and equality checking are outside measured FFT work.
        let rows = indices
            .iter()
            .map(|index| {
                (
                    *index,
                    row_at_columns_v1(&full, *index).expect("reference row"),
                )
            })
            .collect();
        // Both variants finish with only their selected rows retained.
        // Include extraction and full/native matrix release in this common span.
        drop(full);
        drop(columns);
        let complete = started.elapsed();
        MeasuredRows {
            rows,
            prepare,
            evaluate,
            complete,
        }
    }
    fn selected_rows<A: ProofManagedNoteStarkAdapterV1>(
        adapter: &A,
        prepared: &PreparedNoteProfileV1,
        indices: &[usize],
    ) -> MeasuredRows {
        let started = std::time::Instant::now();
        let columns = prepare_fixed_columns_v1(adapter, prepared.trace_size, prepared.fixed_width)
            .expect("fixed preparation");
        let prepare = started.elapsed();
        let begin = std::time::Instant::now();
        let rows = fixed_queries::query_rows_v1(
            columns,
            prepared.trace_log2,
            prepared.layout.common_lde_log2(),
            indices,
        )
        .expect("selected rows");
        let evaluate = begin.elapsed();
        // query_rows_v1 has returned and released its consumed oracle/scratch.
        let complete = started.elapsed();
        MeasuredRows {
            rows,
            prepare,
            evaluate,
            complete,
        }
    }

    /// Print four alternating matched component pairs in one private eight-worker pool.
    ///
    /// No proof is generated and these spans are not whole-verifier or prover times.
    /// Preparation is reconstructed for each path; no cache flush or warm-up is hidden.
    /// `complete` covers preparation through selected-row output with all other
    /// buffers released, providing the same physical completion boundary.
    pub fn measure_profile_eight_workers_v1<A: ProofManagedNoteStarkAdapterV1>(
        adapter: &A,
        label: &str,
    ) {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .expect("eight-worker measurement pool");
        pool.install(|| {
            assert_eq!(rayon::current_num_threads(), 8);
            let (prepared, indices) = fixture_geometry(adapter);
            for sample in 0..4 {
                let (full, selected) = if sample % 2 == 0 {
                    let full = full_rows(adapter, &prepared, &indices);
                    (full, selected_rows(adapter, &prepared, &indices))
                } else {
                    let selected = selected_rows(adapter, &prepared, &indices);
                    (full_rows(adapter, &prepared, &indices), selected)
                };
                assert_eq!(full.rows, selected.rows);
                std::hint::black_box((&full.rows, &selected.rows));
                eprintln!("bck26_fixed_query_component_v1 profile={label} workers=8 sample={sample} full_first={} trace_log2={} lde_log2={} fixed_columns={} queries={} full_prepare_ns={} full_evaluate_ns={} selected_prepare_ns={} selected_evaluate_ns={} full_complete_ns={} selected_complete_ns={} proof_generated=false",
                    sample % 2 == 0, prepared.trace_log2, prepared.layout.common_lde_log2(), prepared.fixed_width, indices.len(), full.prepare.as_nanos(), full.evaluate.as_nanos(), selected.prepare.as_nanos(), selected.evaluate.as_nanos(), full.complete.as_nanos(), selected.complete.as_nanos());
            }
        });
    }
}

/// Deterministic affine-line audits for declared AIR polynomial degrees.
///
/// This test-only helper varies every evaluator input independently along
/// random affine lines and computes finite differences over the Goldilocks
/// field.  A polynomial of declared degree `d` must have an identically zero
/// `(d + 1)`st difference on every sampled line.  Callers separately assert
/// that degree `d` is actually observed, preventing a stale overstatement as
/// well as an unsound understatement.
#[cfg(test)]
pub mod degree_audit {
    use super::F;
    use core::fmt::Debug;
    use rand::{RngCore as _, SeedableRng as _, rngs::StdRng};
    fn random_field_v1(rng: &mut StdRng) -> F {
        F::reduce(u128::from(rng.next_u64()))
    }
    fn random_nonzero_field_v1(rng: &mut StdRng) -> F {
        let value = random_field_v1(rng);
        if value == F::ZERO { F::ONE } else { value }
    }
    fn affine_vector_v1(origin: &[F], direction: &[F], point: F) -> Vec<F> {
        origin
            .iter()
            .copied()
            .zip(direction.iter().copied())
            .map(|(origin, direction)| origin.add(direction.mul(point)))
            .collect()
    }
    /// Measure and enforce the maximum total degree of a residue evaluator.
    pub fn measured_maximum_affine_degree_v1<E>(
        seed: [u8; 32],
        widths: [usize; 5],
        trial_count: usize,
        declared_maximum_degree: u8,
        mut evaluate: impl FnMut(&[F], &[F], &[F], &[F], &[F]) -> Result<Vec<F>, E>,
    ) -> usize
    where
        E: Debug,
    {
        assert!(trial_count > 0, "degree audit requires at least one trial");
        assert!(
            declared_maximum_degree > 0,
            "degree audit requires a positive declared degree"
        );
        let mut rng = StdRng::from_seed(seed);
        let mut measured_maximum = 0;
        let terminal_order = usize::from(declared_maximum_degree) + 1;
        for trial in 0..trial_count {
            let origins = widths.map(|width| {
                (0..width)
                    .map(|_| random_field_v1(&mut rng))
                    .collect::<Vec<_>>()
            });
            let directions = widths.map(|width| {
                (0..width)
                    .map(|_| random_nonzero_field_v1(&mut rng))
                    .collect::<Vec<_>>()
            });
            let mut differences = (0..=terminal_order)
                .map(|point| {
                    let point = F(u64::try_from(point).expect("small degree-audit point fits u64"));
                    let arguments: [Vec<F>; 5] = core::array::from_fn(|index| {
                        affine_vector_v1(&origins[index], &directions[index], point)
                    });
                    evaluate(
                        &arguments[0],
                        &arguments[1],
                        &arguments[2],
                        &arguments[3],
                        &arguments[4],
                    )
                    .unwrap_or_else(|error| {
                        panic!("degree-audit evaluator failed in trial {trial}: {error:?}")
                    })
                })
                .collect::<Vec<_>>();
            let residue_count = differences
                .first()
                .map(Vec::len)
                .expect("degree audit has evaluation points");
            assert!(residue_count > 0, "degree audit requires residues");
            assert!(
                differences
                    .iter()
                    .all(|residues| residues.len() == residue_count),
                "degree-audit residue width changed within trial {trial}"
            );
            for order in 1..=terminal_order {
                differences = differences
                    .windows(2)
                    .map(|pair| {
                        pair[1]
                            .iter()
                            .copied()
                            .zip(pair[0].iter().copied())
                            .map(|(after, before)| after.sub(before))
                            .collect::<Vec<_>>()
                    })
                    .collect();
                let any_nonzero = differences
                    .iter()
                    .flatten()
                    .any(|residue| *residue != F::ZERO);
                if any_nonzero {
                    measured_maximum = measured_maximum.max(order);
                }
                if order == terminal_order {
                    assert!(
                        !any_nonzero,
                        "trial {trial} has nonzero order-{terminal_order} finite difference; \
                         declared maximum degree is {declared_maximum_degree}"
                    );
                }
            }
        }
        measured_maximum
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng as _, rngs::StdRng};
    use std::sync::OnceLock;
    const MOCK_PROFILE_DESCRIPTOR_V1: &[u8] = b"proof-managed-note-mock-relation-v1:wire=PMN1-v1:trace=2^13:base=8:profile-aux=0:profile-fixed=0:profile-constraints=1:constraint-degree=2:max-proof=4194304";
    const MOCK_TRACE_LOG2_V1: u8 = 13;
    const MOCK_DOMAINS_V1: aggregate::AggregateStarkDomainsV1 =
        aggregate::AggregateStarkDomainsV1 {
            digest_context: super::super::transparent_stark::TransparentStarkDigestContextV1::new(
                PrivacyProtocolIdV1::PqMaspStarkV1,
                b"proof-managed-note-mock-profile-v1",
            ),
            base_leaf: b"proof-managed-note-mock-base-leaf-v1",
            base_node: b"proof-managed-note-mock-base-node-v1",
            aux_leaf: b"proof-managed-note-mock-aux-leaf-v1",
            aux_node: b"proof-managed-note-mock-aux-node-v1",
            composition_leaf: b"proof-managed-note-mock-composition-leaf-v1",
            composition_node: b"proof-managed-note-mock-composition-node-v1",
            fri_leaf: b"proof-managed-note-mock-fri-leaf-v1",
            fri_node: b"proof-managed-note-mock-fri-node-v1",
            layout_label: b"proof-managed-note-mock-layout-label-v1",
            base_root_label: b"proof-managed-note-mock-base-root-label-v1",
            aux_root_label: b"proof-managed-note-mock-aux-root-label-v1",
            composition_root_label: b"proof-managed-note-mock-composition-root-label-v1",
            fri_root_label: b"proof-managed-note-mock-fri-root-label-v1",
            fri_beta_label: b"proof-managed-note-mock-fri-beta-label-v1",
            query_seed: b"proof-managed-note-mock-query-seed-v1",
        };
    fn mock_parameters_v1() -> aggregate::AggregateStarkParametersV1 {
        aggregate::AggregateStarkParametersV1 {
            proof_magic: *b"PMN1",
            proof_version: 1,
            fri_commitment_layout: aggregate::AggregateFriCommitmentLayoutV1::Scalar,
            security_lanes: PROOF_MANAGED_NOTE_SECURITY_LANES_V1,
            query_count: PROOF_MANAGED_NOTE_QUERY_COUNT_V1,
            blowup_log2: PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1,
            terminal_log2: PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1,
            terminal_degree_bound: PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1,
            composition_degree_chunks: PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1,
            minimum_trace_log2: MOCK_TRACE_LOG2_V1,
            maximum_trace_log2: MOCK_TRACE_LOG2_V1,
            maximum_trace_groups: 1,
            maximum_segment_instances: 1,
            maximum_base_columns_per_instance: NOTE_COPY_WIDTH_V1,
            maximum_aux_columns_per_instance: NOTE_COPY_AUX_WIDTH_V1,
            maximum_proof_bytes: 4 * 1024 * 1024,
        }
    }
    #[derive(Clone)]
    struct MockAdapterV1 {
        parameters: aggregate::AggregateStarkParametersV1,
        maximum_constraint_degree: u8,
        public_digest: PrivacyOuterDigestV1,
        corrupt_schedule: bool,
        reject_fixed_materialization: bool,
        public_input_reads: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    }
    impl Default for MockAdapterV1 {
        fn default() -> Self {
            Self {
                parameters: mock_parameters_v1(),
                maximum_constraint_degree: NOTE_COPY_CONSTRAINT_DEGREE_V1,
                public_digest: PrivacyOuterDigestV1::from_bytes([0x24; 48]),
                corrupt_schedule: false,
                reject_fixed_materialization: false,
                public_input_reads: None,
            }
        }
    }
    impl ProofManagedNoteStarkAdapterV1 for MockAdapterV1 {
        type ProfileChallenges = ();
        fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
            ProofManagedNoteStarkProtocolV1 {
                parameters: self.parameters,
                domains: MOCK_DOMAINS_V1,
                maximum_constraint_degree: self.maximum_constraint_degree,
                profile_binding_label: b"proof-managed-note-mock-profile-binding-v1",
                profile_descriptor: MOCK_PROFILE_DESCRIPTOR_V1,
                relation_layout_domain: b"proof-managed-note-mock-relation-layout-v1",
            }
        }
        fn public_input_digest_v1(
            &self,
        ) -> Result<PrivacyOuterDigestV1, ProofManagedNoteStarkErrorV1> {
            if let Some(reads) = &self.public_input_reads {
                reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(self.public_digest)
        }
        fn trace_log2_v1(&self) -> u8 {
            MOCK_TRACE_LOG2_V1
        }
        fn base_width_v1(&self) -> usize {
            NOTE_COPY_WIDTH_V1
        }
        fn profile_aux_width_v1(&self) -> usize {
            0
        }
        fn profile_fixed_width_v1(&self) -> usize {
            0
        }
        fn profile_constraint_count_v1(&self) -> usize {
            1
        }
        fn copy_schedule_v1(&self) -> Result<NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1> {
            assert!(
                !self.reject_fixed_materialization,
                "fixed trace must not be materialized before proof admission"
            );
            let trace_size = 1_usize << self.trace_log2_v1();
            let policies = vec![[NoteCopyCellPolicyV1::Variable; NOTE_COPY_WIDTH_V1]; trace_size];
            let mut sigma = vec![[0_u32; NOTE_COPY_WIDTH_V1]; trace_size];
            for row in 0..trace_size {
                for column in 0..NOTE_COPY_WIDTH_V1 {
                    let next_row = (row + 1) % trace_size;
                    sigma[row][column] = u32::try_from(next_row * NOTE_COPY_WIDTH_V1 + column + 1)
                        .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
                }
            }
            if self.corrupt_schedule {
                sigma[0][0] = sigma[0][1];
            }
            Ok(NoteCopyScheduleV1 { policies, sigma })
        }
        fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
            Ok(Vec::new())
        }
        fn derive_profile_challenges_v1(
            &self,
            _transcript: &mut TransparentTranscriptV1,
            _copy_challenges: NoteCopyChallengesV1,
        ) -> Result<Self::ProfileChallenges, ProofManagedNoteStarkErrorV1> {
            Ok(())
        }
        fn build_profile_aux_columns_v1(
            &self,
            _base_columns: &[Vec<F>],
            _copy_aux_columns: &[Vec<F>],
            _fixed_columns: &[Vec<F>],
            _copy_challenges: NoteCopyChallengesV1,
            _profile_challenges: &Self::ProfileChallenges,
        ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
            Ok(Vec::new())
        }
        fn profile_constraint_residues_v1(
            &self,
            current_base: &[F],
            _next_base: &[F],
            _current_aux: &[F],
            _next_aux: &[F],
            _fixed: &[F],
            _copy_challenges: NoteCopyChallengesV1,
            _profile_challenges: &Self::ProfileChallenges,
        ) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
            Ok(vec![
                *current_base
                    .first()
                    .ok_or(ProofManagedNoteStarkErrorV1::InvalidTrace)?,
            ])
        }
    }

    fn mock_base_columns_v1() -> Vec<Vec<F>> {
        (0..NOTE_COPY_WIDTH_V1)
            .map(|column| vec![F(column as u64); 1 << MOCK_TRACE_LOG2_V1])
            .collect()
    }

    #[test]
    fn privacy_rejects_malformed_wire_before_any_fixed_trace_allocation() {
        let adapter = MockAdapterV1 {
            reject_fixed_materialization: true,
            ..MockAdapterV1::default()
        };
        let geometry =
            prepare_note_profile_with_fixed_v1(&adapter, false).expect("fixed-free geometry");
        assert!(geometry.fixed_columns.is_empty());
        for bytes in [vec![], b"PMN1".to_vec(), vec![0; 32]] {
            assert_eq!(
                verify_proof_managed_note_stark_v1(&adapter, &bytes),
                Err(ProofManagedNoteStarkErrorV1::ProofWire)
            );
        }
    }

    #[test]
    fn authenticated_proof_still_rejects_invalid_fixed_copy_schedule() {
        let (adapter, _, proof) = proof_fixture_v1();
        let invalid = MockAdapterV1 {
            corrupt_schedule: true,
            ..adapter.clone()
        };
        assert_eq!(
            verify_proof_managed_note_stark_v1(&invalid, proof),
            Err(ProofManagedNoteStarkErrorV1::Copy)
        );
    }

    #[test]
    fn privacy_rejects_invalid_merkle_opening_before_fixed_trace_allocation() {
        let (adapter, _, proof) = proof_fixture_v1();
        let prepared = prepare_note_profile_with_fixed_v1(adapter, false).expect("geometry");
        let (mut changed, deep) = aggregate::decode_proof_with_deep_v1(
            proof,
            prepared.protocol.parameters,
            &prepared.layout,
        )
        .expect("canonical proof");
        let value = &mut changed.queries[0].trace_groups[0].base_current[0];
        *value = F(*value).add(F::ONE).value();
        let changed = aggregate::encode_proof_with_deep_v1(
            &changed,
            &deep,
            prepared.protocol.parameters,
            &prepared.layout,
        )
        .expect("same transcript and canonical shape, substituted opening");
        let guarded = MockAdapterV1 {
            reject_fixed_materialization: true,
            ..adapter.clone()
        };
        assert_eq!(
            verify_proof_managed_note_stark_v1(&guarded, &changed),
            Err(ProofManagedNoteStarkErrorV1::TraceOpening)
        );
    }

    #[test]
    fn column_stage_orchestration_is_identical_across_rayon_widths() {
        // One more than the source-fixed resident-column bound forces two canonical dispatches.
        // TODO: add whole-proof fixed-RNG byte equality to the slow release suite; repeating the
        // protocol-mandated 20-bit SHA3-384 grind is intentionally outside this unit test.
        assert_eq!(aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1, 8);
        let columns = (0..=aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .map(|column| {
                (0..8)
                    .map(|row| {
                        F::reduce(
                            u128::try_from(column + 3).expect("small column")
                                * u128::try_from(row + 11).expect("small row"),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let run = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("private test thread pool")
                .install(|| {
                    let mut rng = StdRng::from_seed([0x9B; 32]);
                    let (masked, masks) = masked_lde_columns_v1(&columns, 3, 10, &mut rng)
                        .expect("masked LDE columns");
                    let fixed = fixed_lde_columns_v1(&columns, 3, 10).expect("fixed LDE columns");
                    let deep = evaluate_masked_native_columns_at_deep_v1(
                        &columns,
                        &masks,
                        3,
                        E::from_base(F(19)),
                    )
                    .expect("deep column openings");
                    let mask_coefficients = masks
                        .iter()
                        .map(|mask| mask.coefficients().to_vec())
                        .collect::<Vec<_>>();
                    (masked, fixed, deep, mask_coefficients)
                })
        };
        assert_eq!(run(1), run(4));

        let mut rejected_rng = StdRng::from_seed([0xC7; 32]);
        let mut untouched_rng = rejected_rng.clone();
        let malformed = vec![vec![F::ZERO; 7]];
        assert!(matches!(
            masked_lde_columns_v1(&malformed, 3, 10, &mut rejected_rng),
            Err(ProofManagedNoteStarkErrorV1::Internal)
        ));
        assert_eq!(
            rejected_rng.next_u64(),
            untouched_rng.next_u64(),
            "semantic transform rejection must happen before mask sampling"
        );
    }

    #[test]
    fn fixed_lde_in_place_matches_allocating_reference_and_secret_owners_wipe() {
        let columns = (0..=aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .map(|column| {
                (0..8)
                    .map(|row| {
                        F::reduce(
                            u128::try_from(column + 5).expect("small column")
                                * u128::try_from(row + 13).expect("small row"),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let actual = fixed_lde_columns_v1(&columns, 3, 10).expect("in-place fixed LDE");
        let trace_root = goldilocks_primitive_root_v1(3).expect("trace root");
        let lde_root = goldilocks_primitive_root_v1(10).expect("LDE root");
        let expected = columns
            .iter()
            .map(|column| {
                let mut coefficients = column.clone();
                goldilocks_ifft_v1(&mut coefficients, trace_root).expect("reference IFFT");
                coefficients.resize(1 << 10, F::ZERO);
                super::super::transparent_stark::goldilocks_evaluate_coset_v1(
                    &coefficients,
                    1 << 10,
                    lde_root,
                    F(GOLDILOCKS_GENERATOR_V1),
                )
                .expect("allocating fixed-LDE reference")
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);

        let mut base_values = ZeroizingBaseFieldValuesV1::from(vec![F::ONE; 3]);
        base_values.zeroize_v1();
        assert!(base_values.iter().all(|value| *value == F::ZERO));
        let mut base_matrix = ZeroizingBaseFieldMatrixV1::from(vec![vec![F::ONE; 3]; 2]);
        base_matrix.zeroize_v1();
        assert!(base_matrix.iter().flatten().all(|value| *value == F::ZERO));
        let mut extension_values = ZeroizingExtensionFieldValuesV1::from(vec![E::ONE; 3]);
        extension_values.zeroize_v1();
        assert!(extension_values.iter().all(|value| *value == E::ZERO));
        let mut extension_matrix = ZeroizingExtensionFieldMatrixV1::from(vec![vec![E::ONE; 3]; 2]);
        extension_matrix.zeroize_v1();
        assert!(
            extension_matrix
                .iter()
                .flatten()
                .all(|value| *value == E::ZERO)
        );
        let mut extension_cube =
            ZeroizingExtensionFieldCubeV1::from(vec![vec![vec![E::ONE; 3]; 2]; 2]);
        extension_cube.zeroize_v1();
        assert!(
            extension_cube
                .iter()
                .flatten()
                .flatten()
                .all(|value| *value == E::ZERO)
        );
        let mut extension_row = ZeroizingExtensionFieldRowV1([E::ONE; 3]);
        extension_row.zeroize_v1();
        assert!(extension_row.iter().all(|value| *value == E::ZERO));
        assert!(core::mem::needs_drop::<ZeroizingBaseFieldMatrixV1>());
        assert!(core::mem::needs_drop::<ZeroizingExtensionFieldCubeV1>());
    }

    #[test]
    fn bounded_column_dispatch_preserves_order_and_lowest_error() {
        let column_count = aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1 * 2 + 1;
        let active = std::sync::atomic::AtomicUsize::new(0);
        let peak = std::sync::atomic::AtomicUsize::new(0);
        let ordered = rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build()
            .expect("private test thread pool")
            .install(|| {
                collect_bounded_parallel_columns_v1(column_count, |column| {
                    let resident = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(resident, std::sync::atomic::Ordering::SeqCst);
                    std::thread::yield_now();
                    active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(column)
                })
                .expect("bounded ordered dispatch")
            });
        assert_eq!(ordered, (0..column_count).collect::<Vec<_>>());
        assert!(
            peak.load(std::sync::atomic::Ordering::SeqCst)
                <= aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1,
            "resident column transforms must stay inside the source-fixed bound"
        );

        let later_batch_visited = std::sync::atomic::AtomicBool::new(false);
        let error = rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build()
            .expect("private test thread pool")
            .install(|| {
                collect_bounded_parallel_columns_v1(column_count, |column| {
                    if column >= aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1 {
                        later_batch_visited.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    match column {
                        3 => Err(ProofManagedNoteStarkErrorV1::InvalidTrace),
                        5 => Err(ProofManagedNoteStarkErrorV1::InvalidProfile),
                        _ => Ok(column),
                    }
                })
            });
        assert_eq!(error, Err(ProofManagedNoteStarkErrorV1::InvalidTrace));
        assert!(
            !later_batch_visited.load(std::sync::atomic::Ordering::Relaxed),
            "a failing canonical batch must stop before the next batch is dispatched"
        );

        struct DropProbe {
            dropped: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build()
            .expect("private drop-probe pool");
        let created = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let error = pool.install(|| {
            collect_bounded_parallel_columns_v1(
                aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1,
                |column| {
                    if column == 3 {
                        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
                    }
                    created.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(DropProbe {
                        dropped: std::sync::Arc::clone(&dropped),
                    })
                },
            )
        });
        assert!(matches!(
            error,
            Err(ProofManagedNoteStarkErrorV1::InvalidTrace)
        ));
        assert_eq!(
            created.load(std::sync::atomic::Ordering::SeqCst),
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "every successful sibling output must drop when its batch fails"
        );

        let created = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.install(|| {
                let _ = collect_bounded_parallel_columns_v1(
                    aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1,
                    |column| -> Result<DropProbe, ProofManagedNoteStarkErrorV1> {
                        if column == 3 {
                            panic!("injected transform unwind");
                        }
                        created.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(DropProbe {
                            dropped: std::sync::Arc::clone(&dropped),
                        })
                    },
                );
            });
        }));
        assert!(unwind.is_err());
        assert_eq!(
            created.load(std::sync::atomic::Ordering::SeqCst),
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "every constructed worker output must drop during unwind"
        );
    }

    #[test]
    fn ordered_deep_batches_cover_partial_tail_and_stop_at_earliest_error() {
        let batch = aggregate::DEEP_FRI_BASE_BATCH_ROWS_V1;
        let rows = batch * 2 + 17;
        let mut visited = Vec::new();
        try_for_each_ordered_deep_batch_v1(rows, |start, end| {
            visited.push((start, end));
            Ok(())
        })
        .expect("ordered partial-tail traversal");
        assert_eq!(
            visited,
            vec![(0, batch), (batch, batch * 2), (batch * 2, rows)]
        );

        let mut visited = Vec::new();
        let error = try_for_each_ordered_deep_batch_v1(batch * 3 + 17, |start, end| {
            visited.push((start, end));
            if start == batch {
                Err(ProofManagedNoteStarkErrorV1::Composition)
            } else {
                Ok(())
            }
        });
        assert_eq!(error, Err(ProofManagedNoteStarkErrorV1::Composition));
        assert_eq!(visited, vec![(0, batch), (batch, batch * 2)]);
    }

    #[test]
    fn native_constraint_validation_is_identical_across_rayon_widths() {
        let adapter = MockAdapterV1::default();
        let prepared = prepare_note_profile_v1(&adapter).expect("mock profile");
        let base = mock_base_columns_v1();
        let challenges = NoteCopyChallengesV1 {
            lanes: std::array::from_fn(|lane| NoteCopyLaneChallengesV1 {
                beta: F(u64::try_from(lane + 2).expect("small challenge")),
                gamma: F(u64::try_from(lane + 11).expect("small challenge")),
            }),
        };
        let aux = build_note_copy_aux_columns_v1(
            &base,
            &prepared.fixed_columns,
            challenges,
            prepared.trace_size,
        )
        .expect("mock copy auxiliary columns");
        let run = |threads, candidate: &[Vec<F>]| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("private test thread pool")
                .install(|| {
                    validate_native_constraints_v1(
                        &adapter,
                        &prepared,
                        candidate,
                        &aux,
                        challenges,
                        &(),
                    )
                })
        };
        assert_eq!(run(1, &base), Ok(()));
        assert_eq!(run(4, &base), Ok(()));
        let mut invalid = base;
        invalid[0][0] = F::ONE;
        assert_eq!(
            run(1, &invalid),
            Err(ProofManagedNoteStarkErrorV1::Constraint)
        );
        assert_eq!(
            run(4, &invalid),
            Err(ProofManagedNoteStarkErrorV1::Constraint)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn composition_lanes_are_identical_to_serial_across_rayon_widths() {
        const TRACE_LOG2: u8 = PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1;
        let adapter = MockAdapterV1::default();
        let mut protocol = adapter.protocol_v1();
        protocol.parameters.minimum_trace_log2 = TRACE_LOG2;
        protocol.parameters.maximum_trace_log2 = TRACE_LOG2;
        // This focused quotient-scheduling test does not construct a proof. Widen its terminal
        // degree cap only enough to admit the smaller domain; release-profile geometry remains
        // pinned and is covered separately by the Protocol-2 dimension tests.
        protocol.parameters.terminal_degree_bound = (1_usize << 8) - 1;
        let layout = aggregate::AggregateProofLayoutV1::new(
            protocol.parameters,
            vec![aggregate::AggregateTraceGroupLayoutV1 {
                native_trace_log2: TRACE_LOG2,
                segment_instances: 1,
                base_width: NOTE_COPY_WIDTH_V1,
                aux_width: NOTE_COPY_AUX_WIDTH_V1,
            }],
        )
        .expect("focused composition layout");
        let trace_size = 1_usize << TRACE_LOG2;
        let lde_size = layout.common_lde_size();
        let prepared = PreparedNoteProfileV1 {
            protocol,
            trace_log2: TRACE_LOG2,
            trace_size,
            base_width: NOTE_COPY_WIDTH_V1,
            aux_width: NOTE_COPY_AUX_WIDTH_V1,
            fixed_width: NOTE_COPY_FIXED_WIDTH_V1,
            constraint_count: NOTE_COPY_CONSTRAINT_COUNT_V1 + 1,
            layout,
            fixed_columns: Vec::new(),
        };
        let synthetic_columns = |width: usize, salt: u64| {
            (0..width)
                .map(|column| {
                    (0..lde_size)
                        .map(|row| {
                            F::reduce(
                                u128::from(salt + 1)
                                    * u128::try_from(column + 3).expect("small column")
                                    * u128::try_from(row + 5).expect("small row"),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        let base_lde = synthetic_columns(NOTE_COPY_WIDTH_V1, 11);
        let aux_lde = synthetic_columns(NOTE_COPY_AUX_WIDTH_V1, 17);
        let fixed_lde = synthetic_columns(NOTE_COPY_FIXED_WIDTH_V1, 23);
        let copy_challenges = NoteCopyChallengesV1 {
            lanes: std::array::from_fn(|lane| NoteCopyLaneChallengesV1 {
                beta: F(u64::try_from(lane + 29).expect("small beta")),
                gamma: F(u64::try_from(lane + 41).expect("small gamma")),
            }),
        };
        let alphas = (0..PROOF_MANAGED_NOTE_SECURITY_LANES_V1)
            .map(|lane| {
                (0..prepared.constraint_count)
                    .map(|constraint| {
                        E::from_base(F::reduce(
                            u128::try_from(lane + 2).expect("small lane")
                                * u128::try_from(constraint + 7).expect("small constraint"),
                        ))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let run = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("private test thread pool")
                .install(|| {
                    composition_lanes_v1(
                        &adapter,
                        &prepared,
                        &base_lde,
                        &aux_lde,
                        &fixed_lde,
                        copy_challenges,
                        &(),
                        &alphas,
                    )
                    .expect("parallel composition lanes")
                })
        };

        let lde_root = goldilocks_primitive_root_v1(prepared.layout.common_lde_log2())
            .expect("composition LDE root");
        let next_stride = prepared.layout.trace_groups()[0]
            .next_stride(prepared.layout.common_lde_log2())
            .expect("composition next-row stride");
        let mut serial_lanes = (0..PROOF_MANAGED_NOTE_SECURITY_LANES_V1)
            .map(|_| Vec::with_capacity(lde_size))
            .collect::<Vec<_>>();
        let mut x = F(GOLDILOCKS_GENERATOR_V1);
        for index in 0..lde_size {
            let next = (index + next_stride) % lde_size;
            let residues = all_constraint_residues_v1(
                &adapter,
                &prepared,
                &row_at_columns_v1(&base_lde, index).expect("serial current base"),
                &row_at_columns_v1(&base_lde, next).expect("serial next base"),
                &row_at_columns_v1(&aux_lde, index).expect("serial current auxiliary"),
                &row_at_columns_v1(&aux_lde, next).expect("serial next auxiliary"),
                &row_at_columns_v1(&fixed_lde, index).expect("serial fixed"),
                copy_challenges,
                &(),
            )
            .expect("serial constraint residues");
            let inverse_vanishing = x
                .pow(trace_size as u128)
                .sub(F::ONE)
                .inv()
                .expect("composition coset is disjoint from the trace domain");
            for (lane, values) in serial_lanes.iter_mut().enumerate() {
                let numerator = residues
                    .iter()
                    .zip(&alphas[lane])
                    .fold(E::ZERO, |sum, (residue, alpha)| {
                        sum.add(alpha.mul_base(*residue))
                    });
                values.push(numerator.mul_base(inverse_vanishing));
            }
            x = x.mul(lde_root);
        }
        let serial = serial_lanes
            .iter()
            .map(|lane| {
                aggregate::split_composition_evaluations_v1(
                    lane,
                    prepared.protocol.parameters,
                    &prepared.layout,
                )
                .expect("serial composition split")
            })
            .collect::<Vec<_>>();
        assert_eq!(run(1), serial);
        assert_eq!(run(4), serial);
    }

    fn proof_fixture_v1() -> &'static (MockAdapterV1, Vec<Vec<F>>, Vec<u8>) {
        static FIXTURE: OnceLock<(MockAdapterV1, Vec<Vec<F>>, Vec<u8>)> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let adapter = MockAdapterV1::default();
            let base = mock_base_columns_v1();
            let mut rng = StdRng::from_seed([0xA5; 32]);
            let proof = prove_proof_managed_note_stark_v1_with_rng(&adapter, &base, &mut rng)
                .expect("canonical mock candidate")
                .verify_into_bytes_v1(&adapter)
                .expect("independently verified mock proof");
            (adapter, base, proof)
        })
    }
    struct MaxValueRng;
    impl RngCore for MaxValueRng {
        fn next_u32(&mut self) -> u32 {
            u32::MAX
        }
        fn next_u64(&mut self) -> u64 {
            u64::MAX
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(0xFF);
        }
    }
    #[test]
    fn candidate_debug_exposes_length_without_encoded_bytes() {
        let candidate = ProofManagedNoteCandidateV1 {
            encoded: b"OPAQUE_PROOF_SENTINEL".to_vec(),
        };
        let debug = format!("{candidate:?}");
        assert!(debug.contains("encoded_len: 21"));
        assert!(!debug.contains("OPAQUE_PROOF_SENTINEL"));
        assert!(!debug.contains("79, 80, 65, 81"));
    }
    #[test]
    fn candidate_releases_bytes_only_after_one_complete_public_input_verification() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let (adapter, _, bytes) = proof_fixture_v1();
        let reads = Arc::new(AtomicUsize::new(0));
        let mut public_adapter = adapter.clone();
        public_adapter.public_input_reads = Some(reads.clone());
        let candidate = ProofManagedNoteCandidateV1 {
            encoded: bytes.clone(),
        };
        let verified = candidate
            .verify_into_bytes_v1(&public_adapter)
            .expect("valid candidate releases bytes");
        assert_eq!(&verified, bytes);
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        let mut corrupted = bytes.clone();
        corrupted[0] ^= 1;
        assert!(
            ProofManagedNoteCandidateV1 { encoded: corrupted }
                .verify_into_bytes_v1(&public_adapter)
                .is_err()
        );
        public_adapter.public_digest = PrivacyOuterDigestV1::from_bytes([0x25; 48]);
        assert!(
            ProofManagedNoteCandidateV1 {
                encoded: bytes.clone()
            }
            .verify_into_bytes_v1(&public_adapter)
            .is_err()
        );
    }
    #[test]
    fn shared_geometry_descriptor_and_digest_match_every_driver_constant() {
        let expected = format!(
            "proof-managed-note-stark-geometry-v1:proof={}:base-field=goldilocks:challenge-field=goldilocks-fp4:merkle=sha3-384:transcript=sha3-384:copy-width={}:copy-lanes={}:copy-aux-width={}:copy-fixed-width={}:copy-constraints={}:copy-constraint-degree={}:security-lanes={}:queries={}:lde-blowup={}:composition-degree-chunks={}:deep-points={}:deep-openings=base-current,base-next,aux-current,aux-next,composition:deep-mixes=independent:max-native-trace-log2={}:trace-mask-degree={}:trace-mask-coefficients={}:max-constraint-degree={}:fri-terminal={}:fri-degree={}:fri-input=deep-ali:fri-theorem=affine-batched-theorem2:affine-batching-coefficient=3/2:batching-m={}:rho-upper-bound={}/{}:binary-fold-arity={}:extension-field-lower-bound-bits={}:query-error-bits={}:fri-algebraic-commitment-error-bits-min={}:target-soundness-bits={}:grinding={}-nonadditive:frame=privacy-sha3-384-be-v1:scalar-fp4=bounded-be-u64-rejection:query-source=2^64:codec=fixed-public-profile-length-opaque-digest48-canonical-be-fields:frontiers=canonical-minimal:padding=required-zero-tail-to-maximum-encoded-proof-with-deep-v1",
            std::str::from_utf8(PROOF_MANAGED_NOTE_STARK_SUITE_V1).expect("ASCII suite"),
            NOTE_COPY_WIDTH_V1,
            NOTE_COPY_LANES_V1,
            NOTE_COPY_AUX_WIDTH_V1,
            NOTE_COPY_FIXED_WIDTH_V1,
            NOTE_COPY_CONSTRAINT_COUNT_V1,
            NOTE_COPY_CONSTRAINT_DEGREE_V1,
            PROOF_MANAGED_NOTE_SECURITY_LANES_V1,
            PROOF_MANAGED_NOTE_QUERY_COUNT_V1,
            1_usize << PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1,
            PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1,
            PROOF_MANAGED_NOTE_DEEP_QUERY_COUNT_V1,
            PROOF_MANAGED_NOTE_MAX_NATIVE_TRACE_LOG2_V1,
            PROOF_MANAGED_NOTE_MASK_DEGREE_V1,
            PROOF_MANAGED_NOTE_MASK_DEGREE_V1 + 1,
            PROOF_MANAGED_NOTE_MAX_CONSTRAINT_DEGREE_V1,
            1_usize << PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1,
            PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1,
            PROOF_MANAGED_NOTE_FRI_BATCHING_PARAMETER_M_V1,
            PROOF_MANAGED_NOTE_FRI_RATE_NUMERATOR_V1,
            PROOF_MANAGED_NOTE_FRI_RATE_DENOMINATOR_V1,
            PROOF_MANAGED_NOTE_FRI_BINARY_FOLD_ARITY_V1,
            PROOF_MANAGED_NOTE_EXTENSION_FIELD_LOWER_BOUND_BITS_V1,
            PROOF_MANAGED_NOTE_FRI_QUERY_ERROR_BITS_V1,
            PROOF_MANAGED_NOTE_FRI_COMMITMENT_ERROR_BITS_MIN_V1,
            PROOF_MANAGED_NOTE_TARGET_SOUNDNESS_BITS_V1,
            PROOF_MANAGED_NOTE_GRINDING_BITS_V1,
        );
        assert_eq!(
            PROOF_MANAGED_NOTE_STARK_GEOMETRY_DESCRIPTOR_V1,
            expected.as_bytes()
        );
        let digest = proof_managed_note_stark_profile_digest_v1(
            &MOCK_DOMAINS_V1,
            MOCK_PROFILE_DESCRIPTOR_V1,
        )
        .expect("profile digest");
        assert_eq!(
            digest,
            proof_managed_note_stark_profile_digest_v1(
                &MOCK_DOMAINS_V1,
                MOCK_PROFILE_DESCRIPTOR_V1,
            )
            .expect("replayed profile digest"),
        );
    }
    #[test]
    fn affine_batched_fri_certificate_meets_the_release_soundness_floor() {
        let mock_bound =
            validate_note_fri_soundness_v1(mock_parameters_v1()).expect("mock soundness");
        assert_eq!(
            mock_bound,
            aggregate::AggregateFriTheorem2BoundV1 {
                query_error_bits: PROOF_MANAGED_NOTE_FRI_QUERY_ERROR_BITS_V1,
                commitment_error_bits: 199,
            }
        );
        let mut maximum_release_parameters = mock_parameters_v1();
        maximum_release_parameters.minimum_trace_log2 = PROOF_MANAGED_NOTE_MAX_NATIVE_TRACE_LOG2_V1;
        maximum_release_parameters.maximum_trace_log2 = PROOF_MANAGED_NOTE_MAX_NATIVE_TRACE_LOG2_V1;
        assert_eq!(
            validate_note_fri_soundness_v1(maximum_release_parameters)
                .expect("maximum release soundness"),
            aggregate::AggregateFriTheorem2BoundV1 {
                query_error_bits: PROOF_MANAGED_NOTE_FRI_QUERY_ERROR_BITS_V1,
                commitment_error_bits: PROOF_MANAGED_NOTE_FRI_COMMITMENT_ERROR_BITS_MIN_V1,
            }
        );
    }
    #[test]
    fn materialized_deep_codeword_matches_the_opened_row_verifier() {
        // Use a smaller native domain with a test-only terminal bound that
        // still satisfies the Protocol-2 FRI-mask inequality. The production
        // parameter certificate is exercised separately; this test isolates
        // the DEEP materialization/opening differential.
        const DIFFERENTIAL_TRACE_LOG2_V1: u8 = 9;
        let mut parameters = mock_parameters_v1();
        parameters.minimum_trace_log2 = DIFFERENTIAL_TRACE_LOG2_V1;
        parameters.maximum_trace_log2 = DIFFERENTIAL_TRACE_LOG2_V1;
        parameters.terminal_degree_bound = 255;
        parameters.maximum_base_columns_per_instance = 2;
        parameters.maximum_aux_columns_per_instance = 1;
        let layout = aggregate::AggregateProofLayoutV1::new(
            parameters,
            vec![aggregate::AggregateTraceGroupLayoutV1 {
                native_trace_log2: DIFFERENTIAL_TRACE_LOG2_V1,
                segment_instances: 1,
                base_width: 2,
                aux_width: 1,
            }],
        )
        .expect("small DEEP layout");
        let rows = layout.common_lde_size();
        let base_lde = vec![
            (0..rows)
                .map(|index| F(u64::try_from(index + 3).expect("small row")))
                .collect::<Vec<_>>(),
            (0..rows)
                .map(|index| F(u64::try_from(index * 7 + 11).expect("small affine evaluation")))
                .collect::<Vec<_>>(),
        ];
        let aux_lde = vec![
            (0..rows)
                .map(|index| F(u64::try_from(index * 13 + 17).expect("small affine evaluation")))
                .collect::<Vec<_>>(),
        ];
        let compositions = vec![
            (0..parameters.composition_degree_chunks)
                .map(|chunk| {
                    (0..rows)
                        .map(|index| {
                            E::from_base(F(u64::try_from(index * (chunk + 3) + chunk + 19)
                                .expect("small composition evaluation")))
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        ];
        let base_tree = aggregate::row_tree_v1(
            MOCK_DOMAINS_V1.digest_context,
            MOCK_DOMAINS_V1.base_leaf,
            MOCK_DOMAINS_V1.base_node,
            0,
            &base_lde,
            rows,
        )
        .expect("base tree");
        let aux_tree = aggregate::row_tree_v1(
            MOCK_DOMAINS_V1.digest_context,
            MOCK_DOMAINS_V1.aux_leaf,
            MOCK_DOMAINS_V1.aux_node,
            0,
            &aux_lde,
            rows,
        )
        .expect("aux tree");
        let materials = vec![aggregate::AggregateTraceGroupMaterialV1 {
            base_lde,
            aux_lde,
            base_tree,
            aux_tree,
        }];
        let deep_point = E::canonical([2, 3, 5, 7]).expect("canonical nonzero DEEP point");
        assert!(
            aggregate::deep_point_is_admissible_v1(deep_point, parameters, &layout)
                .expect("DEEP admissibility")
        );
        let deep = aggregate::build_materialized_deep_proof_v1(
            &materials,
            &compositions,
            parameters,
            &layout,
            deep_point,
        )
        .expect("materialized DEEP proof");
        let mix = aggregate::AggregateDeepLaneMixV1 {
            trace_groups: vec![aggregate::AggregateDeepTraceGroupMixV1 {
                base_current: vec![
                    E::canonical([23, 71, 73, 79]).unwrap(),
                    E::canonical([29, 83, 89, 97]).unwrap(),
                ],
                base_next: vec![
                    E::canonical([31, 101, 103, 107]).unwrap(),
                    E::canonical([37, 109, 113, 127]).unwrap(),
                ],
                aux_current: vec![E::canonical([41, 131, 137, 139]).unwrap()],
                aux_next: vec![E::canonical([43, 149, 151, 157]).unwrap()],
            }],
            composition: vec![
                E::canonical([47, 64, 78, 90]).unwrap(),
                E::canonical([53, 70, 84, 96]).unwrap(),
                E::canonical([59, 76, 90, 102]).unwrap(),
                E::canonical([61, 78, 92, 104]).unwrap(),
            ],
        };
        aggregate::validate_deep_lane_mixes_v1(core::slice::from_ref(&mix), parameters, &layout)
            .expect("DEEP mix");
        let build_codeword = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("private test thread pool")
                .install(|| {
                    mixed_deep_fri_base_v1(
                        &materials[0].base_lde,
                        &materials[0].aux_lde,
                        &compositions[0],
                        &deep,
                        deep_point,
                        &mix,
                        0,
                        parameters,
                        &layout,
                    )
                    .expect("DEEP codeword")
                })
        };
        let codeword = build_codeword(1);
        assert_eq!(codeword, build_codeword(4));
        assert_eq!(codeword, build_codeword(8));
        let deep_trace = aggregate::canonical_deep_trace_groups_v1(&deep, parameters, &layout)
            .expect("canonical DEEP trace");
        let deep_composition = aggregate::canonical_fp4_fields_v1(
            &deep.composition_values[0],
            parameters.composition_degree_chunks,
        )
        .expect("canonical DEEP composition");
        let stride = layout.trace_groups()[0]
            .next_stride(layout.common_lde_log2())
            .expect("next stride");
        let lde_root = goldilocks_primitive_root_v1(layout.common_lde_log2()).expect("LDE root");
        for index in 0..rows {
            let next = (index + stride) % rows;
            let opened = aggregate::AggregateOpenedTraceGroupV1 {
                base_current: row_at_columns_v1(&materials[0].base_lde, index)
                    .expect("base current"),
                base_next: row_at_columns_v1(&materials[0].base_lde, next).expect("base next"),
                aux_current: row_at_columns_v1(&materials[0].aux_lde, index).expect("aux current"),
                aux_next: row_at_columns_v1(&materials[0].aux_lde, next).expect("aux next"),
            };
            let composition_at_index = compositions[0]
                .iter()
                .map(|chunk| chunk[index])
                .collect::<Vec<_>>();
            let query_point =
                E::from_base(F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(index as u128)));
            let expected = aggregate::deep_ali_mixed_opening_v1(
                query_point,
                deep_point,
                &layout,
                core::slice::from_ref(&opened),
                &deep_trace,
                &composition_at_index,
                &deep_composition,
                &mix,
            )
            .expect("opened-row DEEP quotient");
            assert_eq!(codeword[index], expected, "row {index}");
        }
    }
    #[test]
    fn replayed_native_masks_match_materialized_lde_at_both_deep_points() {
        // Match the valid, bounded differential geometry used immediately
        // above so mask replay is tested without a production-sized fixture.
        const MASK_DIFFERENTIAL_TRACE_LOG2_V1: u8 = 9;
        let trace_log2 = MASK_DIFFERENTIAL_TRACE_LOG2_V1;
        let lde_log2 = trace_log2 + PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1;
        let trace_size = 1_usize << trace_log2;
        let columns = vec![
            (0..trace_size)
                .map(|index| F(u64::try_from(index * 5 + 7).expect("small native trace")))
                .collect::<Vec<_>>(),
            (0..trace_size)
                .map(|index| F(u64::try_from(index * 11 + 13).expect("small native trace")))
                .collect::<Vec<_>>(),
        ];
        let mut rng = StdRng::from_seed([0xD4; 32]);
        let (lde, masks) =
            masked_lde_columns_v1(&columns, trace_log2, lde_log2, &mut rng).expect("masked LDE");
        let deep_point = E::canonical([7, 3, 1, 0]).expect("canonical extension-field DEEP point");
        let mut parameters = mock_parameters_v1();
        parameters.minimum_trace_log2 = trace_log2;
        parameters.maximum_trace_log2 = trace_log2;
        parameters.terminal_degree_bound = 255;
        parameters.maximum_base_columns_per_instance = columns.len();
        parameters.maximum_aux_columns_per_instance = 1;
        let layout = aggregate::AggregateProofLayoutV1::new(
            parameters,
            vec![aggregate::AggregateTraceGroupLayoutV1 {
                native_trace_log2: trace_log2,
                segment_instances: 1,
                base_width: columns.len(),
                aux_width: 1,
            }],
        )
        .expect("mask differential layout");
        assert!(
            aggregate::deep_point_is_admissible_v1(deep_point, parameters, &layout)
                .expect("DEEP admissibility")
        );
        let (current, next) =
            evaluate_masked_native_columns_at_deep_v1(&columns, &masks, trace_log2, deep_point)
                .expect("replayed native masks");
        let native_root = goldilocks_primitive_root_v1(trace_log2).expect("native root");
        let next_point = deep_point.mul_base(native_root);
        for (column_index, codeword) in lde.iter().enumerate() {
            let materialized = aggregate::evaluate_base_coset_polynomial_at_fp4_points_v1(
                codeword,
                lde_log2,
                &[deep_point, next_point],
            )
            .expect("materialized LDE interpolation");
            assert_eq!(current[column_index], materialized[0]);
            assert_eq!(next[column_index], materialized[1]);
        }
    }
    #[test]
    fn copy_schedule_and_residues_are_exact() {
        let adapter = MockAdapterV1::default();
        let prepared = prepare_note_profile_v1(&adapter).expect("profile");
        let mut transcript =
            new_note_transcript_v1(&prepared, &adapter.public_digest).expect("transcript");
        let dummy_groups = [aggregate::AggregateTraceGroupProofV1 {
            base_root: PrivacyOuterDigestV1::from_bytes([7; 48]),
            aux_root: PrivacyOuterDigestV1::default(),
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        }];
        aggregate::absorb_base_roots_v1(&mut transcript, &prepared.protocol.domains, &dummy_groups)
            .expect("base root");
        let challenges = derive_note_copy_challenges_v1(&mut transcript).expect("challenges");
        assert_eq!(challenges.lanes.len(), NOTE_COPY_LANES_V1);
        assert_ne!(challenges.lanes[0], challenges.lanes[1]);
        let base = mock_base_columns_v1();
        let aux = build_note_copy_aux_columns_v1(
            &base,
            &prepared.fixed_columns,
            challenges,
            prepared.trace_size,
        )
        .expect("copy aux");
        for row in 0..prepared.trace_size {
            let next = (row + 1) % prepared.trace_size;
            let residues = note_copy_constraint_residues_v1(
                &row_at_columns_v1(&base, row).expect("base row"),
                &row_at_columns_v1(&aux, row).expect("aux row"),
                &row_at_columns_v1(&aux, next).expect("next aux row"),
                &row_at_columns_v1(&prepared.fixed_columns, row).expect("fixed row"),
                challenges,
            )
            .expect("residues");
            assert_eq!(residues.len(), NOTE_COPY_CONSTRAINT_COUNT_V1);
            assert!(residues.iter().all(|value| *value == F::ZERO));
        }
        let mut changed_aux = aux.clone();
        changed_aux[0][3] = changed_aux[0][3].add(F::ONE);
        let residues = note_copy_constraint_residues_v1(
            &row_at_columns_v1(&base, 3).expect("base row"),
            &row_at_columns_v1(&changed_aux, 3).expect("aux row"),
            &row_at_columns_v1(&changed_aux, 4).expect("next aux row"),
            &row_at_columns_v1(&prepared.fixed_columns, 3).expect("fixed row"),
            challenges,
        )
        .expect("mutated residues");
        assert!(residues.iter().any(|value| *value != F::ZERO));
    }
    #[test]
    fn copy_dual_products_are_total_at_zero_factors_and_reject_a_bad_multiset() {
        let adapter = MockAdapterV1::default();
        let prepared = prepare_note_profile_v1(&adapter).expect("profile");
        let base = mock_base_columns_v1();
        let beta = F(3);
        let identity = prepared.fixed_columns[COPY_FIXED_IDENTITY_OFFSET][0];
        let collision = NoteCopyChallengesV1 {
            lanes: [
                NoteCopyLaneChallengesV1 {
                    beta,
                    gamma: F::ZERO.sub(base[0][0].add(beta.mul(identity))),
                },
                NoteCopyLaneChallengesV1 {
                    beta: F(7),
                    gamma: F(11),
                },
                NoteCopyLaneChallengesV1 {
                    beta: F(13),
                    gamma: F(17),
                },
            ],
        };
        let aux = build_note_copy_aux_columns_v1(
            &base,
            &prepared.fixed_columns,
            collision,
            prepared.trace_size,
        )
        .expect("a zero product factor must not make the honest prover abort");
        for row in 0..prepared.trace_size {
            let next = (row + 1) % prepared.trace_size;
            let residues = note_copy_constraint_residues_v1(
                &row_at_columns_v1(&base, row).expect("base row"),
                &row_at_columns_v1(&aux, row).expect("aux row"),
                &row_at_columns_v1(&aux, next).expect("next aux row"),
                &row_at_columns_v1(&prepared.fixed_columns, row).expect("fixed row"),
                collision,
            )
            .expect("residues");
            assert!(residues.iter().all(|value| *value == F::ZERO));
        }
        let mut malformed_fixed = prepared.fixed_columns.clone();
        let zero_denominator_row = prepared.trace_size - 1;
        malformed_fixed[COPY_FIXED_SIGMA_OFFSET][zero_denominator_row] =
            malformed_fixed[COPY_FIXED_SIGMA_OFFSET][zero_denominator_row].add(F::ONE);
        assert_eq!(
            build_note_copy_aux_columns_v1(&base, &malformed_fixed, collision, prepared.trace_size,),
            Err(ProofManagedNoteStarkErrorV1::Copy),
        );
    }
    #[test]
    fn copy_chip_declared_degree_matches_affine_finite_differences() {
        let challenges = NoteCopyChallengesV1 {
            lanes: [
                NoteCopyLaneChallengesV1 {
                    beta: F(3),
                    gamma: F(5),
                },
                NoteCopyLaneChallengesV1 {
                    beta: F(7),
                    gamma: F(11),
                },
                NoteCopyLaneChallengesV1 {
                    beta: F(13),
                    gamma: F(17),
                },
            ],
        };
        let measured = degree_audit::measured_maximum_affine_degree_v1(
            [0xC2; 32],
            [
                NOTE_COPY_WIDTH_V1,
                NOTE_COPY_WIDTH_V1,
                NOTE_COPY_AUX_WIDTH_V1,
                NOTE_COPY_AUX_WIDTH_V1,
                NOTE_COPY_FIXED_WIDTH_V1,
            ],
            21,
            NOTE_COPY_CONSTRAINT_DEGREE_V1,
            |current_base, _next_base, current_aux, next_aux, fixed| {
                note_copy_constraint_residues_v1(
                    current_base,
                    current_aux,
                    next_aux,
                    fixed,
                    challenges,
                )
            },
        );
        assert_eq!(
            measured,
            usize::from(NOTE_COPY_CONSTRAINT_DEGREE_V1),
            "the shared copy chip's declared maximum degree must be exact"
        );
    }
    #[test]
    fn malformed_schedules_and_non_bytes_fail_closed() {
        let mut duplicate = MockAdapterV1::default();
        duplicate.corrupt_schedule = true;
        assert!(matches!(
            prepare_note_profile_v1(&duplicate),
            Err(ProofManagedNoteStarkErrorV1::Copy)
        ));
        let adapter = MockAdapterV1::default();
        let prepared = prepare_note_profile_v1(&adapter).expect("profile");
        let mut transcript =
            new_note_transcript_v1(&prepared, &adapter.public_digest).expect("transcript");
        let groups = [aggregate::AggregateTraceGroupProofV1 {
            base_root: PrivacyOuterDigestV1::from_bytes([9; 48]),
            aux_root: PrivacyOuterDigestV1::default(),
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        }];
        aggregate::absorb_base_roots_v1(&mut transcript, &prepared.protocol.domains, &groups)
            .expect("base root");
        let challenges = derive_note_copy_challenges_v1(&mut transcript).expect("challenges");
        let mut non_byte = mock_base_columns_v1();
        non_byte[2][7] = F(256);
        assert!(matches!(
            build_note_copy_aux_columns_v1(
                &non_byte,
                &prepared.fixed_columns,
                challenges,
                prepared.trace_size,
            ),
            Err(ProofManagedNoteStarkErrorV1::Copy)
        ));
    }
    #[test]
    fn canonical_proof_roundtrips_and_is_statement_bound() {
        let (adapter, _base, proof) = proof_fixture_v1();
        verify_proof_managed_note_stark_v1(adapter, proof).expect("canonical proof verifies");
        assert_eq!(&proof[..4], b"PMN1");
        assert!(proof.len() < adapter.parameters.maximum_proof_bytes);
        let digest = privacy_outer_digest_frame_v1(
            MOCK_DOMAINS_V1.digest_context,
            b"proof-managed-note-test-proof",
            b"complete-wire",
            0,
            0,
            0,
            &[proof],
        )
        .expect("proof digest");
        assert_ne!(digest, PrivacyOuterDigestV1::default());
        let mut wrong_public = adapter.clone();
        let mut wrong_public_words = wrong_public.public_digest.to_bytes();
        wrong_public_words[0] ^= 1;
        wrong_public.public_digest = PrivacyOuterDigestV1::from_bytes(wrong_public_words);
        assert!(verify_proof_managed_note_stark_v1(&wrong_public, proof).is_err());
    }
    #[test]
    fn exact_wire_and_committed_values_reject_adversarial_mutations() {
        use crate::privacy_engines::privacy_outer_hash::PRIVACY_OUTER_DIGEST_BYTES_V1;

        let (adapter, _base, proof) = proof_fixture_v1();
        assert!(verify_proof_managed_note_stark_v1(adapter, &[]).is_err());
        for length in [1, 4, 7, proof.len() / 4, proof.len() / 2, proof.len() - 1] {
            assert!(verify_proof_managed_note_stark_v1(adapter, &proof[..length]).is_err());
        }
        let mut trailing = proof.to_vec();
        trailing.push(0);
        assert!(verify_proof_managed_note_stark_v1(adapter, &trailing).is_err());
        let header_bytes = 8;
        let digest_bytes = PRIVACY_OUTER_DIGEST_BYTES_V1;
        // The header is followed by base/aux roots and composition/mask roots.
        // Opaque SHA3 digests have no Goldilocks canonical-field restriction.
        for offset in [0_usize, 4, 6].into_iter().chain(
            (0..2 + 2 * PROOF_MANAGED_NOTE_SECURITY_LANES_V1)
                .map(|root| header_bytes + root * digest_bytes),
        ) {
            let mut changed = proof.to_vec();
            changed[offset] ^= 1;
            assert!(
                verify_proof_managed_note_stark_v1(adapter, &changed).is_err(),
                "offset {offset} must be bound"
            );
        }
        let parameters = mock_parameters_v1();
        let layout = aggregate::AggregateProofLayoutV1::new(
            parameters,
            vec![aggregate::AggregateTraceGroupLayoutV1 {
                native_trace_log2: MOCK_TRACE_LOG2_V1,
                segment_instances: 1,
                base_width: NOTE_COPY_WIDTH_V1,
                aux_width: NOTE_COPY_AUX_WIDTH_V1,
            }],
        )
        .expect("mock layout");
        let fri_rounds = layout.fri_rounds(parameters).expect("FRI rounds");
        let deep_insertion =
            header_bytes + (2 + PROOF_MANAGED_NOTE_SECURITY_LANES_V1 * 2) * digest_bytes;
        let deep_bytes =
            aggregate::exact_deep_opening_bytes_v1(parameters, &layout).expect("DEEP byte length");
        let deep_end = deep_insertion + deep_bytes;
        let (decoded, deep) =
            aggregate::decode_proof_with_deep_v1(proof, parameters, &layout).expect("DEEP proof");
        assert_eq!(
            aggregate::encode_proof_with_deep_v1(&decoded, &deep, parameters, &layout)
                .expect("canonical DEEP re-encoding"),
            proof.to_vec()
        );
        assert!(
            aggregate::decode_proof_v1(proof, parameters, &layout).is_err(),
            "the non-DEEP codec must not reinterpret a release proof"
        );
        let mut omitted_deep = proof.to_vec();
        omitted_deep.drain(deep_insertion..deep_end);
        assert!(verify_proof_managed_note_stark_v1(adapter, &omitted_deep).is_err());
        let mut duplicated_deep = proof.to_vec();
        duplicated_deep.splice(
            deep_end..deep_end,
            proof[deep_insertion..deep_end].iter().copied(),
        );
        assert!(verify_proof_managed_note_stark_v1(adapter, &duplicated_deep).is_err());
        let extension_bytes = core::mem::size_of::<[u64; 4]>();
        let deep_region_offsets = [
            ("base-current", deep_insertion),
            (
                "base-next",
                deep_insertion + NOTE_COPY_WIDTH_V1 * extension_bytes,
            ),
            (
                "aux-current",
                deep_insertion + 2 * NOTE_COPY_WIDTH_V1 * extension_bytes,
            ),
            (
                "aux-next",
                deep_insertion
                    + (2 * NOTE_COPY_WIDTH_V1 + NOTE_COPY_AUX_WIDTH_V1) * extension_bytes,
            ),
            (
                "composition",
                deep_insertion
                    + 2 * (NOTE_COPY_WIDTH_V1 + NOTE_COPY_AUX_WIDTH_V1) * extension_bytes,
            ),
        ];
        for (label, offset) in deep_region_offsets {
            let mut changed = proof.to_vec();
            changed[offset + extension_bytes - 1] ^= 1;
            assert!(
                verify_proof_managed_note_stark_v1(adapter, &changed).is_err(),
                "mutated DEEP {label} opening must be rejected"
            );
            for invalid in [
                super::super::transparent_stark::GOLDILOCKS_MODULUS_V1,
                u64::MAX,
            ] {
                for coefficient in 0..4 {
                    let mut noncanonical = proof.to_vec();
                    let start = offset + coefficient * core::mem::size_of::<u64>();
                    noncanonical[start..start + 8].copy_from_slice(&invalid.to_be_bytes());
                    assert!(
                        matches!(
                            verify_proof_managed_note_stark_v1(adapter, &noncanonical),
                            Err(ProofManagedNoteStarkErrorV1::ProofWire)
                        ),
                        "noncanonical DEEP {label} coefficient {coefficient} must fail decoding"
                    );
                }
            }
        }
        let mut reordered_deep = proof.to_vec();
        let first_current =
            reordered_deep[deep_insertion..deep_insertion + extension_bytes].to_vec();
        let first_next = reordered_deep[deep_insertion + NOTE_COPY_WIDTH_V1 * extension_bytes
            ..deep_insertion + (NOTE_COPY_WIDTH_V1 + 1) * extension_bytes]
            .to_vec();
        reordered_deep[deep_insertion..deep_insertion + extension_bytes]
            .copy_from_slice(&first_next);
        reordered_deep[deep_insertion + NOTE_COPY_WIDTH_V1 * extension_bytes
            ..deep_insertion + (NOTE_COPY_WIDTH_V1 + 1) * extension_bytes]
            .copy_from_slice(&first_current);
        assert!(verify_proof_managed_note_stark_v1(adapter, &reordered_deep).is_err());
        let first_terminal =
            deep_end + PROOF_MANAGED_NOTE_SECURITY_LANES_V1 * (fri_rounds + 1) * digest_bytes;
        let mut noncanonical = proof.to_vec();
        noncanonical[first_terminal..first_terminal + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            verify_proof_managed_note_stark_v1(adapter, &noncanonical),
            Err(ProofManagedNoteStarkErrorV1::ProofWire)
        ));
        let grinding = first_terminal
            + PROOF_MANAGED_NOTE_SECURITY_LANES_V1
                * (1 << PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1)
                * core::mem::size_of::<[u64; 4]>();
        let mut wrong_nonce = proof.to_vec();
        wrong_nonce[grinding + 7] ^= 1;
        assert!(verify_proof_managed_note_stark_v1(adapter, &wrong_nonce).is_err());
    }

    #[test]
    fn phase_diagnostics_close_real_profile_entropy_and_constraint_failures() {
        use crate::privacy_engines::proof_phase_diagnostics::test_support::CaptureV1;
        let adapter = MockAdapterV1::default();
        let base = mock_base_columns_v1();
        let capture = CaptureV1::new(false, true);
        let mut invalid = adapter.clone();
        invalid.parameters.query_count -= 1;
        let result = capture.with_default(|| {
            prove_proof_managed_note_stark_v1_with_rng(
                &invalid,
                &base,
                &mut StdRng::from_seed([0xD1; 32]),
            )
        });
        assert!(matches!(
            result,
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
        capture.assert_note_prefix(1, "failed", 0);

        let capture = CaptureV1::new(false, true);
        let result = capture.with_default(|| {
            prove_proof_managed_note_stark_v1_with_rng(&adapter, &base, &mut MaxValueRng)
        });
        assert!(matches!(
            result,
            Err(ProofManagedNoteStarkErrorV1::Randomness)
        ));
        capture.assert_note_prefix(2, "failed", 0);

        // Change the entire first column to preserve its copy multiset while violating
        // the mock profile's first-cell constraint. This reaches native validation.
        let mut invalid_base = base;
        invalid_base[0].fill(F::ONE);
        let capture = CaptureV1::new(false, true);
        let result = capture.with_default(|| {
            prove_proof_managed_note_stark_v1_with_rng(
                &adapter,
                &invalid_base,
                &mut StdRng::from_seed([0xD1; 32]),
            )
        });
        assert!(matches!(
            result,
            Err(ProofManagedNoteStarkErrorV1::Constraint)
        ));
        capture.assert_note_prefix(5, "failed", 0);
    }

    #[test]
    #[ignore = "two full canonical grinds require the owned release prover slot"]
    fn phase_diagnostics_preserve_seeded_candidate_bytes_and_rng_position() {
        use crate::privacy_engines::proof_phase_diagnostics::test_support::CaptureV1;
        let adapter = MockAdapterV1::default();
        let base = mock_base_columns_v1();
        let mut disabled_rng = StdRng::from_seed([0xA5; 32]);
        let mut enabled_rng = StdRng::from_seed([0xA5; 32]);
        let disabled = CaptureV1::new(false, false);
        let baseline = disabled
            .with_default(|| {
                prove_proof_managed_note_stark_v1_with_rng(&adapter, &base, &mut disabled_rng)
            })
            .expect("uninstrumented canonical candidate")
            .verify_into_bytes_v1(&adapter)
            .expect("independent baseline verification");
        let enabled = CaptureV1::new(false, true);
        let observed = enabled
            .with_default(|| {
                prove_proof_managed_note_stark_v1_with_rng(&adapter, &base, &mut enabled_rng)
            })
            .expect("instrumented canonical candidate")
            .verify_into_bytes_v1(&adapter)
            .expect("independent observed verification");
        assert_eq!(baseline, observed);
        let mut disabled_tail = [0_u8; 64];
        let mut enabled_tail = [0_u8; 64];
        disabled_rng.fill_bytes(&mut disabled_tail);
        enabled_rng.fill_bytes(&mut enabled_tail);
        assert_eq!(disabled_tail, enabled_tail);
        assert!(disabled.events().is_empty());
        enabled.assert_note_prefix(16, "succeeded", 0);
    }

    #[test]
    fn malformed_trace_and_entropy_never_emit_a_proof() {
        let adapter = MockAdapterV1::default();
        let mut changed = mock_base_columns_v1();
        changed[0][5] = F::ONE;
        let mut rng = StdRng::from_seed([3; 32]);
        assert!(prove_proof_managed_note_stark_v1_with_rng(&adapter, &changed, &mut rng,).is_err());
        assert!(matches!(
            prove_proof_managed_note_stark_v1_with_rng(
                &adapter,
                &mock_base_columns_v1(),
                &mut MaxValueRng,
            ),
            Err(ProofManagedNoteStarkErrorV1::Randomness)
        ));
    }
    #[test]
    fn malformed_profiles_are_rejected_before_proving() {
        let adapter = MockAdapterV1::default();
        for degree in [0, 1, 5, u8::MAX] {
            let mut invalid = adapter.protocol_v1();
            invalid.maximum_constraint_degree = degree;
            assert_eq!(
                invalid.validate(),
                Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
            );
        }
        let mut wrong_parameters = adapter.clone();
        wrong_parameters.parameters.query_count -= 1;
        assert!(matches!(
            prepare_note_profile_v1(&wrong_parameters),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
        let mut oversized_trace_profile = adapter.clone();
        oversized_trace_profile.parameters.minimum_trace_log2 =
            PROOF_MANAGED_NOTE_MAX_NATIVE_TRACE_LOG2_V1 + 1;
        oversized_trace_profile.parameters.maximum_trace_log2 =
            PROOF_MANAGED_NOTE_MAX_NATIVE_TRACE_LOG2_V1 + 1;
        assert!(matches!(
            oversized_trace_profile.protocol_v1().validate(),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
        let mut degree_below_copy_chip = adapter.clone();
        degree_below_copy_chip.maximum_constraint_degree =
            NOTE_COPY_CONSTRAINT_DEGREE_V1.saturating_sub(1);
        assert!(matches!(
            prepare_note_profile_v1(&degree_below_copy_chip),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
        let mut unsupported_degree = adapter.clone();
        unsupported_degree.maximum_constraint_degree =
            PROOF_MANAGED_NOTE_MAX_CONSTRAINT_DEGREE_V1 + 1;
        assert!(matches!(
            prepare_note_profile_v1(&unsupported_degree),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
        for reserved in aggregate::aggregate_stark_reserved_domains_v1() {
            let mut reserved_aggregate_domain = adapter.protocol_v1();
            reserved_aggregate_domain.profile_binding_label = reserved;
            assert_eq!(
                reserved_aggregate_domain.validate(),
                Err(ProofManagedNoteStarkErrorV1::InvalidProfile),
                "outer profile labels must not reuse aggregate-core roles"
            );
            reserved_aggregate_domain = adapter.protocol_v1();
            reserved_aggregate_domain.relation_layout_domain = reserved;
            assert_eq!(
                reserved_aggregate_domain.validate(),
                Err(ProofManagedNoteStarkErrorV1::InvalidProfile),
                "relation layout domains must not reuse aggregate-core roles"
            );
        }
        let mut oversized_profile_domain = adapter.protocol_v1();
        oversized_profile_domain.profile_binding_label =
            Box::leak(vec![0_u8; usize::from(u16::MAX) + 1].into_boxed_slice());
        assert_eq!(
            oversized_profile_domain.validate(),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile),
            "profile domains must fit the canonical u16-framed transcript"
        );
        let mut degree_four = adapter.clone();
        degree_four.maximum_constraint_degree = PROOF_MANAGED_NOTE_MAX_CONSTRAINT_DEGREE_V1;
        prepare_note_profile_v1(&degree_four)
            .expect("the canonical four composition chunks admit degree-four quotients");
        let mut empty_profile = adapter.protocol_v1();
        empty_profile.profile_descriptor = b"";
        assert_eq!(
            empty_profile.validate(),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile),
        );
    }
    #[test]
    fn mock_profile_cannot_exceed_the_consensus_proof_cap() {
        let mut adapter = MockAdapterV1::default();
        adapter.parameters.maximum_proof_bytes =
            usize::try_from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1).unwrap() + 1;
        assert_eq!(
            adapter.protocol_v1().validate(),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        );
        assert!(matches!(
            prepare_note_profile_v1(&adapter),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
        let canonical = MockAdapterV1::default();
        let prepared = prepare_note_profile_v1(&canonical).expect("canonical profile");
        let hard_maximum = aggregate::maximum_encoded_proof_with_deep_bytes_v1(
            prepared.protocol.parameters,
            &prepared.layout,
        )
        .expect("hard DEEP proof maximum");
        assert!(hard_maximum <= canonical.parameters.maximum_proof_bytes);
        let mut underdeclared = canonical;
        underdeclared.parameters.maximum_proof_bytes = hard_maximum - 1;
        assert!(matches!(
            prepare_note_profile_v1(&underdeclared),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
    }
    #[test]
    fn quotient_degree_capacity_is_exact_and_overflow_checked() {
        let adapter = MockAdapterV1::default();
        let prepared = prepare_note_profile_v1(&adapter).expect("degree-two mock profile fits");
        let maximum_trace_degree =
            maximum_masked_trace_degree_v1(prepared.trace_size).expect("trace degree");
        let maximum_quotient_degree =
            maximum_quotient_degree_v1(prepared.trace_size, adapter.maximum_constraint_degree)
                .expect("quotient degree");
        let maximum_fri_input_degree =
            maximum_fri_input_degree_v1(&prepared.layout, prepared.protocol.parameters)
                .expect("FRI capacity");
        // n = 8192, mask degree = 975, terminal degree = 143, six folds.
        // Quotients span four coefficient chunks; their combined degree is
        // compared with the composition capacity, not one FRI input chunk.
        let maximum_composition_degree = prepared
            .layout
            .maximum_composition_degree(prepared.protocol.parameters)
            .expect("composition capacity");
        assert_eq!(maximum_trace_degree, 9_167);
        assert_eq!(maximum_quotient_degree, 10_142);
        assert_eq!(maximum_fri_input_degree, 9_215);
        assert_eq!(maximum_composition_degree, 36_863);
        assert!(maximum_trace_degree <= maximum_fri_input_degree);
        assert!(maximum_quotient_degree > maximum_fri_input_degree);
        assert!(maximum_quotient_degree <= maximum_composition_degree);
        assert!(matches!(
            maximum_masked_trace_degree_v1(usize::MAX),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
        assert!(matches!(
            maximum_quotient_degree_v1(usize::MAX - PROOF_MANAGED_NOTE_MASK_DEGREE_V1, u8::MAX),
            Err(ProofManagedNoteStarkErrorV1::InvalidProfile)
        ));
        let mut production_parameters = mock_parameters_v1();
        production_parameters.minimum_trace_log2 = 14;
        production_parameters.maximum_trace_log2 = 14;
        let production_layout = aggregate::AggregateProofLayoutV1::new(
            production_parameters,
            vec![aggregate::AggregateTraceGroupLayoutV1 {
                native_trace_log2: 14,
                segment_instances: 1,
                base_width: NOTE_COPY_WIDTH_V1,
                aux_width: NOTE_COPY_AUX_WIDTH_V1,
            }],
        )
        .expect("production-size layout");
        let production_trace_size = 1_usize << 14;
        let degree_four_quotient = maximum_quotient_degree_v1(
            production_trace_size,
            PROOF_MANAGED_NOTE_MAX_CONSTRAINT_DEGREE_V1,
        )
        .expect("degree-four quotient");
        let degree_nine_quotient =
            maximum_quotient_degree_v1(production_trace_size, 9).expect("degree-nine quotient");
        let production_fri_input_capacity =
            maximum_fri_input_degree_v1(&production_layout, production_parameters)
                .expect("production FRI capacity");
        let production_composition_capacity = production_layout
            .maximum_composition_degree(production_parameters)
            .expect("production composition capacity");
        assert_eq!(degree_four_quotient, 53_052);
        assert_eq!(degree_nine_quotient, 139_847);
        assert_eq!(production_fri_input_capacity, 18_431);
        assert_eq!(production_composition_capacity, 73_727);
        assert!(
            maximum_masked_trace_degree_v1(production_trace_size).expect("production trace degree")
                <= production_fri_input_capacity
        );
        assert!(degree_four_quotient <= production_composition_capacity);
        assert!(degree_nine_quotient > production_composition_capacity);
    }
}
