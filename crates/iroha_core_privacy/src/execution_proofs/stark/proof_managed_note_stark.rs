//! Native execution proof driver; privacy proofs use their separate implementation.
//! Shared transparent STARK substrate for proof-managed private-note pools.
//!
//! This module owns proof-system mechanics and relation-neutral note chips: canonical byte range
//! checks, a three-lane byte-copy permutation, masked trace LDEs, verifier-fixed preprocessing,
//! quotient composition, six-lane Goldilocks Poseidon-x7 vector-row commitments, binary FRI, grinding, and the exact
//! aggregate proof codec. Protocol adapters retain their statement policy, ordered hash schedule,
//! profile-only rows, public-input digest, and error mapping.
//!
//! The substrate deliberately has no activation or ledger-effect API. A profile is not safe to
//! expose until its extension-domain residue evaluator, strict proof adversaries, native
//! differential tests, and typed state transition are all complete.
use super::{
    aggregate_stark::{self as aggregate, AggregateOpenedRowEvaluatorV1},
    transparent_stark::{
        GOLDILOCKS_GENERATOR_V1, GoldilocksDigest384V1, GoldilocksFieldV1 as F,
        GoldilocksFp4V1 as E, ReplayableTraceMaskV1, TransparentStarkErrorV1,
        TransparentTranscriptV1, goldilocks_digest384_frame_v1, goldilocks_fft_v1,
        goldilocks_ifft_v1, goldilocks_primitive_root_v1, grind_nonce_v1,
        masked_trace_lde_column_with_mask_v1, sample_trace_mask_v1,
        transparent_stark_zk_mask_geometry_v1, verify_grinding_nonce_v1,
    },
};

use rand::TryRngCore;
use rayon::prelude::*;
use std::collections::BTreeSet;
use thiserror::Error;
#[path = "proof_managed_note_stark_execution_fixed.rs"]
mod execution_fixed;
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
pub const PROOF_MANAGED_NOTE_STARK_SUITE_V1: &[u8] = b"StarkFriPoseidonX7Goldilocks6x64";
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
pub const PROOF_MANAGED_NOTE_MAX_NATIVE_TRACE_LOG2_V1: u8 = 19;
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
/// Worst-case commitment-error exponent at the maximum native trace.
pub const PROOF_MANAGED_NOTE_FRI_COMMITMENT_ERROR_BITS_MIN_V1: u16 = 187;
/// Affine batching parameter in the sole first-release FRI theorem instance.
pub const PROOF_MANAGED_NOTE_FRI_BATCHING_PARAMETER_M_V1: u8 = 3;
/// Exact effective FRI code-rate numerator.
pub const PROOF_MANAGED_NOTE_FRI_RATE_NUMERATOR_V1: u8 = 1;
/// Exact effective FRI code-rate denominator.
pub const PROOF_MANAGED_NOTE_FRI_RATE_DENOMINATOR_V1: u8 = 7;
/// Complete affine arities whose sum enters the commitment-error term.
// Binary fold arities are derived from the full actual domain/terminal schedule.
/// Proven lower-bound exponent for the Goldilocks quartic extension field.
pub const PROOF_MANAGED_NOTE_EXTENSION_FIELD_LOWER_BOUND_BITS_V1: u16 = 252;
/// Complete relation-neutral first-release proof-driver geometry.
///
/// Protocol adapters bind a separate relation descriptor. The canonical
/// profile digest frames this shared descriptor first and the relation
/// descriptor second, so neither layer can silently restate stale geometry.
pub const PROOF_MANAGED_NOTE_STARK_GEOMETRY_DESCRIPTOR_V1: &[u8] = b"proof-managed-note-stark-geometry-v1:proof=StarkFriPoseidonX7Goldilocks6x64:base-field=goldilocks:challenge-field=goldilocks-fp4:merkle=poseidon-x7-goldilocks-six-independent-lanes-6x64:transcript=poseidon-x7-goldilocks-six-independent-lanes-6x64:copy-width=8:copy-lanes=3:copy-aux-width=118:copy-fixed-width=43:copy-constraints=151:copy-constraint-degree=2:security-lanes=1:queries=136:lde-blowup=8:composition-degree-chunks=4:deep-points=1:deep-openings=base-current,base-next,aux-current,aux-next,composition:deep-mixes=independent:max-native-trace-log2=19:trace-mask-degree=975:trace-mask-coefficients=976:max-constraint-degree=4:fri-terminal=1024:fri-degree=143:fri-input=deep-ali:fri-theorem=affine-batched-theorem2:l-minus-one=3/2:batching-m=3:rho-upper-bound=1/7:affine-arities=every-binary-fold:folds=lde-log2-minus-terminal-log2:max-folds=12:extension-field-lower-bound-bits=252:query-error-bits=160:commitment-error-bits-min=187:target-soundness-bits=128:grinding=20-nonadditive:codec=fixed-shape-big-endian-digest384";
/// Derive the canonical digest of shared proof geometry plus one relation.
pub fn proof_managed_note_stark_profile_digest_v1(
    domains: &aggregate::AggregateStarkDomainsV1,
    relation_descriptor: &[u8],
) -> Result<GoldilocksDigest384V1, ProofManagedNoteStarkErrorV1> {
    goldilocks_digest384_frame_v1(
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
) -> Result<GoldilocksDigest384V1, ProofManagedNoteStarkErrorV1> {
    goldilocks_digest384_frame_v1(
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
    /// Complete six-lane Goldilocks Poseidon-x7 Merkle and transcript domains.
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
        l_minus_one_numerator: 3,
        l_minus_one_denominator: 2,
        batching_parameter_m: PROOF_MANAGED_NOTE_FRI_BATCHING_PARAMETER_M_V1,
        rho_numerator: PROOF_MANAGED_NOTE_FRI_RATE_NUMERATOR_V1,
        rho_denominator: PROOF_MANAGED_NOTE_FRI_RATE_DENOMINATOR_V1,
        affine_arities: vec![
            2;
            layout
                .fri_rounds(parameters)
                .map_err(map_aggregate_error_v1)?
        ],
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
        // This retained driver is execution-only; privacy remains in its original module.
        let maximum_native_log = PROOF_MANAGED_NOTE_MAX_NATIVE_TRACE_LOG2_V1;
        let minimum_commitment_bits = PROOF_MANAGED_NOTE_FRI_COMMITMENT_ERROR_BITS_MIN_V1;
        let _combined_profile_digest =
            proof_managed_note_stark_profile_digest_v1(&self.domains, self.profile_descriptor)?;
        if self.parameters.security_lanes != PROOF_MANAGED_NOTE_SECURITY_LANES_V1
            || self.parameters.query_count != PROOF_MANAGED_NOTE_QUERY_COUNT_V1
            || self.parameters.blowup_log2 != PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1
            || self.parameters.terminal_log2 != PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1
            || self.parameters.terminal_degree_bound != PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1
            || self.parameters.composition_degree_chunks
                != PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1
            || self.parameters.maximum_trace_log2 > maximum_native_log
            || self.parameters.maximum_trace_groups != 1
            || self.parameters.maximum_segment_instances != 1
            || self.parameters.maximum_proof_bytes > consensus_proof_cap
            || PROOF_MANAGED_NOTE_MASK_DEGREE_V1 < mask_geometry.minimum_mask_degree
            || fri_soundness.query_error_bits != PROOF_MANAGED_NOTE_FRI_QUERY_ERROR_BITS_V1
            || fri_soundness.commitment_error_bits < minimum_commitment_bits
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
    fn public_input_digest_v1(&self)
    -> Result<GoldilocksDigest384V1, ProofManagedNoteStarkErrorV1>;
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
    #[expect(
        dead_code,
        reason = "execution profiles currently use inactive cells; retain the constant-copy constraint policy"
    )]
    Constant(u8),
    /// The cell belongs to a verifier-fixed variable cycle.
    #[expect(
        dead_code,
        reason = "execution profiles currently use inactive cells; retain the variable-copy constraint policy"
    )]
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
#[cfg(test)]
/// Compare selected execution evaluations against the original native full-LDE path.
pub fn execution_fixed_query_parity_v1<A: ProofManagedNoteStarkAdapterV1>(
    adapter: &A,
    query_indices: &[usize],
) -> Result<bool, ProofManagedNoteStarkErrorV1> {
    let prepared = prepare_note_profile_v1(adapter)?;
    let reference = fixed_lde_columns_v1(
        &prepared.fixed_columns,
        prepared.trace_log2,
        prepared.layout.common_lde_log2(),
    )?;
    let queries = execution_fixed::query_rows_v1(
        prepared.fixed_columns,
        prepared.trace_log2,
        prepared.layout.common_lde_log2(),
        query_indices,
    )?;
    for index in query_indices {
        if queries.get(index) != Some(&row_at_columns_v1(&reference, *index)?) {
            return Ok(false);
        }
    }
    Ok(true)
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
    public_digest: &GoldilocksDigest384V1,
) -> Result<TransparentTranscriptV1, ProofManagedNoteStarkErrorV1> {
    let profile_digest = proof_managed_note_stark_profile_digest_v1(
        &prepared.protocol.domains,
        prepared.protocol.profile_descriptor,
    )?;
    let geometry_digest = proof_managed_note_stark_geometry_digest_v1(&prepared.protocol.domains)?;
    let geometry_digest = geometry_digest.to_le_bytes();
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
    (0..count)
        .map(|_| {
            transcript
                .challenge_fp4(label)
                .map_err(map_transparent_error_v1)
        })
        .collect()
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
    let lde_root = goldilocks_primitive_root_v1(prepared.layout.common_lde_log2())
        .map_err(map_transparent_error_v1)?;
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
    let mut x = F(GOLDILOCKS_GENERATOR_V1);
    // Retain only one canonical row batch at a time. The domain recurrence is evaluated serially
    // across batch boundaries, matching the historical path exactly, while rows inside a batch
    // are independent and collected by index. Serial reduction writes directly into the final
    // lane vectors, avoiding both a full domain-point table and a full row-major staging vector.
    for batch_start in (0..lde_size).step_by(aggregate::DEEP_FRI_BASE_BATCH_ROWS_V1) {
        let batch_end = batch_start
            .checked_add(aggregate::DEEP_FRI_BASE_BATCH_ROWS_V1)
            .map_or(lde_size, |end| end.min(lde_size));
        let batch_len = batch_end - batch_start;
        let mut domain_points = Vec::new();
        domain_points
            .try_reserve_exact(batch_len)
            .map_err(|_| ProofManagedNoteStarkErrorV1::Resource)?;
        for _ in batch_start..batch_end {
            domain_points.push(x);
            x = x.mul(lde_root);
        }
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
                let local_index = index - batch_start;
                let inverse_vanishing = domain_points[local_index]
                    .pow(prepared.trace_size as u128)
                    .sub(F::ONE)
                    .inv()
                    .ok_or(ProofManagedNoteStarkErrorV1::Internal)?;
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
                let mut quotient = E::ZERO;
                for (column_index, column) in base_lde.iter().enumerate() {
                    let value = E::from_base(column[index]);
                    quotient = quotient.add(
                        value
                            .sub(deep_trace.base_current[column_index])
                            .mul(current_inverse)
                            .mul(trace_mix.base_current[column_index]),
                    );
                    quotient = quotient.add(
                        value
                            .sub(deep_trace.base_next[column_index])
                            .mul(next_inverse)
                            .mul(trace_mix.base_next[column_index]),
                    );
                }
                for (column_index, column) in aux_lde.iter().enumerate() {
                    let value = E::from_base(column[index]);
                    quotient = quotient.add(
                        value
                            .sub(deep_trace.aux_current[column_index])
                            .mul(current_inverse)
                            .mul(trace_mix.aux_current[column_index]),
                    );
                    quotient = quotient.add(
                        value
                            .sub(deep_trace.aux_next[column_index])
                            .mul(next_inverse)
                            .mul(trace_mix.aux_next[column_index]),
                    );
                }
                for (chunk_index, (chunk, coefficient)) in
                    composition.iter().zip(&mix.composition).enumerate()
                {
                    quotient = quotient.add(
                        chunk[index]
                            .sub(deep_composition[chunk_index])
                            .mul(current_inverse)
                            .mul(*coefficient),
                    );
                }
                *quotient_slot = quotient;
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
/// Construct the sole canonical proof wire with injected masking entropy.
///
/// The caller supplies exact native base columns; the adapter reconstructs all
/// statement-derived fixed policy and deterministic auxiliary columns. The
/// emitted proof is self-verified before it is returned.
pub fn prove_proof_managed_note_stark_v1_with_rng<
    A: ProofManagedNoteStarkAdapterV1,
    R: TryRngCore,
>(
    adapter: &A,
    base_columns: &[Vec<F>],
    rng: &mut R,
) -> Result<Vec<u8>, ProofManagedNoteStarkErrorV1> {
    let prepared = prepare_note_profile_v1(adapter)?;
    canonical_columns_v1(base_columns, prepared.base_width, prepared.trace_size)?;
    let public_digest = adapter.public_input_digest_v1()?;
    let lde_log2 = prepared.layout.common_lde_log2();
    let lde_size = prepared.layout.common_lde_size();
    let (base_lde, base_masks) =
        masked_lde_columns_v1(base_columns, prepared.trace_log2, lde_log2, rng)?;
    let base_lde = ZeroizingBaseFieldMatrixV1::from(base_lde);
    let base_tree = aggregate::row_tree_v1(
        prepared.protocol.domains.digest_context,
        prepared.protocol.domains.base_leaf,
        prepared.protocol.domains.base_node,
        0,
        &base_lde,
        lde_size,
    )
    .map_err(map_aggregate_error_v1)?;
    let mut transcript = new_note_transcript_v1(&prepared, &public_digest)?;
    let mut trace_group_proofs = vec![aggregate::AggregateTraceGroupProofV1 {
        base_root: base_tree.root(),
        aux_root: GoldilocksDigest384V1::default(),
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
    let mut profile_aux = ZeroizingBaseFieldMatrixV1::from(adapter.build_profile_aux_columns_v1(
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
    validate_native_constraints_v1(
        adapter,
        &prepared,
        base_columns,
        &aux_columns,
        copy_challenges,
        &profile_challenges,
    )?;
    let (aux_lde, aux_masks) =
        masked_lde_columns_v1(&aux_columns, prepared.trace_log2, lde_log2, rng)?;
    let aux_lde = ZeroizingBaseFieldMatrixV1::from(aux_lde);
    let aux_tree = aggregate::row_tree_v1(
        prepared.protocol.domains.digest_context,
        prepared.protocol.domains.aux_leaf,
        prepared.protocol.domains.aux_node,
        0,
        &aux_lde,
        lde_size,
    )
    .map_err(map_aggregate_error_v1)?;
    trace_group_proofs[0].aux_root = aux_tree.root();
    aggregate::absorb_aux_roots_v1(
        &mut transcript,
        &prepared.protocol.domains,
        &trace_group_proofs,
    )
    .map_err(map_aggregate_error_v1)?;
    let alphas = derive_constraint_alphas_v1(&mut transcript, prepared.constraint_count)?;
    let fixed_lde = fixed_lde_columns_v1(&prepared.fixed_columns, prepared.trace_log2, lde_log2)?;
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
    let mut composition_trees = Vec::with_capacity(PROOF_MANAGED_NOTE_SECURITY_LANES_V1);
    let mut composition_roots = Vec::with_capacity(PROOF_MANAGED_NOTE_SECURITY_LANES_V1);
    for lane in 0..PROOF_MANAGED_NOTE_SECURITY_LANES_V1 {
        let tree =
            aggregate::composition_tree_v1(&prepared.protocol.domains, lane, &compositions[lane])
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
    aggregate::validate_deep_proof_shape_v1(&deep, prepared.protocol.parameters, &prepared.layout)
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
    let grinding_state = transcript.state();
    let grinding_nonce = grind_nonce_v1(
        prepared.protocol.domains.digest_context,
        &grinding_state,
        PROOF_MANAGED_NOTE_GRINDING_BITS_V1,
    )
    .map_err(map_transparent_error_v1)?;
    absorb_grinding_nonce_v1(&mut transcript, grinding_nonce)?;
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
    for (group, (base_frontier, aux_frontier)) in trace_group_proofs.iter_mut().zip(trace_frontiers)
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
    let encoded = aggregate::encode_proof_with_deep_v1(
        &proof,
        &deep,
        prepared.protocol.parameters,
        &prepared.layout,
    )
    .map_err(map_aggregate_error_v1)?;
    verify_proof_managed_note_stark_v1(adapter, &encoded)?;
    Ok(encoded)
}
/// Construct a canonical proof with operating-system masking entropy.
#[allow(dead_code)]
pub fn prove_proof_managed_note_stark_v1<A: ProofManagedNoteStarkAdapterV1>(
    adapter: &A,
    base_columns: &[Vec<F>],
) -> Result<Vec<u8>, ProofManagedNoteStarkErrorV1> {
    prove_proof_managed_note_stark_v1_with_rng(adapter, base_columns, &mut rand::rngs::OsRng)
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
            .cloned()
            .ok_or(aggregate::AggregateStarkErrorV1::ConstraintOpening)?;
        let residues = all_constraint_residues_v1(
            self.adapter,
            self.prepared,
            &opening.base_current,
            &opening.base_next,
            &opening.aux_current,
            &opening.aux_next,
            &fixed,
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
    // Reject malformed wire, transcript and Merkle paths before materializing
    // any execution fixed-column or copy-permutation matrix.
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
    let execution_rows = execution_fixed::query_rows_v1(
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
        fixed_openings: &execution_rows,
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
