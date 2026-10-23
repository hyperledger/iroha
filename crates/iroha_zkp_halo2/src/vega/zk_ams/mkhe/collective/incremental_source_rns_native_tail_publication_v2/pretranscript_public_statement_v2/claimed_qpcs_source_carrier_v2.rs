//! Sealed claimed-qPCS/source/numeric carrier after transcript start.
//!
//! This source-only child is reachable only from the already-sealed started
//! pre-transcript owner. It moves that owner's reader bridge into one complete
//! 200-row schedule batch while retaining the exact confidential snapshot and
//! private facts, moves the returned sole schedule and exact qPCS-bound
//! transcript into the pre-auth claimed owner, authenticates with that owner's
//! provisional final seeds, source-preflights before schedule extraction, and
//! retains an exact 24-byte authenticated numeric tail for every row.
//!
//! The result retains a fresh schedule-free numeric cursor but implements no
//! cursor trait itself. The fixed numeric cache moves into the exact claimed
//! parent and remains recursively owned through membership. No source, facts,
//! bridge, schedule, transcript, roots, chronology, raw parts, readiness, or
//! release authority is exposed.

#![allow(
    dead_code,
    reason = "the sealed source-only carrier awaits live correspondence and every direct successor"
)]

use core::{fmt, mem::size_of};

use super::super::super::super::super::{
    direct_object_transport::ZkAmsMkheDirectObjectReadAtProviderV1,
    rns_native_centering_subtraction_relation::{
        RnsNativeCenteringSubtractionErrorV1, RnsNativeCenteringSubtractionPrerequisiteV1,
        verify_rns_native_centering_subtraction_relation_v1,
    },
    rns_native_claimed_successor::RnsNativeClaimedSuccessorV1,
    rns_native_comparator_product::{
        RnsNativeComparatorProductErrorV1, RnsNativeComparatorProductPrerequisiteV1,
        verify_rns_native_comparator_product_v1,
    },
    rns_native_comparator_range_carry_product::{
        RnsNativeComparatorRangeCarryErrorV1, RnsNativeComparatorRangeCarryPrerequisiteV1,
        verify_rns_native_comparator_range_carry_v1,
    },
    rns_native_composite_verifier::{
        ZkAmsMkheRnsNativeCompositeCandidateReceiptV1,
        ZkAmsMkheRnsNativeCompositeVerificationErrorV1,
        verify_zk_ams_mkhe_rns_native_composite_from_source_chain_v2,
    },
    rns_native_cross_field_inventory::RnsNativePreQpcsQMaskInventoryPreflightV1,
    rns_native_cross_field_rlwe_direct::{
        RnsNativeCrossFieldRlweClaimedInventoryNumericV2,
        RnsNativeCrossFieldRlweClaimedInventoryParentV1, RnsNativeCrossFieldRlweDirectErrorV1,
    },
    rns_native_direct_global_membership_handoff::{
        RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2,
        RnsNativeDirectGlobalMembershipHandoffErrorV1, RnsNativeDirectGlobalMembershipHandoffV1,
        verify_rns_native_direct_global_membership_handoff_v2 as verify_direct_global_membership_handoff_core_v2,
    },
    rns_native_existing_radix_commitment_view::{
        RnsNativeExistingRadixCommitmentPrerequisiteV1,
        RnsNativeExistingRadixCommitmentViewErrorV1,
        authenticate_rns_native_existing_radix_commitment_view_v1,
    },
    rns_native_global_lookup_z_commitment_view::{
        RnsNativeGlobalLookupPostZPrerequisiteV1, RnsNativeGlobalLookupPreZPrerequisiteV1,
        RnsNativeGlobalLookupZCommitmentViewErrorV1,
        authenticate_rns_native_global_lookup_post_z_v1, derive_rns_native_global_lookup_pre_z_v1,
        rns_native_global_inverse_product_sumcheck::{
            RnsNativeGlobalInverseProductErrorV1, RnsNativeGlobalInverseProductPrerequisiteV1,
            RnsNativeGlobalMembershipDirectErrorV1, RnsNativeGlobalMembershipPrerequisiteV1,
            verify_rns_native_global_inverse_product_v1, verify_rns_native_global_membership_v1,
        },
    },
    rns_native_profile::{ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1, ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1},
    rns_native_proof_hash::{
        RnsNativeProofDigestV1 as ProofDigestV1, RnsNativeProofHashContextV1,
        RnsNativeProofHashPhaseV1, RnsNativeProofHashPositionV1, RnsNativeProofHashRoleV1,
        RnsNativeProofHashWorkV1,
    },
    rns_native_public_polynomial_reader::{
        RnsNativePublicPolynomialEvaluationV1, RnsNativePublicPolynomialReadReceiptV1,
    },
    rns_native_q_mask_linear_relations::{
        RnsNativeQMaskLinearRelationsErrorV1, RnsNativeQMaskLinearRelationsPrerequisiteV1,
        verify_rns_native_q_mask_linear_relations_v1,
    },
    rns_native_qpcs_fri_complete::{
        RNS_NATIVE_QPCS_CLAIMED_NUMERIC_TAIL_BYTES_V1,
        RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_BYTES_V1,
        RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_WORK_V1,
        RNS_NATIVE_QPCS_CLAIMED_TERMINAL_CHRONOLOGY_BYTES_V1,
        RnsNativeQpcsClaimedInventoryChronologyV2, RnsNativeQpcsFriCompleteErrorV1,
        RnsNativeQpcsSchedulelessClaimedSourceV1, authenticate_rns_native_qpcs_pre_auth_claimed_v1,
        preflight_rns_native_qpcs_authenticated_claimed_source_v1,
        prepare_rns_native_qpcs_pre_auth_claimed_v1,
    },
    rns_native_qpcs_prefix::RnsNativeQpcsRelationScheduleV1,
    rns_native_radix_complement_linear_relation::{
        RnsNativeRadixComplementLinearErrorV1, RnsNativeRadixComplementLinearPrerequisiteV1,
        verify_rns_native_radix_complement_linear_relation_v1,
    },
    rns_native_rlwe_source_statement::RnsNativePublicArtifactViewV1,
    rns_native_section_codec::RnsNativePendingCrossFieldGlobalLookupContextV1,
    rns_native_small_sign_disjointness_product::{
        RnsNativeSmallSignDisjointnessErrorV1, RnsNativeSmallSignDisjointnessPrerequisiteV1,
        verify_rns_native_small_sign_disjointness_v1,
    },
    rns_native_source::ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1,
    rns_native_source_packing_same_opening::{
        RnsNativeSourcePackingCombinedDirectMembershipPredecessorV1,
        RnsNativeSourcePackingCombinedOuterBindingsV1, RnsNativeSourcePackingSafeCoreV1,
        RnsNativeSourcePackingSameOpeningErrorV1, RnsNativeSourcePackingSameOpeningPrerequisiteV1,
        verify_rns_native_source_packing_same_opening_owned_v2,
    },
    rns_native_terminal_cross_basis::RnsNativeTerminalCrossBasisKernelPrerequisiteV1,
    rns_native_transcript::{
        ZkAmsMkheRnsNativeChallengeSeedsV1, ZkAmsMkheRnsNativeQpcsBoundTranscriptV1,
        ZkAmsMkheRnsNativeTerminalRootsV1,
    },
    rns_native_wire::ZkAmsMkheRnsNativeProofEnvelopeV1,
};

use super::super::{
    RnsNativeCompletedQpcsSourceReadV2, RnsNativeSingleQpcsScheduleBatchV2,
    RnsNativeTailPublicationErrorV2, RnsNativeWholePublicationOwnersV2,
};
use super::{
    RnsNativePreTranscriptPublicStatementFactsV2, RnsNativeStartedPreTranscriptPublicStatementV2,
};

const BINDING_VERSION_V1: u8 = 1;
const RECORDS_V2: usize = 43;
const EQUATIONS_V2: usize = 2;
const REPETITIONS_V2: usize = 5;
const RELATIONS_V2: usize = ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1 * REPETITIONS_V2;
const QUERY_OPENINGS_V2: usize = ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1 as usize;
const PUBLIC_EVALUATION_BYTES_V2: usize = size_of::<RnsNativePublicPolynomialEvaluationV1>();
const RETAINED_PUBLIC_EVALUATION_BYTES_V2: usize = RELATIONS_V2 * PUBLIC_EVALUATION_BYTES_V2;
const RETAINED_NUMERIC_CACHE_BYTES_V2: usize =
    RETAINED_PUBLIC_EVALUATION_BYTES_V2 + RNS_NATIVE_QPCS_CLAIMED_NUMERIC_TAIL_BYTES_V1;
const RETAINED_COMMITMENT_DIGEST_BYTES_V2: usize =
    (EQUATIONS_V2 + ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1) * 48;
const RETAINED_PAYLOAD_BYTES_V2: usize = RETAINED_NUMERIC_CACHE_BYTES_V2
    + RNS_NATIVE_QPCS_CLAIMED_TERMINAL_CHRONOLOGY_BYTES_V1
    + RETAINED_COMMITMENT_DIGEST_BYTES_V2;
const CANONICAL_CHECKS_V2: u64 = (RELATIONS_V2 * (3 + 2 * RECORDS_V2 + 2)) as u64;
const RING_POWER_SQUARINGS_V2: u64 = RELATIONS_V2 as u64 * 17;
const MODULAR_MULTIPLICATIONS_V2: u64 = RING_POWER_SQUARINGS_V2 + RELATIONS_V2 as u64;
const MODULAR_ADDITIONS_V2: u64 = RELATIONS_V2 as u64;
const NUMERIC_VALIDATION_WORK_UNITS_V2: u64 =
    CANONICAL_CHECKS_V2 + MODULAR_MULTIPLICATIONS_V2 + MODULAR_ADDITIONS_V2;
const NUMERIC_TAIL_RETENTION_WORK_UNITS_V2: u64 =
    RNS_NATIVE_QPCS_CLAIMED_NUMERIC_TAIL_BYTES_V1 as u64;

const CARRIER_BINDING_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.rns-native.claimed-qpcs-source-carrier.binding";
// Domain, version, four u16 geometry values, lifecycle digest, five public-read
// receipt digests, receipt object count/four u64 counters, the opaque claimed-
// source digest, and the exact two-equation/40-limb digest arrays.
const CARRIER_BINDING_HASH_BYTES_V2: usize = CARRIER_BINDING_DOMAIN_V1.len()
    + 1
    + 4 * 2
    + 32
    + 4 * 32
    + 48
    + 2
    + 4 * 8
    + 48
    + RETAINED_COMMITMENT_DIGEST_BYTES_V2;
const PRE_BINDING_LOCAL_WORK_UNITS_V2: u64 = NUMERIC_VALIDATION_WORK_UNITS_V2
    + NUMERIC_TAIL_RETENTION_WORK_UNITS_V2
    + RETAINED_COMMITMENT_DIGEST_BYTES_V2 as u64;
const COMBINED_BINDING_HASH_BYTES_V2: usize =
    RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_BYTES_V1 + CARRIER_BINDING_HASH_BYTES_V2;
// Includes the canonical 32-byte catalog and full 48-byte proof commitments.
const CARRIER_BINDING_HASH_WORK_V1: RnsNativeProofHashWorkV1 =
    match RnsNativeProofHashWorkV1::from_word_count(536) {
        Ok(work) => work,
        Err(_) => panic!("fixed carrier frame must fit"),
    };
const BINDING_FIELD_MULTIPLICATIONS_V1: u64 = CARRIER_BINDING_HASH_WORK_V1.field_multiplications
    + RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_WORK_V1.field_multiplications;
const BINDING_FIELD_ADDITIONS_V1: u64 = CARRIER_BINDING_HASH_WORK_V1.field_additions
    + RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_WORK_V1.field_additions;
const LOCAL_WORK_UNITS_V2: u64 = PRE_BINDING_LOCAL_WORK_UNITS_V2
    + COMBINED_BINDING_HASH_BYTES_V2 as u64
    + BINDING_FIELD_MULTIPLICATIONS_V1
    + BINDING_FIELD_ADDITIONS_V1;

/// Source-only declaration and chronology implementation are settled.
pub(super) const RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_SOURCE_SETTLED_V2: bool = true;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_CONTRACT_IMPLEMENTED_V2: bool = true;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_SOURCE_PREFLIGHT_ORDER_IMPLEMENTED_V2: bool = true;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_NUMERIC_TAIL_IMPLEMENTED_V2: bool = true;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_CARRIER_LEDGER_IS_ADDITIVE_V2: bool = true;

/// No live, direct, evidence, readiness, or release gate follows. Here
/// `INTEGRATED` means reachable from the still-absent live correspondence
/// entry; the private source-only transitions above do not flip these gates.
pub(super) const RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_LIVE_INTEGRATED_V2: bool = false;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_PRE_QPCS_Q_MASK_INTEGRATED_V2: bool = false;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_PRE_DIRECT_AXES_INTEGRATED_V2: bool = false;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_DIRECT_RELATION_INTEGRATED_V2: bool = false;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_INVENTORY_MEMBERSHIP_INTEGRATED_V2: bool = false;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_GLOBAL_ROOT_DISCHARGED_V2: bool = false;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_DIRECT_OPENINGS_AVAILABLE_V2: bool = false;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_RESOURCE_EVIDENCE_QUALIFIED_V2: bool = false;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_READINESS_V2: bool = false;
pub(super) const RNS_NATIVE_CLAIMED_QPCS_RELEASE_AUTHORIZED_V2: bool = false;

/// Exact additive accounting for the carrier-local work after the existing
/// reader, qPCS, and source-preflight sub-transitions invoked by the consuming
/// entry. This is not end-to-end accounting for that entry. It excludes the
/// existing 3,520-object/200-evaluation public read, complete qPCS/FRI work,
/// both confidential-source passes, proof backing, publication owners, private
/// pre-transcript facts, allocator metadata, later numeric-cursor destination
/// writes, and all later direct work. Zero
/// new heap/authenticated-I/O bytes therefore means zero additive carrier-local
/// bytes after those separately accounted sub-transitions; the 4,800-byte
/// numeric tail is retained inline. The retained payload intentionally excludes
/// two non-authorizing 48-byte binding digests and ordinary owner headers,
/// matching the numeric ledger scope. Exact local work is 28,816 before
/// binding absorption plus 7,826 binding bytes and 7,142,784 hash field
/// operations, for 7,179,426 total units. One work unit is charged per
/// canonical check, modular operation, retained or copied byte, absorbed
/// binding byte and actual dense-MDS hash multiplication/addition. This is
/// not an instruction count and excludes control-flow comparisons.
pub(super) struct RnsNativeClaimedQpcsSourceCarrierLocalResourceLedgerV2 {
    pub(super) relations: u16,
    pub(super) retained_public_evaluation_bytes: u32,
    pub(super) retained_numeric_tail_bytes: u16,
    pub(super) retained_numeric_cache_bytes: u32,
    pub(super) retained_terminal_chronology_bytes: u16,
    pub(super) retained_commitment_digest_bytes: u16,
    pub(super) retained_payload_bytes: u32,
    pub(super) canonical_checks: u32,
    pub(super) ring_power_squarings: u32,
    pub(super) modular_multiplications: u32,
    pub(super) modular_additions: u16,
    pub(super) numeric_tail_retention_work_units: u16,
    pub(super) pre_binding_local_work_units: u32,
    pub(super) claimed_source_binding_hash_bytes: u16,
    pub(super) carrier_binding_hash_bytes: u16,
    pub(super) combined_binding_hash_bytes: u16,
    pub(super) binding_lane_permutations: u32,
    pub(super) binding_poseidon_rounds: u32,
    pub(super) binding_field_multiplications: u32,
    pub(super) binding_field_additions: u32,
    pub(super) local_work_units: u32,
    pub(super) new_heap_bytes: u8,
    pub(super) new_spool_bytes: u8,
    pub(super) new_wire_bytes: u8,
    pub(super) new_authenticated_io_bytes: u8,
}

pub(super) const RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_LOCAL_RESOURCE_LEDGER_V2:
    RnsNativeClaimedQpcsSourceCarrierLocalResourceLedgerV2 =
    RnsNativeClaimedQpcsSourceCarrierLocalResourceLedgerV2 {
        relations: RELATIONS_V2 as u16,
        retained_public_evaluation_bytes: RETAINED_PUBLIC_EVALUATION_BYTES_V2 as u32,
        retained_numeric_tail_bytes: RNS_NATIVE_QPCS_CLAIMED_NUMERIC_TAIL_BYTES_V1 as u16,
        retained_numeric_cache_bytes: RETAINED_NUMERIC_CACHE_BYTES_V2 as u32,
        retained_terminal_chronology_bytes: RNS_NATIVE_QPCS_CLAIMED_TERMINAL_CHRONOLOGY_BYTES_V1
            as u16,
        retained_commitment_digest_bytes: RETAINED_COMMITMENT_DIGEST_BYTES_V2 as u16,
        retained_payload_bytes: RETAINED_PAYLOAD_BYTES_V2 as u32,
        canonical_checks: CANONICAL_CHECKS_V2 as u32,
        ring_power_squarings: RING_POWER_SQUARINGS_V2 as u32,
        modular_multiplications: MODULAR_MULTIPLICATIONS_V2 as u32,
        modular_additions: MODULAR_ADDITIONS_V2 as u16,
        numeric_tail_retention_work_units: NUMERIC_TAIL_RETENTION_WORK_UNITS_V2 as u16,
        pre_binding_local_work_units: PRE_BINDING_LOCAL_WORK_UNITS_V2 as u32,
        claimed_source_binding_hash_bytes: RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_BYTES_V1
            as u16,
        carrier_binding_hash_bytes: CARRIER_BINDING_HASH_BYTES_V2 as u16,
        combined_binding_hash_bytes: COMBINED_BINDING_HASH_BYTES_V2 as u16,
        binding_lane_permutations: (CARRIER_BINDING_HASH_WORK_V1.lane_permutations
            + RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_WORK_V1.lane_permutations)
            as u32,
        binding_poseidon_rounds: (CARRIER_BINDING_HASH_WORK_V1.poseidon_rounds
            + RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_WORK_V1.poseidon_rounds)
            as u32,
        binding_field_multiplications: BINDING_FIELD_MULTIPLICATIONS_V1 as u32,
        binding_field_additions: BINDING_FIELD_ADDITIONS_V1 as u32,
        local_work_units: LOCAL_WORK_UNITS_V2 as u32,
        new_heap_bytes: 0,
        new_spool_bytes: 0,
        new_wire_bytes: 0,
        new_authenticated_io_bytes: 0,
    };

const _: () = {
    assert!(RECORDS_V2 == 43);
    assert!(EQUATIONS_V2 == 2);
    assert!(REPETITIONS_V2 == 5);
    assert!(RELATIONS_V2 == 200);
    assert!(QUERY_OPENINGS_V2 == 160);
    assert!(PUBLIC_EVALUATION_BYTES_V2 == 704);
    assert!(RETAINED_PUBLIC_EVALUATION_BYTES_V2 == 140_800);
    assert!(RNS_NATIVE_QPCS_CLAIMED_NUMERIC_TAIL_BYTES_V1 == 4_800);
    assert!(RETAINED_NUMERIC_CACHE_BYTES_V2 == 145_600);
    assert!(RNS_NATIVE_QPCS_CLAIMED_TERMINAL_CHRONOLOGY_BYTES_V1 == 6_264);
    assert!(RETAINED_COMMITMENT_DIGEST_BYTES_V2 == 2_016);
    assert!(RETAINED_PAYLOAD_BYTES_V2 == 153_880);
    assert!(CANONICAL_CHECKS_V2 == 18_200);
    assert!(RING_POWER_SQUARINGS_V2 == 3_400);
    assert!(MODULAR_MULTIPLICATIONS_V2 == 3_600);
    assert!(MODULAR_ADDITIONS_V2 == 200);
    assert!(NUMERIC_VALIDATION_WORK_UNITS_V2 == 22_000);
    assert!(NUMERIC_TAIL_RETENTION_WORK_UNITS_V2 == 4_800);
    assert!(PRE_BINDING_LOCAL_WORK_UNITS_V2 == 28_816);
    assert!(RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_BYTES_V1 == 5_444);
    assert!(CARRIER_BINDING_HASH_BYTES_V2 == 2_382);
    assert!(COMBINED_BINDING_HASH_BYTES_V2 == 7_826);
    assert!(LOCAL_WORK_UNITS_V2 == 7_179_426);
    assert!(LOCAL_WORK_UNITS_V2 > PRE_BINDING_LOCAL_WORK_UNITS_V2);
    assert!(RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_SOURCE_SETTLED_V2);
    assert!(RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_CONTRACT_IMPLEMENTED_V2);
    assert!(RNS_NATIVE_CLAIMED_QPCS_SOURCE_PREFLIGHT_ORDER_IMPLEMENTED_V2);
    assert!(RNS_NATIVE_CLAIMED_QPCS_NUMERIC_TAIL_IMPLEMENTED_V2);
    assert!(RNS_NATIVE_CLAIMED_QPCS_CARRIER_LEDGER_IS_ADDITIVE_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_LIVE_INTEGRATED_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_PRE_QPCS_Q_MASK_INTEGRATED_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_PRE_DIRECT_AXES_INTEGRATED_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_DIRECT_RELATION_INTEGRATED_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_INVENTORY_MEMBERSHIP_INTEGRATED_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_GLOBAL_ROOT_DISCHARGED_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_DIRECT_OPENINGS_AVAILABLE_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_RESOURCE_EVIDENCE_QUALIFIED_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_READINESS_V2);
    assert!(!RNS_NATIVE_CLAIMED_QPCS_RELEASE_AUTHORIZED_V2);
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::vega::zk_ams::mkhe) enum RnsNativeClaimedQpcsSourceCarrierErrorV2 {
    PublicRead,
    Qpcs,
    SourcePreflight,
    Inventory,
    InvalidCount,
    InvalidOrder,
    InvalidBinding,
    Poisoned,
}

impl fmt::Display for RnsNativeClaimedQpcsSourceCarrierErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RnsNativeClaimedQpcsSourceCarrierErrorV2 {}

/// Failure at the consuming claimed-qPCS-to-composite terminal seam.
///
/// The two variants preserve whether the authenticated source-chain context
/// could not be constructed or the atomic four-stage composite verifier
/// rejected that context.  Neither variant carries partial verification state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::vega::zk_ams::mkhe) enum RnsNativeClaimedQpcsCompositeVerificationErrorV2 {
    /// The retained direct/membership/source-packing lineage could not mint the
    /// sole authenticated composite input.
    Handoff(RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2),
    /// The atomic composite verifier rejected the consumed authenticated input.
    CompositeVerification(ZkAmsMkheRnsNativeCompositeVerificationErrorV1),
}

impl fmt::Display for RnsNativeClaimedQpcsCompositeVerificationErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RnsNativeClaimedQpcsCompositeVerificationErrorV2 {}

/// Fixed-shape qPCS inputs accepted only by the consuming claimed transition.
/// There is deliberately no final transcript field: qPCS borrows final seeds
/// from the provisional chronology already owned by its pre-auth typestate.
pub(super) struct RnsNativeClaimedQpcsAuthenticationInputV2<'digests, 'proof> {
    equation_commitment_digests: &'digests [ProofDigestV1; EQUATIONS_V2],
    limb_commitment_digests: &'digests [ProofDigestV1; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1],
    query_opening_digests: &'digests [ProofDigestV1; QUERY_OPENINGS_V2],
    proof: &'proof [u8],
}

impl<'digests, 'proof> RnsNativeClaimedQpcsAuthenticationInputV2<'digests, 'proof> {
    pub(super) const fn new_v2(
        equation_commitment_digests: &'digests [ProofDigestV1; EQUATIONS_V2],
        limb_commitment_digests: &'digests [ProofDigestV1; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1],
        query_opening_digests: &'digests [ProofDigestV1; QUERY_OPENINGS_V2],
        proof: &'proof [u8],
    ) -> Self {
        Self {
            equation_commitment_digests,
            limb_commitment_digests,
            query_opening_digests,
            proof,
        }
    }
}

struct RnsNativeClaimedSourceCursorV2 {
    next_relation: u16,
    poisoned: bool,
}

impl RnsNativeClaimedSourceCursorV2 {
    const fn new_v2() -> Self {
        Self {
            next_relation: 0,
            poisoned: false,
        }
    }
}

/// Exact publication/read/facts owner retained unchanged across every
/// verifier stage.  It has no projection or raw-parts API.
struct RnsNativeClaimedQpcsRetainedPublicationV2 {
    owners: RnsNativeWholePublicationOwnersV2,
    read_receipt: RnsNativePublicPolynomialReadReceiptV1,
    facts: RnsNativePreTranscriptPublicStatementFactsV2,
    equation_commitment_digests: [ProofDigestV1; EQUATIONS_V2],
    limb_commitment_digests: [ProofDigestV1; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1],
    carrier_binding_digest: ProofDigestV1,
}

/// Move-only qPCS/publication authority retained by the final composite input.
///
/// The complete publication owners, read receipt, public-statement facts, and
/// fixed commitment inventories stay owned here.  Construction is private to
/// the one consuming post-source-packing transition below; no digest-only or
/// raw-parts constructor exists.
#[must_use = "the authenticated qPCS publication must remain owned through composite verification"]
pub(in crate::vega::zk_ams::mkhe) struct RnsNativeQpcsCompositeAuthorityV2<'envelope> {
    retained: RnsNativeClaimedQpcsRetainedPublicationV2,
    envelope: &'envelope ZkAmsMkheRnsNativeProofEnvelopeV1,
}

impl RnsNativeQpcsCompositeAuthorityV2<'_> {
    pub(in crate::vega::zk_ams::mkhe) fn validate_composite_context_v2(
        &self,
        envelope: &ZkAmsMkheRnsNativeProofEnvelopeV1,
        transcript: &ZkAmsMkheRnsNativeChallengeSeedsV1,
    ) -> Result<(), RnsNativeClaimedQpcsSourceCarrierErrorV2> {
        let mut publication_digests =
            [ProofDigestV1::ZERO; EQUATIONS_V2 + ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1 + 1];
        publication_digests[..EQUATIONS_V2]
            .copy_from_slice(&self.retained.equation_commitment_digests);
        publication_digests[EQUATIONS_V2..EQUATIONS_V2 + ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1]
            .copy_from_slice(&self.retained.limb_commitment_digests);
        publication_digests[EQUATIONS_V2 + ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1] =
            self.retained.carrier_binding_digest;
        if !core::ptr::eq(self.envelope, envelope)
            || envelope.profile_manifest_digest() != transcript.profile_manifest_digest()
            || envelope.topology_digest() != transcript.topology_digest()
            || envelope.release_candidate_digest() != transcript.release_candidate_digest()
            || envelope.statement_digest() != transcript.statement_digest()
            || envelope.operational_context_digest() != transcript.operational_context_digest()
            || envelope.source_receipt_digest() != transcript.source_receipt_digest()
            || publication_digests.contains(&ProofDigestV1::ZERO)
            || publication_digests
                .iter()
                .enumerate()
                .any(|(index, digest)| publication_digests[index + 1..].contains(digest))
        {
            return Err(RnsNativeClaimedQpcsSourceCarrierErrorV2::InvalidBinding);
        }
        Ok(())
    }
}

/// Move-only witness that the numeric origin was minted while the full
/// retained-publication owner was still present in this exact carrier.
/// The digest bytes are intentionally trapped in a non-`Copy`, non-`Clone`
/// wrapper and have no accessor.
struct RnsNativeClaimedQpcsRetainedPublicationOriginBindingV2 {
    digest: ProofDigestV1,
}

/// Unmintable outside this child: the sole direct numeric origin combines the
/// exact 200-row public cache, fresh cursor state, and a move-only witness to
/// the retained publication that remains in the outer exact-stage wrapper.
///
/// The type is reexported narrowly only so the direct module can retain and
/// consume it. Its fields and constructor remain private here; it has no raw
/// parts, generic map, clone, schedule, lineage, or finish surface.
#[must_use = "the exact numeric origin must move into the claimed direct parent"]
pub(in crate::vega::zk_ams::mkhe) struct RnsNativeClaimedDirectNumericOriginV2 {
    public_evaluations: Box<[RnsNativePublicPolynomialEvaluationV1; RELATIONS_V2]>,
    next_relation: u16,
    poisoned: bool,
    retained_publication_binding: RnsNativeClaimedQpcsRetainedPublicationOriginBindingV2,
}

impl RnsNativeClaimedDirectNumericOriginV2 {
    fn mint_v2(
        retained: &RnsNativeClaimedQpcsRetainedPublicationV2,
        public_evaluations: Box<[RnsNativePublicPolynomialEvaluationV1]>,
        cursor: RnsNativeClaimedSourceCursorV2,
    ) -> Result<Self, RnsNativeClaimedQpcsSourceCarrierErrorV2> {
        if retained.carrier_binding_digest == ProofDigestV1::ZERO
            || cursor.next_relation != 0
            || cursor.poisoned
        {
            return Err(RnsNativeClaimedQpcsSourceCarrierErrorV2::Poisoned);
        }
        let public_evaluations = public_evaluations
            .try_into()
            .map_err(|_| RnsNativeClaimedQpcsSourceCarrierErrorV2::InvalidCount)?;
        Ok(Self {
            public_evaluations,
            next_relation: cursor.next_relation,
            poisoned: cursor.poisoned,
            retained_publication_binding: RnsNativeClaimedQpcsRetainedPublicationOriginBindingV2 {
                digest: retained.carrier_binding_digest,
            },
        })
    }

    pub(in crate::vega::zk_ams::mkhe) fn is_fresh_v2(&self) -> bool {
        self.retained_publication_binding.digest != ProofDigestV1::ZERO
            && self.next_relation == 0
            && !self.poisoned
    }

    pub(in crate::vega::zk_ams::mkhe) fn take_public_evaluation_v2(
        &mut self,
        limb: usize,
        repetition: usize,
    ) -> Result<RnsNativePublicPolynomialEvaluationV1, RnsNativeCrossFieldRlweDirectErrorV1> {
        if self.poisoned {
            return Err(RnsNativeCrossFieldRlweDirectErrorV1::SourceUnavailable);
        }
        self.poisoned = true;
        let relation = self.next_relation as usize;
        if relation >= RELATIONS_V2
            || limb != relation / REPETITIONS_V2
            || repetition != relation % REPETITIONS_V2
        {
            return Err(RnsNativeCrossFieldRlweDirectErrorV1::SourceUnavailable);
        }
        let public = *self
            .public_evaluations
            .get(relation)
            .ok_or(RnsNativeCrossFieldRlweDirectErrorV1::SourceUnavailable)?;
        self.next_relation = self
            .next_relation
            .checked_add(1)
            .ok_or(RnsNativeCrossFieldRlweDirectErrorV1::ArithmeticOverflow)?;
        self.poisoned = false;
        Ok(public)
    }

    pub(in crate::vega::zk_ams::mkhe) fn is_complete_v2(&self) -> bool {
        self.retained_publication_binding.digest != ProofDigestV1::ZERO
            && self.next_relation as usize == RELATIONS_V2
            && !self.poisoned
    }
}

/// Opaque exact-stage wrapper. Only concrete purpose-specific transitions in
/// this module may replace `Stage`; there is deliberately no generic map,
/// parts, constructor, or detached retained-publication accessor.
#[must_use = "the retained publication and exact verifier stage must advance together"]
pub(in crate::vega::zk_ams::mkhe) struct RnsNativeClaimedQpcsOwnedStageV2<Stage> {
    retained: RnsNativeClaimedQpcsRetainedPublicationV2,
    stage: Stage,
}

struct RnsNativeClaimedQpcsSourceStageV2<'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1> {
    public_evaluations: Box<[RnsNativePublicPolynomialEvaluationV1]>,
    claimed_source: RnsNativeQpcsSchedulelessClaimedSourceV1<'proof, S>,
    cursor: RnsNativeClaimedSourceCursorV2,
}

struct RnsNativeClaimedQpcsInventoryStageV2<
    'qpcs,
    'cross,
    S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1,
> {
    public_evaluations: Box<[RnsNativePublicPolynomialEvaluationV1]>,
    claimed_inventory: RnsNativeQpcsClaimedInventoryChronologyV2<'qpcs, 'cross, S>,
    cursor: RnsNativeClaimedSourceCursorV2,
}

struct RnsNativeClaimedDirectInventoryStageV2<
    'qpcs,
    'cross,
    S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1,
> {
    public_evaluations: Box<[RnsNativePublicPolynomialEvaluationV1]>,
    claimed_direct: RnsNativeCrossFieldRlweClaimedInventoryNumericV2<'qpcs, 'cross, S>,
    cursor: RnsNativeClaimedSourceCursorV2,
}

/// Top-level move-only owner of the exact source/public/qPCS chronology and a
/// fresh, non-exposed numeric cursor state. The nested claimed source privately retains
/// the extracted sole schedule, scheduleless source stage, all three terminal
/// obligations, pre-global capability, and final seeds.
#[must_use = "claimed qPCS/source carrier must remain intact until every successor verifies"]
pub(super) struct RnsNativeClaimedQpcsSourceCarrierV2<
    'proof,
    S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1,
> {
    owned: RnsNativeClaimedQpcsOwnedStageV2<RnsNativeClaimedQpcsSourceStageV2<'proof, S>>,
}

/// Exact publication/read owner after the scheduleless claimed qPCS has been
/// joined to its one sealed cross-section allocation and authenticated
/// inventory. The nested owner still retains the sole schedule and all three
/// terminal-root equality obligations.
#[must_use = "claimed qPCS inventory carrier must remain intact until every successor verifies"]
pub(super) struct RnsNativeClaimedQpcsInventoryCarrierV2<
    'qpcs,
    'cross,
    S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1,
> {
    owned: RnsNativeClaimedQpcsOwnedStageV2<RnsNativeClaimedQpcsInventoryStageV2<'qpcs, 'cross, S>>,
}

/// Source-only owner after the sole authenticated schedule has become the
/// claimed direct relation while remaining paired with publication/read facts
/// and the schedule-free numeric cursor.
#[must_use = "claimed direct inventory carrier remains non-authorizing until successor verification and all root discharges"]
pub(super) struct RnsNativeClaimedDirectInventoryCarrierV2<
    'qpcs,
    'cross,
    S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1,
> {
    owned:
        RnsNativeClaimedQpcsOwnedStageV2<RnsNativeClaimedDirectInventoryStageV2<'qpcs, 'cross, S>>,
}

impl<'qpcs, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsSourceCarrierV2<'qpcs, S>
{
    /// Consume the source carrier and exact sealed cross children into one
    /// inventory-backed chronology. No source, schedule, chronology, or
    /// section child is returned on failure.
    pub(super) fn authenticate_claimed_inventory_v2<'cross>(
        self,
        terminal: RnsNativeTerminalCrossBasisKernelPrerequisiteV1,
        pending_cross: RnsNativePendingCrossFieldGlobalLookupContextV1<'cross>,
        preflight: RnsNativePreQpcsQMaskInventoryPreflightV1<'cross>,
    ) -> Result<
        RnsNativeClaimedQpcsInventoryCarrierV2<'qpcs, 'cross, S>,
        RnsNativeClaimedQpcsSourceCarrierErrorV2,
    > {
        let Self { owned } = self;
        let RnsNativeClaimedQpcsOwnedStageV2 { retained, stage } = owned;
        let RnsNativeClaimedQpcsSourceStageV2 {
            public_evaluations,
            claimed_source,
            cursor,
        } = stage;
        let claimed_inventory = claimed_source
            .authenticate_claimed_inventory_v2(terminal, pending_cross, preflight)
            .map_err(|_| RnsNativeClaimedQpcsSourceCarrierErrorV2::Inventory)?;
        Ok(RnsNativeClaimedQpcsInventoryCarrierV2 {
            owned: RnsNativeClaimedQpcsOwnedStageV2 {
                retained,
                stage: RnsNativeClaimedQpcsInventoryStageV2 {
                    public_evaluations,
                    claimed_inventory,
                    cursor,
                },
            },
        })
    }
}

impl<'qpcs, 'cross, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsInventoryCarrierV2<'qpcs, 'cross, S>
{
    /// Atomically binds the internally retained candidate axes and exact
    /// pre-direct continuation owner into the claimed direct relation.
    pub(super) fn bind_direct_claimed_relation_v2(
        self,
    ) -> Result<
        RnsNativeClaimedDirectInventoryCarrierV2<'qpcs, 'cross, S>,
        RnsNativeClaimedQpcsSourceCarrierErrorV2,
    > {
        let Self { owned } = self;
        let RnsNativeClaimedQpcsOwnedStageV2 { retained, stage } = owned;
        let RnsNativeClaimedQpcsInventoryStageV2 {
            public_evaluations,
            claimed_inventory,
            cursor,
        } = stage;
        let claimed_direct = claimed_inventory
            .bind_direct_claimed_relation_v2()
            .map_err(|_| RnsNativeClaimedQpcsSourceCarrierErrorV2::Inventory)?;
        Ok(RnsNativeClaimedDirectInventoryCarrierV2 {
            owned: RnsNativeClaimedQpcsOwnedStageV2 {
                retained,
                stage: RnsNativeClaimedDirectInventoryStageV2 {
                    public_evaluations,
                    claimed_direct,
                    cursor,
                },
            },
        })
    }
}

impl<'qpcs, 'cross, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedDirectInventoryCarrierV2<'qpcs, 'cross, S>
{
    /// Consume the whole exact-stage carrier into the sole claimed successor.
    /// A previously touched numeric cursor is rejected, the public cache is
    /// converted to an exact boxed array, and all numeric authority moves into
    /// the direct parent before frame preflight.
    pub(super) fn into_claimed_successor_stage_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeClaimedSuccessorV1<
                'cross,
                RnsNativeCrossFieldRlweClaimedInventoryParentV1<'qpcs, 'cross, S>,
            >,
        >,
        RnsNativeClaimedQpcsSourceCarrierErrorV2,
    > {
        let Self { owned } = self;
        let RnsNativeClaimedQpcsOwnedStageV2 { retained, stage } = owned;
        let RnsNativeClaimedDirectInventoryStageV2 {
            public_evaluations,
            claimed_direct,
            cursor,
        } = stage;
        let numeric_origin =
            RnsNativeClaimedDirectNumericOriginV2::mint_v2(&retained, public_evaluations, cursor)?;
        let stage = claimed_direct
            .into_claimed_successor_stage_v2(numeric_origin)
            .map_err(|_| RnsNativeClaimedQpcsSourceCarrierErrorV2::Inventory)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

/// The same move-only started source/publication owner after its original
/// ledger has admitted canonical Merkle and repeated initial leaf-hash work.
/// Work-cap refusal returns the same owner with unchanged ledger counters
/// before reader or qPCS authentication. Source-accessor errors require a
/// concrete adapter invariant before claiming that its owner is unchanged.
#[must_use = "the admitted owner must be consumed by the qPCS source transition"]
pub(super) struct RnsNativeQpcsOpeningHashWorkAdmittedStartedV2<K, P, S>
where
    K: ZkAmsMkheDirectObjectReadAtProviderV1,
    P: ZkAmsMkheDirectObjectReadAtProviderV1,
    S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1,
{
    started: RnsNativeStartedPreTranscriptPublicStatementV2<K, P, S>,
}

impl<K, P, S> RnsNativeStartedPreTranscriptPublicStatementV2<K, P, S>
where
    K: ZkAmsMkheDirectObjectReadAtProviderV1,
    P: ZkAmsMkheDirectObjectReadAtProviderV1,
    S: super::super::super::RnsNativeOriginalBudgetedSourceV1,
{
    /// Admit before any public reader or qPCS authentication side effect.
    /// Work-cap refusal is atomic: the caller receives the owner with
    /// unchanged ledger counters. An accessor error also returns the owner,
    /// but its mutable implementation must establish a no-mutation invariant.
    #[allow(
        clippy::result_large_err,
        reason = "atomic refusal hands back the same move-only owner that the Ok variant wraps, so boxing the error cannot shrink the Result"
    )]
    pub(super) fn admit_canonical_merkle_and_rebind_leaf_hash_work_v2(
        mut self,
    ) -> Result<
        RnsNativeQpcsOpeningHashWorkAdmittedStartedV2<K, P, S>,
        (Self, RnsNativeClaimedQpcsSourceCarrierErrorV2),
    > {
        use crate::vega::zk_ams::mkhe::{
            rns_native_proof_hash::RnsNativeProofHashContextV1,
            rns_native_qpcs_opening_work::RnsNativeQpcsOpeningHashWorkV1,
        };
        let parameter = match RnsNativeProofHashContextV1::canonical() {
            Ok(context) => context.parameter_digest(),
            Err(_) => return Err((self, RnsNativeClaimedQpcsSourceCarrierErrorV2::Qpcs)),
        };
        let work =
            match RnsNativeQpcsOpeningHashWorkV1::for_canonical_merkle_and_rebind_leaf_hashes_v1(
                parameter,
            ) {
                Ok(work) => work,
                Err(_) => return Err((self, RnsNativeClaimedQpcsSourceCarrierErrorV2::Qpcs)),
            };
        let admitted = match self.source.original_budget_mut_v1() {
            Ok(budget) => work.admit_v1(budget),
            Err(_) => {
                return Err((
                    self,
                    RnsNativeClaimedQpcsSourceCarrierErrorV2::SourcePreflight,
                ));
            }
        };
        if admitted.is_err() {
            return Err((self, RnsNativeClaimedQpcsSourceCarrierErrorV2::Qpcs));
        }
        Ok(RnsNativeQpcsOpeningHashWorkAdmittedStartedV2 { started: self })
    }
}

impl<K, P, S> RnsNativeQpcsOpeningHashWorkAdmittedStartedV2<K, P, S>
where
    K: ZkAmsMkheDirectObjectReadAtProviderV1,
    P: ZkAmsMkheDirectObjectReadAtProviderV1,
    S: super::super::super::RnsNativeOriginalBudgetedSourceV1,
{
    /// Consume the sealed started owner through the complete claimed-qPCS,
    /// source-preflight, numeric-materialization, and schedule-extraction
    /// chronology. No intermediate owner or schedule escapes this call.
    pub(super) fn authenticate_claimed_qpcs_source_carrier_v2<'digests, 'proof>(
        self,
        relation_schedule: RnsNativeQpcsRelationScheduleV1,
        qpcs_transcript: ZkAmsMkheRnsNativeQpcsBoundTranscriptV1,
        terminal_roots: ZkAmsMkheRnsNativeTerminalRootsV1,
        input: RnsNativeClaimedQpcsAuthenticationInputV2<'digests, 'proof>,
    ) -> Result<
        RnsNativeClaimedQpcsSourceCarrierV2<'proof, S>,
        RnsNativeClaimedQpcsSourceCarrierErrorV2,
    > {
        let RnsNativeStartedPreTranscriptPublicStatementV2 {
            bridge,
            source,
            facts,
        } = self.started;
        let mut batch = RnsNativeSingleQpcsScheduleBatchV2::begin_v2(bridge, relation_schedule)
            .map_err(map_public_read_error_v2)?;
        for _ in 0..RELATIONS_V2 {
            batch
                .take_next_evaluation_v2()
                .map_err(map_public_read_error_v2)?;
        }
        let RnsNativeCompletedQpcsSourceReadV2 {
            owners,
            schedule,
            evaluations: public_evaluations,
            read_receipt,
        } = batch.finish_v2().map_err(map_public_read_error_v2)?;
        if public_evaluations.len() != RELATIONS_V2 {
            return Err(RnsNativeClaimedQpcsSourceCarrierErrorV2::InvalidCount);
        }

        let RnsNativeClaimedQpcsAuthenticationInputV2 {
            equation_commitment_digests,
            limb_commitment_digests,
            query_opening_digests,
            proof,
        } = input;
        let pre_auth =
            prepare_rns_native_qpcs_pre_auth_claimed_v1(schedule, qpcs_transcript, terminal_roots)
                .map_err(map_qpcs_error_v2)?;
        let authenticated = authenticate_rns_native_qpcs_pre_auth_claimed_v1(
            pre_auth,
            equation_commitment_digests,
            limb_commitment_digests,
            query_opening_digests,
            proof,
        )
        .map_err(map_qpcs_error_v2)?;

        // Copy only the exact arrays accepted by the successful qPCS call.
        // Query-opening digests remain construction-only.
        let equation_commitment_digests = *equation_commitment_digests;
        let limb_commitment_digests = *limb_commitment_digests;
        let public = RnsNativePublicArtifactViewV1::new(
            facts.epoch,
            facts.governed_roster_digest,
            &facts.public_a_limb_digests,
            &facts.public_b_limb_digests,
            &facts.ciphertext_c0_limb_digests,
            &facts.ciphertext_c1_limb_digests,
            &facts.records,
            facts.public_bundle_digest,
        );
        let preflighted = preflight_rns_native_qpcs_authenticated_claimed_source_v1(
            authenticated,
            facts.layout,
            facts.receipt,
            public,
            &equation_commitment_digests,
            &limb_commitment_digests,
            source,
        )
        .map_err(|_| RnsNativeClaimedQpcsSourceCarrierErrorV2::SourcePreflight)?;
        let claimed_source = preflighted
            .materialize_numeric_and_take_schedule_v1(&public_evaluations)
            .map_err(|_| RnsNativeClaimedQpcsSourceCarrierErrorV2::SourcePreflight)?;
        let carrier_binding_digest = carrier_binding_digest_v2(
            &owners,
            &read_receipt,
            &claimed_source,
            &equation_commitment_digests,
            &limb_commitment_digests,
        )?;
        Ok(RnsNativeClaimedQpcsSourceCarrierV2 {
            owned: RnsNativeClaimedQpcsOwnedStageV2 {
                retained: RnsNativeClaimedQpcsRetainedPublicationV2 {
                    owners,
                    read_receipt,
                    facts,
                    equation_commitment_digests,
                    limb_commitment_digests,
                    carrier_binding_digest,
                },
                stage: RnsNativeClaimedQpcsSourceStageV2 {
                    public_evaluations,
                    claimed_source,
                    cursor: RnsNativeClaimedSourceCursorV2::new_v2(),
                },
            },
        })
    }
}

fn map_public_read_error_v2(
    _: RnsNativeTailPublicationErrorV2,
) -> RnsNativeClaimedQpcsSourceCarrierErrorV2 {
    RnsNativeClaimedQpcsSourceCarrierErrorV2::PublicRead
}

fn map_qpcs_error_v2(
    _: RnsNativeQpcsFriCompleteErrorV1,
) -> RnsNativeClaimedQpcsSourceCarrierErrorV2 {
    RnsNativeClaimedQpcsSourceCarrierErrorV2::Qpcs
}

/// Scalar/count axes owned by the actual publication and native read receipt.
#[derive(Clone, Copy)]
struct CarrierBindingContextV1 {
    public: [[u8; 32]; 5],      // lifecycle, manifest, provider, snapshot, read-set
    native: [ProofDigestV1; 2], // qPCS schedule, claimed source
    objects: u16,
    counters: [u64; 4], // bytes, coefficients, multiplications, additions
}

fn carrier_binding_hash_v1(
    axes: CarrierBindingContextV1,
    equations: &[ProofDigestV1; EQUATIONS_V2],
    limbs: &[ProofDigestV1; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1],
) -> Result<ProofDigestV1, RnsNativeClaimedQpcsSourceCarrierErrorV2> {
    if axes.public.contains(&[0; 32])
        || axes.native.contains(&ProofDigestV1::ZERO)
        || equations.contains(&ProofDigestV1::ZERO)
        || limbs.contains(&ProofDigestV1::ZERO)
    {
        return Err(RnsNativeClaimedQpcsSourceCarrierErrorV2::InvalidBinding);
    }
    let geometry = [
        ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1,
        REPETITIONS_V2,
        RECORDS_V2,
        RELATIONS_V2,
    ]
    .map(|value| (value as u16).to_be_bytes());
    let version = [BINDING_VERSION_V1];
    let objects = axes.objects.to_be_bytes();
    let counters = axes.counters.map(u64::to_be_bytes);
    let mut fields: [&[u8]; 60] = [&[]; 60];
    fields[..18].copy_from_slice(&[
        CARRIER_BINDING_DOMAIN_V1,
        &version,
        &geometry[0],
        &geometry[1],
        &geometry[2],
        &geometry[3],
        &axes.public[0],
        &axes.public[1],
        axes.native[0].as_bytes(),
        &axes.public[2],
        &axes.public[3],
        &axes.public[4],
        &objects,
        &counters[0],
        &counters[1],
        &counters[2],
        &counters[3],
        axes.native[1].as_bytes(),
    ]);
    for (slot, digest) in fields[18..]
        .iter_mut()
        .zip(equations.iter().chain(limbs.iter()))
    {
        *slot = digest.as_bytes();
    }
    let context = RnsNativeProofHashContextV1::canonical()
        .map_err(|_| RnsNativeClaimedQpcsSourceCarrierErrorV2::InvalidBinding)?;
    let frame = context
        .frame(
            RnsNativeProofHashRoleV1::Transcript,
            RnsNativeProofHashPhaseV1::Binding,
            RnsNativeProofHashPositionV1 {
                level: 7,
                index: 0,
                counter: 0,
            },
            &fields,
        )
        .map_err(|_| RnsNativeClaimedQpcsSourceCarrierErrorV2::InvalidBinding)?;
    if fields.iter().map(|field| field.len()).sum::<usize>() != CARRIER_BINDING_HASH_BYTES_V2
        || RnsNativeProofHashWorkV1::from_frame(&frame)
            .map_err(|_| RnsNativeClaimedQpcsSourceCarrierErrorV2::InvalidBinding)?
            != CARRIER_BINDING_HASH_WORK_V1
    {
        return Err(RnsNativeClaimedQpcsSourceCarrierErrorV2::InvalidBinding);
    }
    let digest = ProofDigestV1::from_shared(frame.hash());
    if digest == ProofDigestV1::ZERO {
        return Err(RnsNativeClaimedQpcsSourceCarrierErrorV2::InvalidBinding);
    }
    Ok(digest)
}

fn carrier_binding_digest_v2<S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>(
    owners: &RnsNativeWholePublicationOwnersV2,
    receipt: &RnsNativePublicPolynomialReadReceiptV1,
    claimed_source: &RnsNativeQpcsSchedulelessClaimedSourceV1<'_, S>,
    equation_commitment_digests: &[ProofDigestV1; EQUATIONS_V2],
    limb_commitment_digests: &[ProofDigestV1; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1],
) -> Result<ProofDigestV1, RnsNativeClaimedQpcsSourceCarrierErrorV2> {
    carrier_binding_hash_v1(
        CarrierBindingContextV1 {
            public: [
                owners.lifecycle_digest,
                receipt.manifest_digest_v1(),
                receipt.provider_identity_v1(),
                receipt.snapshot_identity_v1(),
                receipt.read_set_digest_v1(),
            ],
            native: [
                receipt.qpcs_schedule_digest_v1(),
                claimed_source.claimed_source_binding_digest_v1(),
            ],
            objects: receipt.object_count_v1(),
            counters: [
                receipt.canonical_bytes_v1(),
                receipt.coefficient_count_v1(),
                receipt.modular_multiplications_v1(),
                receipt.modular_additions_v1(),
            ],
        },
        equation_commitment_digests,
        limb_commitment_digests,
    )
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<
        RnsNativeClaimedSuccessorV1<
            'proof,
            RnsNativeCrossFieldRlweClaimedInventoryParentV1<'source, 'proof, S>,
        >,
    >
{
    pub(in crate::vega::zk_ams::mkhe) fn verify_comparator_product_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeComparatorProductPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeComparatorProductErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_rns_native_comparator_product_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<RnsNativeComparatorProductPrerequisiteV1<'source, 'proof, S>>
{
    pub(in crate::vega::zk_ams::mkhe) fn verify_comparator_range_carry_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeComparatorRangeCarryPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeComparatorRangeCarryErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_rns_native_comparator_range_carry_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<
        RnsNativeComparatorRangeCarryPrerequisiteV1<'source, 'proof, S>,
    >
{
    pub(in crate::vega::zk_ams::mkhe) fn verify_small_sign_disjointness_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeSmallSignDisjointnessPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeSmallSignDisjointnessErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_rns_native_small_sign_disjointness_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<
        RnsNativeSmallSignDisjointnessPrerequisiteV1<'source, 'proof, S>,
    >
{
    pub(in crate::vega::zk_ams::mkhe) fn verify_q_mask_linear_relations_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeQMaskLinearRelationsPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeQMaskLinearRelationsErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_rns_native_q_mask_linear_relations_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<
        RnsNativeQMaskLinearRelationsPrerequisiteV1<'source, 'proof, S>,
    >
{
    pub(in crate::vega::zk_ams::mkhe) fn authenticate_existing_radix_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeExistingRadixCommitmentPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeExistingRadixCommitmentViewErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = authenticate_rns_native_existing_radix_commitment_view_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<
        RnsNativeExistingRadixCommitmentPrerequisiteV1<'source, 'proof, S>,
    >
{
    pub(in crate::vega::zk_ams::mkhe) fn verify_radix_complement_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeRadixComplementLinearPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeRadixComplementLinearErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_rns_native_radix_complement_linear_relation_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<
        RnsNativeRadixComplementLinearPrerequisiteV1<'source, 'proof, S>,
    >
{
    pub(in crate::vega::zk_ams::mkhe) fn verify_centering_subtraction_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeCenteringSubtractionPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeCenteringSubtractionErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_rns_native_centering_subtraction_relation_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<
        RnsNativeCenteringSubtractionPrerequisiteV1<'source, 'proof, S>,
    >
{
    pub(in crate::vega::zk_ams::mkhe) fn derive_global_lookup_pre_z_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeGlobalLookupPreZPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeGlobalLookupZCommitmentViewErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = derive_rns_native_global_lookup_pre_z_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<RnsNativeGlobalLookupPreZPrerequisiteV1<'source, 'proof, S>>
{
    pub(in crate::vega::zk_ams::mkhe) fn authenticate_global_lookup_post_z_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeGlobalLookupPostZPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeGlobalLookupZCommitmentViewErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = authenticate_rns_native_global_lookup_post_z_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<RnsNativeGlobalLookupPostZPrerequisiteV1<'source, 'proof, S>>
{
    pub(in crate::vega::zk_ams::mkhe) fn verify_global_inverse_product_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeGlobalInverseProductPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeGlobalInverseProductErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_rns_native_global_inverse_product_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<
        RnsNativeGlobalInverseProductPrerequisiteV1<'source, 'proof, S>,
    >
{
    pub(in crate::vega::zk_ams::mkhe) fn verify_global_membership_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeGlobalMembershipPrerequisiteV1<'source, 'proof, S>,
        >,
        RnsNativeGlobalMembershipDirectErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_rns_native_global_membership_v1(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<RnsNativeGlobalMembershipPrerequisiteV1<'source, 'proof, S>>
{
    pub(in crate::vega::zk_ams::mkhe) fn verify_direct_global_membership_handoff_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeDirectGlobalMembershipHandoffV1<'source, 'proof, S>,
        >,
        RnsNativeDirectGlobalMembershipHandoffErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_direct_global_membership_handoff_core_v2(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<RnsNativeDirectGlobalMembershipHandoffV1<'source, 'proof, S>>
{
    /// Consume the exact direct/membership handoff into the authenticated
    /// source-packing child while retaining the inseparable publication owner.
    pub(in crate::vega::zk_ams::mkhe) fn verify_source_packing_same_opening_v2(
        self,
    ) -> Result<
        RnsNativeClaimedQpcsOwnedStageV2<
            RnsNativeSourcePackingSameOpeningPrerequisiteV1<
                'proof,
                RnsNativeDirectGlobalMembershipHandoffV1<'source, 'proof, S>,
            >,
        >,
        RnsNativeSourcePackingSameOpeningErrorV1,
    > {
        let Self { retained, stage } = self;
        let stage = verify_rns_native_source_packing_same_opening_owned_v2(stage)?;
        Ok(RnsNativeClaimedQpcsOwnedStageV2 { retained, stage })
    }
}

impl<'source, 'proof, S: ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1>
    RnsNativeClaimedQpcsOwnedStageV2<
        RnsNativeSourcePackingSameOpeningPrerequisiteV1<
            'proof,
            RnsNativeDirectGlobalMembershipHandoffV1<'source, 'proof, S>,
        >,
    >
{
    /// Consume the complete retained-publication/direct/membership/
    /// same-opening lineage directly through the atomic composite verifier.
    /// No detached all-stage input or partial-stage result escapes this seam.
    pub(in crate::vega::zk_ams::mkhe) fn verify_composite_v2(
        self,
        envelope: &ZkAmsMkheRnsNativeProofEnvelopeV1,
    ) -> Result<
        ZkAmsMkheRnsNativeCompositeCandidateReceiptV1,
        RnsNativeClaimedQpcsCompositeVerificationErrorV2,
    > {
        let Self { retained, stage } = self;
        let qpcs_authority = RnsNativeQpcsCompositeAuthorityV2 { retained, envelope };
        let input = stage
            .into_composite_context_v2(qpcs_authority, envelope)
            .map_err(RnsNativeClaimedQpcsCompositeVerificationErrorV2::Handoff)?;
        verify_zk_ams_mkhe_rns_native_composite_from_source_chain_v2(input)
            .map_err(RnsNativeClaimedQpcsCompositeVerificationErrorV2::CompositeVerification)
    }
}

impl<'proof, Stage> RnsNativeSourcePackingCombinedDirectMembershipPredecessorV1<'proof>
    for RnsNativeClaimedQpcsOwnedStageV2<Stage>
where
    Stage: RnsNativeSourcePackingCombinedDirectMembershipPredecessorV1<'proof>,
{
    fn same_opening_successor_v1(&self) -> &'proof [u8] {
        self.stage.same_opening_successor_v1()
    }

    fn successor_independent_safe_core_v1(&self) -> RnsNativeSourcePackingSafeCoreV1 {
        self.stage.successor_independent_safe_core_v1()
    }

    fn combined_outer_bindings_v1(&self) -> RnsNativeSourcePackingCombinedOuterBindingsV1 {
        self.stage.combined_outer_bindings_v1()
    }
}

#[cfg(test)]
#[path = "claimed_qpcs_source_carrier_v2_tests.rs"]
mod tests;
