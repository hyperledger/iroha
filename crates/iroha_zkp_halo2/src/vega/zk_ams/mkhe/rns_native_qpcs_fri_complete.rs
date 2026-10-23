//! Complete correlated FRI closure for the replacement 40-limb qPCS.
//!
//! This private verifier consumes the authenticated fold-zero substage,
//! authenticates FRI layers two through seventeen, checks folds one through
//! sixteen, and derives the terminal degree equation directly from all four
//! authenticated layer-seventeen leaves.  No uncommitted terminal value is
//! accepted from the prover.  Successful verification remains non-authorizing:
//! the RLWE/source linkage is retained as a nonempty digest-bound residual and
//! the composite verifier continues to fail closed.

#[cfg(test)]
use super::rns_native_proof_hash::RnsNativeProofHashWorkV1;
#[cfg(test)]
use super::rns_native_proof_hash::{
    RnsNativeProofDigestV1 as ProofDigestV1, RnsNativeProofHashContextV1,
    RnsNativeProofHashPhaseV1, RnsNativeProofHashPositionV1, RnsNativeProofHashRoleV1,
    decode_proof_digest_v1,
};
use super::{
    manifest::ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1,
    rns_native_profile::{
        ZK_AMS_MKHE_RNS_NATIVE_CORRELATED_FRI_MAX_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1,
        ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1,
    },
    rns_native_qpcs_prefix::{
        DIGEST_BYTES_V1, LEAF_BYTES_V1, MAX_OPENED_LEAVES_V1, QUERY_COUNT_V1,
    },
    rns_native_transcript::ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1,
};
#[cfg(test)]
use super::{
    rns_native_cross_field_inventory::{
        RnsNativePreQpcsQMaskInventoryPreflightV1,
        authenticate_rns_native_cross_field_inventory_from_sealed_pre_qpcs_preflight_v1,
    },
    rns_native_cross_field_rlwe_direct::{
        RnsNativeCrossFieldRlweBoundPreDirectInventoryV1,
        RnsNativeCrossFieldRlweClaimedInventoryNumericV2,
        RnsNativeCrossFieldRlweClaimedQpcsInputV2, RnsNativeCrossFieldRlweDirectErrorV1,
        bind_authenticated_claimed_qpcs_inventory_direct_v2,
        bind_rns_native_cross_field_rlwe_pre_direct_inventory_v1,
    },
    rns_native_profile::{
        ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1, ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1,
        ZK_AMS_MKHE_RNS_NATIVE_QPCS_MAX_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1,
    },
    rns_native_public_polynomial_reader::RnsNativePublicPolynomialEvaluationV1,
    rns_native_qpcs_prefix::{
        DOMAIN_SIZE_V1, Fq2ParametersV1, Fq2V1, IndexSetV1, ROWS_PER_LIMB_V1,
        RnsNativeQpcsFoldZeroStageV1, RnsNativeQpcsRelationScheduleV1, TreeDescriptorV1,
        TreeRoleV1, TreeViewV1, authenticate_rns_native_qpcs_prefix_v1,
        authenticate_rns_native_qpcs_prefix_with_schedule_v1, authenticate_tree_v1,
        derive_fields_v1, descriptor_for_indices_v1, fold_value_with_inverse_x_v1,
        query_pair_indices_v1, read_value_v1, validate_leaf_values_v1,
    },
    rns_native_rlwe_source_statement::{
        RnsNativePublicArtifactViewV1, RnsNativeRlweSourceStatementErrorV1,
        RnsNativeRlweSourceStatementStageV1, preflight_rns_native_rlwe_source_statement_v1,
    },
    rns_native_section_codec::RnsNativePendingCrossFieldGlobalLookupContextV1,
    rns_native_source::{
        ZkAmsMkheRnsNativeSourceLayoutV1, ZkAmsMkheRnsNativeSourceReceiptV1,
        ZkAmsMkheRnsNativeSourceSnapshotV1,
    },
    rns_native_terminal_cross_basis::RnsNativeTerminalCrossBasisKernelPrerequisiteV1,
    rns_native_transcript::{
        ZkAmsMkheRnsNativeChallengeSeedsV1, ZkAmsMkheRnsNativeCrossFieldBoundTranscriptV1,
        ZkAmsMkheRnsNativeCrossFieldRootClaimV1,
        ZkAmsMkheRnsNativeCrossFieldRootEqualityObligationV1,
        ZkAmsMkheRnsNativeQpcsBoundTranscriptV1, ZkAmsMkheRnsNativeTerminalRootsV1,
    },
};

#[cfg(test)]
const CLOSURE_MAGIC_V1: [u8; 4] = *b"ZQFC";
#[cfg(test)]
const CLOSURE_VERSION_V1: u8 = 1;
const FIRST_ENCODED_LAYER_V1: usize = 2;
const LAST_LAYER_V1: usize = ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1 as usize - 1;
const ENCODED_LAYER_COUNT_V1: usize = LAST_LAYER_V1 - FIRST_ENCODED_LAYER_V1 + 1;
#[cfg(test)]
const FIRST_CHECKED_FOLD_V1: u8 = 1;
#[cfg(test)]
const LAST_CHECKED_FOLD_V1: u8 = ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1 - 1;
#[cfg(test)]
const TERMINAL_DERIVED_V1: u8 = 1;
const TREE_DESCRIPTOR_BYTES_V1: usize = 2 + 2 + 4 + 4;
pub(super) const CLOSURE_HEADER_BYTES_V1: usize = 4
    + 4
    + 2
    + 6
    + 2 * 2
    + 3 * 4
    + ENCODED_LAYER_COUNT_V1 * TREE_DESCRIPTOR_BYTES_V1
    + 32
    + 5 * DIGEST_BYTES_V1;
const MAX_FRI_OPENED_LEAVES_V1: usize = 4_028;
const MAX_FRI_AUTHENTICATION_HASHES_V1: usize = 20_030;

pub(super) const MAX_CORRELATED_FRI_AUTHENTICATION_BYTES_V1: usize =
    MAX_FRI_OPENED_LEAVES_V1 * LEAF_BYTES_V1 + MAX_FRI_AUTHENTICATION_HASHES_V1 * DIGEST_BYTES_V1;

#[cfg(test)]
const SCHEDULE_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.rns-native-qpcs.fri-complete.schedule";
#[cfg(test)]
const RESIDUAL_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.rns-native-qpcs.fri-complete.rlwe-source-residual";

/// Tranche-A source typestates and their private direct chronology are implemented,
/// but no live verification entry reaches them.
pub(super) const PRE_AUTH_CLAIMED_QPCS_TYPESTATE_SOURCE_IMPLEMENTED_V1: bool = true;
/// No live production verifier entry consumes the tranche-A owner yet.
pub(super) const PRE_AUTH_CLAIMED_QPCS_INTEGRATED_V1: bool = false;
/// The tranche-A owners grant no proof-verification authority.
pub(super) const PRE_AUTH_CLAIMED_QPCS_VERIFICATION_AUTHORITY_V1: bool = false;
/// The tranche-A owners grant no readiness authority.
pub(super) const PRE_AUTH_CLAIMED_QPCS_READINESS_V1: bool = false;
/// The tranche-A owners grant no release authority.
pub(super) const PRE_AUTH_CLAIMED_QPCS_RELEASE_READY_V1: bool = false;

const _: () = {
    assert!(ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1 == 18);
    assert!(FIRST_ENCODED_LAYER_V1 == 2);
    assert!(LAST_LAYER_V1 == 17);
    assert!(ENCODED_LAYER_COUNT_V1 == 16);
    assert!(CLOSURE_HEADER_BYTES_V1 == 496);
    assert!(QUERY_COUNT_V1 == 160);
    assert!(MAX_OPENED_LEAVES_V1 == 320);
    assert!(LEAF_BYTES_V1 == 6_000);
    assert!(MAX_FRI_OPENED_LEAVES_V1 == 4_028);
    assert!(MAX_FRI_AUTHENTICATION_HASHES_V1 == 20_030);
    assert!(ZK_AMS_MKHE_RNS_NATIVE_CORRELATED_FRI_MAX_BYTES_V1 == 26_409_984);
    assert!(PRE_AUTH_CLAIMED_QPCS_TYPESTATE_SOURCE_IMPLEMENTED_V1);
    assert!(!PRE_AUTH_CLAIMED_QPCS_INTEGRATED_V1);
    assert!(!PRE_AUTH_CLAIMED_QPCS_VERIFICATION_AUTHORITY_V1);
    assert!(!PRE_AUTH_CLAIMED_QPCS_READINESS_V1);
    assert!(!PRE_AUTH_CLAIMED_QPCS_RELEASE_READY_V1);
};

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RnsNativeQpcsFriCompleteErrorV1 {
    InvalidPrefix,
    InvalidContext,
    ProofCapExceeded,
    Truncated,
    TrailingBytes,
    InvalidHeader,
    InvalidCount,
    InvalidOrder,
    NonCanonicalResidue,
    InvalidMerklePath,
    InvalidChallenge,
    InvalidFriEquation,
    InvalidTerminalCoverage,
    InvalidTerminalDegree,
    ArithmeticOverflow,
}

#[cfg(test)]
impl core::fmt::Display for RnsNativeQpcsFriCompleteErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(test)]
impl std::error::Error for RnsNativeQpcsFriCompleteErrorV1 {}

#[cfg(test)]
#[derive(Clone, Copy)]
struct FriClosureContextV1 {
    parameter_digest: [u8; 32],
    transcript_digest: ProofDigestV1,
    qpcs_bound_transcript_state: ProofDigestV1,
    query_seed: ProofDigestV1,
    section_binding_digest: ProofDigestV1,
    roots: [ProofDigestV1; ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1 as usize],
    fold_seeds: [ProofDigestV1; ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1 as usize],
    schedule_digest: ProofDigestV1,
}

#[cfg(test)]
impl FriClosureContextV1 {
    fn from_transcript_v1(
        transcript: &ZkAmsMkheRnsNativeChallengeSeedsV1,
        prefix: &RnsNativeQpcsFoldZeroStageV1<'_>,
    ) -> Result<Self, RnsNativeQpcsFriCompleteErrorV1> {
        let roots = core::array::from_fn(|layer| transcript.qpcs_fri_roots()[layer].root());
        for (layer, root) in transcript.qpcs_fri_roots().iter().enumerate() {
            if usize::from(root.layer()) != layer {
                return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidOrder);
            }
        }
        let fold_seeds = *transcript.qpcs_fri_fold_challenge_seeds();
        let parameter_digest = prefix.parameter_digest();
        let transcript_digest = transcript.transcript_digest();
        let qpcs_bound_transcript_state = transcript.qpcs_bound_transcript_state_v1();
        let query_seed = transcript.qpcs_query_challenge_seed();
        let section_binding_digest = prefix.section_binding_digest();
        let canonical = RnsNativeProofHashContextV1::canonical()
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)?;
        if parameter_digest != canonical.parameter_digest()
            || transcript_digest != prefix.transcript_digest()
            || query_seed != prefix.query_seed()
            || roots[1] != prefix.fri_one_root()
            || [
                transcript_digest,
                qpcs_bound_transcript_state,
                query_seed,
                section_binding_digest,
            ]
            .contains(&ProofDigestV1::ZERO)
            || roots.contains(&ProofDigestV1::ZERO)
            || fold_seeds.contains(&ProofDigestV1::ZERO)
        {
            return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidContext);
        }
        let mut context = Self {
            parameter_digest,
            transcript_digest,
            qpcs_bound_transcript_state,
            query_seed,
            section_binding_digest,
            roots,
            fold_seeds,
            schedule_digest: ProofDigestV1::ZERO,
        };
        context.schedule_digest = schedule_digest_v1(context)?;
        Ok(context)
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct ClosureShapeV1 {
    indices: [IndexSetV1; ENCODED_LAYER_COUNT_V1],
    descriptors: [TreeDescriptorV1; ENCODED_LAYER_COUNT_V1],
    aggregate_opened: usize,
    aggregate_authentication: usize,
    aggregate_values_bytes: usize,
    aggregate_authentication_bytes: usize,
}

#[cfg(test)]
struct ClosureViewV1<'a> {
    layers: [TreeViewV1<'a>; ENCODED_LAYER_COUNT_V1],
    downstream_residual: &'a [u8],
}

#[cfg(test)]
struct DecoderV1<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

#[cfg(test)]
impl<'a> DecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RnsNativeQpcsFriCompleteErrorV1> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::Truncated)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RnsNativeQpcsFriCompleteErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RnsNativeQpcsFriCompleteErrorV1> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, RnsNativeQpcsFriCompleteErrorV1> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::Truncated)?,
        ))
    }

    fn public_digest(&mut self) -> Result<[u8; 32], RnsNativeQpcsFriCompleteErrorV1> {
        self.take(32)?
            .try_into()
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::Truncated)
    }

    fn digest(&mut self) -> Result<ProofDigestV1, RnsNativeQpcsFriCompleteErrorV1> {
        decode_proof_digest_v1(self.take(DIGEST_BYTES_V1)?)
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidHeader)
    }
}

/// Move-only internal output after the complete qPCS FRI argument.
///
/// The retained bytes still require the separate RLWE/source-linkage verifier;
/// this token is therefore deliberately non-authorizing.
#[cfg(test)]
#[allow(
    dead_code,
    missing_copy_implementations,
    reason = "the following private RLWE/source milestone will consume this stage once"
)]
pub(super) struct RnsNativeQpcsFriCompleteStageV1<'a> {
    relation_schedule: Option<RnsNativeQpcsRelationScheduleV1>,
    qpcs_bound_transcript_state: ProofDigestV1,
    parameter_digest: [u8; 32],
    transcript_digest: ProofDigestV1,
    query_seed: ProofDigestV1,
    section_binding_digest: ProofDigestV1,
    schedule_digest: ProofDigestV1,
    evaluations: &'a [u8],
    evaluation_binding_digest: ProofDigestV1,
    residual_digest: ProofDigestV1,
    rlwe_source_residual: &'a [u8],
}

/// Move-only owner created before qPCS authentication from the sole lineaged
/// relation schedule, the exact qPCS-bound transcript, and all claimed
/// terminal roots.
///
/// Its provisional terminal chronology is non-authorizing and retains three
/// undisclosed root-equality obligations.  The schedule cannot be borrowed or
/// extracted; it can only move into the authentication transition below.
#[cfg(test)]
#[allow(
    dead_code,
    missing_copy_implementations,
    reason = "the sole schedule and provisional chronology must move together exactly once"
)]
#[must_use = "the pre-auth claimed-qPCS owner must be consumed by qPCS authentication"]
pub(super) struct RnsNativeQpcsPreAuthClaimedV1 {
    relation_schedule: RnsNativeQpcsRelationScheduleV1,
    expected_qpcs_bound_transcript_state: ProofDigestV1,
    terminal_chronology: ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1,
}

/// Move-only non-authorizing owner after qPCS authenticates under the final
/// seeds produced by the same claimed terminal chronology.
///
/// The authenticated qPCS stage still owns the sole relation schedule and the
/// terminal chronology still owns every undisclosed equality obligation.
#[cfg(test)]
#[allow(
    dead_code,
    missing_copy_implementations,
    reason = "authenticated qPCS and its claimed terminal chronology must remain one-shot"
)]
#[must_use = "authenticated claimed qPCS is incomplete until successor obligations are discharged"]
pub(super) struct RnsNativeQpcsAuthenticatedClaimedV1<'a> {
    qpcs: RnsNativeQpcsFriCompleteStageV1<'a>,
    terminal_chronology: ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1,
}

/// Move-only joint owner proving that a completed qPCS relation schedule and
/// a qPCS-bound transcript descend from the same one-shot relation lineage and
/// have the exact post-FRI, pre-cross-field transcript state retained by this
/// completed closure.
///
/// Construction is private to this module and occurs only by consuming the
/// retained schedule from a successfully completed FRI stage.  In particular,
/// the legacy schedule reconstructed from final public challenge seeds cannot
/// construct this owner.
#[cfg(test)]
#[allow(
    dead_code,
    missing_copy_implementations,
    reason = "the completed qPCS lineage and its sole transcript must move together"
)]
pub(super) struct RnsNativeQpcsCompletedLineageV1 {
    relation_schedule: RnsNativeQpcsRelationScheduleV1,
    qpcs_transcript: Option<ZkAmsMkheRnsNativeQpcsBoundTranscriptV1>,
}

/// Leaf-private one-shot proof that the claimed qPCS schedule, provisional
/// terminal chronology, authenticated numeric tails, and source binding were
/// destructured from one authenticated claimed owner in this module.
///
/// The type name is visible to the direct module, but its tuple field and sole
/// construction site remain private here. It has no constructor, clone, copy,
/// getter, or raw-parts surface.
#[cfg(test)]
#[allow(
    missing_copy_implementations,
    dead_code,
    reason = "the direct claimed-qPCS input must consume this leaf-private origin once"
)]
pub(super) struct RnsNativeAuthenticatedClaimedQpcsOriginV2(());

const CLAIMED_SOURCE_REPETITIONS_V1: usize = 5;
const CLAIMED_SOURCE_RELATIONS_V1: usize =
    ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1 * CLAIMED_SOURCE_REPETITIONS_V1;
const CLAIMED_SOURCE_QPCS_PAIR_BYTES_V1: usize = 2 * core::mem::size_of::<u64>();
const CLAIMED_SOURCE_QPCS_EVALUATION_BYTES_V1: usize =
    CLAIMED_SOURCE_RELATIONS_V1 * CLAIMED_SOURCE_QPCS_PAIR_BYTES_V1;
#[cfg(test)]
const CLAIMED_SOURCE_RING_POWER_SQUARINGS_V1: usize = 17;
const CLAIMED_SOURCE_BINDING_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.rns-native-qpcs.claimed-source-numeric-binding";
pub(super) const RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_BYTES_V1: usize =
    CLAIMED_SOURCE_BINDING_DOMAIN_V1.len()
        + 1
        + 3 * 32
        + 10 * DIGEST_BYTES_V1
        + RNS_NATIVE_QPCS_CLAIMED_NUMERIC_TAIL_BYTES_V1;

/// Exact work of the sole claimed-source numeric frame, checked at hashing.
/// The catalog is 32 bytes; proof commitments remain 48 bytes.
#[cfg(test)]
pub(super) const RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_WORK_V1: RnsNativeProofHashWorkV1 =
    match RnsNativeProofHashWorkV1::from_word_count(872) {
        Ok(work) => work,
        Err(_) => panic!("fixed claimed-source hash frame must fit"),
    };

pub(super) const RNS_NATIVE_QPCS_CLAIMED_NUMERIC_TAIL_BYTES_V1: usize =
    CLAIMED_SOURCE_RELATIONS_V1 * core::mem::size_of::<RnsNativeQpcsAuthenticatedNumericTailV1>();
pub(super) const RNS_NATIVE_QPCS_CLAIMED_TERMINAL_CHRONOLOGY_BYTES_V1: usize =
    core::mem::size_of::<ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1>();

const _: () = {
    assert!(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 == 1 << 17);
    assert!(CLAIMED_SOURCE_RELATIONS_V1 == 200);
    assert!(CLAIMED_SOURCE_QPCS_EVALUATION_BYTES_V1 == 3_200);
    assert!(core::mem::size_of::<RnsNativeQpcsAuthenticatedNumericTailV1>() == 24);
    assert!(RNS_NATIVE_QPCS_CLAIMED_NUMERIC_TAIL_BYTES_V1 == 4_800);
    assert!(RNS_NATIVE_QPCS_CLAIMED_TERMINAL_CHRONOLOGY_BYTES_V1 == 6_264);
    assert!(RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_BYTES_V1 == 5_444);
};

/// The only retained qPCS values needed by a schedule-free direct numeric
/// cursor. Row identity is implicit in the fixed limb-major/repetition-major
/// array position, so no caller-controlled ordinal is retained.
#[derive(Clone, Copy)]
#[repr(C)]
pub(super) struct RnsNativeQpcsAuthenticatedNumericTailV1 {
    a: u64,
    product: u64,
    opening_quotient: u64,
}

impl RnsNativeQpcsAuthenticatedNumericTailV1 {
    #[cfg(test)]
    const UNFILLED: Self = Self {
        a: u64::MAX,
        product: u64::MAX,
        opening_quotient: u64::MAX,
    };

    #[cfg(test)]
    pub(super) const fn values_v1(self) -> (u64, u64, u64) {
        (self.a, self.product, self.opening_quotient)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RnsNativeQpcsClaimedSourceErrorV1 {
    SourcePreflight,
    Inventory,
    InvalidCount,
    InvalidOrder,
    InvalidPoint,
    NonCanonicalResidue,
    ZeroFactor,
    InvalidRelation,
    InvalidBinding,
}

#[cfg(test)]
impl core::fmt::Display for RnsNativeQpcsClaimedSourceErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(test)]
impl std::error::Error for RnsNativeQpcsClaimedSourceErrorV1 {}

/// Opaque owner after the exact authenticated-claimed qPCS has passed source
/// preflight. The sole schedule is still present inside `source.qpcs()` and
/// the complete two-obligation terminal chronology remains paired with it.
#[cfg(test)]
#[allow(
    dead_code,
    missing_copy_implementations,
    reason = "numeric materialization consumes this source-only intermediate exactly once"
)]
#[must_use = "source-preflighted claimed qPCS must be consumed by numeric materialization"]
pub(super) struct RnsNativeQpcsPreflightedClaimedSourceV1<
    'proof,
    S: ZkAmsMkheRnsNativeSourceSnapshotV1,
> {
    source: RnsNativeRlweSourceStatementStageV1<'proof, S>,
    terminal_chronology: ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1,
}

/// Opaque schedule-free source owner after all 200 authenticated numeric tails
/// have been materialized. It retains, but does not expose, the one extracted
/// relation schedule and the whole provisional chronology. In particular it
/// cannot be converted to the legacy completed-lineage or claimed-relation
/// owners, either of which would lose this chronology.
#[cfg(test)]
#[allow(
    dead_code,
    missing_copy_implementations,
    reason = "the private source-chain/inventory carrier consumes this exact owner once"
)]
#[must_use = "schedule-free claimed source remains non-authorizing until every successor verifies"]
pub(super) struct RnsNativeQpcsSchedulelessClaimedSourceV1<
    'proof,
    S: ZkAmsMkheRnsNativeSourceSnapshotV1,
> {
    source: RnsNativeRlweSourceStatementStageV1<'proof, S>,
    relation_schedule: RnsNativeQpcsRelationScheduleV1,
    terminal_chronology: ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1,
    numeric_tails: [RnsNativeQpcsAuthenticatedNumericTailV1; CLAIMED_SOURCE_RELATIONS_V1],
    source_binding_digest: ProofDigestV1,
}

/// One move-only owner joining the authenticated claimed qPCS chronology to
/// the exact sealed cross-section allocation and its authenticated inventory.
///
/// The sole relation schedule and all three terminal-root obligations remain
/// recursively owned. No schedule, chronology, inventory bytes, or raw parts
/// can be projected from this type.
#[cfg(test)]
#[allow(
    dead_code,
    missing_copy_implementations,
    reason = "the direct claimed-relation transition must consume this exact joined owner"
)]
#[must_use = "claimed qPCS inventory chronology remains non-authorizing until direct and terminal-root equality discharge"]
pub(super) struct RnsNativeQpcsClaimedInventoryChronologyV2<
    'qpcs,
    'cross,
    S: ZkAmsMkheRnsNativeSourceSnapshotV1,
> {
    bound_pre_direct_inventory: RnsNativeCrossFieldRlweBoundPreDirectInventoryV1<'qpcs, 'cross, S>,
    relation_schedule: RnsNativeQpcsRelationScheduleV1,
    terminal_chronology: ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1,
    numeric_tails: [RnsNativeQpcsAuthenticatedNumericTailV1; CLAIMED_SOURCE_RELATIONS_V1],
    source_binding_digest: ProofDigestV1,
}

#[cfg(test)]
impl<S: ZkAmsMkheRnsNativeSourceSnapshotV1> RnsNativeQpcsSchedulelessClaimedSourceV1<'_, S> {
    pub(super) const fn claimed_source_binding_digest_v1(&self) -> ProofDigestV1 {
        self.source_binding_digest
    }
}

#[cfg(test)]
impl<'qpcs, S: ZkAmsMkheRnsNativeSourceSnapshotV1>
    RnsNativeQpcsSchedulelessClaimedSourceV1<'qpcs, S>
{
    /// Consume this owner and the exact sealed cross-section children into one
    /// authenticated inventory chronology. Final context is borrowed only
    /// from this owner's own provisional chronology; any failure drops the
    /// source, sole schedule, chronology, and both section children together.
    pub(super) fn authenticate_claimed_inventory_v2<'cross>(
        self,
        terminal: RnsNativeTerminalCrossBasisKernelPrerequisiteV1,
        pending_cross: RnsNativePendingCrossFieldGlobalLookupContextV1<'cross>,
        preflight: RnsNativePreQpcsQMaskInventoryPreflightV1<'cross>,
    ) -> Result<
        RnsNativeQpcsClaimedInventoryChronologyV2<'qpcs, 'cross, S>,
        RnsNativeQpcsClaimedSourceErrorV1,
    > {
        let Self {
            source,
            relation_schedule,
            terminal_chronology,
            numeric_tails,
            source_binding_digest,
        } = self;
        let bound = pending_cross
            .bind_final_context_v1(terminal_chronology.final_challenge_seeds_v1())
            .map_err(|_| RnsNativeQpcsClaimedSourceErrorV1::Inventory)?;
        let inventory =
            authenticate_rns_native_cross_field_inventory_from_sealed_pre_qpcs_preflight_v1(
                terminal_chronology.final_challenge_seeds_v1(),
                source,
                terminal,
                bound,
                preflight,
            )
            .map_err(|_| RnsNativeQpcsClaimedSourceErrorV1::Inventory)?;
        let bound_pre_direct_inventory =
            bind_rns_native_cross_field_rlwe_pre_direct_inventory_v1(inventory)
                .map_err(|_| RnsNativeQpcsClaimedSourceErrorV1::Inventory)?;
        Ok(RnsNativeQpcsClaimedInventoryChronologyV2 {
            bound_pre_direct_inventory,
            relation_schedule,
            terminal_chronology,
            numeric_tails,
            source_binding_digest,
        })
    }
}

#[cfg(test)]
impl<'qpcs, 'cross, S: ZkAmsMkheRnsNativeSourceSnapshotV1>
    RnsNativeQpcsClaimedInventoryChronologyV2<'qpcs, 'cross, S>
{
    /// Consume the authenticated claimed owner directly into the direct
    /// relation. This is the sole place that may create the transcript-empty
    /// completed lineage, and it immediately moves that lineage, the whole
    /// terminal chronology, inventory, and numeric tails into one direct
    /// owner.
    pub(super) fn bind_direct_claimed_relation_v2(
        self,
    ) -> Result<
        RnsNativeCrossFieldRlweClaimedInventoryNumericV2<'qpcs, 'cross, S>,
        RnsNativeCrossFieldRlweDirectErrorV1,
    > {
        let Self {
            bound_pre_direct_inventory,
            relation_schedule,
            terminal_chronology,
            numeric_tails,
            source_binding_digest,
        } = self;
        let completed_qpcs =
            RnsNativeQpcsCompletedLineageV1::from_authenticated_claimed_schedule_v2(
                relation_schedule,
            );
        let claimed_qpcs_origin = RnsNativeAuthenticatedClaimedQpcsOriginV2(());
        let claimed_qpcs_input =
            RnsNativeCrossFieldRlweClaimedQpcsInputV2::from_authenticated_claimed_qpcs_v2(
                claimed_qpcs_origin,
                completed_qpcs,
                terminal_chronology,
                numeric_tails,
                source_binding_digest,
            )?;
        bind_authenticated_claimed_qpcs_inventory_direct_v2(
            bound_pre_direct_inventory,
            claimed_qpcs_input,
        )
    }
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "the undeclared direct adapter consumes this completed qPCS owner"
)]
impl RnsNativeQpcsCompletedLineageV1 {
    /// Purpose-private constructor for the already-authenticated claimed-qPCS
    /// path. The schedule was lineaged and authenticated before terminal roots
    /// were provisionally bound; no raw schedule caller can reach this helper.
    fn from_authenticated_claimed_schedule_v2(
        relation_schedule: RnsNativeQpcsRelationScheduleV1,
    ) -> Self {
        Self {
            relation_schedule,
            qpcs_transcript: None,
        }
    }

    fn from_completed_fri_v1(
        relation_schedule: RnsNativeQpcsRelationScheduleV1,
        expected_qpcs_bound_transcript_state: ProofDigestV1,
        qpcs_transcript: ZkAmsMkheRnsNativeQpcsBoundTranscriptV1,
    ) -> Result<Self, RnsNativeQpcsFriCompleteErrorV1> {
        relation_schedule
            .validate_qpcs_bound_lineage_v1(&qpcs_transcript)
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)?;
        if expected_qpcs_bound_transcript_state == ProofDigestV1::ZERO
            || qpcs_transcript.binding_digest() != expected_qpcs_bound_transcript_state
        {
            return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidContext);
        }
        Ok(Self {
            relation_schedule,
            qpcs_transcript: Some(qpcs_transcript),
        })
    }

    pub(super) const fn relation_schedule_v1(&self) -> &RnsNativeQpcsRelationScheduleV1 {
        &self.relation_schedule
    }

    pub(super) const fn has_unconsumed_qpcs_transcript_v1(&self) -> bool {
        self.qpcs_transcript.is_some()
    }

    #[cfg(test)]
    pub(super) fn qpcs_transcript_binding_digest_v1(
        &self,
    ) -> Result<ProofDigestV1, RnsNativeQpcsFriCompleteErrorV1> {
        self.qpcs_transcript
            .as_ref()
            .map(ZkAmsMkheRnsNativeQpcsBoundTranscriptV1::binding_digest)
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::InvalidOrder)
    }

    pub(super) fn take_qpcs_transcript_v1(
        &mut self,
    ) -> Result<ZkAmsMkheRnsNativeQpcsBoundTranscriptV1, RnsNativeQpcsFriCompleteErrorV1> {
        self.qpcs_transcript
            .take()
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::InvalidOrder)
    }

    /// Consume the sole retained qPCS transcript into the complete provisional
    /// three-root chronology. The schedule stays owned by this lineage and is
    /// left transcript-empty for the direct cross-root obligation.
    pub(super) fn bind_provisional_terminal_chronology_v1(
        &mut self,
        roots: ZkAmsMkheRnsNativeTerminalRootsV1,
    ) -> Result<ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1, RnsNativeQpcsFriCompleteErrorV1>
    {
        self.take_qpcs_transcript_v1()?
            .bind_provisional_terminal_chronology_v1(roots)
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)
    }

    /// Consume the sole qPCS transcript against an authenticated claimed
    /// cross-field root.  The returned transcript is provisional until the
    /// opaque equality obligation is discharged by the direct verifier.
    pub(super) fn bind_claimed_cross_field_root_v1(
        &mut self,
        claim: ZkAmsMkheRnsNativeCrossFieldRootClaimV1,
    ) -> Result<
        (
            ZkAmsMkheRnsNativeCrossFieldBoundTranscriptV1,
            ZkAmsMkheRnsNativeCrossFieldRootEqualityObligationV1,
        ),
        RnsNativeQpcsFriCompleteErrorV1,
    > {
        self.take_qpcs_transcript_v1()?
            .bind_claimed_cross_field_root_v1(claim)
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)
    }

    #[cfg(test)]
    pub(super) fn test_fixture_v1(
        relation_schedule: RnsNativeQpcsRelationScheduleV1,
        expected_qpcs_bound_transcript_state: ProofDigestV1,
        qpcs_transcript: ZkAmsMkheRnsNativeQpcsBoundTranscriptV1,
    ) -> Result<Self, RnsNativeQpcsFriCompleteErrorV1> {
        Self::from_completed_fri_v1(
            relation_schedule,
            expected_qpcs_bound_transcript_state,
            qpcs_transcript,
        )
    }
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "the private RLWE/source verifier will consume these retained bindings; the current composite boundary must remain fail-closed"
)]
impl<'a> RnsNativeQpcsFriCompleteStageV1<'a> {
    pub(super) const fn has_relation_schedule_v1(&self) -> bool {
        self.relation_schedule.is_some()
    }

    /// Borrow the sole authenticated relation schedule without transferring
    /// or duplicating its one-shot lineage.
    pub(super) fn relation_schedule_v1(
        &self,
    ) -> Result<&RnsNativeQpcsRelationScheduleV1, RnsNativeQpcsFriCompleteErrorV1> {
        self.relation_schedule
            .as_ref()
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::InvalidOrder)
    }

    pub(super) fn take_relation_schedule_v1(
        &mut self,
    ) -> Result<RnsNativeQpcsRelationScheduleV1, RnsNativeQpcsFriCompleteErrorV1> {
        self.relation_schedule
            .take()
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::InvalidOrder)
    }

    /// Consume the retained one-shot schedule into a joint owner with the
    /// matching exact qPCS-bound transcript. This transition is the only
    /// production constructor for `RnsNativeQpcsCompletedLineageV1`.
    pub(super) fn take_completed_qpcs_lineage_v1(
        &mut self,
        qpcs_transcript: ZkAmsMkheRnsNativeQpcsBoundTranscriptV1,
    ) -> Result<RnsNativeQpcsCompletedLineageV1, RnsNativeQpcsFriCompleteErrorV1> {
        let expected_qpcs_bound_transcript_state = self.qpcs_bound_transcript_state;
        let relation_schedule = self.take_relation_schedule_v1()?;
        RnsNativeQpcsCompletedLineageV1::from_completed_fri_v1(
            relation_schedule,
            expected_qpcs_bound_transcript_state,
            qpcs_transcript,
        )
    }

    pub(super) const fn parameter_digest(&self) -> [u8; 32] {
        self.parameter_digest
    }

    pub(super) const fn transcript_digest(&self) -> ProofDigestV1 {
        self.transcript_digest
    }

    pub(super) const fn query_seed(&self) -> ProofDigestV1 {
        self.query_seed
    }

    pub(super) const fn section_binding_digest(&self) -> ProofDigestV1 {
        self.section_binding_digest
    }

    pub(super) const fn schedule_digest(&self) -> ProofDigestV1 {
        self.schedule_digest
    }

    pub(super) const fn evaluations(&self) -> &'a [u8] {
        self.evaluations
    }

    pub(super) const fn evaluation_binding_digest(&self) -> ProofDigestV1 {
        self.evaluation_binding_digest
    }

    pub(super) const fn residual_digest(&self) -> ProofDigestV1 {
        self.residual_digest
    }

    pub(super) const fn rlwe_source_residual(&self) -> &'a [u8] {
        self.rlwe_source_residual
    }
}

/// Consume the sole lineaged schedule and exact qPCS transcript before any
/// terminal root is provisionally bound.
///
/// # Errors
///
/// Rejects a schedule from another relation lineage, a legacy unlineaged
/// schedule, roots tagged for another qPCS state, or invalid terminal binding.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "tranche A defines the source typestate before production orchestration is integrated"
)]
pub(super) fn prepare_rns_native_qpcs_pre_auth_claimed_v1(
    relation_schedule: RnsNativeQpcsRelationScheduleV1,
    qpcs_transcript: ZkAmsMkheRnsNativeQpcsBoundTranscriptV1,
    terminal_roots: ZkAmsMkheRnsNativeTerminalRootsV1,
) -> Result<RnsNativeQpcsPreAuthClaimedV1, RnsNativeQpcsFriCompleteErrorV1> {
    let expected_qpcs_bound_transcript_state = qpcs_transcript.binding_digest();
    if expected_qpcs_bound_transcript_state == ProofDigestV1::ZERO {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidContext);
    }
    relation_schedule
        .validate_qpcs_bound_lineage_v1(&qpcs_transcript)
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)?;
    let terminal_chronology = qpcs_transcript
        .bind_provisional_terminal_chronology_v1(terminal_roots)
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)?;
    if !terminal_chronology
        .matches_qpcs_bound_transcript_state_v1(expected_qpcs_bound_transcript_state)
    {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidContext);
    }
    Ok(RnsNativeQpcsPreAuthClaimedV1 {
        relation_schedule,
        expected_qpcs_bound_transcript_state,
        terminal_chronology,
    })
}

/// Authenticate qPCS using the final seeds and the exact schedule already
/// owned by the pre-auth claimed typestate.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "tranche A defines the source transition before production orchestration is integrated"
)]
pub(super) fn authenticate_rns_native_qpcs_pre_auth_claimed_v1<'a>(
    claimed: RnsNativeQpcsPreAuthClaimedV1,
    equation_commitment_digests: &[ProofDigestV1],
    limb_commitment_digests: &[ProofDigestV1],
    query_opening_digests: &[ProofDigestV1],
    proof: &'a [u8],
) -> Result<RnsNativeQpcsAuthenticatedClaimedV1<'a>, RnsNativeQpcsFriCompleteErrorV1> {
    let RnsNativeQpcsPreAuthClaimedV1 {
        relation_schedule,
        expected_qpcs_bound_transcript_state,
        terminal_chronology,
    } = claimed;
    let qpcs = authenticate_rns_native_qpcs_fri_complete_with_schedule_v1(
        terminal_chronology.final_challenge_seeds_v1(),
        relation_schedule,
        equation_commitment_digests,
        limb_commitment_digests,
        query_opening_digests,
        proof,
    )?;
    finish_rns_native_qpcs_pre_auth_claimed_v1(
        qpcs,
        expected_qpcs_bound_transcript_state,
        terminal_chronology,
    )
}

#[cfg(test)]
fn finish_rns_native_qpcs_pre_auth_claimed_v1<'a>(
    qpcs: RnsNativeQpcsFriCompleteStageV1<'a>,
    expected_qpcs_bound_transcript_state: ProofDigestV1,
    terminal_chronology: ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1,
) -> Result<RnsNativeQpcsAuthenticatedClaimedV1<'a>, RnsNativeQpcsFriCompleteErrorV1> {
    if qpcs.relation_schedule.is_none()
        || qpcs.qpcs_bound_transcript_state != expected_qpcs_bound_transcript_state
        || !terminal_chronology
            .matches_qpcs_bound_transcript_state_v1(qpcs.qpcs_bound_transcript_state)
    {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidContext);
    }
    Ok(RnsNativeQpcsAuthenticatedClaimedV1 {
        qpcs,
        terminal_chronology,
    })
}

/// Consume the authenticated-claimed qPCS directly into source preflight.
/// The final seeds are borrowed only from its own provisional chronology and
/// the qPCS stage still owns the sole schedule throughout the preflight call.
/// No transcript, schedule, root, or chronology parts are returned.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn preflight_rns_native_qpcs_authenticated_claimed_source_v1<'proof, S>(
    authenticated: RnsNativeQpcsAuthenticatedClaimedV1<'proof>,
    layout: ZkAmsMkheRnsNativeSourceLayoutV1,
    receipt: ZkAmsMkheRnsNativeSourceReceiptV1,
    public: RnsNativePublicArtifactViewV1<'_>,
    equation_commitment_digests: &[ProofDigestV1],
    limb_commitment_digests: &[ProofDigestV1],
    snapshot: S,
) -> Result<RnsNativeQpcsPreflightedClaimedSourceV1<'proof, S>, RnsNativeQpcsClaimedSourceErrorV1>
where
    S: ZkAmsMkheRnsNativeSourceSnapshotV1,
{
    let RnsNativeQpcsAuthenticatedClaimedV1 {
        qpcs,
        terminal_chronology,
    } = authenticated;
    if !qpcs.has_relation_schedule_v1() {
        return Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidOrder);
    }
    let source = preflight_rns_native_rlwe_source_statement_v1(
        terminal_chronology.final_challenge_seeds_v1(),
        layout,
        receipt,
        public,
        equation_commitment_digests,
        limb_commitment_digests,
        snapshot,
        qpcs,
    )
    .map_err(map_claimed_source_preflight_error_v1)?;
    if !source.qpcs().has_relation_schedule_v1()
        || source.snapshot().layout().source_binding_digest()
            != terminal_chronology
                .final_challenge_seeds_v1()
                .source_binding_digest()
    {
        return Err(RnsNativeQpcsClaimedSourceErrorV1::SourcePreflight);
    }
    Ok(RnsNativeQpcsPreflightedClaimedSourceV1 {
        source,
        terminal_chronology,
    })
}

#[cfg(test)]
fn map_claimed_source_preflight_error_v1(
    _: RnsNativeRlweSourceStatementErrorV1,
) -> RnsNativeQpcsClaimedSourceErrorV1 {
    RnsNativeQpcsClaimedSourceErrorV1::SourcePreflight
}

#[cfg(test)]
impl<'proof, S: ZkAmsMkheRnsNativeSourceSnapshotV1>
    RnsNativeQpcsPreflightedClaimedSourceV1<'proof, S>
{
    /// Materialize all 200 authenticated numeric tails, then and only then
    /// extract the sole schedule. Any error consumes this entire owner and
    /// returns no schedule, chronology, source stage, or partial tail array.
    pub(super) fn materialize_numeric_and_take_schedule_v1(
        mut self,
        public_evaluations: &[RnsNativePublicPolynomialEvaluationV1],
    ) -> Result<
        RnsNativeQpcsSchedulelessClaimedSourceV1<'proof, S>,
        RnsNativeQpcsClaimedSourceErrorV1,
    > {
        if public_evaluations.len() != CLAIMED_SOURCE_RELATIONS_V1
            || self.source.qpcs().evaluations().len() != CLAIMED_SOURCE_QPCS_EVALUATION_BYTES_V1
            || !self.source.qpcs().has_relation_schedule_v1()
        {
            return Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount);
        }
        let mut numeric_tails =
            [RnsNativeQpcsAuthenticatedNumericTailV1::UNFILLED; CLAIMED_SOURCE_RELATIONS_V1];
        {
            let schedule = self
                .source
                .qpcs()
                .relation_schedule_v1()
                .map_err(|_| RnsNativeQpcsClaimedSourceErrorV1::InvalidOrder)?;
            for limb in 0..ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1 {
                for repetition in 0..CLAIMED_SOURCE_REPETITIONS_V1 {
                    let relation = limb * CLAIMED_SOURCE_REPETITIONS_V1 + repetition;
                    let point = schedule
                        .point(limb, repetition)
                        .ok_or(RnsNativeQpcsClaimedSourceErrorV1::InvalidPoint)?;
                    let (product, opening_quotient) =
                        claimed_source_qpcs_pair_v1(self.source.qpcs().evaluations(), relation)?;
                    numeric_tails[relation] = validate_claimed_source_numeric_tail_v1(
                        limb,
                        repetition,
                        point,
                        public_evaluations[relation],
                        product,
                        opening_quotient,
                    )?;
                }
            }
        }
        if numeric_tails.iter().any(|tail| {
            tail.a == u64::MAX || tail.product == u64::MAX || tail.opening_quotient == u64::MAX
        }) {
            return Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount);
        }
        let relation_schedule = self
            .source
            .take_qpcs_relation_schedule_v1()
            .map_err(|_| RnsNativeQpcsClaimedSourceErrorV1::InvalidOrder)?;
        if self.source.qpcs().has_relation_schedule_v1() {
            return Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidOrder);
        }
        let source_binding_digest = claimed_source_numeric_binding_digest_v1(
            &self.source,
            &relation_schedule,
            &self.terminal_chronology,
            &numeric_tails,
        )?;
        Ok(RnsNativeQpcsSchedulelessClaimedSourceV1 {
            source: self.source,
            relation_schedule,
            terminal_chronology: self.terminal_chronology,
            numeric_tails,
            source_binding_digest,
        })
    }
}

/// Exact mixed-role axes of the final claimed-source numeric binding.
///
/// Both ownership boundaries reconstruct these fields independently and call
/// this one frame owner. Computing a digest grants no source/proof authority.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct RnsNativeClaimedNumericBindingAxesV1 {
    pub(super) statement_anchor: ProofDigestV1,
    pub(super) preflight_statement: ProofDigestV1,
    pub(super) public_bundle: [u8; 32],
    pub(super) source_parameter: [u8; 32],
    pub(super) source_transcript: ProofDigestV1,
    pub(super) source_schedule: ProofDigestV1,
    pub(super) source_evaluation: ProofDigestV1,
    pub(super) source_residual: ProofDigestV1,
    pub(super) schedule_parameter: [u8; 32],
    pub(super) q_mask_s_root: ProofDigestV1,
    pub(super) pre_relation_transcript: ProofDigestV1,
    pub(super) relation_seed: ProofDigestV1,
    pub(super) final_transcript: ProofDigestV1,
}

#[cfg(test)]
impl RnsNativeClaimedNumericBindingAxesV1 {
    pub(super) fn digest_v1(
        self,
        numeric_tails: impl IntoIterator<Item = (u64, u64, u64)>,
    ) -> Result<ProofDigestV1, RnsNativeQpcsClaimedSourceErrorV1> {
        if self.public_bundle == [0; 32]
            || self.source_parameter != self.schedule_parameter
            || [
                self.statement_anchor,
                self.preflight_statement,
                self.source_transcript,
                self.source_schedule,
                self.source_evaluation,
                self.source_residual,
                self.q_mask_s_root,
                self.pre_relation_transcript,
                self.relation_seed,
                self.final_transcript,
            ]
            .contains(&ProofDigestV1::ZERO)
        {
            return Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidBinding);
        }
        let mut tails = [0_u8; RNS_NATIVE_QPCS_CLAIMED_NUMERIC_TAIL_BYTES_V1];
        let mut count = 0_usize;
        let mut entries = tails.chunks_exact_mut(24);
        for (a, product, opening_quotient) in numeric_tails {
            let entry = entries
                .next()
                .ok_or(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount)?;
            entry[..8].copy_from_slice(&a.to_be_bytes());
            entry[8..16].copy_from_slice(&product.to_be_bytes());
            entry[16..].copy_from_slice(&opening_quotient.to_be_bytes());
            count += 1;
        }
        if count != CLAIMED_SOURCE_RELATIONS_V1 {
            return Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount);
        }
        binding_hash_v1(
            ClosureBindingRoleV1::ClaimedSource,
            self.schedule_parameter,
            &[
                CLAIMED_SOURCE_BINDING_DOMAIN_V1,
                &[CLOSURE_VERSION_V1],
                self.statement_anchor.as_bytes(),
                self.preflight_statement.as_bytes(),
                &self.public_bundle,
                &self.source_parameter,
                self.source_transcript.as_bytes(),
                self.source_schedule.as_bytes(),
                self.source_evaluation.as_bytes(),
                self.source_residual.as_bytes(),
                &self.schedule_parameter,
                self.q_mask_s_root.as_bytes(),
                self.pre_relation_transcript.as_bytes(),
                self.relation_seed.as_bytes(),
                self.final_transcript.as_bytes(),
                &tails,
            ],
        )
        .map_err(|_| RnsNativeQpcsClaimedSourceErrorV1::InvalidBinding)
    }
}

#[cfg(test)]
fn claimed_source_numeric_binding_digest_v1<S: ZkAmsMkheRnsNativeSourceSnapshotV1>(
    source: &RnsNativeRlweSourceStatementStageV1<'_, S>,
    schedule: &RnsNativeQpcsRelationScheduleV1,
    terminal_chronology: &ZkAmsMkheRnsNativeProvisionalTerminalChronologyV1,
    numeric_tails: &[RnsNativeQpcsAuthenticatedNumericTailV1; CLAIMED_SOURCE_RELATIONS_V1],
) -> Result<ProofDigestV1, RnsNativeQpcsClaimedSourceErrorV1> {
    RnsNativeClaimedNumericBindingAxesV1 {
        statement_anchor: source.statement_anchor_digest(),
        preflight_statement: source.preflight_statement_digest(),
        public_bundle: source.public_bundle_digest(),
        source_parameter: source.qpcs().parameter_digest(),
        source_transcript: source.qpcs().transcript_digest(),
        source_schedule: source.qpcs().schedule_digest(),
        source_evaluation: source.qpcs().evaluation_binding_digest(),
        source_residual: source.qpcs().residual_digest(),
        schedule_parameter: schedule.parameter_digest(),
        q_mask_s_root: schedule.q_mask_s_root(),
        pre_relation_transcript: schedule.qpcs_pre_relation_transcript_digest(),
        relation_seed: schedule.relation_seed(),
        final_transcript: terminal_chronology
            .final_challenge_seeds_v1()
            .transcript_digest(),
    }
    .digest_v1(numeric_tails.iter().copied().map(|tail| tail.values_v1()))
}

#[cfg(test)]
fn claimed_source_qpcs_pair_v1(
    bytes: &[u8],
    relation: usize,
) -> Result<(u64, u64), RnsNativeQpcsClaimedSourceErrorV1> {
    if bytes.len() != CLAIMED_SOURCE_QPCS_EVALUATION_BYTES_V1
        || relation >= CLAIMED_SOURCE_RELATIONS_V1
    {
        return Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount);
    }
    let offset = relation
        .checked_mul(CLAIMED_SOURCE_QPCS_PAIR_BYTES_V1)
        .ok_or(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount)?;
    let product = u64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .and_then(|value| value.try_into().ok())
            .ok_or(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount)?,
    );
    let opening_quotient = u64::from_be_bytes(
        bytes
            .get(offset + 8..offset + 16)
            .and_then(|value| value.try_into().ok())
            .ok_or(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount)?,
    );
    Ok((product, opening_quotient))
}

#[cfg(test)]
fn validate_claimed_source_numeric_tail_v1(
    limb: usize,
    repetition: usize,
    point: u64,
    public: RnsNativePublicPolynomialEvaluationV1,
    product: u64,
    opening_quotient: u64,
) -> Result<RnsNativeQpcsAuthenticatedNumericTailV1, RnsNativeQpcsClaimedSourceErrorV1> {
    let modulus = *ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1
        .get(limb)
        .ok_or(RnsNativeQpcsClaimedSourceErrorV1::InvalidOrder)?;
    if repetition >= CLAIMED_SOURCE_REPETITIONS_V1 || point == 0 || point >= modulus {
        return Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidPoint);
    }
    if [
        point,
        public.public_a,
        public.public_b,
        product,
        opening_quotient,
    ]
    .iter()
    .chain(public.ciphertext_c0.iter())
    .chain(public.ciphertext_c1.iter())
    .any(|value| *value >= modulus)
    {
        return Err(RnsNativeQpcsClaimedSourceErrorV1::NonCanonicalResidue);
    }
    let point_to_n = claimed_source_ring_power_v1(point, modulus);
    let factor = claimed_source_mod_add_v1(point_to_n, 1, modulus);
    if factor == 0 {
        return Err(RnsNativeQpcsClaimedSourceErrorV1::ZeroFactor);
    }
    if product != claimed_source_mod_mul_v1(factor, opening_quotient, modulus) {
        return Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidRelation);
    }
    Ok(RnsNativeQpcsAuthenticatedNumericTailV1 {
        a: point,
        product,
        opening_quotient,
    })
}

#[cfg(test)]
fn claimed_source_mod_add_v1(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

#[cfg(test)]
fn claimed_source_mod_mul_v1(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

#[cfg(test)]
fn claimed_source_ring_power_v1(mut value: u64, modulus: u64) -> u64 {
    for _ in 0..CLAIMED_SOURCE_RING_POWER_SQUARINGS_V1 {
        value = claimed_source_mod_mul_v1(value, value, modulus);
    }
    value
}

/// Consume the authenticated fold-zero stage and complete correlated FRI.
#[cfg(test)]
pub(super) fn authenticate_rns_native_qpcs_fri_complete_v1<'a>(
    transcript: &ZkAmsMkheRnsNativeChallengeSeedsV1,
    equation_commitment_digests: &[ProofDigestV1],
    limb_commitment_digests: &[ProofDigestV1],
    query_opening_digests: &[ProofDigestV1],
    proof: &'a [u8],
) -> Result<RnsNativeQpcsFriCompleteStageV1<'a>, RnsNativeQpcsFriCompleteErrorV1> {
    let prefix = authenticate_rns_native_qpcs_prefix_v1(
        transcript,
        equation_commitment_digests,
        limb_commitment_digests,
        query_opening_digests,
        proof,
    )
    .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidPrefix)?;
    authenticate_fri_after_fold_zero_v1(transcript, prefix)
}

/// Complete qPCS while preserving the exact pre-terminal relation schedule.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "the typed qPCS/cross-field orchestration adapter is not declared yet"
)]
pub(super) fn authenticate_rns_native_qpcs_fri_complete_with_schedule_v1<'a>(
    transcript: &ZkAmsMkheRnsNativeChallengeSeedsV1,
    relation_schedule: RnsNativeQpcsRelationScheduleV1,
    equation_commitment_digests: &[ProofDigestV1],
    limb_commitment_digests: &[ProofDigestV1],
    query_opening_digests: &[ProofDigestV1],
    proof: &'a [u8],
) -> Result<RnsNativeQpcsFriCompleteStageV1<'a>, RnsNativeQpcsFriCompleteErrorV1> {
    let prefix = authenticate_rns_native_qpcs_prefix_with_schedule_v1(
        transcript,
        relation_schedule,
        equation_commitment_digests,
        limb_commitment_digests,
        query_opening_digests,
        proof,
    )
    .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidPrefix)?;
    authenticate_fri_after_fold_zero_v1(transcript, prefix)
}

#[cfg(test)]
fn authenticate_fri_after_fold_zero_v1<'a>(
    transcript: &ZkAmsMkheRnsNativeChallengeSeedsV1,
    mut prefix: RnsNativeQpcsFoldZeroStageV1<'a>,
) -> Result<RnsNativeQpcsFriCompleteStageV1<'a>, RnsNativeQpcsFriCompleteErrorV1> {
    let context = FriClosureContextV1::from_transcript_v1(transcript, &prefix)?;
    let relation_schedule = prefix
        .take_relation_schedule_v1()
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidPrefix)?;
    let closure_parts = FriClosurePartsV1 {
        queries: prefix.queries(),
        fri_one_indices: prefix.fri_one_indices(),
        fri_one_values: prefix.fri_one_values(),
        evaluations: prefix.evaluations(),
        evaluation_binding_digest: prefix.evaluation_binding_digest(),
        closure: prefix.residual(),
    };
    verify_closure_parts_with_retained_evaluations_v1(context, relation_schedule, closure_parts)
}

#[cfg(test)]
struct FriClosurePartsV1<'input, 'proof> {
    queries: &'input [u32; QUERY_COUNT_V1],
    fri_one_indices: IndexSetV1,
    fri_one_values: &'input [u8],
    evaluations: &'proof [u8],
    evaluation_binding_digest: ProofDigestV1,
    closure: &'proof [u8],
}

#[cfg(test)]
fn verify_closure_parts_with_retained_evaluations_v1<'proof>(
    context: FriClosureContextV1,
    relation_schedule: RnsNativeQpcsRelationScheduleV1,
    parts: FriClosurePartsV1<'_, 'proof>,
) -> Result<RnsNativeQpcsFriCompleteStageV1<'proof>, RnsNativeQpcsFriCompleteErrorV1> {
    let FriClosurePartsV1 {
        queries,
        fri_one_indices,
        fri_one_values,
        evaluations,
        evaluation_binding_digest,
        closure,
    } = parts;
    let shape = closure_shape_v1(queries)?;
    let expected_fri_one = query_pair_indices_v1(queries, DOMAIN_SIZE_V1 / 2)
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidPrefix)?;
    if fri_one_indices.values[..fri_one_indices.len]
        != expected_fri_one.values[..expected_fri_one.len]
        || fri_one_values.len() != fri_one_indices.len * LEAF_BYTES_V1
        || evaluations.len() != ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1 * 5 * 2 * 8
        || evaluation_binding_digest == ProofDigestV1::ZERO
    {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidPrefix);
    }
    let view = decode_closure_exact_v1(closure, context, shape)?;
    for ordinal in 0..ENCODED_LAYER_COUNT_V1 {
        let layer = FIRST_ENCODED_LAYER_V1 + ordinal;
        let length = DOMAIN_SIZE_V1 >> layer;
        validate_leaf_values_v1(view.layers[ordinal].values, shape.indices[ordinal].len).map_err(
            |error| match error {
                super::rns_native_qpcs_prefix::RnsNativeQpcsPrefixErrorV1::NonCanonicalResidue => {
                    RnsNativeQpcsFriCompleteErrorV1::NonCanonicalResidue
                }
                _ => RnsNativeQpcsFriCompleteErrorV1::InvalidCount,
            },
        )?;
        authenticate_tree_v1(
            view.layers[ordinal],
            shape.indices[ordinal],
            length,
            TreeRoleV1::Fri,
            u8::try_from(layer).map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?,
            context.parameter_digest,
            context.roots[layer],
        )
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidMerklePath)?;
    }
    let fields = derive_fields_v1().map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)?;
    let mut current_indices = fri_one_indices;
    let mut current_values = fri_one_values;
    for layer in 1..LAST_LAYER_V1 {
        let next = layer + 1 - FIRST_ENCODED_LAYER_V1;
        verify_fold_v1(
            context,
            &fields,
            queries,
            layer,
            current_indices,
            current_values,
            shape.indices[next],
            view.layers[next].values,
        )?;
        current_indices = shape.indices[next];
        current_values = view.layers[next].values;
    }
    verify_terminal_degree_v1(context, &fields, current_indices, current_values)?;
    let residual_digest = residual_digest_v1(context, view.downstream_residual)?;
    Ok(RnsNativeQpcsFriCompleteStageV1 {
        relation_schedule: Some(relation_schedule),
        qpcs_bound_transcript_state: context.qpcs_bound_transcript_state,
        parameter_digest: context.parameter_digest,
        transcript_digest: context.transcript_digest,
        query_seed: context.query_seed,
        section_binding_digest: context.section_binding_digest,
        schedule_digest: context.schedule_digest,
        evaluations,
        evaluation_binding_digest,
        residual_digest,
        rlwe_source_residual: view.downstream_residual,
    })
}

#[cfg(test)]
fn verify_closure_parts_v1<'a>(
    context: FriClosureContextV1,
    queries: &[u32; QUERY_COUNT_V1],
    fri_one_indices: IndexSetV1,
    fri_one_values: &[u8],
    closure: &'a [u8],
) -> Result<RnsNativeQpcsFriCompleteStageV1<'a>, RnsNativeQpcsFriCompleteErrorV1> {
    static TEST_EVALUATIONS_V1: [u8; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1 * 5 * 2 * 8] =
        [0; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1 * 5 * 2 * 8];
    let closure_parts = FriClosurePartsV1 {
        queries,
        fri_one_indices,
        fri_one_values,
        evaluations: &TEST_EVALUATIONS_V1,
        evaluation_binding_digest: super::rns_native_proof_hash::test_proof_digest_v1(
            b"fri-complete-evaluation",
            0,
        ),
        closure,
    };
    verify_closure_parts_with_retained_evaluations_v1(
        context,
        RnsNativeQpcsRelationScheduleV1::test_fixture_v1(context.parameter_digest),
        closure_parts,
    )
}

#[cfg(test)]
fn closure_shape_v1(
    queries: &[u32; QUERY_COUNT_V1],
) -> Result<ClosureShapeV1, RnsNativeQpcsFriCompleteErrorV1> {
    let empty_indices = IndexSetV1 {
        values: [0; MAX_OPENED_LEAVES_V1],
        len: 0,
    };
    let empty_descriptor = TreeDescriptorV1 {
        opened: 0,
        authentication: 0,
        values_bytes: 0,
        authentication_bytes: 0,
    };
    let mut indices = [empty_indices; ENCODED_LAYER_COUNT_V1];
    let mut descriptors = [empty_descriptor; ENCODED_LAYER_COUNT_V1];
    let mut aggregate_opened = 0_usize;
    let mut aggregate_authentication = 0_usize;
    let mut aggregate_values_bytes = 0_usize;
    let mut aggregate_authentication_bytes = 0_usize;
    for layer in 0..=LAST_LAYER_V1 {
        let length = DOMAIN_SIZE_V1 >> layer;
        let layer_indices = query_pair_indices_v1(queries, length)
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidCount)?;
        let descriptor = descriptor_for_indices_v1(layer_indices, length)
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidCount)?;
        aggregate_opened = aggregate_opened
            .checked_add(descriptor.opened)
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
        aggregate_authentication = aggregate_authentication
            .checked_add(descriptor.authentication)
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
        aggregate_values_bytes = aggregate_values_bytes
            .checked_add(descriptor.values_bytes)
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
        aggregate_authentication_bytes = aggregate_authentication_bytes
            .checked_add(descriptor.authentication_bytes)
            .ok_or(RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
        if layer >= FIRST_ENCODED_LAYER_V1 {
            let ordinal = layer - FIRST_ENCODED_LAYER_V1;
            indices[ordinal] = layer_indices;
            descriptors[ordinal] = descriptor;
        }
    }
    let aggregate_bytes = aggregate_values_bytes
        .checked_add(aggregate_authentication_bytes)
        .ok_or(RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
    if aggregate_opened > MAX_FRI_OPENED_LEAVES_V1
        || aggregate_authentication > MAX_FRI_AUTHENTICATION_HASHES_V1
        || aggregate_bytes > ZK_AMS_MKHE_RNS_NATIVE_CORRELATED_FRI_MAX_BYTES_V1 as usize
    {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidCount);
    }
    Ok(ClosureShapeV1 {
        indices,
        descriptors,
        aggregate_opened,
        aggregate_authentication,
        aggregate_values_bytes,
        aggregate_authentication_bytes,
    })
}

#[cfg(test)]
fn decode_closure_exact_v1<'a>(
    closure: &'a [u8],
    context: FriClosureContextV1,
    shape: ClosureShapeV1,
) -> Result<ClosureViewV1<'a>, RnsNativeQpcsFriCompleteErrorV1> {
    if closure.len() > ZK_AMS_MKHE_RNS_NATIVE_QPCS_MAX_BYTES_V1 as usize {
        return Err(RnsNativeQpcsFriCompleteErrorV1::ProofCapExceeded);
    }
    if closure.len() < CLOSURE_HEADER_BYTES_V1 {
        return Err(RnsNativeQpcsFriCompleteErrorV1::Truncated);
    }
    let mut decoder = DecoderV1::new(closure);
    if decoder.take(CLOSURE_MAGIC_V1.len())? != CLOSURE_MAGIC_V1.as_slice()
        || decoder.u8()? != CLOSURE_VERSION_V1
        || decoder.u8()? != ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1
        || usize::from(decoder.u8()?) != ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1
        || usize::from(decoder.u8()?) != ROWS_PER_LIMB_V1
        || decoder.u16()? != ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1
        || usize::from(decoder.u8()?) != FIRST_ENCODED_LAYER_V1
        || usize::from(decoder.u8()?) != LAST_LAYER_V1
        || usize::from(decoder.u8()?) != ENCODED_LAYER_COUNT_V1
        || decoder.u8()? != FIRST_CHECKED_FOLD_V1
        || decoder.u8()? != LAST_CHECKED_FOLD_V1
        || decoder.u8()? != TERMINAL_DERIVED_V1
    {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidHeader);
    }
    let aggregate_opened = usize::from(decoder.u16()?);
    let aggregate_authentication = usize::from(decoder.u16()?);
    let aggregate_values_bytes = usize::try_from(decoder.u32()?)
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
    let aggregate_authentication_bytes = usize::try_from(decoder.u32()?)
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
    let downstream_bytes = usize::try_from(decoder.u32()?)
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
    let empty_descriptor = TreeDescriptorV1 {
        opened: 0,
        authentication: 0,
        values_bytes: 0,
        authentication_bytes: 0,
    };
    let mut encoded = [empty_descriptor; ENCODED_LAYER_COUNT_V1];
    for descriptor in &mut encoded {
        descriptor.opened = usize::from(decoder.u16()?);
        descriptor.authentication = usize::from(decoder.u16()?);
        descriptor.values_bytes = usize::try_from(decoder.u32()?)
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
        descriptor.authentication_bytes = usize::try_from(decoder.u32()?)
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
    }
    let parameter_digest = decoder.public_digest()?;
    let transcript_digest = decoder.digest()?;
    let query_seed = decoder.digest()?;
    let section_binding_digest = decoder.digest()?;
    let schedule_digest = decoder.digest()?;
    let encoded_residual_digest = decoder.digest()?;
    if decoder.cursor != CLOSURE_HEADER_BYTES_V1
        || downstream_bytes == 0
        || aggregate_opened != shape.aggregate_opened
        || aggregate_authentication != shape.aggregate_authentication
        || aggregate_values_bytes != shape.aggregate_values_bytes
        || aggregate_authentication_bytes != shape.aggregate_authentication_bytes
        || encoded
            .iter()
            .zip(shape.descriptors)
            .any(|(encoded, expected)| {
                encoded.opened != expected.opened
                    || encoded.authentication != expected.authentication
                    || encoded.values_bytes != expected.values_bytes
                    || encoded.authentication_bytes != expected.authentication_bytes
            })
        || parameter_digest != context.parameter_digest
        || transcript_digest != context.transcript_digest
        || query_seed != context.query_seed
        || section_binding_digest != context.section_binding_digest
        || schedule_digest != context.schedule_digest
    {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidHeader);
    }
    let encoded_tree_bytes = shape
        .descriptors
        .iter()
        .try_fold(0_usize, |total, descriptor| {
            total
                .checked_add(descriptor.values_bytes)
                .and_then(|value| value.checked_add(descriptor.authentication_bytes))
                .ok_or(RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)
        })?;
    let expected_total = CLOSURE_HEADER_BYTES_V1
        .checked_add(encoded_tree_bytes)
        .and_then(|value| value.checked_add(downstream_bytes))
        .ok_or(RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
    if expected_total > ZK_AMS_MKHE_RNS_NATIVE_QPCS_MAX_BYTES_V1 as usize {
        return Err(RnsNativeQpcsFriCompleteErrorV1::ProofCapExceeded);
    }
    if closure.len() < expected_total {
        return Err(RnsNativeQpcsFriCompleteErrorV1::Truncated);
    }
    if closure.len() != expected_total {
        return Err(RnsNativeQpcsFriCompleteErrorV1::TrailingBytes);
    }
    let empty = TreeViewV1 {
        values: &[],
        authentication: &[],
    };
    let mut layers = [empty; ENCODED_LAYER_COUNT_V1];
    for (layer, descriptor) in layers.iter_mut().zip(shape.descriptors) {
        layer.values = decoder.take(descriptor.values_bytes)?;
        layer.authentication = decoder.take(descriptor.authentication_bytes)?;
    }
    let downstream_residual = decoder.take(downstream_bytes)?;
    if decoder.cursor != closure.len()
        || encoded_residual_digest != residual_digest_v1(context, downstream_residual)?
    {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidHeader);
    }
    Ok(ClosureViewV1 {
        layers,
        downstream_residual,
    })
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "the fixed FRI layer relation has explicit authenticated inputs"
)]
fn verify_fold_v1(
    context: FriClosureContextV1,
    fields: &[Fq2ParametersV1; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1],
    queries: &[u32; QUERY_COUNT_V1],
    layer: usize,
    current_indices: IndexSetV1,
    current_values: &[u8],
    next_indices: IndexSetV1,
    next_values: &[u8],
) -> Result<(), RnsNativeQpcsFriCompleteErrorV1> {
    if !(1..LAST_LAYER_V1).contains(&layer) {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidOrder);
    }
    let length = DOMAIN_SIZE_V1 >> layer;
    let half = u32::try_from(length / 2)
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
    for (limb, &field) in fields.iter().enumerate() {
        let layer_root = field.pow(field.domain_root, 1_u128 << layer);
        let mut alphas = [Fq2V1::ZERO; ROWS_PER_LIMB_V1];
        for (row, alpha) in alphas.iter_mut().enumerate() {
            *alpha = derive_fold_challenge_v1(context, layer, limb, row)?;
        }
        for &query in queries {
            let base = query % half;
            let inverse_exponent = if base == 0 {
                0
            } else {
                u128::try_from(length)
                    .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?
                    - u128::from(base)
            };
            let inverse_x = field.pow(layer_root, inverse_exponent);
            for (row, &alpha) in alphas.iter().enumerate() {
                let coordinate = limb * ROWS_PER_LIMB_V1 + row;
                let positive = read_value_v1(current_indices, current_values, base, coordinate)
                    .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidOrder)?;
                let negative =
                    read_value_v1(current_indices, current_values, base + half, coordinate)
                        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidOrder)?;
                // The fold output remains at `base` in the half-sized layer;
                // `next_indices` contains both lower/upper query-pair members.
                let next = read_value_v1(next_indices, next_values, base, coordinate)
                    .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidOrder)?;
                if next != fold_value_with_inverse_x_v1(field, inverse_x, positive, negative, alpha)
                {
                    return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidFriEquation);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn verify_terminal_degree_v1(
    context: FriClosureContextV1,
    fields: &[Fq2ParametersV1; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1],
    final_indices: IndexSetV1,
    final_values: &[u8],
) -> Result<(), RnsNativeQpcsFriCompleteErrorV1> {
    if final_indices.len != 4 || final_indices.values[..4] != [0, 1, 2, 3] {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidTerminalCoverage);
    }
    for (limb, &field) in fields.iter().enumerate() {
        let layer_root = field.pow(field.domain_root, 1_u128 << LAST_LAYER_V1);
        let inverse_layer_root = field.pow(layer_root, 3);
        let mut alphas = [Fq2V1::ZERO; ROWS_PER_LIMB_V1];
        for (row, alpha) in alphas.iter_mut().enumerate() {
            *alpha = derive_fold_challenge_v1(context, LAST_LAYER_V1, limb, row)?;
        }
        for (row, &alpha) in alphas.iter().enumerate() {
            let coordinate = limb * ROWS_PER_LIMB_V1 + row;
            let value = |index| {
                read_value_v1(final_indices, final_values, index, coordinate)
                    .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidTerminalCoverage)
            };
            let terminal_zero =
                fold_value_with_inverse_x_v1(field, Fq2V1::ONE, value(0)?, value(2)?, alpha);
            let terminal_one = fold_value_with_inverse_x_v1(
                field,
                inverse_layer_root,
                value(1)?,
                value(3)?,
                alpha,
            );
            if terminal_zero != terminal_one {
                return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidTerminalDegree);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn derive_fold_challenge_v1(
    context: FriClosureContextV1,
    layer: usize,
    limb: usize,
    row: usize,
) -> Result<Fq2V1, RnsNativeQpcsFriCompleteErrorV1> {
    let seed = *context
        .fold_seeds
        .get(layer)
        .ok_or(RnsNativeQpcsFriCompleteErrorV1::InvalidChallenge)?;
    // This layer's seed was derived immediately after its root. Later roots
    // and terminal commitments never enter this earlier challenge.
    super::rns_native_qpcs_prefix::derive_fold_challenge_v1(
        context.parameter_digest,
        seed,
        layer,
        limb,
        row,
    )
    .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidChallenge)
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum ClosureBindingRoleV1 {
    Schedule,
    Residual,
    ClaimedSource,
}

#[cfg(test)]
fn binding_hash_v1(
    role: ClosureBindingRoleV1,
    parameter_digest: [u8; 32],
    fields: &[&[u8]],
) -> Result<ProofDigestV1, RnsNativeQpcsFriCompleteErrorV1> {
    let context = RnsNativeProofHashContextV1::canonical()
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)?;
    if context.parameter_digest() != parameter_digest {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidContext);
    }
    let index = match role {
        ClosureBindingRoleV1::Schedule => 0,
        ClosureBindingRoleV1::Residual => 1,
        ClosureBindingRoleV1::ClaimedSource => 2,
    };
    let frame = context
        .frame(
            RnsNativeProofHashRoleV1::Transcript,
            RnsNativeProofHashPhaseV1::Binding,
            RnsNativeProofHashPositionV1 {
                level: 2,
                index,
                counter: 0,
            },
            fields,
        )
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)?;
    if index == 2
        && RnsNativeProofHashWorkV1::from_frame(&frame)
            .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::InvalidContext)?
            != RNS_NATIVE_QPCS_CLAIMED_SOURCE_BINDING_HASH_WORK_V1
    {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidContext);
    }
    let digest = ProofDigestV1::from_shared(frame.hash());
    if digest == ProofDigestV1::ZERO {
        return Err(RnsNativeQpcsFriCompleteErrorV1::InvalidContext);
    }
    Ok(digest)
}

#[cfg(test)]
fn schedule_digest_v1(
    context: FriClosureContextV1,
) -> Result<ProofDigestV1, RnsNativeQpcsFriCompleteErrorV1> {
    const ENTRY_BYTES: usize = 1 + 2 * DIGEST_BYTES_V1;
    let mut ordered_layers = [0_u8; ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1 as usize * ENTRY_BYTES];
    for (layer, entry) in ordered_layers.chunks_exact_mut(ENTRY_BYTES).enumerate() {
        entry[0] =
            u8::try_from(layer).map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?;
        entry[1..1 + DIGEST_BYTES_V1].copy_from_slice(context.roots[layer].as_bytes());
        entry[1 + DIGEST_BYTES_V1..].copy_from_slice(context.fold_seeds[layer].as_bytes());
    }
    binding_hash_v1(
        ClosureBindingRoleV1::Schedule,
        context.parameter_digest,
        &[
            SCHEDULE_DOMAIN_V1,
            &[CLOSURE_VERSION_V1, ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1],
            &context.parameter_digest,
            context.transcript_digest.as_bytes(),
            context.qpcs_bound_transcript_state.as_bytes(),
            context.query_seed.as_bytes(),
            context.section_binding_digest.as_bytes(),
            &ordered_layers,
        ],
    )
}

#[cfg(test)]
fn residual_digest_v1(
    context: FriClosureContextV1,
    residual: &[u8],
) -> Result<ProofDigestV1, RnsNativeQpcsFriCompleteErrorV1> {
    let len = u32::try_from(residual.len())
        .map_err(|_| RnsNativeQpcsFriCompleteErrorV1::ArithmeticOverflow)?
        .to_be_bytes();
    binding_hash_v1(
        ClosureBindingRoleV1::Residual,
        context.parameter_digest,
        &[
            RESIDUAL_DOMAIN_V1,
            &[CLOSURE_VERSION_V1],
            &context.parameter_digest,
            context.transcript_digest.as_bytes(),
            context.query_seed.as_bytes(),
            context.section_binding_digest.as_bytes(),
            context.schedule_digest.as_bytes(),
            &len,
            residual,
        ],
    )
}

#[cfg(test)]
#[path = "rns_native_qpcs_fri_complete_tests.rs"]
mod tests;

#[cfg(test)]
mod claimed_numeric_binding_frame_tests {
    use super::*;

    fn axes() -> RnsNativeClaimedNumericBindingAxesV1 {
        let parameter = RnsNativeProofHashContextV1::canonical()
            .expect("context")
            .parameter_digest();
        let proof = |index| {
            super::super::rns_native_proof_hash::test_proof_digest_v1(
                b"claimed-numeric-binding",
                index,
            )
        };
        RnsNativeClaimedNumericBindingAxesV1 {
            statement_anchor: proof(1),
            preflight_statement: proof(2),
            public_bundle: [3; 32],
            source_parameter: parameter,
            source_transcript: proof(5),
            source_schedule: proof(6),
            source_evaluation: proof(7),
            source_residual: proof(8),
            schedule_parameter: parameter,
            q_mask_s_root: proof(10),
            pre_relation_transcript: proof(11),
            relation_seed: proof(12),
            final_transcript: proof(13),
        }
    }

    #[test]
    fn shared_claimed_numeric_frame_preserves_all_typed_axes_and_exact_200_tails() {
        let base = axes();
        let tails = core::array::from_fn::<_, 200, _>(|index| {
            (index as u64 + 1, index as u64 + 101, index as u64 + 201)
        });
        let mut packed = Vec::new();
        for (a, product, quotient) in tails {
            packed.extend_from_slice(&a.to_be_bytes());
            packed.extend_from_slice(&product.to_be_bytes());
            packed.extend_from_slice(&quotient.to_be_bytes());
        }
        let context = RnsNativeProofHashContextV1::canonical().expect("context");
        let expected = context
            .hash(
                RnsNativeProofHashRoleV1::Transcript,
                RnsNativeProofHashPhaseV1::Binding,
                RnsNativeProofHashPositionV1 {
                    level: 2,
                    index: 2,
                    counter: 0,
                },
                &[
                    CLAIMED_SOURCE_BINDING_DOMAIN_V1,
                    &[CLOSURE_VERSION_V1],
                    base.statement_anchor.as_bytes(),
                    base.preflight_statement.as_bytes(),
                    &base.public_bundle,
                    &base.source_parameter,
                    base.source_transcript.as_bytes(),
                    base.source_schedule.as_bytes(),
                    base.source_evaluation.as_bytes(),
                    base.source_residual.as_bytes(),
                    &base.schedule_parameter,
                    base.q_mask_s_root.as_bytes(),
                    base.pre_relation_transcript.as_bytes(),
                    base.relation_seed.as_bytes(),
                    base.final_transcript.as_bytes(),
                    &packed,
                ],
            )
            .expect("independent shared frame replay");
        assert_eq!(base.digest_v1(tails), Ok(expected));
        for selector in 0..10 {
            let mut changed = base;
            let field = match selector {
                0 => &mut changed.statement_anchor,
                1 => &mut changed.preflight_statement,
                2 => &mut changed.source_transcript,
                3 => &mut changed.source_schedule,
                4 => &mut changed.source_evaluation,
                5 => &mut changed.source_residual,
                6 => &mut changed.q_mask_s_root,
                7 => &mut changed.pre_relation_transcript,
                8 => &mut changed.relation_seed,
                9 => &mut changed.final_transcript,
                _ => unreachable!(),
            };
            let mut bytes = field.to_le_bytes();
            let old = u64::from_le_bytes(bytes[40..48].try_into().expect("sixth lane"));
            bytes[40..48].copy_from_slice(&(if old == 0 { 1 } else { old - 1 }).to_le_bytes());
            *field = ProofDigestV1::from_le_bytes(bytes).expect("canonical sixth lane mutation");
            assert_ne!(changed.digest_v1(tails).expect("bound mutation"), expected);
            let field = match selector {
                0 => &mut changed.statement_anchor,
                1 => &mut changed.preflight_statement,
                2 => &mut changed.source_transcript,
                3 => &mut changed.source_schedule,
                4 => &mut changed.source_evaluation,
                5 => &mut changed.source_residual,
                6 => &mut changed.q_mask_s_root,
                7 => &mut changed.pre_relation_transcript,
                8 => &mut changed.relation_seed,
                9 => &mut changed.final_transcript,
                _ => unreachable!(),
            };
            *field = ProofDigestV1::ZERO;
            assert_eq!(
                changed.digest_v1(tails),
                Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidBinding)
            );
        }
        let mut changed = base;
        changed.public_bundle = [0; 32];
        assert!(changed.digest_v1(tails).is_err());
        let mut changed = base;
        changed.source_parameter[0] ^= 1;
        assert!(changed.digest_v1(tails).is_err());
        changed.schedule_parameter = changed.source_parameter;
        assert!(
            changed.digest_v1(tails).is_err(),
            "equal foreign profiles are not current context"
        );
        assert_eq!(
            base.digest_v1(tails[..199].iter().copied()),
            Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount)
        );
        assert_eq!(
            base.digest_v1(tails.into_iter().chain([(1, 2, 3)])),
            Err(RnsNativeQpcsClaimedSourceErrorV1::InvalidCount)
        );
        let mut changed_tails = tails;
        changed_tails[199].2 ^= 1;
        assert_ne!(base.digest_v1(changed_tails).expect("last tail"), expected);
    }
}
