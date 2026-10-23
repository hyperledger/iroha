//! Fail-closed audit of the ZK-AMS verified-receipt capability graph.
//!
//! This module deliberately distinguishes implemented proof components from
//! operational authorization. A sealed native CPK relation receipt is useful,
//! but the retired structural RNS-Link prototypes never minted an authorizing
//! receipt. The audit therefore keeps a separate bit for each handoff and
//! refuses each operational requirement whose corresponding handoff remains
//! open. Full release remains unavailable until every handoff closes.
//!
//! The release manifest and readiness gate consume the complete audit digest, blocker mask, and
//! aggregate availability. This makes later implementation flips reviewable without allowing an
//! unrelated readiness bit to bypass an open receipt handoff.

use super::{MKHE_VERSION_V1, ZkAmsMkheErrorV1};
const RECEIPT_CAPABILITY_AUDIT_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.verified-receipt-capability-audit";
const BLOCKER_CPK_AGGREGATE_V1: u16 = 1 << 0;
const BLOCKER_RKG_ROUND_ONE_V1: u16 = 1 << 1;
const BLOCKER_RKG_ROUND_TWO_V1: u16 = 1 << 2;
const BLOCKER_GALOIS_KEY_V1: u16 = 1 << 3;
const BLOCKER_RNS_LINK_ALGEBRA_V1: u16 = 1 << 4;
const BLOCKER_TERMINAL_MATERIALIZATION_V1: u16 = 1 << 5;
const BLOCKER_SPLIT_DECRYPTION_V1: u16 = 1 << 6;
const BLOCKER_PERSISTENT_DECRYPTION_EQUALITY_V1: u16 = 1 << 7;
const ALL_RECEIPT_CAPABILITY_BLOCKERS_V1: u16 = BLOCKER_CPK_AGGREGATE_V1
    | BLOCKER_RKG_ROUND_ONE_V1
    | BLOCKER_RKG_ROUND_TWO_V1
    | BLOCKER_GALOIS_KEY_V1
    | BLOCKER_RNS_LINK_ALGEBRA_V1
    | BLOCKER_TERMINAL_MATERIALIZATION_V1
    | BLOCKER_SPLIT_DECRYPTION_V1
    | BLOCKER_PERSISTENT_DECRYPTION_EQUALITY_V1;
const CURRENT_OPEN_RECEIPT_CAPABILITY_BLOCKERS_V1: u16 = ALL_RECEIPT_CAPABILITY_BLOCKERS_V1
    & !(BLOCKER_CPK_AGGREGATE_V1
        | BLOCKER_RKG_ROUND_ONE_V1
        | BLOCKER_RKG_ROUND_TWO_V1
        | BLOCKER_GALOIS_KEY_V1);
const _: () = assert!(ALL_RECEIPT_CAPABILITY_BLOCKERS_V1 == 0xff);
const _: () = assert!(CURRENT_OPEN_RECEIPT_CAPABILITY_BLOCKERS_V1 == 0xf0);
/// One release operation which must be authorized by opaque verified receipts.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ZkAmsMkheReceiptCapabilityConsumerV1 {
    /// Aggregate and admit the exact proof-carrying collective public key.
    CollectivePublicKeyAggregate,
    /// Generate and admit RKG round-one contributions.
    RkgRoundOne,
    /// Generate and admit RKG round-two contributions and normalization.
    RkgRoundTwo,
    /// Generate and admit one key in the frozen Galois schedule.
    GaloisKey,
    /// Turn a bound RNS-Link proof into an algebraically verified receipt.
    RnsLinkVerification,
    /// Materialize the six terminal accumulator families.
    TerminalMaterialization,
    /// Prove and publish one authenticated split-decryption share.
    SplitDecryption,
}
/// Digest-bound status of every mandatory verified-receipt handoff.
///
/// Fields ending in `_specified` or `_bound` describe implemented structure,
/// not semantic proof success.  Fields ending in `_enforced` are true only
/// when every production path for that consumer requires the opaque receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheReceiptCapabilityAuditV1 {
    /// Audit schema version.
    pub(super) version: u8,
    /// The native CPK verifier mints a sealed, non-serializable relation receipt.
    pub(super) cpk_relation_receipt_sealed: bool,
    /// Party-state admission consumes the sealed CPK relation receipt.
    pub(super) cpk_party_state_admission_consumes_receipt: bool,
    /// Every collective-key aggregate path requires the verified CPK receipt set.
    pub(super) cpk_aggregate_receipt_enforced: bool,
    /// Every RKG round-one generator requires a single-use CPK-derived capability.
    pub(super) rkg_round_one_receipt_enforced: bool,
    /// Every RKG round-two/normalization generator requires the chained capability.
    pub(super) rkg_round_two_receipt_enforced: bool,
    /// Every Galois-key generator requires the CPK-derived lineage capability.
    pub(super) galois_key_receipt_enforced: bool,
    /// Canonical RNS-Link bytes bind verifier-derived context and commitments.
    pub(super) rns_link_transport_bound: bool,
    /// Whether the sibling-private native opening path mints a sealed receipt
    /// after checking canonical packing, the 38-limb lift, and both RLWE
    /// equations. Explicitly unverified topology metadata does not satisfy this.
    pub(super) native_bgv_opening_receipt_sealed: bool,
    /// A terminal-local receipt checks the complete relaxed assignment and
    /// recomputes both Hyrax commitments from the materialized openings.
    pub(super) native_materialized_hyrax_receipt_sealed: bool,
    /// The terminal prover consumes that native materialized-opening receipt.
    pub(super) terminal_prover_consumes_native_materialized_receipt: bool,
    /// Whether native release geometry (`X=89`, replicated `U=1_048_576`) is
    /// enforced end to end from state-owned openings through proof checking.
    pub(super) rns_link_family_geometry_matches_native: bool,
    /// Whether the wire carries enough authenticated data to verify all 38
    /// radix/CRT-carry and negacyclic-quotient response equations.
    pub(super) rns_link_carry_quotient_responses_verifiable: bool,
    /// Whether the wire proves that its packed BGV openings equal the existing
    /// 512-row/1024-row Hyrax accumulator commitments.
    pub(super) hyrax_bgv_equality_responses_verifiable: bool,
    /// The full packing/carry/quotient/equality verifier mints an opaque receipt.
    pub(super) rns_link_algebraic_receipt_complete: bool,
    /// Terminal materialization consumes that opaque RNS-Link receipt.
    pub(super) terminal_materialization_receipt_enforced: bool,
    /// Split-decryption proving consumes both CPK and RNS-Link capabilities.
    pub(super) split_decryption_receipts_enforced: bool,
    /// The approximately 1,855-bit smudge relation proves equality to the CPK secret.
    pub(super) persistent_decryption_equality_complete: bool,
    /// The opaque context-issued party use binds roster, epoch, ciphertext,
    /// statement, record, sample, and commitment transcript replay axes.
    pub(super) persistent_decryption_replay_axes_specified: bool,
    /// Exact open-handoff bit set.
    pub(super) blocker_mask: u16,
    /// True only when every structural prerequisite and handoff closes together.
    pub(super) release_available: bool,
    /// Digest of every preceding field.
    pub(super) digest: [u8; 32],
}
impl ZkAmsMkheReceiptCapabilityAuditV1 {
    /// Recheck the blocker set, aggregate state, and audit digest.
    pub(super) fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        if self.version != MKHE_VERSION_V1
            || self.blocker_mask != receipt_capability_blocker_mask_v1(self)
            || self.release_available != receipt_capability_release_available_v1(self)
            || self.digest == [0; 32]
            || self.digest != receipt_capability_audit_digest_v1(self)
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(())
    }
    /// Return whether one exact consumer is currently authorized.
    #[cfg(test)]
    pub(super) const fn authorizes(self, consumer: ZkAmsMkheReceiptCapabilityConsumerV1) -> bool {
        match consumer {
            ZkAmsMkheReceiptCapabilityConsumerV1::CollectivePublicKeyAggregate => {
                self.cpk_relation_receipt_sealed
                    && self.cpk_party_state_admission_consumes_receipt
                    && self.cpk_aggregate_receipt_enforced
            }
            ZkAmsMkheReceiptCapabilityConsumerV1::RkgRoundOne => {
                self.cpk_aggregate_receipt_enforced && self.rkg_round_one_receipt_enforced
            }
            ZkAmsMkheReceiptCapabilityConsumerV1::RkgRoundTwo => {
                self.rkg_round_one_receipt_enforced && self.rkg_round_two_receipt_enforced
            }
            ZkAmsMkheReceiptCapabilityConsumerV1::GaloisKey => {
                self.cpk_aggregate_receipt_enforced && self.galois_key_receipt_enforced
            }
            ZkAmsMkheReceiptCapabilityConsumerV1::RnsLinkVerification => {
                self.rns_link_transport_bound
                    && self.rns_link_family_geometry_matches_native
                    && self.rns_link_carry_quotient_responses_verifiable
                    && self.hyrax_bgv_equality_responses_verifiable
                    && self.rns_link_algebraic_receipt_complete
            }
            ZkAmsMkheReceiptCapabilityConsumerV1::TerminalMaterialization => {
                self.rns_link_family_geometry_matches_native
                    && self.rns_link_carry_quotient_responses_verifiable
                    && self.hyrax_bgv_equality_responses_verifiable
                    && self.rns_link_algebraic_receipt_complete
                    && self.terminal_materialization_receipt_enforced
            }
            ZkAmsMkheReceiptCapabilityConsumerV1::SplitDecryption => {
                self.cpk_aggregate_receipt_enforced
                    && self.rns_link_family_geometry_matches_native
                    && self.rns_link_carry_quotient_responses_verifiable
                    && self.hyrax_bgv_equality_responses_verifiable
                    && self.rns_link_algebraic_receipt_complete
                    && self.split_decryption_receipts_enforced
                    && self.persistent_decryption_equality_complete
                    && self.persistent_decryption_replay_axes_specified
            }
        }
    }
}
/// Evaluate the current source-level capability graph without inferring proof
/// success from a type name, a nonzero digest, or canonical transport bytes.
pub(super) fn zk_ams_mkhe_receipt_capability_audit_v1() -> ZkAmsMkheReceiptCapabilityAuditV1 {
    let mut audit = ZkAmsMkheReceiptCapabilityAuditV1 {
        version: MKHE_VERSION_V1,
        cpk_relation_receipt_sealed: true,
        cpk_party_state_admission_consumes_receipt: true,
        // The public ceremony's sole per-party transition invokes the complete
        // relation verifier, converts its sealed receipt into a move-only
        // contribution, and consumes that contribution into the party-state
        // binding plus staged admission. Finalization requires fixed arrays of
        // all eight admissions and validates each one again; the legacy raw
        // aggregate is test-only.
        cpk_aggregate_receipt_enforced: true,
        // The sole evaluated-key provider admission now consumes a sealed,
        // move-only aggregate of every exact ordered source and CKS receipt
        // before provider I/O, then joins every expected CKS compact output to
        // the authenticated ZARK scan. This closes the three receipt-consumer
        // handoffs only. It does not establish the stronger cross-set algebraic
        // equality between accumulated source outputs and the CKS relation.
        rkg_round_one_receipt_enforced: true,
        rkg_round_two_receipt_enforced: true,
        galois_key_receipt_enforced: true,
        // The retired structural decoder never minted an algebraic receipt, so
        // absence of its private transport is recorded explicitly.
        rns_link_transport_bound: false,
        // The retired 43-opening path likewise returned only unverified
        // topology/count metadata and never minted a sealed native-BGV receipt.
        native_bgv_opening_receipt_sealed: false,
        native_materialized_hyrax_receipt_sealed: true,
        terminal_prover_consumes_native_materialized_receipt: true,
        // No retained RNS-Link schema proves that release geometry and all
        // native openings equal the materialized accumulator commitments.
        rns_link_family_geometry_matches_native: false,
        // A point, one evaluation scalar, and one nonzero response per section
        // do not encode opening/IPA equations for either relation.
        rns_link_carry_quotient_responses_verifiable: false,
        hyrax_bgv_equality_responses_verifiable: false,
        rns_link_algebraic_receipt_complete: false,
        // These APIs currently accept packed/materialized values or native
        // decryption statements without an RNS-Link receipt parameter.
        terminal_materialization_receipt_enforced: false,
        split_decryption_receipts_enforced: false,
        // One atomic ceremony call consumes all eight complete CPK verifier
        // capabilities and emits both the secret-free ordered context and the
        // move-only bindings admitted into party states. The retained context
        // binds fresh use sets to later statements. Prove/verify/split/
        // reconstruct bind its actual points to the shared-secret transcript.
        // Keep this false until the transitive short-solution/SIS equality
        // argument and replacement release-size KAT are certified.
        persistent_decryption_equality_complete: false,
        persistent_decryption_replay_axes_specified: true,
        blocker_mask: 0,
        release_available: false,
        digest: [0; 32],
    };
    audit.blocker_mask = receipt_capability_blocker_mask_v1(audit);
    audit.release_available = receipt_capability_release_available_v1(audit);
    audit.digest = receipt_capability_audit_digest_v1(audit);
    audit
}
/// Require one operational capability without accepting a digest shell or
/// retired structural RNS-Link metadata as a substitute.
///
/// The collective-public-key aggregate and the three evaluated-key receipt consumers are authorized
/// through their sealed handoffs. The independent algebraic/materialization/decryption blockers
/// remain open, so these local successes do not make the complete release available.
#[cfg(test)]
pub(super) fn require_zk_ams_mkhe_receipt_capability_v1(
    consumer: ZkAmsMkheReceiptCapabilityConsumerV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    let audit = zk_ams_mkhe_receipt_capability_audit_v1();
    audit.validate()?;
    if !audit.authorizes(consumer) {
        return Err(ZkAmsMkheErrorV1::ReleaseUnavailable);
    }
    Ok(())
}
fn receipt_capability_blocker_mask_v1(audit: ZkAmsMkheReceiptCapabilityAuditV1) -> u16 {
    let mut blockers = 0_u16;
    for (closed, blocker) in [
        (
            audit.cpk_aggregate_receipt_enforced,
            BLOCKER_CPK_AGGREGATE_V1,
        ),
        (
            audit.rkg_round_one_receipt_enforced,
            BLOCKER_RKG_ROUND_ONE_V1,
        ),
        (
            audit.rkg_round_two_receipt_enforced,
            BLOCKER_RKG_ROUND_TWO_V1,
        ),
        (audit.galois_key_receipt_enforced, BLOCKER_GALOIS_KEY_V1),
        (
            audit.rns_link_algebraic_receipt_complete,
            BLOCKER_RNS_LINK_ALGEBRA_V1,
        ),
        (
            audit.terminal_materialization_receipt_enforced,
            BLOCKER_TERMINAL_MATERIALIZATION_V1,
        ),
        (
            audit.split_decryption_receipts_enforced,
            BLOCKER_SPLIT_DECRYPTION_V1,
        ),
        (
            audit.persistent_decryption_equality_complete,
            BLOCKER_PERSISTENT_DECRYPTION_EQUALITY_V1,
        ),
    ] {
        if !closed {
            blockers |= blocker;
        }
    }
    blockers
}
const fn receipt_capability_release_available_v1(audit: ZkAmsMkheReceiptCapabilityAuditV1) -> bool {
    audit.cpk_relation_receipt_sealed
        && audit.cpk_party_state_admission_consumes_receipt
        && audit.cpk_aggregate_receipt_enforced
        && audit.rkg_round_one_receipt_enforced
        && audit.rkg_round_two_receipt_enforced
        && audit.galois_key_receipt_enforced
        && audit.rns_link_transport_bound
        && audit.native_bgv_opening_receipt_sealed
        && audit.native_materialized_hyrax_receipt_sealed
        && audit.terminal_prover_consumes_native_materialized_receipt
        && audit.rns_link_family_geometry_matches_native
        && audit.rns_link_carry_quotient_responses_verifiable
        && audit.hyrax_bgv_equality_responses_verifiable
        && audit.rns_link_algebraic_receipt_complete
        && audit.terminal_materialization_receipt_enforced
        && audit.split_decryption_receipts_enforced
        && audit.persistent_decryption_equality_complete
        && audit.persistent_decryption_replay_axes_specified
        && audit.blocker_mask == 0
}
fn receipt_capability_audit_digest_v1(audit: ZkAmsMkheReceiptCapabilityAuditV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        RECEIPT_CAPABILITY_AUDIT_DOMAIN_V1,
        4,
    );
    hash.push_field(&[audit.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        audit.cpk_relation_receipt_sealed.into(),
        audit.cpk_party_state_admission_consumes_receipt.into(),
        audit.cpk_aggregate_receipt_enforced.into(),
        audit.rkg_round_one_receipt_enforced.into(),
        audit.rkg_round_two_receipt_enforced.into(),
        audit.galois_key_receipt_enforced.into(),
        audit.rns_link_transport_bound.into(),
        audit.native_bgv_opening_receipt_sealed.into(),
        audit.native_materialized_hyrax_receipt_sealed.into(),
        audit
            .terminal_prover_consumes_native_materialized_receipt
            .into(),
        audit.rns_link_family_geometry_matches_native.into(),
        audit.rns_link_carry_quotient_responses_verifiable.into(),
        audit.hyrax_bgv_equality_responses_verifiable.into(),
        audit.rns_link_algebraic_receipt_complete.into(),
        audit.terminal_materialization_receipt_enforced.into(),
        audit.split_decryption_receipts_enforced.into(),
        audit.persistent_decryption_equality_complete.into(),
        audit.persistent_decryption_replay_axes_specified.into(),
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.blocker_mask.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[audit.release_available.into()])
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vega::zk_ams::mkhe::{
        active::ZkAmsMkheGovernedActiveRosterV1,
        active_exact_binding::{
            VerifiedDirectRelationProofReceiptV1, VerifiedPersistentWitnessBindingV1,
            VerifiedPersistentWitnessDirectRelationUseV1,
            mint_collective_secret_binding_from_verified_cpk_v1,
            verify_and_consume_direct_relation_use_v1,
        },
        cpk_relation::{VerifiedZkAmsMkheCpkBindingSourceV1, VerifiedZkAmsMkheCpkContributionV1},
        decryption::{
            ZkAmsMkheAuthenticatedDecryptionShareV1, ZkAmsMkheDecryptionSplitTransportV1,
            ZkAmsMkheDecryptionStatementV1, split_zk_ams_mkhe_decryption_share_v1,
        },
        manifest::ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1,
        packing::ZkAmsT256PackedPlaintextV1,
        persistent_decryption_equality::{
            ZkAmsMkhePersistentDecryptionPartyUseV1,
            ZkAmsMkhePersistentDecryptionVerificationContextV1,
            prepare_zk_ams_mkhe_persistent_decryption_from_verified_cpk_v1,
        },
        phase23_encrypted::{
            ZkAmsPhase23AccumulatorShapeV1, ZkAmsPhase23MaterializedAccumulatorsV1,
            zk_ams_phase23_materialize_release_accumulator_chunks_v1,
        },
    };
    type MintCpkBindingV1 = fn(
        &ZkAmsMkheGovernedActiveRosterV1,
        [u8; 32],
        usize,
        [u8; 32],
        VerifiedZkAmsMkheCpkBindingSourceV1,
    ) -> Result<VerifiedPersistentWitnessBindingV1, ZkAmsMkheErrorV1>;
    type PrepareSecretFreePersistentDecryptionV1 = for<'a, 'b> fn(
        &'a ZkAmsMkheGovernedActiveRosterV1,
        ZkAmsMkheDecryptionStatementV1<'b>,
        [VerifiedZkAmsMkheCpkContributionV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    ) -> Result<
        (
            ZkAmsMkhePersistentDecryptionVerificationContextV1,
            [ZkAmsMkhePersistentDecryptionPartyUseV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
            [VerifiedPersistentWitnessBindingV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
        ),
        ZkAmsMkheErrorV1,
    >;
    type VerifyDirectRelationV1 =
        fn(
            VerifiedPersistentWitnessDirectRelationUseV1,
            &[u8],
        ) -> Result<VerifiedDirectRelationProofReceiptV1, ZkAmsMkheErrorV1>;
    type BindPersistentDecryptionStatementV1 = for<'a, 'b> fn(
        &'a ZkAmsMkhePersistentDecryptionVerificationContextV1,
        ZkAmsMkheDecryptionStatementV1<'b>,
    ) -> Result<
        [ZkAmsMkhePersistentDecryptionPartyUseV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
        ZkAmsMkheErrorV1,
    >;
    type MaterializeWithoutReceiptV1 =
        fn(
            [u8; 32],
            [u8; 32],
            [u8; 32],
            [u8; 32],
            [u8; 32],
            u8,
            ZkAmsPhase23AccumulatorShapeV1,
            std::vec::IntoIter<Result<ZkAmsT256PackedPlaintextV1, ZkAmsMkheErrorV1>>,
        ) -> Result<ZkAmsPhase23MaterializedAccumulatorsV1, ZkAmsMkheErrorV1>;
    type SplitWithPersistentReceiptV1 =
        for<'a, 'b, 'c> fn(
            ZkAmsMkheDecryptionStatementV1<'a>,
            &'b ZkAmsMkhePersistentDecryptionVerificationContextV1,
            &'c ZkAmsMkheAuthenticatedDecryptionShareV1,
        )
            -> Result<ZkAmsMkheDecryptionSplitTransportV1, ZkAmsMkheErrorV1>;
    fn assert_source_markers_in_order_v1(mut source: &str, markers: &[&str]) {
        for marker in markers {
            source = source
                .split_once(marker)
                .unwrap_or_else(|| panic!("missing ordered source marker: {marker}"))
                .1;
        }
    }
    #[test]
    fn source_surface_guards_distinguish_receipts_from_bypasses() {
        let production = include_str!("receipt_capability_audit.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production source prefix");
        assert!(production.contains("native_bgv_opening_receipt_sealed: false"));
        assert!(!production.contains("native_bgv_opening_receipt_sealed: true"));
        assert!(production.contains("rns_link_transport_bound: false"));
        assert!(!production.contains("rns_link_transport_bound: true"));
        let _: MintCpkBindingV1 = mint_collective_secret_binding_from_verified_cpk_v1;
        let _: PrepareSecretFreePersistentDecryptionV1 =
            prepare_zk_ams_mkhe_persistent_decryption_from_verified_cpk_v1;
        let _: BindPersistentDecryptionStatementV1 =
            ZkAmsMkhePersistentDecryptionVerificationContextV1::bind_statement_v1;
        let _: VerifyDirectRelationV1 = verify_and_consume_direct_relation_use_v1;
        let _: MaterializeWithoutReceiptV1 =
            zk_ams_phase23_materialize_release_accumulator_chunks_v1::<
                std::vec::IntoIter<Result<ZkAmsT256PackedPlaintextV1, ZkAmsMkheErrorV1>>,
            >;
        let _: SplitWithPersistentReceiptV1 = split_zk_ams_mkhe_decryption_share_v1;
        let ceremony_source = include_str!("cpk_ceremony.rs");
        assert!(ceremony_source.contains("pub struct ZkAmsMkheCpkCeremonyV1"));
        let transition = ceremony_source
            .split("pub fn verify_and_absorb_next_party_v1")
            .nth(1)
            .expect("public CPK party transition")
            .split("pub fn finish_v1")
            .next()
            .expect("public CPK party transition boundary");
        assert_source_markers_in_order_v1(
            transition,
            &[
                "let receipt = verify_zk_ams_mkhe_cpk_relation_v1(",
                "VerifiedZkAmsMkheCpkContributionV1::from_verified_relation(receipt)",
                "builder.absorb_verified_party_v1(contribution, share, &mut state, backend)?",
            ],
        );
        let finish = ceremony_source
            .split("pub fn finish_v1")
            .nth(1)
            .expect("public CPK finish transition")
            .split("/// Sealed successful CPK products")
            .next()
            .expect("public CPK finish boundary");
        assert_source_markers_in_order_v1(
            finish,
            &[
                "let staged = builder.finish_staging_v1()?;",
                "staged.finalize_v1(backend)?",
            ],
        );
        let relation_source = include_str!("cpk_relation.rs");
        assert!(relation_source.contains("struct CpkRelationVerificationSealV1;"));
        assert!(relation_source.contains(
            "pub(super) struct VerifiedZkAmsMkheCpkRelationReceiptV1 {\n    _seal: CpkRelationVerificationSealV1,"
        ));
        assert!(relation_source.contains(
            "pub(super) struct VerifiedZkAmsMkheCpkContributionV1 {\n    receipt: VerifiedZkAmsMkheCpkRelationReceiptV1,"
        ));
        assert!(relation_source.contains(
            "pub(super) fn from_verified_relation(receipt: VerifiedZkAmsMkheCpkRelationReceiptV1)"
        ));
        let staged_source = include_str!("persistent_decryption_equality.rs");
        let staged_constructor = staged_source
            .split("pub(super) fn new(")
            .nth(1)
            .expect("bounded CPK staging constructor")
            .split("/// Borrow the builder-owned common `a`")
            .next()
            .expect("bounded CPK staging constructor boundary");
        assert_eq!(
            staged_constructor
                .matches("try_exact_capacity_vec_v1(")
                .count(),
            5
        );
        assert_eq!(
            staged_constructor
                .matches("try_exact_capacity_vec_v1(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)",)
                .count(),
            5
        );
        assert_eq!(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1, 8);
        assert_eq!(
            staged_constructor
                .matches("ZkAmsMkheErrorV1::ResourceCeilingExceeded")
                .count(),
            5
        );
        assert!(!staged_constructor.contains("Vec::new"));
        assert!(!staged_constructor.contains("try_reserve_exact"));
        let verified_absorb = staged_source
            .split("fn absorb_verified_party_inner_v1")
            .nth(1)
            .expect("verified CPK absorption")
            .split("/// Seal only after all eight ordered shares/proofs were consumed.")
            .next()
            .expect("verified CPK absorption boundary");
        assert_source_markers_in_order_v1(
            verified_absorb,
            &[
                ".into_compact_decryption_source(",
                "mint_collective_secret_binding_from_verified_cpk_v1(",
                "consume_collective_public_key_share_for_staging_v1(",
                ".fork_for_state_and_verifier_v1()",
                "self.admissions.push(admission);",
                "party_state.admit_staged_verified_cpk_binding_v1(",
                "self.next_party_index += 1;",
            ],
        );
        let staging_finish = staged_source
            .split("pub(super) fn finish_staging_v1")
            .nth(1)
            .expect("bounded CPK staging finish")
            .split("fn staged_cpk_batch_digest_v1")
            .next()
            .expect("bounded CPK staging boundary");
        for exact_count_guard in [
            "self.next_party_index != ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1",
            "self.admissions.len() != ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1",
            "self.bindings.len() != ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1",
            "self.party_b_pointers.len() != ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1",
            "self.verification_read_receipts.len() != ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1",
            "self.publication_receipts.len() != ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1",
        ] {
            assert!(staging_finish.contains(exact_count_guard));
        }
        assert!(staging_finish.contains(
            "let admissions: [VerifiedCollectivePublicKeyShareStagedAdmissionV1;\n            ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1]"
        ));
        let staged_batch = staged_source
            .split("impl ZkAmsMkheStagedCpkBatchV1")
            .nth(1)
            .expect("sealed staged CPK batch implementation");
        assert!(staged_batch.contains(
            "for party_index in 0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {\n            let admission = &self.admissions[party_index];\n            admission.validate_for_v1"
        ));
        assert!(
            staged_batch
                .matches("for party_index in 0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1")
                .count()
                >= 2
        );
        let collective_source = include_str!("collective.rs");
        assert_eq!(
            collective_source
                .matches("fn aggregate_zk_ams_mkhe_collective_public_key_v1")
                .count(),
            1
        );
        assert!(collective_source.contains(
            "#[cfg(test)]\npub(super) fn aggregate_zk_ams_mkhe_collective_public_key_v1"
        ));
        let staged_aggregate = collective_source
            .split("pub(super) fn finalize_collective_public_key_from_staged_v1")
            .nth(1)
            .expect("sealed staged CPK aggregate")
            .split("fn validate_collective_public_key_share_for_verified_cpk_v1")
            .next()
            .expect("sealed staged CPK aggregate boundary");
        assert!(
            staged_aggregate.contains("for party_index in 0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1")
        );
        assert!(
            staged_aggregate
                .contains("admission.validate_for_v1(roster, transcript_digest, party_index)?")
        );
        for facade_source in [
            include_str!("../mkhe.rs"),
            include_str!("../../zk_ams.rs"),
            include_str!("../../../vega.rs"),
        ] {
            assert!(facade_source.contains("ZkAmsMkheCpkCeremonyV1"));
        }
        let evaluated_key_runtime = include_str!("collective_eval_keys/runtime.rs");
        let runtime_constructor = evaluated_key_runtime
            .split("pub(super) fn new_from_compact_cpk_v1")
            .nth(1)
            .expect("evaluated-key runtime constructor")
            .split("/// Verified aggregate collective-public-key digest.")
            .next()
            .expect("evaluated-key runtime constructor boundary");
        assert!(runtime_constructor.contains(
            "eval_key_binding: super::collective::ZkAmsMkheStreamingCollectiveEvalKeyBindingV1"
        ));
        assert!(
            runtime_constructor.contains("manifest: &ZkAmsMkheCollectiveEvaluatedKeyManifestV1")
        );
        let provider_admission = evaluated_key_runtime
            .split("pub fn validate_seekable_key_provider")
            .nth(1)
            .expect("provider admission")
            .split("fn entry(")
            .next()
            .expect("provider admission boundary");
        assert!(provider_admission.contains("ZkAmsMkheVerifiedEvaluatedKeyEvidenceSetV1"));
        let cap = provider_admission
            .find("consume_evidence_set_before_provider_v1")
            .expect("capability is consumed");
        let provider = provider_admission
            .find("validate_seekable_evaluated_key")
            .expect("provider is scanned");
        assert!(cap < provider);
        let preflight = evaluated_key_runtime
            .split("fn consume_evidence_set_before_provider_v1")
            .nth(1)
            .expect("private evidence preflight")
            .split("impl ZkAmsMkheCollectiveEvaluatedKeyRuntimeV1")
            .next()
            .expect("private evidence preflight boundary");
        assert!(preflight.contains("consume_for_runtime_v1(expected)"));
    }
    #[test]
    fn current_graph_records_every_open_handoff_without_false_certification() {
        let audit = zk_ams_mkhe_receipt_capability_audit_v1();
        audit.validate().unwrap();
        assert!(audit.cpk_relation_receipt_sealed);
        assert!(audit.cpk_party_state_admission_consumes_receipt);
        assert!(audit.cpk_aggregate_receipt_enforced);
        assert!(audit.rkg_round_one_receipt_enforced);
        assert!(audit.rkg_round_two_receipt_enforced);
        assert!(audit.galois_key_receipt_enforced);
        assert!(!audit.rns_link_transport_bound);
        assert!(!audit.native_bgv_opening_receipt_sealed);
        assert!(audit.native_materialized_hyrax_receipt_sealed);
        assert!(audit.terminal_prover_consumes_native_materialized_receipt);
        assert!(!audit.rns_link_family_geometry_matches_native);
        assert!(!audit.rns_link_carry_quotient_responses_verifiable);
        assert!(!audit.hyrax_bgv_equality_responses_verifiable);
        assert!(audit.persistent_decryption_replay_axes_specified);
        assert_eq!(
            audit.blocker_mask,
            CURRENT_OPEN_RECEIPT_CAPABILITY_BLOCKERS_V1
        );
        assert_eq!(audit.blocker_mask, 0xf0);
        assert_ne!(audit.digest, [0; 32]);
        assert!(!audit.release_available);
    }
    #[test]
    fn receipt_consumers_closed_by_sealed_evidence_sets_are_authorized() {
        for consumer in [
            ZkAmsMkheReceiptCapabilityConsumerV1::CollectivePublicKeyAggregate,
            ZkAmsMkheReceiptCapabilityConsumerV1::RkgRoundOne,
            ZkAmsMkheReceiptCapabilityConsumerV1::RkgRoundTwo,
            ZkAmsMkheReceiptCapabilityConsumerV1::GaloisKey,
        ] {
            assert!(zk_ams_mkhe_receipt_capability_audit_v1().authorizes(consumer));
            assert_eq!(require_zk_ams_mkhe_receipt_capability_v1(consumer), Ok(()));
        }
        for consumer in [
            ZkAmsMkheReceiptCapabilityConsumerV1::RnsLinkVerification,
            ZkAmsMkheReceiptCapabilityConsumerV1::TerminalMaterialization,
            ZkAmsMkheReceiptCapabilityConsumerV1::SplitDecryption,
        ] {
            assert!(!zk_ams_mkhe_receipt_capability_audit_v1().authorizes(consumer));
            assert_eq!(
                require_zk_ams_mkhe_receipt_capability_v1(consumer),
                Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
            );
        }
    }
    #[test]
    fn audit_digest_binds_every_capability_axis() {
        let baseline = zk_ams_mkhe_receipt_capability_audit_v1();
        macro_rules! assert_flag_bound {
            ($field:ident) => {{
                let mut changed = baseline;
                changed.$field = !changed.$field;
                assert_ne!(receipt_capability_audit_digest_v1(changed), baseline.digest);
            }};
        }
        assert_flag_bound!(cpk_relation_receipt_sealed);
        assert_flag_bound!(cpk_party_state_admission_consumes_receipt);
        assert_flag_bound!(cpk_aggregate_receipt_enforced);
        assert_flag_bound!(rkg_round_one_receipt_enforced);
        assert_flag_bound!(rkg_round_two_receipt_enforced);
        assert_flag_bound!(galois_key_receipt_enforced);
        assert_flag_bound!(rns_link_transport_bound);
        assert_flag_bound!(native_bgv_opening_receipt_sealed);
        assert_flag_bound!(native_materialized_hyrax_receipt_sealed);
        assert_flag_bound!(terminal_prover_consumes_native_materialized_receipt);
        assert_flag_bound!(rns_link_family_geometry_matches_native);
        assert_flag_bound!(rns_link_carry_quotient_responses_verifiable);
        assert_flag_bound!(hyrax_bgv_equality_responses_verifiable);
        assert_flag_bound!(rns_link_algebraic_receipt_complete);
        assert_flag_bound!(terminal_materialization_receipt_enforced);
        assert_flag_bound!(split_decryption_receipts_enforced);
        assert_flag_bound!(persistent_decryption_equality_complete);
        assert_flag_bound!(persistent_decryption_replay_axes_specified);
        let mut changed = baseline;
        changed.blocker_mask ^= BLOCKER_RNS_LINK_ALGEBRA_V1;
        assert_ne!(receipt_capability_audit_digest_v1(changed), baseline.digest);
        assert_eq!(
            changed.validate(),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
        let mut changed = baseline;
        changed.release_available = true;
        assert_ne!(receipt_capability_audit_digest_v1(changed), baseline.digest);
        assert_eq!(
            changed.validate(),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
    }
}
