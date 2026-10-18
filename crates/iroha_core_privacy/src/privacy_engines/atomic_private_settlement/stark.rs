//! Settlement-only proof protocol and transcript adapter.

use super::relation::{
    ATOMIC_PRIVATE_SETTLEMENT_RELATION_DESCRIPTOR_V1, CompiledAtomicPrivateSettlementRelationV1,
    internal_statement_v1, relation_profile_v1, validate_public_binding_v1,
};
use crate::privacy_engines::{
    aggregate_stark as aggregate,
    ivm_private_note::{
        IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1, PRIVATE_NOTE_BASE_WIDTH_V1,
        PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1, PRIVATE_NOTE_PROFILE_CONSTRAINT_DEGREE_V1,
        PRIVATE_NOTE_TRACE_LOG2_V1, PrivateNoteRelationProfileV1, PrivateNoteStarkRelationV1,
    },
    proof_managed_note_stark::{
        NOTE_COPY_AUX_WIDTH_V1, NoteCopyChallengesV1, NoteCopyScheduleV1,
        PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1, PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1,
        PROOF_MANAGED_NOTE_QUERY_COUNT_V1, PROOF_MANAGED_NOTE_SECURITY_LANES_V1,
        PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1, PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1,
        ProofManagedNoteCandidateV1, ProofManagedNoteStarkAdapterV1, ProofManagedNoteStarkErrorV1,
        ProofManagedNoteStarkProtocolV1, prove_proof_managed_note_stark_v1_with_rng,
        verify_proof_managed_note_stark_v1,
    },
    transparent_stark::{
        GoldilocksFieldV1 as F, PrivacyOuterDigestV1, TransparentStarkDigestContextV1,
        TransparentTranscriptV1, privacy_outer_digest_frame_v1,
    },
};
use iroha_data_model::{
    nexus::{AtomicPrivateSettlementV1, PrivateSettlementProofStatementV1},
    privacy::{IrohaIvmPrivateNoteStarkStatementV1, PrivacyProtocolIdV1},
};
use rand::TryRngCore;

/// Exact settlement proof relation and transcript descriptor.
pub const ATOMIC_PRIVATE_SETTLEMENT_STARK_PROFILE_DESCRIPTOR_V1: &[u8] = b"iroha-atomic-private-settlement-stark-v1:wire=APZ1-v1:shared-proof-managed-note-geometry:trace=2^14:base=556:profile-aux=1:profile-fixed=123:profile-constraints=1375:constraint-degree=4:max-proof=8388608:relation=ivm-private-note-fixed-2-input-3-output-balanced-with-virtual-zero-inputs-and-audited-input-openings:public-input=sha3-384-opaque48(canonical-manifest-intent-proof-binding,canonical-leg-statement-including-successor-root+epoch,canonical-internal-statement,canonical-genesis):successor-correctness=validator-derived-frontier:post-proof-artifacts=manifest+committee-qc+carrier:output-memos=auditor-plaintext-commitment+payer-change-role+sponsor-reimbursement-terms+success-fee-carriers-2:transparent-amx=separate:governed-disabled-by-default";

const SETTLEMENT_PARAMETERS_V1: aggregate::AggregateStarkParametersV1 =
    aggregate::AggregateStarkParametersV1 {
        proof_magic: *b"APZ1",
        proof_version: 1,
        fri_commitment_layout: aggregate::AggregateFriCommitmentLayoutV1::Scalar,
        security_lanes: PROOF_MANAGED_NOTE_SECURITY_LANES_V1,
        query_count: PROOF_MANAGED_NOTE_QUERY_COUNT_V1,
        blowup_log2: PROOF_MANAGED_NOTE_BLOWUP_LOG2_V1,
        terminal_log2: PROOF_MANAGED_NOTE_TERMINAL_LOG2_V1,
        terminal_degree_bound: PROOF_MANAGED_NOTE_TERMINAL_DEGREE_BOUND_V1,
        composition_degree_chunks: PROOF_MANAGED_NOTE_COMPOSITION_DEGREE_CHUNKS_V1,
        minimum_trace_log2: PRIVATE_NOTE_TRACE_LOG2_V1,
        maximum_trace_log2: PRIVATE_NOTE_TRACE_LOG2_V1,
        maximum_trace_groups: 1,
        maximum_segment_instances: 1,
        maximum_base_columns_per_instance: PRIVATE_NOTE_BASE_WIDTH_V1,
        maximum_aux_columns_per_instance: NOTE_COPY_AUX_WIDTH_V1
            + PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1,
        maximum_proof_bytes: IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1,
    };

const SETTLEMENT_DOMAINS_V1: aggregate::AggregateStarkDomainsV1 =
    aggregate::AggregateStarkDomainsV1 {
        digest_context: TransparentStarkDigestContextV1::new(
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            b"atomic-private-settlement-stark-profile-v1",
        ),
        base_leaf: b"atomic-private-settlement-stark-base-leaf-v1",
        base_node: b"atomic-private-settlement-stark-base-node-v1",
        aux_leaf: b"atomic-private-settlement-stark-aux-leaf-v1",
        aux_node: b"atomic-private-settlement-stark-aux-node-v1",
        composition_leaf: b"atomic-private-settlement-stark-composition-leaf-v1",
        composition_node: b"atomic-private-settlement-stark-composition-node-v1",
        fri_leaf: b"atomic-private-settlement-stark-fri-leaf-v1",
        fri_node: b"atomic-private-settlement-stark-fri-node-v1",
        layout_label: b"atomic-private-settlement-stark-layout-v1",
        base_root_label: b"atomic-private-settlement-stark-base-root-v1",
        aux_root_label: b"atomic-private-settlement-stark-aux-root-v1",
        composition_root_label: b"atomic-private-settlement-stark-composition-root-v1",
        fri_root_label: b"atomic-private-settlement-stark-fri-root-v1",
        fri_beta_label: b"atomic-private-settlement-stark-fri-beta-v1",
        query_seed: b"atomic-private-settlement-stark-query-seed-v1",
    };

fn settlement_protocol_v1() -> ProofManagedNoteStarkProtocolV1 {
    ProofManagedNoteStarkProtocolV1 {
        parameters: SETTLEMENT_PARAMETERS_V1,
        domains: SETTLEMENT_DOMAINS_V1,
        maximum_constraint_degree: PRIVATE_NOTE_PROFILE_CONSTRAINT_DEGREE_V1,
        profile_binding_label: b"atomic-private-settlement-stark-profile-v1",
        profile_descriptor: ATOMIC_PRIVATE_SETTLEMENT_STARK_PROFILE_DESCRIPTOR_V1,
        relation_layout_domain: b"atomic-private-settlement-stark-relation-layout-v1",
    }
}

pub(super) fn validate_atomic_private_settlement_stark_profile_v1()
-> Result<(), ProofManagedNoteStarkErrorV1> {
    settlement_protocol_v1().validate()
}

struct AtomicPrivateSettlementStarkAdapterV1<'a> {
    manifest: &'a AtomicPrivateSettlementV1,
    statement: &'a PrivateSettlementProofStatementV1,
    internal_statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    relation_profile: PrivateNoteRelationProfileV1,
}

impl<'a> AtomicPrivateSettlementStarkAdapterV1<'a> {
    fn new(
        manifest: &'a AtomicPrivateSettlementV1,
        statement: &'a PrivateSettlementProofStatementV1,
        internal_statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
        canonical_genesis_hash: [u8; 32],
        current_height: u64,
        relation_profile: PrivateNoteRelationProfileV1,
    ) -> Self {
        Self {
            manifest,
            statement,
            internal_statement,
            canonical_genesis_hash,
            current_height,
            relation_profile,
        }
    }

    const fn relation_v1(&self) -> PrivateNoteStarkRelationV1<'a> {
        PrivateNoteStarkRelationV1::new(self.internal_statement, self.relation_profile)
    }
}

impl ProofManagedNoteStarkAdapterV1 for AtomicPrivateSettlementStarkAdapterV1<'_> {
    type ProfileChallenges = ();

    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
        settlement_protocol_v1()
    }

    fn public_input_digest_v1(&self) -> Result<PrivacyOuterDigestV1, ProofManagedNoteStarkErrorV1> {
        validate_public_binding_v1(
            self.manifest,
            self.statement,
            self.canonical_genesis_hash,
            self.current_height,
        )
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        if internal_statement_v1(self.manifest, self.statement)
            .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?
            != *self.internal_statement
        {
            return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
        }
        let proof_binding_digest = self
            .manifest
            .proof_binding_digest()
            .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        let statement = norito::encode_canonical(self.statement)
            .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        let internal = norito::encode_canonical(self.internal_statement)
            .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        privacy_outer_digest_frame_v1(
            SETTLEMENT_DOMAINS_V1.digest_context,
            b"atomic-private-settlement-stark-public-input-v1",
            b"statement-binding",
            0,
            0,
            0,
            &[
                proof_binding_digest.as_ref(),
                &statement,
                &internal,
                &self.canonical_genesis_hash,
                ATOMIC_PRIVATE_SETTLEMENT_RELATION_DESCRIPTOR_V1,
            ],
        )
        .map_err(|_| ProofManagedNoteStarkErrorV1::Internal)
    }

    fn trace_log2_v1(&self) -> u8 {
        self.relation_v1().trace_log2_v1()
    }

    fn base_width_v1(&self) -> usize {
        self.relation_v1().base_width_v1()
    }

    fn profile_aux_width_v1(&self) -> usize {
        self.relation_v1().profile_aux_width_v1()
    }

    fn profile_fixed_width_v1(&self) -> usize {
        self.relation_v1().profile_fixed_width_v1()
    }

    fn profile_constraint_count_v1(&self) -> usize {
        self.relation_v1().profile_constraint_count_v1()
    }

    fn copy_schedule_v1(&self) -> Result<NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1> {
        self.relation_v1().copy_schedule_v1()
    }

    fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        self.relation_v1().profile_fixed_columns_v1()
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
        base_columns: &[Vec<F>],
        _copy_aux_columns: &[Vec<F>],
        _fixed_columns: &[Vec<F>],
        _copy_challenges: NoteCopyChallengesV1,
        _profile_challenges: &Self::ProfileChallenges,
    ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        self.relation_v1().profile_aux_columns_v1(base_columns)
    }

    fn profile_constraint_residues_v1(
        &self,
        current_base: &[F],
        next_base: &[F],
        current_aux: &[F],
        next_aux: &[F],
        fixed: &[F],
        _copy_challenges: NoteCopyChallengesV1,
        _profile_challenges: &Self::ProfileChallenges,
    ) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
        self.relation_v1().constraint_residues_v1(
            current_base,
            next_base,
            current_aux,
            next_aux,
            fixed,
        )
    }
}

pub fn prove_atomic_private_settlement_stark_v1_with_rng<R: TryRngCore>(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    compiled: &CompiledAtomicPrivateSettlementRelationV1,
    rng: &mut R,
) -> Result<ProofManagedNoteCandidateV1, ProofManagedNoteStarkErrorV1> {
    let relation = PrivateNoteStarkRelationV1::new(&compiled.internal_statement, compiled.profile);
    let base_columns = relation.compile_prover_columns_v1(&compiled.witness)?;
    prove_proof_managed_note_stark_v1_with_rng(
        &AtomicPrivateSettlementStarkAdapterV1::new(
            manifest,
            statement,
            &compiled.internal_statement,
            canonical_genesis_hash,
            current_height,
            compiled.profile,
        ),
        &base_columns,
        rng,
    )
}

pub fn verify_atomic_private_settlement_stark_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    proof: &[u8],
) -> Result<(), ProofManagedNoteStarkErrorV1> {
    let internal_statement = internal_statement_v1(manifest, statement)
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    let profile = relation_profile_v1(manifest, statement)
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    verify_proof_managed_note_stark_v1(
        &AtomicPrivateSettlementStarkAdapterV1::new(
            manifest,
            statement,
            &internal_statement,
            canonical_genesis_hash,
            current_height,
            profile,
        ),
        proof,
    )
}

/// Independently reconstruct the public adapter and consume one unverified candidate.
pub fn verify_constructed_atomic_private_settlement_stark_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
    candidate: ProofManagedNoteCandidateV1,
) -> Result<Vec<u8>, ProofManagedNoteStarkErrorV1> {
    let internal_statement = internal_statement_v1(manifest, statement)
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    let profile = relation_profile_v1(manifest, statement)
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    candidate.verify_into_bytes_v1(&AtomicPrivateSettlementStarkAdapterV1::new(
        manifest,
        statement,
        &internal_statement,
        canonical_genesis_hash,
        current_height,
        profile,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::aps_sidecar_material_fixture_v1 as sidecar_fixture;
    use super::*;
    use crate::privacy_engines::proof_managed_note_stark::fixed_query_audit;

    fn with_fixed_query_adapter<R>(
        run: impl FnOnce(&AtomicPrivateSettlementStarkAdapterV1<'_>) -> R,
    ) -> R {
        let fixture = sidecar_fixture();
        let manifest = &fixture.sidecar.manifest;
        let statement = &fixture.sidecar.payload.statement;
        let internal = internal_statement_v1(manifest, statement).expect("internal statement");
        let profile = relation_profile_v1(manifest, statement).expect("relation profile");
        let adapter = AtomicPrivateSettlementStarkAdapterV1::new(
            manifest,
            statement,
            &internal,
            *manifest.network_id.as_genesis_hash().as_ref(),
            manifest.authority_context_height,
            profile,
        );
        run(&adapter)
    }

    #[test]
    fn aps_fixed_queries_match_full_lde_at_all_fixture_queries_and_boundaries() {
        with_fixed_query_adapter(|adapter| {
            fixed_query_audit::assert_profile_matches_full_lde_v1(adapter);
        });
    }

    #[test]
    fn aps_malformed_wire_is_rejected_before_fixed_column_construction() {
        with_fixed_query_adapter(|adapter| {
            fixed_query_audit::assert_malformed_rejected_before_fixed_v1(adapter);
        });
    }

    #[test]
    #[ignore = "measurement: compares exact full-LDE and selected fixed evaluation; no proof generation"]
    fn measure_aps_fixed_query_evaluation_eight_workers() {
        with_fixed_query_adapter(|adapter| {
            fixed_query_audit::measure_profile_eight_workers_v1(adapter, "aps");
        });
    }

    #[test]
    fn profile_is_closed_and_uses_distinct_wire_magic() {
        validate_atomic_private_settlement_stark_profile_v1().expect("valid settlement profile");
        assert_eq!(SETTLEMENT_PARAMETERS_V1.proof_magic, *b"APZ1");
        assert_ne!(SETTLEMENT_PARAMETERS_V1.proof_magic, *b"IPS1");
        assert_eq!(
            SETTLEMENT_PARAMETERS_V1.maximum_proof_bytes,
            IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1
        );
    }

    #[test]
    fn public_input_is_stable_when_post_proof_artifacts_are_finalized() {
        let fixture = sidecar_fixture();
        let manifest = &fixture.sidecar.manifest;
        let statement = &fixture.sidecar.payload.statement;
        let canonical_genesis_hash = *manifest.network_id.as_genesis_hash().as_ref();
        let internal = internal_statement_v1(manifest, statement).expect("internal statement");
        let profile = relation_profile_v1(manifest, statement).expect("relation profile");
        let provisional = AtomicPrivateSettlementStarkAdapterV1::new(
            manifest,
            statement,
            &internal,
            canonical_genesis_hash,
            10,
            profile,
        )
        .public_input_digest_v1()
        .expect("provisional public input");

        let mut finalized_manifest = manifest.clone();
        finalized_manifest.legs[0].payload_digest = iroha_crypto::Hash::new(b"final payload");
        finalized_manifest.legs[0].availability_certificate_digest =
            iroha_crypto::Hash::new(b"final availability certificate");
        finalized_manifest.legs[0].delta_digest = iroha_crypto::Hash::new(b"final delta");
        let finalized_internal = internal_statement_v1(&finalized_manifest, statement)
            .expect("finalized internal statement");
        let finalized_profile =
            relation_profile_v1(&finalized_manifest, statement).expect("finalized profile");
        let finalized = AtomicPrivateSettlementStarkAdapterV1::new(
            &finalized_manifest,
            statement,
            &finalized_internal,
            canonical_genesis_hash,
            10,
            finalized_profile,
        )
        .public_input_digest_v1()
        .expect("finalized public input");

        assert_eq!(provisional, finalized);
    }

    #[test]
    fn public_input_and_action_digest_bind_successor_root_and_epoch() {
        let fixture = sidecar_fixture();
        let manifest = &fixture.sidecar.manifest;
        let statement = &fixture.sidecar.payload.statement;
        let canonical_genesis_hash = *manifest.network_id.as_genesis_hash().as_ref();
        let internal = internal_statement_v1(manifest, statement).expect("internal statement");
        let profile = relation_profile_v1(manifest, statement).expect("relation profile");
        let original = AtomicPrivateSettlementStarkAdapterV1::new(
            manifest,
            statement,
            &internal,
            canonical_genesis_hash,
            manifest.authority_context_height,
            profile,
        )
        .public_input_digest_v1()
        .expect("original public input");

        let mut substituted = statement.clone();
        substituted.new_root = iroha_data_model::privacy::PrivacyRootV1::new([0xE7; 32]);
        substituted
            .validate()
            .expect("substituted successor remains structurally valid");
        let substituted_internal =
            internal_statement_v1(manifest, &substituted).expect("substituted internal statement");
        let substituted_profile =
            relation_profile_v1(manifest, &substituted).expect("substituted relation profile");
        let substituted_digest = AtomicPrivateSettlementStarkAdapterV1::new(
            manifest,
            &substituted,
            &substituted_internal,
            canonical_genesis_hash,
            manifest.authority_context_height,
            substituted_profile,
        )
        .public_input_digest_v1()
        .expect("substituted public input");

        assert_ne!(original, substituted_digest);
        assert_ne!(internal.action_digest, substituted_internal.action_digest);

        let mut invalid_epoch = statement.clone();
        invalid_epoch.new_epoch = invalid_epoch.new_epoch.saturating_add(1);
        assert!(invalid_epoch.validate().is_err());
    }
}
