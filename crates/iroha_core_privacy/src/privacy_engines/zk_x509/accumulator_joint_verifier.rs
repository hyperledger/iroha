//! Paired-transcript verification of the original CA commitments and FRI.
//!
//! The outer credential verifier must complete the matching MAIN phase too.
//! MAIN authenticates all108 private endpoint equations. This local phase
//! cannot accept an independently supplied point or omit the paired records.

use super::private_links::{CA_EXTRA_MIX_LABEL_V1, CA_EXTRA_OPENINGS_V1, CaMainPrivateLinkPlanV1};
use super::*;
use crate::privacy_engines::zk_x509::credential_joint::{
    JointAuxiliaryBindingV1, JointDeepBindingV1, JointOriginalOpeningsV1, JointPointV1,
    JointSubproofV1,
};

pub struct CaJointVerifierOraclesV1 {
    public: ZkX509CaAccumulatorStarkPublicV1,
    pre_aux: super::super::credential_pre_aux::ZkX509CredentialPreAuxBindingV1,
    layout: aggregate::AggregateProofLayoutV1,
    proof: aggregate::AggregateStarkProofV1,
    deep: aggregate::AggregateDeepProofV1,
    alphas: Vec<E>,
    plan: CaMainPrivateLinkPlanV1,
    transcript: TransparentTranscriptV1,
}
pub struct CaJointVerifierDeepV1 {
    oracles: CaJointVerifierOraclesV1,
    point: E,
    openings: Option<JointOriginalOpeningsV1>,
}
impl CaJointVerifierOraclesV1 {
    /// Decode canonical CA records and bind both original auxiliary roots before
    /// every constraint coefficient. The paired MAIN phase checks the MAIN root.
    pub(crate) fn new_v1(
        public: ZkX509CaAccumulatorStarkPublicV1,
        schedule: &ZkX509ShaCallScheduleV1,
        main_pre_aux: ZkX509CredentialMainPreAuxV1,
        auxiliary: JointAuxiliaryBindingV1,
        encoded: &[u8],
    ) -> Result<Self, ZkX509CaAccumulatorProofErrorV1> {
        let proof_instance = main_pre_aux.proof_instance_v1();
        validate_ca_proof_public_v1(public, schedule)?;
        checked_ca_accumulator_resource_envelope_v1(
            ca_accumulator_resource_request_v1(
                ZK_X509_CA_ACCUMULATOR_REDUCED_AIR_DEGREE_V1,
                1,
                CA_QUERY_COUNT_V1,
            )
            .map_err(ZkX509CaAccumulatorProofErrorV1::from)?,
        )
        .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
        let layout = ca_aggregate_layout_v1()?;
        let inner = decode_ca_proof_envelope_v1(encoded)?;
        let (proof, deep) =
            aggregate::decode_proof_with_deep_v1(inner, CA_AGGREGATE_PARAMETERS_V1, &layout)
                .map_err(map_aggregate_proof_error_v1)?;
        if proof.trace_groups.len() != 1
            || proof.composition_roots.len() != 1
            || proof.fri_mask_roots.len() != 1
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::MalformedProof);
        }
        let mut transcript = new_ca_transcript_v1(proof_instance, public, schedule, &layout)?;
        aggregate::absorb_base_roots_v1(
            &mut transcript,
            &ca_domains_v1(proof_instance),
            &proof.trace_groups,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        let pre_aux = derive_zk_x509_credential_pre_aux_binding_v1(
            main_pre_aux,
            ca_profile_digest_v1()?,
            ca_public_digest_v1(proof_instance, public, schedule)?,
            proof.trace_groups[0].base_root,
        )
        .map_err(map_credential_pre_aux_error_v1)?;
        if !auxiliary.matches_v1(
            &pre_aux,
            JointSubproofV1::Ca,
            proof.trace_groups[0].aux_root,
        ) {
            return Err(ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch);
        }
        absorb_zk_x509_credential_pre_aux_binding_v1(&mut transcript, pre_aux)
            .map_err(map_credential_pre_aux_error_v1)?;
        aggregate::absorb_aux_roots_v1(
            &mut transcript,
            &ca_domains_v1(proof_instance),
            &proof.trace_groups,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        auxiliary
            .absorb_v1(&mut transcript)
            .map_err(map_transparent_proof_error_v1)?;
        let plan = CaMainPrivateLinkPlanV1::new_v1(schedule, pre_aux.sha())?;
        plan.absorb_registration_v1(&mut transcript)?;
        let alphas = derive_ca_constraint_alphas_v1(&mut transcript)?;
        aggregate::absorb_composition_roots_v1(
            &mut transcript,
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &proof.composition_roots,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        aggregate::absorb_fri_mask_roots_v1(
            &mut transcript,
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &proof.fri_mask_roots,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        Ok(Self {
            public,
            pre_aux,
            layout,
            proof,
            deep,
            alphas,
            plan,
            transcript,
        })
    }
    pub(crate) fn checkpoint_v1(&self) -> [PrivacyOuterDigestV1; 3] {
        [
            self.transcript.state(),
            self.proof.composition_roots[0],
            self.proof.fri_mask_roots[0],
        ]
    }
    pub(crate) fn open_joint_point_v1(
        mut self,
        point: JointPointV1,
    ) -> Result<CaJointVerifierDeepV1, ZkX509CaAccumulatorProofErrorV1> {
        let z = point.point_v1();
        if !self.plan.admissible_v1(z)? {
            return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
        }
        point
            .absorb_v1(JointSubproofV1::Ca, &mut self.transcript)
            .map_err(map_transparent_proof_error_v1)?;
        aggregate::absorb_deep_openings_v1(
            &mut self.transcript,
            &self.deep,
            CA_AGGREGATE_PARAMETERS_V1,
            &self.layout,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        Ok(CaJointVerifierDeepV1 {
            oracles: self,
            point: z,
            openings: None,
        })
    }
}
impl CaJointVerifierDeepV1 {
    /// Bind the canonical outer opening record after MAIN's complete DEEP/key
    /// record. The resulting capability is required by both finishing phases.
    pub(crate) fn bind_with_main_v1(
        &mut self,
        main_transcript: &mut TransparentTranscriptV1,
        openings: JointOriginalOpeningsV1,
    ) -> Result<JointDeepBindingV1, ZkX509CaAccumulatorProofErrorV1> {
        let proof_instance = self.oracles.pre_aux.proof_instance_v1();
        if self.openings.is_some() {
            return Err(ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch);
        }
        let binding = openings
            .bind_both_v1(
                proof_instance,
                main_transcript,
                &mut self.oracles.transcript,
            )
            .map_err(map_transparent_proof_error_v1)?;
        self.openings = Some(openings);
        Ok(binding)
    }
    pub(crate) fn finish_v1(
        mut self,
        binding: JointDeepBindingV1,
    ) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
        let proof_instance = self.oracles.pre_aux.proof_instance_v1();
        if !binding.matches_v1(JointSubproofV1::Ca, &self.oracles.transcript)
            || self.openings != Some(binding.openings_v1())
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch);
        }
        let stage = &mut self.oracles;
        let deep_mixes = derive_ca_deep_mixes_v1(&mut stage.transcript, &stage.layout)?;
        let extra_mixes = ca_challenge_vector_v1(
            &mut stage.transcript,
            CA_EXTRA_MIX_LABEL_V1,
            CA_EXTRA_OPENINGS_V1,
        )?;
        let supplemental =
            stage
                .plan
                .ca_supplemental_v1(self.point, &binding.openings_v1().ca, &extra_mixes)?;
        let (fri_betas, terminals) = aggregate::verify_fri_commitments_v1(
            &stage.proof,
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &stage.layout,
            &mut stage.transcript,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        verify_grinding_nonce_v1(
            proof_instance.ca_context_v1(),
            &stage.transcript.state(),
            ZK_X509_GRINDING_BITS_V1,
            stage.proof.grinding_nonce,
        )
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch)?;
        absorb_ca_grinding_nonce_v1(&mut stage.transcript, stage.proof.grinding_nonce)?;
        let indices = aggregate::query_indices_v1(
            &stage.transcript,
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &stage.layout,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        aggregate::verify_all_merkle_openings_v1(
            &stage.proof,
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &stage.layout,
            &indices,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        let fixed = compile_ca_accumulator_fixed_columns_v1()
            .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
        verify_ca_deep_constraints_v1(
            stage.public,
            &stage.deep,
            self.point,
            &stage.layout,
            &fixed,
            stage.pre_aux.sha(),
            stage.pre_aux.rfc5280(),
            &stage.alphas,
        )?;
        aggregate::verify_opened_query_relations_after_complete_oods_v1(
            &stage.proof,
            &stage.deep,
            self.point,
            &deep_mixes,
            CA_AGGREGATE_PARAMETERS_V1,
            &stage.layout,
            &indices,
            &fri_betas,
            &terminals,
            &supplemental,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        Ok(())
    }
}

/// Decode the original CA auxiliary root solely for joint transcript assembly.
/// The caller must subsequently complete both paired cryptographic verifiers.
pub fn ca_joint_auxiliary_root_v1(
    encoded: &[u8],
) -> Result<PrivacyOuterDigestV1, ZkX509CaAccumulatorProofErrorV1> {
    let layout = ca_aggregate_layout_v1()?;
    let inner = decode_ca_proof_envelope_v1(encoded)?;
    let (proof, _) =
        aggregate::decode_proof_with_deep_v1(inner, CA_AGGREGATE_PARAMETERS_V1, &layout)
            .map_err(map_aggregate_proof_error_v1)?;
    proof
        .trace_groups
        .first()
        .filter(|_| proof.trace_groups.len() == 1)
        .map(|group| group.aux_root)
        .ok_or(ZkX509CaAccumulatorProofErrorV1::MalformedProof)
}
