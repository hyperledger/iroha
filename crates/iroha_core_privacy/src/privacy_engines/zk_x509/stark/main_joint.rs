//! Consuming MAIN phases for the paired original MAIN/CA relation.
//!
//! Both roots precede the active quotient coefficients. The complete local
//! relation, 108 cross-proof quotients and every supplemental DEEP term enter
//! the existing composition and original FRI. The canonical claim-free wire
//! can be accepted only after both members of the paired verifier finish.

#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::super::super::accumulator_stark::stages::{
    CaAwaitingMainAuxiliaryV1,
    joint::{CaAwaitingJointOpeningsV1, CaAwaitingJointPointV1},
};
use super::super::super::credential_joint::{
    JointAuxiliaryBindingV1, JointDeepBindingV1, JointOracleCheckpointsV1, JointOriginalOpeningsV1,
    JointPointV1, JointSubproofV1,
};
use super::super::super::sha_call_bus_stark::ZkX509ShaCallScheduleV1;
use super::*;

/// Borrowed, bounded original CA contribution used inside the original MAIN
/// coefficient builder. MAIN24 is returned only after ordinary caches drop.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) struct MainCaCompositionContributionV1<'a> {
    pub(super) plan: &'a main_ca_links::MainCaPrivatePlanV1,
    pub(super) alphas: &'a [E; 108],
    pub(super) original: &'a CaAwaitingMainAuxiliaryV1,
    pub(super) buffers: &'a main_ca_resources::MainCaJointBufferPlanV1,
}

/// All values are already jointly bound before this supplemental coefficient
/// contribution can reach the common original FRI continuation.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) struct MainCaDeepContributionV1<'a> {
    pub(super) plan: &'a main_ca_links::MainCaPrivatePlanV1,
    pub(super) original: &'a main_ca_links::MainCaOriginalAuxiliaryV1,
    pub(super) values: &'a [E; 24],
    pub(super) mixes: &'a [E; 24],
}

/// Original MAIN composition and FRI-mask roots waiting for the CA checkpoint.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct MainAwaitingJointPointV1<'a> {
    phase: ZkX509MainCompositionPhaseV1<'a>,
    ca_plan: main_ca_links::MainCaPrivatePlanV1,
    ca_originals: main_ca_links::MainCaOriginalAuxiliaryV1,
    buffers: main_ca_resources::MainCaJointBufferPlanV1,
    composition: RetainedCompositionMaterialV1,
    composition_roots: Vec<PrivacyOuterDigestV1>,
    fri_masks: Vec<aggregate::AggregateFriMaskOracleMaterialV1>,
    fri_mask_roots: Vec<PrivacyOuterDigestV1>,
    auxiliary: JointAuxiliaryBindingV1,
}

/// MAIN's complete local DEEP record and 24 translated original openings.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct MainAwaitingJointOpeningsV1<'a> {
    oracles: MainAwaitingJointPointV1<'a>,
    point: E,
    deep: aggregate::AggregateDeepProofV1,
    key_openings: [E; main_key_joins::OPENINGS_V1],
    main_openings: [E; 24],
    bound: bool,
    #[cfg(test)]
    timer: PhaseTimerV1,
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> ZkX509MainCompositionPhaseV1<'a> {
    /// Bind this phase's original joined auxiliary root with the original CA
    /// auxiliary root under the exact same X5B1 challenge capability.
    pub(crate) fn joint_auxiliary_binding_v1(
        &self,
        ca: &CaAwaitingMainAuxiliaryV1,
    ) -> Result<JointAuxiliaryBindingV1, ZkX509StarkErrorV1> {
        self.validate_v1()?;
        if self.binding != ca.binding_v1() {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        JointAuxiliaryBindingV1::new_v1(
            &self.binding,
            [self.trace_groups[0].aux_root, ca.auxiliary_root_v1()],
        )
        .map_err(map_transparent_error_v1)
    }

    /// Build the original combined composition before CA working LDEs exist.
    /// Every actual ordinary registration uses the narrowed joint cache plan.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn commit_joint_oracles_v1<R: TryRngCore>(
        mut self,
        ca: &CaAwaitingMainAuxiliaryV1,
        auxiliary: JointAuxiliaryBindingV1,
        rng: &mut R,
    ) -> Result<MainAwaitingJointPointV1<'a>, ZkX509StarkErrorV1> {
        let proof_instance = self.binding.proof_instance_v1();
        self.validate_v1()?;
        if auxiliary != self.joint_auxiliary_binding_v1(ca)? {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let buffers = main_ca_resources::MainCaJointBufferPlanV1::new_v1(&self.layout)?;
        buffers.check_original_owners_v1(
            main_ca_resources::MainCaBufferPhaseV1::Registration,
            ca,
            None,
        )?;
        auxiliary
            .absorb_v1(&mut self.transcript)
            .map_err(map_transparent_error_v1)?;
        // The component transition's earlier draws remain bound history. Only
        // these coefficients sampled after both auxiliary roots are used.
        self.alphas = derive_constraint_alphas_v1(&mut self.transcript, &self.layout)?;
        self.link_alphas = main_terminal_links::MainTerminalLinkPlanV1::new_v1(&self.layout)?
            .derive_alphas_v1(&mut self.transcript)?;
        self.key_alphas = self.key_plan.derive_alphas_v1(&mut self.transcript)?;
        self.sha_union_alphas = self.sha_union_plan.derive_alphas_v1(&mut self.transcript)?;
        let ca_plan = main_ca_links::MainCaPrivatePlanV1::new_v1(
            &self.layout,
            &self.assembly.sha_schedule,
            self.binding.sha(),
        )?;
        let ca_alphas = ca_plan.derive_alphas_v1(&mut self.transcript)?;
        self.composition_transcript_state = self.transcript.state();
        #[cfg(test)]
        let composition_timer = PhaseTimerV1::start_v1(PhaseV1::Composition);
        #[cfg(test)]
        let provider_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionProviders);
        let providers = self.prover_constraint_providers_v1()?;
        #[cfg(test)]
        provider_timer.complete_v1();

        let sources = MainTraceReplaySourcesV1::Bound {
            log19: &self.log19,
            projection: &self.projection,
            io: &self.io,
        };
        let (composition, ca_originals) = main_composition_material_with_ca_v1(
            &self.layout,
            &self.base_polynomials,
            &self.aux_polynomials,
            &sources,
            &providers,
            &self.alphas,
            &self.link_alphas,
            &self.key_plan,
            &self.key_alphas,
            &self.sha_union_plan,
            &self.sha_union_alphas,
            main_bounded_transform::MainBoundedTransformPolicyV1::for_assembly_v1(
                &self.layout,
                self.assembly.allocated_payload_bytes_v1(),
            )?,
            Some(MainCaCompositionContributionV1 {
                plan: &ca_plan,
                alphas: &ca_alphas,
                original: ca,
                buffers: &buffers,
            }),
            rng,
        )?;
        drop(providers);
        let ca_originals = ca_originals.ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        buffers.check_original_owners_v1(
            main_ca_resources::MainCaBufferPhaseV1::Finalization,
            ca,
            Some(&ca_originals),
        )?;
        let shared = self.layout.as_shared()?;
        if SECURITY_LANES != 1 || composition.evaluations.len() != 1 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        #[cfg(test)]
        let commitment_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionCommitment);
        let composition_roots = vec![
            aggregate::streaming_composition_commitment_v1(
                &main_domains_v1(proof_instance),
                0,
                &composition.evaluations[0],
                &[],
            )
            .map_err(map_aggregate_error_v1)?
            .root,
        ];
        aggregate::absorb_composition_roots_v1(
            &mut self.transcript,
            AGGREGATE_PARAMETERS_V1,
            &main_domains_v1(proof_instance),
            &composition_roots,
        )
        .map_err(map_aggregate_error_v1)?;
        #[cfg(test)]
        commitment_timer.complete_v1();
        #[cfg(test)]
        composition_timer.complete_v1();
        let fri_masks = aggregate::build_fri_mask_oracles_v1(
            AGGREGATE_PARAMETERS_V1,
            &main_domains_v1(proof_instance),
            &shared,
            rng,
        )
        .map_err(map_aggregate_error_v1)?;
        if fri_masks.len() != 1 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let fri_mask_roots = vec![fri_masks[0].tree.root()];
        aggregate::absorb_fri_mask_roots_v1(
            &mut self.transcript,
            AGGREGATE_PARAMETERS_V1,
            &main_domains_v1(proof_instance),
            &fri_mask_roots,
        )
        .map_err(map_aggregate_error_v1)?;
        Ok(MainAwaitingJointPointV1 {
            phase: self,
            ca_plan,
            ca_originals,
            buffers,
            composition,
            composition_roots,
            fri_masks,
            fri_mask_roots,
            auxiliary,
        })
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainAwaitingJointPointV1<'a> {
    /// Both original checkpoints and all translated-source exclusions define
    /// the same challenge. An independent standalone point is never accepted.
    pub(crate) fn derive_joint_point_v1(
        &self,
        ca: &CaAwaitingJointPointV1,
    ) -> Result<JointPointV1, ZkX509StarkErrorV1> {
        let ca = ca.checkpoint_v1();
        let shared = self.phase.layout.as_shared()?;
        JointOracleCheckpointsV1 {
            transcript_states: [self.phase.transcript.state(), ca[0]],
            composition_roots: [self.composition_roots[0], ca[1]],
            fri_mask_roots: [self.fri_mask_roots[0], ca[2]],
        }
        .derive_point_v1(self.auxiliary, |point| {
            self.phase
                .key_plan
                .admissible_v1(point, &shared)
                .unwrap_or(false)
                && self.ca_plan.admissible_v1(point).unwrap_or(false)
        })
        .map_err(map_transparent_error_v1)
    }

    /// Evaluate original MAIN traces and chunks, retaining no full replay LDE.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn open_joint_point_v1(
        mut self,
        point: JointPointV1,
    ) -> Result<MainAwaitingJointOpeningsV1<'a>, ZkX509StarkErrorV1> {
        let z = point.point_v1();
        let shared = self.phase.layout.as_shared()?;
        if !self.phase.key_plan.admissible_v1(z, &shared)? || !self.ca_plan.admissible_v1(z)? {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        point
            .absorb_v1(JointSubproofV1::Main, &mut self.phase.transcript)
            .map_err(map_transparent_error_v1)?;
        #[cfg(test)]
        let timer = PhaseTimerV1::start_v1(PhaseV1::DeepAndFri);
        let sources = MainTraceReplaySourcesV1::Bound {
            log19: &self.phase.log19,
            projection: &self.phase.projection,
            io: &self.phase.io,
        };
        let key_openings = self.phase.key_plan.open_v1(
            &self.phase.layout,
            &self.phase.base_polynomials,
            &sources,
            z,
            main_bounded_transform::MainBoundedTransformPolicyV1::for_assembly_v1(
                &self.phase.layout,
                self.phase.assembly.allocated_payload_bytes_v1(),
            )?,
        )?;
        let mut trace_groups = Vec::new();
        trace_groups
            .try_reserve_exact(FULL_PROFILE_TRACE_GROUPS_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for group in 0..FULL_PROFILE_TRACE_GROUPS_V1 {
            let (base_current, base_next) = self.phase.base_polynomials.deep_group_v1(
                &self.phase.layout,
                MainTraceColumnKindV1::Base,
                group,
                z,
                &sources,
            )?;
            let (aux_current, aux_next) = self.phase.aux_polynomials.deep_group_v1(
                &self.phase.layout,
                MainTraceColumnKindV1::Aux,
                group,
                z,
                &sources,
            )?;
            trace_groups.push(aggregate::AggregateDeepTraceGroupOpeningV1 {
                base_current: fp4_values_to_wire_v1(base_current),
                base_next: fp4_values_to_wire_v1(base_next),
                aux_current: fp4_values_to_wire_v1(aux_current),
                aux_next: fp4_values_to_wire_v1(aux_next),
            });
        }
        let deep = aggregate::AggregateDeepProofV1 {
            trace_groups,
            composition_values: evaluate_retained_composition_coefficients_at_deep_v1(
                &self.composition.coefficient_chunks,
                z,
            )?
            .into_iter()
            .map(fp4_values_to_wire_v1)
            .collect(),
        };
        aggregate::absorb_deep_openings_v1(
            &mut self.phase.transcript,
            &deep,
            AGGREGATE_PARAMETERS_V1,
            &shared,
        )
        .map_err(map_aggregate_error_v1)?;
        main_key_joins::MainKeyJoinPlanV1::absorb_openings_v1(
            &key_openings,
            &mut self.phase.transcript,
        )?;
        let main_openings = self.ca_plan.open_v1(&self.ca_originals, z)?;
        Ok(MainAwaitingJointOpeningsV1 {
            oracles: self,
            point: z,
            deep,
            key_openings,
            main_openings,
            bound: false,
            #[cfg(test)]
            timer,
        })
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainAwaitingJointOpeningsV1<'_> {
    /// Mutate both transcript owners in one operation before either local FRI
    /// may sample mixes. Each finishing stage checks the resulting capability.
    pub(crate) fn bind_ca_openings_v1(
        &mut self,
        ca: &mut CaAwaitingJointOpeningsV1,
    ) -> Result<JointDeepBindingV1, ZkX509StarkErrorV1> {
        if self.bound {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let binding = ca
            .bind_with_main_v1(&mut self.oracles.phase.transcript, self.main_openings)
            .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
        self.bound = true;
        Ok(binding)
    }

    /// Use the common original FRI/query/codec path with the24 supplemental
    /// divided differences accumulated before its original FRI evaluation.
    pub(crate) fn finish_v1(
        mut self,
        binding: JointDeepBindingV1,
    ) -> Result<Vec<u8>, ZkX509StarkErrorV1> {
        if !self.bound
            || !binding.matches_v1(JointSubproofV1::Main, &self.oracles.phase.transcript)
            || binding.openings_v1().main != self.main_openings
        {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        self.oracles
            .buffers
            .required_v1(main_ca_resources::MainCaBufferPhaseV1::Finalization)?;
        let key_mixes =
            main_key_joins::MainKeyJoinPlanV1::derive_mixes_v1(&mut self.oracles.phase.transcript)?;
        let (main_mixes, _ca_mixes) = main_ca_links::MainCaPrivatePlanV1::derive_mixes_v1(
            &mut self.oracles.phase.transcript,
        )?;
        let mixes = derive_fri_mixes_v1(
            &mut self.oracles.phase.transcript,
            &self.oracles.phase.layout,
        )?;
        self.oracles.phase.finish_original_openings_v1(
            self.oracles.composition,
            self.oracles.composition_roots,
            self.oracles.fri_masks,
            self.oracles.fri_mask_roots,
            self.deep,
            self.point,
            self.key_openings,
            key_mixes,
            mixes,
            Some(MainCaDeepContributionV1 {
                plan: &self.oracles.ca_plan,
                original: &self.oracles.ca_originals,
                values: &self.main_openings,
                mixes: &main_mixes,
            }),
            #[cfg(test)]
            self.timer,
        )
    }
}

// TODO: validate the paired engine and actual CA capacity gates natively, then
// qualify the complete relation, joint hiding and maximum proof resources.

/// Closed verifier contribution, evaluated against authenticated original DEEP
/// trace openings before the combined composition equality can be accepted.
pub(super) struct MainCaOpenedContributionV1<'a> {
    pub(super) plan: &'a main_ca_links::MainCaPrivatePlanV1,
    pub(super) alphas: &'a [E; 108],
    pub(super) openings: &'a JointOriginalOpeningsV1,
}

/// Canonically decoded MAIN proof at the same two-oracle checkpoint as prover.
pub struct MainJointVerifierOraclesV1<'a> {
    statement: &'a IrohaZkX509StarkP256StatementV1,
    rfc_statement: &'a ZkX509Rfc5280StatementV1,
    binding: ZkX509CredentialPreAuxBindingV1,
    auxiliary: JointAuxiliaryBindingV1,
    layout: AggregateProofLayoutV1,
    proof: ZkX509SegmentedStarkProofV1,
    key_openings: [E; main_key_joins::OPENINGS_V1],
    key_plan: main_key_joins::MainKeyJoinPlanV1,
    key_alphas: Vec<E>,
    link_alphas: Vec<E>,
    sha_union_plan: main_sha_union::MainShaUnionPlanV1,
    sha_union_alphas: Vec<E>,
    alphas: Vec<Vec<Vec<E>>>,
    ca_plan: main_ca_links::MainCaPrivatePlanV1,
    ca_alphas: [E; 108],
    transcript: TransparentTranscriptV1,
}

/// The normal original DEEP/key records have entered the local transcript;
/// neither FRI nor a translated opening is accepted before the paired bind.
pub struct MainJointVerifierDeepV1<'a> {
    oracles: MainJointVerifierOraclesV1<'a>,
    point: E,
    openings: Option<JointOriginalOpeningsV1>,
}

impl<'a> MainJointVerifierOraclesV1<'a> {
    /// Reconstruct each local and joint challenge in exactly the prover order.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(crate) fn new_v1(
        statement: &'a IrohaZkX509StarkP256StatementV1,
        rfc_statement: &'a ZkX509Rfc5280StatementV1,
        public: ZkX509CredentialPublicBindingV1,
        binding: ZkX509CredentialPreAuxBindingV1,
        auxiliary: JointAuxiliaryBindingV1,
        schedule: &ZkX509ShaCallScheduleV1,
        encoded: &[u8],
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let proof_instance = binding.proof_instance_v1();
        let verifier_profile = construct_zk_x509_main_verifier_profile_v1()?;
        let layout = AggregateProofLayoutV1::for_full_profile_v1()?;
        let envelope = decode_zk_x509_main_proof_envelope_v1(encoded)?;
        let proof = decode_zk_x509_segmented_stark_proof_v1(envelope.aggregate_proof, &layout)?;
        let main_pre_aux = main_pre_aux_from_decoded_proof_v1(
            proof_instance,
            public,
            verifier_profile,
            &layout,
            &proof,
        )?;
        if !binding.matches_main_pre_aux_v1(main_pre_aux)
            || proof.aggregate.trace_groups.len() != ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1
            || proof.aggregate.composition_roots.len() != 1
            || proof.aggregate.fri_mask_roots.len() != 1
            || !auxiliary.matches_v1(
                &binding,
                JointSubproofV1::Main,
                proof.aggregate.trace_groups[0].aux_root,
            )
        {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let mut transcript = new_main_transcript_v1(
            proof_instance,
            &public.consensus_context_digest,
            verifier_profile,
        )?;
        absorb_aggregate_layout_v1(
            proof_instance,
            &mut transcript,
            MAIN_LAYOUT_DOMAIN_V1,
            &layout,
        )?;
        aggregate::absorb_base_roots_v1(
            &mut transcript,
            &main_domains_v1(proof_instance),
            &proof.aggregate.trace_groups,
        )
        .map_err(map_aggregate_error_v1)?;
        absorb_zk_x509_credential_pre_aux_binding_v1(&mut transcript, binding)
            .map_err(map_credential_pre_aux_error_v1)?;
        aggregate::absorb_aux_roots_v1(
            &mut transcript,
            &main_domains_v1(proof_instance),
            &proof.aggregate.trace_groups,
        )
        .map_err(map_aggregate_error_v1)?;
        // Reproduce the component phase's bound history before its consuming
        // joint transition; none of these earlier coefficients are accepted.
        let _ = derive_constraint_alphas_v1(&mut transcript, &layout)?;
        let _ = main_terminal_links::MainTerminalLinkPlanV1::new_v1(&layout)?
            .derive_alphas_v1(&mut transcript)?;
        let key_plan = main_key_joins::MainKeyJoinPlanV1::new_v1(
            &layout,
            statement,
            ZkX509Rfc5280StarkShapeV1::from_statement(rfc_statement)
                .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?,
        )?;
        let _ = key_plan.derive_alphas_v1(&mut transcript)?;
        let sha_union_plan = main_sha_union::MainShaUnionPlanV1::new_v1(&layout)?;
        let _ = sha_union_plan.derive_alphas_v1(&mut transcript)?;
        auxiliary
            .absorb_v1(&mut transcript)
            .map_err(map_transparent_error_v1)?;
        let alphas = derive_constraint_alphas_v1(&mut transcript, &layout)?;
        let link_alphas = main_terminal_links::MainTerminalLinkPlanV1::new_v1(&layout)?
            .derive_alphas_v1(&mut transcript)?;
        let key_alphas = key_plan.derive_alphas_v1(&mut transcript)?;
        let sha_union_alphas = sha_union_plan.derive_alphas_v1(&mut transcript)?;
        let ca_plan = main_ca_links::MainCaPrivatePlanV1::new_v1(&layout, schedule, binding.sha())?;
        let ca_alphas = ca_plan.derive_alphas_v1(&mut transcript)?;
        aggregate::absorb_composition_roots_v1(
            &mut transcript,
            AGGREGATE_PARAMETERS_V1,
            &main_domains_v1(proof_instance),
            &proof.aggregate.composition_roots,
        )
        .map_err(map_aggregate_error_v1)?;
        aggregate::absorb_fri_mask_roots_v1(
            &mut transcript,
            AGGREGATE_PARAMETERS_V1,
            &main_domains_v1(proof_instance),
            &proof.aggregate.fri_mask_roots,
        )
        .map_err(map_aggregate_error_v1)?;
        Ok(Self {
            statement,
            rfc_statement,
            binding,
            auxiliary,
            layout,
            proof,
            key_openings: envelope.key_openings,
            key_plan,
            key_alphas,
            link_alphas,
            sha_union_plan,
            sha_union_alphas,
            alphas,
            ca_plan,
            ca_alphas,
            transcript,
        })
    }

    /// Derive the same admitted shared point from both decoded original oracles.
    pub(crate) fn derive_joint_point_v1(
        &self,
        ca: &super::super::super::accumulator_stark::joint_verifier::CaJointVerifierOraclesV1,
    ) -> Result<JointPointV1, ZkX509StarkErrorV1> {
        let ca = ca.checkpoint_v1();
        let shared = self.layout.as_shared()?;
        JointOracleCheckpointsV1 {
            transcript_states: [self.transcript.state(), ca[0]],
            composition_roots: [self.proof.aggregate.composition_roots[0], ca[1]],
            fri_mask_roots: [self.proof.aggregate.fri_mask_roots[0], ca[2]],
        }
        .derive_point_v1(self.auxiliary, |point| {
            self.key_plan.admissible_v1(point, &shared).unwrap_or(false)
                && self.ca_plan.admissible_v1(point).unwrap_or(false)
        })
        .map_err(map_transparent_error_v1)
    }

    pub(crate) fn open_joint_point_v1(
        mut self,
        point: JointPointV1,
    ) -> Result<MainJointVerifierDeepV1<'a>, ZkX509StarkErrorV1> {
        let z = point.point_v1();
        let shared = self.layout.as_shared()?;
        if !self.key_plan.admissible_v1(z, &shared)? || !self.ca_plan.admissible_v1(z)? {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        point
            .absorb_v1(JointSubproofV1::Main, &mut self.transcript)
            .map_err(map_transparent_error_v1)?;
        aggregate::absorb_deep_openings_v1(
            &mut self.transcript,
            &self.proof.deep,
            AGGREGATE_PARAMETERS_V1,
            &shared,
        )
        .map_err(map_aggregate_error_v1)?;
        main_key_joins::MainKeyJoinPlanV1::absorb_openings_v1(
            &self.key_openings,
            &mut self.transcript,
        )?;
        Ok(MainJointVerifierDeepV1 {
            oracles: self,
            point: z,
            openings: None,
        })
    }
}

impl MainJointVerifierDeepV1<'_> {
    /// Exactly one canonical outer opening record mutates both local transcripts.
    pub(crate) fn bind_ca_openings_v1(
        &mut self,
        ca: &mut super::super::super::accumulator_stark::joint_verifier::CaJointVerifierDeepV1,
        openings: JointOriginalOpeningsV1,
    ) -> Result<JointDeepBindingV1, ZkX509StarkErrorV1> {
        if self.openings.is_some() {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let binding = ca
            .bind_with_main_v1(&mut self.oracles.transcript, openings)
            .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
        self.openings = Some(openings);
        Ok(binding)
    }

    /// Authenticate both the complete MAIN/cross composition and the original
    /// FRI that binds all31 key plus24 translated auxiliary openings.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn finish_v1(
        mut self,
        binding: JointDeepBindingV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        let proof_instance = self.oracles.binding.proof_instance_v1();
        if !binding.matches_v1(JointSubproofV1::Main, &self.oracles.transcript)
            || self.openings != Some(binding.openings_v1())
        {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let stage = &mut self.oracles;
        let shared = stage.layout.as_shared()?;
        let openings = binding.openings_v1();
        let key_mixes = main_key_joins::MainKeyJoinPlanV1::derive_mixes_v1(&mut stage.transcript)?;
        let (main_mixes, _ca_mixes) =
            main_ca_links::MainCaPrivatePlanV1::derive_mixes_v1(&mut stage.transcript)?;
        let mut supplemental =
            stage
                .key_plan
                .supplemental_v1(self.point, &stage.key_openings, &key_mixes)?;
        supplemental.extend(stage.ca_plan.supplemental_v1(
            self.point,
            &openings.main,
            &main_mixes,
        )?);
        let mixes = derive_fri_mixes_v1(&mut stage.transcript, &stage.layout)?;
        let deep_mixes = aggregate_deep_lane_mixes_v1(&mixes, &stage.layout)?;
        let (fri_betas, terminals) = aggregate::verify_fri_commitments_v1(
            &stage.proof.aggregate,
            AGGREGATE_PARAMETERS_V1,
            &main_domains_v1(proof_instance),
            &shared,
            &mut stage.transcript,
        )
        .map_err(map_aggregate_error_v1)?;
        verify_grinding_nonce_v1(
            proof_instance.main_context_v1(),
            &stage.transcript.state(),
            ZK_X509_GRINDING_BITS_V1,
            stage.proof.aggregate.grinding_nonce,
        )
        .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
        absorb_grinding_nonce_v1(&mut stage.transcript, stage.proof.aggregate.grinding_nonce)?;
        let indices = query_indices_v1(proof_instance, &stage.transcript, &stage.layout)?;
        aggregate::verify_all_merkle_openings_v1(
            &stage.proof.aggregate,
            AGGREGATE_PARAMETERS_V1,
            &main_domains_v1(proof_instance),
            &shared,
            &indices,
        )
        .map_err(map_aggregate_error_v1)?;
        let post_base = stage.binding.main_post_base();
        let p256_fixed = P256MainVerifierFixedSourceV1::new_v1()?;
        let log5 = MainP256Log5VerifierConstraintSourceV1::for_main_v1(
            &stage.layout,
            &p256_fixed,
            post_base,
        )?;
        let projection = MainProjectionVerifierConstraintSourceV1::for_main_v1(
            &stage.layout,
            stage.statement,
            post_base,
        )?;
        let io = MainIoVerifierConstraintSourceV1::for_main_v1(
            &stage.layout,
            stage.statement,
            post_base,
        )?;
        let mut log19 = MainLog19VerifierConstraintSourceV1::for_main_v1(
            &stage.layout,
            stage.rfc_statement,
            post_base,
        )?;
        log19.prepare_complete_oods_fixed_v1()?;
        main_oods::verify_main_deep_constraints_with_ca_v1(
            &stage.layout,
            &stage.proof.deep,
            self.point,
            &stage.alphas,
            &stage.link_alphas,
            &stage.key_plan,
            &stage.key_alphas,
            &stage.key_openings,
            &stage.sha_union_plan,
            &stage.sha_union_alphas,
            &log5,
            &projection,
            &io,
            &log19,
            Some(MainCaOpenedContributionV1 {
                plan: &stage.ca_plan,
                alphas: &stage.ca_alphas,
                openings: &openings,
            }),
        )?;
        aggregate::verify_opened_query_relations_after_complete_oods_v1(
            &stage.proof.aggregate,
            &stage.proof.deep,
            self.point,
            &deep_mixes,
            AGGREGATE_PARAMETERS_V1,
            &shared,
            &indices,
            &fri_betas,
            &terminals,
            &supplemental,
        )
        .map_err(map_aggregate_error_v1)?;
        Ok(())
    }
}

/// Public roots used only to reconstruct the paired transcript. Neither this
/// decode nor the returned binding constitutes acceptance of either subproof.
pub fn main_joint_auxiliary_from_proofs_v1(
    binding: &ZkX509CredentialPreAuxBindingV1,
    main: &[u8],
    ca: &[u8],
) -> Result<JointAuxiliaryBindingV1, ZkX509StarkErrorV1> {
    let layout = AggregateProofLayoutV1::for_full_profile_v1()?;
    let envelope = decode_zk_x509_main_proof_envelope_v1(main)?;
    let proof = decode_zk_x509_segmented_stark_proof_v1(envelope.aggregate_proof, &layout)?;
    if proof.aggregate.trace_groups.len() != ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1 {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let ca_root =
        super::super::super::accumulator_stark::joint_verifier::ca_joint_auxiliary_root_v1(ca)
            .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
    JointAuxiliaryBindingV1::new_v1(binding, [proof.aggregate.trace_groups[0].aux_root, ca_root])
        .map_err(map_transparent_error_v1)
}

/// Complete both original subproofs using one shared point and paired openings.
/// Calling this function never changes the production activation policy.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn finish_joint_main_ca_v1<R: TryRngCore>(
    main: ZkX509MainCompositionPhaseV1<'_>,
    ca: CaAwaitingMainAuxiliaryV1,
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>, JointOriginalOpeningsV1), ZkX509StarkErrorV1> {
    let auxiliary = main.joint_auxiliary_binding_v1(&ca)?;
    // CA local LDE/composition working owners are created only after the final
    // ordinary MAIN registration and its restricted cache have been dropped.
    let main = main.commit_joint_oracles_v1(&ca, auxiliary, rng)?;
    let ca = ca
        .commit_joint_oracles_v1(auxiliary, rng)
        .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?;
    let point = main.derive_joint_point_v1(&ca)?;
    let mut main = main.open_joint_point_v1(point)?;
    let mut ca = ca
        .open_joint_point_v1(point)
        .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?;
    let binding = main.bind_ca_openings_v1(&mut ca)?;
    let openings = binding.openings_v1();
    // Finish MAIN first so its large coefficient and LDE owners are released
    // before the complete CA row trees and local FRI are constructed.
    let main = main.finish_v1(binding)?;
    let ca = ca
        .finish_v1(binding)
        .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?;
    Ok((main, ca, openings))
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> ZkX509MainAwaitingCredentialBindingV1<'a> {
    /// Admit retained CA originals before allocating MAIN auxiliary replay and
    /// masks; the same owner is passed to every later joint phase.
    pub(crate) fn bind_joint_credential_pre_aux_v1_with_rng<R: TryRngCore>(
        self,
        ca: &CaAwaitingMainAuxiliaryV1,
        rng: &mut R,
    ) -> Result<ZkX509MainCompositionPhaseV1<'a>, ZkX509StarkErrorV1> {
        main_ca_resources::MainCaJointBufferPlanV1::new_v1(&self.layout)?
            .check_original_owners_v1(
                main_ca_resources::MainCaBufferPhaseV1::OriginalCommitments,
                ca,
                None,
            )?;
        self.bind_credential_pre_aux_v1_with_rng(ca.binding_v1(), rng)
    }
}
