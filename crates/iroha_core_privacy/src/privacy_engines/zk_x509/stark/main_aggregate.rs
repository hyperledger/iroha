//! Canonical MAIN aggregate prover and verifier.
//!
//! The implementation shares the verifier-fixed layouts, transcript helpers,
//! and concrete trace providers owned by the parent STARK module.
// This is a private continuation of the parent module's fixed protocol
// vocabulary; it does not define an independent extension surface.
#[cfg(test)]
use super::super::prover_observation::{PhaseTimerV1, PhaseV1};
use super::super::{
    der_stark::ZkX509DerStarkChallengesV1, rfc5280_stark::ZkX509Rfc5280StarkChallengesV1,
    sha_call_bus_stark::ZkX509ShaCallBusChallengesV1,
    sha_word_stark::ZkX509ShaWordStarkChallengesV1,
};
use super::*;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_bounded_transform.rs"]
mod main_bounded_transform;
#[path = "main_ca_links.rs"]
pub(super) mod main_ca_links;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_ca_resources.rs"]
mod main_ca_resources;
#[cfg(test)]
#[path = "main_composition_ownership_tests.rs"]
mod main_composition_ownership_tests;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_fixed_coset.rs"]
mod main_fixed_coset;
#[cfg(test)]
#[path = "main_fixed_replay_batch_tests.rs"]
mod main_fixed_replay_batch_tests;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_fri_retention.rs"]
mod main_fri_retention;
#[path = "main_joint.rs"]
pub mod main_joint;
#[path = "main_key_joins.rs"]
pub(super) mod main_key_joins;
#[cfg(test)]
#[path = "main_native_boundary_tests.rs"]
mod main_native_boundary_tests;
#[path = "main_oods.rs"]
mod main_oods;
#[cfg(test)]
pub(super) use main_oods::verify_standalone_der_oods_v1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_quotient_cache.rs"]
mod main_quotient_cache;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_quotient_denominators.rs"]
mod main_quotient_denominators;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_quotient_stripes.rs"]
mod main_quotient_stripes;
#[cfg(test)]
#[path = "main_resource_tests.rs"]
mod main_resource_tests;
#[cfg(test)]
#[path = "main_secret_ownership_tests.rs"]
mod main_secret_ownership_tests;
#[path = "main_sha_union.rs"]
pub(super) mod main_sha_union;
#[path = "main_terminal_links.rs"]
mod main_terminal_links;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use rayon::prelude::*;
#[derive(Clone, Copy)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) enum MainTraceColumnKindV1 {
    Base,
    Aux,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_deep_replay.rs"]
mod main_deep_replay;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_resources.rs"]
mod main_resources;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_retained_rfc.rs"]
mod main_retained_rfc;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_trace_replay.rs"]
mod main_trace_replay;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "main_transform.rs"]
mod main_transform;
#[cfg(test)]
pub(super) use main_trace_replay::MainTraceMaskGroupV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) use main_trace_replay::MainTracePolynomialSetV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use main_trace_replay::MainTraceReplaySourcesV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn registered_main_group_column_v1(
    layout: &AggregateProofLayoutV1,
    group_index: usize,
    kind: MainTraceColumnKindV1,
    column_index: usize,
) -> Result<(RegisteredSegmentLayoutV1, usize), ZkX509StarkErrorV1> {
    layout.validate_exact_full_profile_registration_v1()?;
    let group = layout
        .trace_groups
        .get(group_index)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let width = match kind {
        MainTraceColumnKindV1::Base => group.base_width,
        MainTraceColumnKindV1::Aux => group.aux_width,
    };
    if column_index >= width {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let mut matched = None;
    for registration in layout
        .registered_segments
        .iter()
        .copied()
        .filter(|registration| registration.trace_group == group_index)
    {
        let (start, end) = match kind {
            MainTraceColumnKindV1::Base => (registration.base_start, registration.base_end()?),
            MainTraceColumnKindV1::Aux => (registration.aux_start, registration.aux_end()?),
        };
        if (start..end).contains(&column_index)
            && matched
                .replace((registration, column_index - start))
                .is_some()
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
    }
    matched.ok_or(ZkX509StarkErrorV1::ProfileMismatch)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn main_trace_group_root_v1(
    kind: MainTraceColumnKindV1,
    commitment: &aggregate::StreamingRowCommitmentResultV1,
) -> TraceGroupProofV1 {
    match kind {
        MainTraceColumnKindV1::Base => TraceGroupProofV1 {
            base_root: commitment.commitment.root,
            aux_root: PrivacyOuterDigestV1::default(),
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        },
        MainTraceColumnKindV1::Aux => TraceGroupProofV1 {
            base_root: PrivacyOuterDigestV1::default(),
            aux_root: commitment.commitment.root,
            base_frontier: Vec::new(),
            aux_frontier: Vec::new(),
        },
    }
}
fn map_credential_pre_aux_error_v1(
    error: super::super::credential_pre_aux::ZkX509CredentialPreAuxErrorV1,
) -> ZkX509StarkErrorV1 {
    use super::super::credential_pre_aux::ZkX509CredentialPreAuxErrorV1 as Error;
    match error {
        Error::Resource => ZkX509StarkErrorV1::AllocationFailure,
        Error::Transcript | Error::Challenge => ZkX509StarkErrorV1::TranscriptMismatch,
    }
}
/// MAIN state after the joined base commitment and before X5B1.
///
/// The type owns every challenge-independent child which must cross the joint credential phase. It
/// exposes only a consuming transition accepting the opaque outer credential binding; raw challenge
/// families and auxiliary commitment APIs are intentionally absent.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct ZkX509MainAwaitingCredentialBindingV1<'a> {
    layout: AggregateProofLayoutV1,
    statement: &'a IrohaZkX509StarkP256StatementV1,
    assembly: &'a ZkX509MainTraceAssemblyV1,
    public: ZkX509CredentialPublicBindingV1,
    p256: P256MainBaseSourceV1,
    sha: [ZkX509ShaBatchSegmentBaseSourceV1<'a>; ZK_X509_SHA_SEGMENT_COUNT_V1],
    projection: MainProjectionTraceGroupSourceV1<'a>,
    io: MainIoTraceGroupSourceV1<'a>,
    trace_groups: Vec<TraceGroupProofV1>,
    base_polynomials: MainTracePolynomialSetV1,
    transcript: TransparentTranscriptV1,
    base_transcript_state: PrivacyOuterDigestV1,
    pre_aux: ZkX509CredentialMainPreAuxV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509MainAwaitingCredentialBindingV1<'_> {
    fn validate_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.layout.validate_exact_full_profile_registration_v1()?;
        validate_zk_x509_main_verifier_profile_v1(self.assembly.verifier_profile)?;
        main_resources::MainProverBufferPlanV1::new_v1(&self.layout)?.check_native_sources_v1(
            self.assembly.allocated_payload_bytes_v1(),
            &[
                self.p256.allocated_payload_bytes_v1(),
                core::mem::size_of_val(&self.sha),
                self.projection.allocated_payload_bytes_v1(),
                self.io.allocated_payload_bytes_v1(),
                self.base_polynomials.retained_rfc_payload_v1(),
            ],
        )?;
        self.base_polynomials
            .validate_v1(&self.layout, MainTraceColumnKindV1::Base)?;
        if self.base_polynomials.proof_instance_v1() != self.pre_aux.proof_instance_v1()
            || self.transcript.context() != self.pre_aux.proof_instance_v1().main_context_v1()
            || self.public.consensus_context_digest == [0_u8; 32]
            || self.trace_groups.len() != ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1
            || self.transcript.state() != self.base_transcript_state
            || self.trace_groups.iter().any(|group| {
                group.base_root == PrivacyOuterDigestV1::default()
                    || group.aux_root != PrivacyOuterDigestV1::default()
            })
            || self.projection.aux.is_some()
            || self.io.bind_attempted
            || self.io.aux_columns.is_some()
            || self.io.post_base.is_some()
        {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        validate_p256_main_registration_order_v1(&self.p256.canonical_registrations_v1()?)
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)
    }
}
/// Composition-ready MAIN state after the sole X5B1 transition.
///
/// Both trace-mask sets, the joined base/aux roots, the exact terminal claims, and per-registration
/// composition coefficients are retained together. A future composition/DEEP/FRI continuation
/// cannot resample challenges or return to either earlier phase.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct ZkX509MainCompositionPhaseV1<'a> {
    layout: AggregateProofLayoutV1,
    statement: &'a IrohaZkX509StarkP256StatementV1,
    assembly: &'a ZkX509MainTraceAssemblyV1,
    public: ZkX509CredentialPublicBindingV1,
    log19: MainLog19BoundTraceGroupSourceV1<'a>,
    projection: MainProjectionTraceGroupSourceV1<'a>,
    io: MainIoTraceGroupSourceV1<'a>,
    trace_groups: Vec<TraceGroupProofV1>,
    base_polynomials: MainTracePolynomialSetV1,
    aux_polynomials: MainTracePolynomialSetV1,
    link_alphas: Vec<E>,
    key_plan: main_key_joins::MainKeyJoinPlanV1,
    key_alphas: Vec<E>,
    sha_union_plan: main_sha_union::MainShaUnionPlanV1,
    sha_union_alphas: Vec<E>,
    alphas: Vec<Vec<Vec<E>>>,
    transcript: TransparentTranscriptV1,
    composition_transcript_state: PrivacyOuterDigestV1,
    binding: ZkX509CredentialPreAuxBindingV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509MainCompositionPhaseV1<'_> {
    fn validate_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        let proof_instance = self.binding.proof_instance_v1();
        if self.base_polynomials.proof_instance_v1() != proof_instance
            || self.aux_polynomials.proof_instance_v1() != proof_instance
            || self.transcript.context() != proof_instance.main_context_v1()
        {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }

        self.layout.validate_exact_full_profile_registration_v1()?;
        validate_zk_x509_main_verifier_profile_v1(self.assembly.verifier_profile)?;
        main_resources::MainProverBufferPlanV1::new_v1(&self.layout)?.check_native_sources_v1(
            self.assembly.allocated_payload_bytes_v1(),
            &[
                self.log19.allocated_payload_bytes_v1(),
                self.projection.allocated_payload_bytes_v1(),
                self.io.allocated_payload_bytes_v1(),
                self.base_polynomials.retained_rfc_payload_v1(),
                self.aux_polynomials.retained_rfc_payload_v1(),
            ],
        )?;
        self.base_polynomials
            .validate_v1(&self.layout, MainTraceColumnKindV1::Base)?;
        self.aux_polynomials
            .validate_v1(&self.layout, MainTraceColumnKindV1::Aux)?;
        if self.public.consensus_context_digest == [0_u8; 32]
            || self.trace_groups.len() != ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1
            || self.log19.post_base != self.binding.main_post_base()
            || self.transcript.state() != self.composition_transcript_state
            || self.trace_groups.iter().any(|group| {
                group.base_root == PrivacyOuterDigestV1::default()
                    || group.aux_root == PrivacyOuterDigestV1::default()
            })
            || self.sha_union_plan != main_sha_union::MainShaUnionPlanV1::new_v1(&self.layout)?
            || self.sha_union_alphas.len() != main_sha_union::UNION_QUOTIENTS_V1
            || self.sha_union_alphas.capacity() != main_sha_union::UNION_QUOTIENTS_V1
            || self
                .sha_union_alphas
                .iter()
                .any(|alpha| !alpha.is_canonical())
            || self.key_alphas.len() != main_key_joins::BLOCKS_V1
            || self.key_alphas.iter().any(|alpha| !alpha.is_canonical())
            || self.link_alphas.len() != main_terminal_links::LINK_COUNT_V1
            || self.link_alphas.capacity() != main_terminal_links::LINK_COUNT_V1
            || self.link_alphas.iter().any(|alpha| !alpha.is_canonical())
            || self.alphas.len() != self.layout.registered_segments.len()
            || self
                .alphas
                .iter()
                .zip(&self.layout.registered_segments)
                .any(|(lanes, registration)| {
                    lanes.len() != SECURITY_LANES
                        || lanes
                            .iter()
                            .any(|lane| lane.len() != registration.segment.constraint_count)
                })
        {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        self.io.validate_bound_phase_v1()?;
        if self.projection.aux.is_none() {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        Ok(())
    }
    fn prover_constraint_providers_v1(
        &self,
    ) -> Result<Vec<MainProverConstraintProviderV1<'_, '_>>, ZkX509StarkErrorV1> {
        self.validate_v1()?;
        let post_base = self.binding.main_post_base();
        let providers = vec![
            MainProverConstraintProviderV1::Log5(
                MainP256Log5ProverConstraintSourceV1::for_main_v1(&self.layout, &self.log19.p256)?,
            ),
            MainProverConstraintProviderV1::P256Scalar(
                MainP256ScalarProverConstraintSourceV1::for_main_v1(
                    &self.layout,
                    &self.log19.p256,
                )?,
            ),
            MainProverConstraintProviderV1::Projection(
                MainProjectionProverConstraintSourceV1::for_main_v1(
                    &self.layout,
                    self.statement,
                    post_base,
                )?,
            ),
            MainProverConstraintProviderV1::Log16(
                MainP256Log16ProverConstraintSourceV1::for_main_v1(&self.layout, &self.log19.p256)?,
            ),
            MainProverConstraintProviderV1::Io(MainIoProverConstraintSourceV1::for_main_v1(
                &self.layout,
                self.statement,
                &self.assembly.io,
                post_base,
            )?),
            MainProverConstraintProviderV1::Log19(MainLog19ProverConstraintSourceV1::for_main_v1(
                &self.layout,
                &self.log19,
            )?),
        ];
        if providers.len() != FULL_PROFILE_TRACE_GROUPS_V1
            || providers
                .iter()
                .zip(&self.layout.trace_groups)
                .any(|(provider, group)| provider.native_trace_log2_v1() != group.native_trace_log2)
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(providers)
    }
}
/// Commit all six canonical MAIN base groups in one ordered row tree and yield the sole outer
/// credential assembly hook.
///
/// This is phase one only. The returned state cannot commit auxiliary columns
/// until the credential layer combines its joined base root with the compact-CA
/// root and supplies the resulting opaque 272-challenge X5B1 binding.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn commit_zk_x509_main_base_phase_v1_with_rng<'a, R: TryRngCore>(
    proof_instance: ZkX509ProofInstanceV1,
    statement: &'a IrohaZkX509StarkP256StatementV1,
    assembly: &'a ZkX509MainTraceAssemblyV1,
    public: ZkX509CredentialPublicBindingV1,
    rng: &mut R,
) -> Result<
    (
        ZkX509MainAwaitingCredentialBindingV1<'a>,
        ZkX509CredentialMainPreAuxV1,
    ),
    ZkX509StarkErrorV1,
> {
    main_bounded_transform::check_completion_v1(
        fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1(),
    )?;
    validate_zk_x509_main_proof_budget_v1()?;
    let layout = AggregateProofLayoutV1::for_full_profile_v1()?;
    let buffer_plan = main_resources::MainProverBufferPlanV1::new_v1(&layout)?;
    buffer_plan.check_before_sources_v1(assembly.allocated_payload_bytes_v1())?;
    validate_zk_x509_main_verifier_profile_v1(assembly.verifier_profile)?;
    if public.consensus_context_digest == [0_u8; 32] {
        return Err(ZkX509StarkErrorV1::InvalidStatement);
    }
    if ca_accumulator_stark_public_v1(&assembly.ca_accumulator_trace, &assembly.sha_schedule)?
        != public.ca_public_v1()
    {
        return Err(ZkX509StarkErrorV1::WitnessStatementMismatch);
    }
    buffer_plan.check_source_shapes_v1(&layout, assembly)?;
    #[cfg(test)]
    let source_timer = PhaseTimerV1::start_v1(PhaseV1::BaseSources);
    let p256 = P256MainBaseSourceV1::new_v1(assembly)?;
    let sha = main_log19_sha_base_sources_v1(&assembly.sha_schedule, &assembly.sha_witnesses)?;
    let projection = MainProjectionTraceGroupSourceV1::for_main_v1(
        &layout,
        statement,
        &assembly.projection_trace,
    )?;
    let io = MainIoTraceGroupSourceV1::for_main_v1(&layout, statement, &assembly.io)?;
    buffer_plan.check_native_sources_v1(
        assembly.allocated_payload_bytes_v1(),
        &[
            p256.allocated_payload_bytes_v1(),
            core::mem::size_of_val(&sha),
            projection.allocated_payload_bytes_v1(),
            io.allocated_payload_bytes_v1(),
        ],
    )?;
    let mut session = ZkX509MainBaseCommitmentSessionV1::new_v1(
        proof_instance,
        &layout,
        public.consensus_context_digest,
        assembly.verifier_profile,
    )?;
    let mut transcript = new_main_transcript_v1(
        proof_instance,
        &public.consensus_context_digest,
        assembly.verifier_profile,
    )?;
    absorb_aggregate_layout_v1(
        proof_instance,
        &mut transcript,
        MAIN_LAYOUT_DOMAIN_V1,
        &layout,
    )?;
    {
        let source = MainLog19BaseTraceGroupSourceV1::for_main_v1(&layout, assembly, &sha, &p256)?;
        buffer_plan.check_native_sources_v1(
            assembly.allocated_payload_bytes_v1(),
            &[
                p256.allocated_payload_bytes_v1(),
                core::mem::size_of_val(&sha),
                projection.allocated_payload_bytes_v1(),
                io.allocated_payload_bytes_v1(),
                source.allocated_payload_bytes_v1(),
            ],
        )?;
        // The preflight wrapper owns metadata only; replay constructs its
        // own wrapper, so do not overlap those allocations.
        drop(source);
    }
    #[cfg(test)]
    source_timer.complete_v1();
    #[cfg(test)]
    let commit_timer = PhaseTimerV1::start_v1(PhaseV1::BaseSampleAndCommit);
    let (base_polynomials, commitment) = MainTracePolynomialSetV1::sample_and_commit_joined_v1(
        proof_instance,
        &layout,
        MainTraceColumnKindV1::Base,
        assembly.allocated_payload_bytes_v1(),
        &MainTraceReplaySourcesV1::Base {
            assembly,
            sha: &sha,
            p256: &p256,
            projection: &projection,
            io: &io,
        },
        rng,
    )?;
    #[cfg(test)]
    commit_timer.complete_v1();
    session.accept_streaming_base_commitment_v1(&commitment)?;
    let trace_groups = vec![main_trace_group_root_v1(
        MainTraceColumnKindV1::Base,
        &commitment,
    )];
    aggregate::absorb_base_roots_v1(
        &mut transcript,
        &main_domains_v1(proof_instance),
        &trace_groups,
    )
    .map_err(map_aggregate_error_v1)?;
    let pre_aux = session.finish_pre_aux_v1()?;
    let base_transcript_state = transcript.state();
    let phase = ZkX509MainAwaitingCredentialBindingV1 {
        layout,
        statement,
        assembly,
        public,
        p256,
        sha,
        projection,
        io,
        trace_groups,
        base_polynomials,
        transcript,
        base_transcript_state,
        pre_aux,
    };
    phase.validate_v1()?;
    Ok((phase, pre_aux))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> ZkX509MainAwaitingCredentialBindingV1<'a> {
    /// Consume phase one, bind all challenge-dependent children with one X5B1
    /// capability, commit all six auxiliary groups in one ordered row tree, absorb terminal
    /// claims, and sample the complete per-registration alpha schedule.
    pub(crate) fn bind_credential_pre_aux_v1_with_rng<R: TryRngCore>(
        self,
        binding: ZkX509CredentialPreAuxBindingV1,
        rng: &mut R,
    ) -> Result<ZkX509MainCompositionPhaseV1<'a>, ZkX509StarkErrorV1> {
        let proof_instance = self.pre_aux.proof_instance_v1();
        main_bounded_transform::check_completion_v1(
            fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1(),
        )?;
        self.validate_v1()?;
        if !binding.matches_main_pre_aux_v1(self.pre_aux) {
            // Reject substitution before transcript absorption or any
            // challenge-dependent child transition.
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let buffer_plan = main_resources::MainProverBufferPlanV1::new_v1(&self.layout)?;
        buffer_plan.check_before_sources_v1(self.assembly.allocated_payload_bytes_v1())?;
        let ZkX509MainAwaitingCredentialBindingV1 {
            layout,
            statement,
            assembly,
            public,
            p256,
            sha,
            mut projection,
            mut io,
            mut trace_groups,
            base_polynomials,
            mut transcript,
            base_transcript_state: _,
            pre_aux: _,
        } = self;
        absorb_zk_x509_credential_pre_aux_binding_v1(&mut transcript, binding)
            .map_err(map_credential_pre_aux_error_v1)?;
        let post_base = binding.main_post_base();
        #[cfg(test)]
        let source_timer = PhaseTimerV1::start_v1(PhaseV1::BoundSources);
        projection.bind_challenges_v1(post_base)?;
        io.bind_challenges_v1(post_base)?;
        let log19 = MainLog19BoundTraceGroupSourceV1::bind_from_phase_v1(
            &layout, assembly, sha, p256, binding,
        )?;
        buffer_plan.check_native_sources_v1(
            assembly.allocated_payload_bytes_v1(),
            &[
                log19.allocated_payload_bytes_v1(),
                projection.allocated_payload_bytes_v1(),
                io.allocated_payload_bytes_v1(),
                base_polynomials.retained_rfc_payload_v1(),
            ],
        )?;
        #[cfg(test)]
        source_timer.complete_v1();
        #[cfg(test)]
        let commit_timer = PhaseTimerV1::start_v1(PhaseV1::AuxSampleAndCommit);
        let (aux_polynomials, commitment) = MainTracePolynomialSetV1::sample_and_commit_joined_v1(
            proof_instance,
            &layout,
            MainTraceColumnKindV1::Aux,
            assembly.allocated_payload_bytes_v1(),
            &MainTraceReplaySourcesV1::Bound {
                log19: &log19,
                projection: &projection,
                io: &io,
            },
            rng,
        )?;
        #[cfg(test)]
        commit_timer.complete_v1();
        trace_groups[0].aux_root = commitment.commitment.root;
        aggregate::absorb_aux_roots_v1(
            &mut transcript,
            &main_domains_v1(proof_instance),
            &trace_groups,
        )
        .map_err(map_aggregate_error_v1)?;
        let alphas = derive_constraint_alphas_v1(&mut transcript, &layout)?;
        let link_alphas = main_terminal_links::MainTerminalLinkPlanV1::new_v1(&layout)?
            .derive_alphas_v1(&mut transcript)?;
        let key_plan = main_key_joins::MainKeyJoinPlanV1::new_v1(
            &layout,
            statement,
            assembly.rfc_base.schedule.shape,
        )?;
        let key_alphas = key_plan.derive_alphas_v1(&mut transcript)?;
        let sha_union_plan = main_sha_union::MainShaUnionPlanV1::new_v1(&layout)?;
        let sha_union_alphas = sha_union_plan.derive_alphas_v1(&mut transcript)?;
        let composition_transcript_state = transcript.state();
        let phase = ZkX509MainCompositionPhaseV1 {
            layout,
            statement,
            assembly,
            public,
            log19,
            projection,
            io,
            trace_groups,
            base_polynomials,
            aux_polynomials,
            link_alphas,
            key_plan,
            key_alphas,
            sha_union_plan,
            sha_union_alphas,
            alphas,
            transcript,
            composition_transcript_state,
            binding,
        };
        phase.validate_v1()?;
        Ok(phase)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509MainCompositionPhaseV1<'_> {
    /// Complete the same original FRI and query path after the selected
    /// transcript has bound every local and supplemental opening.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn finish_original_openings_v1(
        mut self,
        composition_material: RetainedCompositionMaterialV1,
        composition_roots: Vec<PrivacyOuterDigestV1>,
        fri_masks: Vec<aggregate::AggregateFriMaskOracleMaterialV1>,
        fri_mask_roots: Vec<PrivacyOuterDigestV1>,
        deep: aggregate::AggregateDeepProofV1,
        deep_point: E,
        key_openings: [E; main_key_joins::OPENINGS_V1],
        key_mixes: Vec<E>,
        mixes: Vec<Vec<FriMixV1>>,
        ca: Option<main_joint::MainCaDeepContributionV1<'_>>,
        #[cfg(test)] deep_timer: PhaseTimerV1,
    ) -> Result<Vec<u8>, ZkX509StarkErrorV1> {
        let proof_instance = self.binding.proof_instance_v1();
        let sources = MainTraceReplaySourcesV1::Bound {
            log19: &self.log19,
            projection: &self.projection,
            io: &self.io,
        };
        let shared_layout = self.layout.as_shared()?;
        let compositions = &composition_material.evaluations;
        let (canonical_deep_traces, canonical_deep_compositions) =
            canonical_deep_values_v1(&deep, &self.layout)?;
        let key_policy = main_bounded_transform::MainBoundedTransformPolicyV1::for_assembly_v1(
            &self.layout,
            self.assembly.allocated_payload_bytes_v1(),
        )?;
        let mut fri_bases = main_fri_retention::MainRetainedFriInputsV1::new_v1(
            main_fri_bases_from_polynomials_v1(
                &self.layout,
                &self.base_polynomials,
                &self.aux_polynomials,
                &sources,
                &composition_material.coefficient_chunks,
                &mixes,
                deep_point,
                &canonical_deep_traces,
                &canonical_deep_compositions,
                &self.key_plan,
                &key_openings,
                &key_mixes,
                key_policy,
                ca,
            )?,
            self.layout.common_lde_size(),
        )?;
        for (base, mask) in fri_bases.lanes_mut_v1().zip(&fri_masks) {
            aggregate::add_fri_mask_oracle_v1(base, mask).map_err(map_aggregate_error_v1)?;
        }
        let fri_buffer_plan = main_resources::MainProverBufferPlanV1::new_v1(&self.layout)?;
        let retained_fri_payload = fri_bases.allocated_payload_bytes_v1()?;
        let mask_fri_payload = main_fri_retention::mask_evaluation_payload_v1(&fri_masks)?;
        let mut fri_materials = Vec::new();
        fri_materials
            .try_reserve_exact(SECURITY_LANES)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for lane in 0..SECURITY_LANES {
            let mut base_values = fri_bases.copy_lane_v1(lane, |outgoing_capacity| {
                fri_buffer_plan
                    .check_retained_fri_copy_v1(
                        &self.layout,
                        retained_fri_payload,
                        mask_fri_payload,
                        outgoing_capacity,
                    )
                    .map(|_| ())
            })?;
            fri_materials.push(
                aggregate::build_streaming_fri_lane_v1(
                    AGGREGATE_PARAMETERS_V1,
                    &main_domains_v1(proof_instance),
                    &shared_layout,
                    lane,
                    core::mem::take(&mut base_values.0),
                    &mut self.transcript,
                )
                .map_err(map_aggregate_error_v1)?,
            );
        }
        // The original masked FRI inputs remain in clearing owners. Reuse them
        // once queries are fixed instead of replaying every private trace column.
        let grinding_state = self.transcript.state();
        let grinding_nonce = grind_nonce_v1(
            proof_instance.main_context_v1(),
            &grinding_state,
            ZK_X509_GRINDING_BITS_V1,
        )
        .map_err(map_transparent_error_v1)?;
        absorb_grinding_nonce_v1(&mut self.transcript, grinding_nonce)?;
        let query_indices = query_indices_v1(proof_instance, &self.transcript, &self.layout)?;
        #[cfg(test)]
        deep_timer.complete_v1();
        #[cfg(test)]
        let opening_timer = PhaseTimerV1::start_v1(PhaseV1::QueryOpenings);
        let query_skeleton = query_indices
            .iter()
            .map(|index| {
                Ok(aggregate::AggregateQueryProofV1 {
                    index: u32::try_from(*index)
                        .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
                    trace_groups: Vec::new(),
                    composition_values: Vec::new(),
                    fri_mask_values: Vec::new(),
                    fri_lanes: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, ZkX509StarkErrorV1>>()?;
        let opening_indices =
            aggregate::trace_group_opening_indices_v1(&query_skeleton, &shared_layout, 0)
                .map_err(map_aggregate_error_v1)?;
        let base_plan = self
            .base_polynomials
            .joined_plan_v1(&self.layout, MainTraceColumnKindV1::Base)?;
        let aux_plan = self
            .aux_polynomials
            .joined_plan_v1(&self.layout, MainTraceColumnKindV1::Aux)?;
        let base_openings = self.base_polynomials.commit_joined_v1(
            &self.layout,
            MainTraceColumnKindV1::Base,
            &opening_indices,
            self.trace_groups
                .first()
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?
                .base_root,
            self.assembly.allocated_payload_bytes_v1(),
            &sources,
        )?;
        let aux_openings = self.aux_polynomials.commit_joined_v1(
            &self.layout,
            MainTraceColumnKindV1::Aux,
            &opening_indices,
            self.trace_groups
                .first()
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?
                .aux_root,
            self.assembly.allocated_payload_bytes_v1(),
            &sources,
        )?;
        let trace_group = self
            .trace_groups
            .first_mut()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if base_openings.commitment.root != trace_group.base_root
            || aux_openings.commitment.root != trace_group.aux_root
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        trace_group.base_frontier = base_openings.commitment.frontier.clone();
        trace_group.aux_frontier = aux_openings.commitment.frontier.clone();
        let composition_opening_indices =
            aggregate::composition_opening_indices_v1(&query_skeleton, &shared_layout)
                .map_err(map_aggregate_error_v1)?;
        let mut composition_frontiers = Vec::new();
        composition_frontiers
            .try_reserve_exact(SECURITY_LANES)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for (lane, composition) in compositions.iter().enumerate() {
            let commitment = aggregate::streaming_composition_commitment_v1(
                &main_domains_v1(proof_instance),
                lane,
                composition,
                &composition_opening_indices,
            )
            .map_err(map_aggregate_error_v1)?;
            if commitment.root != composition_roots[lane] {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
            composition_frontiers.push(commitment.frontier);
        }
        let fri_mask_frontiers = fri_masks
            .iter()
            .map(|mask| {
                aggregate::canonical_multiproof_frontier_v1(
                    &mask.tree,
                    self.layout.common_lde_size(),
                    &composition_opening_indices,
                )
                .map_err(map_aggregate_error_v1)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut fri_openings = Vec::new();
        fri_openings
            .try_reserve_exact(SECURITY_LANES)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for (lane, material) in fri_materials.iter().enumerate() {
            let mut base_values = fri_bases.take_lane_v1(lane)?;
            fri_openings.push(
                aggregate::open_streaming_fri_lane_v1(
                    AGGREGATE_PARAMETERS_V1,
                    &main_domains_v1(proof_instance),
                    &shared_layout,
                    lane,
                    core::mem::take(&mut base_values.0),
                    material,
                    &query_indices,
                )
                .map_err(map_aggregate_error_v1)?,
            );
        }
        let mut queries = Vec::new();
        queries
            .try_reserve_exact(query_indices.len())
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for (query_position, index) in query_indices.iter().copied().enumerate() {
            let mut opened_groups = Vec::new();
            opened_groups
                .try_reserve_exact(FULL_PROFILE_TRACE_GROUPS_V1)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            for group_index in 0..FULL_PROFILE_TRACE_GROUPS_V1 {
                let base_range = base_plan
                    .group_range_v1(group_index)
                    .map_err(map_aggregate_error_v1)?;
                let aux_range = aux_plan
                    .group_range_v1(group_index)
                    .map_err(map_aggregate_error_v1)?;
                let base = base_openings
                    .opened_rows
                    .get(&index)
                    .and_then(|row| row.get(base_range))
                    .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
                let aux = aux_openings
                    .opened_rows
                    .get(&index)
                    .and_then(|row| row.get(aux_range))
                    .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
                opened_groups.push(aggregate::AggregateTraceGroupQueryV1 {
                    base_current: base.iter().map(|value| value.0).collect(),
                    base_next: Vec::new(),
                    aux_current: aux.iter().map(|value| value.0).collect(),
                    aux_next: Vec::new(),
                });
            }
            queries.push(aggregate::AggregateQueryProofV1 {
                index: u32::try_from(index).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
                trace_groups: opened_groups,
                composition_values: compositions
                    .iter()
                    .map(|lane| {
                        lane.iter()
                            .map(|chunk| chunk[index].coefficients().map(F::value))
                            .collect()
                    })
                    .collect(),
                fri_mask_values: fri_masks
                    .iter()
                    .map(|mask| mask.evaluations[index].coefficients().map(F::value))
                    .collect(),
                fri_lanes: fri_openings
                    .iter()
                    .map(|lane| {
                        lane.queries
                            .get(query_position)
                            .cloned()
                            .ok_or(ZkX509StarkErrorV1::InternalInvariant)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            });
        }
        #[cfg(test)]
        opening_timer.complete_v1();
        drop(self.base_polynomials);
        drop(self.aux_polynomials);
        let fri_lanes = fri_materials
            .into_iter()
            .zip(fri_openings)
            .map(|(material, openings)| FriLaneProofV1 {
                roots: material.roots,
                terminal_values: material
                    .terminal_values
                    .into_iter()
                    .map(|value| value.coefficients().map(F::value))
                    .collect(),
                round_frontiers: openings.round_frontiers,
            })
            .collect();
        let proof = ZkX509SegmentedStarkProofV1 {
            aggregate: aggregate::AggregateStarkProofV1 {
                version: ZK_X509_PROOF_VERSION_V1,
                trace_groups: self.trace_groups,
                composition_roots,
                composition_frontiers,
                fri_mask_roots,
                fri_mask_frontiers,
                fri_lanes,
                queries,
                grinding_nonce,
            },
            deep,
        };
        let aggregate_bytes = encode_zk_x509_segmented_stark_proof_v1(&proof, &self.layout)?;
        encode_zk_x509_main_proof_envelope_v1(&key_openings, &aggregate_bytes)
    }
}
/// Exact six-provider registry for the verifier-owned full MAIN layout.
///
/// The layout is cloned only after every dimension and closed provider
/// discriminator is validated, preventing later caller mutation.
#[cfg(test)]
pub(super) struct MainTraceProviderSetV1<'a> {
    layout: AggregateProofLayoutV1,
    groups: Vec<MainTraceGroupProviderV1<'a>>,
}
#[cfg(test)]
impl<'a> MainTraceProviderSetV1<'a> {
    pub(super) fn new_v1(
        layout: &AggregateProofLayoutV1,
        groups: Vec<MainTraceGroupProviderV1<'a>>,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        if groups.len() != FULL_PROFILE_TRACE_GROUPS_V1
            || groups.len() != layout.trace_groups.len()
            || groups
                .iter()
                .zip(&layout.trace_groups)
                .any(|(provider, group)| provider.native_trace_log2_v1() != group.native_trace_log2)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(MainTraceProviderSetV1 {
            layout: layout.clone(),
            groups,
        })
    }
    fn validate_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.layout.validate_exact_full_profile_registration_v1()?;
        if self.groups.len() != FULL_PROFILE_TRACE_GROUPS_V1
            || self.groups.len() != self.layout.trace_groups.len()
            || self
                .groups
                .iter()
                .zip(&self.layout.trace_groups)
                .any(|(provider, group)| provider.native_trace_log2_v1() != group.native_trace_log2)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
    pub(super) fn registered_column_v1(
        &self,
        group_index: usize,
        kind: MainTraceColumnKindV1,
        column_index: usize,
    ) -> Result<(RegisteredSegmentLayoutV1, usize), ZkX509StarkErrorV1> {
        self.validate_v1()?;
        registered_main_group_column_v1(&self.layout, group_index, kind, column_index)
    }
    pub(super) fn native_group_column_v1(
        &mut self,
        group_index: usize,
        kind: MainTraceColumnKindV1,
        column_index: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let (registration, local_column) =
            self.registered_column_v1(group_index, kind, column_index)?;
        let expected_rows = registration.segment.trace_size();
        let source = self
            .groups
            .get_mut(group_index)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            .source_mut_v1();
        let column = match kind {
            MainTraceColumnKindV1::Base => {
                source.native_base_column_v1(registration, local_column)?
            }
            MainTraceColumnKindV1::Aux => {
                source.native_aux_column_v1(registration, local_column)?
            }
        };
        if column.len() != expected_rows
            || column.iter().any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(column)
    }
}
/// Closed prover-side fixed-polynomial and quotient provider for one canonical MAIN trace group.
///
/// The variants are verifier-derived and exhaustive. No dynamic callback can supply fixed rows or a
/// quotient value, and every challenge-dependent source borrows the already-bound X5B1 phase.
#[cfg(any(test, feature = "privacy-release-evidence"))]
enum MainProverConstraintProviderV1<'phase, 'assembly> {
    Log5(MainP256Log5ProverConstraintSourceV1<'phase>),
    P256Scalar(MainP256ScalarProverConstraintSourceV1<'phase>),
    Projection(MainProjectionProverConstraintSourceV1),
    Log16(MainP256Log16ProverConstraintSourceV1<'phase>),
    Io(MainIoProverConstraintSourceV1),
    Log19(MainLog19ProverConstraintSourceV1<'assembly, 'phase>),
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainProverConstraintProviderV1<'_, '_> {
    fn native_trace_log2_v1(&self) -> u8 {
        match self {
            Self::Log5(_) => 5,
            Self::P256Scalar(_) => 8,
            Self::Projection(_) => 15,
            Self::Log16(_) => 16,
            Self::Io(_) => 18,
            Self::Log19(_) => 19,
        }
    }
    fn stream_fixed_polynomials_v1(
        &self,
        mut consume: impl FnMut(
            RegisteredSegmentLayoutV1,
            usize,
            &[F],
        ) -> Result<(), ZkX509StarkErrorV1>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        match self {
            Self::Log5(source) => source.stream_fixed_polynomials_v1(&mut consume),
            Self::P256Scalar(source) => source.stream_fixed_polynomials_v1(&mut consume),
            Self::Projection(source) => {
                source.stream_fixed_polynomials_v1(|column, coefficients| {
                    consume(source.registration, column, coefficients)
                })
            }
            Self::Log16(source) => source.stream_fixed_polynomials_v1(&mut consume),
            Self::Io(source) => source.stream_fixed_polynomials_v1(|column, coefficients| {
                consume(source.registration, column, coefficients)
            }),
            Self::Log19(source) => source.stream_fixed_polynomials_v1(consume),
        }
    }
    // The direct path remains a test oracle; the independent verifier is separate.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn composition_value_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed_current: &[F],
        fixed_next: &[F],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if fixed_current.len() != registration.segment.fixed_width
            || fixed_next.len() != registration.segment.fixed_width
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        match self {
            Self::Log5(source) => {
                source.composition_value_v1(registration, x, opening, fixed_current, alphas)
            }
            Self::P256Scalar(source) => source.composition_value_v1(
                registration,
                x,
                opening,
                fixed_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                alphas,
            ),
            Self::Projection(source) => source.composition_value_v1(
                registration,
                x,
                opening,
                fixed_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                alphas,
            ),
            Self::Log16(source) => {
                source.composition_value_v1(registration, x, opening, fixed_current, alphas)
            }
            Self::Io(source) => source.composition_value_v1(
                registration,
                x,
                opening,
                fixed_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                alphas,
            ),
            Self::Log19(source) => source.composition_value_v1(
                registration,
                x,
                opening,
                fixed_current,
                fixed_next,
                alphas,
            ),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn composition_value_on_stripe_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        denominators: &main_quotient_denominators::MainQuotientDenominatorsV1,
        row: usize,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed_current: &[F],
        fixed_next: &[F],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if fixed_current.len() != registration.segment.fixed_width
            || fixed_next.len() != registration.segment.fixed_width
            || alphas.len() != registration.segment.constraint_count
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let inverse = denominators.at_v1(registration.segment.trace_log2, row)?;
        let residues = match self {
            Self::Log5(source) => {
                source.constraint_residues_v1(registration, opening, fixed_current)?
            }
            Self::P256Scalar(source) => source.constraint_residues_v1(
                registration,
                opening,
                fixed_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            )?,
            Self::Projection(source) => {
                if registration != source.registration {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                projection_constraint_residues_v1(
                    opening.base_current,
                    opening.base_next,
                    opening.aux_current,
                    opening.aux_next,
                    fixed_current,
                    source.challenges,
                )?
            }
            Self::Log16(source) => {
                source.constraint_residues_v1(registration, opening, fixed_current)?
            }
            Self::Io(source) => source.constraint_residues_v1(
                registration,
                opening,
                fixed_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            )?,
            Self::Log19(source) => {
                source.constraint_residues_v1(registration, opening, fixed_current, fixed_next)?
            }
        };
        if residues.len() != registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(residues
            .iter()
            .zip(alphas)
            .fold(E::ZERO, |sum, (residue, alpha)| {
                sum.add(alpha.mul_base(*residue))
            })
            .mul_base(inverse))
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct ZeroizingMainFixedPolynomialSetV1 {
    registration: RegisteredSegmentLayoutV1,
    columns: Vec<Vec<F>>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZeroizingMainFixedPolynomialSetV1 {
    fn drop(&mut self) {
        for column in &mut self.columns {
            for value in column {
                value.zeroize_v1();
            }
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn stream_main_fixed_polynomial_sets_v1(
    provider: &MainProverConstraintProviderV1<'_, '_>,
    mut consume: impl FnMut(&mut ZeroizingMainFixedPolynomialSetV1) -> Result<(), ZkX509StarkErrorV1>,
) -> Result<(), ZkX509StarkErrorV1> {
    if let MainProverConstraintProviderV1::Log19(source) = provider {
        for registration in source.source.registrations.iter().copied() {
            let mut completed = main_log19_fixed_polynomial_set_v1(source, registration)?;
            consume(&mut completed)?;
        }
        return Ok(());
    }
    let mut pending: Option<ZeroizingMainFixedPolynomialSetV1> = None;
    provider.stream_fixed_polynomials_v1(|registration, local_column, coefficients| {
        if registration.segment.trace_log2 != provider.native_trace_log2_v1()
            || coefficients.len() != registration.segment.trace_size()
            || coefficients
                .iter()
                .any(|coefficient| F::canonical(coefficient.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        if pending
            .as_ref()
            .is_some_and(|set| set.registration != registration)
        {
            let mut completed = pending
                .take()
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
            if completed.columns.len() != completed.registration.segment.fixed_width {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            consume(&mut completed)?;
        }
        let set = pending.get_or_insert_with(|| ZeroizingMainFixedPolynomialSetV1 {
            registration,
            columns: Vec::new(),
        });
        if set.registration != registration
            || local_column != set.columns.len()
            || local_column >= registration.segment.fixed_width
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(coefficients.len())
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        retained.extend_from_slice(coefficients);
        set.columns.push(retained);
        Ok(())
    })?;
    let mut completed = pending.ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if completed.columns.len() != completed.registration.segment.fixed_width {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    consume(&mut completed)
}
/// Construct the existing final fixed matrix directly, avoiding a second
/// pending copy. Each public arithmetic row fills all its admitted columns once;
/// inverse transforms still run in place within bounded eight-column batches.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn main_log19_fixed_polynomial_set_v1(
    source: &MainLog19ProverConstraintSourceV1<'_, '_>,
    registration: RegisteredSegmentLayoutV1,
) -> Result<ZeroizingMainFixedPolynomialSetV1, ZkX509StarkErrorV1> {
    let index = source.source.registration_index_v1(registration)?;
    let root = goldilocks_primitive_root_v1(registration.segment.trace_log2)
        .map_err(map_transparent_error_v1)?;
    let mut set = ZeroizingMainFixedPolynomialSetV1 {
        registration,
        columns: Vec::new(),
    };
    set.columns
        .try_reserve_exact(registration.segment.fixed_width)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    let arithmetic = if index >= 6 {
        let binding = source.source.p256_binding_v1(registration)?;
        (binding.p256.adapter_v1() == P256MainAdapterV1::Arithmetic
            && binding.p256.local_instance_v1() == 0)
            .then_some(binding.p256)
    } else {
        None
    };
    if let Some(binding) = arithmetic {
        for _ in 0..registration.segment.fixed_width {
            set.columns.push(
                zeroed_main_trace_column_v1(registration.segment.trace_size())?.into_vec_v1(),
            );
        }
        #[cfg(test)]
        let rows_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionArithmeticFixedRows);
        source
            .source
            .p256
            .fill_arithmetic_fixed_matrix_v1(binding, &mut set.columns)?;
        #[cfg(test)]
        rows_timer.complete_v1();
        #[cfg(test)]
        let inverse_timer =
            PhaseTimerV1::start_v1(PhaseV1::CompositionArithmeticFixedInverseTransform);
        for batch in set
            .columns
            .chunks_mut(aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
        {
            batch.par_iter_mut().try_for_each(|column| {
                goldilocks_ifft_v1(column, root).map_err(map_transparent_error_v1)
            })?;
        }
        #[cfg(test)]
        inverse_timer.complete_v1();
    } else {
        for column in 0..registration.segment.fixed_width {
            let mut values = source.source.native_fixed_column_v1(registration, column)?;
            goldilocks_ifft_v1(&mut values, root).map_err(map_transparent_error_v1)?;
            set.columns.push(values.into_vec_v1());
        }
    }
    Ok(set)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn canonical_main_registration_index_v1(
    layout: &AggregateProofLayoutV1,
    registration: RegisteredSegmentLayoutV1,
) -> Result<usize, ZkX509StarkErrorV1> {
    layout.validate_exact_full_profile_registration_v1()?;
    layout
        .registered_segments
        .binary_search_by_key(
            &(
                registration.segment.trace_log2,
                registration.segment.adapter,
                registration.segment.instance,
            ),
            |candidate| {
                (
                    candidate.segment.trace_log2,
                    candidate.segment.adapter,
                    candidate.segment.instance,
                )
            },
        )
        .ok()
        .filter(|index| layout.registered_segments.get(*index) == Some(&registration))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[allow(clippy::too_many_arguments)]
fn main_registration_trace_columns_on_coset_v1(
    layout: &AggregateProofLayoutV1,
    polynomials: &MainTracePolynomialSetV1,
    kind: MainTraceColumnKindV1,
    registration: RegisteredSegmentLayoutV1,
    sources: &MainTraceReplaySourcesV1<'_, '_>,
    stripe: main_quotient_stripes::MainQuotientStripeV1,
    cache: &main_quotient_cache::MainQuotientReplayCacheV1,
    transform_policy: main_bounded_transform::MainBoundedTransformPolicyV1,
) -> Result<ZeroizingBaseColumnsV1, ZkX509StarkErrorV1> {
    canonical_main_registration_index_v1(layout, registration)?;
    let (start, width) = match kind {
        MainTraceColumnKindV1::Base => (registration.base_start, registration.segment.base_width),
        MainTraceColumnKindV1::Aux => (registration.aux_start, registration.segment.aux_width),
    };
    cache.evaluate_v1(kind, width, stripe, transform_policy, |columns| {
        polynomials.replay_columns_coefficients_v1(
            layout,
            kind,
            registration.trace_group,
            start + columns.start..start + columns.end,
            sources,
            transform_policy,
        )
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainQuotientRowScratchV1 {
    base_current: ZeroizingMainTraceColumnV1,
    base_next: ZeroizingMainTraceColumnV1,
    aux_current: ZeroizingMainTraceColumnV1,
    aux_next: ZeroizingMainTraceColumnV1,
    fixed_current: ZeroizingMainTraceColumnV1,
    fixed_next: ZeroizingMainTraceColumnV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainQuotientRowScratchV1 {
    fn new_v1(registration: RegisteredSegmentLayoutV1) -> Self {
        Self {
            base_current: ZeroizingMainTraceColumnV1(vec![
                F::ZERO;
                registration.segment.base_width
            ]),
            base_next: ZeroizingMainTraceColumnV1(vec![F::ZERO; registration.segment.base_width]),
            aux_current: ZeroizingMainTraceColumnV1(vec![F::ZERO; registration.segment.aux_width]),
            aux_next: ZeroizingMainTraceColumnV1(vec![F::ZERO; registration.segment.aux_width]),
            fixed_current: ZeroizingMainTraceColumnV1(vec![
                F::ZERO;
                registration.segment.fixed_width
            ]),
            fixed_next: ZeroizingMainTraceColumnV1(vec![F::ZERO; registration.segment.fixed_width]),
        }
    }
    fn fill_v1(
        &mut self,
        row: usize,
        next: usize,
        base: &[Vec<F>],
        aux: &[Vec<F>],
        fixed: &[Vec<F>],
    ) {
        for (column, (current, next_value)) in self
            .base_current
            .iter_mut()
            .zip(&mut *self.base_next)
            .enumerate()
        {
            *current = base[column][row];
            *next_value = base[column][next];
        }
        for (column, (current, next_value)) in self
            .aux_current
            .iter_mut()
            .zip(&mut *self.aux_next)
            .enumerate()
        {
            *current = aux[column][row];
            *next_value = aux[column][next];
        }
        for (column, (current, next_value)) in self
            .fixed_current
            .iter_mut()
            .zip(&mut *self.fixed_next)
            .enumerate()
        {
            *current = fixed[column][row];
            *next_value = fixed[column][next];
        }
    }
    fn opening_v1(&self) -> RegisteredOpenedRowsV1<'_> {
        RegisteredOpenedRowsV1 {
            base_current: &self.base_current,
            base_next: &self.base_next,
            aux_current: &self.aux_current,
            aux_next: &self.aux_next,
        }
    }
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn main_registration_composition_coefficient_chunks_v1(
    layout: &AggregateProofLayoutV1,
    provider: &MainProverConstraintProviderV1<'_, '_>,
    base_polynomials: &MainTracePolynomialSetV1,
    aux_polynomials: &MainTracePolynomialSetV1,
    sources: &MainTraceReplaySourcesV1<'_, '_>,
    fixed: &mut ZeroizingMainFixedPolynomialSetV1,
    alphas: &[Vec<E>],
    shared_layout: &aggregate::AggregateProofLayoutV1,
    sha_union_plan: &main_sha_union::MainShaUnionPlanV1,
    sha_union_centers: &[[F; 4]; 4],
    sha_union_alphas: &[E],
    bounded_transform: main_bounded_transform::MainBoundedTransformPolicyV1,
    joint_buffers: Option<&main_ca_resources::MainCaJointBufferPlanV1>,
) -> Result<Vec<Vec<Vec<E>>>, ZkX509StarkErrorV1> {
    #[cfg(test)]
    let registration_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionRegistration);
    let registration = fixed.registration;
    canonical_main_registration_index_v1(layout, registration)?;
    let plan = registered_retained_prover_plan_v1(registration.segment, layout.common_lde_log2)?;
    if provider.native_trace_log2_v1() != registration.segment.trace_log2
        || alphas.len() != SECURITY_LANES
        || alphas
            .iter()
            .any(|lane| lane.len() != registration.segment.constraint_count)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let first_stripe = main_quotient_stripes::MainQuotientStripeV1::new_v1(
        registration.segment.trace_log2,
        plan.quotient_coset_log2,
        0,
    )?;
    if first_stripe.rows.checked_mul(first_stripe.count) != Some(plan.quotient_coset_rows)
        || first_stripe.next_stride.checked_mul(first_stripe.count)
            != Some(plan.quotient_next_stride)
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let has_centered_union = matches!(
        registration.segment.adapter,
        SegmentAdapterIdV1::Rfc5280 | SegmentAdapterIdV1::Sha256CallBus
    );
    let bounded_transform = if has_centered_union {
        bounded_transform.reserve_additional_v1(
            main_sha_union::ShaUnionEndpointDenominatorsV1::payload_charge_v1(),
        )?
    } else {
        bounded_transform
    };
    let transform_policy = bounded_transform.for_quotient_layout_v1(
        registration.segment.base_width,
        registration.segment.aux_width,
    )?;
    let mut fixed_coset = main_fixed_coset::MainFixedCosetV1::new_v1(
        registration.segment.trace_log2,
        core::mem::take(&mut fixed.columns),
    )?
    .with_transform_policy_v1(transform_policy)?;
    let cache_plan = match joint_buffers {
        Some(plan) => plan.quotient_cache_plan_v1(layout, registration)?,
        None => main_resources::MainProverBufferPlanV1::new_v1(layout)?
            .quotient_cache_plan_v1(layout, registration)?,
    };
    #[cfg(test)]
    let cache_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionTraceCache);
    let cache = main_quotient_cache::MainQuotientReplayCacheV1::from_replay_v1(
        cache_plan,
        |kind, columns| {
            let (polynomials, start) = match kind {
                MainTraceColumnKindV1::Base => (base_polynomials, registration.base_start),
                MainTraceColumnKindV1::Aux => (aux_polynomials, registration.aux_start),
            };
            polynomials.replay_columns_coefficients_v1(
                layout,
                kind,
                registration.trace_group,
                start + columns.start..start + columns.end,
                sources,
                transform_policy,
            )
        },
    )?;
    #[cfg(test)]
    cache_timer.complete_v1();
    let mut quotients = (0..SECURITY_LANES)
        .map(|_| {
            let mut quotient = ZeroizingExtensionColumnV1(Vec::new());
            quotient
                .0
                .try_reserve_exact(plan.quotient_coset_rows)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            quotient.0.resize(plan.quotient_coset_rows, E::ZERO);
            Ok::<_, ZkX509StarkErrorV1>(quotient)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for ordinal in 0..first_stripe.count {
        let stripe = main_quotient_stripes::MainQuotientStripeV1::new_v1(
            registration.segment.trace_log2,
            plan.quotient_coset_log2,
            ordinal,
        )?;
        #[cfg(test)]
        let denominator_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionDenominators);
        let denominators = main_quotient_denominators::MainQuotientDenominatorsV1::new_v1(
            registration.segment.trace_log2,
            stripe,
        )?;
        let sha_union_denominators = if has_centered_union {
            Some(main_sha_union::ShaUnionEndpointDenominatorsV1::new_v1(
                stripe,
            )?)
        } else {
            None
        };
        #[cfg(test)]
        denominator_timer.complete_v1();
        #[cfg(test)]
        let base_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionBaseReplay);
        let base = main_registration_trace_columns_on_coset_v1(
            layout,
            base_polynomials,
            MainTraceColumnKindV1::Base,
            registration,
            sources,
            stripe,
            &cache,
            transform_policy,
        )?;
        #[cfg(test)]
        base_timer.complete_v1();
        #[cfg(test)]
        let aux_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionAuxReplay);
        let aux = main_registration_trace_columns_on_coset_v1(
            layout,
            aux_polynomials,
            MainTraceColumnKindV1::Aux,
            registration,
            sources,
            stripe,
            &cache,
            transform_policy,
        )?;
        #[cfg(test)]
        aux_timer.complete_v1();
        #[cfg(test)]
        let fixed_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionFixedReplay);
        let fixed_columns = fixed_coset.evaluate_v1(stripe)?;
        #[cfg(test)]
        fixed_timer.complete_v1();
        // Each task owns disjoint windows of the canonical full quotient. Only
        // this stripe's interleaved entries are written, so the original IFFT
        // sees exactly its original domain ordering after every stripe.
        const QUOTIENT_ROWS_PER_TASK_V1: usize = 1 << 12;
        let task_entries = stripe
            .count
            .checked_mul(QUOTIENT_ROWS_PER_TASK_V1)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        #[cfg(test)]
        let residue_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionResiduesAndFold);
        quotients
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(lane, quotient)| {
                quotient
                    .0
                    .par_chunks_mut(task_entries)
                    .enumerate()
                    .try_for_each_init(
                        || MainQuotientRowScratchV1::new_v1(registration),
                        |scratch, (chunk_index, output)| {
                            let first_row = chunk_index
                                .checked_mul(QUOTIENT_ROWS_PER_TASK_V1)
                                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
                            for (offset, target) in output
                                .iter_mut()
                                .skip(stripe.ordinal)
                                .step_by(stripe.count)
                                .enumerate()
                            {
                                let row = first_row
                                    .checked_add(offset)
                                    .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
                                let next = (row + stripe.next_stride) % stripe.rows;
                                scratch.fill_v1(row, next, &base, &aux, fixed_columns);
                                *target = provider.composition_value_on_stripe_v1(
                                    registration,
                                    &denominators,
                                    row,
                                    scratch.opening_v1(),
                                    &scratch.fixed_current,
                                    &scratch.fixed_next,
                                    &alphas[lane],
                                )?;
                                if let Some(denominators) = &sha_union_denominators {
                                    if lane != 0 {
                                        return Err(ZkX509StarkErrorV1::ProfileMismatch);
                                    }
                                    *target = target.add(sha_union_plan.local_value_v1(
                                        registration,
                                        row,
                                        &aux,
                                        sha_union_centers,
                                        sha_union_alphas,
                                        denominators,
                                    )?);
                                }
                            }
                            Ok::<_, ZkX509StarkErrorV1>(())
                        },
                    )
            })?;
        #[cfg(test)]
        residue_timer.complete_v1();
    }
    // Coefficients are no longer needed once all original quotient rows exist.
    drop(cache);
    drop(fixed_coset);
    let mut coefficient_chunks =
        ZeroizingExtensionLanesV1::new(Vec::new(), zeroize_extension_lanes_v1);
    coefficient_chunks
        .try_reserve_exact(SECURITY_LANES)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for quotient in &quotients {
        #[cfg(test)]
        let inverse_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionInverseTransform);
        let coefficients = fp4_coset_coefficients_v1(quotient, plan.quotient_coset_log2)?;
        #[cfg(test)]
        inverse_timer.complete_v1();
        #[cfg(test)]
        let chunk_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionDegreeChunks);
        coefficient_chunks.push(composition_coefficient_chunks_v1(
            &coefficients,
            plan.maximum_quotient_degree,
            shared_layout,
        )?);
        #[cfg(test)]
        chunk_timer.complete_v1();
    }
    #[cfg(test)]
    registration_timer.complete_v1();
    Ok(coefficient_chunks.into_vec())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn add_main_composition_coefficient_chunks_v1(
    accumulator: &mut [Vec<Vec<E>>],
    contribution: &[Vec<Vec<E>>],
    coefficient_cap: usize,
) -> Result<(), ZkX509StarkErrorV1> {
    if coefficient_cap == 0
        || accumulator.len() != SECURITY_LANES
        || contribution.len() != SECURITY_LANES
        || accumulator
            .iter()
            .chain(contribution)
            .any(|lane| lane.len() != COMPOSITION_DEGREE_CHUNKS)
        || accumulator.iter().chain(contribution).any(|lane| {
            lane.iter().any(|chunk| {
                chunk.len() > coefficient_cap
                    || chunk.iter().any(|coefficient| !coefficient.is_canonical())
            })
        })
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    // Complete every fallible capacity reservation before changing a logical
    // coefficient. A hostile late chunk therefore cannot leave a partially
    // accumulated composition behind.
    for lane in 0..SECURITY_LANES {
        for chunk in 0..COMPOSITION_DEGREE_CHUNKS {
            let source_len = contribution[lane][chunk].len();
            let target = &mut accumulator[lane][chunk];
            if target.len() < source_len {
                if target.capacity() < source_len {
                    let mut replacement = ZeroizingExtensionColumnV1(Vec::new());
                    replacement
                        .0
                        .try_reserve_exact(source_len)
                        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
                    replacement.0.extend_from_slice(target);
                    // The guard now owns the displaced initialized allocation.
                    // Its Drop clears it before the next replacement is built.
                    core::mem::swap(target, &mut replacement.0);
                }
            }
        }
    }
    for lane in 0..SECURITY_LANES {
        for chunk in 0..COMPOSITION_DEGREE_CHUNKS {
            let source = &contribution[lane][chunk];
            let target = &mut accumulator[lane][chunk];
            if target.len() < source.len() {
                target.resize(source.len(), E::ZERO);
            }
            for (target, source) in target.iter_mut().zip(source) {
                *target = target.add(*source);
            }
            // Keep the maximum public contributor extent after cancellation.
            // Value-based trimming would expose private coefficients through
            // scan work and the final chunk length. The clearing owner retains
            // every initialized cell until it erases the whole live extent.
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn evaluate_main_composition_coefficient_chunks_v1(
    coefficient_chunks: &[Vec<Vec<E>>],
    shared_layout: &aggregate::AggregateProofLayoutV1,
) -> Result<Vec<Vec<Vec<E>>>, ZkX509StarkErrorV1> {
    if coefficient_chunks.len() != SECURITY_LANES
        || coefficient_chunks
            .iter()
            .any(|lane| lane.len() != COMPOSITION_DEGREE_CHUNKS)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let common_rows = shared_layout.common_lde_size();
    let common_root = goldilocks_primitive_root_v1(shared_layout.common_lde_log2())
        .map_err(map_transparent_error_v1)?;
    let coefficient_cap = shared_layout
        .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
        .map_err(map_aggregate_error_v1)?;
    evaluate_main_composition_columns_v1(
        coefficient_chunks,
        common_rows,
        common_root,
        coefficient_cap,
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn evaluate_main_composition_columns_v1(
    coefficient_chunks: &[Vec<Vec<E>>],
    common_rows: usize,
    common_root: F,
    coefficient_cap: usize,
) -> Result<Vec<Vec<Vec<E>>>, ZkX509StarkErrorV1> {
    if coefficient_chunks.len() != SECURITY_LANES
        || coefficient_chunks
            .iter()
            .any(|lane| lane.len() != COMPOSITION_DEGREE_CHUNKS)
        || common_rows == 0
        || !common_rows.is_power_of_two()
        || coefficient_cap == 0
        || coefficient_cap > common_rows
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let mut evaluations = ZeroizingExtensionLanesV1::new(Vec::new(), zeroize_extension_lanes_v1);
    evaluations
        .try_reserve_exact(coefficient_chunks.len())
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for lane in coefficient_chunks {
        // Install the lane in its clearing owner before any populated chunk.
        evaluations.push(Vec::new());
        let target = evaluations
            .last_mut()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        target
            .try_reserve_exact(lane.len())
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for coefficients in lane {
            if coefficients.len() > coefficient_cap
                || coefficients
                    .iter()
                    .any(|coefficient| !coefficient.is_canonical())
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            if coefficients.is_empty() {
                let mut zero = Vec::new();
                zero.try_reserve_exact(common_rows)
                    .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
                zero.resize(common_rows, E::ZERO);
                target.push(zero);
                continue;
            }
            target.push(
                goldilocks_fp4_evaluate_coset_v1(
                    coefficients,
                    common_rows,
                    common_root,
                    F(GOLDILOCKS_GENERATOR_V1),
                )
                .map_err(map_transparent_error_v1)?,
            );
        }
    }
    Ok(evaluations.into_vec())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn main_composition_material_with_ca_v1<R: TryRngCore>(
    layout: &AggregateProofLayoutV1,
    base_polynomials: &MainTracePolynomialSetV1,
    aux_polynomials: &MainTracePolynomialSetV1,
    sources: &MainTraceReplaySourcesV1<'_, '_>,
    providers: &[MainProverConstraintProviderV1<'_, '_>],
    alphas: &[Vec<Vec<E>>],
    link_alphas: &[E],
    key_plan: &main_key_joins::MainKeyJoinPlanV1,
    key_alphas: &[E],
    sha_union_plan: &main_sha_union::MainShaUnionPlanV1,
    sha_union_alphas: &[E],
    bounded_transform: main_bounded_transform::MainBoundedTransformPolicyV1,
    ca: Option<main_joint::MainCaCompositionContributionV1<'_>>,
    rng: &mut R,
) -> Result<
    (
        RetainedCompositionMaterialV1,
        Option<main_ca_links::MainCaOriginalAuxiliaryV1>,
    ),
    ZkX509StarkErrorV1,
> {
    layout.validate_exact_full_profile_registration_v1()?;
    base_polynomials.validate_v1(layout, MainTraceColumnKindV1::Base)?;
    aux_polynomials.validate_v1(layout, MainTraceColumnKindV1::Aux)?;
    if providers.len() != FULL_PROFILE_TRACE_GROUPS_V1
        || providers
            .iter()
            .zip(&layout.trace_groups)
            .any(|(provider, group)| provider.native_trace_log2_v1() != group.native_trace_log2)
        || alphas.len() != layout.registered_segments.len()
        || alphas
            .iter()
            .zip(&layout.registered_segments)
            .any(|(lanes, registration)| {
                lanes.len() != SECURITY_LANES
                    || lanes
                        .iter()
                        .any(|lane| lane.len() != registration.segment.constraint_count)
            })
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    if sha_union_plan != &main_sha_union::MainShaUnionPlanV1::new_v1(layout)?
        || sha_union_alphas.len() != main_sha_union::UNION_QUOTIENTS_V1
        || sha_union_alphas.iter().any(|alpha| !alpha.is_canonical())
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let sha_union_centers = match sources {
        MainTraceReplaySourcesV1::Bound { log19, .. } => log19.rfc.sha_union_centers_v1(),
        _ => return Err(ZkX509StarkErrorV1::TranscriptMismatch),
    };
    let shared_layout = layout.as_shared()?;
    let coefficient_cap = shared_layout
        .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
        .map_err(map_aggregate_error_v1)?;
    let mut coefficient_chunks = ZeroizingExtensionLanesV1::new(
        (0..SECURITY_LANES)
            .map(|_| {
                (0..COMPOSITION_DEGREE_CHUNKS)
                    .map(|_| Vec::new())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
        zeroize_extension_lanes_v1,
    );
    // The ledger already charges every complete accumulator chunk. Reserve
    // before its first private write so later additions never reallocate it.
    for lane in &mut *coefficient_chunks {
        for chunk in lane {
            chunk
                .try_reserve_exact(coefficient_cap)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        }
    }
    let mut seen_registrations = 0_usize;
    #[cfg(test)]
    let registered_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionRegisteredProviders);
    for (group_index, provider) in providers.iter().enumerate() {
        let expected = layout
            .registered_segments
            .iter()
            .copied()
            .filter(|registration| registration.trace_group == group_index)
            .collect::<Vec<_>>();
        let mut seen_in_group = 0_usize;
        stream_main_fixed_polynomial_sets_v1(provider, |fixed| {
            if expected.get(seen_in_group).copied() != Some(fixed.registration) {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            let registration_index =
                canonical_main_registration_index_v1(layout, fixed.registration)?;
            let contribution = ZeroizingExtensionLanesV1::new(
                main_registration_composition_coefficient_chunks_v1(
                    layout,
                    provider,
                    base_polynomials,
                    aux_polynomials,
                    sources,
                    fixed,
                    &alphas[registration_index],
                    &shared_layout,
                    sha_union_plan,
                    sha_union_centers,
                    sha_union_alphas,
                    bounded_transform,
                    ca.as_ref().map(|ca| ca.buffers),
                )?,
                zeroize_extension_lanes_v1,
            );
            #[cfg(test)]
            let fold_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionRegistrationFold);
            add_main_composition_coefficient_chunks_v1(
                &mut coefficient_chunks,
                &contribution,
                coefficient_cap,
            )?;
            #[cfg(test)]
            fold_timer.complete_v1();
            seen_in_group += 1;
            seen_registrations += 1;
            Ok(())
        })?;
        if seen_in_group != expected.len() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
    }
    #[cfg(test)]
    registered_timer.complete_v1();
    if seen_registrations != layout.registered_segments.len() {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    if SECURITY_LANES != 1 {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    #[cfg(test)]
    let terminal_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionTerminalLinks);
    main_terminal_links::MainTerminalLinkPlanV1::new_v1(layout)?.accumulate_v1(
        layout,
        aux_polynomials,
        sources,
        link_alphas,
        bounded_transform,
        coefficient_chunks
            .get_mut(0)
            .and_then(|lane| lane.get_mut(0))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
    )?;
    #[cfg(test)]
    terminal_timer.complete_v1();

    #[cfg(test)]
    let key_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionKeyLinks);
    key_plan.accumulate_v1(
        layout,
        base_polynomials,
        sources,
        key_alphas,
        bounded_transform,
        coefficient_chunks
            .get_mut(0)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
    )?;
    #[cfg(test)]
    key_timer.complete_v1();

    #[cfg(test)]
    let union_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionShaUnion);
    sha_union_plan.accumulate_v1(
        layout,
        aux_polynomials,
        sources,
        sha_union_alphas,
        bounded_transform,
        &mut coefficient_chunks,
    )?;
    #[cfg(test)]
    union_timer.complete_v1();

    let ca_originals = if let Some(ca) = ca {
        ca.buffers.check_original_owners_v1(
            main_ca_resources::MainCaBufferPhaseV1::Registration,
            ca.original,
            None,
        )?;
        // All registration-local caches and fixed rows are now out of scope.
        #[cfg(test)]
        let ca_retention_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionCaRetention);
        let retained = ca.plan.retain_original_auxiliary_v1(
            layout,
            aux_polynomials,
            sources,
            ca.original,
            bounded_transform,
        )?;
        #[cfg(test)]
        ca_retention_timer.complete_v1();
        ca.buffers.check_original_owners_v1(
            main_ca_resources::MainCaBufferPhaseV1::PrivateLinks,
            ca.original,
            Some(&retained),
        )?;
        #[cfg(test)]
        let ca_links_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionCaLinks);
        ca.plan.accumulate_v1(
            layout,
            aux_polynomials,
            sources,
            ca.original,
            &retained,
            ca.alphas,
            bounded_transform,
            &mut coefficient_chunks,
        )?;
        #[cfg(test)]
        ca_links_timer.complete_v1();
        Some(retained)
    } else {
        None
    };
    #[cfg(test)]
    let blinding_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionBlinding);
    let geometry = super::super::composition_masking::QuotientChunkGeometryV1::new_v1(
        &shared_layout,
        AGGREGATE_PARAMETERS_V1,
    )
    .map_err(map_aggregate_error_v1)?;
    for lane in &mut *coefficient_chunks {
        geometry
            .blind_v1(lane, rng)
            .map_err(map_aggregate_error_v1)?;
    }
    #[cfg(test)]
    blinding_timer.complete_v1();
    #[cfg(test)]
    let fp4_timer = PhaseTimerV1::start_v1(PhaseV1::CompositionFp4Evaluations);
    let evaluations =
        evaluate_main_composition_coefficient_chunks_v1(&coefficient_chunks, &shared_layout)?;
    #[cfg(test)]
    fp4_timer.complete_v1();

    Ok((
        RetainedCompositionMaterialV1 {
            evaluations,
            coefficient_chunks: coefficient_chunks.into_vec(),
        },
        ca_originals,
    ))
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn main_fri_bases_from_polynomials_v1(
    layout: &AggregateProofLayoutV1,
    base_polynomials: &MainTracePolynomialSetV1,
    aux_polynomials: &MainTracePolynomialSetV1,
    sources: &MainTraceReplaySourcesV1<'_, '_>,
    composition_coefficients: &[Vec<Vec<E>>],
    mixes: &[Vec<FriMixV1>],
    deep_point: E,
    deep_trace_groups: &[aggregate::AggregateOpenedDeepTraceGroupV1],
    deep_compositions: &[Vec<E>],
    key_plan: &main_key_joins::MainKeyJoinPlanV1,
    key_openings: &[E; main_key_joins::OPENINGS_V1],
    key_mixes: &[E],
    key_policy: main_bounded_transform::MainBoundedTransformPolicyV1,
    ca: Option<main_joint::MainCaDeepContributionV1<'_>>,
) -> Result<Vec<Vec<E>>, ZkX509StarkErrorV1> {
    layout.validate_exact_full_profile_registration_v1()?;
    base_polynomials.validate_v1(layout, MainTraceColumnKindV1::Base)?;
    aux_polynomials.validate_v1(layout, MainTraceColumnKindV1::Aux)?;
    validate_main_fri_mixes_v1(layout, mixes)?;
    if !deep_point.is_canonical()
        || composition_coefficients.len() != SECURITY_LANES
        || composition_coefficients
            .iter()
            .any(|lane| lane.len() != COMPOSITION_DEGREE_CHUNKS)
        || deep_trace_groups.len() != FULL_PROFILE_TRACE_GROUPS_V1
        || deep_compositions.len() != SECURITY_LANES
        || deep_compositions
            .iter()
            .any(|values| values.len() != COMPOSITION_DEGREE_CHUNKS)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let shared_layout = layout.as_shared()?;
    let coefficient_cap = shared_layout
        .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
        .map_err(map_aggregate_error_v1)?;
    let mut accumulators = (0..SECURITY_LANES)
        .map(|_| {
            let mut accumulator = ZeroizingExtensionColumnV1(Vec::new());
            accumulator
                .0
                .try_reserve_exact(coefficient_cap)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            accumulator.0.resize(coefficient_cap, E::ZERO);
            Ok::<_, ZkX509StarkErrorV1>(accumulator)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for group_index in 0..FULL_PROFILE_TRACE_GROUPS_V1 {
        let group_layout = layout
            .trace_groups
            .get(group_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let deep = deep_trace_groups
            .get(group_index)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let group_mixes = mixes
            .get(group_index)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if deep.base_current.len() != group_layout.base_width
            || deep.base_next.len() != group_layout.base_width
            || deep.aux_current.len() != group_layout.aux_width
            || deep.aux_next.len() != group_layout.aux_width
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let retained_columns = base_polynomials
            .retained_group_width_v1(group_index)
            .checked_add(aux_polynomials.retained_group_width_v1(group_index))
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
        let points = main_deep_replay::MainMixedDeepPointsV1::new_v1(
            group_layout.native_trace_log2,
            deep_point,
            retained_columns != 0,
            main_resources::MainProverBufferPlanV1::new_v1(layout)?.replay_batch,
        )?;
        let mut weighted = main_deep_replay::MainMixedDeepQuotientV1::new_lanes_v1(&points)?;
        points.check_workspace_v1(&weighted, weighted.capacity(), &[], 0)?;
        for (kind, polynomials, width, current, next) in [
            (
                MainTraceColumnKindV1::Base,
                base_polynomials,
                group_layout.base_width,
                &deep.base_current,
                &deep.base_next,
            ),
            (
                MainTraceColumnKindV1::Aux,
                aux_polynomials,
                group_layout.aux_width,
                &deep.aux_current,
                &deep.aux_next,
            ),
        ] {
            for first in (0..width).step_by(aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1) {
                let end = width.min(first + aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1);
                let native =
                    polynomials.deep_batch_v1(layout, kind, group_index, first..end, sources)?;
                points.check_workspace_v1(
                    &weighted,
                    weighted.capacity(),
                    &native.native,
                    native.native.capacity(),
                )?;
                let masks = polynomials.original_masks_v1(layout, kind, group_index, first..end)?;
                if native.length != end - first || masks.len() != native.length {
                    return Err(ZkX509StarkErrorV1::InternalInvariant);
                }
                for lane in 0..SECURITY_LANES {
                    let mut batch: [main_deep_replay::MainMixedColumnV1<'_>;
                        aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1] =
                        core::array::from_fn(|_| -> main_deep_replay::MainMixedColumnV1<'_> {
                            (
                                main_deep_replay::MainMixedInputV1::Native(&[], &[]),
                                [E::ZERO; 2],
                                [E::ZERO; 2],
                            )
                        });
                    for (offset, column) in (first..end).enumerate() {
                        let scales = match kind {
                            MainTraceColumnKindV1::Base => [
                                group_mixes[lane].base[column],
                                group_mixes[lane].base_next[column],
                            ],
                            MainTraceColumnKindV1::Aux => [
                                group_mixes[lane].aux[column],
                                group_mixes[lane].aux_next[column],
                            ],
                        };
                        batch[offset] = (
                            native.input_v1(offset, masks[offset].coefficients())?,
                            [current[column], next[column]],
                            scales,
                        );
                    }
                    weighted[lane].add_batch_v1(&points, &batch[..native.length])?;
                }
            }
        }
        for (lane, weighted) in weighted.into_iter().enumerate() {
            weighted.accumulate_v1(
                (group_layout.base_width + group_layout.aux_width)
                    .checked_sub(retained_columns)
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                retained_columns,
                &mut accumulators[lane].0,
            )?;
        }
    }
    for lane in 0..SECURITY_LANES {
        let composition_mix = &mixes[0][lane].composition;
        for chunk in 0..COMPOSITION_DEGREE_CHUNKS {
            accumulate_extension_deep_quotient_v1(
                &composition_coefficients[lane][chunk],
                deep_point,
                deep_compositions[lane][chunk],
                composition_mix[chunk],
                &mut accumulators[lane].0,
            )?;
        }
    }
    if SECURITY_LANES != 1 {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    key_plan.accumulate_deep_v1(
        layout,
        base_polynomials,
        sources,
        deep_point,
        key_openings,
        key_mixes,
        key_policy,
        &mut accumulators
            .get_mut(0)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            .0,
    )?;
    if let Some(ca) = ca {
        ca.plan.accumulate_deep_v1(
            ca.original,
            deep_point,
            ca.values,
            ca.mixes,
            key_policy,
            &mut accumulators
                .get_mut(0)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
                .0,
        )?;
    }
    let common_root =
        goldilocks_primitive_root_v1(layout.common_lde_log2).map_err(map_transparent_error_v1)?;
    let mut evaluated = ZeroizingExtensionChunksV1::new(Vec::new(), zeroize_extension_chunks_v1);
    evaluated
        .try_reserve_exact(SECURITY_LANES)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for coefficients in &accumulators {
        let mut lane = ZeroizingExtensionColumnV1(
            goldilocks_fp4_evaluate_coset_v1(
                coefficients,
                layout.common_lde_size(),
                common_root,
                F(GOLDILOCKS_GENERATOR_V1),
            )
            .map_err(map_transparent_error_v1)?,
        );
        evaluated.push(core::mem::take(&mut lane.0));
    }
    // The caller immediately adopts this allocation in MainRetainedFriInputsV1.
    Ok(evaluated.into_vec())
}
#[cfg(test)]
/// Exact six-provider registry used only for verifier-safe opened-row evaluation.
pub(super) struct MainOpenedProviderSetV1<'a> {
    layout: AggregateProofLayoutV1,
    groups: Vec<MainOpenedGroupProviderV1<'a>>,
}
#[cfg(test)]
impl<'a> MainOpenedProviderSetV1<'a> {
    #[cfg(test)]
    pub(super) fn new_v1(
        layout: &AggregateProofLayoutV1,
        groups: Vec<MainOpenedGroupProviderV1<'a>>,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        if groups.len() != FULL_PROFILE_TRACE_GROUPS_V1
            || groups.len() != layout.trace_groups.len()
            || groups
                .iter()
                .zip(&layout.trace_groups)
                .any(|(provider, group)| provider.native_trace_log2_v1() != group.native_trace_log2)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(MainOpenedProviderSetV1 {
            layout: layout.clone(),
            groups,
        })
    }
    #[cfg(test)]
    fn validate_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.layout.validate_exact_full_profile_registration_v1()?;
        if self.groups.len() != FULL_PROFILE_TRACE_GROUPS_V1
            || self.groups.len() != self.layout.trace_groups.len()
            || self
                .groups
                .iter()
                .zip(&self.layout.trace_groups)
                .any(|(provider, group)| provider.native_trace_log2_v1() != group.native_trace_log2)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn registered_constraint_residues_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        self.validate_v1()?;
        if self
            .layout
            .registered_segments
            .get(
                self.layout
                    .registered_segments
                    .binary_search_by_key(
                        &(
                            registration.segment.trace_log2,
                            registration.segment.adapter,
                            registration.segment.instance,
                        ),
                        |candidate| {
                            (
                                candidate.segment.trace_log2,
                                candidate.segment.adapter,
                                candidate.segment.instance,
                            )
                        },
                    )
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            )
            .copied()
            != Some(registration)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let provider = self
            .groups
            .get_mut(registration.trace_group)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if provider.native_trace_log2_v1() != registration.segment.trace_log2 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        provider.constraint_residues_v1(registration, query_index, next_query_index, x, opening)
    }
}
#[cfg(test)]
fn validate_main_opened_evaluation_shape_v1(
    providers: &MainOpenedProviderSetV1<'_>,
    query_index: usize,
    lane: usize,
    trace_groups: &[aggregate::AggregateOpenedTraceGroupV1],
    alphas: &[Vec<Vec<E>>],
) -> Result<(), ZkX509StarkErrorV1> {
    providers.validate_v1()?;
    let layout = &providers.layout;
    if query_index >= layout.common_lde_size()
        || lane >= SECURITY_LANES
        || trace_groups.len() != layout.trace_groups.len()
        || alphas.len() != layout.registered_segments.len()
        || trace_groups
            .iter()
            .zip(&layout.trace_groups)
            .any(|(opening, group)| {
                opening.base_current.len() != group.base_width
                    || opening.base_next.len() != group.base_width
                    || opening.aux_current.len() != group.aux_width
                    || opening.aux_next.len() != group.aux_width
                    || opening
                        .base_current
                        .iter()
                        .chain(&opening.base_next)
                        .chain(&opening.aux_current)
                        .chain(&opening.aux_next)
                        .any(|value| F::canonical(value.0).is_none())
            })
        || alphas
            .iter()
            .zip(&layout.registered_segments)
            .any(|(lanes, registration)| {
                lanes.len() != SECURITY_LANES
                    || lanes
                        .iter()
                        .any(|values| values.len() != registration.segment.constraint_count)
            })
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn main_opened_composition_value_v1(
    providers: &mut MainOpenedProviderSetV1<'_>,
    query_index: usize,
    lane: usize,
    trace_groups: &[aggregate::AggregateOpenedTraceGroupV1],
    alphas: &[Vec<Vec<E>>],
    link_alphas: &[E],
) -> Result<E, ZkX509StarkErrorV1> {
    validate_main_opened_evaluation_shape_v1(providers, query_index, lane, trace_groups, alphas)?;
    let lde_root = goldilocks_primitive_root_v1(providers.layout.common_lde_log2)
        .map_err(map_transparent_error_v1)?;
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(query_index as u128));
    let mut composition = E::ZERO;
    for registration_index in 0..providers.layout.registered_segments.len() {
        let registration = providers.layout.registered_segments[registration_index];
        let opening = registered_opened_rows_v1(&providers.layout, registration, trace_groups)
            .map_err(map_aggregate_error_v1)?;
        let next_stride = providers
            .layout
            .trace_groups
            .get(registration.trace_group)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            .next_stride(providers.layout.common_lde_log2)?;
        let next_query_index = query_index
            .checked_add(next_stride)
            .map(|index| index % providers.layout.common_lde_size())
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let residues = providers.registered_constraint_residues_v1(
            registration,
            query_index,
            next_query_index,
            x,
            opening,
        )?;
        if residues.len() != registration.segment.constraint_count
            || residues.iter().any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        composition = composition.add(accumulator_quotient_value_v1(
            registration.segment,
            x,
            &residues,
            &alphas[registration_index][lane],
        )?);
    }
    composition =
        composition.add(
            main_terminal_links::MainTerminalLinkPlanV1::new_v1(&providers.layout)?
                .evaluate_base_v1(trace_groups, x, link_alphas)?,
        );
    Ok(composition)
}
#[cfg(test)]
pub(super) fn main_link_composition_for_test_v1(
    layout: &AggregateProofLayoutV1,
    groups: &[aggregate::AggregateOpenedTraceGroupV1],
    point: F,
    alphas: &[E],
) -> Result<E, ZkX509StarkErrorV1> {
    main_terminal_links::MainTerminalLinkPlanV1::new_v1(layout)?
        .evaluate_base_v1(groups, point, alphas)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn validate_main_fri_mixes_v1(
    layout: &AggregateProofLayoutV1,
    mixes: &[Vec<FriMixV1>],
) -> Result<(), ZkX509StarkErrorV1> {
    layout.validate_exact_full_profile_registration_v1()?;
    if mixes.len() != layout.trace_groups.len()
        || mixes.iter().any(|lanes| lanes.len() != SECURITY_LANES)
        || mixes
            .iter()
            .zip(&layout.trace_groups)
            .any(|(lanes, group)| {
                lanes.iter().any(|mix| {
                    mix.base.len() != group.base_width
                        || mix.base_next.len() != group.base_width
                        || mix.aux.len() != group.aux_width
                        || mix.aux_next.len() != group.aux_width
                        || mix.composition.len() != COMPOSITION_DEGREE_CHUNKS
                })
            })
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    for lane in 0..SECURITY_LANES {
        let composition = &mixes[0][lane].composition;
        if mixes
            .iter()
            .any(|lanes| &lanes[lane].composition != composition)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
    }
    Ok(())
}
#[cfg(test)]
/// Full MAIN verifier opened-row evaluator.
///
/// This path is intentionally separate from prover fixed-polynomial streaming:
/// verification samples only the canonical query openings, while proving must
/// traverse the full common domain without inheriting a query-cache bound.
pub(super) struct MainOpenedRowEvaluatorV1<'a, 'providers> {
    pub(super) providers: &'a mut MainOpenedProviderSetV1<'providers>,
    pub(super) alphas: &'a [Vec<Vec<E>>],
    pub(super) link_alphas: &'a [E],
    pub(super) mixes: &'a [Vec<FriMixV1>],
}
#[cfg(test)]
impl aggregate::AggregateOpenedRowEvaluatorV1 for MainOpenedRowEvaluatorV1<'_, '_> {
    fn evaluate_opened_row_v1(
        &mut self,
        query_index: usize,
        lane: usize,
        trace_groups: &[aggregate::AggregateOpenedTraceGroupV1],
        composition_chunks: &[E],
    ) -> Result<aggregate::AggregateExpectedOpeningV1, AggregateStarkErrorV1> {
        validate_main_fri_mixes_v1(&self.providers.layout, self.mixes)
            .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        if composition_chunks.len() != COMPOSITION_DEGREE_CHUNKS {
            return Err(AggregateStarkErrorV1::ConstraintOpening);
        }
        let composition = main_opened_composition_value_v1(
            self.providers,
            query_index,
            lane,
            trace_groups,
            self.alphas,
            self.link_alphas,
        )
        .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        let mut fri_base = E::ZERO;
        for (group_index, opening) in trace_groups.iter().enumerate() {
            let mix = &self.mixes[group_index][lane];
            fri_base = fri_base.add(
                opening
                    .base_current
                    .iter()
                    .zip(&mix.base)
                    .fold(E::ZERO, |sum, (value, coefficient)| {
                        sum.add(coefficient.mul_base(*value))
                    }),
            );
            fri_base = fri_base.add(
                opening
                    .aux_current
                    .iter()
                    .zip(&mix.aux)
                    .fold(E::ZERO, |sum, (value, coefficient)| {
                        sum.add(coefficient.mul_base(*value))
                    }),
            );
        }
        fri_base = fri_base.add(mix_opened_composition_chunks_v1(
            composition_chunks,
            &self.mixes[0][lane],
        )?);
        Ok(aggregate::AggregateExpectedOpeningV1 {
            composition,
            fri_base,
        })
    }
}
#[cfg(test)]
impl aggregate::AggregateOpenedRowEvaluatorV1 for DerOpenedRowEvaluatorV1<'_> {
    fn evaluate_opened_row_v1(
        &mut self,
        query_index: usize,
        lane: usize,
        trace_groups: &[aggregate::AggregateOpenedTraceGroupV1],
        composition_chunks: &[E],
    ) -> Result<aggregate::AggregateExpectedOpeningV1, AggregateStarkErrorV1> {
        let registration = self
            .aggregate_layout
            .registered_segment(SegmentAdapterIdV1::StrictDer, 0)
            .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        if registration.segment != self.layout {
            return Err(AggregateStarkErrorV1::ConstraintOpening);
        }
        let opening = registered_opened_rows_v1(self.aggregate_layout, registration, trace_groups)?;
        let alphas = self
            .alphas
            .get(lane)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        let mix = self
            .mixes
            .get(lane)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        let next_index = query_index
            .checked_add(
                self.aggregate_layout
                    .trace_groups
                    .get(registration.trace_group)
                    .ok_or(AggregateStarkErrorV1::ConstraintOpening)?
                    .next_stride(self.aggregate_layout.common_lde_log2)
                    .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?,
            )
            .map(|index| index % self.aggregate_layout.common_lde_size())
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        let fixed = self
            .fixed_openings
            .get(&query_index)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        let next_fixed = self
            .fixed_openings
            .get(&next_index)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(self.lde_root.pow(query_index as u128));
        let composition = der_quotient_value_v1(
            self.layout,
            x,
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            fixed,
            next_fixed,
            self.challenges,
            self.public,
            self.claims,
            alphas,
        )
        .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        if opening.base_current.len() != mix.base.len()
            || opening.aux_current.len() != mix.aux.len()
        {
            return Err(AggregateStarkErrorV1::ConstraintOpening);
        }
        let mixed_base = opening
            .base_current
            .iter()
            .zip(&mix.base)
            .fold(E::ZERO, |sum, (value, coefficient)| {
                sum.add(coefficient.mul_base(*value))
            });
        let mixed_aux = opening
            .aux_current
            .iter()
            .zip(&mix.aux)
            .fold(E::ZERO, |sum, (value, coefficient)| {
                sum.add(coefficient.mul_base(*value))
            });
        Ok(aggregate::AggregateExpectedOpeningV1 {
            composition,
            fri_base: mixed_base
                .add(mixed_aux)
                .add(mix_opened_composition_chunks_v1(composition_chunks, mix)?),
        })
    }
}
#[cfg(test)]
impl aggregate::AggregateOpenedRowEvaluatorV1 for IoOpenedRowEvaluatorV1<'_> {
    fn evaluate_opened_row_v1(
        &mut self,
        query_index: usize,
        lane: usize,
        trace_groups: &[aggregate::AggregateOpenedTraceGroupV1],
        composition_chunks: &[E],
    ) -> Result<aggregate::AggregateExpectedOpeningV1, AggregateStarkErrorV1> {
        let registration = self
            .aggregate_layout
            .registered_segment(SegmentAdapterIdV1::ByteMemory, 0)
            .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        if registration.segment != self.layout {
            return Err(AggregateStarkErrorV1::ConstraintOpening);
        }
        let opening = registered_opened_rows_v1(self.aggregate_layout, registration, trace_groups)?;
        let alphas = self
            .alphas
            .get(lane)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        let mix = self
            .mixes
            .get(lane)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        let fixed = row_at_v1(self.fixed_lde, query_index)
            .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(self.lde_root.pow(query_index as u128));
        let composition = quotient_value_v1(
            self.layout,
            self.logical_active_rows,
            x,
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            &fixed,
            self.io_challenges,
            alphas,
        )
        .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        if opening.base_current.len() != mix.base.len()
            || opening.aux_current.len() != mix.aux.len()
        {
            return Err(AggregateStarkErrorV1::ConstraintOpening);
        }
        let mixed_base = opening
            .base_current
            .iter()
            .zip(&mix.base)
            .fold(E::ZERO, |sum, (value, coefficient)| {
                sum.add(coefficient.mul_base(*value))
            });
        let mixed_aux = opening
            .aux_current
            .iter()
            .zip(&mix.aux)
            .fold(E::ZERO, |sum, (value, coefficient)| {
                sum.add(coefficient.mul_base(*value))
            });
        Ok(aggregate::AggregateExpectedOpeningV1 {
            composition,
            fri_base: mixed_base
                .add(mixed_aux)
                .add(mix_opened_composition_chunks_v1(composition_chunks, mix)?),
        })
    }
}
#[cfg(test)]
pub(super) struct ProjectionOpenedRowEvaluatorV1<'a> {
    pub(super) aggregate_layout: &'a AggregateProofLayoutV1,
    pub(super) layout: SegmentLayoutV1,
    pub(super) fixed_lde: &'a [Vec<F>],
    pub(super) challenges: ZkX509ProjectionChallengesV1,
    pub(super) alphas: &'a [Vec<E>],
    pub(super) mixes: &'a [FriMixV1],
    pub(super) lde_root: F,
}
#[cfg(test)]
pub(super) struct P256OpenedRowEvaluatorV1<'a> {
    pub(super) material: &'a P256OpenedMaterialV1,
    pub(super) challenges: P256AggregateChallengesV1,
    pub(super) alphas: &'a [Vec<Vec<E>>],
    pub(super) mixes: &'a [Vec<FriMixV1>],
    pub(super) lde_root: F,
}
/// Complete registered arithmetic relation, including local scalar and value-copy recurrences.
fn p256_arithmetic_opened_residues_over_field_v1<A: PolynomialAirFieldV1>(
    registration: RegisteredSegmentLayoutV1,
    opening: RegisteredOpenedRowsV1<'_, A>,
    fixed: &[A],
    challenges: P256AggregateChallengesV1,
) -> Result<Vec<A>, ZkX509StarkErrorV1> {
    let identity = p256_main_registration_from_main_layout_v1(registration)?;
    if identity.adapter_v1() != P256MainAdapterV1::Arithmetic
        || registration.segment.constraint_count != P256_ARITHMETIC_REGISTERED_CONSTRAINT_COUNT_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let current = opening
        .base_current
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next = opening
        .base_next
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let current_aux = opening
        .aux_current
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next_aux = opening
        .aux_next
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let fixed = fixed
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let residues = super::super::p256_aggregate_adapter::evaluate_p256_arithmetic_aggregate_residues_over_field_v1(
        current, next, current_aux, next_aux, fixed, challenges.scalar, challenges.arithmetic_copy,
    )?;

    if residues.len() != registration.segment.constraint_count {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(residues)
}
/// Complete registered external-binding sink, including the constant private terminal column.
fn p256_binding_sink_opened_residues_over_field_v1<A: PolynomialAirFieldV1>(
    registration: RegisteredSegmentLayoutV1,
    opening: RegisteredOpenedRowsV1<'_, A>,
    fixed: &[A],
    challenges: P256AggregateChallengesV1,
) -> Result<Vec<A>, ZkX509StarkErrorV1> {
    let identity = p256_main_registration_from_main_layout_v1(registration)?;
    if identity.adapter_v1() != P256MainAdapterV1::BindingSink
        || registration.segment.constraint_count != P256_BINDING_SINK_REGISTERED_CONSTRAINT_COUNT_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let current = opening
        .base_current
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next = opening
        .base_next
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let current_aux = opening
        .aux_current
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next_aux = opening
        .aux_next
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let fixed = fixed
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let residues = super::super::p256_aggregate_adapter::evaluate_p256_binding_sink_aggregate_residues_over_field_v1(
        current, next, current_aux, next_aux, fixed, challenges.cross,
    )?;

    if residues.len() != registration.segment.constraint_count {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(residues)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn p256_scalar_opened_residues_v1(
    registration: RegisteredSegmentLayoutV1,
    opening: RegisteredOpenedRowsV1<'_>,
    fixed: &[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1],
    challenges: P256ScalarBitBusChallengesV1,
) -> Result<Vec<F>, ZkX509StarkErrorV1> {
    p256_scalar_opened_residues_over_field_v1(registration, opening, fixed, challenges)
}
/// Complete packed scalar-bit relation over F or Fp4, including local terminal-state recurrences.
pub(super) fn p256_scalar_opened_residues_over_field_v1<A: PolynomialAirFieldV1>(
    registration: RegisteredSegmentLayoutV1,
    opening: RegisteredOpenedRowsV1<'_, A>,
    fixed: &[A; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1],
    challenges: P256ScalarBitBusChallengesV1,
) -> Result<Vec<A>, ZkX509StarkErrorV1> {
    let Some((_, 0)) = p256_instance_parts_v1(registration.segment.instance) else {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    };
    if registration.segment.adapter != SegmentAdapterIdV1::P256ScalarBitBus
        || registration.segment.trace_log2 != P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_LOG2_V1
        || registration.segment.base_width != P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1
        || registration.segment.aux_width != P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1
        || registration.segment.fixed_width != P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1
        || registration.segment.constraint_count
            != P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1
        || opening
            .base_current
            .iter()
            .chain(opening.base_next)
            .chain(opening.aux_current)
            .chain(opening.aux_next)
            .chain(fixed)
            .any(|value| !value.is_canonical())
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }

    challenges
        .validate_v1()
        .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
    let current: &[A; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1] = opening
        .base_current
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next: &[A; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1] = opening
        .base_next
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let current_aux: &[A; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1] = opening
        .aux_current
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next_aux: &[A; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1] = opening
        .aux_next
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let residues = super::super::p256_aggregate_adapter::evaluate_p256_scalar_bit_bus_aggregate_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )?;
    if residues.len() != P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1 {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    if residues.len() != P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1 {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(residues)
}
/// Complete registered comparison residues, including local constant-terminal constraints.
///
/// This is the one implementation used by existing scalar queries and the
/// partial MAIN Fp4 adapter. Public challenges remain in F; endpoint equality is a separate joined quotient.
fn p256_comparison_opened_residues_v1<A: PolynomialAirFieldV1>(
    registration: RegisteredSegmentLayoutV1,
    opening: RegisteredOpenedRowsV1<'_, A>,
    fixed: &[A],
    challenges: P256AggregateChallengesV1,
) -> Result<Vec<A>, ZkX509StarkErrorV1> {
    let identity = p256_main_registration_from_main_layout_v1(registration)?;
    let local_instance = identity.local_instance_v1();
    challenges
        .cross
        .validate()
        .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;

    if opening
        .base_current
        .iter()
        .chain(opening.base_next)
        .chain(opening.aux_current)
        .chain(opening.aux_next)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    let residues = match (registration.segment.adapter, local_instance) {
        (SegmentAdapterIdV1::P256Reduction, _instance @ 0..=1) => {
            let current: &[A; P256_REDUCTION_BASE_WIDTH_V1] = opening
                .base_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let next: &[A; P256_REDUCTION_BASE_WIDTH_V1] = opening
                .base_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let current_aux: &[A; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1] = opening
                .aux_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let next_aux: &[A; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1] = opening
                .aux_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let fixed: &[A; P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1] = fixed
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let residues = super::super::p256_aggregate_adapter::evaluate_p256_reduction_aggregate_local_residues_over_field_v1(
                current,
                next,
                current_aux,
                next_aux,
                fixed,
                challenges.cross,
            )?;

            residues
        }
        (SegmentAdapterIdV1::P256LowS, 0) => {
            let current: &[A; P256_LOW_S_BASE_WIDTH_V1] = opening
                .base_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let next: &[A; P256_LOW_S_BASE_WIDTH_V1] = opening
                .base_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let current_aux: &[A; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1] = opening
                .aux_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let next_aux: &[A; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1] = opening
                .aux_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let fixed: &[A; P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1] = fixed
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let residues = super::super::p256_aggregate_adapter::evaluate_p256_low_s_aggregate_local_residues_over_field_v1(
                current,
                next,
                current_aux,
                next_aux,
                fixed,
                challenges.cross,
            )?;

            residues
        }
        _ => return Err(ZkX509StarkErrorV1::ProfileMismatch),
    };
    if residues.len() != registration.segment.constraint_count {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(residues)
}
fn p256_window_opened_residues_over_field_v1<A: PolynomialAirFieldV1>(
    registration: RegisteredSegmentLayoutV1,
    opening: RegisteredOpenedRowsV1<'_, A>,
    fixed: &[A],
    challenges: P256AggregateChallengesV1,
) -> Result<Vec<A>, ZkX509StarkErrorV1> {
    registration.segment.validate()?;
    p256_main_registration_from_main_layout_v1(registration)?;
    if registration.segment.adapter != SegmentAdapterIdV1::P256Window
        || !matches!(
            p256_instance_parts_v1(registration.segment.instance),
            Some((_, 0))
        )
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }

    let current: &[A; P256_WINDOW_BASE_WIDTH_V1] = opening
        .base_current
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next: &[A; P256_WINDOW_BASE_WIDTH_V1] = opening
        .base_next
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let current_aux: &[A; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1] = opening
        .aux_current
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next_aux: &[A; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1] = opening
        .aux_next
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let fixed: &[A; P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1] = fixed
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let residues = super::super::p256_aggregate_adapter::evaluate_p256_window_aggregate_local_residues_over_field_v1(
                current,
                next,
                current_aux,
                next_aux,
                fixed,
                challenges.cross,
                challenges.scalar,
            )?;

    if residues.len() != registration.segment.constraint_count {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(residues)
}
fn p256_value_opened_residues_over_field_v1<A: PolynomialAirFieldV1>(
    registration: RegisteredSegmentLayoutV1,
    opening: RegisteredOpenedRowsV1<'_, A>,
    fixed: &[A],
    challenges: P256AggregateChallengesV1,
) -> Result<Vec<A>, ZkX509StarkErrorV1> {
    registration.segment.validate()?;
    p256_main_registration_from_main_layout_v1(registration)?;

    let (_, local_instance) = p256_instance_parts_v1(registration.segment.instance)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let residues = match (registration.segment.adapter, local_instance) {
        (SegmentAdapterIdV1::P256ValueBus, 0) => {
            let current: &[A; P256_VALUE_BUS_STARK_BASE_WIDTH_V1] = opening
                .base_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let next: &[A; P256_VALUE_BUS_STARK_BASE_WIDTH_V1] = opening
                .base_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let current_aux: &[A; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1] = opening
                .aux_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let next_aux: &[A; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1] = opening
                .aux_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let fixed: &[A; P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1] = fixed
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let residues = super::super::p256_aggregate_adapter::evaluate_p256_value_execution_aggregate_residues_over_field_v1(
                current,
                next,
                current_aux,
                next_aux,
                fixed,
                P256ValueExecutionAggregateChallengesV1 {
                    value: challenges.value,
                    cross: challenges.cross,
                    arithmetic_copy: challenges.arithmetic_copy,
                },
            )?;

            residues
        }
        (SegmentAdapterIdV1::P256ValueBus, 1) => {
            let current: &[A; P256_VALUE_BUS_STARK_BASE_WIDTH_V1] = opening
                .base_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let next: &[A; P256_VALUE_BUS_STARK_BASE_WIDTH_V1] = opening
                .base_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let current_aux: &[A; P256_VALUE_BUS_STARK_AUX_WIDTH_V1] = opening
                .aux_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let next_aux: &[A; P256_VALUE_BUS_STARK_AUX_WIDTH_V1] = opening
                .aux_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let fixed: &[A; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1] = fixed
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let residues =
                super::super::p256_value_bus::evaluate_p256_value_bus_stark_residues_over_field_v1(
                    current,
                    next,
                    current_aux,
                    next_aux,
                    fixed,
                    challenges.value,
                )
                .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;

            residues
        }
        _ => return Err(ZkX509StarkErrorV1::ProfileMismatch),
    };
    if residues.len() != registration.segment.constraint_count {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(residues)
}
/// Availability of a complete per-registration Fp4 AIR implementation.
///
/// Each variant carries a family-specific evaluator so its public challenges
/// and terminal claims cannot be confused with another adapter. This capability
/// authenticates no opening, quotient or complete MAIN proof. Unsupported
/// registrations return None, and there is no reduced-opening codec switch.
#[derive(Clone, Copy)]
enum MainFp4AirEvaluatorV1 {
    P256(P256MainFp4AirEvaluatorV1),
    Sha(ShaMainFp4AirEvaluatorV1),
    Projection(ProjectionMainFp4AirEvaluatorV1),
    ByteMemory(ByteMemoryMainFp4AirEvaluatorV1),
    StrictDer(DerMainFp4AirEvaluatorV1),
    Rfc5280(RfcMainFp4AirEvaluatorV1),
}
impl MainFp4AirEvaluatorV1 {
    fn registration_v1(self) -> RegisteredSegmentLayoutV1 {
        match self {
            Self::P256(evaluator) => evaluator.registration,
            Self::Sha(evaluator) => evaluator.registration,
            Self::Projection(evaluator) => evaluator.registration,
            Self::ByteMemory(evaluator) => evaluator.registration,
            Self::StrictDer(evaluator) => evaluator.registration,
            Self::Rfc5280(evaluator) => evaluator.registration,
        }
    }
    fn for_registration_v1(
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<Option<Self>, ZkX509StarkErrorV1> {
        registration.segment.validate()?;
        if !AggregateProofLayoutV1::for_full_profile_v1()?
            .registered_segments
            .contains(&registration)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        match registration.segment.adapter {
            SegmentAdapterIdV1::P256Reduction
            | SegmentAdapterIdV1::P256LowS
            | SegmentAdapterIdV1::P256ScalarBitBus
            | SegmentAdapterIdV1::P256Window
            | SegmentAdapterIdV1::P256Arithmetic => {
                p256_main_registration_from_main_layout_v1(registration)?;
                Ok(Some(Self::P256(P256MainFp4AirEvaluatorV1 { registration })))
            }
            SegmentAdapterIdV1::P256ValueBus
                if matches!(
                    p256_instance_parts_v1(registration.segment.instance),
                    Some((_, 0 | 1 | 2))
                ) =>
            {
                p256_main_registration_from_main_layout_v1(registration)?;
                Ok(Some(Self::P256(P256MainFp4AirEvaluatorV1 { registration })))
            }
            SegmentAdapterIdV1::Sha256CallBus => {
                Ok(Some(Self::Sha(ShaMainFp4AirEvaluatorV1 { registration })))
            }
            SegmentAdapterIdV1::Projection => {
                Ok(Some(Self::Projection(ProjectionMainFp4AirEvaluatorV1 {
                    registration,
                })))
            }
            SegmentAdapterIdV1::ByteMemory => {
                Ok(Some(Self::ByteMemory(ByteMemoryMainFp4AirEvaluatorV1 {
                    registration,
                })))
            }
            SegmentAdapterIdV1::StrictDer => Ok(Some(Self::StrictDer(DerMainFp4AirEvaluatorV1 {
                registration,
            }))),
            SegmentAdapterIdV1::Rfc5280 => Ok(Some(Self::Rfc5280(RfcMainFp4AirEvaluatorV1 {
                registration,
            }))),
            _ => Ok(None),
        }
    }
}
#[derive(Clone, Copy)]
struct DerMainFp4AirEvaluatorV1 {
    registration: RegisteredSegmentLayoutV1,
}
struct DerMainFp4AirContextV1 {
    challenges: ZkX509DerStarkChallengesV1,
    public: ZkX509DerStarkPublicTerminalsV1,
}
impl DerMainFp4AirEvaluatorV1 {
    fn evaluate_residues_v1(
        self,
        opening: RegisteredOpenedRowsV1<'_, E>,
        fixed: &[E],
        next_fixed: &[E],
        context: DerMainFp4AirContextV1,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        let residues = super::super::der_stark::evaluate_zk_x509_der_stark_local_residues_v1(
            opening
                .base_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            opening
                .base_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            opening
                .aux_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            opening
                .aux_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            fixed
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            next_fixed
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            context.challenges,
            context.public,
        )
        .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?;
        if residues.len() != self.registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(residues)
    }
}
#[derive(Clone, Copy)]
struct RfcMainFp4AirEvaluatorV1 {
    registration: RegisteredSegmentLayoutV1,
}
struct RfcMainFp4AirContextV1 {
    der: ZkX509DerStarkChallengesV1,
    rfc: ZkX509Rfc5280StarkChallengesV1,
}
impl RfcMainFp4AirEvaluatorV1 {
    fn evaluate_residues_v1(
        self,
        opening: RegisteredOpenedRowsV1<'_, E>,
        fixed: &[E],
        context: RfcMainFp4AirContextV1,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        let residues = evaluate_zk_x509_rfc5280_local_residues_v1(
            opening
                .base_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            opening
                .base_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            opening
                .aux_current
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            opening
                .aux_next
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            fixed
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            context.der,
            &context.rfc,
        )
        .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?;
        if residues.len() != self.registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(residues)
    }
}
#[derive(Clone, Copy)]
struct P256MainFp4AirEvaluatorV1 {
    registration: RegisteredSegmentLayoutV1,
}
#[derive(Clone, Copy)]
struct ByteMemoryMainFp4AirEvaluatorV1 {
    registration: RegisteredSegmentLayoutV1,
}
impl ByteMemoryMainFp4AirEvaluatorV1 {
    fn evaluate_residues_v1(
        self,
        logical_active_rows: usize,
        opening: RegisteredOpenedRowsV1<'_, E>,
        fixed: &[E],
        challenges: ZkX509IoChallengesV1,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        io_constraint_residues_v1(
            self.registration.segment,
            logical_active_rows,
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            fixed,
            challenges,
        )
    }
}
#[derive(Clone, Copy)]
struct ProjectionMainFp4AirEvaluatorV1 {
    registration: RegisteredSegmentLayoutV1,
}
impl ProjectionMainFp4AirEvaluatorV1 {
    fn evaluate_residues_v1(
        self,
        opening: RegisteredOpenedRowsV1<'_, E>,
        fixed: &[E],
        challenges: ZkX509ProjectionChallengesV1,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        let residues = projection_constraint_residues_v1(
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            fixed,
            challenges,
        )?;
        if residues.len() != self.registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(residues)
    }
}
impl P256MainFp4AirEvaluatorV1 {
    fn evaluate_residues_v1(
        self,
        opening: RegisteredOpenedRowsV1<'_, E>,
        fixed: &[E],
        challenges: P256AggregateChallengesV1,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        match self.registration.segment.adapter {
            SegmentAdapterIdV1::P256ScalarBitBus => p256_scalar_opened_residues_over_field_v1(
                self.registration,
                opening,
                fixed
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                challenges.scalar,
            ),
            SegmentAdapterIdV1::P256Window => p256_window_opened_residues_over_field_v1(
                self.registration,
                opening,
                fixed,
                challenges,
            ),
            SegmentAdapterIdV1::P256Arithmetic => p256_arithmetic_opened_residues_over_field_v1(
                self.registration,
                opening,
                fixed,
                challenges,
            ),
            SegmentAdapterIdV1::P256ValueBus => {
                match p256_instance_parts_v1(self.registration.segment.instance) {
                    Some((_, 2)) => p256_binding_sink_opened_residues_over_field_v1(
                        self.registration,
                        opening,
                        fixed,
                        challenges,
                    ),
                    Some((_, 0 | 1)) => p256_value_opened_residues_over_field_v1(
                        self.registration,
                        opening,
                        fixed,
                        challenges,
                    ),
                    _ => Err(ZkX509StarkErrorV1::ProfileMismatch),
                }
            }
            SegmentAdapterIdV1::P256Reduction | SegmentAdapterIdV1::P256LowS => {
                p256_comparison_opened_residues_v1(self.registration, opening, fixed, challenges)
            }
            _ => Err(ZkX509StarkErrorV1::ProfileMismatch),
        }
    }
}
#[derive(Clone, Copy)]
struct ShaMainFp4AirEvaluatorV1 {
    registration: RegisteredSegmentLayoutV1,
}
/// Public SHA-family context bound before constraint mixing.
struct ShaMainFp4AirContextV1 {
    word: ZkX509ShaWordStarkChallengesV1,
    call: ZkX509ShaCallBusChallengesV1,
    rfc: ZkX509Rfc5280StarkChallengesV1,
    segment: u8,
}
impl ShaMainFp4AirEvaluatorV1 {
    fn evaluate_residues_v1(
        self,
        current: &ZkX509ShaBatchRowV1<E>,
        next: &ZkX509ShaBatchRowV1<E>,
        context: ShaMainFp4AirContextV1,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        if self.registration.segment.instance != u16::from(context.segment) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let residues =
            super::super::sha_call_bus_stark::evaluate_zk_x509_sha_batch_local_residues_over_field_v1(
                current,
                next,
                context.word,
                context.call,
                &context.rfc,
                context.segment,
            )
            .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?;
        if residues.len() != self.registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(residues)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn p256_opened_residues_v1(
    registration: RegisteredSegmentLayoutV1,
    opening: RegisteredOpenedRowsV1<'_>,
    fixed: &[F],
    challenges: P256AggregateChallengesV1,
) -> Result<Vec<F>, ZkX509StarkErrorV1> {
    let (_, local_instance) = p256_instance_parts_v1(registration.segment.instance)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let mut residues = match (registration.segment.adapter, local_instance) {
        (SegmentAdapterIdV1::P256Reduction, 0 | 1) | (SegmentAdapterIdV1::P256LowS, 0) => {
            p256_comparison_opened_residues_v1(registration, opening, fixed, challenges)?
        }
        (SegmentAdapterIdV1::P256ScalarBitBus, 0) => {
            let fixed: &[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1] = fixed
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            p256_scalar_opened_residues_v1(registration, opening, fixed, challenges.scalar)?
        }
        (SegmentAdapterIdV1::P256Window, 0) => {
            p256_window_opened_residues_over_field_v1(registration, opening, fixed, challenges)?
        }
        (SegmentAdapterIdV1::P256ValueBus, 2) => p256_binding_sink_opened_residues_over_field_v1(
            registration,
            opening,
            fixed,
            challenges,
        )?,
        (SegmentAdapterIdV1::P256Arithmetic, 0) => {
            p256_arithmetic_opened_residues_over_field_v1(registration, opening, fixed, challenges)?
        }
        (SegmentAdapterIdV1::P256ValueBus, 0 | 1) => {
            p256_value_opened_residues_over_field_v1(registration, opening, fixed, challenges)?
        }
        _ => return Err(ZkX509StarkErrorV1::ProfileMismatch),
    };
    if residues.len() != registration.segment.constraint_count {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(core::mem::take(&mut residues))
}
#[cfg(test)]
impl aggregate::AggregateOpenedRowEvaluatorV1 for P256OpenedRowEvaluatorV1<'_> {
    fn evaluate_opened_row_v1(
        &mut self,
        query_index: usize,
        lane: usize,
        trace_groups: &[aggregate::AggregateOpenedTraceGroupV1],
        composition_chunks: &[E],
    ) -> Result<aggregate::AggregateExpectedOpeningV1, AggregateStarkErrorV1> {
        self.material
            .validate()
            .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        self.challenges
            .validate()
            .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        let aggregate_layout = &self.material.registration.layout;
        let registered_segments = &aggregate_layout.registered_segments;
        if lane >= SECURITY_LANES
            || self.alphas.len() != registered_segments.len()
            || self.mixes.len() != aggregate_layout.trace_groups.len()
        {
            return Err(AggregateStarkErrorV1::ConstraintOpening);
        }
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(self.lde_root.pow(query_index as u128));
        let mut composition = E::ZERO;
        let mut fri_base = E::ZERO;
        for (registration_index, registration) in aggregate_layout
            .registered_segments
            .iter()
            .copied()
            .enumerate()
        {
            let opening = registered_opened_rows_v1(aggregate_layout, registration, trace_groups)?;
            let fixed = self.material.fixed_openings[registration_index]
                .get(&query_index)
                .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
            let alphas = self.alphas[registration_index]
                .get(lane)
                .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
            let residues = p256_opened_residues_v1(registration, opening, fixed, self.challenges)
                .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
            let local_composition =
                accumulator_quotient_value_v1(registration.segment, x, &residues, alphas)
                    .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
            let mix = self
                .mixes
                .get(registration.trace_group)
                .and_then(|lanes| lanes.get(lane))
                .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
            let base_end = registration
                .base_end()
                .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
            let aux_end = registration
                .aux_end()
                .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
            let base_mix = mix
                .base
                .get(registration.base_start..base_end)
                .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
            let aux_mix = mix
                .aux
                .get(registration.aux_start..aux_end)
                .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
            if opening.base_current.len() != base_mix.len()
                || opening.aux_current.len() != aux_mix.len()
            {
                return Err(AggregateStarkErrorV1::ConstraintOpening);
            }
            let mixed_base = opening
                .base_current
                .iter()
                .zip(base_mix)
                .fold(E::ZERO, |sum, (value, coefficient)| {
                    sum.add(coefficient.mul_base(*value))
                });
            let mixed_aux = opening
                .aux_current
                .iter()
                .zip(aux_mix)
                .fold(E::ZERO, |sum, (value, coefficient)| {
                    sum.add(coefficient.mul_base(*value))
                });
            composition = composition.add(local_composition);
            fri_base = fri_base.add(mixed_base).add(mixed_aux);
        }
        let composition_mix = self
            .mixes
            .first()
            .and_then(|lanes| lanes.get(lane))
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        if self.mixes.iter().any(|lanes| {
            lanes.get(lane).map(|mix| &mix.composition) != Some(&composition_mix.composition)
        }) {
            return Err(AggregateStarkErrorV1::ConstraintOpening);
        }
        fri_base = fri_base.add(mix_opened_composition_chunks_v1(
            composition_chunks,
            composition_mix,
        )?);
        Ok(aggregate::AggregateExpectedOpeningV1 {
            composition,
            fri_base,
        })
    }
}
#[cfg(test)]
impl aggregate::AggregateOpenedRowEvaluatorV1 for ProjectionOpenedRowEvaluatorV1<'_> {
    fn evaluate_opened_row_v1(
        &mut self,
        query_index: usize,
        lane: usize,
        trace_groups: &[aggregate::AggregateOpenedTraceGroupV1],
        composition_chunks: &[E],
    ) -> Result<aggregate::AggregateExpectedOpeningV1, AggregateStarkErrorV1> {
        let registration = self
            .aggregate_layout
            .registered_segment(SegmentAdapterIdV1::Projection, 0)
            .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        if registration.segment != self.layout {
            return Err(AggregateStarkErrorV1::ConstraintOpening);
        }
        let opening = registered_opened_rows_v1(self.aggregate_layout, registration, trace_groups)?;
        let alphas = self
            .alphas
            .get(lane)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        let mix = self
            .mixes
            .get(lane)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
        let fixed = row_at_v1(self.fixed_lde, query_index)
            .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(self.lde_root.pow(query_index as u128));
        let composition = projection_quotient_value_v1(
            self.layout,
            x,
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            &fixed,
            self.challenges,
            alphas,
        )
        .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
        if opening.base_current.len() != mix.base.len()
            || opening.aux_current.len() != mix.aux.len()
        {
            return Err(AggregateStarkErrorV1::ConstraintOpening);
        }
        let mixed_base = opening
            .base_current
            .iter()
            .zip(&mix.base)
            .fold(E::ZERO, |sum, (value, coefficient)| {
                sum.add(coefficient.mul_base(*value))
            });
        let mixed_aux = opening
            .aux_current
            .iter()
            .zip(&mix.aux)
            .fold(E::ZERO, |sum, (value, coefficient)| {
                sum.add(coefficient.mul_base(*value))
            });
        Ok(aggregate::AggregateExpectedOpeningV1 {
            composition,
            fri_base: mixed_base
                .add(mixed_aux)
                .add(mix_opened_composition_chunks_v1(composition_chunks, mix)?),
        })
    }
}
fn main_pre_aux_from_decoded_proof_v1(
    proof_instance: ZkX509ProofInstanceV1,
    public: ZkX509CredentialPublicBindingV1,
    verifier_profile: ZkX509MainVerifierProfileV1,
    layout: &AggregateProofLayoutV1,
    proof: &ZkX509SegmentedStarkProofV1,
) -> Result<ZkX509CredentialMainPreAuxV1, ZkX509StarkErrorV1> {
    layout.validate_exact_full_profile_registration_v1()?;
    validate_zk_x509_main_verifier_profile_v1(verifier_profile)?;
    if public.consensus_context_digest == [0_u8; 32]
        || proof.aggregate.trace_groups.len() != ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let mut session = ZkX509MainBaseCommitmentSessionV1::new_v1(
        proof_instance,
        layout,
        public.consensus_context_digest,
        verifier_profile,
    )?;
    session.accept_decoded_base_groups_v1(&proof.aggregate.trace_groups)?;
    session.finish_pre_aux_v1()
}
/// Decode the canonical MAIN proof and mint its verifier-owned X5B1 input.
///
/// This performs the exact aggregate shape decode before exposing the opaque
/// pre-auxiliary token. The returned value contains no proof-selected
/// challenge and can only be consumed by the joint MAIN-plus-CA transcript.
pub fn zk_x509_main_pre_aux_from_proof_v1(
    proof_instance: ZkX509ProofInstanceV1,
    public: ZkX509CredentialPublicBindingV1,
    proof_bytes: &[u8],
) -> Result<ZkX509CredentialMainPreAuxV1, ZkX509StarkErrorV1> {
    let verifier_profile = construct_zk_x509_main_verifier_profile_v1()?;
    let layout = AggregateProofLayoutV1::for_full_profile_v1()?;
    let envelope = decode_zk_x509_main_proof_envelope_v1(proof_bytes)?;
    let proof = decode_zk_x509_segmented_stark_proof_v1(envelope.aggregate_proof, &layout)?;
    main_pre_aux_from_decoded_proof_v1(proof_instance, public, verifier_profile, &layout, &proof)
}
#[cfg(test)]
#[path = "main_fp4_air_tests.rs"]
mod fp4_air_tests;

#[cfg(test)]
#[path = "main_sha_fp4_air_tests.rs"]
mod sha_fp4_air_tests;

#[cfg(test)]
#[path = "main_window_fp4_air_tests.rs"]
mod window_fp4_air_tests;

#[cfg(test)]
#[path = "main_value_fp4_air_tests.rs"]
mod value_fp4_air_tests;
