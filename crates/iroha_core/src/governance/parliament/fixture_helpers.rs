// Textually included test-corridor fixtures retain the parent module's private access.
#[cfg(any(test, feature = "iroha-core-tests"))]
fn enacted_fixture_governance(
    requirements: &[RequiredParliamentBodyV1],
) -> iroha_config::parameters::actual::Governance {
    let mut governance = iroha_config::parameters::actual::Governance {
        parliament_alternate_size: 0,
        ..iroha_config::parameters::actual::Governance::default()
    };
    for requirement in requirements {
        match requirement.body {
            ParliamentBody::RulesCommittee => governance.rules_committee_size = 3,
            ParliamentBody::AgendaCouncil => governance.agenda_council_size = 3,
            ParliamentBody::InterestPanel => governance.interest_panel_size = 3,
            ParliamentBody::ReviewPanel => governance.review_panel_size = 3,
            ParliamentBody::CoordinationCouncil => governance.coordination_council_size = 3,
            ParliamentBody::MpcCommittee => governance.mpc_committee_size = 3,
            ParliamentBody::FmaCommittee => governance.fma_committee_size = 3,
            ParliamentBody::OversightCommittee => governance.oversight_committee_size = 3,
            ParliamentBody::PolicyJury => governance.policy_jury_size = 3,
            ParliamentBody::ConfirmationJury => governance.confirmation_jury_size = 3,
        }
    }
    governance
}

#[cfg(any(test, feature = "iroha-core-tests"))]
fn prepare_enacted_fixture_body(
    attempt: &mut ParliamentAttemptStateV1,
    requirement: RequiredParliamentBodyV1,
    election_attempt_id: BodyElectionAttemptId,
) -> (BodyInstanceId, Vec<AccountId>) {
    let governance_attempt_id = attempt.attempt().id;
    attempt
        .begin_invitation_acceptance(governance_attempt_id, election_attempt_id, 2, 1)
        .expect("open enacted-attempt fixture invitation window");
    let members = attempt
        .election(&election_attempt_id)
        .expect("drawn enacted-attempt fixture election")
        .primary_assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    for member in &members {
        attempt
            .record_invitation_response(governance_attempt_id, election_attempt_id, member, true, 2)
            .expect("accept enacted-attempt fixture invitation");
    }
    let body_instance_id = attempt
        .seal_body_roster(governance_attempt_id, election_attempt_id, 3)
        .expect("seal enacted-attempt fixture roster");
    let mut phases = vec![
        DeliberationPhaseV1::Orientation,
        DeliberationPhaseV1::Evidence,
        DeliberationPhaseV1::Questions,
        DeliberationPhaseV1::Responses,
        DeliberationPhaseV1::Deliberation,
        DeliberationPhaseV1::Reflection,
    ];
    if requirement.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot {
        phases.push(DeliberationPhaseV1::Vote);
    }
    for phase in phases {
        attempt
            .advance_body_phase(governance_attempt_id, body_instance_id, phase, 3, 1)
            .expect("advance enacted-attempt fixture deliberation");
    }
    (body_instance_id, members)
}

#[cfg(any(test, feature = "iroha-core-tests"))]
fn complete_enacted_fixture_body(
    attempt: &mut ParliamentAttemptStateV1,
    requirement: RequiredParliamentBodyV1,
    election_attempt_id: BodyElectionAttemptId,
    result_tag: u8,
) {
    let governance_attempt_id = attempt.attempt().id;
    let (body_instance_id, members) =
        prepare_enacted_fixture_body(attempt, requirement, election_attempt_id);
    match requirement.decision_mode {
        ParliamentDecisionModeV1::PublicFinding => {
            let result_root = [result_tag.max(1); 32];
            let mut finalized = false;
            for member in &members {
                finalized = attempt
                    .endorse_public_finding(
                        governance_attempt_id,
                        body_instance_id,
                        result_root,
                        member,
                        3,
                    )
                    .expect("endorse enacted-attempt fixture public finding");
                if finalized {
                    break;
                }
            }
            assert!(
                finalized,
                "fixture seats must reach the public-finding quorum"
            );
        }
        ParliamentDecisionModeV1::HiddenBindingBallot => {
            let root = |tag: u8| [tag.max(1); 32];
            let ballot_attempt_id = BallotAttemptId::derive_v1(body_instance_id, 0);
            let release_beacon_session_id = BeaconSessionId::new(root(0xD0));
            let tle_key_session_id = TleKeySessionId::new(root(0xD1));
            let release_height = 12;
            let tle_session_id = TleSessionId::derive_v1(
                ballot_attempt_id,
                tle_key_session_id,
                release_beacon_session_id,
                release_height,
            );
            attempt
                .register_ballot_attempt(
                    governance_attempt_id,
                    body_instance_id,
                    ballot_attempt_id,
                    0,
                    tle_session_id,
                    tle_key_session_id,
                    release_beacon_session_id,
                    3,
                    ParliamentTimedOvn {
                        registration_phase_blocks: 4,
                        survivor_freeze_phase_blocks: 3,
                        commitment_phase_blocks: 1,
                        release_delay_blocks: 1,
                        opening_phase_blocks: 1,
                        max_ballot_retries: 2,
                        max_corpus_entries: 3,
                    },
                    release_height,
                )
                .expect("register enacted-attempt fixture ballot");
            let registration_root = root(0xD2);
            let dropout_root = root(0xD3);
            let survivor_root = root(0xD4);
            let no_recovery_root = root(0xD5);
            let corpus_root = root(0xD6);
            let timed_commitment_root = root(0xD7);
            attempt
                .close_ballot_registration(
                    governance_attempt_id,
                    ballot_attempt_id,
                    registration_root,
                    3,
                    7,
                )
                .expect("close enacted-attempt fixture ballot registration");
            attempt
                .freeze_ballot_survivors(
                    governance_attempt_id,
                    ballot_attempt_id,
                    dropout_root,
                    survivor_root,
                    3,
                    no_recovery_root,
                    10,
                )
                .expect("freeze enacted-attempt fixture ballot survivors");
            attempt
                .freeze_timed_ovn_corpus(
                    governance_attempt_id,
                    ballot_attempt_id,
                    corpus_root,
                    survivor_root,
                    3,
                    timed_commitment_root,
                    11,
                )
                .expect("freeze enacted-attempt fixture timed corpus");
            attempt
                .begin_ballot_opening_batch(
                    governance_attempt_id,
                    vec![ballot_attempt_id],
                    release_beacon_session_id,
                    release_height,
                    release_height,
                    BeaconPulseId::new(root(0xD8)),
                )
                .expect("open enacted-attempt fixture ballot");
            let outcome = attempt
                .finalize_opened_ballot(
                    governance_attempt_id,
                    ballot_attempt_id,
                    corpus_root,
                    no_recovery_root,
                    tle_session_id,
                    root(0xD9),
                    3,
                    ParliamentAggregateTallyV1 {
                        original_seats: 3,
                        accepted_ballots: 3,
                        aye: 2,
                        nay: 1,
                        abstain: 0,
                    },
                    2,
                    release_height,
                )
                .expect("finalize enacted-attempt fixture ballot");
            assert_eq!(outcome, ParliamentAggregateOutcomeV1::Approved);
        }
    }
}

/// Session of the proposal-bound fixture's only sortition slot.
#[cfg(any(test, feature = "iroha-core-tests"))]
const FIXTURE_SORTITION_SESSION: BeaconSessionId = BeaconSessionId::new([0xB0; 32]);
/// Height of the proposal-bound fixture's only sortition slot.
#[cfg(any(test, feature = "iroha-core-tests"))]
const FIXTURE_SORTITION_PULSE_HEIGHT: u64 = 2;

/// Build a proposal-bound attempt whose complete initial generation awaits the pulse of
/// slot `(FIXTURE_SORTITION_SESSION, FIXTURE_SORTITION_PULSE_HEIGHT)`.
///
/// Returns the attempt, its sorted request ids and the canonical candidate snapshot.
#[cfg(any(test, feature = "iroha-core-tests"))]
fn build_pulse_awaiting_parliament_attempt_for_testing(
    proposal: &ProposalKind,
    mut candidates: Vec<AccountId>,
) -> (
    ParliamentAttemptStateV1,
    Vec<SortitionRequestId>,
    Vec<AccountId>,
    Vec<RequiredParliamentBodyV1>,
) {
    candidates.sort_unstable();
    candidates.dedup();
    assert!(candidates.len() >= 3, "fixture requires three candidates");
    let proposal_content_id = ProposalContentId::new(proposal.fingerprint());
    let governance_attempt_id = GovernanceAttemptId::derive_v1(proposal_content_id, 0);
    let (risk_tier, requirements) = parliament_attempt_policy_v1(proposal);
    let mut attempt = ParliamentAttemptStateV1::try_new(
        GovernanceAttemptV1 {
            id: governance_attempt_id,
            proposal_content_id,
            sequence: 0,
            risk_tier,
            stage: GovernanceStageV1::Qualification,
            status: GovernanceAttemptStatusV1::Active,
        },
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        1,
        // Height 2, the fixture's only sortition slot, is the first native pulse height.
        3,
        proposal.effect_preimage_hash_v1(),
        GovernanceExpectedHeadV1::Absent(
            iroha_data_model::governance::types::GovernanceExpectedHeadAbsentV1 {
                subject_id: proposal
                    .governed_subject_id_v1()
                    .expect("derive fixture proposal subject"),
            },
        ),
        requirements.clone(),
    )
    .expect("create proposal-bound enacted-attempt fixture");
    attempt
        .complete_qualification(governance_attempt_id)
        .expect("complete enacted-attempt fixture qualification");
    let candidate_count = u32::try_from(candidates.len()).expect("candidate count fits u32");
    let sortition_session = FIXTURE_SORTITION_SESSION;
    let mut request_ids = Vec::with_capacity(requirements.len());
    for requirement in &requirements {
        let election_attempt_id =
            BodyElectionAttemptId::derive_v1(governance_attempt_id, requirement.body, 0);
        let request = SortitionRequestV1::try_new_canonical(
            governance_attempt_id,
            election_attempt_id,
            requirement.body,
            parliament_candidate_root_v1(governance_attempt_id, requirement.body, &candidates),
            candidate_count,
            3,
            1,
            FIXTURE_SORTITION_PULSE_HEIGHT,
            sortition_session,
            None,
        )
        .expect("construct enacted-attempt fixture sortition request");
        request_ids.push(request.id);
        attempt
            .register_sortition_request(governance_attempt_id, 0, request, candidates.clone())
            .expect("register enacted-attempt fixture sortition request");
    }
    request_ids.sort_unstable();
    (attempt, request_ids, candidates, requirements)
}

/// Build one proposal-bound Parliament attempt whose initial sortition generation still
/// awaits the pulse of its frozen slot. Returns the attempt, that slot and the waiting
/// election ids.
#[cfg(test)]
pub(crate) fn pulse_awaiting_parliament_attempt_for_testing(
    proposal: &ProposalKind,
    candidates: Vec<AccountId>,
) -> (
    ParliamentAttemptStateV1,
    (BeaconSessionId, u64),
    Vec<BodyElectionAttemptId>,
) {
    let (attempt, _, _, requirements) =
        build_pulse_awaiting_parliament_attempt_for_testing(proposal, candidates);
    attempt
        .validate_proposal_bindings_v1(proposal)
        .expect("pulse-awaiting fixture retains exact proposal bindings");
    let election_attempt_ids = requirements
        .iter()
        .map(|requirement| {
            BodyElectionAttemptId::derive_v1(attempt.attempt().id, requirement.body, 0)
        })
        .collect();
    (
        attempt,
        (FIXTURE_SORTITION_SESSION, FIXTURE_SORTITION_PULSE_HEIGHT),
        election_attempt_ids,
    )
}

#[cfg(any(test, feature = "iroha-core-tests"))]
fn build_certified_parliament_attempt_for_testing<F>(
    proposal: &ProposalKind,
    candidates: Vec<AccountId>,
    network_id: &NetworkId,
    enact_at_height: u64,
    mut complete_body: F,
) -> ParliamentAttemptStateV1
where
    F: FnMut(&mut ParliamentAttemptStateV1, RequiredParliamentBodyV1, BodyElectionAttemptId, u8),
{
    let (mut attempt, request_ids, _candidates, requirements) =
        build_pulse_awaiting_parliament_attempt_for_testing(proposal, candidates);
    let governance_attempt_id = attempt.attempt().id;
    let sortition_session = FIXTURE_SORTITION_SESSION;
    let sortition_pulse_id = BeaconPulseId::new([0xB1; 32]);
    attempt
        .consume_sortition_pulse_batch(
            governance_attempt_id,
            request_ids,
            sortition_session,
            2,
            sortition_pulse_id,
            *sortition_pulse_id.as_bytes(),
            network_id,
            &enacted_fixture_governance(&requirements),
        )
        .expect("consume enacted-attempt fixture sortition pulse");
    for (index, requirement) in requirements.iter().copied().enumerate() {
        complete_body(
            &mut attempt,
            requirement,
            BodyElectionAttemptId::derive_v1(governance_attempt_id, requirement.body, 0),
            0xC0_u8
                .checked_add(u8::try_from(index).expect("body index fits u8"))
                .expect("result tag does not overflow"),
        );
    }
    let certified_at_height = attempt
        .body_bindings
        .values()
        .map(|binding| binding.result_height)
        .max()
        .expect("completed fixture has at least one body result");
    assert!(
        enact_at_height > certified_at_height,
        "fixture enactment must follow atomic certification"
    );
    attempt
        .construct_certificate(governance_attempt_id, certified_at_height, enact_at_height)
        .expect("construct enacted-attempt fixture certificate");
    attempt
        .validate_proposal_bindings_v1(proposal)
        .expect("certified-attempt fixture retains exact proposal bindings");
    attempt
}

/// Build one complete, proposal-bound enacted Parliament attempt for integration fixtures.
///
/// This helper is available only to Core's explicit test corridor. It deliberately exercises the
/// reducer instead of manufacturing detached certificate-only state.
#[cfg(any(test, feature = "iroha-core-tests"))]
#[doc(hidden)]
pub fn enacted_parliament_attempt_for_testing(
    proposal: &ProposalKind,
    candidates: Vec<AccountId>,
    network_id: &NetworkId,
    enact_at_height: u64,
) -> ParliamentAttemptStateV1 {
    let mut attempt = build_certified_parliament_attempt_for_testing(
        proposal,
        candidates,
        network_id,
        enact_at_height,
        complete_enacted_fixture_body,
    );
    let governance_attempt_id = attempt.attempt().id;
    attempt
        .mark_enacted(governance_attempt_id, enact_at_height)
        .expect("mark enacted-attempt fixture enacted");
    attempt
}

/// Build one complete, proposal-bound certified Parliament attempt for integration fixtures.
///
/// The returned attempt is waiting for automatic execution at `enact_at_height`.
#[cfg(any(test, feature = "iroha-core-tests"))]
#[doc(hidden)]
pub fn certified_parliament_attempt_for_testing(
    proposal: &ProposalKind,
    candidates: Vec<AccountId>,
    network_id: &NetworkId,
    enact_at_height: u64,
) -> ParliamentAttemptStateV1 {
    build_certified_parliament_attempt_for_testing(
        proposal,
        candidates,
        network_id,
        enact_at_height,
        complete_enacted_fixture_body,
    )
}

#[cfg(test)]
impl ParliamentAttemptStateV1 {
    /// Reach `NoRoster` for the whole generation of `election_attempt_id` through the only
    /// path an election has to it: consume the pulse of its exact frozen slot with every
    /// request awaiting that slot, open a one-block invitation window at the slot, and let
    /// it close without one accepted member.
    ///
    /// Stops early once the retry or redraw budget rejects the attempt.
    pub(crate) fn fail_sortition_generation_with_empty_roster_for_tests(
        &mut self,
        election_attempt_id: BodyElectionAttemptId,
        pulse_id: BeaconPulseId,
        network_id: &NetworkId,
        governance: &Governance,
        failure_height: u64,
    ) -> Result<(), ParliamentReducerErrorV1> {
        let governance_attempt_id = self.attempt.id;
        let request = self
            .elections
            .get(&election_attempt_id)
            .ok_or(ParliamentReducerErrorV1::UnknownEntity(
                ParliamentReducerEntityV1::BodyElection,
            ))?
            .attempt
            .request;
        let generation: Vec<_> = self
            .elections
            .iter()
            .filter(|(_, election)| {
                election.attempt.status == BodyElectionAttemptStatusV1::AwaitingPulse
                    && election.attempt.request.beacon_session_id == request.beacon_session_id
                    && election.attempt.request.pulse_height == request.pulse_height
            })
            .map(|(election_id, election)| (*election_id, election.attempt.request.id))
            .collect();
        let mut request_ids: Vec<_> = generation
            .iter()
            .map(|(_, request_id)| *request_id)
            .collect();
        request_ids.sort_unstable();
        self.consume_sortition_pulse_batch(
            governance_attempt_id,
            request_ids,
            request.beacon_session_id,
            request.pulse_height,
            pulse_id,
            *pulse_id.as_bytes(),
            network_id,
            governance,
        )?;
        for (election_id, _) in &generation {
            self.begin_invitation_acceptance(
                governance_attempt_id,
                *election_id,
                request.pulse_height,
                1,
            )?;
        }
        for (election_id, _) in generation {
            if self.attempt.status != GovernanceAttemptStatusV1::Active {
                break;
            }
            self.fail_body_election_no_roster(governance_attempt_id, election_id, failure_height)?;
        }
        Ok(())
    }
}

/// Install the genesis `NPoS` policy with `epoch_length_blocks` in a test World.
///
/// This is one of the two committed signals Parliament attempt creation requires.
#[cfg(test)]
pub(crate) fn seed_npos_policy_for_tests(
    state_transaction: &mut crate::state::StateTransaction<'_, '_>,
    epoch_length_blocks: u64,
) {
    let policy = iroha_data_model::parameter::system::SumeragiNposParameters {
        epoch_length_blocks: core::num::NonZeroU64::new(epoch_length_blocks)
            .expect("nonzero fixture epoch length"),
        epoch_seed: [0x31; 32],
        evidence_horizon_blocks: 1,
        slashing_delay_blocks: 1,
        ..iroha_data_model::parameter::system::SumeragiNposParameters::default()
    };
    state_transaction.world.parameters.get_mut().set_parameter(
        iroha_data_model::parameter::Parameter::Custom(policy.into_custom_parameter()),
    );
}

/// Install a committed consensus schedule whose window starts at the transaction's block
/// height and whose genesis epoch has `mode` and ends at height `epoch_length_blocks`.
///
/// This is the other committed signal Parliament attempt creation requires.
#[cfg(test)]
pub(crate) fn seed_consensus_schedule_for_tests(
    state_transaction: &mut crate::state::StateTransaction<'_, '_>,
    mode: iroha_data_model::parameter::system::SumeragiConsensusMode,
    epoch_length_blocks: u64,
) {
    use crate::sumeragi::schedule::{
        ChainParamsRecord, ConsensusSchedule, RetainedConsensusSchedule, ScheduledConfig,
        ScheduledSlot,
    };
    let signed = crate::sumeragi::epoch::tests::genesis_fixture(mode, epoch_length_blocks, false);
    let epoch = crate::sumeragi::epoch::authenticated_genesis(&signed)
        .map(|genesis| genesis.into_parts().0)
        .expect("authenticated fixture genesis epoch");
    let params = ChainParamsRecord::from_parameters(&Default::default());
    let first_height = state_transaction.block_height();
    let graph = ConsensusSchedule::from_owned_entries(
        (first_height..first_height + 3)
            .map(|height| {
                ScheduledSlot::Ready(ScheduledConfig {
                    height,
                    epoch: epoch.clone(),
                    params,
                })
            })
            .collect(),
    )
    .expect("fixture schedule window lies inside the genesis epoch");
    *state_transaction.world.consensus_schedule.get_mut() = RetainedConsensusSchedule::admit(
        &graph,
        &iroha_allocation::AllocationBudget::new(1024 * 1024),
    )
    .expect("admit fixture schedule");
}

/// Seed the complete committed `NPoS` pulse cadence Parliament attempt creation requires:
/// the genesis policy and a matching consensus schedule at the transaction's block height.
#[cfg(test)]
pub(crate) fn seed_npos_sortition_cadence_for_tests(
    state_transaction: &mut crate::state::StateTransaction<'_, '_>,
    epoch_length_blocks: u64,
) {
    seed_npos_policy_for_tests(state_transaction, epoch_length_blocks);
    seed_consensus_schedule_for_tests(
        state_transaction,
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
        epoch_length_blocks,
    );
}
