#[test]
fn narrow_policy_requires_the_anonymity_floor_of_fresh_confirmation_candidates() {
    for eligible_confirmation_candidates in 0..MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1 {
        let mut fixture = opened_policy_ballot(100, 100);
        let governance_attempt_id = fixture.state.attempt.id;
        let result_height = fixture
            .state
            .ballot(&fixture.ballot_id)
            .and_then(|ballot| ballot.opening_height)
            .expect("fixture opening height");

        assert_eq!(
            finalize_policy_with_confirmation_capacity(
                &mut fixture,
                51,
                49,
                0,
                eligible_confirmation_candidates,
            ),
            ParliamentAggregateOutcomeV1::NoResult
        );
        assert_eq!(
            fixture.state.attempt.status,
            GovernanceAttemptStatusV1::Rejected
        );
        assert_eq!(fixture.state.attempt.stage, GovernanceStageV1::PolicyJury);
        assert_eq!(
            fixture.state.required_bodies.last().map(|entry| entry.body),
            Some(ParliamentBody::PolicyJury),
            "an unfillable Confirmation requirement must never be committed"
        );
        assert!(
            !fixture
                .state
                .body_bindings
                .contains_key(&ParliamentBody::PolicyJury)
        );
        let body = fixture
            .state
            .body(&fixture.body_id)
            .expect("failed Policy Jury body");
        assert_eq!(body.instance.status, BodyInstanceStatusV1::NoResult);
        assert!(body.ballot_binding.is_none());
        assert!(body.result_root.is_none());
        let ballot = fixture
            .state
            .ballot(&fixture.ballot_id)
            .expect("failed Policy Jury ballot");
        assert_eq!(ballot.attempt.status, BallotAttemptStatusV1::NoResult);
        assert_eq!(
            ballot.failure_kind,
            Some(ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable)
        );
        assert_eq!(
            ballot.eligible_confirmation_candidates,
            Some(eligible_confirmation_candidates)
        );
        assert_eq!(ballot.failure_height, Some(result_height));
        assert_eq!(
            ballot.failure_root,
            Some(parliament_ballot_failure_root_v1(
                governance_attempt_id,
                fixture.ballot_id,
                ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable,
                result_height,
            ))
        );
        assert_eq!(ballot.outcome, Some(ParliamentAggregateOutcomeV1::Approved));
        fixture
            .state
            .validate()
            .expect("capacity no-result transcript must restore canonically");
        let mut nonterminal = fixture.state.clone();
        nonterminal.attempt.status = GovernanceAttemptStatusV1::Active;
        assert_eq!(
            nonterminal.validate(),
            Err(ParliamentReducerErrorV1::BallotFailureKindMismatch),
            "Confirmation capacity failure cannot leave an active retry path"
        );
        let mut retryable = fixture.state.clone();
        retryable
            .ballots
            .get_mut(&fixture.ballot_id)
            .expect("failed ballot")
            .attempt
            .status = BallotAttemptStatusV1::Superseded;
        assert_eq!(
            retryable.validate(),
            Err(ParliamentReducerErrorV1::BallotFailureKindMismatch),
            "Confirmation capacity failure cannot be superseded by a ballot retry"
        );
    }
}

#[test]
fn narrow_policy_at_randomness_redraw_ceiling_persists_terminal_no_result() {
    let mut fixture = opened_policy_ballot(100, 100);
    fixture.state.randomness_redraws_before_attempt = MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1;
    let governance_attempt_id = fixture.state.attempt.id;
    let result_height = fixture
        .state
        .ballot(&fixture.ballot_id)
        .and_then(|ballot| ballot.opening_height)
        .expect("fixture opening height");

    assert_eq!(
        finalize_policy_with_confirmation_capacity(
            &mut fixture,
            51,
            49,
            0,
            MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1,
        ),
        ParliamentAggregateOutcomeV1::NoResult
    );
    assert_eq!(
        fixture.state.attempt.status,
        GovernanceAttemptStatusV1::Rejected
    );
    assert_eq!(fixture.state.attempt.stage, GovernanceStageV1::PolicyJury);
    assert_eq!(
        fixture.state.required_bodies.last().map(|entry| entry.body),
        Some(ParliamentBody::PolicyJury),
        "the unaffordable Confirmation draw must never enter the pipeline"
    );
    assert!(
        !fixture
            .state
            .body_bindings
            .contains_key(&ParliamentBody::PolicyJury),
        "the narrow Policy result must remain uncommitted"
    );
    let body = fixture
        .state
        .body(&fixture.body_id)
        .expect("failed Policy Jury body");
    assert_eq!(body.instance.status, BodyInstanceStatusV1::NoResult);
    assert!(body.ballot_binding.is_none());
    assert!(body.result_root.is_none());
    let ballot = fixture
        .state
        .ballot(&fixture.ballot_id)
        .expect("failed Policy Jury ballot");
    assert_eq!(ballot.attempt.status, BallotAttemptStatusV1::NoResult);
    assert_eq!(
        ballot.failure_kind,
        Some(ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted)
    );
    assert_eq!(
        ballot.eligible_confirmation_candidates,
        Some(MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1)
    );
    assert_eq!(ballot.failure_height, Some(result_height));
    assert_eq!(
        ballot.failure_root,
        Some(parliament_ballot_failure_root_v1(
            governance_attempt_id,
            fixture.ballot_id,
            ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted,
            result_height,
        ))
    );
    assert_eq!(ballot.outcome, Some(ParliamentAggregateOutcomeV1::Approved));
    assert_eq!(
        ParliamentNoResultKindV1::from(
            ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted
        ),
        ParliamentNoResultKindV1::RandomnessRedrawBudgetExhausted
    );
    fixture
        .state
        .validate()
        .expect("redraw-exhausted opening must restore canonically");

    let bytes = norito::to_bytes(&fixture.state).expect("encode terminal opening");
    let decoded = norito::decode_from_bytes::<ParliamentAttemptStateV1>(&bytes)
        .expect("decode terminal opening");
    assert_eq!(decoded, fixture.state);
    decoded
        .validate()
        .expect("Norito-decoded redraw exhaustion must restore canonically");
    assert_eq!(
        norito::to_bytes(&decoded).expect("re-encode terminal opening"),
        bytes
    );

    let mut below_ceiling = decoded.clone();
    below_ceiling.randomness_redraws_before_attempt -= 1;
    assert_eq!(
        below_ceiling.validate(),
        Err(ParliamentReducerErrorV1::BallotFailureKindMismatch),
        "the redraw-exhaustion classification requires the exact shared ceiling"
    );
    let mut disguised_as_capacity = decoded;
    let disguised_ballot = disguised_as_capacity
        .ballots
        .get_mut(&fixture.ballot_id)
        .expect("terminal ballot");
    disguised_ballot.failure_kind =
        Some(ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable);
    disguised_ballot.failure_root = Some(parliament_ballot_failure_root_v1(
        governance_attempt_id,
        fixture.ballot_id,
        ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable,
        result_height,
    ));
    assert_eq!(
        disguised_as_capacity.validate(),
        Err(ParliamentReducerErrorV1::BallotFailureKindMismatch),
        "a floor-sized eligible set cannot be reclassified as capacity unavailable"
    );
}

#[test]
fn sealed_and_released_cross_store_bindings_fail_closed_on_substitution() {
    let mut fixture = opened_policy_ballot(3, 3);
    let governance_attempt_id = fixture.state.attempt.id;
    let expected_sealed = TimedOvnParliamentReducerBindingV1 {
        proposal_content_id: *fixture.state.attempt.proposal_content_id.as_bytes(),
        governance_attempt_id: *governance_attempt_id.as_bytes(),
        body_instance_id: *fixture.body_id.as_bytes(),
        ballot_attempt_id: *fixture.ballot_id.as_bytes(),
        tle_key_session_id: Some(tle_key_session(23)),
        registration_opened_at_finalized_height: None,
        release_height: Some(40),
        registration_root: Some(root(19)),
        registered_voters: Some(3),
        dropout_root: Some(root(21)),
        survivor_root: Some(root(29)),
        survivors: Some(3),
        no_recovery_root: Some(root(22)),
        corpus_root: Some(root(20)),
        accepted_ballots: Some(3),
        timed_commitment_root: Some(root(25)),
        opening_root: None,
        tally_counts: None,
    };
    assert_eq!(
        fixture.state.timed_ovn_reducer_binding(&fixture.ballot_id),
        Some(expected_sealed)
    );
    assert!(
        fixture
            .state
            .timed_ovn_reducer_binding_matches(&fixture.ballot_id, &expected_sealed)
    );

    let mut substituted_sealed = expected_sealed;
    substituted_sealed.corpus_root = Some(root(99));
    assert!(
        !fixture
            .state
            .timed_ovn_reducer_binding_matches(&fixture.ballot_id, &substituted_sealed),
        "a separately self-consistent sealed lifecycle cannot substitute its corpus root"
    );
    substituted_sealed = expected_sealed;
    substituted_sealed.timed_commitment_root = Some(root(100));
    assert!(
        !fixture
            .state
            .timed_ovn_reducer_binding_matches(&fixture.ballot_id, &substituted_sealed),
        "a separately self-consistent sealed lifecycle cannot substitute its transcript root"
    );

    assert_eq!(
        finalize_policy(&mut fixture, 2, 1, 0),
        ParliamentAggregateOutcomeV1::Approved
    );
    let expected_released = TimedOvnParliamentReducerBindingV1 {
        opening_root: Some(root(27)),
        tally_counts: Some([2, 1, 0]),
        ..expected_sealed
    };
    assert_eq!(
        fixture.state.timed_ovn_reducer_binding(&fixture.ballot_id),
        Some(expected_released)
    );
    assert!(
        fixture
            .state
            .timed_ovn_reducer_binding_matches(&fixture.ballot_id, &expected_released)
    );

    let mut substituted_released = expected_released;
    substituted_released.opening_root = Some(root(101));
    assert!(
        !fixture
            .state
            .timed_ovn_reducer_binding_matches(&fixture.ballot_id, &substituted_released),
        "a separately self-consistent released lifecycle cannot substitute its opening root"
    );
    substituted_released = expected_released;
    substituted_released.tally_counts = Some([1, 2, 0]);
    assert!(
        !fixture
            .state
            .timed_ovn_reducer_binding_matches(&fixture.ballot_id, &substituted_released),
        "a separately self-consistent released lifecycle cannot substitute its tally"
    );
}

#[test]
fn hidden_ballot_corpus_bound_covers_every_original_seat() {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(4);
    advance_to_vote(&mut state, body_id);
    let governance_attempt_id = state.attempt.id;
    let ballot_id = BallotAttemptId::derive_v1(body_id, 0);
    let release_beacon_session_id = beacon_session(24);
    let tle_key_session_id = tle_key_session(23);
    let release_height = 42;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_id,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    let four_seat_policy = ParliamentTimedOvn {
        registration_phase_blocks: 5,
        survivor_freeze_phase_blocks: 4,
        max_corpus_entries: 4,
        ..timed_ovn_policy()
    };
    let subfloor_policy = ParliamentTimedOvn {
        max_corpus_entries: 2,
        ..four_seat_policy
    };
    assert_eq!(
        state.register_ballot_attempt(
            governance_attempt_id,
            body_id,
            ballot_id,
            0,
            tle_session_id,
            tle_key_session_id,
            release_beacon_session_id,
            27,
            subfloor_policy,
            release_height,
        ),
        Err(ParliamentReducerErrorV1::InvalidBallotSchedule)
    );

    state
        .register_ballot_attempt(
            governance_attempt_id,
            body_id,
            ballot_id,
            0,
            tle_session_id,
            tle_key_session_id,
            release_beacon_session_id,
            27,
            four_seat_policy,
            release_height,
        )
        .expect("register ballot with capacity for every original seat");
    let mut registration_window_too_short = state.clone();
    registration_window_too_short
        .ballots
        .get_mut(&ballot_id)
        .expect("registered ballot")
        .registration_phase_blocks = 4;
    assert_eq!(
        registration_window_too_short.validate(),
        Err(ParliamentReducerErrorV1::InvalidBallotSchedule),
        "snapshot validation reserves one admission-slack block plus every registration slot"
    );
    let mut survivor_window_too_short = state.clone();
    survivor_window_too_short
        .ballots
        .get_mut(&ballot_id)
        .expect("registered ballot")
        .survivor_freeze_phase_blocks = 3;
    assert_eq!(
        survivor_window_too_short.validate(),
        Err(ParliamentReducerErrorV1::InvalidBallotSchedule),
        "snapshot validation reserves one authenticated dropout slot per corpus entry"
    );
    state
        .ballots
        .get_mut(&ballot_id)
        .expect("registered ballot")
        .max_corpus_entries = 3;
    assert_eq!(
        state.validate(),
        Err(ParliamentReducerErrorV1::InvalidBallotCount),
        "snapshot validation must reject an undersized persisted corpus bound"
    );
}

#[test]
fn risk_only_escalates_and_policy_request_locks_it() {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    assert_eq!(
        state.escalate_risk(id, RiskTierV1::Routine),
        Err(ParliamentReducerErrorV1::RiskDowngrade)
    );
    assert_eq!(
        state.escalate_risk(id, RiskTierV1::Standard),
        Err(ParliamentReducerErrorV1::RiskEscalationReplay)
    );
    state
        .escalate_risk(id, RiskTierV1::Constitutional)
        .expect("upward escalation succeeds");
    let (request, candidate_snapshot) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        12,
        3,
        3,
        10,
        20,
        beacon_session(13),
        None,
    );
    state
        .register_sortition_request(id, 0, request, candidate_snapshot)
        .expect("Policy Jury request locks risk");
    assert_eq!(
        state.escalate_risk(id, RiskTierV1::Emergency),
        Err(ParliamentReducerErrorV1::RiskTierLocked)
    );
}

#[test]
fn attempt_rejects_an_inert_compare_and_set_subject() {
    let required = vec![RequiredParliamentBodyV1 {
        body: ParliamentBody::PolicyJury,
        decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
    }];
    assert_eq!(
        ParliamentAttemptStateV1::try_new(
            attempt(),
            PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
            10,
            FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
            root(3),
            GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
                subject_id: [0; 32],
            }),
            required.clone(),
        ),
        Err(ParliamentReducerErrorV1::ImmutableBindingMismatch)
    );
    assert_eq!(
        ParliamentAttemptStateV1::try_new(
            attempt(),
            PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
            10,
            FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
            root(3),
            GovernanceExpectedHeadV1::Present(
                iroha_data_model::governance::types::GovernanceExpectedHeadPresentV1 {
                    subject_id: root(4),
                    version: 1,
                    head_root: [0; 32],
                },
            ),
            required.clone(),
        ),
        Err(ParliamentReducerErrorV1::ImmutableBindingMismatch)
    );
    assert_eq!(
        ParliamentAttemptStateV1::try_new(
            attempt(),
            PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
            10,
            FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
            root(3),
            GovernanceExpectedHeadV1::Present(
                iroha_data_model::governance::types::GovernanceExpectedHeadPresentV1 {
                    subject_id: root(4),
                    version: 0,
                    head_root: root(5),
                },
            ),
            required,
        ),
        Err(ParliamentReducerErrorV1::ImmutableBindingMismatch)
    );
}

#[test]
fn attempt_rejects_unsupported_policy_and_noncanonical_decision_modes() {
    let policy_only = vec![RequiredParliamentBodyV1 {
        body: ParliamentBody::PolicyJury,
        decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
    }];
    assert_eq!(
        ParliamentAttemptStateV1::try_new(
            attempt(),
            PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 + 1,
            10,
            FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
            root(3),
            GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
                subject_id: root(4),
            }),
            policy_only,
        ),
        Err(ParliamentReducerErrorV1::UnsupportedPolicyVersion)
    );
    let mut restored = policy_only_state();
    restored.policy_version = PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 + 1;
    assert_eq!(
        restored.validate(),
        Err(ParliamentReducerErrorV1::UnsupportedPolicyVersion)
    );

    let hidden_public_body = vec![
        RequiredParliamentBodyV1 {
            body: ParliamentBody::RulesCommittee,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        },
        RequiredParliamentBodyV1 {
            body: ParliamentBody::PolicyJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        },
    ];
    assert_eq!(
        ParliamentAttemptStateV1::try_new(
            attempt(),
            PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
            10,
            FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
            root(3),
            GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
                subject_id: root(4),
            }),
            hidden_public_body,
        ),
        Err(ParliamentReducerErrorV1::InvalidRequiredBodyPipeline)
    );
}

#[test]
fn sortition_request_requires_the_exact_aligned_frozen_slot_without_overflow() {
    assert_eq!(
        ParliamentAttemptStateV1::try_new(
            attempt(),
            PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
            0,
            FIXTURE_SORTITION_PULSE_EPOCH_LENGTH_BLOCKS,
            root(3),
            GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
                subject_id: root(4),
            }),
            vec![RequiredParliamentBodyV1 {
                body: ParliamentBody::PolicyJury,
                decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
            }],
        ),
        Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule)
    );

    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter policy stage");
    // The fixture freezes a ten-block delay and a three-block native epoch. Too-early and
    // misaligned heights, a skipped boundary, the retired request-height-plus-delay rule
    // where it names no native height, and overflowing heights are all refused.
    for (request_height, pulse_height) in [
        (10, 19),
        (10, 21),
        (10, 22),
        (10, 23),
        (11, 21),
        (u64::MAX - 1, u64::MAX),
        (u64::MAX - 10, u64::MAX),
    ] {
        let (request, candidates) = sortition_request(
            id,
            0,
            ParliamentBody::PolicyJury,
            115,
            3,
            3,
            request_height,
            pulse_height,
            beacon_session(116),
            None,
        );
        assert_eq!(
            state.register_sortition_request(id, 0, request, candidates),
            Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule)
        );
    }

    let (request, candidates) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        115,
        3,
        3,
        10,
        20,
        beacon_session(116),
        None,
    );
    state
        .register_sortition_request(id, 0, request, candidates)
        .expect("the first native pulse height after the frozen delay is accepted");
    state.validate().expect("exact frozen schedule persists");
}

#[test]
fn hidden_ballot_sortition_requires_the_anonymity_floor() {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter Policy Jury stage");
    let (request, one_candidate) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        115,
        1,
        3,
        10,
        20,
        beacon_session(116),
        None,
    );
    assert_eq!(
        state.register_sortition_request(id, 0, request, one_candidate),
        Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot)
    );
    assert!(state.elections.is_empty());
    assert!(state.candidate_snapshots.is_empty());

    let (request, two_candidates) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        117,
        2,
        1,
        10,
        20,
        beacon_session(116),
        None,
    );
    assert_eq!(
        state.register_sortition_request(id, 0, request, two_candidates),
        Err(ParliamentReducerErrorV1::InvalidAssignmentPlan)
    );

    let (request, two_candidates) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        117,
        2,
        3,
        10,
        20,
        beacon_session(116),
        None,
    );
    assert_eq!(
        state.register_sortition_request(id, 0, request, two_candidates),
        Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot)
    );

    let (request, three_candidates) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        118,
        3,
        3,
        10,
        20,
        beacon_session(116),
        None,
    );
    state
        .register_sortition_request(id, 0, request, three_candidates)
        .expect("the anonymity-floor candidate set can enter hidden sortition");
    state.validate().expect("minimum hidden capacity persists");
}

#[test]
fn hidden_sortition_capacity_failure_is_typed_bounded_and_consumes_no_pulse() {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter Policy Jury stage");

    let mut previous_id = None;
    for sequence in 0..=MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
        let snapshot = if sequence % 2 == 0 {
            Vec::new()
        } else {
            candidates(115, 1)
        };
        let request_height = 10_u64 + u64::from(sequence);
        let request = sortition_request_intent(
            id,
            sequence,
            ParliamentBody::PolicyJury,
            snapshot.clone(),
            3,
            request_height,
            generation_slot(&state, request_height, beacon_session(116)),
            beacon_session(116),
        );
        let election_id = request.body_election_attempt_id;
        state
            .record_hidden_sortition_capacity_failure_batch(
                id,
                vec![ParliamentSortitionRequestRegistrationV1 { sequence, request }],
                snapshot,
            )
            .expect("record objective hidden-electorate capacity failure");

        let failure = state
            .sortition_capacity_failure(&election_id)
            .expect("typed pre-request capacity evidence");
        assert_eq!(failure.sequence(), sequence);
        assert_eq!(failure.failure_height(), request_height);
        assert_eq!(
            failure.candidate_count(),
            usize::try_from(sequence % 2).expect("fixture candidate count fits usize")
        );
        assert_eq!(failure.status(), BodyElectionAttemptStatusV1::NoRoster);
        assert!(state.election(&election_id).is_none());
        assert!(state.used_pulse_ids.is_empty());
        assert!(state.used_pulse_slots.is_empty());
        if let Some(previous_id) = previous_id {
            assert_eq!(
                state
                    .sortition_capacity_failure(&previous_id)
                    .expect("retained prior failure")
                    .status(),
                BodyElectionAttemptStatusV1::Superseded
            );
        }
        if sequence == MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
            assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Rejected);
        } else {
            assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Active);
        }
        state
            .validate()
            .expect("typed capacity evidence survives canonical restore validation");
        previous_id = Some(election_id);
    }
}

#[test]
fn hidden_sortition_capacity_restore_rejects_mutated_evidence() {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter Policy Jury stage");
    let snapshot = Vec::new();
    let request = sortition_request_intent(
        id,
        0,
        ParliamentBody::PolicyJury,
        snapshot.clone(),
        3,
        10,
        20,
        beacon_session(116),
    );
    let election_id = request.body_election_attempt_id;
    state
        .record_hidden_sortition_capacity_failure_batch(
            id,
            vec![ParliamentSortitionRequestRegistrationV1 {
                sequence: 0,
                request,
            }],
            snapshot,
        )
        .expect("record zero-candidate evidence");
    state.validate().expect("baseline capacity evidence");

    let mut mutated = state;
    mutated
        .sortition_capacity_failures
        .get_mut(&election_id)
        .expect("capacity evidence")
        .candidate_root = root(0xF1);
    assert_eq!(
        mutated.validate(),
        Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot)
    );
}

/// A Policy Jury election registered at height 10 and awaiting the pulse of slot 20.
fn policy_election_awaiting_slot_20(
    beacon_session_id: BeaconSessionId,
) -> (
    ParliamentAttemptStateV1,
    BodyElectionAttemptId,
    SortitionRequestId,
) {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter Policy Jury stage");
    let (request, snapshot) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        0x90,
        3,
        3,
        10,
        20,
        beacon_session_id,
        None,
    );
    let election_id = request.body_election_attempt_id;
    let request_id = request.id;
    state
        .register_sortition_request(id, 0, request, snapshot)
        .expect("register the pending draw");
    (state, election_id, request_id)
}

#[test]
fn election_awaiting_its_pulse_is_never_failed_retried_redrawn_or_superseded() {
    let session = beacon_session(0x91);
    let (state, election_id, request_id) = policy_election_awaiting_slot_20(session);
    let id = state.attempt.id;
    let governance = governance_for_pending_draws(&state);
    let lifecycle_rejection = Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
        ParliamentReducerEntityV1::BodyElection,
    ));
    let bodies = [ParliamentBody::PolicyJury];

    // Every transition that could once move a pulse wait is rejected with a typed error, at
    // the slot and arbitrarily far past it, and leaves the reducer untouched.
    for height in [20_u64, 21, 5_000, 1_000_000_000] {
        let mut waiting = state.clone();
        assert_eq!(
            waiting.fail_body_election_no_roster(id, election_id, height),
            lifecycle_rejection,
            "no failure at height {height}"
        );
        assert_eq!(
            waiting.begin_invitation_acceptance(id, election_id, height, 1),
            lifecycle_rejection,
            "no invitations without the drawn pulse at height {height}"
        );
        assert_eq!(
            waiting.seal_body_roster(id, election_id, height).map(drop),
            lifecycle_rejection,
            "no roster without the drawn pulse at height {height}"
        );
        assert!(
            waiting
                .next_sortition_retry_v1(height, session, &governance, candidates(0xA0, 4))
                .is_none(),
            "no retry generation is derived at height {height}"
        );
        let fresh = candidates(0xA0, 4);
        for sequence in [0, 1] {
            // A retry (next sequence) and a redraw (same sequence) on a later slot.
            assert_eq!(
                waiting.register_sortition_request_batch(
                    id,
                    sortition_generation(&state, &bodies, sequence, &fresh, height, session),
                    fresh.clone(),
                ),
                lifecycle_rejection,
                "no generation {sequence} supersedes the wait at height {height}"
            );
            let (single, single_snapshot) = sortition_request(
                id,
                sequence,
                ParliamentBody::PolicyJury,
                0xA0,
                4,
                3,
                height,
                generation_slot(&state, height, session),
                session,
                None,
            );
            assert!(
                matches!(
                    waiting.register_sortition_request(id, sequence, single, single_snapshot),
                    Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                        ParliamentReducerEntityV1::BodyElection
                    ) | ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(_))
                ),
                "no single request {sequence} supersedes the wait at height {height}"
            );
            let small = candidates(0xA0, 2);
            assert_eq!(
                waiting.record_hidden_sortition_capacity_failure_batch(
                    id,
                    sortition_generation(&state, &bodies, sequence, &small, height, session),
                    small,
                ),
                lifecycle_rejection,
                "no capacity record {sequence} supersedes the wait at height {height}"
            );
        }
        assert_eq!(
            waiting, state,
            "rejections at height {height} must not mutate state"
        );
    }

    // A substituted pulse never draws: another height or another beacon session names no
    // awaited request, whichever pulse identifier it carries.
    for (substituted_session, substituted_height) in [
        (session, 21),
        (session, 23),
        (session, 19),
        (beacon_session(0x92), 20),
    ] {
        let mut waiting = state.clone();
        assert_eq!(
            consume_sortition(
                &mut waiting,
                id,
                vec![request_id],
                substituted_session,
                substituted_height,
                pulse_id(0x93),
            ),
            Err(ParliamentReducerErrorV1::PulseBindingMismatch)
        );
        assert_eq!(waiting, state);
    }

    // The pulse of exactly the frozen slot still draws, and only then can the election end.
    let mut drawn = state.clone();
    consume_sortition(
        &mut drawn,
        id,
        vec![request_id],
        session,
        20,
        pulse_id(0x93),
    )
    .expect("the exact slot pulse draws");
    let election = drawn.election(&election_id).expect("drawn election");
    assert_eq!(
        election.attempt.status,
        BodyElectionAttemptStatusV1::Drawing
    );
    assert_eq!(election.pulse_id, Some(pulse_id(0x93)));
    assert!(!election.primary_assignments.is_empty());
    drawn.validate().expect("the drawn election persists");
}

#[test]
fn pulse_wait_restores_unchanged_and_the_retired_missing_pulse_terminal_is_malformed() {
    let session = beacon_session(0x94);
    let (state, election_id, _) = policy_election_awaiting_slot_20(session);
    state.validate().expect("a pulse wait is canonical state");

    // Both codecs return the identical wait, still on exactly its frozen slot, and restore
    // accepts it at the slot and far above it.
    let framed = norito::to_bytes(&state).expect("encode the pulse wait");
    let decoded = norito::decode_from_bytes::<ParliamentAttemptStateV1>(&framed)
        .expect("decode the pulse wait");
    let json = norito::json::to_json(&state).expect("serialize the pulse wait");
    let parsed: ParliamentAttemptStateV1 =
        norito::json::from_str(&json).expect("parse the pulse wait");
    for restored in [&decoded, &parsed] {
        assert_eq!(restored, &state);
        restored.validate().expect("the restored wait is canonical");
        for restored_height in [20, 21, 4_000_000] {
            restored
                .validate_restored_height_v1(restored_height)
                .expect("an awaited slot far below the restored height restores cleanly");
        }
        let election = restored.election(&election_id).expect("restored election");
        assert_eq!(
            election.attempt.status,
            BodyElectionAttemptStatusV1::AwaitingPulse
        );
        assert_eq!(election.attempt.request.pulse_height, 20);
        assert_eq!(election.attempt.request.beacon_session_id, session);
        assert_eq!(
            restored.required_beacon_pulse_slots_v1(),
            BTreeSet::from([(session, 20)])
        );
    }

    // The retired shape: a terminal election that never consumed a pulse. No remaining
    // failure kind describes it, with or without a recorded failure height.
    for status in [
        BodyElectionAttemptStatusV1::NoRoster,
        BodyElectionAttemptStatusV1::Superseded,
    ] {
        for failure_kind in [
            None,
            Some(ParliamentElectionFailureKindV1::EmptyAcceptedRoster),
            Some(ParliamentElectionFailureKindV1::InsufficientHiddenBallotRoster),
        ] {
            for failure_height in [None, Some(21)] {
                let mut retired = state.clone();
                let election = retired
                    .elections
                    .get_mut(&election_id)
                    .expect("pending election");
                election.attempt.status = status;
                election.failure_kind = failure_kind;
                election.failure_height = failure_height;
                assert_eq!(
                    retired.validate(),
                    Err(ParliamentReducerErrorV1::InvalidAssignmentPlan),
                    "{status:?} without a consumed pulse ({failure_kind:?}, \
                     {failure_height:?}) must be malformed"
                );
            }
        }
    }
    // A failure record on a live wait is malformed as well.
    let mut marked = state.clone();
    let election = marked
        .elections
        .get_mut(&election_id)
        .expect("pending election");
    election.failure_kind = Some(ParliamentElectionFailureKindV1::EmptyAcceptedRoster);
    election.failure_height = Some(21);
    assert_eq!(
        marked.validate(),
        Err(ParliamentReducerErrorV1::ImmutableBindingMismatch)
    );
}

#[test]
fn live_sortition_candidates_retain_bonds_until_terminal_or_superseded() {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter Policy Jury stage");
    let (request, first_candidates) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        120,
        3,
        3,
        10,
        20,
        beacon_session(121),
        None,
    );
    let first_election_id = request.body_election_attempt_id;
    state
        .register_sortition_request(id, 0, request, first_candidates.clone())
        .expect("register live candidate snapshot");
    assert!(
        first_candidates
            .iter()
            .all(|candidate| state.retains_citizenship_bond(candidate))
    );
    fail_generation_with_empty_roster(&mut state, first_election_id, pulse_id(122), 21);
    assert!(
        first_candidates
            .iter()
            .all(|candidate| !state.retains_citizenship_bond(candidate)),
        "terminal NoRoster must release every unseated candidate bond"
    );

    let (retry, retry_candidates) = sortition_request(
        id,
        1,
        ParliamentBody::PolicyJury,
        130,
        3,
        3,
        21,
        32,
        beacon_session(121),
        None,
    );
    state
        .register_sortition_request(id, 1, retry, retry_candidates.clone())
        .expect("register fresh retry snapshot");
    assert_eq!(
        state
            .election(&first_election_id)
            .expect("superseded first election")
            .attempt()
            .status,
        BodyElectionAttemptStatusV1::Superseded
    );
    assert!(
        first_candidates
            .iter()
            .all(|candidate| !state.retains_citizenship_bond(candidate)),
        "superseded snapshots must stay released"
    );
    assert!(
        retry_candidates
            .iter()
            .all(|candidate| state.retains_citizenship_bond(candidate)),
        "the live retry snapshot must retain every candidate bond"
    );
}

#[test]
fn terminal_attempt_drops_transient_candidates_but_retains_sealed_member_references() {
    let mut transient = policy_only_state();
    let transient_id = transient.attempt.id;
    transient
        .complete_qualification(transient_id)
        .expect("enter Policy Jury stage");
    let (request, candidates) = sortition_request(
        transient_id,
        0,
        ParliamentBody::PolicyJury,
        124,
        3,
        3,
        10,
        20,
        beacon_session(125),
        None,
    );
    transient
        .register_sortition_request(transient_id, 0, request, candidates.clone())
        .expect("register a transient candidate snapshot");
    assert!(
        candidates
            .iter()
            .all(|candidate| transient.references_parliament_member(candidate))
    );
    transient.attempt.status = GovernanceAttemptStatusV1::Rejected;
    assert!(
        candidates
            .iter()
            .all(|candidate| !transient.references_parliament_member(candidate)),
        "terminal outer attempts must release every unseated candidate reference"
    );

    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    let sealed_members = state
        .body(&body_id)
        .expect("sealed body fixture")
        .assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    state.attempt.status = GovernanceAttemptStatusV1::Rejected;
    assert!(
        sealed_members
            .iter()
            .all(|member| state.references_parliament_member(member)),
        "sealed assignments remain immutable historical references"
    );
    assert!(
        sealed_members
            .iter()
            .all(|member| !state.retains_citizenship_bond(member)),
        "terminal historical references do not retain citizenship bonds"
    );
}

#[test]
fn retryable_singleton_capacity_failure_retains_only_its_live_candidate_bond() {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter Policy Jury stage");

    let mut previous_candidate = None;
    for sequence in 0..=MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
        let candidate_tag = 140_u8
            .checked_add(u8::try_from(sequence).expect("retry sequence fits u8"))
            .expect("fixture candidate tag does not overflow");
        let snapshot = candidates(candidate_tag, 1);
        let candidate = snapshot[0].clone();
        let request_height = 30_u64 + u64::from(sequence);
        let request = sortition_request_intent(
            id,
            sequence,
            ParliamentBody::PolicyJury,
            snapshot.clone(),
            3,
            request_height,
            generation_slot(&state, request_height, beacon_session(141)),
            beacon_session(141),
        );
        state
            .record_hidden_sortition_capacity_failure_batch(
                id,
                vec![ParliamentSortitionRequestRegistrationV1 { sequence, request }],
                snapshot,
            )
            .expect("record singleton capacity failure");

        if let Some(previous_candidate) = previous_candidate {
            assert!(
                !state.retains_citizenship_bond(&previous_candidate),
                "superseded capacity evidence must release its historical candidate"
            );
        }
        if sequence < MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
            assert!(
                state.retains_citizenship_bond(&candidate),
                "the active retryable singleton must retain its candidate bond"
            );
        } else {
            assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Rejected);
            assert!(
                !state.retains_citizenship_bond(&candidate),
                "final exhaustion must release the terminal singleton candidate"
            );
        }
        state.validate().expect("capacity bond-retention fixture");
        previous_candidate = Some(candidate);
    }
}

#[test]
fn subfloor_hidden_roster_is_an_objective_no_roster_retry() {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter Policy Jury stage");
    let (request, candidates) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        117,
        3,
        3,
        10,
        20,
        beacon_session(116),
        None,
    );
    let election_id = request.body_election_attempt_id;
    let request_id = request.id;
    state
        .register_sortition_request(id, 0, request, candidates)
        .expect("register anonymity-floor hidden draw");
    consume_sortition(
        &mut state,
        id,
        vec![request_id],
        beacon_session(116),
        20,
        pulse_id(118),
    )
    .expect("draw three hidden seats");
    state
        .begin_invitation_acceptance(id, election_id, 20, 1)
        .expect("open one-block invitation window");
    let members = state
        .election(&election_id)
        .expect("drawn election")
        .primary_assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    state
        .record_invitation_response(id, election_id, &members[0], true, 20)
        .expect("accept one hidden seat");
    state
        .record_invitation_response(id, election_id, &members[1], false, 20)
        .expect("decline one hidden seat");
    state
        .record_invitation_response(id, election_id, &members[2], true, 20)
        .expect("accept a second hidden seat");
    assert_eq!(
        state.seal_body_roster(id, election_id, 21),
        Err(ParliamentReducerErrorV1::InvalidRoster)
    );
    state
        .fail_body_election_no_roster(id, election_id, 21)
        .expect("two hidden seats cannot form an exact-tally body");
    let election = state.election(&election_id).expect("failed election");
    assert_eq!(
        election.failure_kind,
        Some(ParliamentElectionFailureKindV1::InsufficientHiddenBallotRoster)
    );
    assert_eq!(election.failure_height, Some(21));
    assert_eq!(
        election.attempt.status,
        BodyElectionAttemptStatusV1::NoRoster
    );
    state
        .validate()
        .expect("insufficient hidden roster remains a canonical retry point");
}

#[test]
fn simultaneous_sortition_consumes_one_exact_canonical_batch() {
    let mut state = state(vec![
        RequiredParliamentBodyV1 {
            body: ParliamentBody::InterestPanel,
            decision_mode: ParliamentDecisionModeV1::PublicFinding,
        },
        RequiredParliamentBodyV1 {
            body: ParliamentBody::PolicyJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        },
    ]);
    let id = state.attempt.id;
    state.complete_qualification(id).expect("enter interest");
    let mut request_ids = Vec::new();
    for body in [ParliamentBody::InterestPanel, ParliamentBody::PolicyJury] {
        let (request, candidate_snapshot) =
            sortition_request(id, 0, body, 12, 3, 3, 10, 20, beacon_session(30), None);
        request_ids.push(request.id);
        state
            .register_sortition_request(id, 0, request, candidate_snapshot)
            .expect("register simultaneous request");
        if body == ParliamentBody::InterestPanel {
            assert_eq!(
                consume_sortition(
                    &mut state,
                    id,
                    request_ids.clone(),
                    beacon_session(30),
                    20,
                    pulse_id(31),
                ),
                Err(ParliamentReducerErrorV1::InvalidAssignmentPlan),
                "the first draw must cover every initial body in one future-pulse batch"
            );
        }
    }
    request_ids.sort_unstable();
    assert_eq!(
        consume_sortition(
            &mut state,
            id,
            vec![request_ids[0]],
            beacon_session(30),
            20,
            pulse_id(31),
        ),
        Err(ParliamentReducerErrorV1::PulseBindingMismatch)
    );
    consume_sortition(
        &mut state,
        id,
        request_ids,
        beacon_session(30),
        20,
        pulse_id(31),
    )
    .expect("consume complete canonical batch");
    assert!(
        state
            .elections
            .values()
            .all(|election| { election.attempt.status == BodyElectionAttemptStatusV1::Drawing })
    );
    assert!(state.validate().is_ok());
}

#[test]
fn sortition_registration_batch_is_atomic_shared_and_retries_as_one_generation() {
    let required = vec![
        RequiredParliamentBodyV1 {
            body: ParliamentBody::RulesCommittee,
            decision_mode: ParliamentDecisionModeV1::PublicFinding,
        },
        RequiredParliamentBodyV1 {
            body: ParliamentBody::PolicyJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        },
    ];
    let mut base = state(required);
    let id = base.attempt.id;
    base.complete_qualification(id).expect("enter rules stage");

    let initial_candidates = candidates(120, 3);
    let initial = [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury]
        .into_iter()
        .map(|body| {
            let election_id = BodyElectionAttemptId::derive_v1(id, body, 0);
            let request = SortitionRequestV1::try_new_canonical(
                id,
                election_id,
                body,
                parliament_candidate_root_v1(id, body, &initial_candidates),
                3,
                3,
                10,
                20,
                beacon_session(121),
                None,
            )
            .expect("canonical initial batch request");
            ParliamentSortitionRequestRegistrationV1 {
                sequence: 0,
                request,
            }
        })
        .collect::<Vec<_>>();

    let mut partial = base.clone();
    assert_eq!(
        partial.register_sortition_request_batch(id, vec![initial[0]], initial_candidates.clone(),),
        Err(ParliamentReducerErrorV1::InvalidAssignmentPlan)
    );
    assert_eq!(
        partial, base,
        "a rejected partial batch must not mutate state"
    );

    let mut wrong_order = base.clone();
    assert_eq!(
        wrong_order.register_sortition_request_batch(
            id,
            vec![initial[1], initial[0]],
            initial_candidates.clone(),
        ),
        Err(ParliamentReducerErrorV1::InvalidAssignmentPlan)
    );
    assert_eq!(wrong_order, base, "a rejected ordering must be atomic");

    base.register_sortition_request_batch(id, initial, initial_candidates)
        .expect("register exact full initial batch");
    assert_eq!(base.elections.len(), 2);
    assert_eq!(base.candidate_snapshots.len(), 1);
    base.validate()
        .expect("shared initial snapshot persists once");

    let rules_id = *base
        .active_elections
        .get(&ParliamentBody::RulesCommittee)
        .expect("active rules election");
    fail_generation_with_empty_roster(&mut base, rules_id, pulse_id(122), 21);
    assert!(base.active_elections.values().all(|election_id| {
        base.elections.get(election_id).is_some_and(|election| {
            election.attempt.status == BodyElectionAttemptStatusV1::NoRoster
        })
    }));

    let retry_candidates = candidates(124, 3);
    let retry = [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury]
        .into_iter()
        .map(|body| {
            let election_id = BodyElectionAttemptId::derive_v1(id, body, 1);
            let request = SortitionRequestV1::try_new_canonical(
                id,
                election_id,
                body,
                parliament_candidate_root_v1(id, body, &retry_candidates),
                3,
                3,
                21,
                32,
                beacon_session(121),
                None,
            )
            .expect("canonical retry batch request");
            ParliamentSortitionRequestRegistrationV1 {
                sequence: 1,
                request,
            }
        })
        .collect();
    base.register_sortition_request_batch(id, retry, retry_candidates)
        .expect("register one complete fresh initial-draw generation");
    assert_eq!(base.elections.len(), 4);
    assert_eq!(base.candidate_snapshots.len(), 2);
    base.validate()
        .expect("fresh retry generation is persistable");
}

#[test]
fn final_sortition_retry_failure_rejects_and_bounds_persisted_history() {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter policy stage");
    let candidate_snapshot = candidates(130, 3);
    let session = beacon_session(131);

    // Each retry is requested in the block that recorded its predecessor's empty roster.
    let mut request_height = 10;
    for sequence in 0..=MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
        let pulse_height = generation_slot(&state, request_height, session);
        let election_id =
            BodyElectionAttemptId::derive_v1(id, ParliamentBody::PolicyJury, sequence);
        let request = SortitionRequestV1::try_new_canonical(
            id,
            election_id,
            ParliamentBody::PolicyJury,
            parliament_candidate_root_v1(id, ParliamentBody::PolicyJury, &candidate_snapshot),
            3,
            3,
            request_height,
            pulse_height,
            session,
            None,
        )
        .expect("canonical bounded retry request");
        state
            .register_sortition_request_batch(
                id,
                vec![ParliamentSortitionRequestRegistrationV1 { sequence, request }],
                candidate_snapshot.clone(),
            )
            .expect("retry within the hard sortition bound");
        fail_generation_with_empty_roster(
            &mut state,
            election_id,
            pulse_id(u8::try_from(140 + sequence).expect("fixture pulse tag fits u8")),
            pulse_height + 1,
        );
        assert_eq!(
            state.attempt.status,
            if sequence == MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
                GovernanceAttemptStatusV1::Rejected
            } else {
                GovernanceAttemptStatusV1::Active
            }
        );
        request_height = pulse_height + 1;
    }

    assert_eq!(
        state.elections.len(),
        usize::try_from(MAX_PARLIAMENT_SORTITION_RETRIES_V1 + 1).expect("retry bound fits usize")
    );
    assert_eq!(state.candidate_snapshots.len(), 1);
    state
        .validate()
        .expect("exhausted sortition is a canonical terminal attempt");
    state
        .validate_restored_height_v1(request_height)
        .expect("exhausted sortition restores after its failure height");

    let mut over_limit = policy_only_state();
    over_limit
        .complete_qualification(id)
        .expect("enter policy stage for over-limit admission");
    let sequence = MAX_PARLIAMENT_SORTITION_RETRIES_V1 + 1;
    let election_id = BodyElectionAttemptId::derive_v1(id, ParliamentBody::PolicyJury, sequence);
    let request = SortitionRequestV1::try_new_canonical(
        id,
        election_id,
        ParliamentBody::PolicyJury,
        parliament_candidate_root_v1(id, ParliamentBody::PolicyJury, &candidate_snapshot),
        3,
        3,
        10,
        20,
        session,
        None,
    )
    .expect("structurally valid over-limit request");
    assert_eq!(
        over_limit.register_sortition_request(id, sequence, request, candidate_snapshot),
        Err(ParliamentReducerErrorV1::SortitionRetryLimitExceeded)
    );
}

#[test]
fn invitation_responses_seal_only_the_ranked_accepted_roster() {
    let mut state = policy_only_state();
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter Policy Jury stage");
    let (request, candidates) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        70,
        5,
        3,
        10,
        20,
        beacon_session(71),
        None,
    );
    let election_id = request.body_election_attempt_id;
    let request_id = request.id;
    state
        .register_sortition_request(id, 0, request, candidates)
        .expect("register invitation test election");
    consume_sortition(
        &mut state,
        id,
        vec![request_id],
        beacon_session(71),
        20,
        pulse_id(72),
    )
    .expect("derive ranked invitation plan");
    state
        .begin_invitation_acceptance(id, election_id, 20, 2)
        .expect("open two-block invitation window");
    let election = state.election(&election_id).expect("drawn election");
    let first_primary = election.primary_assignments()[0].clone();
    let second_primary = election.primary_assignments()[1].clone();
    let third_primary = election.primary_assignments()[2].clone();
    let first_alternate = election.alternate_assignments()[0].clone();
    let late_alternate = election.alternate_assignments()[1].clone();

    state
        .record_invitation_response(id, election_id, &first_primary.member, true, 20)
        .expect("first primary accepts");
    assert_eq!(
        state.record_invitation_response(id, election_id, &first_primary.member, false, 20),
        Err(ParliamentReducerErrorV1::InvitationResponseReplay)
    );
    state
        .record_invitation_response(id, election_id, &second_primary.member, false, 21)
        .expect("second primary declines");
    state
        .record_invitation_response(id, election_id, &first_alternate.member, true, 21)
        .expect("first ranked alternate accepts");
    state
        .record_invitation_response(id, election_id, &late_alternate.member, true, 21)
        .expect("second ranked alternate accepts");
    assert_eq!(
        state.record_invitation_response(id, election_id, &third_primary.member, true, 22),
        Err(ParliamentReducerErrorV1::InvitationWindowClosed)
    );
    assert_eq!(
        state.seal_body_roster(id, election_id, 21),
        Err(ParliamentReducerErrorV1::InvitationWindowStillOpen)
    );
    let body_id = state
        .seal_body_roster(id, election_id, 22)
        .expect("seal derived accepted roster after close");
    let body = state.body(&body_id).expect("sealed body");
    let expected_members: BTreeSet<_> = [
        first_primary.member,
        first_alternate.member,
        late_alternate.member,
    ]
    .into_iter()
    .collect();
    assert_eq!(
        body.assignments()
            .iter()
            .map(|assignment| assignment.member.clone())
            .collect::<BTreeSet<_>>(),
        expected_members
    );
    assert!(state.validate().is_ok());
}

#[test]
fn election_retry_supersedes_only_no_roster_and_rejects_pulse_reuse() {
    let BodyFixture {
        mut state,
        election_id: first_election,
        request_id: first_request,
        ..
    } = sealed_policy_body(3);
    let id = state.attempt.id;
    assert_eq!(
        state.fail_body_election_no_roster(id, first_election, 22),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BodyElection
        ))
    );
    assert_eq!(
        consume_sortition(
            &mut state,
            id,
            vec![first_request],
            beacon_session(13),
            20,
            pulse_id(14),
        ),
        Err(ParliamentReducerErrorV1::PulseBindingMismatch)
    );

    let mut state = policy_only_state();
    state.complete_qualification(id).expect("enter policy");
    let (first, first_candidates) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        12,
        3,
        3,
        10,
        20,
        beacon_session(13),
        None,
    );
    let first_request_id = first.id;
    let first_election_id = first.body_election_attempt_id;
    state
        .register_sortition_request(id, 0, first, first_candidates)
        .expect("register first election");
    consume_sortition(
        &mut state,
        id,
        vec![first_request_id],
        beacon_session(13),
        20,
        pulse_id(14),
    )
    .expect("consume first pulse");
    state
        .begin_invitation_acceptance(id, first_election_id, 20, 1)
        .expect("begin first invitation window");
    let invited: Vec<_> = state
        .election(&first_election_id)
        .expect("drawn first election")
        .primary_assignments()
        .iter()
        .chain(
            state
                .election(&first_election_id)
                .expect("drawn first election")
                .alternate_assignments(),
        )
        .map(|assignment| assignment.member.clone())
        .collect();
    for member in invited {
        state
            .record_invitation_response(id, first_election_id, &member, false, 20)
            .expect("decline first election invitation");
    }
    state
        .fail_body_election_no_roster(id, first_election_id, 21)
        .expect("record no roster");
    let (retry, retry_candidates) = sortition_request(
        id,
        1,
        ParliamentBody::PolicyJury,
        17,
        3,
        3,
        21,
        32,
        beacon_session(13),
        Some(20),
    );
    let retry_request_id = retry.id;
    state
        .register_sortition_request(id, 1, retry, retry_candidates)
        .expect("register exact retry");
    assert_eq!(
        state
            .election(&first_election_id)
            .expect("old election")
            .attempt
            .status,
        BodyElectionAttemptStatusV1::Superseded
    );
    assert_eq!(
        consume_sortition(
            &mut state,
            id,
            vec![retry_request_id],
            beacon_session(13),
            32,
            pulse_id(14),
        ),
        Err(ParliamentReducerErrorV1::BeaconPulseAlreadyConsumed)
    );
}

#[test]
fn body_phase_transition_table_rejects_skip_replay_and_reverse() {
    let BodyFixture { state, body_id, .. } = sealed_policy_body(3);
    let id = state.attempt.id;
    let phases = [
        DeliberationPhaseV1::Orientation,
        DeliberationPhaseV1::Evidence,
        DeliberationPhaseV1::Questions,
        DeliberationPhaseV1::Responses,
        DeliberationPhaseV1::Deliberation,
        DeliberationPhaseV1::Reflection,
        DeliberationPhaseV1::Vote,
    ];
    let mut cursor = state;
    for (index, expected) in phases.into_iter().enumerate() {
        for candidate in phases {
            let mut probe = cursor.clone();
            let result = probe.advance_body_phase(id, body_id, candidate, 22, 10);
            assert_eq!(
                result.is_ok(),
                candidate == expected,
                "phase row {index:?}, candidate {candidate:?}"
            );
        }
        cursor
            .advance_body_phase(id, body_id, expected, 22, 10)
            .expect("exact next phase succeeds");
    }
    assert_eq!(
        cursor.advance_body_phase(id, body_id, DeliberationPhaseV1::Vote, 22, 10),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BodyInstance
        ))
    );
}

#[test]
fn restore_rejects_partial_body_creation_and_reducer_impossible_statuses() {
    let fixture = sealed_policy_body(3);
    fixture
        .state
        .validate()
        .expect("sealed body fixture is canonical");

    let mut orphaned_election = fixture.state.clone();
    orphaned_election.bodies.remove(&fixture.body_id);
    orphaned_election
        .active_bodies
        .remove(&ParliamentBody::PolicyJury);
    assert_eq!(
        orphaned_election.validate(),
        Err(ParliamentReducerErrorV1::ImmutableBindingMismatch),
        "Sealed election and body creation are one atomic reducer transition"
    );

    for impossible_status in [
        BodyInstanceStatusV1::AwaitingSortition,
        BodyInstanceStatusV1::AcceptingInvitations,
        BodyInstanceStatusV1::Superseded,
    ] {
        let mut malformed = fixture.state.clone();
        malformed
            .bodies
            .get_mut(&fixture.body_id)
            .expect("fixture body")
            .instance
            .status = impossible_status;
        assert!(matches!(
            malformed.validate(),
            Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
                ParliamentReducerEntityV1::BodyInstance
            ))
        ));
    }
}

#[test]
fn absence_is_attempt_local_and_never_changes_original_quorum() {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    let id = state.attempt.id;
    let assignments = state.body(&body_id).expect("body").assignments().to_vec();
    let absent = assignments.first().expect("fixture has a seat");
    let other_member = &assignments
        .get(1)
        .expect("fixture has a second seat")
        .member;
    assert_eq!(
        state.record_attempt_absence(id, body_id, absent.assignment_id, other_member, 22),
        Err(ParliamentReducerErrorV1::UnauthorizedBodyMember)
    );
    state
        .record_attempt_absence(id, body_id, absent.assignment_id, &absent.member, 22)
        .expect("the exact seated member may declare their own absence");
    assert_eq!(
        state.record_attempt_absence(id, body_id, absent.assignment_id, &absent.member, 22),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BodyInstance
        ))
    );
    assert_eq!(
        state.body(&body_id).expect("body").instance.original_seats,
        3
    );
    advance_to_vote(&mut state, body_id);
    let ballot = BallotAttemptId::derive_v1(body_id, 0);
    let release_beacon_session_id = beacon_session(53);
    let tle_key_session_id = tle_key_session(52);
    let release_height = 40;
    let tle_session_id = TleSessionId::derive_v1(
        ballot,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    state
        .register_ballot_attempt(
            id,
            body_id,
            ballot,
            0,
            tle_session_id,
            tle_key_session_id,
            release_beacon_session_id,
            27,
            timed_ovn_policy(),
            release_height,
        )
        .expect("register ballot");
    assert_eq!(
        state.close_ballot_registration(id, ballot, root(51), 3, 31),
        Err(ParliamentReducerErrorV1::InvalidBallotCount)
    );
    state
        .close_ballot_registration(id, ballot, root(51), 2, 31)
        .expect("only nonabsent seats register");
    assert_eq!(
        state
            .ballot(&ballot)
            .expect("ballot")
            .attempt
            .original_seats,
        3
    );
}

/// One canonical sortition generation of `bodies` with three seats each, requested at
/// `request_height` for the exact slot `state` derives for its next generation.
fn sortition_generation(
    state: &ParliamentAttemptStateV1,
    bodies: &[ParliamentBody],
    sequence: u32,
    candidate_snapshot: &[AccountId],
    request_height: u64,
    beacon_session_id: BeaconSessionId,
) -> Vec<ParliamentSortitionRequestRegistrationV1> {
    sortition_generation_at(
        state.attempt.id,
        bodies,
        sequence,
        candidate_snapshot,
        request_height,
        generation_slot(state, request_height, beacon_session_id),
        beacon_session_id,
    )
}

/// One sortition generation of `bodies` with three seats each, requested at `request_height`
/// and claiming the pulse slot `pulse_height`, whether or not the reducer would derive it.
fn sortition_generation_at(
    governance_attempt_id: GovernanceAttemptId,
    bodies: &[ParliamentBody],
    sequence: u32,
    candidate_snapshot: &[AccountId],
    request_height: u64,
    pulse_height: u64,
    beacon_session_id: BeaconSessionId,
) -> Vec<ParliamentSortitionRequestRegistrationV1> {
    bodies
        .iter()
        .map(|&body| ParliamentSortitionRequestRegistrationV1 {
            sequence,
            request: sortition_request_intent(
                governance_attempt_id,
                sequence,
                body,
                candidate_snapshot.to_vec(),
                3,
                request_height,
                pulse_height,
                beacon_session_id,
            ),
        })
        .collect()
}

/// A Rules Committee and a Policy Jury drawn together from the first consumed pulse, with
/// both invitation windows open at height 20 only and `redraws_before` proposal-wide
/// redraws already spent.
fn rules_and_policy_invitations_open(
    redraws_before: u32,
) -> (ParliamentAttemptStateV1, [BodyElectionAttemptId; 2]) {
    let bodies = [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury];
    let mut state = state(public_requirements(&bodies));
    state.randomness_redraws_before_attempt = redraws_before;
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter the Rules stage");
    let logical = BeaconSessionId::for_network_v1(&network_id());
    let snapshot = candidates(60, 12);
    let registrations = sortition_generation(&state, &bodies, 0, &snapshot, 10, logical);
    let mut request_ids: Vec<_> = registrations
        .iter()
        .map(|entry| entry.request.id)
        .collect();
    request_ids.sort_unstable();
    state
        .register_sortition_request_batch(id, registrations, snapshot)
        .expect("register the initial generation");
    consume_sortition(&mut state, id, request_ids, logical, 20, pulse_id(61))
        .expect("consume the first pulse");
    let elections = bodies.map(|body| BodyElectionAttemptId::derive_v1(id, body, 0));
    for election_id in elections {
        state
            .begin_invitation_acceptance(id, election_id, 20, 1)
            .expect("open the invitation window");
    }
    (state, elections)
}

/// Register and draw the Rules Committee and Policy Jury of the attempt for `proposal_tag`
/// from one shared twelve-citizen snapshot and the pulse `pulse` of slot 20, returning each
/// body's ranked primaries and alternates and the cross-body assignment cap.
fn drawn_rules_and_policy_rosters(
    proposal_tag: u8,
    pulse: BeaconPulseId,
) -> (
    GovernanceAttemptId,
    Vec<(ParliamentBody, Vec<AccountId>, Vec<AccountId>, Option<u32>)>,
) {
    let bodies = [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury];
    let mut state = state_with_proposal_tag(public_requirements(&bodies), proposal_tag);
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter the Rules stage");
    let logical = BeaconSessionId::for_network_v1(&network_id());
    let snapshot = candidates(60, 12);
    let registrations = sortition_generation(&state, &bodies, 0, &snapshot, 10, logical);
    let mut request_ids: Vec<_> = registrations
        .iter()
        .map(|entry| entry.request.id)
        .collect();
    request_ids.sort_unstable();
    state
        .register_sortition_request_batch(id, registrations, snapshot)
        .expect("register the initial generation");
    consume_sortition(&mut state, id, request_ids, logical, 20, pulse)
        .expect("consume the shared pulse");
    let rosters = bodies
        .into_iter()
        .map(|body| {
            let election = state
                .election(&BodyElectionAttemptId::derive_v1(id, body, 0))
                .expect("drawn election");
            let members = |assignments: &[ParliamentSeatAssignmentV1]| {
                assignments
                    .iter()
                    .map(|assignment| assignment.member.clone())
                    .collect::<Vec<_>>()
            };
            (
                body,
                members(election.primary_assignments()),
                members(election.alternate_assignments()),
                election.cross_body_assignment_cap,
            )
        })
        .collect();
    (id, rosters)
}

#[test]
fn attempts_consuming_the_same_pulse_over_the_same_snapshot_receive_identical_rosters() {
    // Decision D5 of the governance-availability design: the draw is not bound to the
    // governance attempt. Two attempts of different proposals that consume one pulse over
    // the same snapshot, body set and sizing seat the same citizens in the same order;
    // another pulse changes the draw. Slot alignment makes every request of one epoch
    // window share its pulse, so this correlation spans the window (see the TODO at the
    // seed derivation in `governance/draw.rs`).
    let (first_id, first) = drawn_rules_and_policy_rosters(2, pulse_id(61));
    let (second_id, second) = drawn_rules_and_policy_rosters(7, pulse_id(61));
    assert_ne!(first_id, second_id, "two distinct governance attempts");
    assert_eq!(first, second);
    assert!(first.iter().all(|(_, primaries, ..)| primaries.len() == 3));

    let (other_pulse_id, other_pulse) = drawn_rules_and_policy_rosters(2, pulse_id(62));
    assert_eq!(other_pulse_id, first_id);
    assert_ne!(first, other_pulse, "a different pulse changes the draw");
}

/// Record a response from every invited citizen of `election_id` at `height`: primaries
/// accept when `accept_primaries` holds, and every other invitation is declined.
fn respond_to_every_invitation(
    state: &mut ParliamentAttemptStateV1,
    election_id: BodyElectionAttemptId,
    accept_primaries: bool,
    height: u64,
) {
    let id = state.attempt.id;
    let election = state.election(&election_id).expect("drawn election");
    let responses: Vec<_> = election
        .primary_assignments()
        .iter()
        .map(|assignment| (assignment.member.clone(), accept_primaries))
        .chain(
            election
                .alternate_assignments()
                .iter()
                .map(|assignment| (assignment.member.clone(), false)),
        )
        .collect();
    for (member, accept) in responses {
        state
            .record_invitation_response(id, election_id, &member, accept, height)
            .expect("record the invitation response");
    }
}

#[test]
fn no_roster_retry_at_the_redraw_ceiling_is_one_complete_generation() {
    // Both initially drawn bodies return empty rosters with one proposal-wide redraw left. A
    // single-body retry would spend that last unit and strand the other failed body: it could
    // never be redrawn, yet no transition could terminalize the attempt either. A retry
    // generation therefore covers every failed body for one redraw unit.
    let (mut state, failed) =
        rules_and_policy_invitations_open(MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1 - 1);
    let id = state.attempt.id;
    for election_id in failed {
        respond_to_every_invitation(&mut state, election_id, false, 20);
        state
            .fail_body_election_no_roster(id, election_id, 21)
            .expect("record the empty roster");
    }
    assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Active);
    state
        .validate()
        .expect("both failed bodies remain retryable");

    let logical = BeaconSessionId::for_network_v1(&network_id());
    let snapshot = candidates(90, 12);
    for partial in [
        [ParliamentBody::RulesCommittee],
        [ParliamentBody::PolicyJury],
    ] {
        let mut stranding = state.clone();
        assert_eq!(
            stranding.register_sortition_request_batch(
                id,
                sortition_generation(&state, &partial, 1, &snapshot, 21, logical),
                snapshot.clone(),
            ),
            Err(ParliamentReducerErrorV1::InvalidAssignmentPlan),
            "a retry must not strand another failed body"
        );
        assert_eq!(stranding, state, "a rejected partial retry must not mutate state");
    }

    let bodies = [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury];
    state
        .register_sortition_request_batch(
            id,
            sortition_generation(&state, &bodies, 1, &snapshot, 21, logical),
            snapshot,
        )
        .expect("one generation retries every failed body");
    assert_eq!(
        state.randomness_redraws_used_v1(),
        Ok(MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1)
    );
    state
        .validate()
        .expect("the generation spending the last redraw unit persists");

    // At the ceiling, the retried generation's objective failure is terminal and persistable.
    let retried = BodyElectionAttemptId::derive_v1(id, ParliamentBody::RulesCommittee, 1);
    assert_eq!(
        state
            .election(&retried)
            .expect("retried Rules election")
            .attempt
            .request
            .pulse_height,
        32,
        "the retry targets the first native pulse height after the consumed slot"
    );
    fail_generation_with_empty_roster(&mut state, retried, pulse_id(0xE7), 33);
    assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Rejected);
    state
        .validate()
        .expect("redraw exhaustion is a canonical terminal attempt");
}

#[test]
fn sub_floor_retry_generation_records_capacity_evidence_for_every_failed_body() {
    // A public and a hidden body both fail after the first pulse. A retry whose live electorate
    // is below the hidden-ballot floor records capacity evidence for the complete generation,
    // as the initial generation does, and a later adequate generation redraws both bodies.
    let (mut state, failed) = rules_and_policy_invitations_open(0);
    let id = state.attempt.id;
    for election_id in failed {
        respond_to_every_invitation(&mut state, election_id, false, 20);
        state
            .fail_body_election_no_roster(id, election_id, 21)
            .expect("record the empty roster");
    }
    let logical = BeaconSessionId::for_network_v1(&network_id());
    let bodies = [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury];
    let small = candidates(90, 2);
    state
        .record_hidden_sortition_capacity_failure_batch(
            id,
            sortition_generation(&state, &bodies, 1, &small, 21, logical),
            small,
        )
        .expect("a sub-floor electorate is typed evidence for the whole generation");
    assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Active);
    for body in bodies {
        let evidence = BodyElectionAttemptId::derive_v1(id, body, 1);
        assert_eq!(state.active_sortition_capacity_failures.get(&body), Some(&evidence));
    }
    state
        .validate()
        .expect("a retry generation's capacity evidence persists");

    let adequate = candidates(100, 12);
    assert_eq!(
        state.clone().register_sortition_request_batch(
            id,
            sortition_generation(&state, &bodies, 2, &adequate, 21, logical),
            adequate.clone(),
        ),
        Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
        "capacity evidence is retried only in a later block"
    );
    state
        .register_sortition_request_batch(
            id,
            sortition_generation(&state, &bodies, 2, &adequate, 22, logical),
            adequate,
        )
        .expect("an adequate electorate redraws every failed body");
    assert!(state.active_sortition_capacity_failures.is_empty());
    state
        .validate()
        .expect("the redrawn generation persists");
}

#[test]
fn later_stage_terminal_no_roster_rejects_a_persistable_attempt() {
    // The Policy Jury is drawn with the Rules Committee but serves a later stage. When its
    // roster comes back empty with the proposal-wide redraw budget spent, it can never be
    // redrawn, so the reducer rejects the attempt while the Rules stage is still in progress.
    // Persistence must accept that terminal state whether or not the current-stage body sealed.
    let (open, [rules, policy]) =
        rules_and_policy_invitations_open(MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1);
    let id = open.attempt.id;

    let mut deliberating = open.clone();
    respond_to_every_invitation(&mut deliberating, rules, true, 20);
    respond_to_every_invitation(&mut deliberating, policy, false, 20);
    let rules_body = deliberating
        .seal_body_roster(id, rules, 21)
        .expect("seal the Rules roster");
    deliberating
        .advance_body_phase(id, rules_body, DeliberationPhaseV1::Orientation, 21, 10)
        .expect("the Rules Committee deliberates");
    deliberating
        .validate()
        .expect("the deliberating attempt persists");
    let members: Vec<_> = deliberating
        .body(&rules_body)
        .expect("sealed Rules body")
        .assignments()
        .iter()
        .map(|seat| seat.member.clone())
        .collect();
    assert!(
        members
            .iter()
            .all(|member| deliberating.retains_citizenship_bond(member))
    );
    deliberating
        .fail_body_election_no_roster(id, policy, 21)
        .expect("record the empty Policy roster");
    assert_eq!(
        deliberating.attempt.status,
        GovernanceAttemptStatusV1::Rejected
    );
    assert_eq!(deliberating.attempt.stage, GovernanceStageV1::Rules);
    deliberating
        .validate()
        .expect("a later-stage terminal sortition failure is a canonical rejection");
    assert!(
        members
            .iter()
            .all(|member| !deliberating.retains_citizenship_bond(member)),
        "the rejected attempt releases the seated Rules members' bonds"
    );

    let mut unsealed = open;
    respond_to_every_invitation(&mut unsealed, rules, true, 20);
    respond_to_every_invitation(&mut unsealed, policy, false, 20);
    unsealed
        .fail_body_election_no_roster(id, policy, 21)
        .expect("record the empty Policy roster before the Rules roster seals");
    assert_eq!(unsealed.attempt.status, GovernanceAttemptStatusV1::Rejected);
    unsealed
        .validate()
        .expect("the rejection persists before the current-stage roster seals");
}

#[test]
fn retry_generations_never_share_a_pulse_slot() {
    // Within one block, a second retry could join the slot an earlier retry registered while
    // freezing a different snapshot (a citizen registered in between). The pulse batch draws
    // every request of a slot from one snapshot, so that slot could never be consumed and the
    // attempt would stay active. Each generation therefore owns a fresh slot.
    let (mut state, [rules, policy]) = rules_and_policy_invitations_open(0);
    let id = state.attempt.id;
    for election_id in [rules, policy] {
        respond_to_every_invitation(&mut state, election_id, false, 20);
    }
    let logical = BeaconSessionId::for_network_v1(&network_id());
    state
        .fail_body_election_no_roster(id, rules, 21)
        .expect("record the empty Rules roster");
    let first_snapshot = candidates(90, 12);
    state
        .register_sortition_request_batch(
            id,
            sortition_generation(
                &state,
                &[ParliamentBody::RulesCommittee],
                1,
                &first_snapshot,
                21,
                logical,
            ),
            first_snapshot,
        )
        .expect("retry the only failed body");
    state
        .fail_body_election_no_roster(id, policy, 21)
        .expect("record the empty Policy roster");

    let grown_snapshot = candidates(110, 12);
    // The Rules retry holds the first native slot after the consumed one. A second retry
    // claiming that slot in the same block is refused.
    let rules_retry_slot = 32;
    let policy_retry = |pulse_height| {
        sortition_generation_at(
            id,
            &[ParliamentBody::PolicyJury],
            1,
            &grown_snapshot,
            21,
            pulse_height,
            logical,
        )
    };
    let mut joining = state.clone();
    assert_eq!(
        joining.register_sortition_request_batch(
            id,
            policy_retry(rules_retry_slot),
            grown_snapshot.clone()
        ),
        Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
        "a retry must not join a slot another generation registered"
    );
    assert_eq!(joining, state, "a rejected joining retry must not mutate state");

    // Persistence independently refuses a slot whose awaiting requests froze different
    // snapshots, since no pulse batch could consume it.
    let mut diverged = state.clone();
    let [entry]: [ParliamentSortitionRequestRegistrationV1; 1] = policy_retry(rules_retry_slot)
        .try_into()
        .expect("one Policy Jury registration");
    diverged
        .register_sortition_request(id, entry.sequence, entry.request, grown_snapshot.clone())
        .expect("the per-request reducer alone admits the shared slot");
    assert_eq!(
        diverged.validate(),
        Err(ParliamentReducerErrorV1::InvalidCandidateSnapshot)
    );

    // The derived slot of a second generation in the same block is the next native pulse
    // height after the Rules retry's slot, so the retry needs no later block.
    let fresh_slot = generation_slot(&state, 21, logical);
    assert_eq!(fresh_slot, 35);
    state
        .register_sortition_request_batch(id, policy_retry(fresh_slot), grown_snapshot)
        .expect("the same block offers the next native slot");
    state
        .validate()
        .expect("generations on distinct slots persist");
    let rules_retry = state
        .election(&BodyElectionAttemptId::derive_v1(
            id,
            ParliamentBody::RulesCommittee,
            1,
        ))
        .expect("Rules retry")
        .attempt
        .request
        .id;
    consume_sortition(
        &mut state,
        id,
        vec![rules_retry],
        logical,
        rules_retry_slot,
        pulse_id(62),
    )
        .expect("each slot is consumable on its own");
}

#[test]
fn retry_capacity_evidence_may_cover_a_subset_with_mixed_sequences() {
    // After the first draw, a retry generation holds only the failed bodies, and their
    // sequences differ when they failed at different times. A sub-floor electorate records
    // capacity evidence for that whole subset, and persistence must accept it.
    let bodies = [
        ParliamentBody::RulesCommittee,
        ParliamentBody::InterestPanel,
        ParliamentBody::PolicyJury,
    ];
    let mut state = state(public_requirements(&bodies));
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter the Rules stage");
    let logical = BeaconSessionId::for_network_v1(&network_id());
    let initial = candidates(60, 12);
    let registrations = sortition_generation(&state, &bodies, 0, &initial, 10, logical);
    let mut request_ids: Vec<_> = registrations
        .iter()
        .map(|entry| entry.request.id)
        .collect();
    request_ids.sort_unstable();
    state
        .register_sortition_request_batch(id, registrations, initial)
        .expect("register the initial generation");
    consume_sortition(&mut state, id, request_ids, logical, 20, pulse_id(63))
        .expect("consume the first pulse");
    let [rules, interest, policy] = bodies.map(|body| BodyElectionAttemptId::derive_v1(id, body, 0));
    for (election_id, window) in [(rules, 1), (interest, 1), (policy, 5)] {
        state
            .begin_invitation_acceptance(id, election_id, 20, window)
            .expect("open the invitation window");
    }
    respond_to_every_invitation(&mut state, rules, true, 20);
    respond_to_every_invitation(&mut state, interest, false, 20);
    respond_to_every_invitation(&mut state, policy, false, 20);
    state
        .seal_body_roster(id, rules, 21)
        .expect("seal the Rules roster");
    state
        .fail_body_election_no_roster(id, interest, 21)
        .expect("record the empty Interest roster");
    let adequate = candidates(90, 12);
    state
        .register_sortition_request_batch(
            id,
            sortition_generation(
                &state,
                &[ParliamentBody::InterestPanel],
                1,
                &adequate,
                21,
                logical,
            ),
            adequate,
        )
        .expect("retry the Interest Panel");
    state
        .fail_body_election_no_roster(id, policy, 25)
        .expect("record the empty Policy roster after its longer window");
    fail_generation_with_empty_roster(
        &mut state,
        BodyElectionAttemptId::derive_v1(id, ParliamentBody::InterestPanel, 1),
        pulse_id(0xE9),
        33,
    );

    let small = candidates(130, 2);
    let capacity_slot = generation_slot(&state, 33, logical);
    let generation = [(ParliamentBody::InterestPanel, 2), (ParliamentBody::PolicyJury, 1)]
        .map(|(body, sequence)| ParliamentSortitionRequestRegistrationV1 {
            sequence,
            request: sortition_request_intent(
                id,
                sequence,
                body,
                small.clone(),
                3,
                33,
                capacity_slot,
                logical,
            ),
        })
        .to_vec();
    state
        .record_hidden_sortition_capacity_failure_batch(id, generation, small)
        .expect("a sub-floor electorate records evidence for the failed subset");
    assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Active);
    state
        .validate()
        .expect("subset capacity evidence with mixed sequences persists");
}
