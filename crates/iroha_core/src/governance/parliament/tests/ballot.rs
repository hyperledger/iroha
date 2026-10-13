#[test]
fn public_finding_requires_authority_bound_two_thirds_endorsement() {
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
    let attempt_id = state.attempt.id;
    state
        .complete_qualification(attempt_id)
        .expect("enter first public body");
    let mut request_ids = Vec::new();
    let mut interest_election_id = None;
    for body in [ParliamentBody::InterestPanel, ParliamentBody::PolicyJury] {
        let (request, candidate_snapshot) = sortition_request(
            attempt_id,
            0,
            body,
            12,
            3,
            3,
            10,
            20,
            beacon_session(90),
            None,
        );
        if body == ParliamentBody::InterestPanel {
            interest_election_id = Some(request.body_election_attempt_id);
        }
        request_ids.push(request.id);
        state
            .register_sortition_request(attempt_id, 0, request, candidate_snapshot)
            .expect("register simultaneous body request");
    }
    request_ids.sort_unstable();
    consume_sortition(
        &mut state,
        attempt_id,
        request_ids,
        beacon_session(90),
        20,
        pulse_id(91),
    )
    .expect("consume complete simultaneous draw");
    let election_id = interest_election_id.expect("interest election id");
    state
        .begin_invitation_acceptance(attempt_id, election_id, 20, 1)
        .expect("open interest invitations");
    let members = state
        .election(&election_id)
        .expect("interest election")
        .primary_assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    for member in &members {
        state
            .record_invitation_response(attempt_id, election_id, member, true, 20)
            .expect("selected interest member accepts");
    }
    let body_id = state
        .seal_body_roster(attempt_id, election_id, 21)
        .expect("seal public body");
    for phase in [
        DeliberationPhaseV1::Orientation,
        DeliberationPhaseV1::Evidence,
        DeliberationPhaseV1::Questions,
        DeliberationPhaseV1::Responses,
        DeliberationPhaseV1::Deliberation,
        DeliberationPhaseV1::Reflection,
    ] {
        state
            .advance_body_phase(attempt_id, body_id, phase, 22, 10)
            .expect("advance public deliberation");
    }
    assert_eq!(
        state
            .body(&body_id)
            .expect("public body")
            .public_finding_deadline_height(),
        Some(32)
    );
    let mut public_vote = state.clone();
    public_vote
        .bodies
        .get_mut(&body_id)
        .expect("public body")
        .instance
        .status = BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Vote);
    assert_eq!(
        public_vote.validate(),
        Err(ParliamentReducerErrorV1::DecisionModeMismatch),
        "a public-finding body has no private Vote phase"
    );

    let mut expired = state.clone();
    assert_eq!(
        expired.fail_public_finding_no_result(attempt_id, body_id, 32),
        Err(ParliamentReducerErrorV1::PublicFindingWindowStillOpen)
    );
    assert_eq!(
        expired.endorse_public_finding(attempt_id, body_id, root(100), &members[0], 33),
        Err(ParliamentReducerErrorV1::PublicFindingWindowClosed)
    );
    expired
        .fail_public_finding_no_result(attempt_id, body_id, 33)
        .expect("the permissionless trigger closes an expired public finding");
    assert_eq!(
        expired
            .body(&body_id)
            .expect("expired public body")
            .public_finding_no_result_kind(),
        Some(ParliamentNoResultKindV1::PublicFindingDeadlineExpired)
    );
    expired
        .validate()
        .expect("deadline-expired public finding persists canonically");

    let mut irreconcilable = state.clone();
    for (member, tag) in members.iter().zip([101_u8, 102, 103]) {
        assert!(
            !irreconcilable
                .endorse_public_finding(attempt_id, body_id, root(tag), member, 22)
                .expect("distinct seated endorsement is accepted")
        );
    }
    assert_eq!(
        irreconcilable.attempt.status,
        GovernanceAttemptStatusV1::Rejected
    );
    assert_eq!(
        irreconcilable
            .body(&body_id)
            .expect("irreconcilable public body")
            .instance
            .status,
        BodyInstanceStatusV1::NoResult
    );
    irreconcilable
        .validate()
        .expect("a mathematically unreachable public quorum is terminal after restore");

    let mut absent_quorum = state.clone();
    for member in &members[..2] {
        absent_quorum
            .record_attempt_absence(
                attempt_id,
                body_id,
                AssignmentId::derive_v1(election_id, member),
                member,
                22,
            )
            .expect("seated member records their own absence");
    }
    assert_eq!(
        absent_quorum.attempt.status,
        GovernanceAttemptStatusV1::Rejected
    );
    assert_eq!(
        absent_quorum
            .body(&body_id)
            .expect("absence-terminal public body")
            .instance
            .status,
        BodyInstanceStatusV1::NoResult
    );
    absent_quorum
        .validate()
        .expect("insufficient eligible public seats are terminal after restore");

    assert_eq!(
        state.endorse_public_finding(attempt_id, body_id, root(92), &account(99), 22),
        Err(ParliamentReducerErrorV1::UnauthorizedBodyMember)
    );
    assert!(
        !state
            .endorse_public_finding(attempt_id, body_id, root(92), &members[0], 22)
            .expect("first seated endorsement")
    );
    assert_eq!(
        state.endorse_public_finding(attempt_id, body_id, root(93), &members[0], 22),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BodyInstance
        ))
    );
    assert!(
        !state
            .endorse_public_finding(attempt_id, body_id, root(93), &members[1], 22)
            .expect("dissenting seated endorsement")
    );
    state
        .validate()
        .expect("split sub-quorum endorsements persist canonically");
    assert!(
        state
            .endorse_public_finding(attempt_id, body_id, root(92), &members[2], 22)
            .expect("second matching endorsement reaches two-thirds")
    );
    let body = state.body(&body_id).expect("final public body");
    assert_eq!(body.result_root(), Some(root(92)));
    let binding = body
        .public_finding_binding
        .as_ref()
        .expect("quorum binding retained");
    assert_eq!(binding.endorsements, 2);
    assert_eq!(binding.quorum, 2);
    assert_eq!(binding.endorsing_assignments.len(), 2);
    state
        .validate()
        .expect("authority-bound public-finding quorum persists canonically");

    let mut forged = state.clone();
    forged
        .bodies
        .get_mut(&body_id)
        .expect("public body")
        .public_finding_binding
        .as_mut()
        .expect("public binding")
        .endorsement_root = root(94);
    assert_eq!(
        forged.validate(),
        Err(ParliamentReducerErrorV1::CertificateBindingMismatch)
    );

    let mut substituted_endorsers = state.clone();
    substituted_endorsers
        .bodies
        .get_mut(&body_id)
        .expect("public body")
        .public_finding_binding
        .as_mut()
        .expect("public binding")
        .endorsing_assignments[0] = AssignmentId::derive_v1(election_id, &members[1]);
    assert_eq!(
        substituted_endorsers.validate(),
        Err(ParliamentReducerErrorV1::CertificateBindingMismatch)
    );

    let mut surplus_endorsement = state;
    let dissenting_assignment = AssignmentId::derive_v1(election_id, &members[1]);
    let body = surplus_endorsement
        .bodies
        .get_mut(&body_id)
        .expect("public body");
    body.public_finding_endorsements
        .insert(dissenting_assignment, root(92));
    let endorsing_assignments = body
        .public_finding_endorsements
        .keys()
        .copied()
        .collect::<Vec<_>>();
    let binding = body
        .public_finding_binding
        .as_mut()
        .expect("public binding");
    binding.endorsements = 3;
    binding.endorsing_assignments = endorsing_assignments;
    binding.endorsement_root = parliament_public_finding_endorsement_root_v1(
        attempt_id,
        body_id,
        root(92),
        &binding.endorsing_assignments,
    );
    assert_eq!(
        surplus_endorsement.validate(),
        Err(ParliamentReducerErrorV1::CertificateBindingMismatch)
    );
}

#[test]
fn casting_context_authorization_replays_all_prefix_phases_and_rejects_tampering() {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    advance_to_vote(&mut state, body_id);
    let governance_attempt_id = state.attempt.id;
    let ballot_attempt_id = BallotAttemptId::derive_v1(body_id, 0);
    let network_id = network_id();
    let network_binding = *network_id.as_bytes();
    let tle_key = casting_tle_key(network_binding, 0xA0);
    let tle_key_session_id = tle_key.public_state().key_session_id;
    let release_beacon_session_id = beacon_session(0xA4);
    let release_height = 40;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_attempt_id,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    state
        .register_ballot_attempt(
            governance_attempt_id,
            body_id,
            ballot_attempt_id,
            0,
            tle_session_id,
            tle_key_session_id,
            release_beacon_session_id,
            27,
            timed_ovn_policy(),
            release_height,
        )
        .expect("register casting-context ballot");
    let session = TimedOvnSessionPublicV1 {
        network_id: network_binding,
        proposal_content_id: *state.proposal_content_id().as_bytes(),
        governance_attempt_id: *governance_attempt_id.as_bytes(),
        body_instance_id: *body_id.as_bytes(),
        ballot_attempt_id: *ballot_attempt_id.as_bytes(),
        parameter_hash: timed_ovn_parameter_hash_v1(),
        tle_key_session_id,
        tle_key_transcript_hash: tle_key.public_state().transcript_hash,
        tle_master_public_key: *tle_key.master_public_key().as_bytes(),
    };
    let mut lifecycle =
        TimedOvnLifecycleStateV1::open_registration(session, 27, release_height, &tle_key)
            .expect("open casting-context registration");
    let mut rng = StdRng::from_seed([0xA5; 32]);
    for assignment in state.body(&body_id).expect("fixture body").assignments() {
        let participant_hash =
            parliament_ballot_participant_hash_v1(ballot_attempt_id, &assignment.member);
        let (_, registration) = TimedOvnRegistrationSecretV1::generate_with_rng(
            &session.rebuild(&tle_key).expect("timed session"),
            participant_hash,
            &mut rng,
        )
        .expect("registration");
        lifecycle = lifecycle
            .register_participant(participant_hash, registration.to_bytes(), &tle_key)
            .expect("authenticated registration");
    }

    let registered_state = casting_state_at_height(
        state.clone(),
        lifecycle.clone(),
        Some(&tle_key),
        Some(tle_key_session_id),
        30,
    );
    let registered = authorize_parliament_timed_ovn_casting_context_v1(
        &registered_state.query_view(),
        ballot_attempt_id,
    )
    .expect("registered casting context");
    assert_eq!(
        registered.phase(),
        ParliamentTimedOvnCastingPhaseV1::Registered
    );
    assert_eq!(registered.registration_records().len(), 3);
    assert!(registered.survivor_participant_hashes().is_none());
    let registered_archive = registered.archive_v1();
    let validated_registered_archive = registered_archive
        .validate_v1()
        .expect("registered archive replays independently");
    let registered_view = registered_state.query_view();
    let (registered_snapshot, registered_bindings) =
        derive_parliament_timed_ovn_casting_snapshot_v1(registered_view.world(), 30)
            .expect("derive authenticated registered casting snapshot");
    assert_eq!(registered_snapshot.count, 1);
    assert_eq!(registered_bindings.len(), 1);
    assert!(validated_registered_archive.matches_compact_binding_v1(&registered_bindings[0]));
    assert_eq!(
        derive_parliament_timed_ovn_casting_snapshot_v1(registered_view.world(), 30)
            .expect("repeat deterministic registered casting snapshot"),
        (registered_snapshot, registered_bindings)
    );

    for stale_height in [26, 31] {
        let stale_state = casting_state_at_height(
            state.clone(),
            lifecycle.clone(),
            Some(&tle_key),
            Some(tle_key_session_id),
            stale_height,
        );
        assert_eq!(
            authorize_parliament_timed_ovn_casting_context_v1(
                &stale_state.query_view(),
                ballot_attempt_id,
            )
            .expect_err("out-of-window registered context must be rejected"),
            TimedOvnCastingAuthorizationErrorV1::PhaseWindowInactive
        );
    }

    let mut malformed_schedule = state.clone();
    let mut malformed_schedule_state = casting_state_at_height(
        malformed_schedule.clone(),
        lifecycle.clone(),
        Some(&tle_key),
        Some(tle_key_session_id),
        30,
    );
    malformed_schedule
        .ballots
        .get_mut(&ballot_attempt_id)
        .expect("casting-context ballot")
        .registration_close_height = 27;
    malformed_schedule_state
        .world
        .parliament_attempts
        .insert(governance_attempt_id, malformed_schedule);
    assert_eq!(
        authorize_parliament_timed_ovn_casting_context_v1(
            &malformed_schedule_state.query_view(),
            ballot_attempt_id,
        )
        .expect_err("malformed casting schedule must be rejected"),
        TimedOvnCastingAuthorizationErrorV1::InvalidPhaseSchedule
    );

    let missing_key_state =
        casting_state_at_height(state.clone(), lifecycle.clone(), None, None, 30);
    assert!(matches!(
        authorize_parliament_timed_ovn_casting_context_v1(
            &missing_key_state.query_view(),
            ballot_attempt_id,
        ),
        Err(TimedOvnCastingAuthorizationErrorV1::MissingKeySession)
    ));

    let mut tampered_registration = lifecycle.clone();
    tampered_registration.corrupt_first_registration_record_for_testing();
    let tampered_state = casting_state_at_height(
        state.clone(),
        tampered_registration,
        Some(&tle_key),
        Some(tle_key_session_id),
        30,
    );
    assert!(matches!(
        authorize_parliament_timed_ovn_casting_context_v1(
            &tampered_state.query_view(),
            ballot_attempt_id,
        ),
        Err(TimedOvnCastingAuthorizationErrorV1::TimedOvn(_))
    ));

    let wrong_key = casting_tle_key(network_binding, 0xB0);
    let mismatched_key_state = casting_state_at_height(
        state.clone(),
        lifecycle.clone(),
        Some(&wrong_key),
        Some(tle_key_session_id),
        30,
    );
    assert!(matches!(
        authorize_parliament_timed_ovn_casting_context_v1(
            &mismatched_key_state.query_view(),
            ballot_attempt_id,
        ),
        Err(TimedOvnCastingAuthorizationErrorV1::TimedOvn(_)
            | TimedOvnCastingAuthorizationErrorV1::KeySession(_))
    ));

    let lifecycle = lifecycle
        .close_registration(&tle_key)
        .expect("close registration evidence");
    let TimedOvnLifecycleStateV1::RegistrationClosed(closed) = &lifecycle else {
        panic!("expected closed registration");
    };
    let (_, roster) = closed.validate(&tle_key).expect("replay closed roster");
    state
        .close_ballot_registration(
            governance_attempt_id,
            ballot_attempt_id,
            *roster.roster_root(),
            3,
            31,
        )
        .expect("advance reducer registration close");
    let closed_state = casting_state_at_height(
        state.clone(),
        lifecycle.clone(),
        Some(&tle_key),
        Some(tle_key_session_id),
        32,
    );
    let closed_context = authorize_parliament_timed_ovn_casting_context_v1(
        &closed_state.query_view(),
        ballot_attempt_id,
    )
    .expect("registration-closed casting context");
    assert_eq!(
        closed_context.phase(),
        ParliamentTimedOvnCastingPhaseV1::RegistrationClosed
    );
    assert!(closed_context.release_identity().is_none());
    let stale_closed_state = casting_state_at_height(
        state.clone(),
        lifecycle.clone(),
        Some(&tle_key),
        Some(tle_key_session_id),
        34,
    );
    assert_eq!(
        authorize_parliament_timed_ovn_casting_context_v1(
            &stale_closed_state.query_view(),
            ballot_attempt_id,
        )
        .expect_err("expired registration-closed context must be rejected"),
        TimedOvnCastingAuthorizationErrorV1::PhaseWindowInactive
    );

    let lifecycle = lifecycle
        .freeze_survivors(&tle_key)
        .expect("freeze survivor evidence");
    let TimedOvnLifecycleStateV1::SurvivorsFrozen(frozen) = &lifecycle else {
        panic!("expected survivor-frozen evidence");
    };
    state
        .freeze_ballot_survivors(
            governance_attempt_id,
            ballot_attempt_id,
            *frozen.dropout_root(),
            frozen.release_identity().survivor_corpus_root,
            u32::try_from(frozen.survivor_participant_hashes().len()).expect("survivor count"),
            frozen.release_identity().no_recovery_root,
            34,
        )
        .expect("advance reducer survivor freeze");
    let frozen_state = casting_state_at_height(
        state.clone(),
        lifecycle.clone(),
        Some(&tle_key),
        Some(tle_key_session_id),
        34,
    );
    let frozen_context = authorize_parliament_timed_ovn_casting_context_v1(
        &frozen_state.query_view(),
        ballot_attempt_id,
    )
    .expect("survivor-frozen casting context");
    assert_eq!(
        frozen_context.phase(),
        ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen
    );
    assert_eq!(
        frozen_context
            .survivor_participant_hashes()
            .expect("frozen survivors")
            .len(),
        3
    );
    assert!(frozen_context.release_identity().is_some());
    assert!(
        frozen_context
            .archive_v1()
            .validate_v1()
            .expect("frozen archive replays")
            .prepared_attempt()
            .is_some()
    );
    let stale_frozen_state = casting_state_at_height(
        state,
        lifecycle,
        Some(&tle_key),
        Some(tle_key_session_id),
        36,
    );
    assert_eq!(
        authorize_parliament_timed_ovn_casting_context_v1(
            &stale_frozen_state.query_view(),
            ballot_attempt_id,
        )
        .expect_err("expired survivor-frozen context must be rejected"),
        TimedOvnCastingAuthorizationErrorV1::PhaseWindowInactive
    );

    assert_eq!(
        ParliamentTimedOvnCastingPhaseV1::try_from(TimedOvnLifecyclePhaseV1::Sealed),
        Err(TimedOvnCastingAuthorizationErrorV1::PhaseNotCastable)
    );
    assert_eq!(
        ParliamentTimedOvnCastingPhaseV1::try_from(TimedOvnLifecyclePhaseV1::Released),
        Err(TimedOvnCastingAuthorizationErrorV1::PhaseNotCastable)
    );
}

#[test]
fn timed_ovn_checkpoint_prechecks_reject_phase_and_height_before_replay() {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    advance_to_vote(&mut state, body_id);
    let attempt_id = state.attempt.id;
    let ballot_id = BallotAttemptId::derive_v1(body_id, 0);
    let release_beacon_session_id = beacon_session(24);
    let tle_key_session_id = tle_key_session(23);
    let release_height = 40;
    state
        .register_ballot_attempt(
            attempt_id,
            body_id,
            ballot_id,
            0,
            TleSessionId::derive_v1(
                ballot_id,
                tle_key_session_id,
                release_beacon_session_id,
                release_height,
            ),
            tle_key_session_id,
            release_beacon_session_id,
            27,
            timed_ovn_policy(),
            release_height,
        )
        .expect("register timed ballot");

    assert_eq!(
        state.precheck_close_ballot_registration(attempt_id, ballot_id, 30),
        Err(ParliamentReducerErrorV1::WrongBallotPhaseHeight)
    );
    state
        .precheck_close_ballot_registration(attempt_id, ballot_id, 31)
        .expect("exact registration deadline passes the cheap guard");
    state
        .close_ballot_registration(attempt_id, ballot_id, root(19), 3, 31)
        .expect("close registration");
    assert_eq!(
        state.precheck_close_ballot_registration(attempt_id, ballot_id, 31),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BallotAttempt
        ))
    );

    assert_eq!(
        state.precheck_freeze_ballot_survivors(attempt_id, ballot_id, 33),
        Err(ParliamentReducerErrorV1::WrongBallotPhaseHeight)
    );
    state
        .precheck_freeze_ballot_survivors(attempt_id, ballot_id, 34)
        .expect("exact survivor deadline passes the cheap guard");
    state
        .freeze_ballot_survivors(attempt_id, ballot_id, root(21), root(29), 3, root(22), 34)
        .expect("freeze survivors");
    assert_eq!(
        state.precheck_freeze_ballot_survivors(attempt_id, ballot_id, 34),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BallotAttempt
        ))
    );

    assert_eq!(
        state.precheck_freeze_timed_ovn_corpus(attempt_id, ballot_id, 34),
        Err(ParliamentReducerErrorV1::WrongBallotPhaseHeight)
    );
    state
        .precheck_freeze_timed_ovn_corpus(attempt_id, ballot_id, 35)
        .expect("first commitment-window height passes the cheap guard");
    state
        .precheck_freeze_timed_ovn_corpus(attempt_id, ballot_id, 36)
        .expect("last commitment-window height passes the cheap guard");
    assert_eq!(
        state.precheck_freeze_timed_ovn_corpus(attempt_id, ballot_id, 37),
        Err(ParliamentReducerErrorV1::WrongBallotPhaseHeight)
    );

    let mut early_completion = state.clone();
    early_completion
        .freeze_timed_ovn_corpus(attempt_id, ballot_id, root(20), root(29), 3, root(25), 35)
        .expect("a complete corpus may seal at the first window height");
    assert_eq!(
        early_completion
            .ballot(&ballot_id)
            .expect("early-completed ballot")
            .commitment_closed_at_height,
        Some(35)
    );

    let mut incomplete_at_close = state.clone();
    incomplete_at_close
        .fail_ballot_no_result(attempt_id, ballot_id, false, 37)
        .expect("an incomplete corpus prefix becomes objectively fail-able after close");
    assert_eq!(
        incomplete_at_close
            .ballot(&ballot_id)
            .expect("failed incomplete ballot")
            .failure_kind,
        Some(ParliamentBallotFailureKindV1::CommitmentDeadlineExpired)
    );

    state
        .freeze_timed_ovn_corpus(attempt_id, ballot_id, root(20), root(29), 3, root(25), 36)
        .expect("freeze ballot corpus");
    assert_eq!(
        state.precheck_freeze_timed_ovn_corpus(attempt_id, ballot_id, 36),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BallotAttempt
        ))
    );
}

#[test]
fn restore_rejects_body_and_active_ballot_lifecycle_divergence() {
    let fixture = opened_policy_ballot(3, 3);
    fixture
        .state
        .validate()
        .expect("opened ballot fixture is canonical");

    let mut nonballoting_body = fixture.state.clone();
    nonballoting_body
        .bodies
        .get_mut(&fixture.body_id)
        .expect("fixture body")
        .instance
        .status = BodyInstanceStatusV1::RosterSealed;
    assert!(matches!(
        nonballoting_body.validate(),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BodyInstance
        ))
    ));

    let mut finalized = fixture;
    assert_eq!(
        finalize_policy(&mut finalized, 2, 1, 0),
        ParliamentAggregateOutcomeV1::Approved
    );
    finalized
        .state
        .bodies
        .get_mut(&finalized.body_id)
        .expect("fixture body")
        .instance
        .status = BodyInstanceStatusV1::Rejected;
    assert_eq!(
        finalized.state.validate(),
        Err(ParliamentReducerErrorV1::CertificateBindingMismatch),
        "the body terminal status must agree with the finalized aggregate outcome"
    );
}

#[test]
fn ballot_transition_table_freezes_corpus_and_retries_without_fallback() {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    advance_to_vote(&mut state, body_id);
    let id = state.attempt.id;
    let ballot = BallotAttemptId::derive_v1(body_id, 0);
    let first_release_beacon_session_id = beacon_session(24);
    let first_tle_key_session_id = tle_key_session(23);
    let first_release_height = 40;
    let first_tle_session_id = TleSessionId::derive_v1(
        ballot,
        first_tle_key_session_id,
        first_release_beacon_session_id,
        first_release_height,
    );
    state
        .register_ballot_attempt(
            id,
            body_id,
            ballot,
            0,
            first_tle_session_id,
            first_tle_key_session_id,
            first_release_beacon_session_id,
            27,
            timed_ovn_policy(),
            first_release_height,
        )
        .expect("registration");
    assert_eq!(
        state.freeze_ballot_survivors(id, ballot, root(21), root(29), 3, root(22), 34),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BallotAttempt
        ))
    );
    state
        .close_ballot_registration(id, ballot, root(19), 3, 31)
        .expect("commitment");
    assert_eq!(
        state.close_ballot_registration(id, ballot, root(19), 3, 31),
        Err(ParliamentReducerErrorV1::InvalidLifecycleTransition(
            ParliamentReducerEntityV1::BallotAttempt
        ))
    );
    assert_eq!(
        state.freeze_ballot_survivors(id, ballot, root(21), root(29), 2, root(22), 34),
        Err(ParliamentReducerErrorV1::InvalidBallotCount),
        "the two-survivor exact-tally disclosure must fail before ballot acceptance"
    );
    let privacy_failed = state.ballot(&ballot).expect("active ballot");
    assert_eq!(
        privacy_failed.attempt.status,
        BallotAttemptStatusV1::SurvivorFreeze
    );
    assert!(privacy_failed.survivors.is_none());
    assert!(privacy_failed.accepted_ballots.is_none());
    assert!(privacy_failed.corpus_root.is_none());
    assert!(privacy_failed.opening_root.is_none());
    assert!(privacy_failed.tally.is_none());
    state
        .fail_ballot_no_result(id, ballot, false, 35)
        .expect("sub-floor survivor freeze reaches deterministic deadline NoResult");
    let no_result = state.ballot(&ballot).expect("failed ballot");
    assert_eq!(no_result.attempt.status, BallotAttemptStatusV1::NoResult);
    assert_eq!(
        no_result.failure_kind,
        Some(ParliamentBallotFailureKindV1::SurvivorDeadlineExpired)
    );
    assert!(no_result.accepted_ballots.is_none());
    assert!(no_result.opening_root.is_none());
    assert!(no_result.tally.is_none());
    let retry = BallotAttemptId::derive_v1(body_id, 1);
    assert_eq!(
        state.register_ballot_attempt(
            id,
            body_id,
            retry,
            1,
            first_tle_session_id,
            tle_key_session(31),
            beacon_session(32),
            41,
            timed_ovn_policy(),
            54,
        ),
        Err(ParliamentReducerErrorV1::TleSessionAlreadyConsumed)
    );
    let retry_release_beacon_session_id = beacon_session(33);
    let retry_tle_key_session_id = tle_key_session(32);
    let retry_release_height = 54;
    let retry_tle_session_id = TleSessionId::derive_v1(
        retry,
        retry_tle_key_session_id,
        retry_release_beacon_session_id,
        retry_release_height,
    );
    state
        .register_ballot_attempt(
            id,
            body_id,
            retry,
            1,
            retry_tle_session_id,
            retry_tle_key_session_id,
            retry_release_beacon_session_id,
            41,
            timed_ovn_policy(),
            retry_release_height,
        )
        .expect("fresh attempt retries");
    assert_eq!(
        state.ballot(&ballot).expect("old ballot").attempt.status,
        BallotAttemptStatusV1::Superseded
    );
    assert_eq!(
        state
            .ballot(&retry)
            .expect("retry ballot")
            .attempt
            .original_seats,
        3
    );
}

/// Build a validated attempt retaining `key_session_id` through two ballot deadlines.
pub(crate) fn tle_key_session_retention_attempt_fixture_v1(
    key_session_id: TleKeySessionId,
) -> ParliamentAttemptStateV1 {
    tle_key_session_retention_attempt_fixture_with_retry_schedule_v1(key_session_id, 47, 60)
}

/// Build a validated attempt whose retry retains `key_session_id` forever.
pub(crate) fn tle_key_session_unbounded_retention_attempt_fixture_v1(
    key_session_id: TleKeySessionId,
) -> ParliamentAttemptStateV1 {
    tle_key_session_retention_attempt_fixture_with_retry_schedule_v1(
        key_session_id,
        u64::MAX - 15,
        u64::MAX - 2,
    )
}

/// Build a validated attempt whose first timed-OVN ballot ended `ReleasePulseUnavailable`
/// through the reducer: its corpus froze and the release deadline passed without a pulse at
/// `(release_beacon_session_id, release_height)`. Returns the attempt and that release slot.
pub(crate) fn release_pulse_unavailable_attempt_fixture_v1(
    release_beacon_session_id: BeaconSessionId,
) -> (ParliamentAttemptStateV1, (BeaconSessionId, u64)) {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    advance_to_vote(&mut state, body_id);
    let attempt_id = state.attempt.id;
    let ballot_id = BallotAttemptId::derive_v1(body_id, 0);
    let tle_key_session_id = tle_key_session(72);
    let release_height = 40;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_id,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    state
        .register_ballot_attempt(
            attempt_id,
            body_id,
            ballot_id,
            0,
            tle_session_id,
            tle_key_session_id,
            release_beacon_session_id,
            27,
            timed_ovn_policy(),
            release_height,
        )
        .expect("register private ballot");
    state
        .close_ballot_registration(attempt_id, ballot_id, root(71), 3, 31)
        .expect("freeze registration");
    state
        .freeze_ballot_survivors(attempt_id, ballot_id, root(74), root(75), 3, root(76), 34)
        .expect("freeze survivors");
    state
        .freeze_timed_ovn_corpus(attempt_id, ballot_id, root(77), root(75), 3, root(78), 36)
        .expect("freeze timed corpus");
    state
        .fail_ballot_no_result(attempt_id, ballot_id, false, release_height + 1)
        .expect("release expiry is derived after its boundary");
    assert_eq!(
        state
            .ballot(&ballot_id)
            .expect("failed ballot")
            .failure_kind,
        Some(ParliamentBallotFailureKindV1::ReleasePulseUnavailable)
    );
    (state, (release_beacon_session_id, release_height))
}

fn tle_key_session_retention_attempt_fixture_with_retry_schedule_v1(
    key_session_id: TleKeySessionId,
    retry_registered_at_height: u64,
    retry_release_height: u64,
) -> ParliamentAttemptStateV1 {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    advance_to_vote(&mut state, body_id);
    let governance_attempt_id = state.attempt.id;
    let policy = timed_ovn_policy();

    let first_ballot = BallotAttemptId::derive_v1(body_id, 0);
    let first_beacon = beacon_session(87);
    let first_release_height = 40;
    let first_tle_session = TleSessionId::derive_v1(
        first_ballot,
        key_session_id,
        first_beacon,
        first_release_height,
    );
    state
        .register_ballot_attempt(
            governance_attempt_id,
            body_id,
            first_ballot,
            0,
            first_tle_session,
            key_session_id,
            first_beacon,
            27,
            policy,
            first_release_height,
        )
        .expect("register first ballot");
    assert_eq!(
        state
            .tle_key_session_retention_contributions_v1()
            .get(&key_session_id),
        Some(&42)
    );

    state
        .fail_ballot_no_result(governance_attempt_id, first_ballot, false, 41)
        .expect("objectively fail first ballot");
    let retry_ballot = BallotAttemptId::derive_v1(body_id, 1);
    let retry_beacon = beacon_session(88);
    let retry_tle_session = TleSessionId::derive_v1(
        retry_ballot,
        key_session_id,
        retry_beacon,
        retry_release_height,
    );
    state
        .register_ballot_attempt(
            governance_attempt_id,
            body_id,
            retry_ballot,
            1,
            retry_tle_session,
            key_session_id,
            retry_beacon,
            retry_registered_at_height,
            policy,
            retry_release_height,
        )
        .expect("register retry with rotating key still retained");

    state
}

#[test]
fn tle_custody_retention_uses_maximum_deadline_across_ballot_retries() {
    let key_session_id = tle_key_session(86);
    let state = tle_key_session_retention_attempt_fixture_v1(key_session_id);
    let contributions = state.tle_key_session_retention_contributions_v1();
    assert_eq!(contributions.get(&key_session_id), Some(&62));
    assert_eq!(
        contributions.get(&tle_key_session(89)),
        None,
        "unreferenced sessions must not contribute to the retention index"
    );
}

#[test]
fn final_private_ballot_retry_failure_rejects_the_governance_attempt() {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    advance_to_vote(&mut state, body_id);
    let attempt_id = state.attempt.id;
    let policy = timed_ovn_policy();
    let mut registered_at_height = 30_u64;
    let mut final_ballot = None;
    let mut final_failure_height = None;

    for sequence in 0..=policy.max_ballot_retries {
        let ballot_id = BallotAttemptId::derive_v1(body_id, sequence);
        let tle_key_session_id =
            tle_key_session(u8::try_from(110 + sequence).expect("test sequence fits in u8"));
        let release_beacon_session_id =
            beacon_session(u8::try_from(120 + sequence).expect("test sequence fits in u8"));
        let release_height = registered_at_height + 13;
        let tle_session_id = TleSessionId::derive_v1(
            ballot_id,
            tle_key_session_id,
            release_beacon_session_id,
            release_height,
        );
        state
            .register_ballot_attempt(
                attempt_id,
                body_id,
                ballot_id,
                sequence,
                tle_session_id,
                tle_key_session_id,
                release_beacon_session_id,
                registered_at_height,
                policy,
                release_height,
            )
            .expect("register the exact next private ballot attempt");
        let failure_height = registered_at_height + 5;
        state
            .fail_ballot_no_result(attempt_id, ballot_id, false, failure_height)
            .expect("registration timeout is objectively derived");
        final_ballot = Some(ballot_id);
        final_failure_height = Some(failure_height);
        if sequence < policy.max_ballot_retries {
            assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Active);
        }
        registered_at_height = failure_height;
    }

    assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Rejected);
    assert_eq!(
        state.body(&body_id).expect("policy body").instance.status,
        BodyInstanceStatusV1::NoResult
    );
    let active_ballot = state
        .active_ballot_for_body(&body_id)
        .expect("the final failed ballot remains the active body transcript");
    assert_eq!(
        active_ballot.attempt().id,
        final_ballot.expect("final ballot id")
    );
    assert_eq!(
        active_ballot.failure_kind(),
        Some(ParliamentBallotFailureKindV1::RegistrationDeadlineExpired)
    );
    assert_eq!(active_ballot.failure_height(), final_failure_height);
    state
        .validate()
        .expect("exhausted private-ballot retry rejection persists canonically");
}

#[test]
fn proposal_wide_redraw_budget_composes_sortition_and_timed_ovn_retries() {
    let mut state = policy_only_state();
    state.randomness_redraws_before_attempt = MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1 - 2;
    let governance_attempt_id = state.attempt.id;
    state
        .complete_qualification(governance_attempt_id)
        .expect("enter Policy Jury stage");

    let (initial_request, initial_candidates) = sortition_request(
        governance_attempt_id,
        0,
        ParliamentBody::PolicyJury,
        180,
        3,
        3,
        10,
        20,
        beacon_session(181),
        None,
    );
    let initial_election_id = initial_request.body_election_attempt_id;
    state
        .register_sortition_request(
            governance_attempt_id,
            0,
            initial_request,
            initial_candidates,
        )
        .expect("the proposal's baseline draw remains free");
    fail_generation_with_empty_roster(&mut state, initial_election_id, pulse_id(0xE8), 21);

    let (retry_request, retry_candidates) = sortition_request(
        governance_attempt_id,
        1,
        ParliamentBody::PolicyJury,
        182,
        3,
        3,
        21,
        32,
        beacon_session(183),
        None,
    );
    let retry_election_id = retry_request.body_election_attempt_id;
    let retry_request_id = retry_request.id;
    state
        .register_sortition_request(governance_attempt_id, 1, retry_request, retry_candidates)
        .expect("one fresh sortition generation consumes the penultimate unit");
    assert_eq!(
        state
            .randomness_redraws_used_v1()
            .expect("bounded redraw count"),
        MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1 - 1
    );
    consume_sortition(
        &mut state,
        governance_attempt_id,
        vec![retry_request_id],
        beacon_session(183),
        32,
        pulse_id(184),
    )
    .expect("consume the retry pulse");
    state
        .begin_invitation_acceptance(governance_attempt_id, retry_election_id, 32, 1)
        .expect("open retry invitations");
    let selected = state
        .election(&retry_election_id)
        .expect("drawn retry election")
        .primary_assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    for member in selected {
        state
            .record_invitation_response(governance_attempt_id, retry_election_id, &member, true, 32)
            .expect("accept retry assignment");
    }
    let body_id = state
        .seal_body_roster(governance_attempt_id, retry_election_id, 33)
        .expect("seal the retained retry roster");
    for phase in [
        DeliberationPhaseV1::Orientation,
        DeliberationPhaseV1::Evidence,
        DeliberationPhaseV1::Questions,
        DeliberationPhaseV1::Responses,
        DeliberationPhaseV1::Deliberation,
        DeliberationPhaseV1::Reflection,
        DeliberationPhaseV1::Vote,
    ] {
        state
            .advance_body_phase(governance_attempt_id, body_id, phase, 33, 10)
            .expect("advance retained roster to its hidden ballot");
    }

    let policy = timed_ovn_policy();
    let initial_ballot_id = BallotAttemptId::derive_v1(body_id, 0);
    let initial_key_session_id = tle_key_session(185);
    let initial_release_session_id = beacon_session(186);
    let initial_release_height = 53;
    let initial_tle_session_id = TleSessionId::derive_v1(
        initial_ballot_id,
        initial_key_session_id,
        initial_release_session_id,
        initial_release_height,
    );
    state
        .register_ballot_attempt(
            governance_attempt_id,
            body_id,
            initial_ballot_id,
            0,
            initial_tle_session_id,
            initial_key_session_id,
            initial_release_session_id,
            40,
            policy,
            initial_release_height,
        )
        .expect("register the roster's initial timed-OVN session");

    let retained_transport_snapshot = state.clone();
    assert!(matches!(
        state.register_ballot_attempt(
            governance_attempt_id,
            body_id,
            initial_ballot_id,
            0,
            initial_tle_session_id,
            initial_key_session_id,
            initial_release_session_id,
            40,
            policy,
            initial_release_height,
        ),
        Err(ParliamentReducerErrorV1::DuplicateOrZeroIdentifier(
            ParliamentReducerEntityV1::BallotAttempt
        ))
    ));
    assert_eq!(
        state, retained_transport_snapshot,
        "an exact transport retry over the retained roster/session must be state-idempotent"
    );
    assert_eq!(
        state
            .randomness_redraws_used_v1()
            .expect("bounded redraw count"),
        MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1 - 1,
        "an exact transport retry must not spend a redraw unit"
    );

    state
        .fail_ballot_no_result(governance_attempt_id, initial_ballot_id, false, 45)
        .expect("objectively expire initial registration");
    let retry_ballot_id = BallotAttemptId::derive_v1(body_id, 1);
    let retry_key_session_id = tle_key_session(187);
    let retry_release_session_id = beacon_session(188);
    let retry_release_height = 58;
    let retry_tle_session_id = TleSessionId::derive_v1(
        retry_ballot_id,
        retry_key_session_id,
        retry_release_session_id,
        retry_release_height,
    );
    state
        .register_ballot_attempt(
            governance_attempt_id,
            body_id,
            retry_ballot_id,
            1,
            retry_tle_session_id,
            retry_key_session_id,
            retry_release_session_id,
            45,
            policy,
            retry_release_height,
        )
        .expect("the final proposal-wide unit admits one fresh timed-OVN session");
    assert_eq!(
        state
            .randomness_redraws_used_v1()
            .expect("bounded redraw count"),
        MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1
    );
    state
        .fail_ballot_no_result(governance_attempt_id, retry_ballot_id, false, 50)
        .expect("failure at the cumulative ceiling rejects the attempt");
    assert_eq!(state.attempt.status, GovernanceAttemptStatusV1::Rejected);
    state
        .validate()
        .expect("nested redraw exhaustion is canonical persisted state");

    let encoded = norito::to_bytes(&state).expect("encode redraw-bounded attempt");
    let decoded = norito::decode_from_bytes::<ParliamentAttemptStateV1>(&encoded)
        .expect("decode redraw-bounded attempt");
    assert_eq!(decoded, state);
    decoded
        .validate()
        .expect("decoded redraw prefix and derived usage remain canonical");

    let mut mutated_prefix = decoded;
    mutated_prefix.randomness_redraws_before_attempt -= 1;
    assert_eq!(
        mutated_prefix.validate(),
        Err(ParliamentReducerErrorV1::RetrySequenceMismatch),
        "a lowered persisted prefix must not justify terminal exhaustion"
    );
}

#[test]
fn ballot_failure_reason_is_derived_from_the_frozen_phase() {
    let BodyFixture {
        mut state, body_id, ..
    } = sealed_policy_body(3);
    advance_to_vote(&mut state, body_id);
    let attempt_id = state.attempt.id;
    let ballot_id = BallotAttemptId::derive_v1(body_id, 0);
    let release_beacon_session_id = beacon_session(73);
    let tle_key_session_id = tle_key_session(72);
    let release_height = 40;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_id,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    state
        .register_ballot_attempt(
            attempt_id,
            body_id,
            ballot_id,
            0,
            tle_session_id,
            tle_key_session_id,
            release_beacon_session_id,
            27,
            timed_ovn_policy(),
            release_height,
        )
        .expect("register private ballot");

    assert_eq!(
        state.fail_ballot_no_result(attempt_id, ballot_id, false, 31),
        Err(ParliamentReducerErrorV1::BallotFailureKindMismatch)
    );
    let mut registration_expired = state.clone();
    registration_expired
        .fail_ballot_no_result(attempt_id, ballot_id, false, 32)
        .expect("registration expiry is derived after its boundary");
    assert_eq!(
        registration_expired
            .ballot(&ballot_id)
            .expect("failed ballot")
            .failure_kind,
        Some(ParliamentBallotFailureKindV1::RegistrationDeadlineExpired)
    );
    let expected_failure_root = parliament_ballot_failure_root_v1(
        attempt_id,
        ballot_id,
        ParliamentBallotFailureKindV1::RegistrationDeadlineExpired,
        32,
    );
    assert_eq!(
        registration_expired
            .ballot(&ballot_id)
            .expect("failed ballot")
            .failure_root,
        Some(expected_failure_root)
    );
    registration_expired
        .validate()
        .expect("derived registration failure persists canonically");
    registration_expired
        .ballots
        .get_mut(&ballot_id)
        .expect("failed ballot")
        .failure_root = Some(root(70));
    assert_eq!(
        registration_expired.validate(),
        Err(ParliamentReducerErrorV1::BallotFailureKindMismatch)
    );

    state
        .close_ballot_registration(attempt_id, ballot_id, root(71), 3, 31)
        .expect("freeze registration");
    let mut survivor_expired = state.clone();
    survivor_expired
        .fail_ballot_no_result(attempt_id, ballot_id, false, 35)
        .expect("survivor expiry is derived after its boundary");
    assert_eq!(
        survivor_expired
            .ballot(&ballot_id)
            .expect("failed ballot")
            .failure_kind,
        Some(ParliamentBallotFailureKindV1::SurvivorDeadlineExpired)
    );

    state
        .freeze_ballot_survivors(attempt_id, ballot_id, root(74), root(75), 3, root(76), 34)
        .expect("freeze survivors");
    let mut commitment_expired = state.clone();
    commitment_expired
        .fail_ballot_no_result(attempt_id, ballot_id, false, 37)
        .expect("commitment expiry is derived after its boundary");
    assert_eq!(
        commitment_expired
            .ballot(&ballot_id)
            .expect("failed ballot")
            .failure_kind,
        Some(ParliamentBallotFailureKindV1::CommitmentDeadlineExpired)
    );

    state
        .freeze_timed_ovn_corpus(attempt_id, ballot_id, root(77), root(75), 3, root(78), 36)
        .expect("freeze timed corpus");
    let mut release_expired = state.clone();
    release_expired
        .fail_ballot_no_result(attempt_id, ballot_id, false, 41)
        .expect("release expiry is derived after its boundary");
    assert_eq!(
        release_expired
            .ballot(&ballot_id)
            .expect("failed ballot")
            .failure_kind,
        Some(ParliamentBallotFailureKindV1::ReleasePulseUnavailable)
    );
    assert_eq!(
        release_expired.unavailable_release_pulse_slots_v1(),
        BTreeSet::from([(release_beacon_session_id, release_height)])
    );
    assert!(
        release_expired
            .classifies_release_pulse_unavailable_at(release_beacon_session_id, release_height)
    );

    let mut finalized_pulse_before_deadline = state.clone();
    assert_eq!(
        finalized_pulse_before_deadline.fail_ballot_no_result(
            attempt_id,
            ballot_id,
            true,
            release_height + 1,
        ),
        Err(ParliamentReducerErrorV1::BallotFailureKindMismatch)
    );
    finalized_pulse_before_deadline
        .fail_ballot_no_result(attempt_id, ballot_id, true, release_height + 3)
        .expect("an unconsumed finalized pulse cannot strand a ballot past opening deadline");
    assert_eq!(
        finalized_pulse_before_deadline
            .ballot(&ballot_id)
            .expect("failed ballot")
            .failure_kind,
        Some(ParliamentBallotFailureKindV1::OpeningDeadlineExpired)
    );
    finalized_pulse_before_deadline
        .validate()
        .expect("objective opening-deadline failure persists canonically");

    let mut late_opening = state.clone();
    assert_eq!(
        late_opening.begin_ballot_opening_batch(
            attempt_id,
            vec![ballot_id],
            release_beacon_session_id,
            release_height,
            release_height + 3,
            pulse_id(80),
        ),
        Err(ParliamentReducerErrorV1::PulseBindingMismatch)
    );

    state
        .begin_ballot_opening_batch(
            attempt_id,
            vec![ballot_id],
            release_beacon_session_id,
            release_height,
            release_height,
            pulse_id(79),
        )
        .expect("consume exact release pulse");
    assert_eq!(
        state.fail_ballot_no_result(attempt_id, ballot_id, true, release_height),
        Err(ParliamentReducerErrorV1::BallotFailureKindMismatch)
    );
    let mut opening_expired = state.clone();
    opening_expired
        .fail_ballot_no_result(attempt_id, ballot_id, true, release_height + 3)
        .expect("an incomplete aggregate opening expires objectively");
    assert_eq!(
        opening_expired
            .ballot(&ballot_id)
            .expect("failed opening")
            .failure_kind,
        Some(ParliamentBallotFailureKindV1::OpeningDeadlineExpired)
    );
    opening_expired
        .validate()
        .expect("expired opening transcript remains canonical");
    assert_eq!(
        state
            .ballot(&ballot_id)
            .expect("opening ballot")
            .attempt
            .status,
        BallotAttemptStatusV1::Opening
    );
    state
        .validate()
        .expect("a rejected caller-selected opening failure leaves canonical state");
}
