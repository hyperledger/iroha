// Aligned, collision-safe sortition slots: the first consensus-native pulse height derived
// from the attempt's frozen delay, frozen epoch length and own generation history.

/// A qualified Policy-Jury-only attempt frozen with `delay` and the native epoch length
/// `epoch_length_blocks`.
fn slot_state(delay: u64, epoch_length_blocks: u64) -> ParliamentAttemptStateV1 {
    let mut state = ParliamentAttemptStateV1::try_new(
        attempt(),
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        delay,
        epoch_length_blocks,
        root(3),
        GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: root(4),
        }),
        vec![RequiredParliamentBodyV1 {
            body: ParliamentBody::PolicyJury,
            decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
        }],
    )
    .expect("valid slot fixture");
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter Policy Jury stage");
    state
}

/// One Policy Jury registration of `sequence` requested at `request_height` and claiming
/// `pulse_height`.
fn policy_slot_registration(
    state: &ParliamentAttemptStateV1,
    sequence: u32,
    snapshot: &[AccountId],
    request_height: u64,
    pulse_height: u64,
    beacon_session_id: BeaconSessionId,
) -> Vec<ParliamentSortitionRequestRegistrationV1> {
    vec![ParliamentSortitionRequestRegistrationV1 {
        sequence,
        request: sortition_request_intent(
            state.attempt.id,
            sequence,
            ParliamentBody::PolicyJury,
            snapshot.to_vec(),
            3,
            request_height,
            pulse_height,
            beacon_session_id,
        ),
    }]
}

#[test]
fn aligned_sortition_pulse_height_is_the_first_native_height_without_saturation() {
    // Native pulse heights are exactly the heights `h` with `(h + 1) % L == 0`.
    assert_eq!(aligned_sortition_pulse_height_v1(9, 10), Some(9));
    assert_eq!(aligned_sortition_pulse_height_v1(10, 10), Some(19));
    assert_eq!(aligned_sortition_pulse_height_v1(1, 10), Some(9));
    assert_eq!(aligned_sortition_pulse_height_v1(19, 10), Some(19));
    assert_eq!(aligned_sortition_pulse_height_v1(20, 10), Some(29));

    // The minimum NPoS epoch length.
    assert_eq!(aligned_sortition_pulse_height_v1(1, 3), Some(2));
    assert_eq!(aligned_sortition_pulse_height_v1(2, 3), Some(2));
    assert_eq!(aligned_sortition_pulse_height_v1(3, 3), Some(5));
    for earliest in 1..=64_u64 {
        for epoch_length_blocks in 3..=17_u64 {
            let height = aligned_sortition_pulse_height_v1(earliest, epoch_length_blocks)
                .expect("small heights never overflow");
            assert!(height >= earliest);
            assert!(height - earliest < epoch_length_blocks);
            assert_eq!((height + 1) % epoch_length_blocks, 0);
        }
    }

    // Zero and sub-minimum inputs name no slot.
    assert_eq!(aligned_sortition_pulse_height_v1(0, 10), None);
    for epoch_length_blocks in 0..3 {
        assert_eq!(
            aligned_sortition_pulse_height_v1(9, epoch_length_blocks),
            None
        );
    }

    // Overflow of the slot or of its successor height is refused, never saturated.
    assert_eq!(u64::MAX % 3, 0);
    assert_eq!(aligned_sortition_pulse_height_v1(u64::MAX, 3), None);
    assert_eq!(
        aligned_sortition_pulse_height_v1(u64::MAX - 1, 3),
        Some(u64::MAX - 1)
    );
    assert_eq!(
        aligned_sortition_pulse_height_v1(u64::MAX, 4),
        None,
        "a slot whose successor height overflows is not a native pulse height"
    );
    assert_eq!(aligned_sortition_pulse_height_v1(u64::MAX, u64::MAX), None);
    assert_eq!(
        aligned_sortition_pulse_height_v1(u64::MAX - 2, u64::MAX),
        Some(u64::MAX - 1)
    );
    assert_eq!(
        aligned_sortition_pulse_height_v1(u64::MAX - 1, u64::MAX),
        Some(u64::MAX - 1)
    );
}

#[test]
fn attempt_freezes_a_native_epoch_length_of_at_least_three_blocks() {
    for epoch_length_blocks in 0..3 {
        assert_eq!(
            ParliamentAttemptStateV1::try_new(
                attempt(),
                PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
                10,
                epoch_length_blocks,
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
    }
    let state = slot_state(4, 10);
    assert_eq!(state.sortition_pulse_delay_blocks(), 4);
    assert_eq!(state.sortition_pulse_epoch_length_blocks(), 10);
    state.validate().expect("frozen geometry persists");

    let encoded = norito::to_bytes(&state).expect("encode frozen geometry");
    let decoded = norito::decode_from_bytes::<ParliamentAttemptStateV1>(&encoded)
        .expect("decode frozen geometry");
    assert_eq!(decoded.sortition_pulse_epoch_length_blocks(), 10);
    assert_eq!(decoded, state);
}

#[test]
fn generation_slot_is_above_the_delay_and_every_earlier_generation_slot() {
    let session = beacon_session(201);
    let mut state = slot_state(4, 10);
    let id = state.attempt.id;

    // Without an earlier generation the slot is the first native height after the delay.
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(5, session),
        Some(9)
    );
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(6, session),
        Some(19)
    );
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(u64::MAX - 3, session),
        None,
        "request height plus delay overflows"
    );
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(u64::MAX - 4, session),
        None,
        "the aligned slot overflows"
    );

    // A capacity-failure record is a generation: it holds slot 9 without consuming a pulse.
    let single = candidates(210, 1);
    state
        .record_hidden_sortition_capacity_failure_batch(
            id,
            policy_slot_registration(&state, 0, &single, 5, 9, session),
            single,
        )
        .expect("record sub-floor capacity evidence on slot 9");
    assert!(state.used_pulse_slots.is_empty());
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(5, session),
        Some(19),
        "a later generation in the same epoch window targets the next boundary"
    );
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(16, session),
        Some(29),
        "the frozen delay still bounds the slot from below"
    );
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(5, beacon_session(202)),
        Some(9),
        "generation slots are scoped to their beacon session"
    );

    // An election is a generation as well.
    let adequate = candidates(220, 3);
    state
        .register_sortition_request_batch(
            id,
            policy_slot_registration(&state, 1, &adequate, 6, 19, session),
            adequate,
        )
        .expect("register the retry on the next boundary");
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(7, session),
        Some(29)
    );

    let mut saturated = slot_state(1, 4);
    let saturated_id = saturated.attempt.id;
    let top = candidates(230, 1);
    let top_slot = u64::MAX - 4;
    assert_eq!((top_slot + 1) % 4, 0);
    saturated
        .record_hidden_sortition_capacity_failure_batch(
            saturated_id,
            policy_slot_registration(&saturated, 0, &top, top_slot - 1, top_slot, session),
            top,
        )
        .expect("record evidence on the last expressible native slot");
    assert_eq!(
        saturated.next_sortition_generation_pulse_height_v1(top_slot, session),
        None,
        "no native slot above the last one fits u64"
    );
}

#[test]
fn capacity_retry_in_the_same_epoch_window_targets_the_next_boundary() {
    let session = beacon_session(203);
    let mut state = slot_state(1, 10);
    let id = state.attempt.id;
    let single = candidates(210, 1);
    state
        .record_hidden_sortition_capacity_failure_batch(
            id,
            policy_slot_registration(&state, 0, &single, 5, 9, session),
            single,
        )
        .expect("record sub-floor capacity evidence on slot 9");
    state.validate().expect("capacity evidence persists");

    // The retry is requested one block later, inside the same epoch window. Height 9 is the
    // first native height after its delay, but the evidence generation already holds it.
    let adequate = candidates(220, 3);
    for (claim, reason) in [
        (
            7,
            "the retired request-height-plus-delay rule names no native pulse height",
        ),
        (
            9,
            "a retry must not join the slot of the generation it supersedes",
        ),
        (
            29,
            "a retry must not skip the first free native pulse height",
        ),
    ] {
        let mut rejected = state.clone();
        assert_eq!(
            rejected.register_sortition_request_batch(
                id,
                policy_slot_registration(&state, 1, &adequate, 6, claim, session),
                adequate.clone(),
            ),
            Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
            "{reason}"
        );
        assert_eq!(rejected, state, "a rejected retry must not mutate state");
    }
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(6, session),
        Some(19)
    );
    state
        .register_sortition_request_batch(
            id,
            policy_slot_registration(&state, 1, &adequate, 6, 19, session),
            adequate,
        )
        .expect("the retry on the next boundary is accepted");
    let retry = state
        .election(&BodyElectionAttemptId::derive_v1(
            id,
            ParliamentBody::PolicyJury,
            1,
        ))
        .expect("registered retry");
    assert_eq!(
        retry.attempt.status,
        BodyElectionAttemptStatusV1::AwaitingPulse
    );
    assert_eq!(retry.attempt.request.pulse_height, 19);
    state
        .validate()
        .expect("generations on distinct native slots persist");
}

#[test]
fn no_roster_retry_after_a_consumed_slot_targets_a_later_boundary() {
    let session = beacon_session(204);
    let mut state = slot_state(4, 10);
    let id = state.attempt.id;
    let (first, first_candidates) = sortition_request(
        id,
        0,
        ParliamentBody::PolicyJury,
        210,
        3,
        3,
        5,
        9,
        session,
        None,
    );
    let first_request_id = first.id;
    let first_election_id = first.body_election_attempt_id;
    state
        .register_sortition_request(id, 0, first, first_candidates)
        .expect("register the first generation on slot 9");
    consume_sortition(
        &mut state,
        id,
        vec![first_request_id],
        session,
        9,
        pulse_id(205),
    )
    .expect("consume the pulse of slot 9");
    state
        .begin_invitation_acceptance(id, first_election_id, 9, 1)
        .expect("open the invitation window");
    respond_to_every_invitation(&mut state, first_election_id, false, 9);
    state
        .fail_body_election_no_roster(id, first_election_id, 10)
        .expect("record the empty roster");

    // A retry in the failure block: its delay ends at height 14 inside the next epoch
    // window, so the slot is that window's native pulse height.
    let retry_candidates = candidates(220, 3);
    assert_eq!(
        state.next_sortition_generation_pulse_height_v1(10, session),
        Some(19)
    );
    let mut old_rule = state.clone();
    assert_eq!(
        old_rule.register_sortition_request_batch(
            id,
            policy_slot_registration(&state, 1, &retry_candidates, 10, 14, session),
            retry_candidates.clone(),
        ),
        Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
        "request height plus delay is not a native pulse height"
    );
    assert_eq!(old_rule, state);
    state
        .register_sortition_request_batch(
            id,
            policy_slot_registration(&state, 1, &retry_candidates, 10, 19, session),
            retry_candidates,
        )
        .expect("the retry targets the later boundary");
    state
        .validate()
        .expect("a consumed slot and its retry slot persist");
}

#[test]
fn persistence_rechecks_every_generation_slot_from_frozen_fields() {
    let session = beacon_session(206);
    let mut state = slot_state(1, 10);
    let id = state.attempt.id;
    let single = candidates(210, 1);
    state
        .record_hidden_sortition_capacity_failure_batch(
            id,
            policy_slot_registration(&state, 0, &single, 5, 9, session),
            single,
        )
        .expect("record sub-floor capacity evidence on slot 9");
    let adequate = candidates(220, 3);
    state
        .register_sortition_request_batch(
            id,
            policy_slot_registration(&state, 1, &adequate, 6, 19, session),
            adequate,
        )
        .expect("register the retry on slot 19");
    state.validate().expect("the exact schedule persists");
    let retry_id = BodyElectionAttemptId::derive_v1(id, ParliamentBody::PolicyJury, 1);
    let evidence_id = BodyElectionAttemptId::derive_v1(id, ParliamentBody::PolicyJury, 0);

    // A different frozen epoch length no longer explains the stored slots.
    for epoch_length_blocks in [2, 7, 20] {
        let mut wrong_length = state.clone();
        wrong_length.sortition_pulse_epoch_length_blocks = epoch_length_blocks;
        assert_eq!(
            wrong_length.validate(),
            Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
            "frozen epoch length {epoch_length_blocks}"
        );
    }
    let mut wrong_delay = state.clone();
    wrong_delay.sortition_pulse_delay_blocks = 5;
    assert_eq!(
        wrong_delay.validate(),
        Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
        "a longer frozen delay moves the evidence generation past slot 9"
    );

    // A hand-built election slot: the retired rule, a misaligned height, a skipped boundary
    // and the slot of the earlier generation are all refused.
    for claim in [7, 18, 20, 29, 9] {
        let mut hand_built = state.clone();
        let request = &mut hand_built
            .elections
            .get_mut(&retry_id)
            .expect("registered retry")
            .attempt
            .request;
        request.pulse_height = claim;
        request.id = request.canonical_id();
        assert_eq!(
            hand_built.validate(),
            Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
            "hand-built retry slot {claim}"
        );
    }

    // A hand-built capacity-evidence slot is refused in the same way.
    for claim in [6, 8, 19] {
        let mut hand_built = state.clone();
        let failure = hand_built
            .sortition_capacity_failures
            .get_mut(&evidence_id)
            .expect("capacity evidence");
        failure.pulse_height = claim;
        failure.request_intent_id = SortitionRequestV1 {
            id: SortitionRequestId::new([0; 32]),
            governance_attempt_id: id,
            body_election_attempt_id: evidence_id,
            body: failure.body,
            candidate_root: failure.candidate_root,
            candidate_count: 1,
            target_seats: failure.target_seats,
            request_height: failure.request_height,
            pulse_height: claim,
            beacon_session_id: failure.beacon_session_id,
        }
        .canonical_id();
        assert_eq!(
            hand_built.validate(),
            Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
            "hand-built evidence slot {claim}"
        );
    }

    // Generation slots stay in registration order. With a three-block epoch the evidence
    // generation holds slot 8 and its retry slot 11. A hand-built retry requested at height 1
    // would name the native slot 2 on its own, below the generation it supersedes.
    let mut short_epoch = slot_state(1, 3);
    let single = candidates(210, 1);
    short_epoch
        .record_hidden_sortition_capacity_failure_batch(
            id,
            policy_slot_registration(&short_epoch, 0, &single, 5, 8, session),
            single,
        )
        .expect("record sub-floor capacity evidence on slot 8");
    let adequate = candidates(220, 3);
    short_epoch
        .register_sortition_request_batch(
            id,
            policy_slot_registration(&short_epoch, 1, &adequate, 6, 11, session),
            adequate,
        )
        .expect("register the retry on slot 11");
    short_epoch
        .validate()
        .expect("the exact short-epoch schedule persists");
    let mut non_monotone = short_epoch;
    let request = &mut non_monotone
        .elections
        .get_mut(&retry_id)
        .expect("registered retry")
        .attempt
        .request;
    request.request_height = 1;
    request.pulse_height = 2;
    request.id = request.canonical_id();
    assert_eq!(
        non_monotone.validate(),
        Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
        "a retry cannot hold a slot below the generation it supersedes"
    );
}

#[test]
fn persistence_requires_one_request_height_per_generation_slot() {
    let bodies = [ParliamentBody::RulesCommittee, ParliamentBody::PolicyJury];
    let mut state = state(public_requirements(&bodies));
    let id = state.attempt.id;
    state
        .complete_qualification(id)
        .expect("enter the Rules stage");
    let logical = BeaconSessionId::for_network_v1(&network_id());
    let snapshot = candidates(60, 12);
    let registrations = sortition_generation(&state, &bodies, 0, &snapshot, 10, logical);
    assert!(
        registrations
            .iter()
            .all(|entry| entry.request.pulse_height == 20),
        "the fixture delay and epoch length place the generation on slot 20"
    );
    state
        .register_sortition_request_batch(id, registrations, snapshot)
        .expect("register the two-body generation on slot 20");
    state.validate().expect("the shared generation persists");

    // Request height 9 also aligns to slot 20 on its own, so only the rule that one
    // generation shares one request height refuses a hand-built divergent body.
    assert_eq!(
        state.derived_sortition_generation_pulse_height_v1(9, None),
        Some(20)
    );
    for body in bodies {
        let mut divergent = state.clone();
        let request = &mut divergent
            .elections
            .get_mut(&BodyElectionAttemptId::derive_v1(id, body, 0))
            .expect("registered election")
            .attempt
            .request;
        request.request_height = 9;
        request.id = request.canonical_id();
        assert_eq!(
            divergent.validate(),
            Err(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule),
            "{body:?} claims another request height inside the shared generation"
        );
    }
}
