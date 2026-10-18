// Execute-level coverage of the sortition cadence a Parliament attempt freezes at creation:
// the consensus-native NPoS epoch length comes from committed state only, and a chain without
// that cadence creates no attempt.

/// Seed an admitted proposal and the manager permission, and return the creation instruction.
fn seed_parliament_attempt_cadence_fixture(
    state_transaction: &mut StateTransaction<'_, '_>,
) -> gov::CreateParliamentGovernanceAttemptV1 {
    let proposal = parliament_permissionless_progress_proposal();
    state_transaction.world.account_permissions.insert(
        ALICE_ID.clone(),
        BTreeSet::from([Permission::from(CanManageParliament)]),
    );
    state_transaction
        .world
        .put_governance_proposal(
            proposal.fingerprint(),
            crate::state::GovernanceProposalRecord {
                proposer: ALICE_ID.clone(),
                kind: proposal.clone(),
                created_height: 1,
                status: crate::state::GovernanceProposalStatus::Proposed,
            },
        )
        .expect("store proposal");
    for candidate in &parliament_test_candidates() {
        insert_parliament_initial_sortition_citizen(state_transaction, candidate, 10);
    }
    gov::CreateParliamentGovernanceAttemptV1 {
        proposal,
        attempt_sequence: 0,
    }
}

/// Assert that a rejected creation stored nothing and touched no Parliament index.
fn assert_no_parliament_attempt_state(
    state_transaction: &StateTransaction<'_, '_>,
    create: &gov::CreateParliamentGovernanceAttemptV1,
) {
    let world = &state_transaction.world;
    assert!(
        world
            .parliament_attempts
            .get(&create.governance_attempt_id())
            .is_none()
    );
    assert_eq!(world.parliament_attempts.iter().count(), 0);
    assert_eq!(
        *world.parliament_attempt_counts.get(),
        crate::state::ParliamentAttemptCountsV1::default()
    );
    assert_eq!(world.parliament_member_reference_counts.iter().count(), 0);
    assert_eq!(
        world.parliament_required_beacon_pulse_slots.iter().count(),
        0
    );
    assert_eq!(world.parliament_certified_enactments.iter().count(), 0);
    assert_eq!(
        world
            .governance_proposals
            .get(&create.proposal.fingerprint())
            .expect("retained proposal")
            .status,
        crate::state::GovernanceProposalStatus::Proposed
    );
}

fn assert_parliament_cadence_rejection(
    state_transaction: &mut StateTransaction<'_, '_>,
    create: &gov::CreateParliamentGovernanceAttemptV1,
    scenario: &str,
) {
    let error = create
        .clone()
        .execute(&ALICE_ID, state_transaction)
        .expect_err(scenario);
    assert!(
        format!("{error:?}").contains(PARLIAMENT_SORTITION_REQUIRES_NPOS_CADENCE_V1),
        "{scenario}: {error:?}"
    );
    assert_no_parliament_attempt_state(state_transaction, create);
}

#[test]
fn parliament_attempt_creation_is_rejected_without_the_native_npos_cadence() {
    use iroha_data_model::parameter::system::SumeragiConsensusMode;

    assert_eq!(
        PARLIAMENT_SORTITION_REQUIRES_NPOS_CADENCE_V1,
        "Parliament sortition requires the consensus-native NPoS pulse cadence"
    );

    // A Permissioned chain: neither an NPoS policy nor a schedule (as inside genesis).
    let mut state = blank_test_state();
    configure_parliament_fixture_state(
        &mut state,
        &parliament_permissionless_progress_proposal(),
        4,
    );
    let mut block = state.block(first_test_block_header());
    let mut state_transaction = block.transaction();
    let create = seed_parliament_attempt_cadence_fixture(&mut state_transaction);
    assert_parliament_cadence_rejection(
        &mut state_transaction,
        &create,
        "a chain without an NPoS policy and a schedule has no native pulse cadence",
    );

    // A Permissioned chain after genesis: a committed Permissioned schedule, no NPoS policy.
    // Its mutable Sumeragi `epoch_length_blocks` parameter is never a cadence.
    crate::governance::parliament::seed_consensus_schedule_for_tests(
        &mut state_transaction,
        SumeragiConsensusMode::Permissioned,
        10,
    );
    assert!(
        state_transaction
            .world
            .sumeragi_npos_parameters()
            .expect("policy decoder completes")
            .is_none()
    );
    assert_parliament_cadence_rejection(
        &mut state_transaction,
        &create,
        "a Permissioned chain has no native pulse cadence",
    );

    // The NPoS policy alone, with a Permissioned schedule: the signals disagree.
    crate::governance::parliament::seed_npos_policy_for_tests(&mut state_transaction, 10);
    assert_parliament_cadence_rejection(
        &mut state_transaction,
        &create,
        "an NPoS policy cannot override a Permissioned schedule",
    );
    drop(state_transaction);
    drop(block);

    // The NPoS policy before any schedule exists, as inside genesis execution.
    let mut state = blank_test_state();
    configure_parliament_fixture_state(
        &mut state,
        &parliament_permissionless_progress_proposal(),
        4,
    );
    let mut block = state.block(first_test_block_header());
    let mut state_transaction = block.transaction();
    let create = seed_parliament_attempt_cadence_fixture(&mut state_transaction);
    crate::governance::parliament::seed_npos_policy_for_tests(&mut state_transaction, 10);
    assert_parliament_cadence_rejection(
        &mut state_transaction,
        &create,
        "genesis execution has no committed schedule",
    );

    // An NPoS schedule whose epoch does not end on a multiple of the policy length.
    crate::governance::parliament::seed_consensus_schedule_for_tests(
        &mut state_transaction,
        SumeragiConsensusMode::Npos,
        7,
    );
    assert_parliament_cadence_rejection(
        &mut state_transaction,
        &create,
        "the committed schedule and the NPoS policy must agree",
    );
}

#[test]
fn parliament_attempt_creation_freezes_the_committed_npos_epoch_length() {
    let mut state = blank_test_state();
    configure_parliament_fixture_state(
        &mut state,
        &parliament_permissionless_progress_proposal(),
        4,
    );
    let mut block = state.block(first_test_block_header());
    let mut state_transaction = block.transaction();
    let create = seed_parliament_attempt_cadence_fixture(&mut state_transaction);
    crate::governance::parliament::seed_npos_sortition_cadence_for_tests(
        &mut state_transaction,
        10,
    );
    let governance_attempt_id = create.governance_attempt_id();
    create
        .execute(&ALICE_ID, &mut state_transaction)
        .expect("an NPoS chain creates the attempt");
    let attempt = state_transaction
        .world
        .parliament_attempts
        .get(&governance_attempt_id)
        .expect("stored attempt");
    assert_eq!(attempt.sortition_pulse_epoch_length_blocks(), 10);
    assert_eq!(attempt.sortition_pulse_delay_blocks(), 4);
    attempt.validate().expect("the frozen geometry persists");

    // Later node-local governance configuration cannot move the frozen geometry, and the
    // executor derives the initial slot from the frozen fields alone: the request in block 1
    // targets height 9, the first native pulse height at or after the four-block delay.
    state_transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("retain the attempt's original cadence before policy change");
    state.gov.parliament_sortition_pulse_delay_blocks = 99;
    let mut block = state.block(first_test_block_header());
    let mut state_transaction = block.transaction();
    gov::SubmitParliamentLifecycleTransitionV1 {
        governance_attempt_id,
        transition: gov::ParliamentLifecycleTransitionV1::CompleteQualification,
    }
    .execute(&ALICE_ID, &mut state_transaction)
    .expect("complete qualification");
    initial_parliament_sortition_intent(governance_attempt_id)
        .execute(&ALICE_ID, &mut state_transaction)
        .expect("register the canonical initial generation");
    let attempt = state_transaction
        .world
        .parliament_attempts
        .get(&governance_attempt_id)
        .expect("stored attempt");
    let beacon_session_id = BeaconSessionId::for_network_v1(&state_transaction.network_id);
    let requirements = attempt.required_bodies().to_vec();
    assert!(!requirements.is_empty());
    for required in &requirements {
        let request = attempt
            .election(&BodyElectionAttemptId::derive_v1(
                governance_attempt_id,
                required.body,
                0,
            ))
            .expect("every initial body")
            .attempt()
            .request;
        assert_eq!(request.request_height, 1);
        assert_eq!(request.pulse_height, 9);
        assert_eq!(request.beacon_session_id, beacon_session_id);
    }
    assert_eq!(
        attempt.next_sortition_generation_pulse_height_v1(2, beacon_session_id),
        Some(19),
        "a later generation targets the next native boundary"
    );
    attempt
        .validate()
        .expect("the aligned initial generation persists");
}
