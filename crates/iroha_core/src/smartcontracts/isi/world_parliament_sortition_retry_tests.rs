// Execute-level coverage of the planned no-roster sortition retry: the exact next generation
// the driver plan advises is the one Core admits, by anyone for an SCCP attempt and through
// the Parliament manager otherwise.

/// Seed a qualified attempt of `proposal` whose complete initial generation, requested at
/// height 1, consumed the pulse of its exact slot and failed without a roster because
/// nobody accepted before the invitation window closed.
fn seed_parliament_no_roster_retry_fixture(
    state_transaction: &mut StateTransaction<'_, '_>,
    proposal: ProposalKind,
) -> (GovernanceAttemptId, Vec<RequiredParliamentBodyV1>) {
    const REQUEST_HEIGHT: u64 = 1;
    const PULSE_DELAY: u64 = 4;

    let proposal_id = proposal.fingerprint();
    let proposal_content_id = ProposalContentId::new(proposal_id);
    let governance_attempt_id = GovernanceAttemptId::derive_v1(proposal_content_id, 0);
    let (risk_tier, requirements) = parliament_attempt_policy_v1(&proposal);
    let mut governance = parliament_test_governance(&requirements);
    governance.citizenship_bond_amount = Quantity::from(10_u64);
    governance.parliament_sortition_pulse_delay_blocks = PULSE_DELAY;
    state_transaction.gov = governance;
    let expected_head = parliament_expected_head_v1(&proposal, state_transaction)
        .expect("derive the actual proposal subject head");
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
        PULSE_DELAY,
        // The initial slot `REQUEST_HEIGHT + PULSE_DELAY` is the first native pulse height.
        REQUEST_HEIGHT + PULSE_DELAY + 1,
        proposal.effect_preimage_hash_v1(),
        expected_head,
        requirements.clone(),
    )
    .expect("create the retry attempt");
    attempt
        .complete_qualification(governance_attempt_id)
        .expect("complete qualification");

    let candidates = parliament_test_candidates();
    for candidate in &candidates {
        insert_parliament_initial_sortition_citizen(state_transaction, candidate, 10);
    }
    let candidate_count = u32::try_from(candidates.len()).expect("fixture candidate count fits");
    let beacon_session_id = BeaconSessionId::for_network_v1(&state_transaction.network_id);
    let registrations = requirements
        .iter()
        .map(|required| gov::ParliamentSortitionRequestRegistrationV1 {
            sequence: 0,
            request: SortitionRequestV1::try_new_canonical(
                governance_attempt_id,
                BodyElectionAttemptId::derive_v1(governance_attempt_id, required.body, 0),
                required.body,
                parliament_candidate_root_v1(governance_attempt_id, required.body, &candidates),
                candidate_count,
                3,
                REQUEST_HEIGHT,
                REQUEST_HEIGHT + PULSE_DELAY,
                beacon_session_id,
                None,
            )
            .expect("canonical initial request"),
        })
        .collect();
    attempt
        .register_sortition_request_batch(governance_attempt_id, registrations, candidates)
        .expect("register the initial generation");
    attempt
        .fail_sortition_generation_with_empty_roster_for_tests(
            BodyElectionAttemptId::derive_v1(governance_attempt_id, requirements[0].body, 0),
            iroha_data_model::governance::types::BeaconPulseId::new([0xE5; 32]),
            &state_transaction.network_id,
            &state_transaction.gov,
            REQUEST_HEIGHT + PULSE_DELAY + 1,
        )
        .expect("the consumed initial pulse left every roster empty");

    state_transaction
        .world
        .put_governance_proposal(
            proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: ALICE_ID.clone(),
                kind: proposal,
                created_height: REQUEST_HEIGHT,
                status: crate::state::GovernanceProposalStatus::Proposed,
            },
        )
        .expect("store proposal");
    state_transaction
        .world
        .put_parliament_attempt(attempt)
        .expect("store the failed attempt");
    (governance_attempt_id, requirements)
}

/// The single exact transition the driver plan advises for the containing block.
fn planned_parliament_sortition_retry(
    state_transaction: &StateTransaction<'_, '_>,
    governance_attempt_id: GovernanceAttemptId,
) -> gov::SubmitParliamentLifecycleTransitionV1 {
    let execution_height = state_transaction.block_height();
    let plan = state_transaction
        .world
        .parliament_attempts
        .get(&governance_attempt_id)
        .expect("retained failed attempt")
        .plan_driver_v1(
            &crate::governance::parliament::WorldPlanInputsV1 {
                world: &state_transaction.world,
                network_id: &state_transaction.network_id,
            },
            &state_transaction.network_id,
            &state_transaction.gov,
            execution_height - 1,
            execution_height,
        );
    assert!(plan.due.is_empty(), "{plan:?}");
    let [exact] = plan.exact.as_slice() else {
        panic!("one exact retry: {plan:?}");
    };
    assert_eq!(exact.height, execution_height);
    assert!(
        matches!(
            exact.transition,
            gov::ParliamentLifecycleTransitionV1::RegisterSortitionRequest(_)
        ),
        "{exact:?}"
    );
    gov::SubmitParliamentLifecycleTransitionV1 {
        governance_attempt_id,
        transition: exact.transition.clone(),
    }
}

fn assert_parliament_generation_redrawn(
    state_transaction: &StateTransaction<'_, '_>,
    governance_attempt_id: GovernanceAttemptId,
    requirements: &[RequiredParliamentBodyV1],
) {
    let attempt = state_transaction
        .world
        .parliament_attempts
        .get(&governance_attempt_id)
        .expect("persisted retry");
    for required in requirements {
        let retry = attempt
            .election(&BodyElectionAttemptId::derive_v1(
                governance_attempt_id,
                required.body,
                1,
            ))
            .expect("every failed body is redrawn")
            .attempt();
        assert_eq!(retry.status, BodyElectionAttemptStatusV1::AwaitingPulse);
        assert_eq!(
            retry.request.request_height,
            state_transaction.block_height()
        );
    }
    attempt
        .validate()
        .expect("the redrawn generation survives reducer validation");
}

fn parliament_retry_block_header() -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(10).expect("nonzero height"),
        None,
        None,
        0,
        0,
    )
}

#[test]
fn parliament_planned_sccp_sortition_retry_is_permissionless_and_admitted() {
    let state = blank_test_state();
    let mut block = state.block(parliament_retry_block_header());
    let mut state_transaction = block.transaction();
    let proposal = sccp_route_governance_test_kind(&sccp_route_governance_test_proposal(
        state_transaction.network_id,
    ));
    let (governance_attempt_id, requirements) =
        seed_parliament_no_roster_retry_fixture(&mut state_transaction, proposal);
    let manager: Permission = CanManageParliament.into();
    assert!(!has_exact_permission(
        &state_transaction.world,
        &BOB_ID,
        &manager
    ));

    planned_parliament_sortition_retry(&state_transaction, governance_attempt_id)
        .execute(&BOB_ID, &mut state_transaction)
        .expect("anyone may submit the planned SCCP retry");
    assert_parliament_generation_redrawn(&state_transaction, governance_attempt_id, &requirements);
}

#[test]
fn parliament_planned_sortition_retry_is_manager_intent_outside_sccp() {
    let state = blank_test_state();
    let mut block = state.block(parliament_retry_block_header());
    let mut state_transaction = block.transaction();
    let (governance_attempt_id, requirements) = seed_parliament_no_roster_retry_fixture(
        &mut state_transaction,
        parliament_permissionless_progress_proposal(),
    );
    state_transaction.world.account_permissions.insert(
        ALICE_ID.clone(),
        BTreeSet::from([Permission::from(CanManageParliament)]),
    );
    let retry = planned_parliament_sortition_retry(&state_transaction, governance_attempt_id);

    let error = retry
        .clone()
        .execute(&BOB_ID, &mut state_transaction)
        .expect_err("a non-manager cannot submit request intent");
    assert!(format!("{error:?}").contains("CanManageParliament"));
    retry
        .execute(&ALICE_ID, &mut state_transaction)
        .expect("the manager submits the exact planned retry");
    assert_parliament_generation_redrawn(&state_transaction, governance_attempt_id, &requirements);
}
