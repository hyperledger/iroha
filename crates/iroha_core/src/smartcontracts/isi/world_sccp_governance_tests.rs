// SCCP v1 route-governance intake, its per-subject Parliament head, and the
// fail-closed generic bridge-proof verifier gate.
// TODO(ws33): drive certificate enactment end to end (including due-certificate
// execution failures) in `crates/iroha_core/tests/sccp_governance.rs`.

fn sccp_route_governance_test_proposal(
    network_id: iroha_data_model::NetworkId,
) -> iroha_data_model::sccp::governance::SccpGovernanceProposalV1 {
    use iroha_data_model::sccp::{
        governance::{
            SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
            SccpSetParametersActionV1,
        },
        params::SccpParametersV1,
    };
    SccpGovernanceProposalV1 {
        network_id,
        base_revisions: vec![(SccpGovernanceSubjectV1::Parameters, 0).into()],
        actions: vec![SccpGovernanceActionV1::SetParameters(
            SccpSetParametersActionV1 {
                next: SccpParametersV1::taira_default(),
            },
        )],
    }
}

fn bond_sccp_route_governance_test_proposer(state_transaction: &mut StateTransaction<'_, '_>) {
    state_transaction.gov.citizenship_bond_amount = Quantity::from(10_u32);
    state_transaction.world.citizens.insert(
        ALICE_ID.clone(),
        crate::state::CitizenshipRecord::new(ALICE_ID.clone(), Quantity::from(10_u32), 1),
    );
}

fn sccp_route_governance_test_kind(
    proposal: &iroha_data_model::sccp::governance::SccpGovernanceProposalV1,
) -> ProposalKind {
    ProposalKind::SccpRouteGovernance(
        iroha_data_model::governance::types::SccpRouteGovernanceProposal {
            proposal: Box::new(proposal.clone()),
        },
    )
}

world_test!(sccp_route_governance_proposal_rejects_statically_invalid_proposals {
    blank_test_state_transaction!(checked state, block, stx);
    bond_sccp_route_governance_test_proposer(&mut stx);
    let foreign = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign SCCP network")),
    );
    assert_ne!(foreign, stx.network_id);
    let mut without_actions = sccp_route_governance_test_proposal(stx.network_id);
    without_actions.actions.clear();
    for (proposal, needle) in [
        (sccp_route_governance_test_proposal(foreign), "network_id"),
        (without_actions, "no actions"),
    ] {
        let error = gov::ProposeSccpRouteGovernance { proposal }
            .execute(&ALICE_ID, &mut stx)
            .expect_err("a statically invalid SCCP proposal must be rejected");
        assert!(
            matches!(&error, InstructionExecutionError::InvariantViolation(message)
                if message.contains(needle)),
            "unexpected static rejection: {error:?}"
        );
    }
    assert!(stx.world.governance_proposals.iter().next().is_none());
});

world_test!(sccp_route_governance_proposal_requires_permission_or_bond {
    blank_test_state_transaction!(checked state, block, stx);
    let proposal = sccp_route_governance_test_proposal(stx.network_id);
    let error = gov::ProposeSccpRouteGovernance {
        proposal: proposal.clone(),
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("an unbonded account without the proposer permission must be rejected");
    assert!(
        matches!(&error, InstructionExecutionError::InvariantViolation(message)
            if message.contains("CanProposeSccpRouteGovernance required")),
        "unexpected proposer rejection: {error:?}"
    );
    assert!(stx.world.governance_proposals.iter().next().is_none());
    stx.world.account_permissions.insert(
        ALICE_ID.clone(),
        BTreeSet::from([Permission::from(
            iroha_executor_data_model::permission::sccp::CanProposeSccpRouteGovernance,
        )]),
    );
    let before_events = stx.world.internal_event_buf.len();
    let error = gov::ProposeSccpRouteGovernance { proposal }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("SCCP proposer permission must not bypass the Parliament ballot gate");
    assert!(error.to_string().contains("ParliamentBallotUnavailable"));
    assert!(stx.world.governance_proposals.iter().next().is_none());
    assert_eq!(stx.world.internal_event_buf.len(), before_events);
});

world_test!(sccp_route_governance_storage_records_once_and_replays_idempotently {
    blank_test_state_transaction!(checked state, block, stx);
    bond_sccp_route_governance_test_proposer(&mut stx);
    let proposal = sccp_route_governance_test_proposal(stx.network_id);
    record_sccp_route_governance_proposal(proposal.clone(), &ALICE_ID, &mut stx)
        .expect("proposal storage component");
    let kind = sccp_route_governance_test_kind(&proposal);
    let proposal_id = kind.fingerprint();
    let record = stx
        .world
        .governance_proposals
        .get(&proposal_id)
        .expect("canonical SCCP route-governance proposal");
    assert_eq!(record.kind, kind);
    assert_eq!(record.proposer, ALICE_ID.clone());
    assert_eq!(
        record.status,
        crate::state::GovernanceProposalStatus::Proposed
    );
    let before = norito::codec::Encode::encode(record);
    record_sccp_route_governance_proposal(proposal.clone(), &ALICE_ID, &mut stx)
        .expect("an exact storage replay is idempotent");
    assert_eq!(stx.world.governance_proposals.iter().count(), 1);
    assert_eq!(
        stx.world
            .governance_proposals
            .get(&proposal_id)
            .map(norito::codec::Encode::encode),
        Some(before.clone())
    );
    let events = stx.world.internal_event_buf.len();
    let error = gov::ProposeSccpRouteGovernance { proposal }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("a bonded citizen or existing record cannot bypass the ballot gate");
    assert!(error.to_string().contains("ParliamentBallotUnavailable"));
    assert_eq!(stx.world.governance_proposals.get(&proposal_id).map(norito::codec::Encode::encode), Some(before));
    assert_eq!(stx.world.internal_event_buf.len(), events);
});

world_test!(sccp_route_governance_expected_head_is_scoped_per_subject {
    let state = blank_test_state();
    let mut block = state.block(first_test_block_header_with_checked_height());
    let mut stx = block.transaction();
    let kind = sccp_route_governance_test_kind(&sccp_route_governance_test_proposal(
        stx.network_id,
    ));
    let subject_id = kind.governed_subject_id_v1().expect("subject id");
    let GovernanceExpectedHeadV1::Present(fresh) =
        parliament_expected_head_v1(&kind, &stx).expect("head")
    else {
        panic!("an SCCP head is always present");
    };
    assert_eq!(fresh.subject_id, subject_id);
    assert_eq!(fresh.version, 1);
    let parameters = iroha_data_model::sccp::governance::SccpGovernanceSubjectV1::Parameters;
    assert_eq!(
        fresh.head_root,
        parliament_governance_head_root_v1(&vec![(parameters.clone(), 0_u64)])
    );
    // Another subject's revision leaves the head unchanged; this subject's revision moves it.
    crate::smartcontracts::isi::sccp::store::set_governance_revision(
        &mut stx,
        iroha_data_model::sccp::governance::SccpGovernanceSubjectV1::LightClient(
            iroha_data_model::bridge::SccpNetworkV1::EthereumMainnet,
        ),
        4,
    );
    assert_eq!(
        parliament_expected_head_v1(&kind, &stx).expect("head"),
        GovernanceExpectedHeadV1::Present(fresh.clone())
    );
    crate::smartcontracts::isi::sccp::store::set_governance_revision(&mut stx, parameters, 2);
    let GovernanceExpectedHeadV1::Present(moved) =
        parliament_expected_head_v1(&kind, &stx).expect("head")
    else {
        panic!("an SCCP head is always present");
    };
    assert_eq!(moved.version, 3);
    assert_ne!(moved.head_root, fresh.head_root);
});

world_test!(bridge_payloads_without_an_authoritative_verifier_fail_closed {
    let ics = BridgeProofPayload::Ics(iroha_data_model::bridge::BridgeIcsProof {
        verifier_manifest_hash: [0xAA; 32],
        state_root: [0x11; 32],
        leaf_hash: [0x22; 32],
        proof: iroha_crypto::MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(vec![
            [0x22; 32],
            [0x33; 32],
        ])
        .get_proof(0)
        .expect("fixture Merkle proof"),
        hash_function: iroha_data_model::bridge::BridgeHashFunction::Sha256,
    });
    let transparent = BridgeProofPayload::TransparentZk(BridgeTransparentProof {
        verifier_manifest_hash: [0xBB; 32],
        proof: ProofBox::new("halo2/mock".into(), vec![0xDE, 0xAD]),
        recursion_depth: Some(1),
    });
    for payload in [ics, transparent] {
        let error = reject_unverifiable_bridge_payload(&payload)
            .expect_err("a payload without an on-chain verifier must fail closed");
        assert!(
            format!("{error:?}").contains("authoritative on-chain verifier"),
            "unexpected bridge payload rejection: {error:?}"
        );
    }
});

world_test!(sccp_governance_proposals_list_open_proposals_with_their_admissibility {
    use crate::smartcontracts::isi::sccp::{read, store};
    blank_test_state_transaction!(checked state, block, stx);
    bond_sccp_route_governance_test_proposer(&mut stx);
    assert!(read::governance_proposals(&*stx.world).is_empty());
    let proposal = sccp_route_governance_test_proposal(stx.network_id);
    record_sccp_route_governance_proposal(proposal.clone(), &ALICE_ID, &mut stx)
        .expect("proposal listing DATA; not a qualified ballot or admitted proposal");
    let listed = read::governance_proposals(&*stx.world);
    let [open] = listed.as_slice() else {
        panic!("one open proposal: {listed:?}");
    };
    assert_eq!(open.proposal, proposal);
    assert_eq!(
        open.content_id,
        iroha_data_model::governance::types::ProposalContentId::derive_v1(
            &sccp_route_governance_test_kind(&proposal)
        )
    );
    assert!(open.admissible);
    assert_eq!(open.latest_attempt, None);
    // Another enactment moved the subject, so no attempt can pass the preflight any more.
    store::set_governance_revision(
        &mut stx,
        iroha_data_model::sccp::governance::SccpGovernanceSubjectV1::Parameters,
        1,
    );
    let listed = read::governance_proposals(&*stx.world);
    assert!(!listed[0].admissible);
});

// This fixture establishes a route and retained pause before running the real stored,
// validated due-certificate executor. It qualifies effect/cause binding and rollback, not
// route registration, current PQ ballot production, or emergency-pause establishment.
fn seed_due_sccp_control_certificate(
    stx: &mut StateTransaction<'_, '_>,
    paused: bool,
) -> DueParliamentCertificateFixture {
    use crate::smartcontracts::isi::sccp::{
        pause_record::RetainedSccpFastPause, store, test_support,
    };
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        sccp::{
            governance::{
                SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
                SccpSetDestinationPausedActionV1,
            },
            params::SccpParametersV1,
        },
    };
    let network = SccpNetworkV1::EthereumMainnet;
    store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
    let mut route = test_support::sample_route(network);
    route.revisions.get_mut(&1).unwrap().destination_paused = !paused;
    store::routes::insert(stx, network, route).unwrap();
    let mut pause = test_support::sample_fast_pause(1);
    pause.enacted_at_ms = stx.block_unix_timestamp_ms();
    pause.until_ms = pause.enacted_at_ms.checked_add(10_000).unwrap();
    let retained = RetainedSccpFastPause::admit(&pause, &stx.execution_budget()).unwrap();
    store::fast_pauses::insert(stx, network, retained).unwrap();
    let proposal = SccpGovernanceProposalV1 {
        network_id: stx.network_id,
        base_revisions: vec![(SccpGovernanceSubjectV1::RouteControl(network), 0).into()],
        actions: vec![SccpGovernanceActionV1::SetDestinationPaused(
            SccpSetDestinationPausedActionV1 {
                network,
                revision: 1,
                paused,
            },
        )],
    };
    seed_due_parliament_certificate(stx, sccp_route_governance_test_kind(&proposal))
}

#[test]
fn parliament_due_sccp_control_binds_exact_certificate_and_complete_pause_state() {
    use crate::smartcontracts::isi::sccp::store;
    use iroha_data_model::{bridge::SccpNetworkV1, sccp::events::SccpEvent};
    use iroha_sccp::v1::control::{ControlLeafV1, control_leaf};

    for paused in [false, true] {
        let state = blank_test_state();
        let block =
            new_dummy_block_at_height(NonZeroU64::new(PARLIAMENT_DUE_CERTIFICATE_HEIGHT).unwrap());
        let mut state_block = state.block(block.as_ref().header());
        let fixture = {
            let mut seed = state_block.transaction();
            let fixture = seed_due_sccp_control_certificate(&mut seed, paused);
            seed.apply();
            fixture
        };
        let network = SccpNetworkV1::EthereumMainnet;
        let original_pause = store::fast_pauses::get(&state_block.world, &network)
            .unwrap()
            .clone();
        let mut execution = state_block.transaction();
        assert_eq!(
            execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution)
                .unwrap(),
            DueParliamentCertificateExecutionV1::Applied
        );
        let expected_id = *GovernanceCertificateId::derive_v1(&fixture.certificate).as_bytes();
        assert_ne!(expected_id, fixture.proposal_id);
        let row = *store::control_messages::get(&*execution.world, &(network, 1, 1)).unwrap();
        assert_eq!(
            (row.track, row.parliament_paused, row.fast_pause_until_ms),
            (1, paused, original_pause.until_ms),
            "control record must preserve both original pause owners"
        );
        assert_eq!(
            row.certificate_id, expected_id,
            "control record must bind the exact enacting governance certificate"
        );
        assert_eq!(row.effect_hash, fixture.certificate.effect_preimage_hash);
        assert_eq!(
            (row.height, row.commitment_index),
            (PARLIAMENT_DUE_CERTIFICATE_HEIGHT, 0)
        );
        let revision = &store::routes::get(&*execution.world, &network)
            .unwrap()
            .revisions[&1];
        assert_eq!(
            row.leaf,
            control_leaf(
                execution.network_id.as_bytes(),
                network,
                &revision.destination_word,
                &ControlLeafV1 {
                    route_revision: 1,
                    control_nonce: 1,
                    track: 1,
                    parliament_paused: u8::from(paused),
                    fast_pause_until_ms: original_pause.until_ms,
                    certificate_id: expected_id,
                    effect_hash: fixture.certificate.effect_preimage_hash,
                }
            )
            .unwrap()
        );
        assert_eq!(revision.destination_paused, paused);
        assert_eq!(revision.next_control_nonce, 2);
        assert_eq!(
            store::fast_pauses::get(&*execution.world, &network),
            Some(&original_pause)
        );
        assert!(execution.world.internal_event_buf.iter().any(
            |event| matches!(event.as_ref(), DataEvent::Sccp(SccpEvent::ControlRecorded(event))
                if event.certificate_id == expected_id && event.track == 1
                    && event.parliament_paused == paused
                    && event.fast_pause_until_ms == original_pause.until_ms)
        ));
        assert_automatic_parliament_execution_event(
            &execution,
            &fixture,
            gov::ParliamentAutomaticExecutionOutcomeV1::Enacted,
        );
        execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution)
            .expect_err("the same certificate cannot record a second control");
        assert_eq!(store::control_messages::len(&*execution.world), 1);
    }
}

#[test]
fn parliament_due_sccp_control_full_block_rolls_back_flag_nonce_and_cause() {
    use crate::smartcontracts::isi::sccp::{leaves, store};
    use iroha_data_model::{bridge::SccpNetworkV1, sccp::control::SccpLeafRefV1};
    let state = blank_test_state();
    let block =
        new_dummy_block_at_height(NonZeroU64::new(PARLIAMENT_DUE_CERTIFICATE_HEIGHT).unwrap());
    let mut state_block = state.block(block.as_ref().header());
    let fixture = {
        let mut seed = state_block.transaction();
        let fixture = seed_due_sccp_control_certificate(&mut seed, true);
        for index in 0..leaves::MAX_LEAVES_PER_BLOCK {
            leaves::allocate_leaf(&mut seed, SccpLeafRefV1::transfer([index as u8; 32])).unwrap();
        }
        seed.apply();
        fixture
    };
    let network = SccpNetworkV1::EthereumMainnet;
    let original_route = store::routes::get(&state_block.world, &network)
        .unwrap()
        .clone();
    let original_pause = store::fast_pauses::get(&state_block.world, &network)
        .unwrap()
        .clone();
    {
        let mut execution = state_block.transaction();
        assert!(
            matches!(execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution).unwrap(),
            DueParliamentCertificateExecutionV1::EffectFailed { failure_root }
                if failure_root == parliament_execution_failure_root_v1(&fixture.certificate, PARLIAMENT_DUE_CERTIFICATE_HEIGHT))
        );
        // The actual production block-start caller drops this isolated effect on failure.
    }
    assert_eq!(
        store::routes::get(&state_block.world, &network),
        Some(&original_route)
    );
    assert_eq!(
        store::fast_pauses::get(&state_block.world, &network),
        Some(&original_pause)
    );
    assert!(store::control_messages::is_empty(&state_block.world));
    assert_eq!(
        leaves::leaf_count_at(&state_block.world, PARLIAMENT_DUE_CERTIFICATE_HEIGHT),
        leaves::MAX_LEAVES_PER_BLOCK as usize
    );
}
