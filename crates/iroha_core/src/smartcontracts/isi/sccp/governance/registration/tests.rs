//! Native registration pin, handoff, original-scope and deployment controls.
//! Component fixtures do not open the unavailable P0/P5 launch authority.

use super::*;
use crate::state::sccp_generation_custody::GenerationFixtureStorage as _;
use crate::{
    smartcontracts::isi::sccp::{
        generation::{SccpGenerationEndV1, SccpGenerationMemberV1},
        test_support::{authority, blank_state, header, sample_generation, sample_pin},
    },
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        deployment::{SccpEvmDeploymentV1, SccpTonCodeRefV1, SccpTonDeploymentV1},
        registry::SccpRouteRevisionV1,
    },
};
use iroha_model_base::topology::LaneId;

fn resolved(generation: u64, height: u64) -> SccpCommitteeGenerationV1 {
    let mut record = sample_generation(generation, height);
    // Explicit retained registration DATA, not a registration lookup or a finality claim.
    record.members = (1..=4)
        .map(|seed| {
            Some(SccpGenerationMemberV1 {
                lane_id: LaneId::new(0),
                validator: authority(seed),
                activation_height: 1,
            })
        })
        .collect();
    record
}

fn install(stx: &mut StateTransaction<'_, '_>, records: &[SccpCommitteeGenerationV1]) {
    for record in records {
        store::committee_generations::insert(stx, record.generation, record.clone()).unwrap();
    }
    store::committee_current::set(stx, records.last().unwrap().generation);
}

fn two_generations() -> [SccpCommitteeGenerationV1; 2] {
    let mut first = resolved(1, 1);
    let mut second = resolved(2, 3);
    second.start_timestamp_ms = 8_000;
    second.start_lc = 8_000;
    second.deadline_ms = second.start_timestamp_ms + second.validity_ms;
    second.liable_until_lc = second.start_lc + second.validity_ms + second.grace_ms;
    first.end = Some(SccpGenerationEndV1 {
        end_height: 2,
        end_timestamp_ms: 8_000,
        next_committee_root: second.committee_root,
        successor_validity_ms: second.validity_ms,
    });
    [first, second]
}

#[test]
fn pin_matches_all_four_retained_coordinates_and_initial_floor() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let record = resolved(1, 1);
    install(&mut stx, &[record.clone()]);
    let pin = sample_pin(&record);
    assert_eq!(
        retained_pin(&*stx.world, &pin, 16_000, 86_400_000, 3).unwrap(),
        &record
    );
    for bad in [
        SccpCommitteePinV1 {
            generation: 2,
            ..pin
        },
        SccpCommitteePinV1 {
            committee_root: [7; 32],
            ..pin
        },
        SccpCommitteePinV1 {
            start_height: 2,
            ..pin
        },
        SccpCommitteePinV1 {
            until_ms: pin.until_ms + 1,
            ..pin
        },
        SccpCommitteePinV1 {
            generation: 0,
            ..pin
        },
    ] {
        assert!(retained_pin(&*stx.world, &bad, 16_000, 86_400_000, 3).is_err());
    }
    let revision = SccpRouteRevisionV1::staged(
        1,
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [3; 20],
            runtime_code_hash: [4; 32],
        }),
        pin,
        100,
        4,
    );
    assert_eq!(revision.initial_committee, pin);
    assert_eq!(revision.forgery_floor, pin.generation);
    assert_eq!(revision.quarantine, None);
}

#[test]
fn every_intervening_generation_needs_resolved_members_and_a_genuine_handoff() {
    for variant in 0..7 {
        let state = blank_state();
        let mut block = state.block(header(4));
        let mut stx = block.transaction();
        let mut records = two_generations();
        match variant {
            0 => {}
            1 => records[1].members[0] = None,
            2 => records[0].end = None,
            3 => records[0].end.as_mut().unwrap().next_committee_root = [0x55; 32],
            4 => records[1].cause = SccpGenerationCauseV1::Resync,
            5 => records[0].end.as_mut().unwrap().successor_validity_ms -= 1,
            6 => records[1].generation = 3,
            _ => unreachable!(),
        }
        let pin = sample_pin(&records[0]);
        install(&mut stx, &records);
        let result = retained_pin(&*stx.world, &pin, 16_000, 86_400_000, 3);
        assert_eq!(result.is_ok(), variant == 0, "variant {variant}");
    }
}

#[test]
fn deadline_is_inclusive_checks_successors_and_never_saturates_a_required_margin() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let mut records = two_generations();
    records[1].validity_ms = 900_000_000;
    records[1].deadline_ms = records[1].start_timestamp_ms + records[1].validity_ms;
    records[1].liable_until_lc = records[1].start_lc + records[1].validity_ms + records[1].grace_ms;
    records[0].end.as_mut().unwrap().successor_validity_ms = records[1].validity_ms;
    let pin = sample_pin(&records[0]);
    install(&mut stx, &records);
    let heartbeat = 86_400_000;
    let boundary = records[1].deadline_ms - heartbeat - PIN_MARGIN_MS;
    assert!(retained_pin(&*stx.world, &pin, boundary, heartbeat, 3).is_ok());
    assert!(pin.until_ms > records[1].deadline_ms);
    assert!(retained_pin(&*stx.world, &pin, boundary + 1, heartbeat, 3).is_err());
    for (now, heartbeat) in [(u64::MAX, 0), (1, u64::MAX)] {
        assert!(retained_pin(&*stx.world, &pin, now, heartbeat, 3).is_err());
    }
}

#[test]
fn missing_current_future_tenure_and_noncanonical_keys_do_not_authenticate_a_pin() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let mut record = resolved(1, 1);
    let pin = sample_pin(&record);
    install(&mut stx, &[record.clone()]);
    store::committee_current::set(&mut stx, 2);
    assert!(retained_pin(&*stx.world, &pin, 0, 0, 3).is_err());
    store::committee_current::set(&mut stx, 1);
    assert!(retained_pin(&*stx.world, &pin, 0, 0, u64::MAX).is_err());
    record.start_height = 5;
    store::committee_generations::insert(&mut stx, 1, record.clone()).unwrap();
    assert!(retained_pin(&*stx.world, &sample_pin(&record), 0, 0, 3).is_err());
    record.start_height = 1;
    record.keys = (1..=4).map(|n| [n; 48]).collect();
    record.committee_root =
        iroha_data_model::sumeragi_finality::certified_result::committee_root(&record.keys)
            .unwrap();
    assert!(record.is_well_formed());
    store::committee_generations::insert(&mut stx, 1, record.clone()).unwrap();
    assert!(retained_pin(&*stx.world, &sample_pin(&record), 0, 0, 3).is_err());
    // Source-corruption control: bypass the typed writer only to exercise the reader guard.
    record.keys[1] = record.keys[0];
    stx.world
        .sccp_committee_generations
        .insert(1, record.clone());
    assert!(retained_pin(&*stx.world, &sample_pin(&record), 0, 0, 3).is_err());
}

#[test]
fn original_identity_comes_from_the_committed_global_tip() {
    assert!(original_identity(&blank_state().view()).is_err());
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let view = chain.state().view();
    let identity = original_identity(&view).unwrap();
    assert_eq!(identity.network, *view.network_id().as_bytes());
    assert_eq!(identity.instance, chain.instance().0);
    assert_eq!(
        identity.parent_height,
        u64::try_from(view.height()).unwrap()
    );
    crate::state::native_capture_fixture::with_native_capture_dataspace_source(
        |state, _, _, _, _| {
            let error = original_identity(&state.view())
                .err()
                .expect("non-Global original");
            assert!(error.to_string().contains("original Global root"));
        },
    );
}

fn ton_action(
    record: &SccpCommitteeGenerationV1,
    identity: &OriginalIdentity,
) -> SccpRegisterRouteActionV1 {
    let pin = sample_pin(record);
    let code = SccpTonCodeRefV1 {
        hash: [5; 32],
        depth: 0,
    };
    let init = TonMinterInitV1 {
        taira_network_id: identity.network,
        consensus_instance: identity.instance,
        route_revision: 1,
        max_supply: 100,
        pin_generation: pin.generation,
        pin_root: pin.committee_root,
        pin_start_height: pin.start_height,
        pin_until_ms: pin.until_ms,
        pin_keys: record.keys.clone(),
        wallet_code: code,
        bucket_code: code,
    };
    SccpRegisterRouteActionV1 {
        network: SccpNetworkV1::TonMainnet,
        revision: 1,
        initial_committee: pin,
        max_wrapped_supply: 100,
        deployment: SccpDeploymentV1::Ton(SccpTonDeploymentV1 {
            master_account: minter_account_id(&init, code).unwrap(),
            minter_code: code,
            wallet_code: code,
            bucket_code: code,
        }),
    }
}

#[test]
fn ton_address_binds_original_identity_pin_revision_cap_and_all_code_references() {
    let record = resolved(1, 1);
    // Pure address-vector inputs only. Production obtains this private structure from tip.
    let identity = OriginalIdentity {
        network: [1; 32],
        instance: [2; 32],
        parent_height: 3,
    };
    let original = ton_action(&record, &identity);
    assert!(deployment(&original, &record, &identity).is_ok());
    for variant in 0..11 {
        let mut changed = original.clone();
        let mut changed_identity = OriginalIdentity { ..identity };
        match variant {
            0 => changed_identity.network[0] ^= 1,
            1 => changed_identity.instance[0] ^= 1,
            2 => changed.revision += 1,
            3 => changed.max_wrapped_supply += 1,
            4 => changed.initial_committee.generation += 1,
            5 => changed.initial_committee.committee_root[0] ^= 1,
            6 => changed.initial_committee.start_height += 1,
            7 => changed.initial_committee.until_ms += 1,
            n => {
                let SccpDeploymentV1::Ton(ton) = &mut changed.deployment else {
                    unreachable!()
                };
                match n {
                    8 => ton.minter_code.depth += 1,
                    9 => ton.wallet_code.hash[0] ^= 1,
                    10 => ton.bucket_code.depth += 1,
                    _ => unreachable!(),
                }
            }
        }
        assert!(
            deployment(&changed, &record, &changed_identity).is_err(),
            "variant {variant}"
        );
    }
}

#[test]
fn an_offered_evm_address_never_substitutes_for_locked_creation_authority() {
    let record = resolved(1, 1);
    let identity = OriginalIdentity {
        network: [1; 32],
        instance: [2; 32],
        parent_height: 3,
    };
    let mut action = ton_action(&record, &identity);
    action.network = SccpNetworkV1::EthereumMainnet;
    action.deployment = SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
        address: [7; 20],
        runtime_code_hash: [8; 32],
    });
    assert!(
        deployment(&action, &record, &identity)
            .unwrap_err()
            .to_string()
            .contains("creation-code/deployer authority")
    );
}

#[test]
fn validated_ton_inputs_do_not_open_missing_launch_or_forgery_authority() {
    use crate::smartcontracts::isi::sccp::{controls::ControlCauseV1, escrow, governance};
    use iroha_data_model::sccp::{
        governance::{SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1},
        params::SccpParametersV1,
    };
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let mut block = chain.state().block(header(2));
    let mut stx = block.transaction();
    // The tip is genuine; SCCP records below are pre-enactment component DATA, not a
    // certified generation or evidence that RegisterRoute has ever succeeded.
    store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
    escrow::create_route_escrows(&mut stx).unwrap();
    let record = resolved(1, 1);
    install(&mut stx, &[record.clone()]);
    let identity = original_identity(&stx).unwrap();
    let action = ton_action(&record, &identity);
    assert!(validate_available(&stx, &action).is_ok());
    let before = store::routes::get(&*stx.world, &action.network)
        .cloned()
        .unwrap();
    let word = action.deployment.destination_word();
    let subject = SccpGovernanceSubjectV1::Route(action.network);
    let proposal = SccpGovernanceProposalV1 {
        network_id: *stx.network_id(),
        base_revisions: vec![],
        actions: vec![SccpGovernanceActionV1::RegisterRoute(action)],
    };
    let events = stx.world.internal_event_buf.len();
    let error = governance::enact(
        &mut stx,
        &proposal,
        [1; 32],
        ControlCauseV1::for_test([2; 32], [3; 32]),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("launch/reconciliation and forgery authority are unavailable")
    );
    assert_eq!(
        store::routes::get(&*stx.world, &SccpNetworkV1::TonMainnet),
        Some(&before)
    );
    assert!(!store::destination_words::contains(&*stx.world, &word));
    assert_eq!(store::governance_revision(&*stx.world, &subject), 0);
    assert!(store::control_messages::is_empty(&*stx.world));
    assert!(store::block_leaves::is_empty(&*stx.world));
    assert_eq!(stx.world.internal_event_buf.len(), events);
}
