//! Focused transition, frozen binding, liability and allocation controls.
//!
//! Structural planning tests supply explicit checked committee inputs; only native-chain
//! tests qualify source execution. No fixture creates a production verifier shortcut.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::{authority, blank_state, header};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::nexus::{PublicLaneValidatorRecord, PublicLaneValidatorStatus};
use iroha_model_base::{metadata::Metadata, topology::LaneId};
use std::num::NonZeroU64;

fn peers(seed: u8, count: u8) -> Vec<PeerId> {
    let mut peers = (seed..seed + count)
        .map(|seed| {
            PeerId::new(
                KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .public_key()
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    peers.sort();
    peers
}
fn at(height: u64, time: u64) -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(height).unwrap(), None, None, time, 0)
}
fn inputs<'a>(
    height: u64,
    roster: &'a [PeerId],
    next: Option<&'a [PeerId]>,
) -> SccpHeightInputsV1<'a> {
    use super::super::height::SccpRosterV1;
    SccpHeightInputsV1 {
        mode: ConsensusMode::Npos,
        height,
        epoch: 0,
        epoch_end_height: if next.is_some() { height } else { height + 100 },
        roster: SccpRosterV1::from_peers(roster).unwrap(),
        next_roster: next.map(|peers| SccpRosterV1::from_peers(peers).unwrap()),
    }
}
fn seed(stx: &mut StateTransaction<'_, '_>, peers: &[PeerId]) {
    let parameters = SccpParametersV1::taira_default();
    let committee = Committee::read(peers).unwrap();
    let generation = prepare_record(
        stx,
        &committee,
        Creation {
            generation: 1,
            cause: SccpGenerationCauseV1::Genesis,
            start_height: 1,
            timestamp_ms: 1_000,
            liability_clock: 1_000,
        },
        &parameters,
    )
    .unwrap();
    store::parameters::set(stx, Some(parameters));
    install_genesis(stx, generation).unwrap();
}

#[test]
fn epoch_guard_checks_zero_exact_floor_and_overflow_without_wrapping() {
    use crate::smartcontracts::isi::sccp::params::validate_epoch;
    assert!(validate_epoch(0, u64::MAX).is_err());
    assert!(validate_epoch(u64::MAX, 0).is_err());
    assert!(validate_epoch(3_599, 1_000).is_err());
    assert!(validate_epoch(3_600, 1_000).is_ok());
    assert!(validate_epoch(u64::MAX, u64::MAX).is_err());
}

#[test]
fn key_change_beats_heartbeat_and_keeps_outgoing_certificate_generation() {
    let state = blank_state();
    let parameters = SccpParametersV1::taira_default();
    let candidate = at(2, 1_000 + parameters.committee_heartbeat_ms);
    let mut block = state.block(candidate);
    let mut stx = block.transaction();
    let original = peers(1, 4);
    let successor = peers(10, 7);
    seed(&mut stx, &original);
    let source = inputs(2, &original, Some(&successor));
    let prepared = plan(&stx, &candidate, Some(&source)).unwrap();
    assert_eq!(prepared.generation, 1);
    assert_eq!(
        prepared.rotation.as_ref().unwrap().cause,
        SccpGenerationCauseV1::KeyChange
    );
    assert_eq!(prepared.rotation.as_ref().unwrap().keys.len(), 7);
    let next_root = prepared.next_committee_root;
    prepared.publish(&mut stx).unwrap();
    assert_eq!(*store::committee_current::get(&*stx.world), 2);
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1)
            .unwrap()
            .end
            .unwrap()
            .next_committee_root,
        next_root
    );
    let new = store::committee_generations::get(&*stx.world, &2).unwrap();
    assert_eq!(
        (new.start_height, new.start_timestamp_ms),
        (3, timestamp_ms(&candidate))
    );
    assert!(new.end.is_none());
}

#[test]
fn key_change_before_heartbeat_requires_rotation_at_the_original_boundary() {
    let state = blank_state();
    let candidate = at(2, 1_001);
    let mut block = state.block(candidate);
    let mut stx = block.transaction();
    let original = peers(1, 4);
    let successor = peers(10, 7);
    seed(&mut stx, &original);
    let source = inputs(2, &original, Some(&successor));
    let prepared = plan(&stx, &candidate, Some(&source)).unwrap();
    assert!(
        prepared.rotation.is_some(),
        "a changed native boundary committee must rotate before the heartbeat deadline"
    );
    assert_eq!(prepared.generation, 1);
    assert_eq!(
        prepared.rotation.as_ref().unwrap().cause,
        SccpGenerationCauseV1::KeyChange
    );
    let successor_root = Committee::read(&successor).unwrap().root;
    assert_eq!(prepared.next_committee_root, successor_root);
    assert_eq!(
        prepared.committee_root,
        Committee::read(&original).unwrap().root,
        "SC2 boundary header must retain the outgoing committee root"
    );
    prepared.publish(&mut stx).unwrap();
    assert_eq!(*store::committee_current::get(&*stx.world), 2);
    assert_eq!(
        store::committee_generations::get(&*stx.world, &2)
            .unwrap()
            .start_height,
        3
    );
}

#[test]
fn unchanged_committee_has_only_the_exact_heartbeat_trigger() {
    let state = blank_state();
    let original = peers(1, 4);
    let deadline = 1_000 + SccpParametersV1::taira_default().committee_heartbeat_ms;
    let mut block = state.block(at(2, deadline));
    let mut stx = block.transaction();
    seed(&mut stx, &original);
    let source = inputs(2, &original, None);
    let early = plan(&stx, &at(2, deadline - 1), Some(&source)).unwrap();
    assert!(early.rotation.is_none());
    assert_eq!(early.validity_ms, 0);
    let due = plan(&stx, &at(2, deadline), Some(&source)).unwrap();
    assert_eq!(
        due.rotation.as_ref().unwrap().cause,
        SccpGenerationCauseV1::Heartbeat
    );
    assert_eq!(due.next_committee_root, due.committee_root);
    assert_eq!(due.generation, 1);
}

#[test]
fn missing_wrong_height_unsorted_duplicate_and_incomplete_boundary_inputs_leave_generation_unchanged()
 {
    let state = blank_state();
    let candidate = header(2);
    let mut block = state.block(candidate);
    let mut stx = block.transaction();
    let original = peers(1, 4);
    seed(&mut stx, &original);
    assert!(matches!(
        plan(&stx, &candidate, None),
        Err(GenerationError::Degraded(Degraded::MissingInputs))
    ));
    let mut unsorted = original.clone();
    unsorted.swap(0, 1);
    let mut duplicate = original.clone();
    duplicate[1] = duplicate[0].clone();
    let mut incomplete = inputs(2, &original, Some(&original));
    incomplete.next_roster = None;
    let cases = [
        inputs(3, &original, None),
        inputs(2, &unsorted, None),
        incomplete,
        inputs(2, &duplicate, None),
    ];
    for source in cases {
        assert!(matches!(
            plan(&stx, &candidate, Some(&source)),
            Err(GenerationError::Degraded(Degraded::InvalidInputs))
        ));
        assert_eq!(*store::committee_current::get(&*stx.world), 1);
        assert_eq!(store::committee_generations::len(&*stx.world), 1);
        assert!(
            store::committee_generations::get(&*stx.world, &1)
                .unwrap()
                .end
                .is_none()
        );
    }
}

#[test]
fn resync_uses_real_native_parent_time_then_boundary_rotates_again() {
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let parent = chain.state().view().native_execution_tip().unwrap();
    let candidate = at(2, 5_000);
    let mut block = chain.state().block(candidate);
    let mut stx = block.transaction();
    let previous = peers(1, 4);
    let current = peers(10, 7);
    let next = peers(20, 4);
    seed(&mut stx, &previous);
    let source = inputs(2, &current, Some(&next));
    let prepared = plan(&stx, &candidate, Some(&source)).unwrap();
    assert_eq!(
        prepared.generation, 2,
        "SC23 a missed committee change must create the original resync generation"
    );
    assert_eq!(
        prepared.resync.as_ref().unwrap().cause,
        SccpGenerationCauseV1::Resync
    );
    assert_eq!(prepared.resync.as_ref().unwrap().start_height, 2);
    assert_eq!(
        prepared
            .old_end
            .as_ref()
            .unwrap()
            .end
            .unwrap()
            .end_timestamp_ms,
        parent.creation_time_ms()
    );
    assert_eq!(prepared.rotation.as_ref().unwrap().generation, 3);
    prepared.publish(&mut stx).unwrap();
    assert_eq!(*store::committee_current::get(&*stx.world), 3);
    let restored = store::committee_generations::get(&*stx.world, &2).unwrap();
    assert_eq!(restored.keys.len(), 7);
    assert_eq!(restored.end.unwrap().end_height, 2);
    assert_eq!(
        store::committee_generations::get(&*stx.world, &3)
            .unwrap()
            .keys
            .len(),
        4
    );
}

fn registration(peer: PeerId, owner: u8, lane_id: LaneId) -> PublicLaneValidatorRecord {
    let validator = authority(owner);
    PublicLaneValidatorRecord {
        lane_id,
        validator: validator.clone(),
        peer_id: peer,
        stake_account: validator,
        total_stake: 1_u64.into(),
        self_stake: 1_u64.into(),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Active,
        activation_height: 1,
        election_exit_height: None,
        deactivation_height: None,
    }
}
#[test]
fn frozen_member_binding_rejects_ambiguous_or_inactive_registration() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut stx = block.transaction();
    let peer = peers(1, 4).remove(0);
    let lane = LaneId::SINGLE;
    assert!(stx.is_lane_active_for_authority(lane));
    assert_eq!(stx.staking_authority_lane(lane), Some(lane));
    let first = registration(peer.clone(), 1, lane);
    let second = registration(peer.clone(), 2, lane);
    stx.world
        .public_lane_validators
        .insert((lane, first.validator.clone()), first.clone());
    assert_eq!(
        member_for_peer(&stx, &peer, 2).unwrap().validator,
        &first.validator
    );
    stx.world
        .public_lane_validators
        .insert((lane, second.validator.clone()), second.clone());
    assert!(
        member_for_peer(&stx, &peer, 2).is_none(),
        "ambiguity never selects by map order"
    );
    stx.world
        .public_lane_validators
        .remove((lane, second.validator));
    assert!(member_for_peer(&stx, &peer, 0).is_none());
    let mut ended = first.clone();
    ended.deactivation_height = Some(2);
    stx.world
        .public_lane_validators
        .insert((lane, first.validator), ended);
    assert!(member_for_peer(&stx, &peer, 2).is_none());
    assert!(member_for_peer(&stx, &peer, 1).is_some());
}

#[test]
fn destination_progress_is_strict_and_bounded_and_never_rewrites_clearance() {
    use crate::smartcontracts::isi::sccp::test_support::sample_route;
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        sccp::light_client::{
            SccpLcHeadV1, SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1,
        },
    };
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut stx = block.transaction();
    let peers = peers(1, 4);
    let committee = Committee::read(&peers).unwrap();
    let parameters = SccpParametersV1::taira_default();
    for id in 1..=65 {
        let mut record = prepare_record(
            &stx,
            &committee,
            Creation {
                generation: id,
                cause: if id == 1 {
                    SccpGenerationCauseV1::Genesis
                } else {
                    SccpGenerationCauseV1::Heartbeat
                },
                start_height: id,
                timestamp_ms: 1_000,
                liability_clock: 1_000,
            },
            &parameters,
        )
        .unwrap();
        record.end = Some(SccpGenerationEndV1 {
            end_height: 65,
            end_timestamp_ms: 1_000,
            next_committee_root: committee.root,
            successor_validity_ms: parameters.committee_validity_ms,
        });
        publish_record(&mut stx, record).expect("fixture generation publication");
    }
    store::liability_clock::set(&mut stx, 2_000);
    let network = SccpNetworkV1::EthereumMainnet;
    store::routes::insert(&mut stx, network, sample_route(network)).unwrap();
    clear_destinations(&mut stx).unwrap();
    assert!(
        store::committee_generations::get(&*stx.world, &1)
            .unwrap()
            .dest_cleared_lc
            .is_none(),
        "route without light client blocks clearance"
    );
    let deadline = 1_000 + parameters.committee_validity_ms;
    let mut client = SccpLightClientV1 {
        params: SccpLightClientParamsV1::defaults_for(network).unwrap(),
        head: SccpLcHeadV1 {
            latest_set_id: 1,
            latest_finalized: SccpLcPointV1 {
                source_height: 1,
                block_hash: [1; 32],
                source_time_ms: deadline,
            },
            last_progress_taira_ms: 1_000,
        },
        frozen: None,
        state_hash: [2; 32],
    };
    store::light_clients::insert(&mut stx, network, client).unwrap();
    clear_destinations(&mut stx).unwrap();
    assert!(
        store::committee_generations::get(&*stx.world, &1)
            .unwrap()
            .dest_cleared_lc
            .is_none(),
        "deadline itself is insufficient"
    );
    client.head.latest_finalized.source_time_ms += 1;
    store::light_clients::insert(&mut stx, network, client).unwrap();
    clear_destinations(&mut stx).unwrap();
    assert_eq!(
        store::committee_generations::iter(&*stx.world)
            .filter(|(_, g)| g.dest_cleared_lc == Some(2_000))
            .count(),
        64
    );
    assert!(
        store::committee_generations::get(&*stx.world, &65)
            .unwrap()
            .dest_cleared_lc
            .is_none()
    );
    store::liability_clock::set(&mut stx, 3_000);
    clear_destinations(&mut stx).unwrap();
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1)
            .unwrap()
            .dest_cleared_lc,
        Some(2_000)
    );
    assert_eq!(
        store::committee_generations::get(&*stx.world, &65)
            .unwrap()
            .dest_cleared_lc,
        Some(3_000)
    );
}

#[test]
fn combined_resync_rotation_capacity_wait_stays_pending_until_external_release() {
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_allocation::release::ReleaseRegistration;
    use std::task::{Context, Poll, Waker};
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let candidate = at(2, 5_000);
    let mut block = chain.state().block(candidate);
    let mut stx = block.transaction();
    seed(&mut stx, &peers(1, 4));
    let current = peers(10, 7);
    let next = peers(20, 4);
    let source = inputs(2, &current, Some(&next));
    let budget = stx.execution_budget();
    let mut waiter_reservation = budget
        .try_reserve(ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut waiter = ReleaseRegistration::from_reservation(&mut waiter_reservation).unwrap();
    drop(waiter_reservation);
    let draft = draft(&stx, &candidate, Some(&source)).unwrap();
    let demand = draft.demand().unwrap();
    drop(draft);
    let occupied = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    budget.set_limit_bytes(occupied + demand);
    let external = budget.try_reserve_bytes(1).unwrap();
    let error = match plan(&stx, &candidate, Some(&source)) {
        Err(GenerationError::Deferred(original)) => original,
        other => panic!("expected original capacity: {other:?}"),
    };
    let Some(AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    }) = error.allocation_refusal()
    else {
        panic!("original capacity retained")
    };
    assert_eq!(*requested_bytes, demand);
    assert_eq!(
        budget.reserved_bytes(),
        occupied + 1,
        "no partial resync payload survives or self-releases"
    );
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Pending);
    assert_eq!(store::committee_generations::len(&*stx.world), 1);
    assert!(
        store::committee_generations::get(&*stx.world, &1)
            .unwrap()
            .end
            .is_none()
    );
    // This thread owns live admitted writers, so its refunds deliberately cannot wake
    // work that would reacquire them. Model a genuinely external owner releasing credit.
    std::thread::scope(|scope| {
        scope.spawn(move || drop(external)).join().unwrap();
    });
    assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Ready(()));
    let complete = plan(&stx, &candidate, Some(&source)).unwrap();
    assert_eq!(complete.generation, 2);
    assert_eq!(complete.rotation.as_ref().unwrap().generation, 3);
    drop(complete);
    assert_eq!(budget.reserved_bytes(), occupied);
    waiter.cancel();
    budget.set_limit_bytes(original_limit);
}

#[test]
fn handoff_resolves_original_registration_for_successor_tenure_and_freezes_it() {
    let state = blank_state();
    let candidate = at(2, 2_000);
    let mut block = state.block(candidate);
    let mut stx = block.transaction();
    let original = peers(1, 4);
    let next = peers(10, 7);
    seed(&mut stx, &original);
    let lane = LaneId::SINGLE;
    let mut elected = registration(next[0].clone(), 1, lane);
    elected.activation_height = 3;
    let mut departing = registration(next[1].clone(), 2, lane);
    departing.deactivation_height = Some(3);
    stx.world
        .public_lane_validators
        .insert((lane, elected.validator.clone()), elected.clone());
    stx.world
        .public_lane_validators
        .insert((lane, departing.validator.clone()), departing.clone());
    let source = inputs(2, &original, Some(&next));
    let prepared = plan(&stx, &candidate, Some(&source)).unwrap();
    let successor = prepared.rotation.as_ref().unwrap();
    assert_eq!(successor.start_height, 3);
    let frozen = successor.members[0]
        .as_ref()
        .expect("new h+1 seat is slashable");
    assert_eq!(frozen.validator, elected.validator);
    assert_eq!(frozen.activation_height, 3);
    assert!(
        successor.members[1].is_none(),
        "exclusive deactivation at h+1 cannot back its successor"
    );
    assert!(
        member_for_peer(&stx, &elected.peer_id, 1).is_none(),
        "G1 still resolves tenure at genesis"
    );
    assert!(
        member_for_peer(&stx, &elected.peer_id, 2).is_none(),
        "G7 still resolves tenure at h"
    );
    assert!(member_for_peer(&stx, &departing.peer_id, 2).is_some());
    // Changing a later registration lookup cannot rewrite the already admitted generation.
    stx.world
        .public_lane_validators
        .remove((lane, elected.validator.clone()));
    let replacement = registration(elected.peer_id.clone(), 3, lane);
    stx.world
        .public_lane_validators
        .insert((lane, replacement.validator.clone()), replacement);
    prepared.publish(&mut stx).unwrap();
    let committed = store::committee_generations::get(&*stx.world, &2).unwrap();
    assert_eq!(
        committed.members[0].as_ref().unwrap().validator,
        elected.validator
    );
    assert_eq!(committed.members[0].as_ref().unwrap().activation_height, 3);
}

#[test]
fn global_member_binding_ignores_participant_staking_registration() {
    use iroha_data_model::nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig};
    use iroha_model_base::topology::DataSpaceId;
    use std::num::NonZeroU32;

    let state = blank_state();
    let candidate = at(2, 2_000);
    let mut block = state.block(candidate);
    let mut stx = block.transaction();
    let participant = LaneId::new(1);
    let dataspace = DataSpaceId::new(1);
    stx.nexus.lane_catalog = LaneCatalog::new(
        NonZeroU32::new(2).unwrap(),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: participant,
                alias: "participant-root".into(),
                dataspace_id: dataspace,
                ..LaneConfig::default()
            },
        ],
    )
    .unwrap();
    stx.nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&stx.nexus.lane_catalog);
    stx.nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: dataspace,
            alias: "participant".into(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .unwrap();
    assert!(stx.is_lane_active_for_authority(participant));
    assert_eq!(stx.staking_authority_lane(participant), Some(participant));
    let original = peers(1, 4);
    let next = peers(10, 7);
    seed(&mut stx, &original);
    let mut global = registration(next[0].clone(), 1, LaneId::SINGLE);
    global.activation_height = 3;
    let participant_record = registration(next[0].clone(), 2, participant);
    stx.world
        .public_lane_validators
        .insert((LaneId::SINGLE, global.validator.clone()), global.clone());
    stx.world.public_lane_validators.insert(
        (participant, participant_record.validator.clone()),
        participant_record,
    );
    let source = inputs(2, &original, Some(&next));
    let prepared = plan(&stx, &candidate, Some(&source)).unwrap();
    let successor = prepared.rotation.as_ref().unwrap();
    assert_eq!(successor.start_height, 3);
    let member = successor.members[0]
        .as_ref()
        .expect("global elected signer remains slashable");
    assert_eq!(member.lane_id, LaneId::SINGLE);
    assert_eq!(member.validator, global.validator);
    assert_eq!(member.activation_height, 3);
    assert!(member_for_peer(&stx, &next[0], 2).is_none());
    let duplicate = registration(next[0].clone(), 3, LaneId::SINGLE);
    stx.world
        .public_lane_validators
        .insert((LaneId::SINGLE, duplicate.validator.clone()), duplicate);
    assert!(
        member_for_peer(&stx, &next[0], 3).is_none(),
        "duplicate global registrations remain unresolved"
    );
}

#[test]
fn destination_clearance_visits_only_bounded_pending_index_after_cleared_history() {
    for cleared_history in [0, 64, 512] {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let peers = peers(1, 4);
        let committee = Committee::read(&peers).unwrap();
        let parameters = SccpParametersV1::taira_default();
        for id in 1..=cleared_history + 65 {
            let mut record = prepare_record(
                &stx,
                &committee,
                Creation {
                    generation: id,
                    cause: if id == 1 {
                        SccpGenerationCauseV1::Genesis
                    } else {
                        SccpGenerationCauseV1::Heartbeat
                    },
                    start_height: id,
                    timestamp_ms: 1_000,
                    liability_clock: 1_000,
                },
                &parameters,
            )
            .unwrap();
            record.end = Some(SccpGenerationEndV1 {
                end_height: cleared_history + 65,
                end_timestamp_ms: 1_000,
                next_committee_root: committee.root,
                successor_validity_ms: parameters.committee_validity_ms,
            });
            if id <= cleared_history {
                record.dest_cleared_lc = Some(2_000);
            }
            publish_record(&mut stx, record).expect("fixture generation publication");
        }
        store::liability_clock::set(&mut stx, 3_000);
        assert_eq!(stx.world.sccp_destination_pending_generations.len(), 65);
        assert_eq!(
            clear_destinations(&mut stx).unwrap(),
            64,
            "work is independent of {cleared_history} cleared records"
        );
        assert_eq!(
            stx.world
                .sccp_destination_pending_generations
                .iter()
                .map(|(id, ())| *id)
                .collect::<Vec<_>>(),
            vec![cleared_history + 65]
        );
        for id in cleared_history + 1..=cleared_history + 64 {
            assert_eq!(
                store::committee_generations::get(&*stx.world, &id)
                    .unwrap()
                    .dest_cleared_lc,
                Some(3_000)
            );
        }
        assert_eq!(clear_destinations(&mut stx).unwrap(), 1);
        assert_eq!(
            clear_destinations(&mut stx).unwrap(),
            0,
            "no historical scan once work is cleared"
        );
        assert!(stx.world.sccp_destination_pending_generations.is_empty());
    }
}
