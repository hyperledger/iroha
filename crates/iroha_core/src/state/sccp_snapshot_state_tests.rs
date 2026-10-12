//! SCCP snapshot envelope current/undo conservation and malformed-state rejection.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::{populate_every_sccp_map, sample_anchor};
use crate::state::deserialize::StateRestoreError;

fn encoded(world: &World) -> String {
    let mut out = String::new();
    serialize_envelope(world, &mut out);
    out
}

fn restore(text: &str, world: &mut World) -> Result<(), StateRestoreError> {
    let budget = world.sccp_committee_generations.allocation_budget().clone();
    json::from_json::<SnapshotSccpState>(text)?.restore(world, &budget)
}

// Every constructor keeps the original finite-pool refusal. The first refusing owner
// can be a direct generation map, its decoded graph, or the remaining aggregate graph.
fn original_allocation_refusal(error: &StateRestoreError) -> &AllocationRefusal {
    match error {
        StateRestoreError::Admission(StateAdmissionError::Storage(
            StateStorageAdmissionError::World(mv::storage::AdmittedStorageError::Allocation(
                original,
            )),
        ))
        | StateRestoreError::Sccp(SccpRestoreError::Storage(
            mv::storage::AdmittedStorageError::Allocation(original),
        ))
        | StateRestoreError::Sccp(SccpRestoreError::Admission(original))
        | StateRestoreError::Sccp(SccpRestoreError::Generation(
            GenerationRecordError::Admission(original),
        )) => original,
        _ => panic!("original local allocation refusal must retain its type: {error:?}"),
    }
}

/// Return a World whose every SCCP map and cell holds a current value and an undo record.
pub(crate) fn sccp_world() -> World {
    let world = World::default();
    let budget = world.sccp_committee_generations.allocation_budget().clone();
    {
        let mut block = world.block();
        populate_every_sccp_map(&mut block, 1, &budget);
        block.commit();
    }
    {
        let mut block = world.block();
        populate_every_sccp_map(&mut block, 2, &budget);
        block.commit();
    }
    world
}

#[test]
fn every_sccp_member_is_serialized_in_field_order() {
    let text = encoded(&World::default());
    let value: json::Value = json::from_json(&text).expect("envelope JSON");
    let json::Value::Object(members) = &value else {
        panic!("the envelope is an object");
    };
    assert_eq!(members.len(), 31, "one member per SCCP world field");
    let mut restored = World::default();
    restore(&text, &mut restored).expect("an empty envelope restores");
    assert_eq!(encoded(&restored), text);
}

#[test]
fn sccp_snapshot_preserves_every_current_and_undo_envelope() {
    let original = sccp_world();
    let expected = encoded(&original);
    let mut restored = World::default();
    restore(&expected, &mut restored).expect("restore every SCCP envelope");
    assert_eq!(encoded(&restored), expected);
    {
        let prior = original.block_and_revert();
        let replacement = restored.block_and_revert();
        let mut left = String::new();
        let mut right = String::new();
        serialize_block_envelope(&prior, &mut left);
        serialize_block_envelope(&replacement, &mut right);
        assert_eq!(left, right, "the undo records restore identically");
        assert_eq!(*replacement.sccp_reset_nonce.get(), Some([1; 32]));
        assert_eq!(*replacement.sccp_committee_current.get(), 1);
        assert_eq!(replacement.sccp_committee_generations.len(), 1);
        assert_eq!(
            replacement.sccp_anchor_open.get().as_slice()[0].core_hash,
            [1; 32]
        );
        assert_eq!(replacement.sccp_anchor_chunks.len(), 1);
        assert_eq!(replacement.sccp_fast_pauses.len(), 1);
        assert_eq!(replacement.sccp_fast_pause_rounds.len(), 1);
        assert_eq!(replacement.sccp_fast_pause_suspended_until_ms.len(), 1);
        assert_eq!(
            replacement
                .sccp_pause_panel
                .get()
                .as_ref()
                .unwrap()
                .panel_seq,
            1
        );
        assert_eq!(replacement.sccp_block_commitments.len(), 1);
        assert_eq!(replacement.sccp_light_client_checkpoints.len(), 1);
        assert_eq!(
            replacement.sccp_anchor_open.get().as_slice()[0].core_hash,
            [1; 32]
        );
        assert_eq!(replacement.sccp_anchor_chunks.len(), 1);
    }
    {
        let view = restored.view();
        assert_eq!(*view.sccp_reset_nonce(), Some([3; 32]));
        assert_eq!(*view.sccp_committee_current(), 2);
        assert_eq!(view.sccp_committee_generations().len(), 2);
        assert_eq!(view.sccp_anchor_open().as_slice()[0].core_hash, [2; 32]);
        assert_eq!(view.sccp_anchor_chunks().len(), 2);
        assert_eq!(view.sccp_fast_pauses().len(), 1);
        assert_eq!(view.sccp_fast_pause_rounds().len(), 1);
        assert_eq!(view.sccp_fast_pause_suspended_until_ms().len(), 1);
        assert_eq!(view.sccp_pause_panel().as_ref().unwrap().panel_seq, 2);
        assert_eq!(view.sccp_block_commitments().len(), 2);
        assert_eq!(view.sccp_history_leaves().len(), 2);
        assert_eq!(view.sccp_history().size, 1);
        assert!(view.sccp_parameters().is_some());
        assert_eq!(view.sccp_anchor_open().as_slice()[0].core_hash, [2; 32]);
        assert_eq!(view.sccp_anchor_chunks().len(), 2);
    }
    restored.block_and_revert().commit();
    let reverted = encoded(&restored);
    let mut restarted = World::default();
    restore(&reverted, &mut restarted).expect("restore the reverted envelope");
    assert_eq!(encoded(&restarted), reverted);
}

#[test]
fn sccp_snapshot_requires_every_member_and_rejects_invalid_values() {
    let source = sccp_world();
    let value: json::Value = json::from_json(&encoded(&source)).expect("envelope JSON");
    let json::Value::Object(fields) = &value else {
        unreachable!()
    };
    for field in fields.keys() {
        let mut missing = value.clone();
        missing.as_object_mut().expect("object").remove(field);
        assert!(
            restore(
                &json::to_json(&missing).expect("JSON"),
                &mut World::default()
            )
            .is_err(),
            "{field}"
        );
    }
    let mut target = World::default();
    let before = encoded(&target);
    let mut parameters = SccpParametersV1::taira_default();
    parameters.max_exempt_transactions_per_block = 0;
    let bad_parameters = json::to_value(&Some(parameters)).expect("JSON");
    let bad_history = json::to_value(&SccpHistoryStateV1 {
        size: 3,
        peaks: vec![[1; 32]],
    })
    .expect("JSON");
    let bad_anchors = json::to_value(&vec![sample_anchor(1); 4097]).expect("JSON");
    let bad_nonce = json::to_value(&Some([0_u8; 32])).expect("JSON");
    for (field, bad) in [
        ("sccp_parameters", bad_parameters),
        ("sccp_history", bad_history),
        ("sccp_reset_nonce", bad_nonce),
        ("sccp_anchor_open", bad_anchors),
    ] {
        for member in ["revert", "blocks"] {
            let mut malformed = value.clone();
            let envelope = malformed
                .as_object_mut()
                .expect("object")
                .get_mut(field)
                .expect("member")
                .as_object_mut()
                .expect("cell envelope");
            envelope.insert(member.into(), bad.clone());
            assert!(
                restore(&json::to_json(&malformed).expect("JSON"), &mut target).is_err(),
                "{field}.{member}"
            );
            assert_eq!(
                encoded(&target),
                before,
                "restore is atomic on {field} failure"
            );
        }
    }
}

#[test]
fn sccp_snapshot_rejects_retired_and_unknown_members_without_publication() {
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let source = sccp_world();
    let value: json::Value = json::from_json(&encoded(&source)).expect("envelope JSON");
    let mut target = world_with(|block| populate_every_sccp_map(block, 3, &budget));
    let before = encoded(&target);
    assert_ne!(
        before,
        encoded(&source),
        "the destination has distinct retained State"
    );
    for field in [
        "sccp_bridge_keys",
        "sccp_bridge_key_owners",
        "sccp_rosters",
        "sccp_roster_current",
        "sccp_heartbeat_marker",
        "sccp_attestation_subjects",
        "sccp_attestation_status",
        "sccp_attestation_signatures",
        "sccp_attestation_faults",
        "sccp_member_last_signed",
        "sccp_handoff_stalled",
        "sccp_prune_cursor",
        "sccp_unrecognized_member",
    ] {
        let mut malformed = value.clone();
        assert!(
            malformed
                .as_object_mut()
                .expect("object")
                .insert(field.into(), json::Value::Null)
                .is_none(),
            "{field} must not belong to the current envelope"
        );
        let error = restore(&json::to_json(&malformed).expect("JSON"), &mut target)
            .expect_err("an unknown field must never restore as current State");
        assert!(error.to_string().contains(field), "{field}: {error}");
        assert_eq!(
            encoded(&target),
            before,
            "{field}: refusal leaves State unchanged"
        );
    }
}

/// Return a World whose only SCCP content is one entry `write` puts directly into the overlay,
/// bypassing the `store` funnel that would refuse it.
fn world_with(write: impl FnOnce(&mut WorldBlock<'_>)) -> World {
    let world = World::default();
    {
        let mut block = world.block();
        write(&mut block);
        block.commit();
    }
    world
}

#[test]
fn sccp_snapshot_rejects_every_storage_invariant_violation() {
    use crate::smartcontracts::isi::sccp::test_support::sample_route;
    use iroha_data_model::sccp::{
        control::SCCP_FIRST_CONTROL_NONCE_V1, params::SCCP_MESSAGES_MAX_PER_BLOCK_V1,
    };
    let network = SccpNetworkV1::EthereumMainnet;
    let control_key = (network, 1, SCCP_FIRST_CONTROL_NONCE_V1);
    let control = |commitment_index| SccpControlRecordV1 {
        track: 1,
        parliament_paused: true,
        fast_pause_until_ms: 0,
        height: 4,
        commitment_index,
        leaf: [1; 32],
        certificate_id: [1; 32],
        effect_hash: [5; 32],
    };
    let profile_activation = |profile_hash| SccpLcProfileActivationV1 {
        profile_hash,
        activation_height: 9,
        proposal_id: [1; 32],
    };
    let commitment = |message_count| SccpBlockCommitmentV1 {
        root: [1; 32],
        message_count,
        history_index: 0,
    };
    let mut cases: Vec<(&str, World, World)> = vec![
        (
            "sccp_block_leaves",
            world_with(|block| {
                block.sccp_block_leaves.insert(
                    (4, SCCP_MESSAGES_MAX_PER_BLOCK_V1),
                    SccpLeafRefV1::transfer([1; 32]),
                );
            }),
            world_with(|block| {
                block.sccp_block_leaves.insert(
                    (4, SCCP_MESSAGES_MAX_PER_BLOCK_V1 - 1),
                    SccpLeafRefV1::transfer([1; 32]),
                );
            }),
        ),
        (
            "sccp_block_commitments",
            world_with(|block| {
                block.sccp_block_commitments.insert(4, commitment(0));
            }),
            world_with(|block| {
                block
                    .sccp_block_commitments
                    .insert(4, commitment(SCCP_MESSAGES_MAX_PER_BLOCK_V1));
            }),
        ),
        (
            "sccp_block_commitments",
            world_with(|block| {
                block
                    .sccp_block_commitments
                    .insert(4, commitment(SCCP_MESSAGES_MAX_PER_BLOCK_V1 + 1));
            }),
            world_with(|block| {
                block.sccp_block_commitments.insert(4, commitment(1));
            }),
        ),
        (
            "sccp_control_messages",
            world_with(|block| {
                block
                    .sccp_control_messages
                    .insert(control_key, control(SCCP_MESSAGES_MAX_PER_BLOCK_V1));
            }),
            world_with(|block| {
                block.sccp_control_messages.insert(control_key, control(0));
            }),
        ),
        (
            "sccp_routes",
            world_with(|block| {
                block
                    .sccp_routes
                    .insert(SccpNetworkV1::BscMainnet, sample_route(network));
            }),
            world_with(|block| {
                block.sccp_routes.insert(network, sample_route(network));
            }),
        ),
        (
            "sccp_governance_revisions",
            world_with(|block| {
                block
                    .sccp_governance_revisions
                    .insert(SccpGovernanceSubjectV1::Parameters, 0);
            }),
            world_with(|block| {
                block
                    .sccp_governance_revisions
                    .insert(SccpGovernanceSubjectV1::Parameters, 1);
            }),
        ),
        (
            "sccp_pending_counts",
            world_with(|block| {
                block.sccp_pending_counts.insert((network, 1), (0, 0));
            }),
            world_with(|block| {
                block.sccp_pending_counts.insert((network, 1), (0, 1));
            }),
        ),
        (
            "sccp_light_client_profiles",
            world_with(|block| {
                block
                    .sccp_light_client_profiles
                    .insert((network, 1), profile_activation([1; 32]));
            }),
            world_with(|block| {
                block
                    .sccp_light_client_profiles
                    .insert((network, 2), profile_activation([1; 32]));
            }),
        ),
        (
            "sccp_light_client_profiles",
            world_with(|block| {
                block
                    .sccp_light_client_profiles
                    .insert((network, 2), profile_activation([0; 32]));
            }),
            world_with(|block| {
                block
                    .sccp_light_client_profiles
                    .insert((network, 3), profile_activation([2; 32]));
            }),
        ),
        (
            "sccp_light_client_profiles",
            world_with(|block| {
                block
                    .sccp_light_client_profiles
                    .insert((SccpNetworkV1::SoraTaira, 2), profile_activation([1; 32]));
            }),
            world_with(|block| {
                block
                    .sccp_light_client_profiles
                    .insert((SccpNetworkV1::TonMainnet, 2), profile_activation([1; 32]));
            }),
        ),
    ];
    // Native cause and key constraints apply equally to current and undo entries.
    for (key, record) in [
        ((network, 0, SCCP_FIRST_CONTROL_NONCE_V1), control(0)),
        ((network, 1, 0), control(0)),
        (
            (SccpNetworkV1::SoraTaira, 1, SCCP_FIRST_CONTROL_NONCE_V1),
            control(0),
        ),
        (
            control_key,
            SccpControlRecordV1 {
                track: 0,
                ..control(0)
            },
        ),
        (
            control_key,
            SccpControlRecordV1 {
                track: 2,
                ..control(0)
            },
        ),
        (
            control_key,
            SccpControlRecordV1 {
                certificate_id: [0; 32],
                ..control(0)
            },
        ),
        (
            control_key,
            SccpControlRecordV1 {
                effect_hash: [0; 32],
                ..control(0)
            },
        ),
    ] {
        cases.push((
            "sccp_control_messages",
            world_with(|block| {
                block.sccp_control_messages.insert(key, record);
            }),
            world_with(|block| {
                block.sccp_control_messages.insert(control_key, control(0));
            }),
        ));
    }
    for (field, invalid, valid) in cases {
        let mut target = World::default();
        let before = encoded(&target);
        let error = restore(&encoded(&invalid), &mut target)
            .expect_err("an entry that breaks its stored invariant never restores");
        assert!(error.to_string().contains(field), "{field}: {error}");
        assert_eq!(
            encoded(&target),
            before,
            "restore is atomic on {field} failure"
        );
        let mut malformed_undo: json::Value = json::from_json(&encoded(&valid)).expect("JSON");
        let invalid_value: json::Value = json::from_json(&encoded(&invalid)).expect("JSON");
        let bad_entries = invalid_value.as_object().expect("object")[field]
            .as_object()
            .expect("map envelope")["blocks"]
            .clone();
        malformed_undo
            .as_object_mut()
            .expect("object")
            .get_mut(field)
            .expect("field")
            .as_object_mut()
            .expect("map envelope")
            .insert("revert".into(), bad_entries);
        let error = restore(&json::to_json(&malformed_undo).expect("JSON"), &mut target)
            .expect_err("invalid undo entries never restore behind valid current entries");
        assert!(error.to_string().contains(field), "{field}: {error}");
        assert_eq!(encoded(&target), before, "undo failure is atomic: {field}");
        let text = encoded(&valid);
        restore(&text, &mut target).unwrap_or_else(|error| panic!("{field}: {error}"));
        assert_eq!(
            encoded(&target),
            text,
            "{field}: the valid neighbour restores"
        );
    }
}

#[test]
fn generation_and_anchor_snapshot_refusals_preserve_distinct_destination_state() {
    use crate::smartcontracts::isi::sccp::test_support::sample_generation;
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut target = world_with(|block| populate_every_sccp_map(block, 3, &budget));
    let before = encoded(&target);
    let source: json::Value = json::from_json(&encoded(&sccp_world())).unwrap();
    fn record(key: u64, value: &impl norito::codec::Encode) -> json::Value {
        // Canonical DTO mutation never manufactures an invalid retained runtime owner.
        norito::json!({
            "key": {"encoded_hex": (hex::encode(key.encode()))},
            "value": {"encoded_hex": (hex::encode(value.encode()))}
        })
    }
    let mut bad_generation = sample_generation(1);
    bad_generation.deadline_ms += 1;
    let bad_record = json::Value::Array(vec![record(1_u64, &bad_generation)]);
    let mut bad_members = sample_generation(1);
    bad_members.members.pop();
    let bad_members = json::Value::Array(vec![record(1_u64, &bad_members)]);
    let mut bad_root = sample_generation(1);
    bad_root.committee_root[0] ^= 1;
    let bad_root = json::Value::Array(vec![record(1_u64, &bad_root)]);
    let bad_key = json::Value::Array(vec![record(2_u64, &sample_generation(1))]);
    let bad_chunk = json::Value::Array(vec![record(u64::MAX, &[3_u8; 32])]);
    let bad_open = json::to_value(&vec![
        SccpAnchorV1 {
            core_hash: [1; 32],
            result: [2; 32],
        };
        SCCP_ANCHOR_CHUNK_SIZE_V1
    ])
    .unwrap();
    for (field, bad) in [
        ("sccp_committee_generations", bad_record),
        ("sccp_committee_generations", bad_members),
        ("sccp_committee_generations", bad_root),
        ("sccp_committee_generations", bad_key),
        ("sccp_anchor_chunks", bad_chunk),
        ("sccp_anchor_open", bad_open),
    ] {
        for member in ["blocks", "revert"] {
            let mut malformed = source.clone();
            let value = if field == "sccp_anchor_open" && member == "revert" {
                norito::json!({"value": (bad.clone())})
            } else {
                bad.clone()
            };
            malformed
                .as_object_mut()
                .unwrap()
                .get_mut(field)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(member.into(), value);
            let error = restore(&json::to_json(&malformed).unwrap(), &mut target)
                .expect_err("malformed canonical snapshot DTO");
            assert!(
                error.to_string().contains(field),
                "{field}.{member}: {error}"
            );
            assert_eq!(
                encoded(&target),
                before,
                "{field}.{member}: no partial publication"
            );
        }
    }
}

#[test]
fn snapshot_original_pool_refusal_preserves_destination_and_retries_exact_envelope() {
    let source = encoded(&sccp_world());
    let source_budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut target = world_with(|block| populate_every_sccp_map(block, 3, &source_budget));
    let before = encoded(&target);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let blocker = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
    let expected = budget.reserved_bytes();
    let error = json::from_json::<SnapshotSccpState>(&source)
        .unwrap()
        .restore(&mut target, &budget)
        .unwrap_err();
    let iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ..
    } = original_allocation_refusal(&error).clone()
    else {
        panic!("original complete graph refusal: {error:?}");
    };
    assert!(requested_bytes > 0);
    assert_eq!(reserved_bytes, expected);
    assert_eq!(limit_bytes, budget.limit_bytes());
    assert_eq!(budget.reserved_bytes(), expected);
    assert_eq!(encoded(&target), before);
    drop(blocker);
    json::from_json::<SnapshotSccpState>(&source)
        .unwrap()
        .restore(&mut target, &budget)
        .unwrap();
    assert_eq!(encoded(&target), source);
    assert!(budget.reserved_bytes() > 0);
}

#[test]
fn pause_snapshot_rejects_malformed_current_and_undo_without_publication() {
    use crate::smartcontracts::isi::sccp::test_support::{
        sample_fast_pause, sample_fast_pause_round, sample_pause_panel,
    };
    use norito::codec::Encode;
    fn row(key: &impl Encode, value: &impl Encode) -> json::Value {
        norito::json!({"key": {"encoded_hex": (hex::encode(key.encode()))}, "value": {"encoded_hex": (hex::encode(value.encode()))}})
    }
    let original = encoded(&sccp_world());
    let source: json::Value = json::from_json(&original).unwrap();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut target = world_with(|block| populate_every_sccp_map(block, 3, &budget));
    let before = encoded(&target);
    let mut pause = sample_fast_pause(1);
    pause.until_ms = pause.enacted_at_ms;
    let mut round = sample_fast_pause_round(1);
    round.endorsers.clear();
    let mut panel = sample_pause_panel(1);
    panel.accept_until_ms = panel.term_ends_at_ms + 1;
    let network = SccpNetworkV1::EthereumMainnet;
    for (field, bad) in [
        (
            "sccp_fast_pauses",
            json::Value::Array(vec![row(&network, &pause)]),
        ),
        (
            "sccp_fast_pauses",
            json::Value::Array(vec![row(&SccpNetworkV1::SoraTaira, &sample_fast_pause(1))]),
        ),
        (
            "sccp_fast_pause_rounds",
            json::Value::Array(vec![row(&(network, SccpPanelRoleV1::Primary), &round)]),
        ),
        (
            "sccp_fast_pause_suspended_until_ms",
            json::Value::Array(vec![row(&network, &0_u64)]),
        ),
        ("sccp_pause_panel", json::to_value(&Some(panel)).unwrap()),
    ] {
        for member in ["blocks", "revert"] {
            let mut malformed = source.clone();
            let bad = if field == "sccp_pause_panel" && member == "revert" {
                norito::json!({"value": (bad.clone())})
            } else {
                bad.clone()
            };
            malformed
                .as_object_mut()
                .unwrap()
                .get_mut(field)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(member.into(), bad);
            let error = restore(&json::to_json(&malformed).unwrap(), &mut target)
                .expect_err("invalid current/undo pause DTO");
            assert!(
                error.to_string().contains(field),
                "{field}.{member}: {error}"
            );
            assert_eq!(
                encoded(&target),
                before,
                "{field}.{member} did not publish any prefix"
            );
        }
    }
    restore(&original, &mut target).unwrap();
    assert_eq!(encoded(&target), original);
}

#[test]
fn pause_snapshot_admits_complete_current_and_undo_graph_once_and_holds_final_readers() {
    // Cell values remain charged until the original EBR generation is reclaimed.
    // Advancing that real collector is distinct from dropping shared payload readers.
    fn collect_until(budget: &AllocationBudget, expected: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while budget.reserved_bytes() != expected {
            assert!(
                std::time::Instant::now() < deadline,
                "original SCCP snapshot retirement {} != {expected}",
                budget.reserved_bytes(),
            );
            crossbeam_epoch::pin().flush();
            std::thread::yield_now();
        }
    }
    let source = encoded(&sccp_world());
    let measured = AllocationBudget::new(16 * 1024 * 1024);
    let mut world = World::default();
    json::from_json::<SnapshotSccpState>(&source)
        .unwrap()
        .restore(&mut world, &measured)
        .unwrap();
    let bytes = measured.reserved_bytes();
    let peak_bytes = measured.peak_reserved_bytes();
    assert!(bytes > 0);
    assert!(peak_bytes >= bytes);
    let retirement_pin = crossbeam_epoch::pin();
    drop(world);
    retirement_pin.flush();
    assert!(
        measured.reserved_bytes() > 0,
        "current and undo Cell graphs stay charged while their epoch is pinned"
    );
    drop(retirement_pin);
    collect_until(&measured, 0);
    assert_eq!(measured.reserved_bytes(), 0);
    // Generation records restore directly under the pool before the remaining aggregate
    // graph is admitted. Any local failure must retire all private owners and publish nothing.
    let mut target = World::default();
    let before = encoded(&target);
    let probe = AllocationBudget::new(0);
    let error = json::from_json::<SnapshotSccpState>(&source)
        .unwrap()
        .restore(&mut target, &probe)
        .unwrap_err();
    let AllocationRefusal::ExceedsLimit {
        requested_bytes: first_bytes,
        limit_bytes: 0,
    } = original_allocation_refusal(&error).clone()
    else {
        panic!("first original owner must refuse before allocating: {error:?}");
    };
    assert!(first_bytes > 0 && first_bytes < bytes);
    assert_eq!(probe.reserved_bytes(), 0);
    assert_eq!(encoded(&target), before);
    let refused_budget = AllocationBudget::new(first_bytes);
    let blocker = refused_budget.try_reserve_bytes(1).unwrap();
    let error = json::from_json::<SnapshotSccpState>(&source)
        .unwrap()
        .restore(&mut target, &refused_budget)
        .unwrap_err();
    let AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ..
    } = original_allocation_refusal(&error).clone()
    else {
        panic!("original owner capacity refusal: {error:?}");
    };
    assert_eq!(
        (requested_bytes, reserved_bytes, limit_bytes),
        (first_bytes, 1, first_bytes)
    );
    assert_eq!(
        refused_budget.reserved_bytes(),
        1,
        "refused restoration retains no private prefix"
    );
    assert_eq!(encoded(&target), before);
    drop(blocker);
    let error = json::from_json::<SnapshotSccpState>(&source)
        .unwrap()
        .restore(&mut target, &refused_budget)
        .unwrap_err();
    assert!(matches!(
        original_allocation_refusal(&error),
        AllocationRefusal::Capacity { .. } | AllocationRefusal::ExceedsLimit { .. }
    ));
    collect_until(&refused_budget, 0);
    assert_eq!(
        encoded(&target),
        before,
        "later original admission publishes no prefix"
    );
    // Restore must fund the measured overlap of old/new private map generations;
    // retained bytes alone exclude those transient original owners.
    let budget = AllocationBudget::new(peak_bytes);
    json::from_json::<SnapshotSccpState>(&source)
        .unwrap()
        .restore(&mut target, &budget)
        .unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(encoded(&target), source);
    let readers = {
        let view = target.view();
        (
            view.sccp_fast_pauses().iter().next().unwrap().1.clone(),
            view.sccp_fast_pause_rounds()
                .iter()
                .next()
                .unwrap()
                .1
                .clone(),
            view.sccp_pause_panel().as_ref().unwrap().clone(),
        )
    };
    // Round and panel storage use immutable ordered buffers rather than Model maps.
    // Measure their actual current records through the canonical snapshot projection.
    let reader_bytes = {
        let round: SccpFastPauseRoundV1 =
            json::from_json(&json::to_json(&readers.1).unwrap()).unwrap();
        let panel: SccpPausePanelV1 = json::from_json(&json::to_json(&readers.2).unwrap()).unwrap();
        RetainedSccpFastPause::admission_demand(&readers.0).unwrap()
            + RetainedSccpFastPauseRound::admission_demand(&round).unwrap()
            + RetainedSccpPausePanel::admission_demand(&panel).unwrap()
    };
    drop(target);
    collect_until(&budget, reader_bytes);
    assert_eq!(budget.reserved_bytes(), reader_bytes);
    assert!(
        budget.reserved_bytes() > 0,
        "external current readers retain their actual graphs"
    );
    assert!(
        budget.reserved_bytes() < bytes,
        "unreferenced undo and other graphs retired"
    );
    drop(readers);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn destination_pending_index_restores_current_and_exact_predecessor_generations() {
    use crate::smartcontracts::isi::sccp::test_support::sample_generation;
    use iroha_data_model::sccp::generation::SccpGenerationEndV1;

    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let ended = |seed| {
        let mut record = RetainedSccpGeneration::admit(&sample_generation(seed), &budget).unwrap();
        record.end = Some(SccpGenerationEndV1 {
            end_height: 10,
            end_timestamp_ms: 10_000,
            next_committee_root: record.committee_root,
            successor_validity_ms: record.validity_ms,
        });
        record
    };
    let pending_one = ended(1);
    let mut cleared_one = pending_one.clone();
    cleared_one.dest_cleared_lc = Some(5_000);
    let active_three = RetainedSccpGeneration::admit(&sample_generation(3), &budget).unwrap();
    let mut world = World::default();
    world.sccp_committee_generations = CommitteeStorage::try_restore_admitted(
        world.sccp_committee_generations.allocation_budget().clone(),
        |current, undo| {
            for (id, record) in [(1, cleared_one), (2, ended(2)), (3, ended(3))] {
                current(id, record)?;
            }
            for (id, record) in [(1, Some(pending_one)), (2, None), (3, Some(active_three))] {
                undo(id, record)?;
            }
            Ok::<(), mv::storage::AdmittedStorageError>(())
        },
    )
    .unwrap();
    world.sccp_destination_pending_generations =
        destination_pending_index(&world.sccp_committee_generations);
    let mut restored = World::default();
    restore(&encoded(&world), &mut restored).unwrap();
    assert_eq!(
        restored
            .sccp_destination_pending_generations
            .view()
            .iter()
            .map(|(id, ())| *id)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    {
        let reverted = restored.block_and_revert();
        assert_eq!(
            reverted
                .sccp_destination_pending_generations
                .iter()
                .map(|(id, ())| *id)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert!(reverted.sccp_committee_generations.get(&2).is_none());
        assert!(
            reverted
                .sccp_committee_generations
                .get(&3)
                .unwrap()
                .end
                .is_none()
        );
    }
    let mut advanced = restored.block();
    advanced.sccp_destination_pending_generations.remove(2);
    drop(advanced);
    assert_eq!(
        restored.sccp_destination_pending_generations.view().len(),
        2,
        "discarding a transaction preserves the committed work index"
    );
}
