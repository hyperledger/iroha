//! SCCP snapshot envelope current/undo conservation and malformed-state rejection.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::{populate_every_sccp_map, sample_anchor};
use crate::state::deserialize::StateRestoreError;
#[cfg(test)]
use crate::state::sccp_generation_custody::GenerationFixtureStorage as _;

fn encoded(world: &World) -> String {
    let mut out = String::new();
    serialize_envelope(world, &mut out);
    out
}

fn restore(text: &str, world: &mut World) -> Result<(), StateRestoreError> {
    json::from_json::<SnapshotSccpState>(text)?.restore(world)
}

/// Return a World whose every SCCP map and cell holds a current value and an undo record.
pub(crate) fn sccp_world() -> World {
    let world = World::default();
    {
        let mut block = world.block();
        populate_every_sccp_map(&mut block, 1);
        block.commit();
    }
    {
        let mut block = world.block();
        populate_every_sccp_map(&mut block, 2);
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
    assert_eq!(members.len(), 27, "one member per SCCP world field");
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
        assert_eq!(*replacement.sccp_committee_current.get(), 1);
        assert_eq!(replacement.sccp_committee_generations.len(), 1);
        assert_eq!(*replacement.sccp_liability_clock.get(), 44_000);
        assert_eq!(*replacement.sccp_degraded_run.get(), 1);
        assert_eq!(replacement.sccp_anchor_open.get(), &vec![sample_anchor(1)]);
        assert_eq!(replacement.sccp_anchor_chunks.get(&1), Some(&[1; 32]));
        assert!(replacement.sccp_anchor_chunks.get(&2).is_none());
        assert_eq!(replacement.sccp_light_client_checkpoints.len(), 1);
    }
    {
        let view = restored.view();
        assert_eq!(*view.sccp_committee_current(), 2);
        assert_eq!(view.sccp_committee_generations().len(), 2);
        assert_eq!(view.sccp_anchor_chunks().len(), 2);
        assert_eq!(*view.sccp_liability_clock(), 48_000);
        assert_eq!(*view.sccp_degraded_run(), 2);
        assert_eq!(view.sccp_anchor_open(), &vec![sample_anchor(2)]);
        assert_eq!(view.sccp_history().size, 1);
        assert!(view.sccp_parameters().is_some());
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
    let bad_anchors = json::to_value(&vec![SccpAnchorV1::default(); 4097]).expect("JSON");
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
    use crate::smartcontracts::isi::sccp::test_support::{sample_generation, sample_route};
    use iroha_data_model::sccp::{
        commitment::SccpBlockCommitmentV1, params::SCCP_MESSAGES_MAX_PER_BLOCK_V1,
    };
    let network = SccpNetworkV1::EthereumMainnet;
    let control = |commitment_index| SccpControlRecordV1 {
        track: 1,
        parliament_paused: true,
        fast_pause_until_ms: 0,
        height: 4,
        commitment_index,
        leaf: [1; 32],
        certificate_id: [1; 32],
        effect_hash: [0x45; 32],
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
            "sccp_committee_generations",
            world_with(|block| {
                let mut malformed = sample_generation(1, 5);
                malformed.members.pop();
                block.sccp_committee_generations.insert(1, malformed);
            }),
            world_with(|block| {
                block
                    .sccp_committee_generations
                    .insert(1, sample_generation(1, 5));
            }),
        ),
        (
            "sccp_committee_generations",
            world_with(|block| {
                block
                    .sccp_committee_generations
                    .insert(2, sample_generation(1, 5));
            }),
            world_with(|block| {
                block
                    .sccp_committee_generations
                    .insert(1, sample_generation(1, 5));
            }),
        ),
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
            "sccp_committee_generations",
            world_with(|block| {
                let mut malformed = sample_generation(1, 5);
                malformed.committee_root[0] ^= 1;
                block.sccp_committee_generations.insert(1, malformed);
            }),
            world_with(|block| {
                block
                    .sccp_committee_generations
                    .insert(1, sample_generation(1, 5));
            }),
        ),
        (
            "sccp_control_messages",
            world_with(|block| {
                block
                    .sccp_control_messages
                    .insert((network, 1, 1), control(SCCP_MESSAGES_MAX_PER_BLOCK_V1));
            }),
            world_with(|block| {
                block
                    .sccp_control_messages
                    .insert((network, 1, 1), control(0));
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
        ((network, 0, 1), control(0)),
        ((network, 1, 0), control(0)),
        ((SccpNetworkV1::SoraTaira, 1, 1), control(0)),
        (
            (network, 1, 1),
            SccpControlRecordV1 {
                track: 0,
                ..control(0)
            },
        ),
        (
            (network, 1, 1),
            SccpControlRecordV1 {
                track: 2,
                ..control(0)
            },
        ),
        (
            (network, 1, 1),
            SccpControlRecordV1 {
                certificate_id: [0; 32],
                ..control(0)
            },
        ),
        (
            (network, 1, 1),
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
                block
                    .sccp_control_messages
                    .insert((network, 1, 1), control(0));
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
fn anchor_snapshot_preserves_full_open_chunk_and_present_zero_root() {
    let original = world_with(|block| {
        *block.sccp_anchor_open.get_mut() = vec![SccpAnchorV1::default(); 4096];
        block.sccp_anchor_chunks.insert(0, [0; 32]);
    });
    let text = encoded(&original);
    let mut restored = World::default();
    restore(&text, &mut restored).expect("inclusive anchor limit and zero digest restore");
    assert_eq!(encoded(&restored), text);
    assert_eq!(restored.view().sccp_anchor_open().len(), 4096);
    assert_eq!(restored.view().sccp_anchor_chunks().get(&0), Some(&[0; 32]));
}
