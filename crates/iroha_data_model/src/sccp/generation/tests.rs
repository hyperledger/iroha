//! Exact SCCP generation, liability-clock and anchor codec and boundary controls.

use super::*;
use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};
use iroha_crypto::{Algorithm, Hash, KeyPair};

fn generation() -> SccpCommitteeGenerationV1 {
    let mut keys: Vec<[u8; 48]> = (1..=4)
        .map(|seed| {
            let pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap();
            pair.public_key()
                .try_to_bytes()
                .unwrap()
                .1
                .try_into()
                .unwrap()
        })
        .collect();
    keys.sort();
    let account = AccountId::new(
        KeyPair::try_from_seed(vec![9; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    );
    SccpCommitteeGenerationV1 {
        generation: 1,
        committee_root: crate::sumeragi_finality::certified_result::committee_root(&keys).unwrap(),
        keys,
        members: vec![
            Some(SccpGenerationMemberV1 {
                lane_id: LaneId::SINGLE,
                validator: account,
                activation_height: 1,
            }),
            None,
            None,
            None,
        ],
        cause: SccpGenerationCauseV1::Genesis,
        start_height: 1,
        start_timestamp_ms: 1_000,
        start_lc: 1_000,
        validity_ms: 100,
        deadline_ms: 1_100,
        grace_ms: 20,
        progress_cap_ms: 30,
        liable_until_lc: 1_120,
        dest_cleared_lc: None,
        end: None,
    }
}

#[test]
fn generation_records_roundtrip_and_reject_unknown_fields() {
    let mut row = generation();
    roundtrip(&row);
    for missing in ["end", "dest_cleared_lc"] {
        let mut raw = norito::json::to_value(&row).unwrap();
        let norito::json::Value::Object(fields) = &mut raw else {
            unreachable!()
        };
        fields.remove(missing);
        assert!(
            norito::json::from_json::<SccpCommitteeGenerationV1>(
                &norito::json::to_json(&raw).unwrap()
            )
            .is_err(),
            "required field {missing}"
        );
    }
    assert_rejects_unknown_field(&row, &[]);
    assert_rejects_unknown_field(&row, &["members", "0"]);
    row.end = Some(SccpGenerationEndV1 {
        end_height: 7,
        end_timestamp_ms: 1_050,
        next_committee_root: [3; 32],
        successor_validity_ms: 100,
    });
    row.dest_cleared_lc = Some(1_060);
    roundtrip(&row);
    assert_rejects_unknown_field(&row, &["end"]);
    for cause in [
        SccpGenerationCauseV1::Genesis,
        SccpGenerationCauseV1::KeyChange,
        SccpGenerationCauseV1::Heartbeat,
        SccpGenerationCauseV1::Resync,
    ] {
        roundtrip(&cause);
        assert_rejects_unknown_field(&cause, &[]);
    }
    let anchor = SccpAnchorV1 {
        core_hash: [1; 32],
        result: [2; 32],
    };
    roundtrip(&anchor);
    assert_rejects_unknown_field(&anchor, &[]);
}

#[test]
fn stored_generation_rejects_bad_geometry_bindings_roots_and_deadlines() {
    let row = generation();
    assert!(row.is_well_formed());
    let mut candidates = Vec::new();
    let mut wrong = row.clone();
    wrong.generation = 0;
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.start_height = 0;
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.generation = 2;
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.cause = SccpGenerationCauseV1::Resync;
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.start_lc += 1;
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.keys.pop();
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.keys.swap(0, 1);
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.keys[1] = wrong.keys[0];
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.members.pop();
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.keys[0] = [0; 48];
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.committee_root[0] ^= 1;
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.validity_ms = 0;
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.deadline_ms += 1;
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.liable_until_lc += 1;
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.dest_cleared_lc = Some(row.start_lc - 1);
    candidates.push(wrong);
    let mut wrong = row.clone();
    wrong.end = Some(SccpGenerationEndV1 {
        end_height: 0,
        end_timestamp_ms: 900,
        next_committee_root: [0; 32],
        successor_validity_ms: 0,
    });
    candidates.push(wrong);
    for wrong in candidates {
        assert!(!wrong.is_well_formed(), "{wrong:?}");
    }
    let mut saturated = row;
    saturated.start_timestamp_ms = u64::MAX - 5;
    saturated.start_lc = u64::MAX - 6;
    saturated.deadline_ms = u64::MAX;
    saturated.liable_until_lc = u64::MAX;
    assert!(saturated.is_well_formed());
}

#[test]
fn liability_is_inclusive_and_uses_the_captured_progress_and_grace_windows() {
    let mut row = generation();
    assert!(
        row.is_liable(1, u64::MAX),
        "current generation stays liable"
    );
    assert!(row.is_liable(2, 1_120));
    assert!(
        row.is_liable(2, 1_150),
        "missing destination progress includes its cap boundary"
    );
    assert!(!row.is_liable(2, 1_151));
    row.dest_cleared_lc = Some(1_140);
    assert!(
        row.is_liable(2, 1_160),
        "clearance retains the full original evidence grace"
    );
    assert!(!row.is_liable(2, 1_161));
    row.dest_cleared_lc = Some(1_001);
    assert!(
        row.is_liable(2, 1_120),
        "early clearance cannot shorten the time leg"
    );
    assert!(!row.is_liable(2, 1_121));
    row.dest_cleared_lc = Some(u64::MAX - 1);
    assert!(
        row.is_liable(2, u64::MAX),
        "overflow saturates and never releases early"
    );
}

#[test]
fn liability_clock_caps_halts_and_never_wraps_or_runs_backward() {
    assert_eq!(next_liability_clock_v1(100, 200, 201, 1_000), 101);
    assert_eq!(next_liability_clock_v1(100, 200, 100, 1_000), 100);
    assert_eq!(
        next_liability_clock_v1(100, 200, u64::MAX, 1_000),
        100 + 1_000 + SCCP_LC_SLACK_MS_V1
    );
    assert_eq!(
        next_liability_clock_v1(u64::MAX - 2, u64::MAX - 2, u64::MAX, u64::MAX),
        u64::MAX
    );
    for heartbeat in [0, 1, 3_600_000, 86_400_000, u64::MAX] {
        for parent_time in [0, 100, u64::MAX - 1, u64::MAX] {
            let parent_lc = parent_time / 2;
            let next = next_liability_clock_v1(parent_lc, parent_time, u64::MAX, heartbeat);
            assert!(next >= parent_lc);
            assert!(next - parent_lc <= heartbeat.saturating_add(SCCP_LC_SLACK_MS_V1));
        }
    }
}

fn anchors() -> Vec<SccpAnchorV1> {
    (0..SCCP_ANCHOR_CHUNK_SIZE_V1)
        .map(|index| {
            let mut core_hash = [0; 32];
            core_hash[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let mut result = [0; 32];
            result[8..16].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            SccpAnchorV1 { core_hash, result }
        })
        .collect()
}

/// Independent full-level implementation; production uses a logarithmic fixed frontier.
fn reference(chunk: u64, anchors: &[SccpAnchorV1], position: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    let mut level: Vec<[u8; 32]> = anchors
        .iter()
        .enumerate()
        .map(|(index, anchor)| {
            let height = chunk * 4_096 + index as u64 + 1;
            let input = [
                b"sccp/anchor-leaf/v1".as_slice(),
                &height.to_be_bytes(),
                &anchor.core_hash,
                &anchor.result,
            ]
            .concat();
            Hash::new(input).into()
        })
        .collect();
    let mut index = position;
    let mut path = Vec::new();
    while level.len() > 1 {
        path.push(level[index ^ 1]);
        level = level
            .chunks_exact(2)
            .map(|pair| {
                Hash::new([b"sccp/anchor-node/v1".as_slice(), &pair[0], &pair[1]].concat()).into()
            })
            .collect();
        index /= 2;
    }
    (level[0], path)
}

#[test]
fn anchor_frontier_matches_full_tree_and_exact_witnesses_bind_height_core_hash_and_result() {
    let rows = anchors();
    assert_eq!(anchor_chunk_root_v1(0, &rows[..4_095]), None);
    assert_eq!(anchor_chunk_root_v1(u64::MAX, &rows), None);
    assert_eq!(anchor_leaf_v1(0, &rows[0]), None);
    for chunk in [0, 1, 77] {
        let root = anchor_chunk_root_v1(chunk, &rows).unwrap();
        for index in [0, 1, 2047, 2048, 4095] {
            let (expected, path) = reference(chunk, &rows, index);
            assert_eq!(root, expected);
            let height = chunk * 4096 + index as u64 + 1;
            assert_eq!(path.len(), SCCP_ANCHOR_PATH_LENGTH_V1);
            assert!(verify_anchor_path_v1(height, &rows[index], &path, &root));
            assert!(!verify_anchor_path_v1(
                height + 4096,
                &rows[index],
                &path,
                &root
            ));
            assert!(!verify_anchor_path_v1(0, &rows[index], &path, &root));
            assert!(!verify_anchor_path_v1(
                height,
                &rows[index],
                &path[..11],
                &root
            ));
            let mut changed = rows[index];
            changed.core_hash[0] ^= 1;
            assert!(!verify_anchor_path_v1(height, &changed, &path, &root));
            let mut changed = rows[index];
            changed.result[0] ^= 1;
            assert!(!verify_anchor_path_v1(height, &changed, &path, &root));
            let mut changed_path = path.clone();
            changed_path[0][0] ^= 1;
            assert!(!verify_anchor_path_v1(
                height,
                &rows[index],
                &changed_path,
                &root
            ));
        }
    }
}
