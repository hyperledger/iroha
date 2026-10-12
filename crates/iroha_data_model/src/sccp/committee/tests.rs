//! Canonical native generation shape, original credential projection and liability boundaries.

use super::*;
use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};
use iroha_crypto::KeyPair;

fn start() -> SccpGenerationStartV1 {
    SccpGenerationStartV1 {
        generation: 1,
        cause: SccpGenerationCauseV1::Genesis,
        height: 1,
        timestamp_ms: 1_000,
        liability_clock: 1_000,
    }
}

fn member(seed: u8) -> SccpGenerationMemberV1 {
    let key = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
    SccpGenerationMemberV1 {
        lane_id: LaneId::SINGLE,
        validator: AccountId::new(key.public_key().clone()),
        activation_height: 1,
    }
}

fn fixture() -> SccpCommitteeGenerationV1 {
    SccpCommitteeGenerationV1::from_epoch(
        start(),
        &SccpParametersV1::taira_default(),
        &crate::sumeragi::epoch::tests::fixture(4),
        vec![Some(member(1)), None, Some(member(2)), Some(member(3))],
    )
    .unwrap()
}

fn ended() -> SccpCommitteeGenerationV1 {
    let mut generation = fixture();
    generation.end = Some(SccpGenerationEndV1 {
        end_height: 10,
        end_timestamp_ms: 2_000,
        next_committee_root: generation.committee_root,
        successor_validity_ms: generation.validity_ms,
    });
    generation
}

#[test]
fn canonical_records_roundtrip_every_cause_and_optional_member() {
    let mut value = ended();
    value.dest_cleared_lc = Some(value.liable_until_lc);
    for cause in [
        SccpGenerationCauseV1::Genesis,
        SccpGenerationCauseV1::KeyChange,
        SccpGenerationCauseV1::Heartbeat,
        SccpGenerationCauseV1::Resync,
    ] {
        value.cause = cause;
        value.generation = if cause == SccpGenerationCauseV1::Genesis {
            1
        } else {
            2
        };
        value.start_height = value.generation;
        value.validate().unwrap();
        roundtrip(&value);
        let bytes = norito::encode_canonical(&value).unwrap();
        let decoded: SccpCommitteeGenerationV1 = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, value);
        decoded.validate().unwrap();
        roundtrip(&cause);
    }
    roundtrip(&fixture());
    roundtrip(&member(1));
    roundtrip(&value.end.unwrap());
    // Neither raw value has an implied Iroha hash low-bit convention.
    let anchor = SccpAnchorV1 {
        core_hash: [0; 32],
        result: [0x80; 32],
    };
    roundtrip(&anchor);
    assert_rejects_unknown_field(&anchor, &[]);
    assert_rejects_unknown_field(&value, &[]);
    assert_rejects_unknown_field(&value, &["members", "0"]);
    assert_rejects_unknown_field(&value, &["end"]);
}

#[test]
fn original_epoch_credentials_define_order_and_creation_facts_are_immutable() {
    for count in [4, 7, 31] {
        let mut epoch = crate::sumeragi::epoch::tests::fixture(count);
        let mut parameters = SccpParametersV1::taira_default();
        parameters.destination_progress_cap_ms = 0;
        let generation =
            SccpCommitteeGenerationV1::from_epoch(start(), &parameters, &epoch, vec![None; count])
                .unwrap();
        for (key, original) in generation.keys.iter().zip(&epoch.committee) {
            assert_eq!(
                key.as_slice(),
                original.validator.public_key().try_to_bytes().unwrap().1
            );
        }
        assert_eq!(generation.progress_cap_ms, 0, "zero is a normative cap");
        let frozen = generation.clone();
        parameters.committee_validity_ms += 1;
        epoch.committee[0].proof_of_possession[0] ^= 1;
        assert_eq!(generation, frozen);
        assert!(matches!(
            SccpCommitteeGenerationV1::from_epoch(start(), &parameters, &epoch, vec![None; count],),
            Err(SccpGenerationError::Epoch(_))
        ));
    }
}

#[test]
fn constructor_refuses_invalid_creation_parameters_epoch_interval_and_overflow() {
    let epoch = crate::sumeragi::epoch::tests::fixture(4);
    let good = SccpParametersV1::taira_default();
    let mut bad = good;
    bad.committee_validity_ms = 1;
    assert!(matches!(
        SccpCommitteeGenerationV1::from_epoch(start(), &bad, &epoch, vec![None; 4],),
        Err(SccpGenerationError::Parameters(_))
    ));
    let mut outside = start();
    outside.height = epoch.authorization.last_height + 1;
    assert_eq!(
        SccpCommitteeGenerationV1::from_epoch(outside, &good, &epoch, vec![None; 4]),
        Err(SccpGenerationError::Field("start_height"))
    );
    let mut overflow = start();
    overflow.timestamp_ms = u64::MAX;
    assert_eq!(
        SccpCommitteeGenerationV1::from_epoch(overflow, &good, &epoch, vec![None; 4]),
        Err(SccpGenerationError::Overflow)
    );
    overflow.timestamp_ms = 1;
    overflow.liability_clock = u64::MAX;
    assert_eq!(
        SccpCommitteeGenerationV1::from_epoch(overflow, &good, &epoch, vec![None; 4]),
        Err(SccpGenerationError::Overflow)
    );
    assert_eq!(
        SccpCommitteeGenerationV1::from_epoch(start(), &good, &epoch, vec![None; 3]),
        Err(SccpGenerationError::Field("members"))
    );
}

#[test]
fn owned_parts_preserve_backing_and_reject_key_substitution() {
    let epoch = crate::sumeragi::epoch::tests::fixture(4);
    let parameters = SccpParametersV1::taira_default();
    let original = fixture();
    let keys = original.keys.clone();
    let members = original.members.clone();
    let key_ptr = keys.as_ptr();
    let member_ptr = members.as_ptr();
    let retained =
        SccpCommitteeGenerationV1::from_owned_parts(start(), &parameters, &epoch, keys, members)
            .unwrap();
    assert_eq!(retained, original);
    assert_eq!(retained.keys.as_ptr(), key_ptr);
    assert_eq!(retained.members.as_ptr(), member_ptr);
    let mut reordered = original.keys.clone();
    reordered.swap(0, 1);
    let mut changed = original.keys.clone();
    changed[0][0] ^= 1;
    for keys in [reordered, changed, original.keys[..3].to_vec()] {
        assert_eq!(
            SccpCommitteeGenerationV1::from_owned_parts(
                start(),
                &parameters,
                &epoch,
                keys,
                original.members.clone(),
            ),
            Err(SccpGenerationError::Field("original_epoch_keys"))
        );
    }
}

#[test]
fn member_shape_preserves_zero_activation_but_not_two_tenures_of_one_account() {
    let mut generation = fixture();
    generation.members[0].as_mut().unwrap().activation_height = 0;
    generation.validate().unwrap();
    generation.generation = 2;
    generation.cause = SccpGenerationCauseV1::Heartbeat;
    generation.start_height = 2;
    let mut duplicate = generation.members[0].clone().unwrap();
    duplicate.activation_height = 2;
    generation.members[1] = Some(duplicate);
    assert_eq!(
        generation.validate(),
        Err(SccpGenerationError::Field("members"))
    );
}

#[test]
fn malformed_decoded_claims_are_not_authority_and_fail_structural_validation() {
    type Mutation = fn(&mut SccpCommitteeGenerationV1);
    let cases: &[(&str, Mutation)] = &[
        ("zero generation", |v| v.generation = 0),
        ("wrong genesis cause", |v| {
            v.cause = SccpGenerationCauseV1::Heartbeat
        }),
        ("late genesis", |v| v.start_height = 2),
        ("non-genesis at genesis height", |v| {
            v.generation = 2;
            v.cause = SccpGenerationCauseV1::Heartbeat;
        }),
        ("genesis clock", |v| v.start_lc -= 1),
        ("short committee", |v| {
            v.keys.pop();
        }),
        ("committee order", |v| v.keys.swap(0, 1)),
        ("duplicate key", |v| v.keys[1] = v.keys[0]),
        ("bad subgroup key", |v| v.keys[0] = [0; 48]),
        ("root mismatch", |v| v.committee_root[0] ^= 1),
        ("short members", |v| {
            v.members.pop();
        }),
        ("duplicate account", |v| v.members[1] = v.members[0].clone()),
        ("wrong lane", |v| {
            v.members[0].as_mut().unwrap().lane_id = LaneId::new(1)
        }),
        ("future activation", |v| {
            v.members[0].as_mut().unwrap().activation_height = 2
        }),
        ("future clock", |v| v.start_lc = v.start_timestamp_ms + 1),
        ("zero validity", |v| v.validity_ms = 0),
        ("long validity", |v| {
            v.validity_ms = SCCP_MAX_VALIDITY_MS_V1 + 1
        }),
        ("short grace", |v| {
            v.grace_ms = SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1 - 1
        }),
        ("long grace", |v| {
            v.grace_ms = SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1 + 1
        }),
        ("long progress cap", |v| {
            v.progress_cap_ms = SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1 + 1
        }),
        ("deadline", |v| v.deadline_ms += 1),
        ("liability deadline", |v| v.liable_until_lc += 1),
        ("early end height", |v| {
            v.end.as_mut().unwrap().end_height = 0
        }),
        ("early end time", |v| {
            v.end.as_mut().unwrap().end_timestamp_ms = 0
        }),
        ("empty successor root", |v| {
            v.end.as_mut().unwrap().next_committee_root = [0; 32]
        }),
        ("zero successor validity", |v| {
            v.end.as_mut().unwrap().successor_validity_ms = 0
        }),
        ("long successor validity", |v| {
            v.end.as_mut().unwrap().successor_validity_ms = SCCP_MAX_VALIDITY_MS_V1 + 1
        }),
        ("early destination clearance", |v| {
            v.dest_cleared_lc = Some(v.start_lc - 1)
        }),
        ("unended destination clearance", |v| {
            v.end = None;
            v.dest_cleared_lc = Some(v.start_lc);
        }),
    ];
    for (label, mutate) in cases {
        let mut claim = ended();
        mutate(&mut claim);
        let encoded = norito::encode_canonical(&claim).unwrap();
        let decoded: SccpCommitteeGenerationV1 = norito::decode_canonical(&encoded).unwrap();
        assert!(decoded.validate().is_err(), "{label}");
    }
}

#[test]
fn liability_is_inclusive_and_uses_creation_windows_without_overflow() {
    let mut generation = ended();
    let until = generation.liable_until_lc;
    let cap = generation.progress_cap_ms;
    assert!(generation.liable_at(2, until));
    assert!(generation.liable_at(2, until + cap));
    assert!(!generation.liable_at(2, until + cap + 1));
    assert!(
        generation.liable_at(1, u64::MAX),
        "current generation always liable"
    );
    generation.dest_cleared_lc = Some(until + 1);
    let cleared_end = until + 1 + generation.grace_ms;
    assert!(generation.liable_at(2, cleared_end));
    assert!(!generation.liable_at(2, cleared_end + 1));
    generation.dest_cleared_lc = Some(generation.start_lc);
    assert!(
        generation.liable_at(2, until),
        "time leg remains independently inclusive"
    );
    assert!(!generation.liable_at(2, until + 1));
    generation.dest_cleared_lc = Some(u64::MAX);
    generation.validate().unwrap();
    assert!(generation.liable_at(2, u64::MAX));
    generation.dest_cleared_lc = None;
    generation.generation = 2;
    generation.cause = SccpGenerationCauseV1::Heartbeat;
    generation.start_height = 2;
    generation.start_lc = u64::MAX - generation.validity_ms - generation.grace_ms;
    generation.start_timestamp_ms = generation.start_lc;
    generation.deadline_ms = generation.start_timestamp_ms + generation.validity_ms;
    generation.liable_until_lc = u64::MAX;
    generation.end.as_mut().unwrap().end_timestamp_ms = generation.start_timestamp_ms;
    generation.validate().unwrap();
    assert!(generation.liable_at(3, u64::MAX));
}
