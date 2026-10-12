//! Current fast-pause codec, cause binding and strict ordering controls.

use super::*;
use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};

fn network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(
        Hash::new(b"SCCP pause codec fixture"),
    ))
}

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}

fn endorsement(incident_digest: [u8; 32], recorded_at_height: u64) -> SccpFastPauseEndorsementV1 {
    SccpFastPauseEndorsementV1 {
        incident_digest,
        recorded_at_height,
    }
}

fn pause() -> SccpFastPauseV1 {
    SccpFastPauseV1 {
        certificate_id: [1; 32],
        effect_hash: [2; 32],
        panel_id: [3; 32],
        enacted_at: SccpPassPositionV1 {
            height: 9,
            position: 4,
        },
        enacted_at_ms: 1_000,
        until_ms: 2_000,
        taira: true,
        revisions: vec![1, 3],
    }
}

fn panel() -> SccpPausePanelV1 {
    let drawn: Vec<_> = (1..=15).map(account).collect();
    let accepted = [drawn[0].clone(), drawn[10].clone()].into_iter().collect();
    SccpPausePanelV1 {
        panel_seq: 1,
        pulse_id: [1; 32],
        seated_height: 10,
        seated_at_ms: 1_000,
        accept_until_ms: 2_000,
        term_ends_at_ms: 3_000,
        drawn,
        accepted,
        primary_id: [2; 32],
        backup_id: [3; 32],
    }
}

fn certificate() -> SccpFastPauseCertificateV1 {
    SccpFastPauseCertificateV1 {
        network_id: network(),
        network: SccpNetworkV1::EthereumMainnet,
        panel_id: [1; 32],
        panel_role: SccpPanelRoleV1::Primary,
        panel_seq: 1,
        head: 0,
        endorsement_root: [2; 32],
        endorsement_count: 4,
        quorum: 4,
        incident_root: [3; 32],
        effect_preimage_hash: SccpFastPauseCertificateV1::effect_hash(
            network(),
            SccpNetworkV1::EthereumMainnet,
            0,
        ),
        certified_at_height: 11,
        certified_at_ms: 2_000,
    }
}

#[test]
fn pause_records_roundtrip_and_reject_missing_or_unknown_fields() {
    let pause = pause();
    let panel = panel();
    let round = SccpFastPauseRoundV1 {
        panel_id: panel.primary_id,
        panel_seq: panel.panel_seq,
        head: 0,
        opened_at_ms: 1_000,
        closes_at_ms: 2_000,
        endorsers: [(panel.drawn[0].clone(), endorsement([4; 32], 10))]
            .into_iter()
            .collect(),
        certify_due: false,
    };
    assert!(pause.has_valid_shape());
    assert!(panel.has_geometry(5));
    assert!(round.has_valid_shape());
    roundtrip(&pause);
    roundtrip(&panel);
    roundtrip(&round);
    roundtrip(&certificate());
    roundtrip(&SccpFastPauseCertificateId::derive_v1(&certificate()));
    for role in [SccpPanelRoleV1::Primary, SccpPanelRoleV1::Backup] {
        roundtrip(&role);
    }
    assert_rejects_unknown_field(&pause, &[]);
    assert_rejects_unknown_field(&pause, &["enacted_at"]);
    assert_rejects_unknown_field(&panel, &[]);
    assert_rejects_unknown_field(&round, &[]);
    assert_rejects_unknown_field(&certificate(), &[]);
    for key in [
        "certificate_id",
        "effect_hash",
        "panel_id",
        "enacted_at",
        "enacted_at_ms",
        "until_ms",
        "taira",
        "revisions",
    ] {
        let mut value = norito::json::to_value(&pause).unwrap();
        let norito::json::Value::Object(fields) = &mut value else {
            unreachable!()
        };
        fields.remove(key);
        assert!(
            norito::json::from_json::<SccpFastPauseV1>(&norito::json::to_json(&value).unwrap())
                .is_err(),
            "missing {key}"
        );
    }
}

#[test]
fn pause_endorsement_named_record_roundtrips_with_closed_schema() {
    let original = endorsement([0xa5; 32], u64::MAX);
    roundtrip(&original);
    assert_rejects_unknown_field(&original, &[]);
    let value = norito::json::to_value(&original).unwrap();
    let fields = value.as_object().expect("named endorsement object");
    assert_eq!(fields.len(), 2);
    assert_eq!(
        fields["incident_digest"],
        norito::json::to_value(&original.incident_digest).unwrap()
    );
    assert_eq!(
        fields["recorded_at_height"],
        norito::json::Value::from(u64::MAX)
    );
    for missing in ["incident_digest", "recorded_at_height"] {
        let mut malformed = value.clone();
        malformed.as_object_mut().unwrap().remove(missing);
        assert!(
            norito::json::from_json::<SccpFastPauseEndorsementV1>(
                &norito::json::to_json(&malformed).unwrap()
            )
            .is_err(),
            "missing {missing}"
        );
    }
    // A timestamp spelling or positional JSON value is not a first-release record.
    let mut timestamp = value.clone();
    let fields = timestamp.as_object_mut().unwrap();
    let height = fields.remove("recorded_at_height").unwrap();
    fields.insert("recorded_at_ms".to_owned(), height);
    assert!(
        norito::json::from_json::<SccpFastPauseEndorsementV1>(
            &norito::json::to_json(&timestamp).unwrap()
        )
        .is_err()
    );
    let schema = SccpFastPauseRoundV1::schema();
    let Some(iroha_schema::Metadata::Struct(fields)) = schema.get::<SccpFastPauseEndorsementV1>()
    else {
        panic!("the round must include its endorsement's named schema");
    };
    assert_eq!(fields.declarations.len(), 2);
    assert_eq!(fields.declarations[0].name, "incident_digest");
    assert_eq!(
        fields.declarations[0].ty,
        core::any::TypeId::of::<[u8; 32]>()
    );
    assert_eq!(fields.declarations[1].name, "recorded_at_height");
    assert_eq!(fields.declarations[1].ty, core::any::TypeId::of::<u64>());
    assert!(schema.contains_key::<BTreeMap<AccountId, SccpFastPauseEndorsementV1>>());
}

#[test]
fn pause_round_rejects_positional_endorsement_json() {
    let row = SccpFastPauseRoundV1 {
        panel_id: [1; 32],
        panel_seq: 1,
        head: 0,
        opened_at_ms: 1_000,
        closes_at_ms: 2_000,
        endorsers: [(account(1), endorsement([2; 32], 7))]
            .into_iter()
            .collect(),
        certify_due: false,
    };
    assert!(row.has_valid_shape());
    roundtrip(&row);
    let mut malformed = norito::json::to_value(&row).unwrap();
    let entries = malformed
        .as_object_mut()
        .unwrap()
        .get_mut("endorsers")
        .unwrap()
        .as_object_mut()
        .unwrap();
    *entries.values_mut().next().unwrap() = norito::json::Value::Array(vec![
        norito::json::to_value(&[2_u8; 32]).unwrap(),
        norito::json::Value::from(7_u64),
    ]);
    assert!(
        norito::json::from_json::<SccpFastPauseRoundV1>(
            &norito::json::to_json(&malformed).unwrap()
        )
        .is_err()
    );
}

#[test]
fn pause_parts_expire_without_a_block_and_lifts_compare_original_positions() {
    let row = pause();
    assert!(row.holds_taira(1_999));
    assert!(!row.holds_taira(2_000));
    assert_eq!(row.destination_expiry(1, 1_999), 2_000);
    assert_eq!(row.destination_expiry(2, 1_999), 0);
    assert_eq!(row.destination_expiry(3, 2_000), 0);
    for (height, position, timestamp_ms, allowed) in [
        (9, 5, 1_000, true),
        (9, 4, u64::MAX, false),
        (9, 3, u64::MAX, false),
        (8, u32::MAX, u64::MAX, false),
        (10, 0, 0, true),
    ] {
        assert_eq!(
            row.enacted_at.precedes_casting_open(GovernanceAnchorV1 {
                height,
                position,
                timestamp_ms
            }),
            allowed
        );
    }
    let mut bad = row.clone();
    bad.revisions = vec![3, 1];
    assert!(!bad.has_valid_shape());
    bad.revisions = vec![1, 1];
    assert!(!bad.has_valid_shape());
    bad.revisions = vec![0];
    assert!(!bad.has_valid_shape());
    bad.revisions.clear();
    bad.taira = false;
    assert!(!bad.has_valid_shape());
    bad.taira = true;
    assert!(bad.has_valid_shape());
    bad.until_ms = bad.enacted_at_ms;
    assert!(!bad.has_valid_shape());
    for field in [0, 1, 2] {
        let mut bad = row.clone();
        match field {
            0 => bad.certificate_id = [0; 32],
            1 => bad.effect_hash = [0; 32],
            _ => bad.panel_id = [0; 32],
        }
        assert!(!bad.has_valid_shape());
    }
}

#[test]
fn panel_shape_rejects_duplicate_members_and_foreign_acceptance() {
    let original = panel();
    assert!(original.has_geometry(5));
    assert!(!original.has_geometry(6));
    let mut bad = original.clone();
    bad.drawn[5] = bad.drawn[0].clone();
    assert!(!bad.has_geometry(5));
    let mut bad = original.clone();
    bad.accepted.insert(account(99));
    assert!(!bad.has_geometry(5));
    let mut bad = original.clone();
    bad.drawn.truncate(9);
    assert!(!bad.has_geometry(5));
    let mut bad = original.clone();
    bad.drawn.push(account(99));
    assert!(!bad.has_geometry(5));
    let mut bad = original.clone();
    bad.backup_id = bad.primary_id;
    assert!(!bad.has_geometry(5));
    let mut bad = original;
    bad.term_ends_at_ms = bad.accept_until_ms;
    assert!(!bad.has_geometry(5));
}

#[test]
fn round_shape_rejects_empty_or_unbound_endorsements() {
    let mut row = SccpFastPauseRoundV1 {
        panel_id: [1; 32],
        panel_seq: 1,
        head: 0,
        opened_at_ms: 1_000,
        closes_at_ms: 2_000,
        endorsers: BTreeMap::new(),
        certify_due: false,
    };
    assert!(!row.has_valid_shape());
    row.endorsers.insert(account(1), endorsement([2; 32], 1));
    assert!(row.has_valid_shape());
    row.endorsers.insert(account(2), endorsement([0; 32], 1));
    assert!(!row.has_valid_shape());
    row.endorsers.insert(account(2), endorsement([2; 32], 0));
    assert!(!row.has_valid_shape());
    row.endorsers.insert(account(2), endorsement([2; 32], 1));
    assert!(row.has_valid_shape());
    row.closes_at_ms = row.opened_at_ms;
    assert!(!row.has_valid_shape());
}

#[test]
fn certificate_identity_binds_every_cause_field_and_effect_domain() {
    let original = certificate();
    let id = SccpFastPauseCertificateId::derive_v1(&original);
    assert_ne!(id.as_bytes(), &original.effect_preimage_hash);
    let mut variants = [original; 14];
    variants[0].network_id = NetworkId::from_genesis_hash(
        HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(Hash::new(b"other")),
    );
    variants[1].network = SccpNetworkV1::BscMainnet;
    variants[2].panel_id[0] ^= 1;
    variants[3].panel_role = SccpPanelRoleV1::Backup;
    variants[4].panel_seq += 1;
    variants[5].head += 1;
    variants[6].endorsement_root[0] ^= 1;
    variants[7].endorsement_count += 1;
    variants[8].quorum += 1;
    variants[9].incident_root[0] ^= 1;
    variants[10].effect_preimage_hash[0] ^= 1;
    variants[11].certified_at_height += 1;
    variants[12].certified_at_ms += 1;
    variants[13].network = SccpNetworkV1::TonMainnet;
    for changed in variants {
        assert_ne!(SccpFastPauseCertificateId::derive_v1(&changed), id);
    }
    for (network_id, network, head) in [
        (variants[0].network_id, original.network, original.head),
        (original.network_id, variants[1].network, original.head),
        (original.network_id, original.network, original.head + 1),
    ] {
        assert_ne!(
            SccpFastPauseCertificateV1::effect_hash(network_id, network, head),
            original.effect_preimage_hash
        );
    }
}
