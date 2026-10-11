//! DA snapshot index coherence at current and retained predecessor cuts.
//!
//! Records carry real deterministic signatures. These are persisted-index tests,
//! not current-controller admission or block-finality qualification.

use super::*;
use iroha_data_model::da::commitment::DaCommitmentLocation;

fn record(sequence: u8, alias: Option<&str>) -> DaPinIntentWithLocation {
    let key =
        iroha_crypto::KeyPair::try_from_seed(vec![0x97; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let network = iroha_data_model::NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x98; 32])),
    );
    let intent = crate::da::signed_test_pin_intent(
        crate::da::signed_test_ingest_authorization(
            network,
            &key,
            LaneId::SINGLE,
            1,
            u64::from(sequence),
            1,
        ),
        &key,
        StorageTicketId::new([sequence; 32]),
        ManifestDigest::new([sequence.wrapping_add(64); 32]),
        alias.map(str::to_owned),
    );
    DaPinIntentWithLocation {
        intent,
        location: DaCommitmentLocation {
            block_height: u64::from(sequence) + 1,
            index_in_bundle: 0,
        },
    }
}

fn insert(world: &World, record: DaPinIntentWithLocation) {
    let mut block = world.block();
    let intent = &record.intent;
    if let Some(alias) = &intent.alias {
        block
            .da_pin_intents_by_alias
            .insert(alias.clone(), intent.storage_ticket);
    }
    block
        .da_pin_intents_by_manifest
        .insert(intent.manifest_hash, intent.storage_ticket);
    block.da_pin_intents_by_lane_epoch.insert(
        (intent.lane_id, intent.epoch, intent.sequence),
        intent.storage_ticket,
    );
    block
        .da_pin_intents_by_ticket
        .insert(intent.storage_ticket, record);
    block.commit();
}

fn fixture() -> (World, DaPinIntentWithLocation) {
    let world = World::default();
    let first = record(1, Some("pin/alias"));
    insert(&world, first.clone());
    (world, first)
}

fn restore(world: &World) -> Result<World, json::Error> {
    let encoded = json::to_json(world).unwrap();
    let ivm = IVM::new(0);
    let seed = IvmSeed {
        ivm: &ivm,
        _marker: PhantomData,
    };
    parse_world(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        SnapshotJsonMap::parse(&encoded, "world")?,
        &seed,
    )
    .map_err(crate::state::deserialize::snapshot_format_error_for_test)
}

fn maps(world: &World) -> [String; 4] {
    [
        json::to_json(&world.da_pin_intents_by_ticket).unwrap(),
        json::to_json(&world.da_pin_intents_by_alias).unwrap(),
        json::to_json(&world.da_pin_intents_by_manifest).unwrap(),
        json::to_json(&world.da_pin_intents_by_lane_epoch).unwrap(),
    ]
}

fn without_undo<T: norito::json::JsonSerialize + norito::json::JsonDeserialize>(value: &T) -> T {
    let mut encoded: json::Value = json::from_str(&json::to_json(value).unwrap()).unwrap();
    let json::Value::Object(fields) = &mut encoded else {
        panic!("storage object")
    };
    fields.insert("revert".to_owned(), json::Value::Object(BTreeMap::new()));
    json::from_str(&json::to_json(&encoded).unwrap()).unwrap()
}

#[test]
fn current_and_undo_maps_roundtrip_without_validation_mutating_history() {
    let (world, first) = fixture();
    let second = record(2, Some("pin/alias"));
    insert(&world, second.clone());
    let before = maps(&world);
    validate_da_pin_persistence(&world).unwrap();
    assert_eq!(
        maps(&world),
        before,
        "validation cannot consume actual undo"
    );
    let restored = restore(&world).unwrap();
    assert_eq!(maps(&restored), before);
    assert_eq!(
        restored.da_pin_intents_by_alias.view().get("pin/alias"),
        Some(&second.intent.storage_ticket)
    );
    let previous = restored.da_pin_intents_by_ticket.block_and_revert();
    assert_eq!(previous.get(&first.intent.storage_ticket), Some(&first));
    assert_eq!(previous.get(&second.intent.storage_ticket), None);
    drop(previous);
    assert_eq!(maps(&restored), before);
}

#[test]
fn every_pin_map_is_a_required_first_release_snapshot_field() {
    let encoded = json::to_json(&World::default()).unwrap();
    let ivm = IVM::new(0);
    let seed = IvmSeed {
        ivm: &ivm,
        _marker: PhantomData,
    };
    for name in [
        "da_pin_intents_by_ticket",
        "da_pin_intents_by_alias",
        "da_pin_intents_by_manifest",
        "da_pin_intents_by_lane_epoch",
    ] {
        let mut map = SnapshotJsonMap::parse(&encoded, "world").unwrap();
        assert!(
            map.remove(name).is_some(),
            "serialized schema must include {name}"
        );
        let error = parse_world(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            map,
            &seed,
        )
        .map_err(crate::state::deserialize::snapshot_format_error_for_test)
        .err()
        .expect("missing canonical map must fail");
        assert!(error.to_string().contains(name), "{error}");
    }
}

#[test]
fn mismatched_primary_and_missing_or_foreign_secondary_rows_fail_restore() {
    for mutation in 0..6 {
        let (world, first) = fixture();
        {
            let mut block = world.block();
            match mutation {
                0 => {
                    block
                        .da_pin_intents_by_ticket
                        .remove(first.intent.storage_ticket);
                    block
                        .da_pin_intents_by_ticket
                        .insert(StorageTicketId::new([33; 32]), first.clone());
                }
                1 => {
                    block
                        .da_pin_intents_by_manifest
                        .remove(first.intent.manifest_hash);
                }
                2 => {
                    block
                        .da_pin_intents_by_manifest
                        .insert(ManifestDigest::new([34; 32]), first.intent.storage_ticket);
                }
                3 => {
                    block.da_pin_intents_by_lane_epoch.remove((
                        first.intent.lane_id,
                        first.intent.epoch,
                        first.intent.sequence,
                    ));
                }
                4 => {
                    block
                        .da_pin_intents_by_lane_epoch
                        .insert((LaneId::SINGLE, 9, 9), first.intent.storage_ticket);
                }
                5 => {
                    block.da_pin_intents_by_manifest.insert(
                        ManifestDigest::new([35; 32]),
                        StorageTicketId::new([36; 32]),
                    );
                }
                _ => unreachable!(),
            }
            block.commit();
        }
        let error = restore(&world)
            .err()
            .expect("malformed persisted indexes must fail");
        assert!(
            error
                .to_string()
                .contains("invalid current DA pin-index projection"),
            "mutation {mutation}: {error}"
        );
    }
}

#[test]
fn duplicate_manifest_lane_identity_or_location_cannot_survive_snapshot_restore() {
    for mutation in 0..3 {
        let (world, first) = fixture();
        let mut second = record(2, None);
        // These adversarial persisted values test identity/index consistency;
        // changing the index fields does not claim valid ingestion authorization.
        match mutation {
            0 => second.intent.manifest_hash = first.intent.manifest_hash,
            1 => {
                second.intent.lane_id = first.intent.lane_id;
                second.intent.epoch = first.intent.epoch;
                second.intent.sequence = first.intent.sequence;
            }
            2 => second.location = first.location,
            _ => unreachable!(),
        }
        insert(&world, second);
        let error = restore(&world)
            .err()
            .expect("duplicate canonical identity must fail");
        assert!(
            error
                .to_string()
                .contains("invalid current DA pin-index projection"),
            "mutation {mutation}: {error}"
        );
    }
}

#[test]
fn alias_rebinding_and_absence_are_valid_but_foreign_bindings_are_rejected() {
    let (world, first) = fixture();
    let second = record(2, Some("pin/alias"));
    insert(&world, second.clone());
    restore(&world).unwrap();
    {
        let mut block = world.block();
        block.da_pin_intents_by_alias.remove("pin/alias".to_owned());
        block.commit();
    }
    let restored = restore(&world).unwrap();
    assert_eq!(
        restored
            .da_pin_intents_by_ticket
            .view()
            .get(&first.intent.storage_ticket),
        Some(&first)
    );
    assert_eq!(
        restored
            .da_pin_intents_by_ticket
            .view()
            .get(&second.intent.storage_ticket),
        Some(&second)
    );
    assert!(
        restored.da_pin_intents_by_alias.view().is_empty(),
        "retirement need not bind older retained aliases"
    );
    for wrong_alias in [false, true] {
        let (world, first) = fixture();
        let mut block = world.block();
        block.da_pin_intents_by_alias.insert(
            if wrong_alias {
                "undeclared/alias".to_owned()
            } else {
                "pin/alias".to_owned()
            },
            if wrong_alias {
                first.intent.storage_ticket
            } else {
                StorageTicketId::new([39; 32])
            },
        );
        block.commit();
        let error = restore(&world)
            .err()
            .expect("foreign alias binding must fail");
        assert!(
            error.to_string().contains("da_pin_intents_by_alias"),
            "{error}"
        );
    }
}

#[test]
fn individually_plausible_current_maps_cannot_hide_inconsistent_retained_undo() {
    for mutation in 0..4 {
        let (mut world, _) = fixture();
        match mutation {
            0 => world.da_pin_intents_by_ticket = without_undo(&world.da_pin_intents_by_ticket),
            1 => world.da_pin_intents_by_alias = without_undo(&world.da_pin_intents_by_alias),
            2 => world.da_pin_intents_by_manifest = without_undo(&world.da_pin_intents_by_manifest),
            3 => {
                world.da_pin_intents_by_lane_epoch =
                    without_undo(&world.da_pin_intents_by_lane_epoch)
            }
            _ => unreachable!(),
        }
        let before = maps(&world);
        let error = restore(&world)
            .err()
            .expect("incoherent predecessor must fail");
        assert!(
            error
                .to_string()
                .contains("invalid predecessor DA pin-index projection"),
            "mutation {mutation}: {error}"
        );
        assert_eq!(
            maps(&world),
            before,
            "failed restore cannot change source undo"
        );
    }
}
