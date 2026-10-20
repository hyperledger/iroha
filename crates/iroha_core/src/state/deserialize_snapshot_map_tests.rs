//! Original-pool snapshot field indexes and allocation-free canonical comparison.

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
use mv::storage::AdmittedStorageError;
use std::{alloc::Layout, task::Context};

fn storage_error(error: StateRestoreError) -> AdmittedStorageError {
    let StateRestoreError::Admission(StateAdmissionError::Storage(
        StateStorageAdmissionError::World(original),
    )) = error
    else {
        panic!("snapshot index refusal must retain its original storage source");
    };
    original
}

#[test]
fn snapshot_index_retains_exact_original_layout_and_borrows_keys_through_moves() {
    let raw = r#"{"world":{"consensus_evidence":{"revert":{},"blocks":{}}},"tip":7}"#;
    let layout = Layout::array::<SnapshotJsonEntry<'_>>(2).unwrap();
    let original = AllocationBudget::new(layout.size());
    let foreign = AllocationBudget::new(layout.size());
    let mut map = None;
    let allocations = allocations_during(|| {
        map = Some(
            SnapshotJsonMap::parse_admitted(raw, "state", &["world", "tip"], &original).unwrap(),
        );
    });
    let mut map = map.unwrap();
    let index = map.admitted.as_ref().unwrap();
    assert!(
        index.belongs_to(&original),
        "snapshot index retains the captured original pool"
    );
    assert!(!index.belongs_to(&foreign));
    assert_eq!(original.reserved_bytes(), layout.size());
    assert_eq!(
        allocations, 1,
        "one exact index has no nested key or order allocations"
    );
    let pointer = index.as_slice().as_ptr();
    assert_eq!(index.as_slice()[0].key.as_ptr(), raw[2..].as_ptr());
    assert_eq!(map.first_key(), Some("tip"));
    assert!(map.contains_key("world"));
    let world = map.remove("world").unwrap();
    assert!(!map.contains_key("world"));
    assert!(map.remove("world").is_none());
    map.require_source_order(&["world", "tip"], "state")
        .unwrap();
    let moved = map;
    assert_eq!(
        moved.admitted.as_ref().unwrap().as_slice().as_ptr(),
        pointer
    );
    assert_eq!(original.reserved_bytes(), layout.size());
    let SnapshotJsonField::Borrowed { raw: world_raw } = world else {
        panic!("the original nested source stays borrowed");
    };
    assert_eq!(world_raw.as_ptr(), raw[9..].as_ptr());
    drop(moved);
    assert_eq!(original.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn snapshot_index_refusal_preserves_original_release_and_allocator_category() {
    let raw = r#"{"consensus_evidence":{"revert":{},"blocks":{}}}"#;
    let layout = Layout::array::<SnapshotJsonEntry<'_>>(1).unwrap();
    let original = AllocationBudget::new(layout.size());
    let occupied = original.try_reserve(layout).unwrap();
    let expected = original.try_reserve(layout).unwrap_err();
    let actual = storage_error(
        SnapshotJsonMap::parse_admitted(raw, "world", &["consensus_evidence"], &original)
            .err()
            .unwrap(),
    );
    let AdmittedStorageError::Allocation(actual) = actual else {
        panic!("capacity refusal is retained without replacement");
    };
    assert_eq!(actual, expected);
    let AllocationRefusal::Capacity { release, .. } = actual else {
        panic!("original live owner supplies the wait");
    };
    let scratch = AllocationBudget::new(ReleaseRegistration::allocation_layout().size());
    let mut prepaid = scratch
        .try_reserve(ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    let foreign = AllocationBudget::new(layout.size());
    drop(foreign.try_reserve(layout).unwrap());
    assert!(
        registration.poll_wait(&release, &mut context).is_pending(),
        "foreign pool releases never unblock the captured refusal"
    );
    drop(occupied);
    assert!(registration.poll_wait(&release, &mut context).is_ready());

    let (result, refused) = refuse_one_layout_during(layout, || {
        SnapshotJsonMap::parse_admitted(raw, "world", &["consensus_evidence"], &original)
    });
    assert!(
        refused,
        "fault injection reaches the sole exact backing allocation"
    );
    let physical = storage_error(result.err().unwrap());
    assert_eq!(physical, AdmittedStorageError::Allocator { layout });
    assert!(
        physical.release_wait().is_none(),
        "physical failure cannot invent a capacity wait"
    );
    assert_eq!(original.reserved_bytes(), 0);
    let retry =
        SnapshotJsonMap::parse_admitted(raw, "world", &["consensus_evidence"], &original).unwrap();
    assert_eq!(original.reserved_bytes(), layout.size());
    drop(retry);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn snapshot_index_nested_objects_unwind_and_schema_failures_reclaim_original_custody() {
    let raw = r#"{"world":{"consensus_evidence":{"revert":{},"blocks":{}}}}"#;
    let layout = Layout::array::<SnapshotJsonEntry<'_>>(1).unwrap();
    let original = AllocationBudget::new(layout.size() * 2);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut root =
            SnapshotJsonMap::parse_admitted(raw, "state", &["world"], &original).unwrap();
        let world = root
            .remove("world")
            .unwrap()
            .into_object("world", &["consensus_evidence"], &original)
            .unwrap();
        assert!(root.is_empty());
        assert!(world.contains_key("consensus_evidence"));
        assert_eq!(original.reserved_bytes(), 2 * layout.size());
        panic!("unwind with both original indexes alive");
    }));
    assert!(unwind.is_err());
    assert_eq!(original.reserved_bytes(), 0);
    // Each object fits the two-field schema, so only the in-index checks refuse it.
    for malformed in [
        r#"{"world":0,"world":1}"#,
        r#"{"\u0077orld":0}"#,
        r#"{"world":0} true"#,
    ] {
        let mut result = None;
        let allocations = allocations_during(|| {
            result = Some(SnapshotJsonMap::parse_admitted(
                malformed,
                "state",
                &["world", "tip"],
                &original,
            ));
        });
        assert!(matches!(
            result.unwrap(),
            Err(StateRestoreError::Serialization(_))
        ));
        assert_eq!(
            allocations, 1,
            "schema refusal allocates only the admitted index"
        );
        assert_eq!(original.reserved_bytes(), 0);
    }
    let empty = AllocationBudget::new(0);
    assert_eq!(
        allocations_during(|| {
            let map = SnapshotJsonMap::parse_admitted("{}", "state", &[], &empty).unwrap();
            assert!(map.is_empty());
            map.require_source_order(&[], "state").unwrap();
        }),
        0
    );
    let canonical =
        SnapshotJsonMap::parse_admitted(r#"{"a":0,"b":1}"#, "state", &["a", "b"], &original)
            .unwrap();
    assert!(
        canonical
            .require_source_order(&["b", "a"], "state")
            .is_err()
    );
    assert!(canonical.require_source_order(&["a"], "state").is_err());
    drop(canonical);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn snapshot_comparison_streams_hash_keys_and_nested_values_without_scratch() {
    let hash = iroha_crypto::Hash::new(b"snapshot comparison hash");
    let value = BTreeMap::from([(hash, vec![hash])]);
    let canonical = json::to_json(&value).unwrap();
    let escaped = BTreeMap::from([(hash, vec!["\u{10348}\n"])]);
    let escaped_canonical = json::to_json(&escaped).unwrap();
    assert_eq!(
        allocations_during(|| {
            assert!(snapshot_json_matches(&value, &canonical).unwrap());
            assert!(snapshot_json_matches(&escaped, &escaped_canonical).unwrap());
        }),
        0,
        "canonical hash key and nested value writers require no heap scratch"
    );
    assert!(
        !snapshot_json_matches(&value, "{}").unwrap(),
        "snapshot comparison rejects changed canonical bytes"
    );
    assert!(!snapshot_json_matches(&value, &canonical[..canonical.len() - 1]).unwrap());
    assert!(!snapshot_json_matches(&value, &format!("{canonical} ")).unwrap());
}

#[test]
fn snapshot_index_defers_active_decode_refusal_without_labelling_it_evidence() {
    use crate::snapshot::TryReadError;
    let original = AllocationBudget::new(1024);
    let limits = norito::core::DecodeLimits::new(0, 1024, 1024, 1024, 32);
    let result = norito::core::with_decode_limits_scope(limits, || {
        SnapshotJsonMap::parse_admitted(r#"{"world":0}"#, "state", &["world"], &original)
    });
    let Err(error) = result else {
        panic!("the active decode scope refuses the State index");
    };
    assert!(
        matches!(error, StateRestoreError::ExecutionDeferred(_)),
        "an active decode refusal while indexing State is a local restore deferral"
    );
    assert!(
        matches!(
            TryReadError::from(error),
            TryReadError::StateExecutionDeferred(_)
        ),
        "the snapshot reader reports local execution resources, not evidence custody"
    );
    assert_eq!(original.reserved_bytes(), 0);
    // Completed syntax and the fixed protocol depth limit remain snapshot rejection.
    assert!(matches!(
        snapshot_index_json_error(json::Error::InvalidUtf8),
        StateRestoreError::Serialization(json::Error::InvalidUtf8)
    ));
    assert!(matches!(
        snapshot_index_json_error(json::Error::NestingDepthExceeded {
            depth: 2,
            limit: 1,
            context: "JSON value",
        }),
        StateRestoreError::Serialization(json::Error::NestingDepthExceeded { .. })
    ));
    // Outside the refusing scope the same object is admitted.
    let retry =
        SnapshotJsonMap::parse_admitted(r#"{"world":0}"#, "state", &["world"], &original).unwrap();
    assert!(retry.contains_key("world"));
    drop(retry);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn snapshot_index_is_sized_by_its_schema_not_the_input_entry_count() {
    // The original pool holds exactly the two-field schema index.
    let layout = Layout::array::<SnapshotJsonEntry<'_>>(2).unwrap();
    let original = AllocationBudget::new(layout.size());
    for (raw, unknown) in [
        (r#"{"a":0,"b":1,"c":2}"#, Some("state.c")),
        (r#"{"c":0,"a":1,"b":2}"#, Some("state.c")),
        (r#"{"a":0,"a":1,"b":2}"#, None),
        (r#"{"a":0,"b":1,"b":2}"#, None),
    ] {
        let result = SnapshotJsonMap::parse_admitted(raw, "state", &["a", "b"], &original);
        let Err(StateRestoreError::Serialization(error)) = result else {
            panic!("an object larger than its schema is malformed, never a local index refusal");
        };
        match unknown {
            Some(expected) => assert!(
                matches!(&error, json::Error::InvalidField { field, message }
                    if field == expected && message.contains("unknown field")),
                "{error:?}"
            ),
            None => assert!(
                matches!(
                    error,
                    json::Error::WithPos {
                        msg: "duplicate snapshot field",
                        ..
                    }
                ),
                "{error:?}"
            ),
        }
        assert_eq!(original.reserved_bytes(), 0);
    }
    // Objects no larger than the schema are indexed exactly as before.
    let map = SnapshotJsonMap::parse_admitted(r#"{"a":0,"b":1}"#, "state", &["a", "b"], &original)
        .unwrap();
    assert_eq!(original.reserved_bytes(), layout.size());
    map.require_source_order(&["a", "b"], "state").unwrap();
    drop(map);
    let short =
        SnapshotJsonMap::parse_admitted(r#"{"a":0}"#, "state", &["a", "b"], &original).unwrap();
    assert!(matches!(
        short.require_source_order(&["a", "b"], "state"),
        Err(json::Error::InvalidField { ref field, ref message })
            if field == "state" && message.contains("canonical schema order")
    ));
    drop(short);
    assert_eq!(original.reserved_bytes(), 0);
}

fn rendered(field: Option<SnapshotJsonField<'_>>) -> Option<String> {
    field.map(|field| match field {
        SnapshotJsonField::Borrowed { raw } => raw.to_owned(),
        SnapshotJsonField::Owned(value) => json::to_json(&value).unwrap(),
    })
}

#[test]
fn snapshot_map_get_borrows_without_consuming_on_admitted_and_fixture_maps() {
    let raw = r#"{"first":{"a":1},"second":[2]}"#;
    let budget = AllocationBudget::new(1 << 16);
    let json::Value::Object(owned) = json::from_str::<json::Value>(raw).unwrap() else {
        panic!("fixture source is an object");
    };
    let maps = [
        SnapshotJsonMap::parse_admitted(raw, "state", &["first", "second"], &budget).unwrap(),
        SnapshotJsonMap::parse(raw, "state").unwrap(),
        SnapshotJsonMap::from_owned(owned),
    ];
    for (index, mut map) in maps.into_iter().enumerate() {
        if index == 0 {
            // The admitted index borrows the original source without any allocation.
            let mut borrowed = None;
            let allocations = allocations_during(|| borrowed = map.get("first"));
            assert_eq!(allocations, 0);
            let Some(SnapshotJsonField::Borrowed { raw: first }) = borrowed else {
                panic!("admitted get borrows the original value");
            };
            assert_eq!(first.as_ptr(), raw[9..].as_ptr());
        }
        for _ in 0..2 {
            for (key, expected) in [("first", r#"{"a":1}"#), ("second", "[2]")] {
                assert_eq!(rendered(map.get(key)).as_deref(), Some(expected), "{index}");
                assert!(
                    map.contains_key(key),
                    "get must not consume {key} ({index})"
                );
            }
        }
        assert!(map.get("third").is_none());
        assert_eq!(rendered(map.remove("first")).as_deref(), Some(r#"{"a":1}"#));
        assert!(
            map.get("first").is_none(),
            "removed field is gone ({index})"
        );
        assert!(map.remove("first").is_none());
        assert!(!map.contains_key("first"));
        assert_eq!(rendered(map.get("second")).as_deref(), Some("[2]"));
        assert_eq!(map.first_key(), Some("second"));
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_world_decoder_rejects_reordered_missing_and_unknown_fields_itself() {
    let encoded = json::to_json(&World::default()).unwrap();
    let order = canonical_world_field_order();
    let canonical = SnapshotJsonMap::parse_world_fixture(&encoded).unwrap();
    let entries: Vec<(&str, &str)> = order
        .iter()
        .map(|key| match canonical.get(key) {
            Some(SnapshotJsonField::Borrowed { raw }) => (*key, raw),
            _ => panic!("canonical World field {key}"),
        })
        .collect();
    let render = |entries: &[(&str, &str)]| {
        let fields: Vec<String> = entries
            .iter()
            .map(|(key, raw)| format!("\"{key}\":{raw}"))
            .collect();
        format!("{{{}}}", fields.join(","))
    };
    assert_eq!(
        render(&entries),
        encoded,
        "fixture renders exact World bytes"
    );
    let mut reordered = entries.clone();
    reordered.swap(0, 1);
    let mut missing = entries.clone();
    missing.remove(1);
    let ivm = IVM::new(0);
    let seed = IvmSeed {
        ivm: &ivm,
        _marker: PhantomData,
    };
    let budget = AllocationBudget::new(
        iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
    );
    // Both objects index admitted known fields; only the World decoder sees the schema.
    for source in [render(&reordered), render(&missing)] {
        let map = SnapshotJsonMap::parse_world_fixture(&source).unwrap();
        let error = match parse_world(&budget, map, &seed) {
            Ok(_) => panic!("the World decoder itself must reject noncanonical admitted fields"),
            Err(error) => error,
        };
        assert!(
            matches!(
                &error,
                StateRestoreError::Serialization(json::Error::InvalidField { field, message })
                    if field == "world" && message.contains("canonical schema order")
            ),
            "{error:?}"
        );
    }
    // An unknown name never reaches the World decoder: the index refuses it by name.
    let mut unknown = entries.clone();
    unknown[1].0 = "council";
    let error = SnapshotJsonMap::parse_world_fixture(&render(&unknown))
        .err()
        .expect("the admitted index refuses an unknown World field");
    assert!(
        matches!(
            &error,
            StateRestoreError::Serialization(json::Error::InvalidField { field, message })
                if field == "world.council" && message.contains("unknown field")
        ),
        "{error:?}"
    );
    parse_world(&budget, canonical, &seed).expect("canonical admitted World restores");
}

/// Structurally valid native vote-equivocation claim; its zero signatures are invalid.
fn native_evidence_claim(
    status: iroha_data_model::block::consensus::EvidencePenaltyStatus,
) -> iroha_data_model::block::consensus::EvidenceRecord {
    use iroha_data_model::block::consensus::{
        Evidence, EvidenceAttribution, EvidenceOffender, EvidenceRecord, EvidenceScope,
        RecordedEvidenceV1,
    };
    use iroha_sumeragi::{
        message::{Evidence as NativeEvidence, Vote, VoteKind},
        types::{EpochId, Hash32, SIGNATURE_LEN, Signature as NativeSignature},
    };
    let vote = |subject| Vote {
        kind: VoteKind::Prepare,
        instance: Hash32([1; 32]),
        epoch: EpochId {
            epoch: 0,
            context: Hash32([2; 32]),
        },
        height: 1,
        view: 0,
        block_hash: Hash32([subject; 32]),
        result: Hash32([4; 32]),
        signer: 0,
        sig: NativeSignature([0; SIGNATURE_LEN]),
    };
    let key =
        iroha_crypto::KeyPair::try_from_seed(vec![0xA1; 32], iroha_crypto::Algorithm::BlsNormal)
            .unwrap();
    EvidenceRecord {
        evidence: RecordedEvidenceV1::Native(
            Evidence::from_native(&NativeEvidence::VoteEquivocation(vote(0xA1), vote(0xA2)))
                .unwrap(),
        ),
        attribution: EvidenceAttribution {
            scope: EvidenceScope::Root,
            instance: [1; 32],
            height: 1,
            epoch: 0,
            context_id: [2; 32],
            authority_generation: [3; 32],
            offenders: vec![EvidenceOffender {
                lane_stake: None,
                signer: 0,
                peer_id: PeerId::new(key.public_key().clone()),
            }],
            safety_violation: false,
        },
        recorded_at_height: 1,
        recorded_at_view: 0,
        recorded_at_ms: 1_000,
        penalty_status: status,
    }
}

#[test]
fn evidence_comparison_matches_ordinary_writer_for_native_and_sccp_records() {
    use crate::sumeragi::evidence::record::{parse_record, sccp_storage_claim_for_testing};
    use iroha_data_model::block::consensus::{EvidencePenaltyStatus, RecordedEvidenceV1};
    let budget = AllocationBudget::new(1 << 24);
    let applied = native_evidence_claim(EvidencePenaltyStatus::Applied { height: 5 });
    let RecordedEvidenceV1::Native(proof) = &applied.evidence else {
        unreachable!("native fixture");
    };
    let native_key = crate::sumeragi::evidence::evidence_key(proof);
    let applied = RetainedEvidenceRecord::from_fixture(applied, &budget).unwrap();
    let pending = RetainedEvidenceRecord::from_fixture(
        native_evidence_claim(EvidencePenaltyStatus::Pending),
        &budget,
    )
    .unwrap();
    let sccp_source = json::to_json(&sccp_storage_claim_for_testing()).unwrap();
    let sccp = parse_record(&mut json::Parser::new(&sccp_source), &budget).unwrap();
    let sccp_key = iroha_crypto::Hash::prehashed(sccp.sccp_evidence_id().unwrap());
    // Current native and SCCP rows; a value undo for the native key and a null
    // undo for the SCCP key, which was inserted in this block.
    let storage = Storage::<iroha_crypto::Hash, RetainedEvidenceRecord>::from_snapshot_parts(
        BTreeMap::from([(native_key, applied), (sccp_key, sccp)]),
        BTreeMap::from([(native_key, Some(pending)), (sccp_key, None)]),
    );
    let canonical = json::to_json(&storage).unwrap();
    assert!(canonical.contains("sccp_forgery") && canonical.contains(":null"));
    assert_eq!(snapshot_json_matches(&storage, &canonical), Ok(true));
    let mut altered = canonical.clone();
    altered.pop();
    assert_eq!(snapshot_json_matches(&storage, &altered), Ok(false));
    let restored = SnapshotJsonField::Borrowed { raw: &canonical }
        .decode_evidence(&budget)
        .expect("canonical native and SCCP evidence restores");
    assert_eq!(json::to_json(&restored).unwrap(), canonical);
    let snapshot = restored.snapshot();
    assert_eq!(
        snapshot.current().get(&native_key).unwrap().penalty_status,
        EvidencePenaltyStatus::Applied { height: 5 }
    );
    assert_eq!(
        snapshot
            .current()
            .get(&sccp_key)
            .unwrap()
            .sccp_evidence_id()
            .map(iroha_crypto::Hash::prehashed),
        Some(sccp_key)
    );
    assert_eq!(
        snapshot
            .revert_map()
            .get(&native_key)
            .unwrap()
            .as_ref()
            .unwrap()
            .penalty_status,
        EvidencePenaltyStatus::Pending
    );
    assert_eq!(snapshot.revert_map().get(&sccp_key), Some(&None));
}
