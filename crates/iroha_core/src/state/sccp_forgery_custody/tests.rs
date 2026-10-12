//! Storage controls; synthetic keys/ids do not authenticate a forgery or instruction.
use super::*;
use mv::storage::StorageReadOnly as _;
use norito::codec::Encode as _;

fn account() -> AccountId {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    let members = (1..=2)
        .map(|seed| {
            MultisigMember::new(
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
                1,
            )
            .unwrap()
        })
        .collect();
    AccountId::new_multisig(MultisigPolicy::new(2, members).unwrap())
}
#[test]
fn charged_key_matches_canonical_tuple_and_clone_keeps_one_graph() {
    let account = account();
    let budget = AllocationBudget::new(1 << 20);
    let key = OffenceKey::try_copy(7, LaneId::new(2), &account, &budget).unwrap();
    assert_eq!(
        key.encode(),
        (7u64, LaneId::new(2), account.clone()).encode()
    );
    let used = budget.reserved_bytes();
    assert!(key.belongs_to(&budget));
    assert!(!key.belongs_to(&AllocationBudget::new(1 << 20)));
    let same = key.clone();
    assert_eq!(same, key);
    assert_eq!(budget.reserved_bytes(), used);
    assert!(std::ptr::eq(&*same, &*key));
    drop(key);
    assert_eq!(budget.reserved_bytes(), used);
    drop(same);
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn exact_capacity_refuses_then_retries_without_account_or_charge_leak() {
    let account = account();
    let budget = AllocationBudget::new(1 << 20);
    let key = OffenceKey::try_copy(1, LaneId::SINGLE, &account, &budget).unwrap();
    let demand = budget.reserved_bytes();
    drop(key);
    budget.set_limit_bytes(demand - 1);
    assert!(matches!(
        OffenceKey::try_copy(1, LaneId::SINGLE, &account, &budget),
        Err(ForgeryStorageError::Storage(
            AdmittedStorageError::Allocation(_)
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(demand);
    let key = OffenceKey::try_copy(1, LaneId::SINGLE, &account, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), demand);
    drop(key);
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn key_decoder_preserves_wire_refuses_noncanonical_or_zero_generation_and_refunds() {
    let account = account();
    let budget = AllocationBudget::new(1 << 20);
    let bytes = (7u64, LaneId::new(2), account.clone()).encode();
    let text = hex::encode(&bytes);
    let key = OffenceKey::decode_snapshot_hex(&text, &budget).unwrap();
    assert_eq!(key.encode(), bytes);
    drop(key);
    assert_eq!(budget.reserved_bytes(), 0);
    for bad in [
        text.to_uppercase(),
        format!("{text}00"),
        text[..text.len() - 2].to_owned(),
        hex::encode((0u64, LaneId::new(2), account).encode()),
    ] {
        assert!(OffenceKey::decode_snapshot_hex(&bad, &budget).is_err());
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
#[test]
fn noncopy_keys_restore_exact_current_and_undo_without_graph_recopy() {
    let account = account();
    let budget = AllocationBudget::new(1 << 20);
    let one = OffenceKey::try_copy(1, LaneId::SINGLE, &account, &budget).unwrap();
    let two = OffenceKey::try_copy(2, LaneId::SINGLE, &account, &budget).unwrap();
    let store = OffenceStorage::try_restore_admitted(budget.clone(), |current, undo| {
        undo(one.clone(), Some([1; 32]))?;
        undo(two.clone(), None)?;
        current(one.clone(), [2; 32])?;
        current(two.clone(), [3; 32])?;
        Ok::<_, AdmittedStorageError>(())
    })
    .unwrap();
    let snapshot = store.snapshot();
    assert_eq!(snapshot.current().get(&one), Some(&[2; 32]));
    assert_eq!(snapshot.revert_map().get(&one), Some(&Some([1; 32])));
    assert_eq!(snapshot.revert_map().get(&two), Some(&None));
    assert!(std::ptr::eq(
        &**snapshot.current().iter().next().unwrap().0,
        &*one
    ));
    drop(snapshot);
    drop(store);
    drop(one);
    drop(two);
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn world_offence_once_max_rollback_and_foreign_pool_refusal() {
    use crate::smartcontracts::isi::sccp::{
        store::forgery_offences,
        test_support::{blank_state, header},
    };
    let state = blank_state();
    let account = account();
    let mut block = state.block(header(3));
    let original = block
        .world
        .sccp_forgery_offences
        .allocation_budget()
        .clone();
    let foreign = AllocationBudget::new(1 << 20);
    let foreign_key = OffenceKey::try_copy(7, LaneId::SINGLE, &account, &foreign).unwrap();
    {
        let mut tx = block.transaction();
        let (retained, error) =
            forgery_offences::insert_new(&mut tx, foreign_key, [1; 32]).unwrap_err();
        assert!(matches!(error, AdmittedStorageError::ScopeIdentity));
        assert!(retained.belongs_to(&foreign));
        drop(retained);
        assert_eq!(foreign.reserved_bytes(), 0);
        let key = OffenceKey::try_copy(7, LaneId::SINGLE, &account, &original).unwrap();
        assert!(forgery_offences::insert_new(&mut tx, key.clone(), [1; 32]).unwrap());
        assert!(!forgery_offences::insert_new(&mut tx, key.clone(), [2; 32]).unwrap());
        assert_eq!(tx.world.sccp_forgery_offences.get(&key), Some(&[1; 32]));
        assert_eq!(*tx.world.sccp_forgery_max_generation.get(), Some(7));
        // Reject this whole child; neither the permanent map nor maximum may leak.
    }
    assert!(block.world.sccp_forgery_offences.is_empty());
    assert_eq!(*block.world.sccp_forgery_max_generation.get(), None);
    {
        let mut tx = block.transaction();
        let key = OffenceKey::try_copy(7, LaneId::SINGLE, &account, &original).unwrap();
        assert!(forgery_offences::insert_new(&mut tx, key, [1; 32]).unwrap());
        tx.apply();
    }
    assert_eq!(block.world.sccp_forgery_offences.len(), 1);
    assert_eq!(*block.world.sccp_forgery_max_generation.get(), Some(7));
}

fn snapshot_claim() -> (String, String, [u8; 32]) {
    use crate::state::{World, sccp_snapshot_state::serialize_envelope};
    use crate::sumeragi::evidence::record::{parse_record, sccp_storage_claim_for_testing};
    use iroha_data_model::block::consensus::RecordedEvidenceV1;
    let mut world = World::new();
    let source = sccp_storage_claim_for_testing();
    let RecordedEvidenceV1::SccpForgery(material) = &source.evidence else {
        unreachable!()
    };
    let original = world.sccp_forgery_offences.allocation_budget().clone();
    let key = OffenceKey::try_copy(
        material.generation,
        material.offenders[0].lane_id,
        &material.offenders[0].validator,
        &original,
    )
    .unwrap();
    let text = norito::json::to_json(&source).unwrap();
    let record = parse_record(&mut norito::json::Parser::new(&text), &original).unwrap();
    let id = record.sccp_evidence_id().unwrap();
    assert_ne!(
        id.encode(),
        id.to_vec(),
        "snapshot value is canonical Norito, not raw bytes"
    );
    {
        let mut block = world.consensus_evidence.block();
        block.insert(iroha_crypto::Hash::prehashed(id), record);
        block.commit();
    }
    world
        .sccp_forgery_offences
        .try_with_admitted_block(|b| b.try_insert_admitted(key, id).map_err(|(_, e)| e))
        .unwrap();
    world.sccp_forgery_max_generation = initialize_max(Some(7), Some(None), &original).unwrap();
    let mut encoded = String::new();
    serialize_envelope(&world, &mut encoded);
    (encoded, text, id)
}
fn with_evidence(text: &str, id: [u8; 32]) -> crate::state::World {
    let world = crate::state::World::new();
    let record = crate::sumeragi::evidence::record::parse_record(
        &mut norito::json::Parser::new(text),
        world.sccp_forgery_offences.allocation_budget(),
    )
    .unwrap();
    {
        let mut block = world.consensus_evidence.block();
        block.insert(iroha_crypto::Hash::prehashed(id), record);
        block.commit();
    }
    world
}
#[test]
fn snapshot_requires_both_exact_offence_cuts_and_matching_maximum() {
    use crate::state::sccp_snapshot_state::{SnapshotSccpState, serialize_envelope};
    let (encoded, text, id) = snapshot_claim();
    let mut restored = with_evidence(&text, id);
    norito::json::from_json::<SnapshotSccpState>(&encoded)
        .unwrap()
        .restore(&mut restored)
        .unwrap();
    let mut roundtrip = String::new();
    serialize_envelope(&restored, &mut roundtrip);
    assert_eq!(roundtrip, encoded);
    let mut malformed: norito::json::Value = norito::json::from_json(&encoded).unwrap();
    malformed
        .as_object_mut()
        .unwrap()
        .get_mut("sccp_forgery_max_generation")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "blocks".into(),
            norito::json::to_value(&Some(8u64)).unwrap(),
        );
    let mut restored = with_evidence(&text, id);
    let error =
        norito::json::from_json::<SnapshotSccpState>(&norito::json::to_json(&malformed).unwrap())
            .unwrap()
            .restore(&mut restored)
            .unwrap_err();
    assert!(
        error.to_string().contains("maximum does not match"),
        "{error}"
    );
}
#[test]
fn snapshot_rejects_each_mixed_predecessor_cut_and_keeps_original_world() {
    use crate::state::sccp_snapshot_state::SnapshotSccpState;
    let (encoded, text, id) = snapshot_claim();
    for mismatch in [false, true] {
        let mut input: norito::json::Value = norito::json::from_json(&encoded).unwrap();
        let mut world = with_evidence(&text, id);
        if mismatch {
            // Evidence existed before this cut, while offence claims it is new.
            world.consensus_evidence.block().commit();
        } else {
            // Offence claims it existed, while evidence was inserted in this cut.
            input
                .as_object_mut()
                .unwrap()
                .get_mut("sccp_forgery_offences")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(
                    "revert".into(),
                    norito::json::to_value(&Vec::<u8>::new()).unwrap(),
                );
            input
                .as_object_mut()
                .unwrap()
                .get_mut("sccp_forgery_max_generation")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(
                    "revert".into(),
                    norito::json::to_value(&std::collections::BTreeMap::from([("value", 7_u64)]))
                        .unwrap(),
                );
        }
        let snapshot =
            norito::json::from_json::<SnapshotSccpState>(&norito::json::to_json(&input).unwrap())
                .unwrap();
        // MV cells encode present undo as an explicit value object, including
        // Option payloads. Reach the cut join with the intended decoded state.
        assert_eq!(snapshot.sccp_forgery_max_generation.view().get(), &Some(7));
        assert_eq!(
            snapshot
                .sccp_forgery_max_generation
                .predecessor_view()
                .get(),
            &if mismatch { Some(None) } else { Some(Some(7)) }
        );
        let error = snapshot.restore(&mut world).unwrap_err();
        assert!(error.to_string().contains("current/undo cut"), "{error}");
        assert!(world.sccp_forgery_offences.view().is_empty());
        assert_eq!(*world.sccp_forgery_max_generation.view().get(), None);
    }
}
#[test]
fn snapshot_rejects_native_record_raw_id_payload_and_evidence_key_substitutions() {
    use crate::state::sccp_snapshot_state::SnapshotSccpState;
    use crate::sumeragi::evidence::record::{
        RetainedEvidenceRecord, sccp_storage_claim_for_testing,
    };
    use iroha_data_model::block::consensus::{Evidence, EvidenceScope, RecordedEvidenceV1};
    let (encoded, text, id) = snapshot_claim();
    let mut world = crate::state::World::new();
    let mut data = sccp_storage_claim_for_testing();
    data.evidence = RecordedEvidenceV1::Native(Evidence { native: Vec::new() });
    data.attribution.scope = EvidenceScope::Root;
    let native =
        RetainedEvidenceRecord::from_fixture(data, world.sccp_forgery_offences.allocation_budget())
            .unwrap();
    world
        .consensus_evidence
        .insert(iroha_crypto::Hash::prehashed(id), native);
    let error = norito::json::from_json::<SnapshotSccpState>(&encoded)
        .unwrap()
        .restore(&mut world)
        .unwrap_err();
    assert!(error.to_string().contains("native evidence cannot back"));
    let mut bad_id = id;
    bad_id[0] ^= 1;
    let mut world = with_evidence(&text, bad_id);
    assert!(
        norito::json::from_json::<SnapshotSccpState>(&encoded)
            .unwrap()
            .restore(&mut world)
            .is_err()
    );
    // The maintained envelope emits a Norito array payload; raw32 bytes are not accepted.
    let malformed = encoded.replace(&hex::encode(id.encode()), &hex::encode(id));
    assert_ne!(malformed, encoded);
    let mut world = with_evidence(&text, id);
    assert!(
        norito::json::from_json::<SnapshotSccpState>(&malformed)
            .unwrap()
            .restore(&mut world)
            .is_err()
    );
}
