//! Local complete-custody controls. Existing native source material is retained as bytes only;
//! these tests never convert a local inventory digest into finality, eligibility or Queue authority.

use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    AccountId, NetworkId,
    isi::{InstructionBox, musubi::AdvanceMusubiPinOutboxV1, sorafs::RegisterPinManifest},
    transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent, TransactionBuilder},
};
use iroha_primitives::{numeric::Quantity, time::TimeSource};
use std::{collections::BTreeMap, time::Duration};

fn original() -> (NativeMusubiPinSessionV1, KeyPair) {
    let key = KeyPair::from_seed(vec![0x7a; 32], Algorithm::Ed25519);
    (
        NativeMusubiPinSessionV1 {
            network: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                b"local inventory codec only",
            ))),
            authority: AccountId::new(key.public_key().clone()),
            session: [8; 32],
            storage_class: 0,
            retention_horizon_secs: 30 * 24 * 60 * 60,
        },
        key,
    )
}
fn fixture_operation(store: &Store) -> Operation {
    let mut source = crate::musubi_publication_service::finality::tests::reader_fixture().query;
    // Local byte binding only: no reader is invoked on this modified specimen.
    source.network_id = store.original.network;
    let asset: iroha_data_model::asset::AssetDefinitionId =
        crate::musubi_publication_service::native_pin::authorization::test_asset(7);
    Operation {
        id: [9; 32],
        ordinal: 1,
        context_digest: [0x51; 32],
        source: slot::encode_frame(&source).unwrap(),
        authorization: NativePinAuthorizationV1 {
            deadline_unix_ms: 200_000,
            max_check_rounds: 2,
            per_transaction: FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    asset.clone(),
                    Quantity::from(1u64),
                )],
                None,
            ),
            max_total_fees: BTreeMap::from([(asset, Quantity::from(1u64))]),
        },
    }
}
fn make_request(
    store: &Store,
    operation: &Operation,
    kind: SlotKind,
    action: &InstructionBox,
) -> SlotRequest {
    SlotRequest {
        network: store.original.network,
        authority: store.original.authority.clone(),
        session: store.original.session,
        operation: operation.id,
        kind,
        pin_selected_at_unix_ms: matches!(kind, SlotKind::Pin).then_some(1_000),
        instruction: slot::encode_frame(action).unwrap(),
        authorization: operation.authorization.clone(),
    }
}
fn pin(store: &Store, operation: &Operation) -> (SlotRequest, TransactionPayload) {
    use sorafs_manifest::{DagCodecId, ManifestBuilder, PinPolicy, ProfileId, StorageClass};
    let source = operation.source().unwrap();
    let archive = &source.registration.commitment;
    let manifest = ManifestBuilder::new()
        .root_cid(archive.root_cid.as_bytes().to_vec())
        .dag_codec(DagCodecId(sorafs_manifest::MANIFEST_DAG_CODEC))
        .chunking_from_registry(ProfileId(1))
        .chunk_digest_sha3_256(*archive.chunk_plan_digest.as_bytes())
        .por_root(*archive.por_root.as_bytes())
        .content_length(archive.content_length)
        .car_digest(*archive.car_digest.as_bytes())
        .car_size(archive.car_size)
        .pin_policy(PinPolicy {
            min_replicas: 3,
            storage_class: match store.original.storage_class {
                0 => StorageClass::Hot,
                1 => StorageClass::Warm,
                2 => StorageClass::Cold,
                _ => unreachable!(),
            },
            retention_epoch: 1
                + iroha_data_model::transaction::DEFAULT_TRANSACTION_TIME_TO_LIVE.as_secs()
                + store.original.retention_horizon_secs,
        })
        .build()
        .unwrap();
    let action: InstructionBox =
        RegisterPinManifest::new(manifest.encode().unwrap(), None, None).into();
    let request = make_request(store, operation, SlotKind::Pin, &action);
    let payload = TransactionBuilder::new_with_time_source(
        store.original.network,
        store.original.authority.clone(),
        &TimeSource::new_fixed(Duration::from_millis(1_000)),
        operation.authorization.per_transaction.clone(),
    )
    .with_instructions([action])
    .into_payload()
    .unwrap();
    (request, payload)
}

#[test]
fn atomic_session_reopen_never_recreates_missing_history_or_accepts_unknown_members() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pins");
    let (expected, _) = original();
    assert!(Store::open(&path, &expected).is_err());
    assert!(!path.exists());
    let (value, _) = original();
    let store = Store::initialize(&path, value).unwrap();
    let before = store.inventory(None).unwrap();
    assert_eq!(before.operations, 0);
    assert_eq!(before.signed_pins, 0);
    assert!(
        Store::open(&path, &expected).is_err(),
        "same session is exclusively held"
    );
    drop(store);
    let store = Store::open(&path, &expected).unwrap();
    assert_eq!(store.inventory(None).unwrap().digest, before.digest);
    store.directory.create_child("unexpected").unwrap();
    assert!(store.inventory(None).is_err());
    drop(store);
    assert!(Store::open(&path, &expected).is_err());
    std::fs::remove_dir(path.join("unexpected")).unwrap();
    std::fs::remove_file(path.join("lock")).unwrap();
    assert!(Store::open(&path, &expected).is_err());
    assert!(!path.join("lock").exists());
}

#[test]
fn complete_signed_inventory_reconstructs_only_exact_predecessor_and_reserves_original_fees() {
    let root = tempfile::tempdir().unwrap();
    let (original, key) = original();
    let store = Store::initialize(&root.path().join("pins"), original).unwrap();
    let operation = fixture_operation(&store);
    let empty = store.inventory(None).unwrap().digest;
    store.create_operation(&operation).unwrap();
    assert_eq!(
        store.inventory(None).unwrap().digest,
        empty,
        "unsigned claims grant no native inventory advance"
    );
    let (request, payload) = pin(&store, &operation);
    let mut slot = store.create_slot(&operation, request).unwrap();
    store.admit_payload(&operation, &slot, &payload).unwrap();
    slot.retain_payload(&payload).unwrap();
    slot.sign_original(
        &key,
        &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(1_001),
        std::time::Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    assert!(slot.record_exposure().unwrap());
    drop(slot);
    let complete = store.inventory(None).unwrap();
    assert_eq!(complete.operations, 1);
    assert_eq!(complete.signed_pins, 1);
    assert_ne!(complete.digest, empty);
    assert_eq!(store.inventory(Some(operation.id)).unwrap().digest, empty);
    assert!(store.inventory(Some([99; 32])).is_err());
    let advance: InstructionBox = AdvanceMusubiPinOutboxV1 {
        network_id: store.original.network,
        pin_authority: store.original.authority.clone(),
        session_id: store.original.session,
        expected_revision: 1,
        expected_inventory_digest: empty,
        inventory_digest: complete.digest,
    }
    .into();
    let request = make_request(&store, &operation, SlotKind::Advance, &advance);
    let control = store.create_slot(&operation, request).unwrap();
    let payload = TransactionBuilder::new_with_time_source(
        store.original.network,
        store.original.authority.clone(),
        &TimeSource::new_fixed(Duration::from_millis(1_001)),
        operation.authorization.per_transaction.clone(),
    )
    .with_instructions([advance])
    .into_payload()
    .unwrap();
    assert!(
        store.admit_payload(&operation, &control, &payload).is_err(),
        "unknown pin dispatch never refunds its original fee reservation"
    );
    assert!(control.payload().unwrap().is_none());
}

#[test]
fn unknown_partial_controls_gaps_and_original_substitutions_cannot_be_ignored() {
    let root = tempfile::tempdir().unwrap();
    let (original, _) = original();
    let store = Store::initialize(&root.path().join("pins"), original).unwrap();
    let mut operation = fixture_operation(&store);
    store.create_operation(&operation).unwrap();
    operation.authorization.deadline_unix_ms += 1;
    let (request, _) = pin(&store, &operation);
    assert!(store.create_slot(&operation, request).is_err());
    let op = store
        .directory
        .open_child(format!("op-{}", hex::encode(operation.id)))
        .unwrap();
    let partial = op.create_child("check-01").unwrap();
    drop(partial);
    assert!(
        store.inventory(None).is_err(),
        "missing Check original cannot be absence"
    );
    std::fs::remove_dir(op.path().join("check-01")).unwrap();
    let mut gap = fixture_operation(&store);
    gap.id = [10; 32];
    gap.ordinal = 3;
    assert!(store.create_operation(&gap).is_err());
    assert_eq!(store.inventory(None).unwrap().operations, 1);
}

#[test]
fn payload_admission_binds_held_slot_directory_and_each_sibling_purpose() {
    let root = tempfile::tempdir().unwrap();
    let (original, _) = original();
    let store = Store::initialize(&root.path().join("pins"), original).unwrap();
    let operation = fixture_operation(&store);
    store.create_operation(&operation).unwrap();
    let (request, payload) = pin(&store, &operation);
    let foreign = Slot::create(&root.path().join("outside-selected-operation"), request).unwrap();
    assert!(store.admit_payload(&operation, &foreign, &payload).is_err());
    assert!(foreign.payload().unwrap().is_none());
    drop(foreign);

    let (request, payload) = pin(&store, &operation);
    let pin_slot = store.create_slot(&operation, request).unwrap();
    let control: InstructionBox = AdvanceMusubiPinOutboxV1 {
        network_id: store.original.network,
        pin_authority: store.original.authority.clone(),
        session_id: store.original.session,
        expected_revision: 0,
        expected_inventory_digest: [0; 32],
        inventory_digest: [1; 32],
    }
    .into();
    // A structurally valid initializer placed under another fixed name must not be counted as
    // that other purpose. The candidate pin remains held throughout the sibling audit.
    let wrong_path = store.slot_path(&operation, SlotKind::Advance).unwrap();
    let misplaced = Slot::create(
        &wrong_path,
        make_request(&store, &operation, SlotKind::Initialize, &control),
    )
    .unwrap();
    drop(misplaced);
    assert!(
        store
            .admit_payload(&operation, &pin_slot, &payload)
            .is_err()
    );
    assert!(pin_slot.payload().unwrap().is_none());
}

#[test]
fn retirement_preserves_exact_signed_inventory_fees_and_read_only_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pins");
    let (selected, key) = original();
    let store = Store::initialize(&path, selected).unwrap();
    let operation = fixture_operation(&store);
    assert!(store.find_operation(operation.id).unwrap().is_none());
    store.create_operation(&operation).unwrap();
    assert_eq!(
        store.find_operation(operation.id).unwrap().unwrap(),
        operation
    );
    let (request, payload) = pin(&store, &operation);
    let mut slot = store.create_slot(&operation, request).unwrap();
    store.admit_payload(&operation, &slot, &payload).unwrap();
    slot.retain_payload(&payload).unwrap();
    slot.sign_original(
        &key,
        &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(1_001),
        std::time::Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let wire = slot.signed().unwrap().encode_wire_v1().unwrap();
    assert!(slot.record_exposure().unwrap());
    drop(slot);
    let before = store.inventory(None).unwrap();
    store.retire_operation(&operation).unwrap();
    store.retire_operation(&operation).unwrap();
    assert!(store.require_active_operation(&operation).is_err());
    let after = store.inventory(None).unwrap();
    assert_eq!(after.digest, before.digest);
    assert_eq!(after.signed_pins, before.signed_pins);
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    let (request, _) = pin(&store, &operation);
    assert!(store.create_slot(&operation, request).is_err());
    let (expected, _) = original();
    drop(store);
    let store = Store::open(&path, &expected).unwrap();
    assert!(store.require_active_operation(&operation).is_err());
    let slot = store.open_slot(&operation, SlotKind::Pin).unwrap().unwrap();
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), wire);
    assert!(!slot.record_exposure().unwrap());
    drop(slot);
    let directory = store
        .directory
        .open_child(format!("op-{}", hex::encode(operation.id)))
        .unwrap();
    let journal = Journal::open(directory.path()).unwrap();
    // Native records are immutable: even a well-formed replacement retirement is refused.
    assert!(
        journal
            .write_native(NativeRecord::Retired, &Retirement { operation: [0; 32] })
            .is_err()
    );
}

#[test]
fn complete_future_storage_bound_is_reserved_before_each_original_or_slot() {
    let root = tempfile::tempdir().unwrap();
    let (original, _) = original();
    let store = Store::initialize(&root.path().join("pins"), original).unwrap();
    let operation = fixture_operation(&store);
    let root_budget = store.inventory(None).unwrap().reserved_bytes;
    assert_eq!(root_budget, ROOT_BYTES);
    store.create_operation(&operation).unwrap();
    assert_eq!(
        store.inventory(None).unwrap().reserved_bytes,
        ROOT_BYTES + OPERATION_BYTES
    );
    let (request, _) = pin(&store, &operation);
    let slot = store.create_slot(&operation, request).unwrap();
    assert!(slot.payload().unwrap().is_none());
    drop(slot);
    let incomplete = store.inventory(None).unwrap();
    assert_eq!(
        incomplete.reserved_bytes,
        ROOT_BYTES + OPERATION_BYTES + SLOT_BYTES
    );
    assert!(incomplete.bytes < incomplete.reserved_bytes);
    store.retire_operation(&operation).unwrap();
    assert_eq!(
        store.inventory(None).unwrap().reserved_bytes,
        incomplete.reserved_bytes,
        "retirement does not refund still-retained records or their future fixed footprint"
    );
}

#[test]
fn exact_paid_policy_rejects_reframed_requests_and_changed_session_on_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pins");
    let (selected, _) = original();
    let store = Store::initialize(&path, selected).unwrap();
    let operation = fixture_operation(&store);
    store.create_operation(&operation).unwrap();
    for case in 0..6 {
        let (mut request, _) = pin(&store, &operation);
        let action: InstructionBox = slot::decode_frame(&request.instruction).unwrap();
        let original_pin = action
            .as_any()
            .downcast_ref::<RegisterPinManifest>()
            .unwrap();
        let mut manifest =
            sorafs_manifest::decode_manifest_v1_canonical(&original_pin.manifest_payload).unwrap();
        match case {
            0 => manifest.pin_policy.storage_class = sorafs_manifest::StorageClass::Warm,
            1 => manifest.pin_policy.retention_epoch += 1,
            2 => manifest.pin_policy.min_replicas = 2,
            3 => request.pin_selected_at_unix_ms = Some(2_001),
            4 => request.pin_selected_at_unix_ms = None,
            5 => manifest.metadata.push(sorafs_manifest::MetadataEntry {
                key: "changed".into(),
                value: "unsigned intent".into(),
            }),
            _ => unreachable!(),
        }
        request.instruction = slot::encode_frame(&InstructionBox::from(RegisterPinManifest::new(
            manifest.encode().unwrap(),
            None,
            None,
        )))
        .unwrap();
        assert!(
            store.create_slot(&operation, request).is_err(),
            "reframed case {case}"
        );
        assert!(
            store
                .open_slot(&operation, SlotKind::Pin)
                .unwrap()
                .is_none()
        );
    }
    // A well-formed canonical request installed independently still fails the complete census.
    let (mut request, _) = pin(&store, &operation);
    request.pin_selected_at_unix_ms = Some(2_001);
    let path_for_slot = store.slot_path(&operation, SlotKind::Pin).unwrap();
    let misplaced = Slot::create(&path_for_slot, request).unwrap();
    drop(misplaced);
    assert!(store.inventory(None).is_err());
    drop(store);
    let (expected, _) = original();
    assert!(Store::open(&path, &expected).is_err());

    let clean = root.path().join("clean");
    let (selected, _) = original();
    drop(Store::initialize(&clean, selected).unwrap());
    for case in 0..3 {
        let (mut expected, _) = original();
        match case {
            0 => expected.storage_class = 2,
            1 => expected.retention_horizon_secs += 1,
            2 => {
                expected.authority = AccountId::new(
                    KeyPair::from_seed(vec![0x73; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                )
            }
            _ => unreachable!(),
        }
        assert!(Store::open(&clean, &expected).is_err());
    }
    let (expected, _) = original();
    let held = Store::open(&clean, &expected).unwrap();
    let (mut substituted, _) = original();
    substituted.storage_class = 1;
    held.directory
        .write_atomic(
            "operation.json",
            norito::json::to_json(&substituted).unwrap().as_bytes(),
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    assert!(
        held.inventory(None).is_err(),
        "online owner substitution must be detected under the original lock"
    );
    drop(held);
    assert!(Store::open(&clean, &expected).is_err());
}

#[test]
fn warm_original_retention_survives_later_payload_time_and_exact_wire_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pins");
    let (mut selected, key) = original();
    selected.storage_class = 1;
    selected.retention_horizon_secs = 90 * 24 * 60 * 60;
    let expected: NativeMusubiPinSessionV1 =
        norito::json::from_str(&norito::json::to_json(&selected).unwrap()).unwrap();
    let store = Store::initialize(&path, selected).unwrap();
    let operation = fixture_operation(&store);
    store.create_operation(&operation).unwrap();
    let (request, mut payload) = pin(&store, &operation);
    assert_eq!(request.pin_selected_at_unix_ms, Some(1_000));
    let original_instruction = request.instruction.clone();
    // A request-only retry may obtain a later bounded quote. It must retain the original
    // manifest selection time and horizon, independently of that new payload creation time.
    payload.creation_time_ms += 10_000;
    let mut slot = store.create_slot(&operation, request).unwrap();
    store.admit_payload(&operation, &slot, &payload).unwrap();
    slot.retain_payload(&payload).unwrap();
    slot.sign_original(
        &key,
        &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(11_001),
        std::time::Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let wire = slot.signed().unwrap().encode_wire_v1().unwrap();
    drop(slot);
    let digest = store.inventory(None).unwrap().digest;
    drop(store);
    let reopened = Store::open(&path, &expected).unwrap();
    assert_eq!(reopened.inventory(None).unwrap().digest, digest);
    let slot = reopened
        .open_slot(&operation, SlotKind::Pin)
        .unwrap()
        .unwrap();
    assert_eq!(slot.request().pin_selected_at_unix_ms, Some(1_000));
    assert_eq!(slot.request().instruction, original_instruction);
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), wire);
}
