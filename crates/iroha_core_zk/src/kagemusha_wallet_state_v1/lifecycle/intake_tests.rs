//! Transaction boundaries with explicit mock native refusals and durable-write faults.

use super::*;

fn footprint(wallet: &Wallet) -> (usize, usize) {
    let records = wallet.archive.records.lock().unwrap();
    (records.len(), records.values().map(Vec::len).sum())
}

#[test]
fn semantic_intake_refusals_discard_private_drafts_and_keep_fixed_binding() {
    for validation in [false, true] {
        let mut sizes = Vec::new();
        for size in [1, 32 * 1024] {
            let mut wallet = prepared_wallet();
            let before = wallet.snapshot().unwrap();
            wallet.proofs.preparation_payload = vec![37; size];
            wallet.proofs.fail_preparation_plan = !validation;
            wallet.proofs.fail_preparation_validation = validation;
            let signatures = wallet.custody.signatures;
            let digest =
                crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(
                    &wallet.proofs.preparation_payload,
                );
            assert!(matches!(wallet.execute(request()), Err(Error::Invalid(_))));
            assert_eq!(wallet.snapshot().unwrap().sequence, before.sequence);
            assert_eq!(wallet.custody.signatures, signatures);
            assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
            assert!(
                !wallet
                    .archive
                    .records
                    .lock()
                    .unwrap()
                    .contains_key(&ArchiveKey::Object(digest))
            );
            assert!(
                !wallet
                    .archive
                    .records
                    .lock()
                    .unwrap()
                    .contains_key(&ArchiveKey::PreparationDraft(request().request_id))
            );
            assert_eq!(
                wallet.retry_request(&request().request_id).unwrap(),
                RequestStatusV1::Preparing
            );
            sizes.push(footprint(&wallet));
            let mut wallet = restart(wallet);
            let footprint_before_retry = footprint(&wallet);
            assert!(matches!(wallet.execute(request()), Err(Error::Invalid(_))));
            assert_eq!(footprint(&wallet), footprint_before_retry);
            let changed = OperationRequestV1 {
                request_id: request().request_id,
                action: OperationActionV1::Unload {
                    amount: 1,
                    charge: None,
                },
            };
            assert!(matches!(
                wallet.execute(changed),
                Err(Error::OperationConflict)
            ));
        }
        assert_eq!(
            sizes[0], sizes[1],
            "no variable draft payload survives semantic refusal"
        );
    }
}

#[test]
fn validated_batch_recovers_exact_choices_after_every_publication_boundary() {
    for boundary in 0..7 {
        let mut wallet = prepared_wallet();
        wallet.proofs.preparation_payload = vec![59; 97];
        let digest = crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(
            &wallet.proofs.preparation_payload,
        );
        let key = match boundary {
            0 | 1 => Some(ArchiveKey::PreparationDraft(request().request_id)),
            2 | 3 => Some(ArchiveKey::Object(digest)),
            _ => None,
        };
        if let Some(key) = key {
            *wallet.archive.fail_put.lock().unwrap() = Some((key, boundary % 2 == 1));
        } else if boundary < 6 {
            wallet.custody.fail_publication_at =
                Some((wallet.custody.publication_calls + 2, boundary == 5));
        } else {
            wallet.archive.fail_remove = true;
        }
        let signatures = wallet.custody.signatures;
        assert!(wallet.execute(request()).is_err(), "boundary {boundary}");
        assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
        assert_eq!(wallet.custody.signatures, signatures);
        assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
        let mut wallet = restart(wallet);
        let result = wallet.execute(request()).unwrap();
        assert!(matches!(result, Completion::Complete(_)));
        assert_eq!(
            wallet.proofs.preparations.load(Ordering::SeqCst),
            if boundary == 0 { 2 } else { 1 }
        );
        assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
        assert_eq!(wallet.custody.signatures, signatures + 1);
        assert!(
            !wallet
                .archive
                .records
                .lock()
                .unwrap()
                .contains_key(&ArchiveKey::PreparationDraft(request().request_id))
        );
        assert_eq!(wallet.execute(request()).unwrap(), result);
        assert_eq!(wallet.custody.signatures, signatures + 1);
    }
}

#[test]
fn retained_plan_validation_and_proof_retries_cannot_publish_new_draft_bytes() {
    let mut wallet = prepared_wallet();
    wallet.proofs.preparation_payload = vec![71; 99];
    wallet.proofs.fail_preparation_proof = true;
    assert!(matches!(wallet.execute(request()), Err(Error::Proof(_))));
    let selected = footprint(&wallet);
    let mut wallet = restart(wallet);
    assert!(matches!(wallet.execute(request()), Err(Error::Proof(_))));
    assert_eq!(footprint(&wallet), selected);
    wallet.proofs.preparation_payload = vec![72; 113];
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::WitnessLost(_))
    ));
    assert_eq!(footprint(&wallet), selected);
    assert_eq!(wallet.custody.signatures, 1);
}

#[test]
fn canonical_load_refusal_discards_short_and_long_private_request_originals() {
    use iroha_data_model::{
        events::{
            EventBox,
            data::{DataEvent, kagemusha::KagemushaLoadCommittedV1},
        },
        isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1,
        sumeragi_finality::SumeragiCommitCertificateV1,
    };
    let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    let encoded: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/ordinary_load_receipt_v1.json"
    )))
    .unwrap();
    let mut receipt = KagemushaWalletLoadReceiptV1::decode_canonical(
        &hex::decode(encoded["receipt_frame_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    receipt.scheme_id = scheme.scheme_id();
    let event = EventBox::Data(
        DataEvent::KagemushaLoadCommitted(
            KagemushaLoadCommittedV1::from_receipt(&receipt).unwrap(),
        )
        .into(),
    );
    let tree: iroha_crypto::MerkleTree<EventBox> =
        [iroha_crypto::HashOf::new(&event)].into_iter().collect();
    let mut footprints = Vec::new();
    for size in [1, 32 * 1024] {
        let mut wallet = prepared_wallet();
        wallet.confirm_mock_activation_for_intake();
        let finality = KagemushaWalletLoadFinalityV1 {
            version: 1,
            receipt_digest: receipt.receipt_digest().unwrap(),
            certificate: SumeragiCommitCertificateV1 {
                consensus_header: vec![1],
                commit_qc: vec![2],
                result_preimage: vec![3; size],
            },
            event_proof: tree.get_proof(0).unwrap(),
        };
        let request = OperationRequestV1 {
            request_id: [72; 32],
            action: OperationActionV1::Load {
                receipt: receipt.to_canonical_bytes().unwrap(),
                finality: finality.to_canonical_bytes().unwrap(),
            },
        };
        request.validate(&scheme).unwrap();
        let original = PrivateArchiveBytes::encode(&NativeIntentV1::user(request.clone())).unwrap();
        let object = crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(
            &original,
        );
        let before = footprint(&wallet);
        let snapshot = wallet.snapshot().unwrap();
        let signatures = wallet.custody.signatures;
        assert!(matches!(
            wallet.execute(request.clone()),
            Err(Error::Proof("Load native epoch selector"))
        ));
        let after = footprint(&wallet);
        footprints.push((after.0 - before.0, after.1 - before.1));
        assert_eq!(wallet.snapshot().unwrap(), snapshot);
        assert_eq!(wallet.custody.signatures, signatures);
        assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
        assert!(
            !wallet
                .archive
                .records
                .lock()
                .unwrap()
                .contains_key(&ArchiveKey::Object(object))
        );
        assert!(
            !wallet
                .archive
                .records
                .lock()
                .unwrap()
                .contains_key(&ArchiveKey::PreparationDraft(request.request_id))
        );
        let mut wallet = restart(wallet);
        assert!(matches!(
            wallet.execute(request.clone()),
            Err(Error::Proof("Load native epoch selector"))
        ));
        assert_eq!(footprint(&wallet), after);
        assert_eq!(
            wallet.retry_request(&request.request_id).unwrap(),
            RequestStatusV1::Preparing
        );
    }
    assert_eq!(footprints[0], footprints[1]);
}

#[test]
fn retained_batch_memory_admission_precedes_read_and_never_demands_fresh_disk_headroom() {
    let mut wallet = prepared_wallet();
    wallet.proofs.preparation_payload = vec![61; 97];
    let object = crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(
        &wallet.proofs.preparation_payload,
    );
    *wallet.archive.fail_put.lock().unwrap() = Some((ArchiveKey::Object(object), false));
    assert!(matches!(wallet.execute(request()), Err(Error::Storage(_))));
    assert!(
        wallet
            .archive
            .records
            .lock()
            .unwrap()
            .contains_key(&ArchiveKey::PreparationDraft(request().request_id))
    );
    let mut wallet = restart(wallet);
    let reads = wallet.archive.draft_reads.load(Ordering::SeqCst);
    wallet.custody.resources.memory_bytes = Some(0);
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::NotEnoughMemory)
    ));
    assert_eq!(wallet.archive.draft_reads.load(Ordering::SeqCst), reads);
    wallet.custody.fail_resources = true;
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::Provider(ProviderError::Unavailable(_)))
    ));
    assert_eq!(wallet.archive.draft_reads.load(Ordering::SeqCst), reads);
    wallet.custody.fail_resources = false;
    wallet.custody.resources.memory_bytes = None;
    wallet.custody.resources.storage_bytes = 0;
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::NotEnoughStorage)
    ));
    assert!(wallet.archive.draft_reads.load(Ordering::SeqCst) > reads);
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert!(
        !wallet
            .archive
            .records
            .lock()
            .unwrap()
            .contains_key(&ArchiveKey::PreparationDraft(request().request_id)),
        "retained batch promoted and cleaned before the independent fresh-proof capacity refusal"
    );
}

#[test]
fn fresh_storage_admission_charges_staging_and_materialization_and_preserves_provider_errors() {
    use crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1;
    use crate::kagemusha_wallet_state_v1::capacity::{
        INTAKE_MEMORY_RESERVATION_BYTES, INTAKE_STORAGE_RESERVATION_BYTES,
        OPERATION_RESERVATION_BYTES,
    };
    let mut wallet = prepared_wallet();
    wallet.proofs.capacity = KagemushaWalletRuntimeCapacityV1 {
        storage_bytes: 1000,
        memory_bytes: 2000,
    };
    let required = INTAKE_STORAGE_RESERVATION_BYTES + 1000;
    assert!(
        INTAKE_STORAGE_RESERVATION_BYTES
            > OPERATION_RESERVATION_BYTES
                + 2 * crate::kagemusha_wallet_state_v1::lifecycle::INTAKE_BATCH_BYTES as u64
                + 2 * crate::kagemusha_wallet_state_v1::lifecycle::INTAKE_DRAFT_BYTES as u64
    );
    let before = footprint(&wallet);
    wallet.custody.resources.storage_bytes = required - 1;
    wallet.custody.resources.memory_bytes = Some(u64::MAX);
    assert!(matches!(
        wallet.require_intake_capacity(),
        Err(Error::NotEnoughStorage)
    ));
    wallet.custody.fail_resources = true;
    assert!(matches!(
        wallet.require_intake_capacity(),
        Err(Error::Provider(ProviderError::Unavailable(_)))
    ));
    wallet.custody.fail_resources = false;
    wallet.custody.resources.storage_bytes = required;
    wallet.custody.resources.memory_bytes = Some(INTAKE_MEMORY_RESERVATION_BYTES + 1999);
    assert!(matches!(
        wallet.require_intake_capacity(),
        Err(Error::NotEnoughMemory)
    ));
    assert!(matches!(
        wallet.require_intake_memory(),
        Err(Error::NotEnoughMemory)
    ));
    wallet.custody.resources.memory_bytes = Some(INTAKE_MEMORY_RESERVATION_BYTES + 2000);
    wallet.require_intake_capacity().unwrap();
    wallet.require_intake_memory().unwrap();
    wallet.custody.resources.memory_bytes = None;
    wallet.require_intake_capacity().unwrap();
    assert_eq!(footprint(&wallet), before);
}
