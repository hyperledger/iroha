//! Transaction boundaries with explicit mock native refusals and durable-write faults.

use super::*;

fn footprint(wallet: &Wallet) -> (usize, usize) {
    let records = wallet.archive.records.lock().unwrap();
    (records.len(), records.values().map(Vec::len).sum())
}

#[test]
fn semantic_intake_refusals_discard_private_drafts_and_keep_fixed_binding() {
    // A fresh preparation is refused by native planning, before any batch is retained.
    let mut sizes = Vec::new();
    for size in [1, 32 * 1024] {
        let mut wallet = prepared_wallet();
        let before = wallet.snapshot().unwrap();
        wallet.proofs.preparation_payload = vec![37; size];
        wallet.proofs.fail_preparation_plan = true;
        let signatures = wallet.custody.signatures;
        let digest = crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(
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

#[test]
fn recovered_batch_validation_refusal_keeps_the_exact_batch_unpublished_and_unproven() {
    let mut wallet = prepared_wallet();
    wallet.proofs.preparation_payload = vec![41; 97];
    let object = object_digest(&wallet.proofs.preparation_payload);
    // The batch is retained before plan publication: one object put fails definitively.
    *wallet.archive.fail_put.lock().unwrap() = Some((ArchiveKey::Object(object), false));
    let signatures = wallet.custody.signatures;
    assert!(matches!(wallet.execute(request()), Err(Error::Storage(_))));
    let draft = ArchiveKey::PreparationDraft(request().request_id);
    let retained = wallet.archive.records.lock().unwrap()[&draft].clone();
    let selected = footprint(&wallet);
    let mut wallet = restart(wallet);
    wallet.proofs.fail_preparation_validation = true;
    for _ in 0..2 {
        assert!(matches!(
            wallet.execute(request()),
            Err(Error::Invalid("test native validation refusal"))
        ));
        assert_eq!(wallet.archive.records.lock().unwrap()[&draft], retained);
        assert_eq!(footprint(&wallet), selected);
        assert_eq!(
            wallet.retry_request(&request().request_id).unwrap(),
            RequestStatusV1::Preparing
        );
    }
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.custody.signatures, signatures);
    wallet.proofs.fail_preparation_validation = false;
    assert!(matches!(
        wallet.execute(request()).unwrap(),
        Completion::Complete(_)
    ));
    assert_eq!(wallet.custody.signatures, signatures + 1);
}

#[test]
fn held_plan_validation_refusal_changes_nothing_and_never_proves() {
    let mut wallet = prepared_wallet();
    wallet.proofs.preparation_payload = vec![43; 97];
    // The plan publication commits but reports failure: the plan is selected, unproven.
    wallet.custody.fail_publication_at = Some((wallet.custody.publication_calls + 2, true));
    let signatures = wallet.custody.signatures;
    assert!(wallet.execute(request()).is_err());
    let selected = footprint(&wallet);
    let mut wallet = restart(wallet);
    wallet.proofs.fail_preparation_validation = true;
    for _ in 0..2 {
        assert!(matches!(
            wallet.execute(request()),
            Err(Error::Invalid("test native validation refusal"))
        ));
        assert_eq!(footprint(&wallet), selected);
    }
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.custody.signatures, signatures);
    wallet.proofs.fail_preparation_validation = false;
    assert!(matches!(
        wallet.execute(request()).unwrap(),
        Completion::Complete(_)
    ));
    assert_eq!(wallet.custody.signatures, signatures + 1);
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
        // Fresh intake derives once: no in-workspace or batch replay of its own plan.
        assert_eq!(derivations(&wallet), 1, "boundary {boundary}");
        assert_eq!(wallet.proofs.validations.load(Ordering::SeqCst), 0);
        let mut wallet = restart(wallet);
        let result = wallet.execute(request()).unwrap();
        assert!(matches!(result, Completion::Complete(_)));
        assert_eq!(
            wallet.proofs.preparations.load(Ordering::SeqCst),
            if boundary == 0 { 2 } else { 1 }
        );
        assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 1);
        assert_eq!(wallet.custody.signatures, signatures + 1);
        // The resumed call derives twice: a fresh plan (nothing was retained), the
        // recovered batch replay (1..=4) or the held plan's validation (5, 6); then commit.
        assert_eq!(derivations(&wallet), 3, "boundary {boundary}");
        assert_eq!(
            wallet.proofs.validations.load(Ordering::SeqCst),
            usize::from(boundary != 0),
            "boundary {boundary}"
        );
        assert_eq!(
            wallet.proofs.proof_origins.lock().unwrap().last(),
            Some(if boundary == 0 {
                &TestOriginV1::Plan
            } else {
                &TestOriginV1::Validate
            }),
            "boundary {boundary}"
        );
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
        INTAKE_PEAK_MEMORY_BYTES, INTAKE_STORAGE_RESERVATION_BYTES, OPERATION_RESERVATION_BYTES,
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
    let queries = wallet.custody.resource_queries;
    let observation = NativeWorkTurnV1::start(NativeWorkKindV1::Execute);
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
    wallet.custody.resources.memory_bytes = Some(INTAKE_PEAK_MEMORY_BYTES - 1);
    assert!(matches!(
        wallet.require_intake_capacity(),
        Err(Error::NotEnoughMemory)
    ));
    assert!(matches!(
        wallet.require_intake_memory(),
        Err(Error::NotEnoughMemory)
    ));
    wallet.custody.resources.memory_bytes = Some(INTAKE_PEAK_MEMORY_BYTES);
    wallet.require_intake_capacity().unwrap();
    wallet.require_intake_memory().unwrap();
    wallet.custody.resources.memory_bytes = None;
    wallet.require_intake_capacity().unwrap();
    let observed = observation.finish(true).admissions;
    assert_eq!(
        wallet.custody.resource_queries,
        queries + 7,
        "observation adds no probe"
    );
    assert_eq!(observed.count, 7);
    let rows: Vec<_> = observed.records.iter().flatten().collect();
    assert_eq!(
        rows.iter().map(|row| row.result).collect::<Vec<_>>(),
        vec![
            NativeAdmissionResultV1::StorageShortfall,
            NativeAdmissionResultV1::ProbeFailed,
            NativeAdmissionResultV1::MemoryShortfall,
            NativeAdmissionResultV1::MemoryShortfall,
            NativeAdmissionResultV1::Passed,
            NativeAdmissionResultV1::Passed,
            NativeAdmissionResultV1::Passed,
        ]
    );
    assert_eq!(rows[1].available, None);
    assert_eq!(rows[3].phase, NativeAdmissionPhaseV1::IntakeMemory);
    assert_eq!(rows[6].available.unwrap().memory_bytes, None);
    assert_eq!(footprint(&wallet), before);
}

#[test]
fn intake_memory_is_the_larger_of_staging_and_proving_never_their_sum() {
    use crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1;
    use crate::kagemusha_wallet_state_v1::capacity::INTAKE_PEAK_MEMORY_BYTES;
    // One staged derivation keeps intake below half a GiB, under a 4 GB phone's proving bound.
    assert!(
        INTAKE_PEAK_MEMORY_BYTES < 512 << 20,
        "{INTAKE_PEAK_MEMORY_BYTES}"
    );
    let mut wallet = prepared_wallet();
    wallet.custody.resources.storage_bytes = u64::MAX / 2;
    // Staging dominates a small relation bound; a larger relation bound replaces it.
    for proving in [
        2_000,
        INTAKE_PEAK_MEMORY_BYTES,
        INTAKE_PEAK_MEMORY_BYTES + 4_096,
    ] {
        wallet.proofs.capacity = KagemushaWalletRuntimeCapacityV1 {
            storage_bytes: 1_000,
            memory_bytes: proving,
        };
        let required = proving.max(INTAKE_PEAK_MEMORY_BYTES);
        wallet.custody.resources.memory_bytes = Some(required - 1);
        assert!(matches!(
            wallet.require_intake_capacity(),
            Err(Error::NotEnoughMemory)
        ));
        assert!(matches!(
            wallet.require_intake_memory(),
            Err(Error::NotEnoughMemory)
        ));
        wallet.custody.resources.memory_bytes = Some(required);
        wallet.require_intake_capacity().unwrap();
        wallet.require_intake_memory().unwrap();
    }
}

#[test]
fn transient_read_back_failure_retains_the_batch_and_heals_on_the_held_plan_retry() {
    let mut wallet = prepared_wallet();
    wallet.proofs.preparation_payload = vec![83; 97];
    let object = object_digest(&wallet.proofs.preparation_payload);
    wallet.archive.hide_object_once(object);
    let signatures = wallet.custody.signatures;
    assert!(matches!(wallet.execute(request()), Err(Error::Storage(_))));
    // The plan is selected, staging is retained, and nothing was proven or signed.
    assert!(
        wallet
            .archive
            .records
            .lock()
            .unwrap()
            .contains_key(&ArchiveKey::PreparationDraft(request().request_id))
    );
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.custody.signatures, signatures);
    assert_eq!(derivations(&wallet), 1);
    let mut wallet = restart(wallet);
    assert!(matches!(
        wallet.execute(request()).unwrap(),
        Completion::Complete(_)
    ));
    assert_eq!(derivations(&wallet), 3, "held-plan validation and commit");
    assert_eq!(wallet.proofs.validations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.custody.signatures, signatures + 1);
    assert!(
        !wallet
            .archive
            .records
            .lock()
            .unwrap()
            .contains_key(&ArchiveKey::PreparationDraft(request().request_id))
    );
}

#[test]
fn missing_staged_object_fails_every_retry_stably_without_proof_or_signature() {
    let mut wallet = prepared_wallet();
    wallet.proofs.preparation_payload = vec![89; 97];
    let object = object_digest(&wallet.proofs.preparation_payload);
    wallet.archive.hide_object(object);
    let signatures = wallet.custody.signatures;
    assert!(matches!(
        wallet.execute(request()),
        Err(Error::WitnessLost("index object"))
    ));
    let retained = footprint(&wallet);
    let mut wallet = restart(wallet);
    for _ in 0..2 {
        // The held plan never re-materializes from the retained batch.
        assert!(matches!(
            wallet.execute(request()),
            Err(Error::WitnessLost("index object"))
        ));
        assert_eq!(footprint(&wallet), retained);
    }
    assert!(
        wallet
            .archive
            .records
            .lock()
            .unwrap()
            .contains_key(&ArchiveKey::PreparationDraft(request().request_id))
    );
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.custody.signatures, signatures);
    wallet.archive.reveal_object(object);
    assert!(matches!(
        wallet.execute(request()).unwrap(),
        Completion::Complete(_)
    ));
    assert_eq!(wallet.custody.signatures, signatures + 1);
}
