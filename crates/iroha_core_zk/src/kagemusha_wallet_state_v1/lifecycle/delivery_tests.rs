//! Real Coordinator lookup/replay over explicit custody/proof probes. Seeded completion DATA
//! does not establish installed financial proofs, hardware execution or phone qualification.

use super::*;

fn retained_delivery() -> (Wallet, [u8; 32], Vec<u8>, Vec<u8>) {
    let mut wallet = wallet();
    let payment: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
    let companion: KagemushaWalletPayerCompanionV1 = fixture("KagemushaWalletPayerCompanionV1");
    let mut request = None;
    for row in vectors()["envelopes"].as_array().unwrap() {
        let envelope: KagemushaWalletEnvelopeV1 =
            archive::decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap();
        match envelope.message {
            KagemushaWalletMessageV1::Request { request: original } => request = Some(original),
            _ => {}
        }
    }
    let request = request
        .unwrap()
        .complete_with(&payment.signed_request().unwrap())
        .unwrap();
    assert_eq!(request.signed(), payment.signed_request().unwrap());
    payment
        .verify(
            &fixture("KagemushaWalletSchemeV1"),
            &companion.payer_credential,
            &companion.certificates,
            &request,
        )
        .unwrap();
    let received: KagemushaWalletCompletionRecordV1 = fixture("KagemushaWalletCompletionRecordV1");
    let credited =
        KagemushaWalletCreditedV1::from_receive(archive::decode(&received.output).unwrap())
            .unwrap();
    let credited_digest = credited
        .verify_for(&fixture("KagemushaWalletSchemeV1"), &request, &payment)
        .unwrap()
        .0;
    let request = archive::encode(&request).unwrap();
    let credited = archive::encode(&credited).unwrap();
    wallet.wallet_id = payment.signed_request().unwrap().body.payer_wallet_id;
    wallet.archive.wallet = wallet.wallet_id;
    // Seed a canonical ArchiveSent completion, signed by the actual payer fixture key.
    // The financial proof remains an explicit mock; neither a foreign Receive output nor
    // a caller-selected operation/frame/hash can substitute for this completion binding.
    let mut archived = frozen(
        Some(&bootstrap()),
        KagemushaWalletEffectV1::Load {
            receipt_digest: field(98),
            load_ordinal: 0,
            amount: 1,
            online_charge: 0,
        },
    );
    archived.credential = companion.payer_credential.clone();
    let mut body = archived.capsule.body().clone();
    body.wallet_id = wallet.wallet_id;
    body.kind = KagemushaWalletOperationKindV1::ArchiveSent;
    body.statement.effect = KagemushaWalletEffectV1::ArchiveSent {
        credit_id: payment.digests().unwrap().credit_id,
        credited: credited_digest,
    };
    body.statement.next_load = 0;
    body.successor_state =
        KagemushaWalletStateV1::bootstrap(&archived.credential, field(92)).unwrap();
    body.successor_state.core.sequence = body.statement.sequence;
    body.successor_state.core.balance = 20;
    body.retained_inputs = vec![
        (KagemushaWalletRetainedInputRoleV1::Request, request.clone()),
        (
            KagemushaWalletRetainedInputRoleV1::Payment,
            payment.to_canonical_bytes().unwrap(),
        ),
        (
            KagemushaWalletRetainedInputRoleV1::Credited,
            credited.clone(),
        ),
        (
            KagemushaWalletRetainedInputRoleV1::Credential,
            archived.credential.to_canonical_bytes().unwrap(),
        ),
        (
            KagemushaWalletRetainedInputRoleV1::CertificateSet,
            archive::encode(&companion.certificates).unwrap(),
        ),
    ]
    .into_iter()
    .map(|(role, bytes)| KagemushaWalletRetainedInputV1 { role, bytes })
    .collect();
    rebind_frozen_successor(&mut archived, body);
    archived.validate().unwrap();
    let capsule = &archived.capsule;
    let operation = capsule.body().operation_id;
    let archive_capsule = capsule.custody_digest();
    let owner = TransitionOwner::new(&archived.credential);
    let signature: Signature =
        signer(&archived.credential).sign(&kagemusha_wallet_signing_message_v1(
            KagemushaWalletSigningDomainV1::Receipt,
            &owner.receipt_body(capsule, &archive_capsule).unwrap(),
        ));
    let signature = signature.normalize_s().unwrap_or(signature);
    let signature = KagemushaDeviceSignatureV1::from_raw_bytes(&signature.to_bytes()).unwrap();
    let record = owner
        .assemble(capsule, &archive_capsule, &signature)
        .unwrap();
    record.verify(&archived.credential, capsule).unwrap();
    let result = record.output.clone();
    let retained = Retained {
        operation_id: operation,
        capsule_digest: archive_capsule,
        selected_generation: 4,
        completion_digest: record.completion_digest().unwrap(),
        frame: record.to_canonical_bytes().unwrap(),
        record,
    };
    wallet.custody.retained.insert(operation, retained.clone());
    let (selected, mut manifest) = wallet.manifest().unwrap();
    manifest.indexed = Some(capsule.body().statement.sequence);
    manifest.capsule = archive_capsule;
    manifest.steps = manifest
        .steps
        .set(
            &mut wallet.archive,
            manifest::sequence_key(capsule.body().statement.sequence),
            &archive::encode(&manifest::StepEntry {
                capsule: archive_capsule,
                operation,
                selected_generation: retained.selected_generation,
                completion: retained.completion_digest,
                kind: KagemushaWalletOperationKindV1::ArchiveSent,
                checkpoints: 0,
                collected: false,
            })
            .unwrap(),
        )
        .unwrap();
    // The permanent selected StepEntry authenticates every returned completion byte. No
    // historical Send capsule/source, Archive capsule or new native derivation is needed.
    let mut marker = enrollment();
    marker.wallet_id = wallet.wallet_id;
    marker.payment_key = archived.credential.body.payment_key;
    marker.generation = retained.selected_generation + 1;
    marker.state = capsule.head_marker_state();
    wallet.custody.status = SlotStatus::Released(marker_record(marker, retained.completion_digest));
    wallet.publish_manifest(selected, &manifest).unwrap();
    let send_id = [77; 32];
    let send_operation = payment
        .send
        .statement
        .operation_id(&wallet.wallet_id)
        .unwrap();
    let send_capsule = [84; 32];
    let send_commitment = payment.send.receipt.capsule_commitment;
    let send = NativeIntentV1::user(OperationRequestV1 {
        request_id: send_id,
        action: OperationActionV1::Send {
            request: request.clone(),
        },
    });
    wallet
        .retain_delivery_test_mapping(send, send_capsule, send_commitment, send_operation)
        .unwrap();
    // Send completion/capsule/source are absent: only the explicit permanent tombstone is
    // available. A regression that reopens archive_send_source cannot pass this test.
    wallet.custody.tombstones.insert(
        send_operation,
        crate::kagemusha_wallet_advance_v1::KagemushaWalletTombstoneV1 {
            version: 1,
            operation_id: send_operation,
            kind: KagemushaWalletOperationKindV1::Send as u8,
            selected_generation: 3,
            capsule_digest: send_capsule,
            completion_digest: [8; 32],
        },
    );
    let intent = NativeIntentV1::retained_delivery_test_originals(
        &payment,
        send_capsule,
        request,
        credited.clone(),
        companion.payer_credential.to_canonical_bytes().unwrap(),
        archive::encode(&companion.certificates).unwrap(),
    );
    wallet
        .retain_delivery_test_mapping(
            intent,
            archive_capsule,
            capsule.receipt_commitment(),
            operation,
        )
        .unwrap();
    assert_eq!(
        wallet.retry(&operation).unwrap(),
        Some(Completion::Complete(result.clone()))
    );
    (wallet, send_id, credited, result)
}

#[test]
fn bound_delivery_query_and_exact_retry_survive_collected_send_and_lost_app_ack() {
    let (mut wallet, send, credited, original) = retained_delivery();
    for _ in 0..2 {
        assert_eq!(
            wallet.credited_status_for_send(&send, &credited).unwrap(),
            RequestStatusV1::Outcome(Completion::Complete(original.clone()))
        );
        assert_eq!(
            wallet.accept_credited_for_send(&send, &credited).unwrap(),
            Completion::Complete(original.clone())
        );
    }
    assert_eq!(wallet.custody.signatures, 0);
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
}

#[test]
fn bound_delivery_foreign_request_and_unavailable_custody_never_mean_complete_or_absent() {
    let (mut wallet, send, credited, _) = retained_delivery();
    assert!(
        wallet
            .credited_status_for_send(&[82; 32], &credited)
            .is_err()
    );
    assert!(
        wallet
            .accept_credited_for_send(&[82; 32], &credited)
            .is_err()
    );
    wallet.custody.unavailable = true;
    assert!(wallet.credited_status_for_send(&send, &credited).is_err());
    assert!(wallet.accept_credited_for_send(&send, &credited).is_err());
    assert_eq!(wallet.custody.signatures, 0);
}

#[test]
fn bound_delivery_after_send_pruning_rejects_changed_private_tombstone() {
    let (mut wallet, send, credited, _) = retained_delivery();
    wallet
        .custody
        .tombstones
        .values_mut()
        .next()
        .unwrap()
        .capsule_digest[0] ^= 1;
    assert!(wallet.credited_status_for_send(&send, &credited).is_err());
    assert!(wallet.accept_credited_for_send(&send, &credited).is_err());
    assert_eq!(wallet.custody.signatures, 0);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
}

#[test]
fn bound_delivery_after_send_pruning_rejects_mismatched_archive_completion_pair() {
    for public in [false, true] {
        let (mut wallet, send, credited, _) = retained_delivery();
        let retained = wallet.custody.retained.values_mut().next().unwrap();
        if public {
            retained.record.receipt.capsule_commitment[0] ^= 1;
        } else {
            retained.record.capsule_digest[0] ^= 1;
        }
        assert!(wallet.credited_status_for_send(&send, &credited).is_err());
        assert!(wallet.accept_credited_for_send(&send, &credited).is_err());
        assert_eq!(wallet.custody.signatures, 0);
        assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn delivery_read_refusal_preserves_collected_send_and_exact_retry_without_signing() {
    let (mut wallet, send, credited, original) = retained_delivery();
    let root = wallet.manifest().unwrap().0;
    for limits in [
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
    ] {
        let status = norito::with_decode_limits_scope(limits, || {
            wallet.credited_status_for_send(&send, &credited)
        });
        assert!(matches!(status, Err(Error::DecodeResource(ref cause))
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        let retry = norito::with_decode_limits_scope(limits, || {
            wallet.accept_credited_for_send(&send, &credited)
        });
        assert!(matches!(retry, Err(Error::DecodeResource(ref cause))
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        assert_eq!(wallet.manifest().unwrap().0, root);
        assert_eq!(
            wallet.credited_status_for_send(&send, &credited).unwrap(),
            RequestStatusV1::Outcome(Completion::Complete(original.clone()))
        );
        assert_eq!(
            wallet.accept_credited_for_send(&send, &credited).unwrap(),
            Completion::Complete(original.clone())
        );
    }
    assert_eq!(wallet.custody.signatures, 0);
    assert_eq!(wallet.proofs.preparations.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
}
