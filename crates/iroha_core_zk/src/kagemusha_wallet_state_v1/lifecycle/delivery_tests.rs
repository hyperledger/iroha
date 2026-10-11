//! Real Coordinator lookup/replay over explicit custody/proof probes. Seeded completion DATA
//! does not establish installed financial proofs, hardware execution or phone qualification.

use super::*;

fn retained_delivery() -> (Wallet, [u8; 32], Vec<u8>, Vec<u8>) {
    let mut wallet = wallet();
    let payment: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
    let mut offer = None;
    let mut request = None;
    for row in vectors()["envelopes"].as_array().unwrap() {
        let envelope: KagemushaWalletEnvelopeV1 =
            archive::decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap();
        match envelope.message {
            KagemushaWalletMessageV1::Offer { offer: original } => offer = Some(original),
            KagemushaWalletMessageV1::Request { request: original } => request = Some(original),
            _ => {}
        }
    }
    let offer = offer.unwrap();
    let request = request.unwrap();
    assert_eq!(request.signed(), payment.request);
    payment
        .verify(
            &fixture("KagemushaWalletSchemeV1"),
            &offer.payer_credential,
            &offer.certificates,
            &request,
        )
        .unwrap();
    let request = archive::encode(&request).unwrap();
    let received: KagemushaWalletCompletionRecordV1 = fixture("KagemushaWalletCompletionRecordV1");
    let credited =
        KagemushaWalletCreditedV1::from_receive(archive::decode(&received.output).unwrap())
            .unwrap();
    let credited = archive::encode(&credited).unwrap();
    wallet.wallet_id = payment.request.body.payer_wallet_id;
    wallet.archive.wallet = wallet.wallet_id;
    // Explicit metadata fixture has an indexed head but no historical Send step/capsule.
    // Completion authority is supplied only by the test custody outcomes below.
    let (selected, mut manifest) = wallet.manifest().unwrap();
    manifest.indexed = Some(1);
    manifest.capsule = [83; 32];
    wallet.publish_manifest(selected, &manifest).unwrap();
    let send_id = [77; 32];
    let send_operation = payment
        .send
        .statement
        .operation_id(&wallet.wallet_id)
        .unwrap();
    let send_capsule = payment.send.receipt.capsule_digest;
    let send = NativeIntentV1::user(OperationRequestV1 {
        request_id: send_id,
        action: OperationActionV1::Send {
            request: request.clone(),
        },
    });
    wallet
        .retain_delivery_test_mapping(send, send_capsule, send_operation)
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
        request,
        credited.clone(),
        offer.payer_credential.to_canonical_bytes().unwrap(),
        archive::encode(&offer.certificates).unwrap(),
    );
    let operation = [79; 32];
    let archive_capsule = [80; 32];
    wallet
        .retain_delivery_test_mapping(intent, archive_capsule, operation)
        .unwrap();
    let mut record: KagemushaWalletCompletionRecordV1 =
        fixture("KagemushaWalletCompletionRecordV1");
    record.operation_id = operation;
    let result = record.output.clone();
    wallet.custody.retained.insert(
        operation,
        Retained {
            operation_id: operation,
            capsule_digest: archive_capsule,
            selected_generation: 4,
            completion_digest: [81; 32],
            frame: vec![1],
            record,
        },
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
