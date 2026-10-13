//! Provider-free completed-receipt checks retain the original journal lease and finalized reads.

use super::*;

#[test]
fn completed_stream_check_survives_signer_drop_and_never_calls_provider_or_mutates_state() {
    let mut harness = Harness::new();
    let body = body(36);
    let receipt = harness
        .sign(&body)
        .expect("completed original stream operation");
    let checker = harness
        .service()
        .completed_receipt_check()
        .expect("read-only checker from original journal");
    drop(harness.service.take());

    let before = harness.source.counts();
    let calls = harness.calls();
    let validated_receipt = checker
        .check(&payload(&body))
        .expect("exact completed receipt");
    let after = harness.source.counts();
    assert_eq!(validated_receipt.bytes(), receipt.bytes());
    assert_eq!(harness.calls(), calls);
    assert_eq!(
        (after.signing, after.reserves, after.commits),
        (before.signing, before.reserves, before.commits),
        "completed Check cannot reserve, complete or sign"
    );
    assert_eq!(after.completed - before.completed, 3);
    assert!(after.current > before.current);
    assert!(!format!("{checker:?}").contains(&body.token_id));
}

#[test]
fn completed_stream_check_refuses_missing_or_substituted_finalized_row_without_key_use() {
    for mutation in 0..2 {
        let mut harness = Harness::new();
        let body = body(37 + mutation);
        let receipt = harness
            .sign(&body)
            .expect("completed original stream operation");
        let decoded = SignerStreamTokenReceiptV1::decode_canonical(receipt.bytes()).unwrap();
        let checker = harness.service().completed_receipt_check().unwrap();
        drop(harness.service.take());
        let mut history = harness.source.history.lock().unwrap();
        if mutation == 0 {
            history.remove(&decoded.intent.operation_id);
        } else {
            history.get_mut(&decoded.intent.operation_id).unwrap().3[0] ^= 1;
        }
        drop(history);

        let before = harness.source.counts();
        let calls = harness.calls();
        assert_eq!(
            checker.check(&payload(&body)).unwrap_err(),
            SignerStreamTokenErrorV1::Operation(SignerOperationErrorV1::ReservationConflict)
        );
        let after = harness.source.counts();
        assert_eq!(
            (after.signing, after.reserves, after.commits),
            (before.signing, before.reserves, before.commits)
        );
        assert_eq!(harness.calls(), calls);
    }
}

#[test]
fn completed_stream_check_rejects_current_revocation_and_altered_private_receipt() {
    for mutation in 0..2 {
        let mut harness = Harness::new();
        let body = body(39 + mutation);
        let receipt = harness.sign(&body).unwrap();
        let decoded = SignerStreamTokenReceiptV1::decode_canonical(receipt.bytes()).unwrap();
        let checker = harness.service().completed_receipt_check().unwrap();
        drop(harness.service.take());
        if mutation == 0 {
            harness
                .source
                .base
                .state
                .lock()
                .unwrap()
                .context
                .signer_revoked = true;
        } else {
            fs::set_permissions(
                harness.source.path(decoded.intent.operation_id),
                fs::Permissions::from_mode(0o444),
            )
            .unwrap();
        }
        let calls = harness.calls();
        assert!(checker.check(&payload(&body)).is_err());
        assert_eq!(harness.calls(), calls);
    }
}
