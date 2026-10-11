//! Actual durable wallet phases, lazy identity failure and inherited read admission.

use super::super::tests::{request, service};
use super::*;
use std::{fs, sync::atomic::Ordering};

#[test]
fn scoped_wallet_inspection_preserves_all_real_phases_markers_and_no_http() {
    let (service, transport) = service();
    let _profile = ChainDiscriminantGuard::enter(service.config.account_chain_discriminant);
    let root = tempfile::tempdir().unwrap();
    let original_path = root.path().join("original");
    service
        .prepare_transfer(&request(), &original_path)
        .unwrap();
    let original = Journal::open(&original_path).unwrap();
    let request: Request = original
        .read_native(NativeRecord::Request)
        .unwrap()
        .unwrap();
    let payload: Payload = original
        .read_native(NativeRecord::Payload)
        .unwrap()
        .unwrap();
    let operation: TransactionJournal = original
        .read_native(NativeRecord::Operation)
        .unwrap()
        .unwrap();
    drop(original);
    for (phase, expected) in [
        ("request", NativePreparationPhase::RequestOnly),
        ("payload", NativePreparationPhase::PayloadRetained),
        ("signed", NativePreparationPhase::Signed),
        ("marked", NativePreparationPhase::Signed),
        ("retired", NativePreparationPhase::Retired),
    ] {
        let path = root.path().join(phase);
        let journal = Journal::create_preparation(&path, &request).unwrap();
        if matches!(phase, "payload" | "signed" | "marked") {
            journal
                .write_native(NativeRecord::Payload, &payload)
                .unwrap();
        }
        if matches!(phase, "signed" | "marked") {
            journal
                .write_native(NativeRecord::Operation, &operation)
                .unwrap();
        }
        if phase == "marked" {
            assert!(journal.record_submission(&operation).unwrap());
        }
        if phase == "retired" {
            journal
                .write_native(
                    NativeRecord::Retired,
                    &Retirement {
                        schema: "iroha.wallet.native-retirement.v1".into(),
                        request_sha256: request.commitment().unwrap(),
                    },
                )
                .unwrap();
        }
        let files = [
            "preparation.json",
            "payload.json",
            "operation.json",
            "submission.json",
            "retired.json",
        ]
        .map(|name| (name, fs::read(path.join(name)).ok()));
        let requests = transport.requests.load(Ordering::SeqCst);
        let quotes = transport.quote_count.load(Ordering::SeqCst);
        let dispatches = transport.dispatch_count.load(Ordering::SeqCst);
        let actual = norito::core::with_decode_limits_scope(LIMITS, || {
            Retained::read(&journal, &service.config)
        })
        .unwrap();
        assert_eq!(actual.phase(), expected, "{phase}");
        assert_eq!(
            actual.request.commitment().unwrap(),
            request.commitment().unwrap()
        );
        assert_eq!(
            actual.signed.is_some(),
            matches!(phase, "signed" | "marked")
        );
        assert_eq!(transport.requests.load(Ordering::SeqCst), requests);
        assert_eq!(transport.quote_count.load(Ordering::SeqCst), quotes);
        assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), dispatches);
        for (name, before) in files {
            assert_eq!(fs::read(path.join(name)).ok(), before);
        }
    }
}

#[test]
fn scoped_wallet_first_identity_refusal_precedes_later_extent_and_same_source_retry() {
    let (service, transport) = service();
    let _profile = ChainDiscriminantGuard::enter(service.config.account_chain_discriminant);
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("original");
    service.prepare_transfer(&request(), &path).unwrap();
    let original_request = fs::read(path.join("preparation.json")).unwrap();
    let original_payload = fs::read(path.join("payload.json")).unwrap();
    let mut changed: Request = norito::json::from_slice(&original_request).unwrap();
    changed.schema = "invalid-original-request".into();
    let directory = iroha_fs::PrivateDirectory::open(&path).unwrap();
    directory
        .write_atomic(
            "preparation.json",
            &canonical_bytes(&changed).unwrap(),
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(path.join("payload.json"))
        .unwrap()
        .set_len(u64::try_from(MAX_JOURNAL_BYTES + 1).unwrap())
        .unwrap();
    let requests = transport.requests.load(Ordering::SeqCst);
    let error = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "preparation differs from the original wallet identity or finite authorization"
    );
    assert!(!format!("{error:#}").contains("journal evidence exceeds its byte bound"));
    assert_eq!(transport.requests.load(Ordering::SeqCst), requests);
    directory
        .write_atomic(
            "preparation.json",
            &original_request,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    directory
        .write_atomic(
            "payload.json",
            &original_payload,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    assert_eq!(
        service
            .inspect_transfer_preparation(&path, &request())
            .unwrap()
            .phase(),
        NativePreparationPhase::Signed
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), requests);
    assert_eq!(
        fs::read(path.join("preparation.json")).unwrap(),
        original_request
    );
    assert_eq!(
        fs::read(path.join("payload.json")).unwrap(),
        original_payload
    );
}

#[test]
fn scoped_wallet_inherited_zero_allocation_refuses_first_native_read_then_retries() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("original");
    service.prepare_transfer(&request(), &path).unwrap();
    let original = fs::read(path.join("preparation.json")).unwrap();
    let requests = transport.requests.load(Ordering::SeqCst);
    let budget = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(0, 0, 0, 0, 0));
    let error = budget
        .with(|| service.inspect_transfer_preparation(&path, &request()))
        .unwrap_err();
    assert!(
        matches!(error.downcast_ref::<norito::Error>().and_then(|error| error.decode_resource_error()),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 })
            if attempted == u64::try_from(original.len()).unwrap())
    );
    assert_eq!(budget.consumed_allocated_bytes(), 0);
    assert_eq!(transport.requests.load(Ordering::SeqCst), requests);
    assert!(!norito::core::decode_limits_active());
    assert_eq!(
        service
            .inspect_transfer_preparation(&path, &request())
            .unwrap()
            .phase(),
        NativePreparationPhase::Signed
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), requests);
    assert_eq!(fs::read(path.join("preparation.json")).unwrap(), original);
}
