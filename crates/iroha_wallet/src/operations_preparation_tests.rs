//! Durable-prefix recovery controls using the actual wallet producer and exact original envelopes.
use super::super::tests::{request, service};
use super::*;
use std::{sync::atomic::Ordering, time::Instant};

fn bytes(path: &Path, name: &str) -> Vec<u8> {
    std::fs::read(path.join(name)).unwrap()
}
fn request_only(service: &AccountService, transport: &super::super::tests::Transport, path: &Path) {
    transport
        .incompatible_submission
        .store(true, Ordering::SeqCst);
    assert!(service.prepare_transfer(&request(), path).is_err());
    transport
        .incompatible_submission
        .store(false, Ordering::SeqCst);
    assert!(path.join("preparation.json").is_file());
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
}

#[test]
fn inspection_exposes_only_the_exact_canonical_retained_request_commitment() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("commitment");
    let missing = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap();
    assert_eq!(missing.request_sha256(), None);
    assert!(!path.exists());
    request_only(&service, &transport, &path);
    let original = bytes(&path, "preparation.json");
    let request_commitment = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap()
        .request_sha256()
        .unwrap()
        .to_owned();
    assert_eq!(request_commitment.len(), 64);
    service.prepare_transfer(&request(), &path).unwrap();
    let signed = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap();
    assert_eq!(signed.phase(), NativePreparationPhase::Signed);
    assert_eq!(signed.request_sha256(), Some(request_commitment.as_str()));
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let before = transport.requests.load(Ordering::SeqCst);
    let partial = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap();
    assert_eq!(partial.phase(), NativePreparationPhase::PayloadRetained);
    assert_eq!(partial.request_sha256(), Some(request_commitment.as_str()));
    assert_eq!(bytes(&path, "preparation.json"), original);
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);

    let retired_path = root.path().join("retired-commitment");
    request_only(&service, &transport, &retired_path);
    let before = transport.requests.load(Ordering::SeqCst);
    let receipt = service
        .retire_transfer_unprepared(&retired_path, &request())
        .unwrap();
    let inspected = service
        .inspect_transfer_preparation(&retired_path, &request())
        .unwrap();
    assert_eq!(inspected.phase(), NativePreparationPhase::Retired);
    assert_eq!(inspected.request_sha256(), Some(receipt.request_sha256()));
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
}

#[test]
fn request_only_is_read_only_and_explicit_finish_keeps_original_authorization() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("request");
    request_only(&service, &transport, &path);
    let original = bytes(&path, "preparation.json");
    let before = transport.requests.load(Ordering::SeqCst);
    let inspected = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap();
    assert_eq!(inspected.phase(), NativePreparationPhase::RequestOnly);
    assert_eq!(inspected.unprepared_status(), Some(OperationStatus::Absent));
    assert!(inspected.into_signed_transaction().is_err());
    assert_eq!(
        service
            .resume(&path, NativeOperationKind::Transfer)
            .unwrap()
            .status,
        OperationStatus::Absent
    );
    assert!(
        service
            .submit(&path, NativeOperationKind::Transfer)
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
    assert_eq!(bytes(&path, "preparation.json"), original);
    service.prepare_transfer(&request(), &path).unwrap();
    assert_eq!(bytes(&path, "preparation.json"), original);
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 1);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
}

#[test]
fn retained_payload_finishes_same_nonce_ttl_quote_and_canonical_wire_without_http() {
    let (service, transport) = service();
    let mut config = service.config.clone();
    config.transaction_add_nonce = true;
    let service = AccountService {
        client: Client::with_http_transport(config.clone(), transport.clone()).unwrap(),
        config,
        deadline: None,
        cancellation: None,
    };
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("payload");
    service.prepare_transfer(&request(), &path).unwrap();
    let original_request = bytes(&path, "preparation.json");
    let original_payload = bytes(&path, "payload.json");
    let original_operation = bytes(&path, "operation.json");
    let original = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap()
        .into_signed_transaction()
        .unwrap();
    assert!(original.payload().nonce.is_some());
    // Replay the genuine durable prefix immediately before operation publication. No marker or
    // dispatch existed, and the exact original quoted payload remains unchanged.
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let before = transport.requests.load(Ordering::SeqCst);
    let inspected = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap();
    assert_eq!(inspected.phase(), NativePreparationPhase::PayloadRetained);
    assert_eq!(
        service
            .resume(&path, NativeOperationKind::Transfer)
            .unwrap()
            .status,
        OperationStatus::Absent
    );
    assert!(!path.join("operation.json").exists());
    service.prepare_transfer(&request(), &path).unwrap();
    let finished = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap()
        .into_signed_transaction()
        .unwrap();
    assert_eq!(finished.payload(), original.payload());
    assert_eq!(finished.hash(), original.hash());
    assert_eq!(
        encode_signed(&finished).unwrap(),
        finished.encode_versioned()
    );
    assert_eq!(finished.encode_versioned(), original.encode_versioned());
    assert_eq!(bytes(&path, "operation.json"), original_operation);
    assert_eq!(bytes(&path, "payload.json"), original_payload);
    assert_eq!(bytes(&path, "preparation.json"), original_request);
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
}

#[test]
fn current_signed_preparation_reuses_exact_wire_after_once_only_submission_marker() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("signed");
    service.prepare_transfer(&request(), &path).unwrap();
    let original = bytes(&path, "operation.json");
    let journal = Journal::open(&path).unwrap();
    let record: TransactionJournal = journal.read_operation().unwrap();
    assert!(journal.record_submission(&record).unwrap());
    drop(journal);
    let before = transport.requests.load(Ordering::SeqCst);
    assert_eq!(
        service.prepare_transfer(&request(), &path).unwrap().status,
        OperationStatus::Pending
    );
    assert_eq!(bytes(&path, "operation.json"), original);
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    assert!(
        service
            .retire_transfer_unprepared(&path, &request())
            .is_err()
    );
}

#[test]
fn changed_request_fee_network_and_payload_refuse_without_http() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("bound");
    service.prepare_transfer(&request(), &path).unwrap();
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let before = transport.requests.load(Ordering::SeqCst);
    let mut changed = request();
    changed.amount = Quantity::from(4_u32);
    assert!(
        service
            .inspect_transfer_preparation(&path, &changed)
            .is_err()
    );
    assert!(service.prepare_transfer(&changed, &path).is_err());
    changed = request();
    changed.fee_payment = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(7));
    assert!(
        service
            .inspect_transfer_preparation(&path, &changed)
            .is_err()
    );
    let mut foreign = service.config.clone();
    foreign.torii_api_url = "http://127.0.0.1:8090/".parse().unwrap();
    assert!(
        AccountService::new(foreign)
            .unwrap()
            .inspect_transfer_preparation(&path, &request())
            .is_err()
    );
    let journal = Journal::open(&path).unwrap();
    let mut payload: EncodedPayload = journal.read_native(NativeRecord::Payload).unwrap().unwrap();
    let request_record: Request = journal.read_native(NativeRecord::Request).unwrap().unwrap();
    let mut wire = payload.verify(&request_record, &service.config).unwrap();
    wire.nonce =
        std::num::NonZeroU32::new(wire.nonce.map_or(1, |value| value.get().saturating_add(1)));
    payload.payload_hex = bounded_hex(&encode_payload(&wire).unwrap()).unwrap();
    // A changed payload can still be structurally valid as an unsigned request. Once operation
    // exists, the original signed bytes must bind it, and immutable publication never replaces it.
    assert!(
        journal
            .write_native(NativeRecord::Payload, &payload)
            .is_err()
    );
    drop(journal);
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
}

#[test]
fn request_retirement_is_exact_locked_and_never_infers_from_unknown_material() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("retire");
    request_only(&service, &transport, &path);
    let original = bytes(&path, "preparation.json");
    let held = Journal::open(&path).unwrap();
    assert!(
        service
            .retire_transfer_unprepared(&path, &request())
            .is_err()
    );
    drop(held);
    let directory = iroha_fs::PrivateDirectory::open(&path).unwrap();
    directory
        .write_atomic("unknown.json", b"unknown", iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(
        service
            .retire_transfer_unprepared(&path, &request())
            .is_err()
    );
    std::fs::remove_file(path.join("unknown.json")).unwrap();
    drop(directory);
    let before = transport.requests.load(Ordering::SeqCst);
    let retired = service
        .retire_transfer_unprepared(&path, &request())
        .unwrap();
    let marker = bytes(&path, "retired.json");
    assert_eq!(
        service
            .retire_transfer_unprepared(&path, &request())
            .unwrap()
            .request_sha256(),
        retired.request_sha256()
    );
    assert_eq!(bytes(&path, "retired.json"), marker);
    assert_eq!(
        service
            .inspect_transfer_preparation(&path, &request())
            .unwrap()
            .phase(),
        NativePreparationPhase::Retired
    );
    assert!(service.prepare_transfer(&request(), &path).is_err());
    assert!(
        service
            .submit(&path, NativeOperationKind::Transfer)
            .is_err()
    );
    assert!(
        service
            .resume(&path, NativeOperationKind::Transfer)
            .is_err()
    );
    assert_eq!(bytes(&path, "preparation.json"), original);
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
}

#[test]
fn operation_only_and_inconsistent_stages_never_decode_as_unsigned_or_missing() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("complete");
    service.prepare_transfer(&request(), &path).unwrap();
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let retired_layout = root.path().join("operation-only");
    drop(Journal::create_prepared(&retired_layout, &record).unwrap());
    let before = transport.requests.load(Ordering::SeqCst);
    assert!(
        service
            .inspect_transfer_preparation(&retired_layout, &request())
            .is_err()
    );
    assert!(
        service
            .prepare_transfer(&request(), &retired_layout)
            .is_err()
    );
    assert!(
        service
            .resume(&retired_layout, NativeOperationKind::Transfer)
            .is_err()
    );
    std::fs::remove_file(path.join("payload.json")).unwrap();
    assert!(
        service
            .inspect_transfer_preparation(&path, &request())
            .is_err()
    );
    assert!(
        service
            .retire_transfer_unprepared(&path, &request())
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
}

#[test]
fn expired_signed_transfer_resume_preserves_undispatched_and_uncertain_outcomes() {
    for dispatched in [false, true] {
        let (mut service, transport) = service();
        service.config.transaction_ttl = Duration::from_millis(1500);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signed-expiry");
        service.prepare_transfer(&request(), &path).unwrap();
        let transaction = service
            .inspect_transfer_preparation(&path, &request())
            .unwrap()
            .into_signed_transaction()
            .unwrap();
        let expiry = transaction_deadline(&transaction).unwrap();
        if dispatched {
            let journal = Journal::open(&path).unwrap();
            let record: TransactionJournal = journal.read_operation().unwrap();
            assert!(journal.record_submission(&record).unwrap());
        }
        let original = bytes(&path, "operation.json");
        let marker = dispatched.then(|| bytes(&path, "submission.json"));
        let wait_limit = Instant::now() + Duration::from_secs(3);
        while current_unix_ms().unwrap() < expiry {
            assert!(Instant::now() < wait_limit, "signed deadline must elapse");
            std::thread::sleep(Duration::from_millis(10));
        }
        let expected = if dispatched {
            OperationStatus::Pending
        } else {
            OperationStatus::Expired
        };
        for result in [
            service.resume(&path, NativeOperationKind::Transfer),
            service.submit(&path, NativeOperationKind::Transfer),
        ] {
            assert_eq!(result.unwrap().status, expected);
        }
        assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
        assert_eq!(bytes(&path, "operation.json"), original);
        assert_eq!(std::fs::read(path.join("submission.json")).ok(), marker);
    }
}

#[test]
fn real_expired_payload_is_readonly_and_cannot_redraw_under_fresh_io_deadline() {
    let (mut service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    service.config.transaction_ttl = Duration::from_millis(1500);
    let path = root.path().join("expired");
    service.prepare_transfer(&request(), &path).unwrap();
    let signed = service
        .inspect_transfer_preparation(&path, &request())
        .unwrap()
        .into_signed_transaction()
        .unwrap();
    let expiry = transaction_deadline(&signed).unwrap();
    let original_request = bytes(&path, "preparation.json");
    let original_payload = bytes(&path, "payload.json");
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let wait_limit = Instant::now() + Duration::from_secs(3);
    while current_unix_ms().unwrap() < expiry {
        assert!(
            Instant::now() < wait_limit,
            "original finite expiry must elapse"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let before = transport.requests.load(Ordering::SeqCst);
    let refreshed = service
        .with_deadline(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(
        refreshed
            .inspect_transfer_preparation(&path, &request())
            .unwrap()
            .unprepared_status(),
        Some(OperationStatus::Expired)
    );
    assert_eq!(
        refreshed
            .resume(&path, NativeOperationKind::Transfer)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert!(refreshed.prepare_transfer(&request(), &path).is_err());
    assert!(
        refreshed
            .retire_transfer_unprepared(&path, &request())
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
    assert_eq!(bytes(&path, "preparation.json"), original_request);
    assert_eq!(bytes(&path, "payload.json"), original_payload);
    assert!(!path.join("operation.json").exists());
}

#[test]
fn missing_requires_safe_original_parent_and_unknown_staging_never_selects_work() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("selected");
    assert_eq!(
        service
            .inspect_transfer_preparation(&path, &request())
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(
        service
            .inspect_transfer_preparation(&root.path().join("absent-parent/child"), &request())
            .is_err()
    );
    let decoy = root.path().join("unpublished-staging");
    service.prepare_transfer(&request(), &decoy).unwrap();
    let before = transport.requests.load(Ordering::SeqCst);
    assert_eq!(
        service
            .inspect_transfer_preparation(&path, &request())
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
    assert!(!path.exists());
}

#[test]
#[cfg(unix)]
fn dangling_or_unsafe_parent_cannot_be_classified_missing() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let (service, _) = service();
    let root = tempfile::tempdir().unwrap();
    symlink(root.path().join("missing"), root.path().join("alias")).unwrap();
    assert!(
        service
            .inspect_transfer_preparation(&root.path().join("alias/child"), &request())
            .is_err()
    );
    let broad = root.path().join("broad");
    std::fs::create_dir(&broad).unwrap();
    std::fs::set_permissions(&broad, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        service
            .inspect_transfer_preparation(&broad.join("child"), &request())
            .is_err()
    );
}

#[test]
fn inherited_zero_allocation_refuses_before_request_publication_or_http() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("quota");
    let result = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(4096, 4 * 1024 * 1024, 4 * 1024 * 1024, 0, 64),
        || service.prepare_transfer(&request(), &path),
    );
    assert!(result.is_err());
    assert!(!path.exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn payload_request_quote_and_signed_stage_substitutions_refuse_before_network() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("substitutions");
    service.prepare_transfer(&request(), &path).unwrap();
    let original = bytes(&path, "payload.json");
    let directory = iroha_fs::PrivateDirectory::open(&path).unwrap();
    let before = transport.requests.load(Ordering::SeqCst);
    for change in 0..4 {
        let mut payload: EncodedPayload = norito::json::from_slice(&original).unwrap();
        match change {
            0 => payload.request_sha256 = "00".repeat(32),
            1 => {
                payload.quote.intent =
                    FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(7))
            }
            2 => payload.payload_hex.make_ascii_uppercase(),
            _ => {
                let raw = decode_hex(&payload.payload_hex, PAYLOAD_MAX).unwrap();
                let mut decoded: TransactionPayload =
                    bounded::decode_bounded(&raw, PAYLOAD_MAX).unwrap();
                decoded.nonce = std::num::NonZeroU32::new(17);
                payload.payload_hex = bounded_hex(&encode_payload(&decoded).unwrap()).unwrap();
            }
        }
        directory
            .write_atomic(
                "payload.json",
                &canonical_bytes(&payload).unwrap(),
                iroha_fs::PublishMode::Replace,
            )
            .unwrap();
        assert!(
            service
                .inspect_transfer_preparation(&path, &request())
                .is_err(),
            "substitution {change}"
        );
        assert!(
            service.prepare_transfer(&request(), &path).is_err(),
            "substitution {change}"
        );
    }
    directory
        .write_atomic("payload.json", &original, iroha_fs::PublishMode::Replace)
        .unwrap();
    assert_eq!(
        service
            .inspect_transfer_preparation(&path, &request())
            .unwrap()
            .phase(),
        NativePreparationPhase::Signed
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
}

#[test]
#[cfg(unix)]
fn unknown_native_child_material_refuses_every_retained_phase_before_http() {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let (service, transport) = service();
    let _profile = ChainDiscriminantGuard::enter(service.config.account_chain_discriminant);
    let root = tempfile::tempdir().unwrap();
    let original_path = root.path().join("original-signed");
    service
        .prepare_transfer(&request(), &original_path)
        .unwrap();
    let original = Journal::open(&original_path).unwrap();
    let retained_request: Request = original
        .read_native(NativeRecord::Request)
        .unwrap()
        .unwrap();
    let retained_payload: EncodedPayload = original
        .read_native(NativeRecord::Payload)
        .unwrap()
        .unwrap();
    let retained_operation: TransactionJournal = original
        .read_native(NativeRecord::Operation)
        .unwrap()
        .unwrap();
    drop(original);
    for (phase, expected) in [
        ("request", NativePreparationPhase::RequestOnly),
        ("payload", NativePreparationPhase::PayloadRetained),
        ("signed", NativePreparationPhase::Signed),
        ("dispatch", NativePreparationPhase::Signed),
        ("retired", NativePreparationPhase::Retired),
    ] {
        for directory in [false, true] {
            let path = root.path().join(format!("{phase}-{directory}"));
            let held = Journal::create_preparation(&path, &retained_request).unwrap();
            if matches!(phase, "payload" | "signed" | "dispatch") {
                held.write_native(NativeRecord::Payload, &retained_payload)
                    .unwrap();
            }
            if matches!(phase, "signed" | "dispatch") {
                held.write_native(NativeRecord::Operation, &retained_operation)
                    .unwrap();
            }
            if phase == "dispatch" {
                assert!(held.record_submission(&retained_operation).unwrap());
            }
            if phase == "retired" {
                held.write_native(
                    NativeRecord::Retired,
                    &Retirement {
                        schema: "iroha.wallet.native-retirement.v1".into(),
                        request_sha256: retained_request.commitment().unwrap(),
                    },
                )
                .unwrap();
            }
            drop(held);
            assert_eq!(
                service
                    .inspect_transfer_preparation(&path, &request())
                    .unwrap()
                    .phase(),
                expected,
                "the genuine unmodified durable phase must be accepted"
            );
            let known = [
                "preparation.json",
                "payload.json",
                "operation.json",
                "submission.json",
                "retired.json",
            ]
            .map(|name| (name, std::fs::read(path.join(name)).ok()));
            let unknown = path.join("unknown-native-evidence");
            if directory {
                std::fs::create_dir(&unknown).unwrap();
                std::fs::set_permissions(&unknown, std::fs::Permissions::from_mode(0o700)).unwrap();
            } else {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&unknown)
                    .unwrap();
            }
            let requests = transport.requests.load(Ordering::SeqCst);
            let quotes = transport.quote_count.load(Ordering::SeqCst);
            let dispatches = transport.dispatch_count.load(Ordering::SeqCst);
            assert!(
                service
                    .inspect_transfer_preparation(&path, &request())
                    .is_err()
            );
            assert!(service.prepare_transfer(&request(), &path).is_err());
            assert!(
                service
                    .resume(&path, NativeOperationKind::Transfer)
                    .is_err()
            );
            assert!(
                service
                    .submit(&path, NativeOperationKind::Transfer)
                    .is_err()
            );
            assert_eq!(transport.requests.load(Ordering::SeqCst), requests);
            assert_eq!(transport.quote_count.load(Ordering::SeqCst), quotes);
            assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), dispatches);
            for (name, bytes) in known {
                assert_eq!(std::fs::read(path.join(name)).ok(), bytes);
            }
            assert_eq!(unknown.is_dir(), directory);
            assert!(
                unknown.exists(),
                "inspection never repairs foreign material"
            );
        }
    }
}
