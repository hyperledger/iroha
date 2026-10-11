//! Genuine bounded certificate bytes and exact retained payload recovery controls.

use super::super::tests::{private_options, private_root_fixture, service};
use super::*;
use iroha_data_model::private_dataspace::{PrivateDataspaceAnchor, PrivateDataspaceAnchorState};
use std::sync::atomic::Ordering;

fn anchor_request() -> PrivateRootAnchorRequest {
    let (mut fixture, registration) = private_root_fixture();
    let state =
        PrivateDataspaceAnchorState::from_authorized_registration(registration.clone()).unwrap();
    let block = fixture.block_with_submitted_work(fixture.next_header());
    let proof = fixture.certify(block);
    let verified = fixture.verifier().verify_retained_decision(&proof).unwrap();
    let anchor = PrivateDataspaceAnchor::from_certificate(
        &registration,
        verified.block().commit_certificate().unwrap(),
    )
    .unwrap();
    PrivateRootAnchorRequest {
        state,
        anchor,
        options: private_options(),
    }
}

#[test]
fn genuine_private_anchor_payload_prefix_recovers_exact_wire_without_another_quote() {
    let (service, transport) = service();
    let request = anchor_request();
    assert!(norito::encode_canonical(&request.anchor).unwrap().len() > 4096);
    let temporary = tempfile::tempdir().unwrap();
    let original_path = temporary.path().join("original");
    service
        .prepare_private_root_anchor(&request, &original_path)
        .unwrap();
    service
        .verify_private_root_anchor_journal(&original_path, &request)
        .unwrap();
    let held = Journal::open(&original_path).unwrap();
    let record: TransactionJournal = held.read_operation().unwrap();
    let wire = record
        .verify(&service.config)
        .unwrap()
        .encode_wire_v1()
        .unwrap();
    let original: Request = held.read_native(NativeRecord::Request).unwrap().unwrap();
    let payload: Payload = held.read_native(NativeRecord::Payload).unwrap().unwrap();
    let payload_bytes = std::fs::read(original_path.join("payload.json")).unwrap();
    drop(held);
    let quotes = transport.quote_count.load(Ordering::SeqCst);
    let calls = transport.requests.load(Ordering::SeqCst);

    // Retain the real immutable request/payload prefix at the pre-signature crash boundary.
    // No signature, node result, certificate or byte frame is fabricated by this fixture.
    let prefix_path = temporary.path().join("payload-prefix");
    let prefix = Journal::create_preparation(&prefix_path, &original).unwrap();
    prefix
        .write_native(NativeRecord::Payload, &payload)
        .unwrap();
    let phase = norito::with_decode_limits_scope(LIMITS, || {
        Retained::read(&prefix, &service.config)
            .unwrap()
            .into_inspection()
            .unwrap()
    });
    assert_eq!(phase.phase(), NativePreparationPhase::PayloadRetained);
    assert!(phase.signed_transaction().is_none());
    assert!(!prefix_path.join("operation.json").exists());
    drop(prefix);
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);

    assert_eq!(
        service
            .prepare_private_root_anchor(&request, &prefix_path)
            .unwrap()
            .status,
        OperationStatus::Prepared
    );
    service
        .verify_private_root_anchor_journal(&prefix_path, &request)
        .unwrap();
    let recovered = Journal::open(&prefix_path).unwrap();
    let record: TransactionJournal = recovered.read_operation().unwrap();
    assert_eq!(
        record
            .verify(&service.config)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    assert_eq!(
        std::fs::read(prefix_path.join("payload.json")).unwrap(),
        payload_bytes
    );
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), quotes);
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
}

#[test]
fn byte_frame_decoder_keeps_wire_bounds_and_inherited_allocation_limits() {
    let bytes = vec![0x39_u8; 8192];
    let frame = bounded::encode_bounded(&bytes, 16 * 1024).unwrap();
    assert_eq!(
        bounded::decode_bounded::<Vec<u8>>(&frame, 16 * 1024).unwrap(),
        bytes
    );
    assert!(bounded::decode_bounded::<Vec<u8>>(&frame, frame.len() - 1).is_err());
    let failure = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(16 * 1024, 16 * 1024, 16 * 1024, 0, 64),
        || bounded::decode_bounded::<Vec<u8>>(&frame, 16 * 1024),
    )
    .unwrap_err();
    assert!(failure.chain().any(|error| matches!(
        error.downcast_ref::<norito::Error>(),
        Some(norito::Error::TotalAllocationExceeded { .. })
    )));
}

#[test]
fn anchor_byte_frames_keep_typed_fee_and_committee_bounds_before_http() {
    let (service, transport) = service();
    let request = anchor_request();
    let temporary = tempfile::tempdir().unwrap();
    let mut overfees = request.clone();
    overfees.options.max_total_fees.clear();
    for value in 1..=17_u8 {
        let mut bytes = [value; 16];
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        overfees.options.max_total_fees.insert(
            AssetDefinitionId::from_uuid_bytes(bytes).unwrap(),
            Quantity::from(1_u32),
        );
    }
    assert!(
        service
            .prepare_private_root_anchor(&overfees, &temporary.path().join("overfees"))
            .is_err()
    );
    let mut oversized = request;
    oversized.anchor.certificate.consensus_header =
        vec![0; iroha_data_model::sumeragi_amx::MAX_AMX_HEADER_BYTES + 1];
    assert!(
        service
            .prepare_private_root_anchor(&oversized, &temporary.path().join("oversized"))
            .is_err()
    );
    let (_, mut registration) = private_root_fixture();
    registration.initial_epoch.committee.pop();
    let malformed = PrivateRootRegistrationRequest {
        alias: "walletroot".into(),
        expected_ownership_generation: 1,
        registration,
        options: private_options(),
    };
    assert!(
        service
            .prepare_private_root_registration(&malformed, &temporary.path().join("committee"))
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 0);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
}

#[test]
fn bounded_operation_encoder_charges_one_exact_frame_without_renewal() {
    let value = vec![0x39_u8; 64];
    let expected = norito::encode_canonical(&value).unwrap();
    let length = expected.len();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, length, 64);
    norito::with_decode_limits_scope(limits, || {
        assert!(bounded::encode_bounded(&value, length - 1).is_err());
        assert_eq!(bounded::encode_bounded(&value, length).unwrap(), expected);
        let error = bounded::encode_bounded(&value, length).unwrap_err();
        assert!(matches!(error.downcast_ref::<norito::Error>(),
            Some(norito::Error::TotalAllocationExceeded { attempted, limit })
                if *attempted == (length * 2) as u64 && *limit == length as u64));
    });
}

#[test]
fn concrete_payload_encoder_charges_one_retained_frame_without_renewal() {
    let (service, _) = service();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("payload-codec");
    service
        .prepare_transfer(&super::super::tests::request(), &path)
        .unwrap();
    let journal = Journal::open(&path).unwrap();
    let record: TransactionJournal = journal.read_operation().unwrap();
    let signed = record.verify(&service.config).unwrap();
    let payload = signed.payload();
    let expected = norito::encode_canonical(payload).unwrap();
    let length = expected.len();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, length, 64);
    norito::with_decode_limits_scope(limits, || {
        assert_eq!(encode_payload(payload).unwrap(), expected);
        let error = encode_payload(payload).unwrap_err();
        assert!(matches!(error.downcast_ref::<norito::Error>(),
            Some(norito::Error::TotalAllocationExceeded { attempted, limit })
                if *attempted == (length * 2) as u64 && *limit == length as u64));
    });
}
