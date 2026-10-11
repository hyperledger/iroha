//! Original-selection and bounded-codec controls; these never fabricate completed providers.
use super::*;
use iroha_data_model::musubi::MusubiVerificationLockDigestV1;

fn asset(seed: u8) -> AssetDefinitionId {
    let mut value = [seed; 16];
    value[6] = (value[6] & 15) | 0x40;
    value[8] = (value[8] & 63) | 0x80;
    AssetDefinitionId::from_uuid_bytes(value).unwrap()
}
fn limits() -> NativeMusubiStorageLimitsV1 {
    NativeMusubiStorageLimitsV1 {
        authorization_window_ms: 60_000,
        max_check_rounds: 8,
        fee_asset: asset(0x41),
        per_transaction_fee: Quantity::from(1u32),
        total_fees: Quantity::from(16u32),
    }
}
fn request() -> MusubiStorageCoordinationRequestV1 {
    let fixture = crate::musubi_publication_service::finality::tests::reader_fixture();
    from_source(fixture.query)
}
fn from_source(
    query: MusubiPublicationFinalizedArchiveRegistrationQueryV1,
) -> MusubiStorageCoordinationRequestV1 {
    let registration = query.registration;
    MusubiStorageCoordinationRequestV1 {
        version: 1,
        operation_id: [0xB1; 32],
        generation: 1,
        prior_location_ids: Vec::new(),
        network_id: query.network_id,
        publisher: registration.registered_by.clone(),
        commitment: registration.commitment.clone(),
        verification_lock_digest: MusubiVerificationLockDigestV1::new([0xB2; 32]),
        staging_receipt: registration.staging_receipt.clone(),
        expected_policy_revision: query.expected_policy_revision,
        finalized_registration:
            iroha_musubi_service::MusubiFinalizedArchiveRegistrationEvidenceV1 {
                version: query.version,
                network_id: query.network_id,
                transaction_hash: query.transaction_hash,
                snapshot: query.snapshot,
                registration,
            },
    }
}
#[test]
fn operation_namespace_excludes_request_bytes_but_request_digest_binds_them() {
    let original = request();
    original.validate().unwrap();
    let id = operation_id(&original).unwrap();
    let digest = original.canonical_request_digest().unwrap();
    let mut changed = original.clone();
    changed.verification_lock_digest = MusubiVerificationLockDigestV1::new([0xB3; 32]);
    assert_eq!(operation_id(&changed).unwrap(), id);
    assert_ne!(changed.canonical_request_digest().unwrap(), digest);
    changed = original.clone();
    changed.expected_policy_revision += 1;
    assert_eq!(operation_id(&changed).unwrap(), id);
    assert_ne!(changed.canonical_request_digest().unwrap(), digest);
    changed = original.clone();
    changed.operation_id[0] ^= 1;
    assert_ne!(operation_id(&changed).unwrap(), id);
    changed = original.clone();
    changed.generation = 2;
    changed.prior_location_ids = vec![MusubiArchiveLocationIdV1::new([0xB4; 32])];
    assert_ne!(operation_id(&changed).unwrap(), id);
    assert_ne!(
        location_id(&original, &[1; 32]).unwrap(),
        location_id(&original, &[2; 32]).unwrap()
    );
}
#[test]
fn original_limits_never_renew_and_pin_principal_is_not_a_fee_claim() {
    let configured = limits();
    let original = configured.authorization(10_000, 50_000).unwrap();
    assert_eq!(original.deadline_unix_ms, 50_000);
    assert_eq!(
        configured
            .authorization(10_000, 90_000)
            .unwrap()
            .deadline_unix_ms,
        70_000
    );
    // Reopening validates the selected ceilings only. The retained original deadline is untouched.
    configured.matches(&original).unwrap();
    assert!(original.ensure_live(49_999).is_ok());
    assert!(original.ensure_live(50_000).is_err());
    let mut changed = configured.clone();
    changed.max_check_rounds += 1;
    assert!(changed.matches(&original).is_err());
    changed = configured.clone();
    changed.total_fees = Quantity::from(17u32);
    assert!(changed.matches(&original).is_err());
    changed = configured.clone();
    changed.per_transaction_fee = Quantity::from(2u32);
    assert!(changed.matches(&original).is_err());
    changed = configured.clone();
    changed.fee_asset = asset(0x42);
    assert!(changed.matches(&original).is_err());
    assert!(
        configured
            .authorization(u64::MAX - 100, u64::MAX - 1)
            .is_err()
    );
    assert!(configured.authorization(20, 20).is_err());
    assert!(original.per_transaction.gas_limit().is_none());
    assert!(
        original
            .per_transaction
            .charge_limits()
            .iter()
            .all(|fee| fee.kind == FeeChargeKind::Nexus)
    );
}
#[test]
fn original_namespace_and_source_copy_ignore_ambient_layout_and_obey_cumulative_budget() {
    let original = request();
    let expected = operation_id(&original).unwrap();
    let digest = original.canonical_request_digest().unwrap();
    let source = source_query(&original).unwrap();
    {
        let _flags = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(operation_id(&original).unwrap(), expected);
        assert_eq!(source_query(&original).unwrap(), source);
        assert_eq!(original.canonical_request_digest().unwrap(), digest);
    }
    let zero =
        norito::DecodeLimits::new(16 * 1024 * 1024, 16 * 1024 * 1024, 16 * 1024 * 1024, 0, 64);
    assert!(norito::with_decode_limits_scope(zero, || operation_id(&original)).is_err());
    assert!(norito::with_decode_limits_scope(zero, || bounded_copy(&source.registration)).is_err());
    let length = norito::canonical_frame_len(&source.registration).unwrap();
    let tight = norito::DecodeLimits::new(
        16 * 1024 * 1024,
        16 * 1024 * 1024,
        16 * 1024 * 1024,
        length,
        64,
    );
    assert!(
        norito::with_decode_limits_scope(tight, || bounded_copy(&source.registration)).is_err(),
        "the retained raw frame consumes allowance before typed decode allocations"
    );
}

#[test]
fn cached_archive_preflight_reaches_the_actual_delegate_and_keeps_its_refusal() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Refusing(Arc<AtomicUsize>);
    impl MusubiStorageCoordinationBackendV1 for Refusing {
        fn verify_current_registration(
            &self,
            _: &MusubiStorageCoordinationRequestV1,
        ) -> Result<(), BackendError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(BackendError::Permanent)
        }
        fn coordinate_storage(
            &mut self,
            _: &VerifiedStorageCoordinationRequestV1<'_>,
        ) -> Result<MusubiStorageCoordinationResponseV1, BackendError> {
            panic!("read-only cached check cannot enter effectful coordination")
        }
    }
    let fixture = crate::musubi_publication_service::finality::tests::reader_fixture();
    let request = from_source(fixture.query);
    let called = Arc::new(AtomicUsize::new(0));
    let checked = crate::musubi_publication_service::storage_coordination::FinalizedRegistrationCheckedStorageBackendV1::new(
        fixture.reader, Box::new(Refusing(Arc::clone(&called))));
    assert_eq!(
        checked.verify_current_registration(&request),
        Err(BackendError::Permanent)
    );
    assert_eq!(called.load(Ordering::SeqCst), 1);
    let mut wrong = request;
    wrong.finalized_registration.transaction_hash[0] ^= 1;
    assert_eq!(
        checked.verify_current_registration(&wrong),
        Err(BackendError::Permanent)
    );
    assert_eq!(
        called.load(Ordering::SeqCst),
        1,
        "original archive verification still precedes delegate"
    );
}

#[test]
fn invalid_native_builder_selection_performs_no_custody_io() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("never-initialize");
    let key = KeyPair::from_seed(vec![0xE1; 32], iroha_crypto::Algorithm::Ed25519);
    assert!(
        NativeMusubiStorageBuilderV1::new(missing.clone(), [0; 32], key.clone(), limits()).is_err()
    );
    let mut invalid = limits();
    invalid.max_check_rounds = 17;
    assert!(
        NativeMusubiStorageBuilderV1::new(missing.clone(), [1; 32], key.clone(), invalid).is_err()
    );
    let mut invalid = limits();
    invalid.total_fees = Quantity::from(0u32);
    assert!(NativeMusubiStorageBuilderV1::new(missing.clone(), [1; 32], key, invalid).is_err());
    assert!(!missing.exists());
}

#[test]
fn read_only_call_window_can_outlive_original_effects_without_authorizing_new_work() {
    use std::{cell::Cell, collections::VecDeque, time::Duration};
    struct Clock(VecDeque<u64>);
    impl MusubiPublicationServiceClockV1 for Clock {
        fn current_time_ms(&mut self) -> Result<u64, BackendError> {
            self.0.pop_front().ok_or(BackendError::Retryable)
        }
    }
    let original = limits().authorization(10_000, 50_000).unwrap();
    assert!(original.ensure_live(50_001).is_err());
    // This is a call-window control only; the closure supplies no fabricated native facts.
    let observed = Cell::new(0);
    let deadline = Instant::now() + Duration::from_secs(5);
    let value = read_current_for_call(
        90_000,
        deadline,
        &mut Clock([50_001, 50_002].into()),
        |now| {
            observed.set(now);
            Ok(7)
        },
    )
    .unwrap();
    assert_eq!(value, 7);
    assert_eq!(observed.get(), 50_001);
    assert_eq!(original.deadline_unix_ms, 50_000);
    assert!(
        original
            .check_effect_boundary(&mut Clock([50_002].into()), deadline)
            .is_err()
    );
    for observations in [[90_000, 90_000], [60_000, 90_000], [60_000, 59_999]] {
        assert!(
            read_current_for_call(
                90_000,
                deadline,
                &mut Clock(observations.into()),
                |_| Ok(())
            )
            .is_err()
        );
    }
    assert!(
        read_current_for_call(
            90_000,
            Instant::now(),
            &mut Clock(VecDeque::new()),
            |_| -> eyre::Result<()> { panic!("expired call cannot enter native observation") }
        )
        .is_err()
    );
}

#[test]
fn operation_identity_charges_one_canonical_publisher_frame_without_renewal() {
    let original = request();
    let expected = operation_id(&original).unwrap();
    let length = norito::canonical_frame_len(&original.publisher).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, length, 128);
    norito::with_decode_limits_scope(limits, || {
        assert_eq!(operation_id(&original).unwrap(), expected);
        let error = operation_id(&original).unwrap_err();
        assert!(matches!(error.downcast_ref::<norito::Error>(),
            Some(norito::Error::TotalAllocationExceeded { .. })));
    });
}

#[test]
fn storage_copy_charges_one_frame_and_its_independently_measured_decoded_graph() {
    let source = vec![0x37_u8; 64];
    let frame = norito::encode_canonical(&source).unwrap();
    let budget = 65536;
    let limits = norito::DecodeLimits::new(65536, 65536, 65536, budget, 128);
    let decoded_bytes = norito::with_decode_limits_scope(limits, || {
        assert_eq!(norito::decode_canonical::<Vec<u8>>(&frame).unwrap(), source);
        let norito::Error::TotalAllocationExceeded { attempted, .. } =
            norito::core::reserve_decode_allocation(budget + 1).unwrap_err()
        else { panic!("allocation usage probe must refuse without charging"); };
        attempted as usize - budget - 1
    });
    let exact = frame.len() + decoded_bytes;
    let limits = norito::DecodeLimits::new(65536, 65536, 65536, exact, 128);
    norito::with_decode_limits_scope(limits, || {
        assert_eq!(bounded_copy(&source).unwrap(), source);
        assert!(bounded_copy(&source).is_err(), "copy cannot renew inherited allowance");
    });
}
