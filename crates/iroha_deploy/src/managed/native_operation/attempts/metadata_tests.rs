//! Bounded canonical envelope controls; synthetic child bytes never establish native authority.

use super::*;

#[test]
fn canonical_image_bounds_rows_before_storage_and_defers_later_child_decoding() {
    let mut value = wire(Phase::Published, [0x51; 32], None, Vec::new());
    value.dispatch = b"invalid first dispatch".to_vec();
    value.rows = (0..MAX_ATTEMPTS)
        .map(|_| Row {
            authorization: vec![0x61],
            observation: Vec::new(),
            commit: Vec::new(),
            retirement: Vec::new(),
        })
        .collect();
    let encoded = encode_image(&value, MAX_IMAGE_BYTES).unwrap();
    let image = Image::decode(encoded, 0).unwrap();
    assert_eq!(image.row_count(), MAX_ATTEMPTS);
    assert_eq!(
        image.read::<Dispatch>(None, 0).err().unwrap().to_string(),
        "invalid canonical dispatch custody record"
    );

    value.rows.push(Row {
        authorization: vec![0x61],
        observation: Vec::new(),
        commit: Vec::new(),
        retirement: Vec::new(),
    });
    let encoded = encode_image(&value, MAX_IMAGE_BYTES).unwrap();
    assert_eq!(
        Image::decode(encoded, 0).err().unwrap().to_string(),
        "invalid canonical operation metadata image"
    );
    value.rows.pop().unwrap();

    // The whole envelope is canonical. Its later logical frame is too large, but cannot
    // mask the first dispatch's decoder failure before that later read is reached.
    value.rows.last_mut().unwrap().retirement = vec![0x71; MAX_RECORD_BYTES + 1];
    let encoded = encode_image(&value, MAX_IMAGE_BYTES).unwrap();
    let image = Image::decode(encoded, 0).unwrap();
    assert_eq!(
        image.read::<Dispatch>(None, 0).err().unwrap().to_string(),
        "invalid canonical dispatch custody record"
    );
    assert_eq!(
        image
            .read::<Retirement>(Some(MAX_ATTEMPTS as u8), 3)
            .err()
            .unwrap()
            .to_string(),
        "dispatch custody record exceeds its bound"
    );
}

#[test]
fn pending_original_uses_its_purpose_bound_and_never_the_published_metadata_bound() {
    // Match the largest concrete capacity Original envelope. These bytes test codec limits,
    // not a native checkpoint: the concrete publisher must still authenticate the content.
    let maximum = super::super::super::MAX_CHECKPOINT_BYTES + 3 * 1024 * 1024;
    let original = vec![0x42; maximum];
    let mut value = wire(
        Phase::PublishingOriginal,
        Hash::new(&original).into(),
        None,
        original,
    );
    let encoded = encode_image(&value, maximum + 1024).unwrap();
    assert!(encoded.len() > MAX_IMAGE_BYTES);
    assert!(
        Image::decode(encoded.clone(), 0).is_err(),
        "ordinary published-image reader has the smaller bound"
    );
    let image = Image::decode(encoded, maximum).unwrap();
    assert_eq!(bytes(&image.bytes, image.index.pending).len(), maximum);
    assert_eq!(image.row_count(), 0);
    value.pending_original.push(0x42);
    value.original = Hash::new(&value.pending_original).into();
    let oversized = encode_image(&value, maximum + 1024).unwrap();
    assert!(
        Image::decode(oversized, maximum).is_err(),
        "one-byte-over pending Original must refuse"
    );
    value.pending_original.pop().unwrap();
    value.original = Hash::new(&value.pending_original).into();
    value.phase = Phase::Pristine;
    let disguised = encode_image(&value, maximum + 1024).unwrap();
    assert!(
        Image::decode(disguised, maximum).is_err(),
        "published phase cannot carry an unpublished Original payload"
    );
}

#[test]
fn aggregate_frame_admission_preserves_narrow_inherited_field_and_allocation_refusals() {
    // Canonical codec-only frames: no Authorization or native-proof parser consumes these values.
    let child = vec![0x41_u8; MAX_RECORD_BYTES / 32];
    let mut value = wire(Phase::Published, [0x52; 32], None, Vec::new());
    value.dispatch = encode(&child, MAX_RECORD_BYTES).unwrap();
    value.rows = (0..MAX_ATTEMPTS)
        .map(|_| Row {
            authorization: encode(&child, MAX_RECORD_BYTES).unwrap(),
            observation: Vec::new(),
            commit: Vec::new(),
            retirement: Vec::new(),
        })
        .collect();
    let encoded = encode_image(&value, MAX_IMAGE_BYTES).unwrap();
    assert!(encoded.len() > MAX_RECORD_BYTES);
    assert!(encoded.len() < MAX_IMAGE_BYTES);
    let limits = |field, allocation| {
        norito::DecodeLimits::new(MAX_IMAGE_BYTES, field, MAX_IMAGE_BYTES, allocation, 32)
    };
    let run = |field, allocation| {
        let child_entered = std::cell::Cell::new(false);
        let (result, usage) =
            norito::core::with_decode_limits_measured(limits(field, allocation), || {
                let image = Image::decode(encoded.clone(), 0)?;
                assert_eq!(image.row_count(), MAX_ATTEMPTS);
                child_entered.set(true);
                image.read::<Vec<u8>>(Some(MAX_ATTEMPTS as u8), 0)
            });
        (result, usage, child_entered.get())
    };
    let ample_allocation = 2 * MAX_IMAGE_BYTES;
    let (indexed, envelope_usage) = norito::core::with_decode_limits_measured(
        limits(MAX_IMAGE_BYTES, ample_allocation),
        || Image::decode(encoded.clone(), 0).map(|image| image.row_count()),
    );
    assert_eq!(indexed.unwrap(), MAX_ATTEMPTS);
    let envelope = envelope_usage.total_allocated_bytes();
    assert!(envelope > 1 && envelope < ample_allocation);
    let (accepted, used, child_entered) = run(MAX_IMAGE_BYTES, ample_allocation);
    assert!(child_entered);
    assert_eq!(accepted.unwrap(), Some(child.clone()));
    let exact = used.total_allocated_bytes();
    assert!(exact > envelope && exact <= ample_allocation);
    let (refused, _, child_entered) = run(MAX_RECORD_BYTES, ample_allocation);
    assert!(
        !child_entered,
        "inherited field limit refuses before the child decoder"
    );
    assert_eq!(
        refused.err().unwrap().to_string(),
        "invalid canonical operation metadata image"
    );
    for allocation in [0, 1, envelope - 1, envelope, exact - 1] {
        let (refused, usage, child_entered) = run(MAX_IMAGE_BYTES, allocation);
        let envelope_refused = allocation < envelope;
        assert_eq!(child_entered, !envelope_refused);
        assert_eq!(
            refused.err().unwrap().to_string(),
            if envelope_refused {
                "invalid canonical operation metadata image"
            } else {
                "invalid canonical dispatch custody record"
            }
        );
        assert!(usage.total_allocated_bytes() <= allocation);
    }
    let (accepted, used, child_entered) = run(MAX_IMAGE_BYTES, exact);
    assert!(child_entered);
    assert_eq!(accepted.unwrap(), Some(child));
    assert_eq!(used.total_allocated_bytes(), exact);
}

#[test]
fn retained_attempt_rejects_changed_outer_original_before_row_reuse_or_mutation() {
    let _resources = crate::managed::native_test_guard();
    let fixture = super::super::tests::Fixture::new();
    let attempt = fixture.reserve();
    let original = fixture.operation.read(FILE, MAX_IMAGE_BYTES).unwrap();
    let authorization = test_read_attempt_component(&attempt, "authorization.nrt")
        .unwrap()
        .unwrap();
    let mut changed = Image::decode(original.to_vec(), 0).unwrap().owned();
    changed.original[0] ^= 1;
    let changed = encode_image(&changed, MAX_IMAGE_BYTES).unwrap();
    fixture
        .operation
        .write_atomic(FILE, &changed, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        test_read_attempt_component(&attempt, "authorization.nrt")
            .unwrap()
            .unwrap(),
        authorization
    );
    for result in [
        attempt.verify_authorization(),
        attempt.retain_observation(Observation::ordinary()),
    ] {
        assert_eq!(
            result.err().unwrap().to_string(),
            "operation metadata differs from its published Original"
        );
    }
    assert_eq!(
        fixture
            .operation
            .read(FILE, MAX_IMAGE_BYTES)
            .unwrap()
            .as_slice(),
        changed.as_slice()
    );
    assert!(
        test_read_attempt_component(&attempt, "observation.nrt")
            .unwrap()
            .is_none()
    );
    assert!(!attempt.wallet_path().exists());
    fixture
        .operation
        .write_atomic(FILE, &original, PublishMode::Replace)
        .unwrap();
    attempt.verify_authorization().unwrap();
    assert_eq!(
        fixture.operation.read(FILE, MAX_IMAGE_BYTES).unwrap(),
        original
    );

    // Obtain an actual RequestOnly preparation while the binding is intact. A changed
    // image must not publish its commit even though this genuine preparation is retained.
    let preparation = fixture.retain(&attempt);
    assert_eq!(preparation.phase(), NativePreparationPhase::RequestOnly);
    let retained = fixture.operation.read(FILE, MAX_IMAGE_BYTES).unwrap();
    let request = std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap();
    let observation = test_read_attempt_component(&attempt, "observation.nrt")
        .unwrap()
        .unwrap();
    assert!(
        test_read_attempt_component(&attempt, "committed.nrt")
            .unwrap()
            .is_none()
    );
    let mut changed = Image::decode(retained.to_vec(), 0).unwrap().owned();
    changed.original[0] ^= 1;
    let changed = encode_image(&changed, MAX_IMAGE_BYTES).unwrap();
    fixture
        .operation
        .write_atomic(FILE, &changed, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        super::super::commit(&attempt, None, Observation::ordinary(), &preparation)
            .err()
            .unwrap()
            .to_string(),
        "operation metadata differs from its published Original"
    );
    assert_eq!(
        fixture
            .operation
            .read(FILE, MAX_IMAGE_BYTES)
            .unwrap()
            .as_slice(),
        changed.as_slice()
    );
    assert!(
        test_read_attempt_component(&attempt, "committed.nrt")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        test_read_attempt_component(&attempt, "observation.nrt")
            .unwrap()
            .unwrap(),
        observation
    );
    assert_eq!(
        std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap(),
        request
    );
    assert!(!attempt.wallet_path().join("payload.json").exists());

    fixture
        .operation
        .write_atomic(FILE, &retained, PublishMode::Replace)
        .unwrap();
    super::super::commit(&attempt, None, Observation::ordinary(), &preparation).unwrap();
    assert!(
        test_read_attempt_component(&attempt, "committed.nrt")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        test_read_attempt_component(&attempt, "observation.nrt")
            .unwrap()
            .unwrap(),
        observation
    );
    assert_eq!(
        std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap(),
        request
    );
    assert!(!attempt.wallet_path().join("payload.json").exists());
}

#[test]
fn reserved_body_reads_its_native_reservation_bound_instead_of_the_image_bound() {
    // Raw byte custody only: no Reservation decoder or native authorization accepts this fixture.
    let temporary = tempfile::tempdir().unwrap();
    let operation = PrivateDirectory::open_or_create(temporary.path().join("body")).unwrap();
    let mut reservation = vec![0x53; MAX_RESERVATION_BYTES];
    assert!(reservation.len() > MAX_IMAGE_BYTES);
    let image = reserved_body(&reservation).unwrap();
    assert!(image.len() < MAX_IMAGE_BYTES);
    operation
        .write_atomic("reserved.nrt", &reservation, PublishMode::CreateNew)
        .unwrap();
    operation
        .write_atomic(FILE, &image, PublishMode::CreateNew)
        .unwrap();
    require_reserved(&operation).unwrap();

    reservation.push(0x53);
    let oversized_image = reserved_body(&reservation).unwrap();
    operation
        .write_atomic("reserved.nrt", &reservation, PublishMode::Replace)
        .unwrap();
    operation
        .write_atomic(FILE, &oversized_image, PublishMode::Replace)
        .unwrap();
    let error = require_reserved(&operation).unwrap_err();
    assert!(
        matches!(&error, crate::managed::Error::Io(source)
        if source.kind() == std::io::ErrorKind::InvalidInput
            && source.to_string() == "file exceeds the read bound"),
        "{error:?}"
    );
    assert_eq!(
        operation.read(FILE, MAX_IMAGE_BYTES).unwrap().as_slice(),
        oversized_image.as_slice()
    );
    assert_eq!(
        std::fs::metadata(operation.path().join("reserved.nrt"))
            .unwrap()
            .len(),
        (MAX_RESERVATION_BYTES + 1) as u64
    );

    reservation.pop().unwrap();
    operation
        .write_atomic("reserved.nrt", &reservation, PublishMode::Replace)
        .unwrap();
    operation
        .write_atomic(FILE, &image, PublishMode::Replace)
        .unwrap();
    require_reserved(&operation).unwrap();
}
