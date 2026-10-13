//! Genuine dispatch records retain lazy refusal order, codec accounting and source retry.

use super::*;
use crate::managed::Error;

fn observed(fixture: &Fixture) -> (Result<History>, parse_digest_tests::Counts) {
    let counter = parse_digest_tests::Counter::begin();
    let result = fixture.history();
    (result, counter.finish())
}

#[test]
fn scoped_parser_preserves_metadata_and_row_validation_before_later_record_reads() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let (history, counts) = observed(&fixture);
    let history = history.unwrap();
    assert_eq!(counts.reads, 2);
    assert_eq!(counts.decoded, 2);
    assert_eq!(history.reserved_attempt_count(), 1);
    let dispatch = fixture
        .operation
        .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
        .unwrap();
    let authorization = metadata::test_read_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "authorization.nrt",
    )
    .unwrap()
    .unwrap();
    assert!(!attempt.wallet_path().join("preparation.json").exists());

    let mut changed = history.dispatch.clone().unwrap();
    changed.semantic = [0x92; 32];
    metadata::test_replace_component(
        &fixture.operation,
        None,
        "dispatch.nrt",
        Some(&encode(&changed, MAX_RECORD_BYTES).unwrap()),
    )
    .unwrap();
    fixture
        .operation
        .write_atomic("closing.nrt", b"not canonical", PublishMode::CreateNew)
        .unwrap();
    // Fixed reserve-policy dispatches reject enrollment closure files before decoding.
    let (refused, counts) = observed(&fixture);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "dispatch operation contains unknown material"),
        "unexpected inventory refusal: {:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 0);
    assert_eq!(counts.decoded, 0);
    std::fs::remove_file(fixture.operation.path().join("closing.nrt")).unwrap();
    let (refused, counts) = observed(&fixture);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "dispatch high-water differs from its original scope"),
        "unexpected high-water refusal: {:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    assert_eq!(
        history
            .require_metadata_in_tree(None)
            .err()
            .unwrap()
            .to_string(),
        "dispatch inventory changed during native operation"
    );
    fixture
        .operation
        .write_atomic(metadata::FILE, &dispatch, PublishMode::Replace)
        .unwrap();

    let mut changed = attempt.authorization.clone();
    changed.semantic = [0x93; 32];
    metadata::test_replace_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "authorization.nrt",
        Some(&encode(&changed, MAX_RECORD_BYTES).unwrap()),
    )
    .unwrap();
    metadata::test_replace_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "observation.nrt",
        Some(b"not canonical"),
    )
    .unwrap();
    let (refused, counts) = observed(&fixture);
    assert!(
        matches!(refused, Err(Error::Invalid(message)) if message == "dispatch authorization changed its original purpose, intent or predecessor")
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 2);
    metadata::test_replace_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "authorization.nrt",
        Some(&authorization),
    )
    .unwrap();
    let (refused, counts) = observed(&fixture);
    assert!(
        matches!(refused, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record")
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 2);
    metadata::test_replace_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "observation.nrt",
        None,
    )
    .unwrap();
    let (retried, counts) = observed(&fixture);
    assert_eq!(retried.unwrap().reserved_attempt_count(), 1);
    assert_eq!(counts.reads, 2);
    assert_eq!(counts.decoded, 2);
    history.require_current_local(None).unwrap();
    assert!(!attempt.wallet_path().join("preparation.json").exists());
    assert!(!attempt.wallet_path().join("payload.json").exists());
    assert!(!attempt.wallet_path().join("operation.json").exists());
}

#[test]
fn scoped_record_decode_keeps_active_allocation_refusal_and_exact_original_retry() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let original = metadata::test_read_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "authorization.nrt",
    )
    .unwrap()
    .unwrap();
    let zero =
        norito::DecodeLimits::new(MAX_RECORD_BYTES, MAX_RECORD_BYTES, MAX_RECORD_BYTES, 0, 32);
    let counter = parse_digest_tests::Counter::begin();
    let refused = norito::core::with_decode_limits_scope(zero, || {
        attempt.directory.read_scope(|_reader| {
            metadata::load(&fixture.operation)
                .and_then(|image| image.read::<Authorization>(Some(attempt.ordinal()), 0))
        })
    });
    let counts = counter.finish();
    assert!(
        matches!(refused, Err(Error::Invalid(message)) if message == "invalid canonical operation metadata image")
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 0);
    let wide = norito::DecodeLimits::new(
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        64 * 1024 * 1024,
        32,
    );
    let counter = parse_digest_tests::Counter::begin();
    let (indexed, envelope_usage) = norito::core::with_decode_limits_measured(wide, || {
        attempt
            .directory
            .read_scope(|_reader| metadata::load(&fixture.operation).map(|_| ()))
    });
    indexed.unwrap();
    let counts = counter.finish();
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 0);
    let envelope = envelope_usage.total_allocated_bytes();
    assert!(envelope > 0);
    let child_limited = norito::DecodeLimits::new(
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        envelope,
        32,
    );
    let counter = parse_digest_tests::Counter::begin();
    let (refused, usage) = norito::core::with_decode_limits_measured(child_limited, || {
        attempt.directory.read_scope(|_reader| {
            metadata::load(&fixture.operation)
                .and_then(|image| image.read::<Authorization>(Some(attempt.ordinal()), 0))
        })
    });
    let counts = counter.finish();
    assert!(
        matches!(refused, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record")
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 0);
    assert_eq!(usage.total_allocated_bytes(), envelope);
    let counter = parse_digest_tests::Counter::begin();
    let retried = norito::core::with_decode_limits_scope(wide, || {
        attempt.directory.read_scope(|_reader| {
            metadata::load(&fixture.operation)
                .and_then(|image| image.read::<Authorization>(Some(attempt.ordinal()), 0))
        })
    })
    .unwrap();
    let counts = counter.finish();
    assert!(retried.as_ref() == Some(&attempt.authorization));
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    assert_eq!(
        metadata::test_read_component(
            &fixture.operation,
            Some(attempt.ordinal()),
            "authorization.nrt"
        )
        .unwrap()
        .unwrap(),
        original
    );
    history_retry(&fixture, &attempt);
}

fn history_retry(fixture: &Fixture, attempt: &Attempt) {
    let history = fixture.history().unwrap();
    history.require_current_local(None).unwrap();
    attempt.verify_authorization().unwrap();
    assert_eq!(history.reserved_attempt_count(), 1);
    assert!(!attempt.wallet_path().join("payload.json").exists());
}

#[cfg(unix)]
#[test]
fn scoped_record_absence_and_typed_decoder_error_do_not_escape_changed_native_custody() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let original = metadata::test_read_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "authorization.nrt",
    )
    .unwrap()
    .unwrap();
    for body in ["absence", "decoder_error"] {
        if body == "decoder_error" {
            metadata::test_replace_component(
                &fixture.operation,
                Some(attempt.ordinal()),
                "authorization.nrt",
                Some(b"not canonical"),
            )
            .unwrap();
        }
        let path = attempt.directory.path().to_owned();
        let displaced = path.with_extension("displaced");
        let refused = attempt.directory.read_scope(|_reader| {
            let result = metadata::load(&fixture.operation).and_then(|image| image.read::<Authorization>(Some(attempt.ordinal()), usize::from(body == "absence")));
            if body == "absence" {
                assert!(result.as_ref().unwrap().is_none());
            } else {
                assert!(matches!(&result, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record"));
            }
            fs::rename(&path, &displaced).unwrap();
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            result
        });
        assert!(
            matches!(refused, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::Other)
        );
        fs::remove_dir(&path).unwrap();
        fs::rename(&displaced, &path).unwrap();
        if body == "decoder_error" {
            metadata::test_replace_component(
                &fixture.operation,
                Some(attempt.ordinal()),
                "authorization.nrt",
                Some(&original),
            )
            .unwrap();
        }
        history_retry(&fixture, &attempt);
    }
}

#[test]
fn first_dispatch_semantic_refusal_precedes_oversized_later_logical_frame() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let history = fixture.history().unwrap();
    let original = fixture
        .operation
        .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
        .unwrap();
    let oversized = metadata::test_changed_image(
        &original,
        Some(attempt.ordinal()),
        "observation.nrt",
        Some(&vec![0x71; MAX_RECORD_BYTES + 1]),
    )
    .unwrap();
    let mut dispatch = history.dispatch.clone().unwrap();
    dispatch.semantic = [0x92; 32];
    let wrong_first = metadata::test_changed_image(
        &oversized,
        None,
        "dispatch.nrt",
        Some(&encode(&dispatch, MAX_RECORD_BYTES).unwrap()),
    )
    .unwrap();
    fixture
        .operation
        .write_atomic(metadata::FILE, &wrong_first, PublishMode::Replace)
        .unwrap();
    let (refused, counts) = observed(&fixture);
    assert!(matches!(refused, Err(Error::Invalid(message))
        if message == "dispatch high-water differs from its original scope"));
    assert_eq!((counts.reads, counts.decoded), (1, 1));
    fixture
        .operation
        .write_atomic(metadata::FILE, &oversized, PublishMode::Replace)
        .unwrap();
    let (refused, counts) = observed(&fixture);
    assert!(matches!(refused, Err(Error::Invalid(message))
        if message == "dispatch custody record exceeds its bound"));
    assert_eq!((counts.reads, counts.decoded), (1, 2));
    fixture
        .operation
        .write_atomic(metadata::FILE, &original, PublishMode::Replace)
        .unwrap();
    history_retry(&fixture, &attempt);
    assert_eq!(
        fixture
            .operation
            .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
            .unwrap(),
        original
    );
    assert!(!attempt.wallet_path().exists());
}
