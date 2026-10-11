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
    assert_eq!(counts.reads, 7);
    assert_eq!(counts.decoded, 2);
    assert_eq!(history.reserved_attempt_count(), 1);
    let dispatch = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let authorization = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    assert!(!attempt.wallet_path().join("preparation.json").exists());

    let mut changed = history.dispatch.clone().unwrap();
    changed.semantic = [0x92; 32];
    fixture
        .operation
        .write_atomic(
            "dispatch.nrt",
            &encode(&changed, MAX_RECORD_BYTES).unwrap(),
            PublishMode::Replace,
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
            .unwrap_err()
            .to_string(),
        "dispatch inventory changed during native operation"
    );
    fixture
        .operation
        .write_atomic("dispatch.nrt", &dispatch, PublishMode::Replace)
        .unwrap();

    let mut changed = attempt.authorization.clone();
    changed.semantic = [0x93; 32];
    attempt
        .directory
        .write_atomic(
            "authorization.nrt",
            &encode(&changed, MAX_RECORD_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    attempt
        .directory
        .write_atomic("observation.nrt", b"not canonical", PublishMode::CreateNew)
        .unwrap();
    let (refused, counts) = observed(&fixture);
    assert!(
        matches!(refused, Err(Error::Invalid(message)) if message == "dispatch authorization changed its original purpose, intent or predecessor")
    );
    assert_eq!(counts.reads, 4);
    assert_eq!(counts.decoded, 2);
    attempt
        .directory
        .write_atomic("authorization.nrt", &authorization, PublishMode::Replace)
        .unwrap();
    let (refused, counts) = observed(&fixture);
    assert!(
        matches!(refused, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record")
    );
    assert_eq!(counts.reads, 5);
    assert_eq!(counts.decoded, 2);
    std::fs::remove_file(attempt.directory.path().join("observation.nrt")).unwrap();
    let (retried, counts) = observed(&fixture);
    assert_eq!(retried.unwrap().reserved_attempt_count(), 1);
    assert_eq!(counts.reads, 7);
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
    let original = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let zero =
        norito::DecodeLimits::new(MAX_RECORD_BYTES, MAX_RECORD_BYTES, MAX_RECORD_BYTES, 0, 32);
    let counter = parse_digest_tests::Counter::begin();
    let refused = norito::core::with_decode_limits_scope(zero, || {
        attempt
            .directory
            .read_scope(|reader| read_record_in_scope::<Authorization>(reader, "authorization.nrt"))
    });
    let counts = counter.finish();
    assert!(
        matches!(refused, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record")
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
    let retried = norito::core::with_decode_limits_scope(wide, || {
        attempt
            .directory
            .read_scope(|reader| read_record_in_scope::<Authorization>(reader, "authorization.nrt"))
    })
    .unwrap();
    let counts = counter.finish();
    assert!(retried.as_ref() == Some(&attempt.authorization));
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    assert_eq!(
        attempt
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
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
    let original = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    for body in ["absence", "decoder_error"] {
        if body == "decoder_error" {
            attempt
                .directory
                .write_atomic("authorization.nrt", b"not canonical", PublishMode::Replace)
                .unwrap();
        }
        let path = attempt.directory.path().to_owned();
        let displaced = path.with_extension("displaced");
        let refused = attempt.directory.read_scope(|reader| {
            let result = read_record_in_scope::<Authorization>(reader, if body == "absence" { "missing.nrt" } else { "authorization.nrt" });
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
            attempt
                .directory
                .write_atomic("authorization.nrt", &original, PublishMode::Replace)
                .unwrap();
        }
        history_retry(&fixture, &attempt);
    }
}
