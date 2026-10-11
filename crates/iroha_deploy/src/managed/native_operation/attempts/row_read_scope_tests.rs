//! Genuine attempt rows keep native censuses and canonical reads in one closed suffix scope.

use super::*;
use crate::managed::Error;
use iroha_fs::FileIdentity;

#[test]
fn closed_row_scope_keeps_before_after_native_inventory_and_original_retry() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let history = fixture.history().unwrap();
    let root = history.root.as_ref().unwrap();
    let row_identity = attempt.directory.identity().unwrap();
    let authorization_path = attempt.directory.path().join("authorization.nrt");
    let authorization_identity =
        FileIdentity::of(&std::fs::File::open(&authorization_path).unwrap()).unwrap();
    let original = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let original_names = attempt.directory.entries(7).unwrap();
    let reopened = PrivateDirectory::open(attempt.directory.path()).unwrap();
    for directory in [&attempt.directory, &reopened] {
        let counter = parse_digest_tests::Counter::begin();
        let observed = root
            .read_tree_scope(|tree| {
                tree.read_scope(directory, |reader| {
                    let before = checked_attempt_inventory(reader.entries(7)?)?;
                    let authorization: Option<Authorization> =
                        read_record_in_scope(reader, "authorization.nrt")?;
                    assert!(authorization.as_ref() == Some(&attempt.authorization));
                    assert_eq!(checked_attempt_inventory(reader.entries(7)?)?, before);
                    Ok::<_, Error>(authorization)
                })
            })
            .unwrap();
        let counts = counter.finish();
        assert!(observed.as_ref() == Some(&attempt.authorization));
        assert_eq!(counts.reads, 1);
        assert_eq!(counts.decoded, 1);
    }
    let counter = parse_digest_tests::Counter::begin();
    let bounded: Result<Option<Authorization>> = root.read_tree_scope(|tree| {
        tree.read_scope(&attempt.directory, |reader| {
            reader.entries(0)?;
            read_record_in_scope(reader, "authorization.nrt")
        })
    });
    let counts = counter.finish();
    assert!(
        matches!(bounded, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput)
    );
    assert_eq!(counts.reads, 0);
    assert_eq!(counts.decoded, 0);

    attempt
        .directory
        .write_atomic("foreign.nrt", b"foreign", PublishMode::CreateNew)
        .unwrap();
    let counter = parse_digest_tests::Counter::begin();
    let unknown: Result<Option<Authorization>> = root.read_tree_scope(|tree| {
        tree.read_scope(&attempt.directory, |reader| {
            checked_attempt_inventory(reader.entries(7)?)?;
            read_record_in_scope(reader, "authorization.nrt")
        })
    });
    let counts = counter.finish();
    assert!(
        matches!(unknown, Err(Error::Invalid(message)) if message == "dispatch attempt contains unknown material")
    );
    assert_eq!(counts.reads, 0);
    assert_eq!(counts.decoded, 0);
    std::fs::remove_file(attempt.directory.path().join("foreign.nrt")).unwrap();

    let counter = parse_digest_tests::Counter::begin();
    let changed: Result<Option<Authorization>> = root.read_tree_scope(|tree| {
        tree.read_scope(&attempt.directory, |reader| {
            let before = checked_attempt_inventory(reader.entries(7)?)?;
            let authorization = read_record_in_scope(reader, "authorization.nrt")?;
            // This is a real permitted native name, so fresh equality is needed after reading.
            attempt
                .directory
                .write_atomic("replay.nrt", b"changed census", PublishMode::CreateNew)
                .unwrap();
            if checked_attempt_inventory(reader.entries(7)?)? != before {
                return Err(invalid(
                    "retained dispatch metadata changed during native operation",
                ));
            }
            Ok(authorization)
        })
    });
    let counts = counter.finish();
    assert!(
        matches!(changed, Err(Error::Invalid(message)) if message == "retained dispatch metadata changed during native operation")
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    std::fs::remove_file(attempt.directory.path().join("replay.nrt")).unwrap();
    history.require_current_local(None).unwrap();
    assert_eq!(fixture.history().unwrap().reserved_attempt_count(), 1);
    assert_eq!(attempt.directory.identity().unwrap(), row_identity);
    assert_eq!(
        FileIdentity::of(&std::fs::File::open(&authorization_path).unwrap()).unwrap(),
        authorization_identity
    );
    assert_eq!(attempt.directory.entries(7).unwrap(), original_names);
    assert_eq!(
        attempt
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    assert!(!attempt.wallet_path().exists());
}

#[cfg(unix)]
#[test]
fn closed_row_scope_custody_overrides_real_optional_and_decode_results_and_restores_originals() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let history = fixture.history().unwrap();
    let root = history.root.as_ref().unwrap();
    let row_path = attempt.directory.path().to_owned();
    let original_identity = attempt.directory.identity().unwrap();
    let authorization_path = row_path.join("authorization.nrt");
    let authorization_identity =
        FileIdentity::of(&fs::File::open(&authorization_path).unwrap()).unwrap();
    let original = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let original_names = attempt.directory.entries(7).unwrap();
    let held_authorization = fixture._temporary.path().join("held-authorization.nrt");
    let held_row = fixture._temporary.path().join("held-row");
    for boundary in ["row", "anchor"] {
        for kind in ["present", "absence", "decoder_error", "native_not_found"] {
            if kind == "decoder_error" {
                fs::rename(&authorization_path, &held_authorization).unwrap();
                attempt
                    .directory
                    .write_atomic(
                        "authorization.nrt",
                        b"not canonical",
                        PublishMode::CreateNew,
                    )
                    .unwrap();
            }
            let counter = parse_digest_tests::Counter::begin();
            let refused: Result<Option<Authorization>> = root.read_tree_scope(|tree| {
                tree.read_scope(&attempt.directory, |reader| {
                    checked_attempt_inventory(reader.entries(7)?)?;
                    let result = if kind == "native_not_found" {
                        reader.read("missing.nrt", MAX_RECORD_BYTES, decode_record::<Authorization>)
                            .map_err(Error::from).and_then(|value| value.map(Some))
                    } else {
                        read_record_in_scope::<Authorization>(reader, if kind == "absence" { "missing.nrt" } else { "authorization.nrt" })
                    };
                    match kind {
                        "present" => assert!(result.as_ref().unwrap().as_ref() == Some(&attempt.authorization)),
                        "absence" => assert!(result.as_ref().unwrap().is_none()),
                        "decoder_error" => assert!(matches!(&result, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record")),
                        _ => assert!(matches!(&result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)),
                    }
                    if boundary == "row" {
                        fs::rename(&row_path, &held_row).unwrap();
                        fs::create_dir(&row_path).unwrap();
                        fs::set_permissions(&row_path, fs::Permissions::from_mode(0o700)).unwrap();
                    } else {
                        fs::set_permissions(fixture.operation.path(), fs::Permissions::from_mode(0o755)).unwrap();
                    }
                    result
                })
            });
            let counts = counter.finish();
            let expected = if boundary == "row" {
                std::io::ErrorKind::Other
            } else {
                std::io::ErrorKind::PermissionDenied
            };
            assert!(
                matches!(&refused, Err(Error::Io(error)) if error.kind() == expected),
                "{:?}",
                refused.as_ref().err()
            );
            assert_eq!(counts.reads, usize::from(kind != "native_not_found"));
            assert_eq!(counts.decoded, usize::from(kind == "present"));
            if boundary == "row" {
                fs::remove_dir(&row_path).unwrap();
                fs::rename(&held_row, &row_path).unwrap();
            } else {
                fs::set_permissions(fixture.operation.path(), fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            if kind == "decoder_error" {
                fs::remove_file(&authorization_path).unwrap();
                fs::rename(&held_authorization, &authorization_path).unwrap();
            }
            history.require_current_local(None).unwrap();
            assert_eq!(fixture.history().unwrap().reserved_attempt_count(), 1);
            assert_eq!(attempt.directory.identity().unwrap(), original_identity);
            assert_eq!(
                FileIdentity::of(&fs::File::open(&authorization_path).unwrap()).unwrap(),
                authorization_identity
            );
            assert_eq!(attempt.directory.entries(7).unwrap(), original_names);
            assert_eq!(
                attempt
                    .directory
                    .read("authorization.nrt", MAX_RECORD_BYTES)
                    .unwrap(),
                original
            );
            assert!(!attempt.wallet_path().exists());
        }
    }
}
