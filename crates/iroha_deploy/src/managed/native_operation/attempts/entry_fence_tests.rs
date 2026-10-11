//! Actual local-record and native-edge refusals after adjacent entry-fence consolidation.
//! Every retry uses the same retained owners; no local record supplies native authority.

use super::*;
use crate::managed::Error;

fn require_io<T>(result: Result<T>, kind: std::io::ErrorKind) {
    match result {
        Err(Error::Io(error)) => assert_eq!(error.kind(), kind),
        Err(error) => panic!("expected native I/O refusal, received {error:?}"),
        Ok(_) => panic!("changed native custody was accepted"),
    }
}

#[test]
fn adjacent_entries_recheck_original_records_and_absence_before_genuine_wallet_inspection() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    fixture.commit(&attempt);
    let history = fixture.history().unwrap();
    let original = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let request = std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap();
    let inventory = attempt.directory.entries(7).unwrap();
    let operation_names = fixture.operation.entries(6).unwrap();
    let identity = attempt.directory.identity().unwrap();
    let refused_before_inspection = || {
        let inspected = std::cell::Cell::new(0);
        assert!(
            history
                .verify_wallets(|attempt| {
                    inspected.set(inspected.get() + 1);
                    fixture.inspect(attempt)
                })
                .is_err()
        );
        assert_eq!(inspected.get(), 0);
        assert_eq!(
            std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap(),
            request
        );
        assert!(!attempt.wallet_path().join("payload.json").exists());
        assert!(!attempt.wallet_path().join("operation.json").exists());
    };
    let retry = || {
        attempt.verify_authorization().unwrap();
        history.require_current().unwrap();
        history
            .verify_wallets(|attempt| fixture.inspect(attempt))
            .unwrap();
        fixture
            .history()
            .unwrap()
            .verify_wallets(|attempt| fixture.inspect(attempt))
            .unwrap();
        assert_eq!(attempt.directory.identity().unwrap(), identity);
    };
    retry();

    let mut changed = attempt.authorization.clone();
    changed.terms.requested_deadline_unix_ms += 1;
    attempt
        .directory
        .write_atomic(
            "authorization.nrt",
            &encode(&changed, MAX_RECORD_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(matches!(
        attempt.verify_authorization(),
        Err(Error::Invalid(message))
            if message == "original dispatch authorization was lost or changed"
    ));
    assert!(fixture.history().is_err());
    refused_before_inspection();
    attempt
        .directory
        .write_atomic("authorization.nrt", &original, PublishMode::Replace)
        .unwrap();
    retry();

    attempt
        .directory
        .write_atomic(
            "authorization.nrt",
            b"invalid canonical authorization",
            PublishMode::Replace,
        )
        .unwrap();
    assert!(matches!(
        attempt.verify_authorization(),
        Err(Error::Invalid(_))
    ));
    assert!(fixture.history().is_err());
    refused_before_inspection();
    attempt
        .directory
        .write_atomic("authorization.nrt", &original, PublishMode::Replace)
        .unwrap();
    retry();

    std::fs::remove_file(attempt.directory.path().join("authorization.nrt")).unwrap();
    assert!(matches!(
        attempt.verify_authorization(),
        Err(Error::Invalid(message))
            if message == "original dispatch authorization was lost or changed"
    ));
    assert!(fixture.history().is_err());
    refused_before_inspection();
    attempt
        .directory
        .write_atomic("authorization.nrt", &original, PublishMode::CreateNew)
        .unwrap();
    retry();

    attempt
        .directory
        .write_atomic(
            "authorization.nrt",
            &vec![0; MAX_RECORD_BYTES + 1],
            PublishMode::Replace,
        )
        .unwrap();
    require_io(
        attempt.verify_authorization(),
        std::io::ErrorKind::InvalidInput,
    );
    require_io(fixture.history(), std::io::ErrorKind::InvalidInput);
    refused_before_inspection();
    attempt
        .directory
        .write_atomic("authorization.nrt", &original, PublishMode::Replace)
        .unwrap();
    retry();

    // An earlier canonical absence must be freshly read, even with a genuine retained wallet.
    attempt
        .directory
        .write_atomic(
            "retired.nrt",
            &encode(
                &Retirement {
                    authorization: attempt.digest().unwrap(),
                    successor: [0x91; 32],
                    kind: RetirementKind::Missing,
                },
                MAX_RECORD_BYTES,
            )
            .unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(matches!(history.require_current(), Err(Error::Invalid(_))));
    refused_before_inspection();
    std::fs::remove_file(attempt.directory.path().join("retired.nrt")).unwrap();
    retry();

    attempt
        .directory
        .write_atomic("foreign.nrt", b"not authority", PublishMode::CreateNew)
        .unwrap();
    assert!(matches!(history.require_current(), Err(Error::Invalid(_))));
    assert!(fixture.history().is_err());
    refused_before_inspection();
    std::fs::remove_file(attempt.directory.path().join("foreign.nrt")).unwrap();
    retry();
    assert_eq!(attempt.directory.entries(7).unwrap(), inventory);
    assert_eq!(fixture.operation.entries(6).unwrap(), operation_names);
    assert_eq!(
        attempt
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    assert_eq!(
        std::fs::read(attempt.wallet_path().join("preparation.json")).unwrap(),
        request
    );
}

#[cfg(unix)]
#[test]
fn adjacent_entries_recheck_every_native_directory_edge_and_original_restoration() {
    use std::os::unix::fs::PermissionsExt as _;

    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let history = fixture.history().unwrap();
    let root = history.root.as_ref().unwrap();
    let original = fixture
        .operation
        .read("original.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let dispatch = fixture
        .operation
        .read("dispatch.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let authorization = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let operation_names = fixture.operation.entries(6).unwrap();
    let attempt_names = root.entries(MAX_ATTEMPTS).unwrap();
    let row_names = attempt.directory.entries(7).unwrap();
    let retained_reparse = || {
        History::read_retained(
            &fixture.operation,
            Purpose::ReservePolicy,
            fixture.semantic,
            &HistoryScope::FixedBody,
            &history,
        )
    };
    let retry = || {
        attempt.verify_authorization().unwrap();
        history.require_current().unwrap();
        fixture.history().unwrap();
        retained_reparse().unwrap();
        history
            .verify_wallets(|_| Err(invalid("unobserved original must not inspect a wallet")))
            .unwrap();
        assert!(!attempt.wallet_path().exists());
    };
    retry();
    let directories = [
        (&fixture.operation, "operation", 0),
        (root, "attempt-root", 1),
        (&attempt.directory, "attempt-row", 2),
    ];
    for (directory, _, _) in directories {
        let identity = directory.identity().unwrap();
        let permissions = std::fs::metadata(directory.path()).unwrap().permissions();
        assert_eq!(permissions.mode() & 0o7777, 0o700);
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        require_io(
            attempt.verify_authorization(),
            std::io::ErrorKind::PermissionDenied,
        );
        require_io(
            history.require_current(),
            std::io::ErrorKind::PermissionDenied,
        );
        require_io(fixture.history(), std::io::ErrorKind::PermissionDenied);
        std::fs::set_permissions(directory.path(), permissions).unwrap();
        retry();
        assert_eq!(directory.identity().unwrap(), identity);
    }
    let file_path = attempt.directory.path().join("authorization.nrt");
    let permissions = std::fs::metadata(&file_path).unwrap().permissions();
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    require_io(
        attempt.verify_authorization(),
        std::io::ErrorKind::PermissionDenied,
    );
    require_io(
        history.require_current(),
        std::io::ErrorKind::PermissionDenied,
    );
    require_io(fixture.history(), std::io::ErrorKind::PermissionDenied);
    std::fs::set_permissions(&file_path, permissions).unwrap();
    retry();

    for (directory, label, level) in directories {
        let path = directory.path();
        let identity = directory.identity().unwrap();
        let saved = fixture._temporary.path().join(format!("displaced-{label}"));
        std::fs::rename(path, &saved).unwrap();
        // Missing native directory custody must not become optional record absence.
        require_io(attempt.verify_authorization(), std::io::ErrorKind::NotFound);
        require_io(retained_reparse(), std::io::ErrorKind::NotFound);
        assert!(history.require_current().is_err());
        assert!(!path.exists());
        let replacement = PrivateDirectory::open_or_create(path).unwrap();
        // Supply the same real local bytes so the refusal comes from the original native edge.
        if level == 0 {
            replacement
                .write_atomic("original.nrt", &original, PublishMode::CreateNew)
                .unwrap();
            replacement
                .write_atomic("dispatch.nrt", &dispatch, PublishMode::CreateNew)
                .unwrap();
            replacement
                .create_child("attempts")
                .unwrap()
                .create_child("0001")
                .unwrap()
                .write_atomic("authorization.nrt", &authorization, PublishMode::CreateNew)
                .unwrap();
        } else if level == 1 {
            replacement
                .create_child("0001")
                .unwrap()
                .write_atomic("authorization.nrt", &authorization, PublishMode::CreateNew)
                .unwrap();
        } else {
            replacement
                .write_atomic("authorization.nrt", &authorization, PublishMode::CreateNew)
                .unwrap();
        }
        assert_ne!(replacement.identity().unwrap(), identity);
        require_io(attempt.verify_authorization(), std::io::ErrorKind::Other);
        require_io(history.require_current(), std::io::ErrorKind::Other);
        require_io(retained_reparse(), std::io::ErrorKind::Other);
        if level == 0 {
            require_io(fixture.history(), std::io::ErrorKind::Other);
        } else {
            // A standalone parser has not observed these child identities. The retained
            // reparse above must refuse even though this new exact-byte prefix is valid.
            let fresh = fixture.history().unwrap();
            assert_ne!(
                fresh.attempts[0].directory.identity().unwrap(),
                attempt.directory.identity().unwrap()
            );
        }
        assert!(
            !path
                .join(if level == 0 {
                    "attempts/0001/transaction"
                } else if level == 1 {
                    "0001/transaction"
                } else {
                    "transaction"
                })
                .exists()
        );
        assert!(saved.is_dir());
        drop(replacement);
        std::fs::remove_dir_all(path).unwrap();
        std::fs::rename(&saved, path).unwrap();
        retry();
        assert_eq!(directory.identity().unwrap(), identity);
        assert!(!saved.exists());
    }
    assert_eq!(fixture.operation.entries(6).unwrap(), operation_names);
    assert_eq!(root.entries(MAX_ATTEMPTS).unwrap(), attempt_names);
    assert_eq!(attempt.directory.entries(7).unwrap(), row_names);
    assert_eq!(
        attempt
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        authorization
    );
    assert_eq!(
        fixture
            .operation
            .read("original.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    assert_eq!(
        fixture
            .operation
            .read("dispatch.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        dispatch
    );
}
