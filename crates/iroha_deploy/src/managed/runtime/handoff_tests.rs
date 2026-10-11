//! Genuine inherited runtime ownership, pre-session closure and shared startup budget controls.

use super::*;
use iroha_fs::{FileIdentity, FileSnapshot};

const CHILD: &str = "managed::runtime::handoff_tests::inherited_worker_child";

fn budget(deadline: Option<u128>) -> activation::Budget {
    activation::Budget {
        started: Instant::now(),
        timeout: Duration::from_secs(30),
        startup_deadline_ns: deadline,
        utc_ceiling_unix_ms: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(progress::Progress::default()),
    }
}

fn wait_record(directory: &PrivateDirectory, name: &str) {
    let end = Instant::now() + Duration::from_secs(20);
    while directory.read_optional(name, 1).unwrap().is_none() {
        assert!(Instant::now() < end, "child handshake did not arrive");
        thread::sleep(Duration::from_millis(2));
    }
}

fn child_command(directory: &PrivateDirectory, owner: &File, mode: &str) -> Command {
    let log = directory.open_append("handoff-child.log").unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg(CHILD)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env("IROHA_TEST_HANDOFF_DIRECTORY", directory.path())
        .env("IROHA_TEST_HANDOFF_MODE", mode)
        .stdin(Stdio::from(owner.try_clone().unwrap()))
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    command
}

#[test]
fn inherited_worker_child() {
    let Some(path) = std::env::var_os("IROHA_TEST_HANDOFF_DIRECTORY") else {
        return;
    };
    let directory = PrivateDirectory::open_exact(std::path::Path::new(&path)).unwrap();
    directory
        .write_atomic("loaded", b"1", PublishMode::CreateNew)
        .unwrap();
    wait_record(&directory, "go");
    let mode = std::env::var("IROHA_TEST_HANDOFF_MODE").unwrap();
    if mode == "expired" || mode == "program-fail" {
        let root = std::env::var_os("IROHA_TEST_HANDOFF_STORE").unwrap();
        let store = ManagedStore::open(std::path::Path::new(&root)).unwrap();
        let deadline: u128 = std::env::var("IROHA_TEST_HANDOFF_DEADLINE")
            .unwrap()
            .parse()
            .unwrap();
        let result = run_worker(&store, "local", Duration::from_secs(30), deadline);
        if mode == "program-fail" {
            assert!(
                matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
            );
        } else {
            assert!(result.is_err());
        }
        let status: ManagedStatus = decode(&directory.read(STATUS, MAX_METADATA).unwrap()).unwrap();
        assert_eq!(status.phase, ManagedPhase::Failed);
        assert_eq!(status.running_peers, 0);
        assert!(
            status
                .failure
                .unwrap()
                .contains("verifying the installed runtime")
        );
        assert!(
            directory
                .read_optional(WORKER, MAX_METADATA)
                .unwrap()
                .is_none()
        );
        for slot in 0..4 {
            assert!(!directory.path().join(format!("peer{slot}.launch")).exists());
        }
    } else {
        let _owner =
            adopt_worker_ownership(&directory, inherited_worker_file().unwrap(), "handoff")
                .unwrap();
        directory
            .write_atomic("admitted", b"1", PublishMode::CreateNew)
            .unwrap();
        wait_record(&directory, "finish");
    }
}

#[test]
fn inherited_runtime_owner_fences_delayed_admission_and_retires_only_the_old_session() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
    let operation = store::acquire(&directory, "operation.lock", "handoff").unwrap();
    let owner = store::acquire(&directory, "runtime.lock", "handoff").unwrap();
    let original = FileIdentity::of(&owner).unwrap();
    directory
        .write_atomic(
            WORKER,
            &encode(&WorkerRecord {
                token: "a".repeat(64),
            })
            .unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    directory
        .write_atomic("retained", b"original bytes", PublishMode::CreateNew)
        .unwrap();
    store::clear_worker_session(&directory).unwrap();
    assert!(
        directory
            .read_optional(WORKER, MAX_METADATA)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        directory.read("retained", 64).unwrap().as_slice(),
        b"original bytes"
    );
    assert_eq!(FileIdentity::of(&owner).unwrap(), original);
    let mut child = child_command(&directory, &owner, "adopt").spawn().unwrap();
    drop(owner);
    // Observe a real loaded child which deliberately has not adopted its stdin yet. The
    // inherited object, rather than a child PID guess or a session record, fences this window.
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_record(&directory, "loaded");
        assert!(matches!(
            store::acquire(&directory, "runtime.lock", "handoff"),
            Err(Error::Busy(_))
        ));
        assert!(
            directory
                .read_optional(WORKER, MAX_METADATA)
                .unwrap()
                .is_none()
        );
        directory
            .write_atomic("go", b"1", PublishMode::CreateNew)
            .unwrap();
        wait_record(&directory, "admitted");
        assert!(matches!(
            store::acquire(&directory, "runtime.lock", "handoff"),
            Err(Error::Busy(_))
        ));
        directory
            .write_atomic("finish", b"1", PublishMode::CreateNew)
            .unwrap();
    }));
    // Every spawned child is waited even if an observation fails; its own handshake bound
    // provides ordinary exit, never a signal or a guessed-PID cleanup.
    let closed = child.wait().unwrap();
    observed.unwrap();
    assert!(closed.success());
    let retry = store::acquire(&directory, "runtime.lock", "handoff").unwrap();
    assert_eq!(FileIdentity::of(&retry).unwrap(), original);
    drop(operation);
}

#[test]
fn wrong_runtime_descriptor_refuses_before_generation_or_failed_status_publication() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
    let owner = store::acquire(&directory, "runtime.lock", "handoff").unwrap();
    let original = FileIdentity::of(&owner).unwrap();
    let wrong = directory.open_ownership_lock("another.lock").unwrap();
    assert!(adopt_worker_ownership(&directory, wrong, "handoff").is_err());
    assert!(
        directory
            .read_optional(STATUS, MAX_METADATA)
            .unwrap()
            .is_none()
    );
    assert!(
        directory
            .read_optional(WORKER, MAX_METADATA)
            .unwrap()
            .is_none()
    );
    assert_eq!(FileIdentity::of(&owner).unwrap(), original);
    FileSnapshot::private_journal(&owner).unwrap();
    #[cfg(unix)]
    {
        let path = directory.path().join("runtime.lock");
        let displaced = directory.path().join("displaced.lock");
        std::fs::rename(&path, &displaced).unwrap();
        assert!(adopt_worker_ownership(&directory, owner.try_clone().unwrap(), "handoff").is_err());
        let replacement = directory.open_ownership_lock("runtime.lock").unwrap();
        assert_ne!(FileIdentity::of(&replacement).unwrap(), original);
        assert!(adopt_worker_ownership(&directory, owner.try_clone().unwrap(), "handoff").is_err());
        drop(replacement);
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&displaced, &path).unwrap();
    }
    #[cfg(windows)]
    assert!(
        std::fs::rename(
            directory.path().join("runtime.lock"),
            directory.path().join("displaced.lock")
        )
        .is_err()
    );
    let admitted =
        adopt_worker_ownership(&directory, owner.try_clone().unwrap(), "handoff").unwrap();
    assert_eq!(FileIdentity::of(&admitted).unwrap(), original);
    drop(admitted);
    drop(owner);
    assert_eq!(
        FileIdentity::of(&store::acquire(&directory, "runtime.lock", "handoff").unwrap()).unwrap(),
        original
    );
}

#[test]
fn delayed_worker_refuses_the_original_expired_budget_and_closes_starting_without_peers() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, prepared) =
        super::super::tests::fixture(&temporary.path().join("state"), "local");
    let operation = store::acquire(&directory, "operation.lock", "local").unwrap();
    let owner = store::acquire(&directory, "runtime.lock", "local").unwrap();
    let before = generation::read(&directory).unwrap();
    let initial = ManagedStatus {
        context: prepared.context.clone(),
        phase: ManagedPhase::Starting,
        running_peers: 0,
        failure: None,
    };
    publish(&directory, &initial).unwrap();
    let deadline = startup_deadline(Instant::now(), Duration::from_secs(1)).unwrap();
    let mut command = child_command(&directory, &owner, "expired");
    command
        .env("IROHA_TEST_HANDOFF_STORE", store.root())
        .env("IROHA_TEST_HANDOFF_DEADLINE", deadline.to_string());
    let mut child = command.spawn().unwrap();
    drop(command);
    drop(owner);
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_record(&directory, "loaded");
        assert!(matches!(
            store::acquire(&directory, "runtime.lock", "local"),
            Err(Error::Busy(_))
        ));
        while continuous_remaining(deadline).unwrap().is_some() {
            thread::sleep(Duration::from_millis(2));
        }
        directory
            .write_atomic("go", b"1", PublishMode::CreateNew)
            .unwrap();
    }));
    let closed = child.wait().unwrap();
    observed.unwrap();
    assert!(closed.success());
    let after = generation::read(&directory).unwrap();
    assert_eq!(after.prepared, before.prepared);
    let status: ManagedStatus = decode(&directory.read(STATUS, MAX_METADATA).unwrap()).unwrap();
    assert_eq!(status.context, prepared.context);
    assert_eq!(status.phase, ManagedPhase::Failed);
    assert_eq!(status.running_peers, 0);
    assert!(
        status
            .failure
            .unwrap()
            .starts_with("startup deadline expired")
    );
    store::acquire(&directory, "runtime.lock", "local").unwrap();
    drop(operation);
}

#[test]
fn shared_budget_closes_late_handoffs_and_peer_spawn_while_renewal_remains_independent() {
    let _resources = super::super::native_test_guard();
    let started = Instant::now();
    let deadline = startup_deadline(started, Duration::from_secs(30)).unwrap();
    let mut original = budget(Some(deadline));
    let before = continuous_remaining(deadline).unwrap().unwrap();
    assert!(original.check().unwrap() <= before);
    let observed = Instant::now();
    let derived = original.deadline().unwrap();
    assert!(derived <= observed + before);
    assert!(continuous_remaining(u128::MAX).is_err());
    original.startup_deadline_ns = Some(0);
    assert_eq!(original.check().unwrap_err(), original.progress.deadline());
    let (sender, receiver) = mpsc::sync_channel(1);
    sender.send(Ok(())).unwrap();
    // This is the main loop's real close: a queued success and fresh local Instant cannot
    // override the original frontend's expired shared deadline.
    assert_eq!(original.check().unwrap_err(), original.progress.deadline());
    assert!(matches!(
        observe_readiness(
            &receiver,
            &original.progress,
            original.started,
            original.timeout
        ),
        Some(Ok(()))
    ));
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
    let daemon =
        super::super::program::NativeProgram::capture(&std::env::current_exe().unwrap()).unwrap();
    let mut command = Command::new(daemon.path());
    assert!(spawn_with_launch_fence(&directory, 0, &mut command, &daemon, &original).is_err());
    assert_eq!(directory.read("peer0.launch", 1).unwrap().as_slice(), b"0");
    assert!(budget(None).check().is_ok());
    original.startup_deadline_ns = Some(u128::MAX);
    assert_eq!(
        original.check().unwrap_err(),
        original.progress.unconfirmed()
    );
}

#[test]
fn admitted_worker_closes_native_program_failure_without_creating_a_session_or_peers() {
    let _resources = super::super::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, directory, prepared) =
        super::super::tests::fixture(&temporary.path().join("state"), "local");
    let operation = store::acquire(&directory, "operation.lock", "local").unwrap();
    let owner = store::acquire(&directory, "runtime.lock", "local").unwrap();
    let original = generation::read(&directory).unwrap();
    let mut changed = original.clone();
    changed.daemon.path = temporary.path().join("missing-daemon");
    let manifest = directory.open_child(generation::DIRECTORY).unwrap();
    manifest
        .write_atomic(MANIFEST, &encode(&changed).unwrap(), PublishMode::Replace)
        .unwrap();
    publish(
        &directory,
        &ManagedStatus {
            context: prepared.context.clone(),
            phase: ManagedPhase::Starting,
            running_peers: 0,
            failure: None,
        },
    )
    .unwrap();
    let deadline = startup_deadline(Instant::now(), Duration::from_secs(30)).unwrap();
    let mut command = child_command(&directory, &owner, "program-fail");
    command
        .env("IROHA_TEST_HANDOFF_STORE", store.root())
        .env("IROHA_TEST_HANDOFF_DEADLINE", deadline.to_string());
    let mut child = command.spawn().unwrap();
    drop(command);
    drop(owner);
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_record(&directory, "loaded");
        directory
            .write_atomic("go", b"1", PublishMode::CreateNew)
            .unwrap();
    }));
    let closed = child.wait().unwrap();
    observed.unwrap();
    assert!(closed.success());
    let status: ManagedStatus = decode(&directory.read(STATUS, MAX_METADATA).unwrap()).unwrap();
    assert_eq!(status.context, prepared.context);
    assert_eq!(status.phase, ManagedPhase::Failed);
    assert_eq!(status.running_peers, 0);
    assert!(
        status
            .failure
            .unwrap()
            .starts_with("startup could not be confirmed")
    );
    manifest
        .write_atomic(MANIFEST, &encode(&original).unwrap(), PublishMode::Replace)
        .unwrap();
    assert_eq!(
        generation::read(&directory).unwrap().prepared,
        original.prepared
    );
    store::acquire(&directory, "runtime.lock", "local").unwrap();
    drop(operation);
}
