//! Terminal publication and runtime ownership remain fenced until all owned work exits.

use super::*;

// On assertion unwinding, unblock this test's task before scoped threads are joined.
struct ReleaseTask(Option<mpsc::Sender<()>>);
impl ReleaseTask {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for ReleaseTask {
    fn drop(&mut self) {
        self.release();
    }
}

fn wait_cancelled(cancelled: &AtomicBool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cancelled.load(Ordering::Acquire) {
        assert!(
            Instant::now() < deadline,
            "terminal cleanup never cancelled work"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn deadline_and_down_join_all_mutators_before_terminal_status_and_owner_release() {
    let _resources = crate::managed::native_test_guard();
    for down in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let (_, directory, prepared) =
            crate::managed::tests::fixture(&temporary.path().join("state"), "background");
        let initial = ManagedStatus {
            context: prepared.context,
            phase: if down {
                ManagedPhase::Ready
            } else {
                ManagedPhase::Starting
            },
            running_peers: 0,
            failure: None,
        };
        publish(&directory, &initial).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let (activation_release, activation_held) = mpsc::channel();
        let (refresh_release, refresh_held) = mpsc::channel();
        let (entered, entered_rx) = mpsc::channel();
        let (done, done_rx) = mpsc::channel();
        thread::scope(|scope| {
            // Both guards drop before scope joins if the observing assertions fail.
            let mut activation_release = ReleaseTask(Some(activation_release));
            let mut refresh_release = ReleaseTask(Some(refresh_release));
            let cancelled_for_worker = Arc::clone(&cancelled);
            let directory = &directory;
            let initial = &initial;
            let worker = scope.spawn(move || {
                // Match run_worker's declaration order: task owner drops before runtime.lock.
                let ownership = store::acquire(directory, "runtime.lock", "background").unwrap();
                let mut processes =
                    PeerProcesses::with_background(Arc::clone(&cancelled_for_worker));
                let activation_path = directory.path().to_owned();
                let activation_entered = entered.clone();
                processes
                    .spawn_activation(move || {
                        activation_entered.send(()).unwrap();
                        activation_held
                            .recv_timeout(Duration::from_secs(10))
                            .unwrap();
                        PrivateDirectory::open(activation_path)
                            .unwrap()
                            .write_atomic("activation-finished", b"done", PublishMode::CreateNew)
                            .unwrap();
                    })
                    .unwrap();
                let refresh_path = directory.path().to_owned();
                processes
                    .spawn_refresh(move || {
                        entered.send(()).unwrap();
                        refresh_held.recv_timeout(Duration::from_secs(10)).unwrap();
                        PrivateDirectory::open(refresh_path)
                            .unwrap()
                            .write_atomic("refresh-finished", b"done", PublishMode::CreateNew)
                            .unwrap();
                    })
                    .unwrap();
                let mut status = initial.clone();
                let progress = progress::Progress::default();
                progress.enter(progress::Phase::InitialReadiness);
                let failure = progress.deadline();
                let result = if down {
                    stop_worker(
                        directory,
                        &mut status,
                        &mut processes,
                        &cancelled_for_worker,
                        failure,
                    )
                } else {
                    fail_worker(
                        directory,
                        &mut status,
                        &mut processes,
                        &cancelled_for_worker,
                        failure,
                    )
                };
                assert_eq!(result.is_ok(), down);
                assert_eq!(
                    directory.read("activation-finished", 4).unwrap().as_slice(),
                    b"done"
                );
                assert_eq!(
                    directory.read("refresh-finished", 4).unwrap().as_slice(),
                    b"done"
                );
                let retained: ManagedStatus =
                    decode(&directory.read(STATUS, MAX_METADATA).unwrap()).unwrap();
                assert_eq!(retained, status);
                assert_eq!(
                    status.phase,
                    if down {
                        ManagedPhase::Stopped
                    } else {
                        ManagedPhase::Failed
                    }
                );
                assert_eq!(status.running_peers, 0);
                if !down {
                    assert_eq!(status.failure, Some(failure.message()));
                }
                drop(processes);
                drop(ownership);
                done.send(()).unwrap();
            });
            for _ in 0..2 {
                entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            wait_cancelled(&cancelled);
            assert_eq!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
            let retained: ManagedStatus =
                decode(&directory.read(STATUS, MAX_METADATA).unwrap()).unwrap();
            assert_eq!(
                &retained, initial,
                "terminal status escaped before task drain"
            );
            assert!(matches!(
                store::acquire(directory, "runtime.lock", "background"),
                Err(Error::Busy(_))
            ));
            activation_release.release();
            // A remaining refresh task is independently owned; draining activation is insufficient.
            assert_eq!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
            assert!(matches!(
                store::acquire(directory, "runtime.lock", "background"),
                Err(Error::Busy(_))
            ));
            refresh_release.release();
            worker.join().unwrap();
            done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        store::acquire(&directory, "runtime.lock", "background").unwrap();
    }
}

#[test]
fn unwinding_worker_cancels_and_joins_before_runtime_ownership_drops() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_, directory, _) =
        crate::managed::tests::fixture(&temporary.path().join("state"), "background");
    let cancelled = Arc::new(AtomicBool::new(false));
    let (release, held) = mpsc::channel();
    let (entered, entered_rx) = mpsc::channel();
    thread::scope(|scope| {
        let mut release = ReleaseTask(Some(release));
        let cancelled_for_worker = Arc::clone(&cancelled);
        let directory = &directory;
        let worker = scope.spawn(move || {
            let outcome = std::panic::catch_unwind(|| {
                let _ownership = store::acquire(directory, "runtime.lock", "background").unwrap();
                let mut processes = PeerProcesses::with_background(cancelled_for_worker);
                let path = directory.path().to_owned();
                processes
                    .spawn_activation(move || {
                        entered.send(()).unwrap();
                        held.recv_timeout(Duration::from_secs(10)).unwrap();
                        PrivateDirectory::open(path)
                            .unwrap()
                            .write_atomic("unwind-finished", b"done", PublishMode::CreateNew)
                            .unwrap();
                    })
                    .unwrap();
                panic!("controlled worker unwind");
            });
            assert!(outcome.is_err());
        });
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        wait_cancelled(&cancelled);
        assert!(!worker.is_finished());
        assert!(matches!(
            store::acquire(directory, "runtime.lock", "background"),
            Err(Error::Busy(_))
        ));
        assert!(
            directory
                .read_optional("unwind-finished", 4)
                .unwrap()
                .is_none()
        );
        release.release();
        worker.join().unwrap();
    });
    assert_eq!(
        directory.read("unwind-finished", 4).unwrap().as_slice(),
        b"done"
    );
    store::acquire(&directory, "runtime.lock", "background").unwrap();
}
