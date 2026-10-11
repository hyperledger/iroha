//! Actual owned handles and genuine renderer provenance; no test process is treated as a daemon.

use super::*;
use crate::{
    localnet::LocalnetServiceProfile, managed::service_bootstrap::ManagedServiceBootstrap,
};

fn launch() -> (tempfile::TempDir, PreparedLocalnet, Arc<GeneratedLaunch>) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "owned-launch",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
    parent
        .authorize_generated_startup(deadline, Arc::new(AtomicBool::new(false)))
        .unwrap()
        .unwrap();
    drop(parent);
    let owner = Arc::new(GeneratedServiceRuntime::open(&prepared).unwrap());
    let revision = owner.prepare_catalog(deadline).unwrap();
    let launch = GeneratedLaunch::new(owner, revision, &prepared).unwrap();
    (temporary, prepared, launch)
}

#[test]
fn generated_command_requires_exact_revision_and_invalidation_prevents_reuse() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, launch) = launch();
    let daemon = std::path::Path::new("iroha3d");
    let command = launch.command(daemon, 0).unwrap();
    let peer = launch.revision.peer(0).unwrap();
    let digest = hex::encode(peer.blake3());
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [
            std::ffi::OsStr::new("--sora"),
            "--config".as_ref(),
            peer.path().as_os_str(),
            "--config-blake3".as_ref(),
            digest.as_ref()
        ]
    );
    assert_eq!(
        command.get_current_dir(),
        prepared.context.client_config.parent()
    );
    assert!(launch.command(daemon, 4).is_err());
    let mut owner = PeerProcesses {
        children: Vec::new(),
        launch: Some(Arc::clone(&launch)),
        background: None,
    };
    for plan in prepared.provider_service_plans().unwrap().unwrap() {
        assert!(
            owner.gateway(plan.provider_id()).is_err(),
            "rendered config without owned children is not a live gateway"
        );
    }
    assert!(owner.gateways().is_err());
    owner.stop().unwrap();
    assert!(!launch.active.load(Ordering::Acquire));
    assert!(launch.command(daemon, 0).is_err());
    assert!(launch.validate().is_err());
}

#[cfg(unix)]
#[test]
fn original_guard_dies_on_owned_stop_and_cannot_be_reused_for_another_launch() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, launch) = launch();
    let children = (0..4)
        .map(|_| Command::new("/bin/sleep").arg("30").spawn().unwrap())
        .collect();
    let mut processes = PeerProcesses::from_children(children);
    processes.launch = Some(Arc::clone(&launch));
    let mut gateways = processes.gateways().unwrap();
    let plans = prepared.provider_service_plans().unwrap().unwrap();
    for (index, gateway) in gateways.iter_mut().enumerate() {
        assert_eq!(gateway.provider(), plans[index].provider_id());
        let plan = prepared
            .gateway_compliance_plan(gateway.provider())
            .unwrap()
            .unwrap();
        gateway.validate(&prepared, &plan).unwrap();
        for other in &plans {
            if other.provider_id() != gateway.provider() {
                let foreign = prepared
                    .gateway_compliance_plan(other.provider_id())
                    .unwrap()
                    .unwrap();
                assert!(gateway.validate(&prepared, &foreign).is_err());
            }
        }
    }
    let unknown = iroha_data_model::sorafs::capacity::ProviderId::new([0xAB; 32]);
    assert!(processes.gateway(unknown).is_err());
    let comparison = crate::managed::native_operation::ManagedTransactionFinality {
        transaction_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"catalog-has-no-transaction",
        )),
        height: 13,
        block_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"catalog-has-no-carrier",
        )),
        block_time_ms: 1,
    };
    for gateway in &mut gateways {
        assert!(
            gateway.selected_enrollment(comparison).is_err(),
            "Catalog launch cannot supply enrollment authority"
        );
        let plan = prepared
            .gateway_compliance_plan(gateway.provider())
            .unwrap()
            .unwrap();
        let mut foreign = prepared.clone();
        foreign.context.name.push_str("-foreign");
        assert!(gateway.validate(&foreign, &plan).is_err());
    }
    processes.stop().unwrap();
    assert!(processes.children.is_empty());
    for gateway in &mut gateways {
        let plan = prepared
            .gateway_compliance_plan(gateway.provider())
            .unwrap()
            .unwrap();
        assert!(gateway.require_running().is_err());
        assert!(gateway.selected_enrollment(comparison).is_err());
        assert!(gateway.validate(&prepared, &plan).is_err());
        assert!(processes.gateway(gateway.provider()).is_err());
    }
    assert!(processes.gateways().is_err());
    assert!(processes.generated().unwrap().is_none());
    assert!(!launch.active.load(Ordering::Acquire));
}

#[cfg(unix)]
#[test]
fn owned_start_refuses_an_unselected_or_changed_daemon_before_logs_and_launch_markers() {
    use std::io::Write;
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_store, directory, _prepared) =
        crate::managed::tests::fixture(&temporary.path().join("state"), "selected");
    let mut retained = crate::managed::generation::read(&directory).unwrap();
    let path = temporary.path().join("daemon");
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    let selected = crate::managed::program::NativeProgram::capture(&path).unwrap();
    retained.daemon = selected.pin().unwrap();
    let ownership = crate::managed::store::acquire(&directory, "runtime.lock", "selected").unwrap();
    let unselected =
        crate::managed::program::NativeProgram::capture(&std::env::current_exe().unwrap()).unwrap();
    let mut processes = PeerProcesses::default();
    let budget = activation::Budget {
        started: Instant::now(),
        timeout: Duration::from_secs(30),
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(progress::Progress::default()),
    };
    assert!(matches!(
        processes.start(&directory, &retained, &ownership, &unselected, None, &budget),
        Err(Error::Invalid(message)) if message == "daemon differs from the retained runtime path"
    ));
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"changed selected daemon")
        .unwrap();
    assert!(
        processes
            .start(&directory, &retained, &ownership, &selected, None, &budget)
            .is_err()
    );
    let changed = crate::managed::program::NativeProgram::capture(&path).unwrap();
    assert!(matches!(
        processes.start(&directory, &retained, &ownership, &changed, None, &budget),
        Err(Error::Invalid(message)) if message == "daemon differs from the retained runtime contents"
    ));
    assert!(processes.children.is_empty());
    assert!(processes.launch.is_none());
    for (index, peer) in retained.prepared.peers.iter().enumerate() {
        assert!(!directory.path().join(&peer.log_name).exists());
        assert!(
            !directory
                .path()
                .join(format!("peer{index}.launch"))
                .exists()
        );
    }
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    assert!(selected.validate().is_err());
    crate::managed::program::NativeProgram::matching(&retained.daemon)
        .unwrap()
        .validate()
        .unwrap();
    assert!(processes.children.is_empty());
    assert!(processes.launch.is_none());
}

#[test]
fn background_slots_join_before_replacement_and_preserve_consumed_panics() {
    for activation in [false, true] {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut owner = PeerProcesses::with_background(Arc::clone(&cancelled));
        let finished = Arc::new(AtomicBool::new(false));
        let first_finished = Arc::clone(&finished);
        let first = move || first_finished.store(true, Ordering::Release);
        if activation {
            owner.spawn_activation(first)
        } else {
            owner.spawn_refresh(first)
        }
        .unwrap();
        let second = move || {
            assert!(
                finished.load(Ordering::Acquire),
                "replacement preceded original thread exit"
            );
            panic!("controlled owned task panic");
        };
        if activation {
            owner.spawn_activation(second)
        } else {
            owner.spawn_refresh(second)
        }
        .unwrap();
        let replaced = Arc::new(AtomicBool::new(false));
        let attempted = Arc::clone(&replaced);
        let replacement = move || attempted.store(true, Ordering::Release);
        let error = if activation {
            owner.spawn_activation(replacement)
        } else {
            owner.spawn_refresh(replacement)
        }
        .unwrap_err();
        assert!(error.to_string().contains("task panicked"));
        assert!(!replaced.load(Ordering::Acquire));
        cancelled.store(true, Ordering::Release);
        assert!(
            owner
                .stop()
                .unwrap_err()
                .to_string()
                .contains("panicked before replacement")
        );
        owner.stop().unwrap();
    }
}

#[test]
fn background_drain_joins_refresh_even_when_activation_panics() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut owner = PeerProcesses::with_background(Arc::clone(&cancelled));
    owner
        .spawn_activation(|| panic!("controlled activation panic"))
        .unwrap();
    let completed = Arc::new(AtomicBool::new(false));
    let refresh_completed = Arc::clone(&completed);
    owner
        .spawn_refresh(move || refresh_completed.store(true, Ordering::Release))
        .unwrap();
    cancelled.store(true, Ordering::Release);
    assert!(
        owner
            .stop()
            .unwrap_err()
            .to_string()
            .contains("owned activation task panicked")
    );
    assert!(completed.load(Ordering::Acquire));
    assert!(owner.background.as_ref().unwrap().activation.is_none());
    assert!(owner.background.as_ref().unwrap().refresh.is_none());
    owner.stop().unwrap();
}

#[test]
fn ordinary_peer_restart_preserves_background_tasks_until_terminal_cancellation() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut owner = PeerProcesses::with_background(Arc::clone(&cancelled));
    let (release, held) = mpsc::channel();
    owner
        .spawn_activation(move || {
            let _ = held.recv_timeout(Duration::from_secs(10));
        })
        .unwrap();
    owner.stop().unwrap();
    assert!(!cancelled.load(Ordering::Acquire));
    assert!(owner.background.as_ref().unwrap().activation.is_some());
    assert!(
        !owner
            .background
            .as_ref()
            .unwrap()
            .activation
            .as_ref()
            .unwrap()
            .is_finished()
    );
    release.send(()).unwrap();
    cancelled.store(true, Ordering::Release);
    owner.stop().unwrap();
    assert!(owner.background.as_ref().unwrap().activation.is_none());
}

#[cfg(unix)]
#[test]
fn child_cleanup_error_still_drains_all_owned_background_tasks() {
    struct RestorePoison(Arc<Mutex<Child>>);
    impl Drop for RestorePoison {
        fn drop(&mut self) {
            self.0.clear_poison();
        }
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut owner = PeerProcesses::with_background(Arc::clone(&cancelled));
    let mut child = Command::new("/bin/sleep").arg("0").spawn().unwrap();
    child.wait().unwrap();
    let child = Arc::new(Mutex::new(child));
    owner.children.push(Arc::clone(&child));
    let _restore_poison = RestorePoison(Arc::clone(&child));
    let poison = Arc::clone(&child);
    assert!(
        thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("controlled child handle poison");
        })
        .join()
        .is_err()
    );
    owner
        .spawn_activation(|| panic!("controlled task panic with child error"))
        .unwrap();
    let completed = Arc::new(AtomicBool::new(false));
    let task_completed = Arc::clone(&completed);
    owner
        .spawn_refresh(move || task_completed.store(true, Ordering::Release))
        .unwrap();
    cancelled.store(true, Ordering::Release);
    let error = owner.stop().unwrap_err();
    assert!(error.to_string().contains("owned child lock failed"));
    assert!(error.to_string().contains("owned activation task panicked"));
    assert!(completed.load(Ordering::Acquire));
    assert!(owner.background.as_ref().unwrap().activation.is_none());
    assert!(owner.background.as_ref().unwrap().refresh.is_none());
    assert_eq!(
        owner.children.len(),
        1,
        "failed cleanup must retain the actual child handle"
    );
    child.clear_poison();
    owner.stop().unwrap();
    assert!(owner.children.is_empty());
}

#[test]
fn attachment_scope_does_not_create_a_binding_when_no_parent_is_configured() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, _, prepared) =
        crate::managed::tests::fixture(&temporary.path().join("state"), "unattached");
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut owner = PeerProcesses::with_background(Arc::clone(&cancelled));
    assert!(owner.attachment().is_none());
    owner
        .start_attachment(&store, "unattached", &prepared)
        .unwrap();
    assert!(owner.attachment().is_none());
    cancelled.store(true, Ordering::Release);
    owner.stop().unwrap();
}

#[test]
fn replacement_cannot_start_while_the_original_task_is_still_mutating() {
    for activation in [false, true] {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut owner = PeerProcesses::with_background(Arc::clone(&cancelled));
        let completed = Arc::new(AtomicBool::new(false));
        let original_completed = Arc::clone(&completed);
        let (release, held) = mpsc::channel();
        let (entered, entered_rx) = mpsc::channel();
        let original = move || {
            entered.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(10)).unwrap();
            original_completed.store(true, Ordering::Release);
        };
        if activation {
            owner.spawn_activation(original)
        } else {
            owner.spawn_refresh(original)
        }
        .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let (replacement_started, replacement_rx) = mpsc::channel();
        let (attempting, attempting_rx) = mpsc::channel();
        thread::scope(|scope| {
            let release = release;
            let replacing = scope.spawn(move || {
                let replacement = move || {
                    assert!(completed.load(Ordering::Acquire));
                    replacement_started.send(()).unwrap();
                };
                attempting.send(()).unwrap();
                if activation {
                    owner.spawn_activation(replacement)
                } else {
                    owner.spawn_refresh(replacement)
                }
                .unwrap();
                cancelled.store(true, Ordering::Release);
                owner.stop().unwrap();
            });
            attempting_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(
                replacement_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
            assert!(!replacing.is_finished());
            release.send(()).unwrap();
            replacing.join().unwrap();
            replacement_rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
        });
    }
}

#[cfg(unix)]
mod plan_selection_tests;

#[cfg(unix)]
pub(super) mod batch_validation_tests;
