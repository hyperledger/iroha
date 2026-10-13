#[cfg(unix)]
#[test]
fn durable_inrou_egress_gc_retains_uncommitted_precharge_after_restart() -> Result<()> {
    let mut state = test_state();
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.container.runtime = SoraContainerRuntimeV1::Inrou;
    bundle.service.execution_plane =
        iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService;
    let deployment = sample_deployment_state(&bundle);
    let reporting_epoch = deployment
        .service_lease
        .as_ref()
        .expect("hosted service lease")
        .reporting_epoch;
    let lease_started_height = deployment
        .service_lease
        .as_ref()
        .expect("hosted service lease")
        .lease_started_height;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_deployment_fixture(world, &bundle, deployment);
    }
    let local_peer_id = canonical_inrou_test_peer_id();
    insert_inrou_service_placement_fixture(&mut state, &bundle, local_peer_id, [1]);

    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let current = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        bundle.service.service_name.as_ref(),
        (lease_started_height, reporting_epoch),
        &bundle.service.service_version,
        (1, &Hash::new(Encode::encode(&("placement", 1_u16)))),
        &ALICE_ID,
        None,
    )?;
    current.advance_to(4096)?;
    let current_path = current.path.clone();
    drop(current);
    let obsolete = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        bundle.service.service_name.as_ref(),
        (
            lease_started_height,
            reporting_epoch.checked_add(1).expect("successor epoch"),
        ),
        &bundle.service.service_version,
        (1, &Hash::new(Encode::encode(&("placement", 1_u16)))),
        &ALICE_ID,
        None,
    )?;
    let obsolete_path = obsolete.path.clone();
    drop(obsolete);

    // Model a fresh daemon: neither in-memory accounting nor workers have
    // been reconstructed, and WSV has no reporter checkpoint yet.
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(state_dir)
            .with_local_host_identity(ALICE_ID.clone(), local_peer_id),
        Arc::clone(&state),
    );
    assert!(manager.inrou_replica_egress_accounting.lock().is_empty());
    assert!(manager.hosted_http_workers.lock().is_empty());
    let view = state.view();
    manager.reconcile_inrou_egress_checkpoint_files(&view)?;
    assert!(current_path.is_file());
    assert_eq!(
        read_inrou_durable_egress_checkpoint(
            &current_path,
            &inrou_egress_reporter_key_digest(
                bundle.service.service_name.as_ref(),
                lease_started_height,
                reporting_epoch,
                &bundle.service.service_version,
                1,
                &Hash::new(Encode::encode(&("placement", 1_u16))),
                &ALICE_ID,
            )?,
        )?,
        4096
    );
    assert!(!obsolete_path.exists());
    Ok(())
}
#[cfg(unix)]
#[test]
fn durable_inrou_egress_gc_rejects_unexpected_symlink_and_oversized_scans() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let checkpoint_dir = prepare_inrou_egress_checkpoint_dir(
        &state_dir.join(SORACLOUD_INROU_EGRESS_CHECKPOINT_DIR),
    )?;
    let retained_digest = [0x44; 32];
    let retained_path = checkpoint_dir.join(format!("{}.bin", hex::encode(retained_digest)));
    write_inrou_durable_egress_checkpoint(&retained_path, &retained_digest, 13)?;
    let unexpected = checkpoint_dir.join("unexpected");
    fs::write(&unexpected, b"unexpected")?;
    reconcile_inrou_egress_checkpoint_directory(&state_dir, &BTreeSet::from([retained_digest]), 8)
        .expect_err("an unrecognized checkpoint-directory entry must fail closed");
    fs::remove_file(&unexpected)?;

    let symlink_digest = [0x55; 32];
    let symlink_path = checkpoint_dir.join(format!("{}.bin", hex::encode(symlink_digest)));
    symlink(&retained_path, &symlink_path)?;
    reconcile_inrou_egress_checkpoint_directory(&state_dir, &BTreeSet::from([retained_digest]), 8)
        .expect_err("a symlinked checkpoint-directory entry must fail closed");
    fs::remove_file(&symlink_path)?;

    let second_digest = [0x66; 32];
    write_inrou_durable_egress_checkpoint(
        &checkpoint_dir.join(format!("{}.bin", hex::encode(second_digest))),
        &second_digest,
        0,
    )?;
    reconcile_inrou_egress_checkpoint_directory(
        &state_dir,
        &BTreeSet::from([retained_digest, second_digest]),
        1,
    )
    .expect_err("a checkpoint directory above the fixed scan cap must fail closed");
    Ok(())
}
#[test]
fn inrou_egress_accounting_is_exact_across_concurrent_writers() -> Result<()> {
    const WRITERS: usize = 8;
    const BYTES_PER_WRITER: usize = 4_097;
    let accounting =
        PortableVmReplicaEgressAccounting::new(PortableVmEgressAccounting::new(37), 11);
    let workers = (0..WRITERS)
        .map(|_| {
            let accounting = accounting.clone();
            thread::spawn(move || -> io::Result<usize> {
                let global_stop = AtomicBool::new(false);
                let session_stop = AtomicBool::new(false);
                let mut writer = TestPartialWriter {
                    maximum_write_bytes: 7,
                    fail_after_bytes: None,
                    bytes: Vec::new(),
                };
                write_inrou_bridge_buffer_bounded(
                    &mut writer,
                    &[0x5a; BYTES_PER_WRITER],
                    &global_stop,
                    &session_stop,
                    Some(&accounting),
                )?;
                Ok(writer.bytes.len())
            })
        })
        .collect::<Vec<_>>();

    for worker in workers {
        assert_eq!(worker.join().expect("egress writer")?, BYTES_PER_WRITER);
    }
    assert_eq!(
        accounting.revision_accounted_egress_bytes(),
        37 + (WRITERS * BYTES_PER_WRITER) as u64
    );
    assert_eq!(
        accounting.reporter_accounted_egress_bytes(),
        11 + (WRITERS * BYTES_PER_WRITER) as u64
    );
    Ok(())
}
#[test]
fn inrou_egress_accounting_fails_closed_before_counter_overflow() {
    let accounting =
        PortableVmReplicaEgressAccounting::new(PortableVmEgressAccounting::new(u64::MAX - 2), 100);
    let global_stop = AtomicBool::new(false);
    let session_stop = AtomicBool::new(false);
    let mut writer = TestPartialWriter {
        maximum_write_bytes: usize::MAX,
        fail_after_bytes: None,
        bytes: Vec::new(),
    };

    write_inrou_bridge_buffer_bounded(
        &mut writer,
        b"abc",
        &global_stop,
        &session_stop,
        Some(&accounting),
    )
    .expect_err("the byte beyond u64::MAX must not be written");

    assert_eq!(writer.bytes, b"ab");
    assert_eq!(accounting.revision_accounted_egress_bytes(), u64::MAX);
    assert_eq!(accounting.reporter_accounted_egress_bytes(), 102);
    assert!(global_stop.load(AtomicOrdering::Acquire));
}
#[test]
fn inrou_bridge_teardown_joins_after_accounting_stop_and_restart_reuses_counter() -> Result<()> {
    let accounting =
        PortableVmReplicaEgressAccounting::new(PortableVmEgressAccounting::new(101), 13);
    let worker_accounting = accounting.clone();
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        release_rx.recv().expect("release accounting worker");
        worker_accounting
            .revision
            .advance_floor(105)
            .expect("capture final session accounting");
        worker_accounting
            .reporter
            .advance_floor(17)
            .expect("capture final reporter accounting");
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut bridge = PortableVmLoopbackBridge {
        listen_address: listener.local_addr()?,
        stop: Arc::new(AtomicBool::new(true)),
        worker: Some(worker),
    };
    let (stopped_tx, stopped_rx) = mpsc::sync_channel(1);
    let stop_worker = thread::spawn(move || {
        bridge.stop();
        let _ = stopped_tx.send(());
    });
    assert!(
        matches!(
            stopped_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "teardown must join even when accounting already stopped the bridge"
    );
    release_tx.send(())?;
    stopped_rx.recv_timeout(Duration::from_secs(1))?;
    stop_worker.join().expect("bridge stop worker");
    assert_eq!(accounting.revision_accounted_egress_bytes(), 105);
    assert_eq!(accounting.reporter_accounted_egress_bytes(), 17);

    let global_stop = AtomicBool::new(false);
    let session_stop = AtomicBool::new(false);
    let mut restarted_writer = TestPartialWriter {
        maximum_write_bytes: 1,
        fail_after_bytes: None,
        bytes: Vec::new(),
    };
    write_inrou_bridge_buffer_bounded(
        &mut restarted_writer,
        b"x",
        &global_stop,
        &session_stop,
        Some(&accounting),
    )?;
    assert_eq!(accounting.revision_accounted_egress_bytes(), 106);
    assert_eq!(accounting.reporter_accounted_egress_bytes(), 18);
    Ok(())
}
#[test]
fn inrou_two_replicas_advance_immediately_after_authoritative_checkpoint() -> Result<()> {
    let revision_accounting = PortableVmEgressAccounting::new(40);
    let replicas = [
        PortableVmReplicaEgressAccounting::new(revision_accounting.clone(), 0),
        PortableVmReplicaEgressAccounting::new(revision_accounting.clone(), 0),
    ];
    for (replica, payload) in replicas
        .iter()
        .zip([b"one".as_slice(), b"three".as_slice()])
    {
        let global_stop = AtomicBool::new(false);
        let session_stop = AtomicBool::new(false);
        let mut writer = TestPartialWriter {
            maximum_write_bytes: 2,
            fail_after_bytes: None,
            bytes: Vec::new(),
        };
        write_inrou_bridge_buffer_bounded(
            &mut writer,
            payload,
            &global_stop,
            &session_stop,
            Some(replica),
        )?;
    }
    assert_eq!(revision_accounting.accounted_egress_bytes(), 48);
    revision_accounting.advance_floor(48)?;
    replicas[0].reporter.advance_floor(3)?;
    replicas[1].reporter.advance_floor(5)?;

    let global_stop = AtomicBool::new(false);
    let session_stop = AtomicBool::new(false);
    let mut writer = TestPartialWriter {
        maximum_write_bytes: 1,
        fail_after_bytes: None,
        bytes: Vec::new(),
    };
    write_inrou_bridge_buffer_bounded(
        &mut writer,
        b"x",
        &global_stop,
        &session_stop,
        Some(&replicas[0]),
    )?;
    assert_eq!(replicas[0].revision_accounted_egress_bytes(), 49);
    assert_eq!(replicas[1].revision_accounted_egress_bytes(), 49);
    assert_eq!(replicas[0].reporter_accounted_egress_bytes(), 4);
    assert_eq!(replicas[1].reporter_accounted_egress_bytes(), 5);
    assert_eq!(revision_accounting.accounted_egress_bytes(), 49);
    Ok(())
}
#[test]
fn hosted_http_revision_egress_floor_reaches_u64_max_without_aggregation() -> Result<()> {
    let accounting = PortableVmEgressAccounting::new(u64::MAX - 1);
    accounting.advance_floor(u64::MAX)?;
    assert_eq!(accounting.accounted_egress_bytes(), u64::MAX);
    Ok(())
}
#[test]
fn portable_vm_loopback_bridge_sends_no_bytes_when_backend_attestation_fails() -> Result<()> {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let backend_address = backend.local_addr()?;
    backend.set_nonblocking(true)?;
    let public = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let public_address = public.local_addr()?;
    let mut bridge = PortableVmLoopbackBridge::start_with_connector(
        public,
        backend_address,
        PortableVmReplicaEgressAccounting::new(PortableVmEgressAccounting::new(0), 0),
        Arc::new(|_, _| None),
    )?;
    let mut client = TcpStream::connect(public_address)?;
    client.write_all(b"must-not-reach-rebound-backend")?;
    let _ = client.shutdown(Shutdown::Both);
    drop(client);
    thread::sleep(Duration::from_millis(50));
    bridge.stop();
    assert!(
        matches!(backend.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "bridge must authenticate before it opens any backend connection"
    );
    Ok(())
}
#[test]
fn portable_vm_loopback_bridge_rejects_ipv6_backend_selection() -> Result<()> {
    let public = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let connector: PortableVmBackendConnector = Arc::new(|_, _| None);
    let error = match PortableVmLoopbackBridge::start_with_connector(
        public,
        "[::1]:41231".parse()?,
        PortableVmReplicaEgressAccounting::new(PortableVmEgressAccounting::new(0), 0),
        connector,
    ) {
        Ok(mut bridge) => {
            bridge.stop();
            panic!("Inrou V1 must not select an IPv6 bridge backend");
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    Ok(())
}
#[test]
fn portable_vm_loopback_bridge_stop_is_bounded_with_a_nonreading_backend() -> Result<()> {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let backend_address = backend.local_addr()?;
    let (accepted_tx, accepted_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let backend_worker = thread::spawn(move || -> io::Result<()> {
        let (stream, _) = backend.accept()?;
        accepted_tx
            .send(())
            .map_err(|error| io::Error::other(error.to_string()))?;
        let _ = release_rx.recv_timeout(Duration::from_secs(5));
        drop(stream);
        Ok(())
    });
    let public = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let public_address = public.local_addr()?;
    let mut bridge = PortableVmLoopbackBridge::start_with_connector(
        public,
        backend_address,
        PortableVmReplicaEgressAccounting::new(PortableVmEgressAccounting::new(0), 0),
        Arc::new(|backend, _| TcpStream::connect_timeout(&backend, Duration::from_secs(1)).ok()),
    )?;
    let mut client = TcpStream::connect(public_address)?;
    let client_writer = thread::spawn(move || {
        let payload = vec![0x5a_u8; 64 * 1024].into_boxed_slice();
        while client.write_all(&payload).is_ok() {}
    });
    accepted_rx.recv_timeout(Duration::from_secs(2))?;
    thread::sleep(Duration::from_millis(100));

    let (stopped_tx, stopped_rx) = mpsc::sync_channel(1);
    let stop_worker = thread::spawn(move || {
        let started_at = std::time::Instant::now();
        bridge.stop();
        let _ = stopped_tx.send(started_at.elapsed());
    });
    let stopped = stopped_rx.recv_timeout(Duration::from_secs(2));
    let _ = release_tx.send(());
    let _ = stop_worker.join();
    let _ = client_writer.join();
    backend_worker.join().expect("backend worker")?;
    let elapsed = stopped.expect("bridge stop must not wait on a non-reading backend");
    assert!(
        elapsed < Duration::from_secs(2),
        "bridge stop exceeded its absolute teardown bound: {elapsed:?}"
    );
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn portable_vm_loopback_bridge_stop_cancels_stalled_qmp_attestation() -> Result<()> {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let backend_address = backend.local_addr()?;
    backend.set_nonblocking(true)?;
    let (supervisor_qmp, mut stalled_qmp) = UnixStream::pair()?;
    let (qmp_started_tx, qmp_started_rx) = mpsc::sync_channel(1);
    let (qmp_release_tx, qmp_release_rx) = mpsc::sync_channel(1);
    let qmp_worker = thread::spawn(move || -> io::Result<()> {
        stalled_qmp.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut request = [0_u8; 256];
        let read = stalled_qmp.read(&mut request)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "bridge closed QMP before issuing attestation",
            ));
        }
        qmp_started_tx
            .send(())
            .map_err(|error| io::Error::other(error.to_string()))?;
        let _ = qmp_release_rx.recv_timeout(Duration::from_secs(5));
        Ok(())
    });
    let qmp_control = Arc::new(parking_lot::Mutex::new(PortableVmQmpControl {
        reader: io::BufReader::new(supervisor_qmp),
    }));
    let public = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let public_address = public.local_addr()?;
    let connector = Arc::new(move |expected_backend: SocketAddr, stop: &AtomicBool| {
        let deadline = std::time::Instant::now() + SORACLOUD_INROU_QMP_SESSION_ATTEST_TIMEOUT;
        loop {
            if stop.load(AtomicOrdering::Acquire) {
                return None;
            }
            if let Some(mut control) = qmp_control.try_lock() {
                if attest_inrou_qmp_host_forward(
                    &mut control,
                    8080,
                    expected_backend,
                    deadline,
                    Some(stop),
                )
                .is_err()
                {
                    return None;
                }
                return TcpStream::connect_timeout(&expected_backend, Duration::from_secs(1)).ok();
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(1));
        }
    });
    let mut bridge = PortableVmLoopbackBridge::start_with_connector(
        public,
        backend_address,
        PortableVmReplicaEgressAccounting::new(PortableVmEgressAccounting::new(0), 0),
        connector,
    )?;
    let client = TcpStream::connect(public_address)?;
    qmp_started_rx.recv_timeout(Duration::from_secs(2))?;

    let started_at = std::time::Instant::now();
    bridge.stop();
    let elapsed = started_at.elapsed();
    let _ = client.shutdown(Shutdown::Both);
    let _ = qmp_release_tx.send(());
    qmp_worker.join().expect("QMP worker")?;
    assert!(matches!(
        backend.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert!(
        elapsed < Duration::from_secs(1),
        "bridge stop waited on the stalled QMP command: {elapsed:?}"
    );
    Ok(())
}
#[test]
fn hosted_http_probe_without_healthcheck_requires_a_live_listener() -> Result<()> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let base_url = format!("http://{}", listener.local_addr()?);
    probe_hosted_http_health(&base_url, None)?;
    drop(listener);
    assert_eyre_error_contains(
        &probe_hosted_http_health(&base_url, None)
            .expect_err("a missing listener must not be reported as healthy"),
        "connect to hosted-HTTP listener",
    );
    assert_eyre_error_contains(
        &probe_hosted_http_health(&format!("{base_url}/unexpected"), None)
            .expect_err("listener probes must reject URLs outside the exact origin"),
        "must be an explicit IPv4 loopback HTTP origin",
    );
    Ok(())
}
#[test]
fn hosted_http_health_probe_rejects_redirects_and_non_loopback_origins() -> Result<()> {
    assert_eyre_error_contains(
        &probe_hosted_http_health("http://192.0.2.1:8080", Some("/health"))
            .expect_err("health probes must remain on the explicit loopback origin"),
        "must be an explicit IPv4 loopback HTTP origin",
    );

    let redirect_target = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    redirect_target.set_nonblocking(true)?;
    let redirect_target_address = redirect_target.local_addr()?;
    let target = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            match redirect_target.accept() {
                Ok((_stream, _address)) => return true,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return true,
            }
        }
        false
    });
    let redirect_source = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let source_address = redirect_source.local_addr()?;
    let source = std::thread::spawn(move || {
        if let Ok((mut stream, _address)) = redirect_source.accept() {
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{redirect_target_address}/metadata\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    assert_eyre_error_contains(
        &probe_hosted_http_health(&format!("http://{source_address}"), Some("/health"))
            .expect_err("a redirect must not satisfy the health probe"),
        "returned 302",
    );
    source.join().expect("redirect source thread");
    assert!(
        !target.join().expect("redirect target thread"),
        "the host health client must not follow a guest-controlled redirect"
    );
    Ok(())
}
#[cfg(not(windows))]
#[test]
fn inrou_host_command_runner_clears_caller_environment() -> Result<()> {
    if std::env::var_os("HOME").is_none() {
        return Ok(());
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let helper = temp_dir.path().join("inrou-sanitized-command");
    fs::write(
        &helper,
        "#!/bin/sh\nif [ \"${HOME+x}\" = x ]; then exit 91; fi\n[ \"$PATH\" = /usr/bin:/bin:/usr/sbin:/sbin ]\n",
    )?;
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))?;

    run_host_command(&helper, &[])?;
    Ok(())
}
#[test]
fn portable_vm_kvm_identity_allows_only_the_derived_device_group() -> Result<()> {
    let mut identity = PortableVmChildIdentity {
        uid: 70_000,
        gid: 70_001,
        supplementary_gids: vec![108],
    };
    let kvm_device = PortableVmKvmDeviceAccess {
        uid: 0,
        gid: 108,
        mode: 0o660,
        hard_links: 1,
        rdev: SORACLOUD_INROU_KVM_DEVICE_RDEV,
        is_character_device: true,
    };
    validate_portable_vm_kvm_identity(&identity, kvm_device)?;
    identity.supplementary_gids.push(999);
    assert_eyre_error_contains(
        &validate_portable_vm_kvm_identity(&identity, kvm_device)
            .expect_err("KVM must reject unrelated supplementary groups"),
        "supplementary gids must be exactly",
    );
    identity.gid = 108;
    identity.supplementary_gids.clear();
    assert_eyre_error_contains(
        &validate_portable_vm_kvm_identity(&identity, kvm_device)
            .expect_err("the shared KVM group must not protect tenant disks"),
        "must remain distinct",
    );
    Ok(())
}
#[test]
fn portable_vm_identity_accepts_exactly_four_equal_slots() -> Result<()> {
    for slot in
        0..iroha_config::parameters::defaults::soracloud_runtime::INROU_PORTABLE_VM_ID_SLOT_COUNT
    {
        let id = SORACLOUD_INROU_ID_BASE + slot;
        let accepted = PortableVmChildIdentity {
            uid: id,
            gid: id,
            supplementary_gids: vec![108],
        };
        validate_portable_vm_child_identity_values(&accepted)?;
        assert_eq!(inrou_firewall_identity_slot(&accepted)?, slot as usize);
        #[cfg(target_os = "linux")]
        assert_eq!(
            inrou_service_identity_name(&accepted)?,
            format!("iroha-inrou-{slot}")
        );
    }
    let accepted = PortableVmChildIdentity {
        uid: SORACLOUD_INROU_ID_BASE,
        gid: SORACLOUD_INROU_ID_BASE,
        supplementary_gids: vec![108],
    };
    for id in [
        0,
        60_001,
        SORACLOUD_INROU_ID_BASE - 1,
        SORACLOUD_INROU_ID_MAX_EXCLUSIVE,
        524_288,
        1_879_048_191,
        u32::MAX,
    ] {
        let rejected = PortableVmChildIdentity {
            uid: id,
            gid: id,
            ..accepted.clone()
        };
        let _ = validate_portable_vm_child_identity_values(&rejected)
            .expect_err("primary ids outside the canonical four slots must fail closed");
        let _ = inrou_firewall_identity_slot(&rejected)
            .expect_err("firewall custody must reject identities outside canonical slots");
    }
    for (uid, gid) in [(70_000, 70_001), (70_003, 70_002)] {
        let rejected = PortableVmChildIdentity {
            uid,
            gid,
            ..accepted.clone()
        };
        let _ = validate_portable_vm_child_identity_values(&rejected)
            .expect_err("uid and primary gid must select the same canonical slot");
        let _ = inrou_firewall_identity_slot(&rejected)
            .expect_err("firewall custody must reject mismatched uid/gid slots");
    }
    for gid in [60_001, 65_534, 524_288, 2_147_483_648, u32::MAX] {
        let rejected = PortableVmChildIdentity {
            supplementary_gids: vec![gid],
            ..accepted.clone()
        };
        assert_eyre_error_contains(
            &validate_portable_vm_child_identity_values(&rejected)
                .expect_err("Linux host-reserved supplementary gids must fail closed"),
            "Inrou QEMU supplementary gid",
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn startup_owner_lock_remains_exclusive_through_transfer_and_binds_the_slot() -> Result<()> {
    let directory = canonical_runtime_fixture_tempdir()?;
    for slot in 0..4 {
        let path = directory.path().join(format!("slot-{slot}.lock"));
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        let guard = lock_inrou_owner_slot(file, slot)?;
        let identity = PortableVmChildIdentity {
            uid: 70_000 + slot as u32,
            gid: 70_000 + slot as u32,
            supplementary_gids: vec![108],
        };
        guard.require_identity(&identity)?;
        let other = PortableVmChildIdentity {
            uid: 70_000 + ((slot + 1) % 4) as u32,
            gid: 70_000 + ((slot + 1) % 4) as u32,
            supplementary_gids: vec![108],
        };
        assert!(guard.require_identity(&other).is_err());
        let open = || fs::OpenOptions::new().read(true).write(true).open(&path);
        assert!(
            lock_inrou_owner_slot(open()?, slot).is_err(),
            "same-slot supervisor must not enter the absence scan"
        );
        let transferred = guard;
        assert!(
            lock_inrou_owner_slot(open()?, slot).is_err(),
            "moving the guard into a probe/firewall must not unlock it"
        );
        transferred.require_identity(&identity)?;
        drop(transferred);
        drop(lock_inrou_owner_slot(open()?, slot)?);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inrou_executable_alternatives_fixture() -> (
    BTreeMap<PathBuf, InrouExecutablePathMetadata>,
    BTreeMap<PathBuf, PathBuf>,
) {
    let directory = InrouExecutablePathMetadata {
        device: 1,
        inode: 1,
        mode: 0o040755,
        uid: 0,
        gid: 0,
        links: 1,
        size: 0,
        modified: (1, 0),
        changed: (1, 0),
    };
    let mut metadata = BTreeMap::new();
    for (index, path) in ["/", "/usr", "/usr/sbin", "/etc", "/etc/alternatives"]
        .into_iter()
        .enumerate()
    {
        metadata.insert(
            PathBuf::from(path),
            InrouExecutablePathMetadata {
                inode: index as u64 + 1,
                ..directory
            },
        );
    }
    let links = BTreeMap::from([
        (PathBuf::from("/sbin"), PathBuf::from("usr/sbin")),
        (
            PathBuf::from("/usr/sbin/iptables"),
            PathBuf::from("/etc/alternatives/iptables"),
        ),
        (
            PathBuf::from("/etc/alternatives/iptables"),
            PathBuf::from("../../usr/sbin/iptables-nft"),
        ),
        (
            PathBuf::from("/usr/sbin/iptables-nft"),
            PathBuf::from("xtables-nft-multi"),
        ),
    ]);
    for (index, path) in links.keys().enumerate() {
        metadata.insert(
            path.clone(),
            InrouExecutablePathMetadata {
                inode: index as u64 + 10,
                mode: 0o120777,
                ..directory
            },
        );
    }
    metadata.insert(
        PathBuf::from("/usr/sbin/xtables-nft-multi"),
        InrouExecutablePathMetadata {
            inode: 20,
            mode: 0o100755,
            ..directory
        },
    );
    (metadata, links)
}

#[cfg(target_os = "linux")]
#[test]
fn inrou_executable_entry_admission_accepts_merged_usr_alternatives_and_preserves_dispatch_name() {
    let (metadata, links) = inrou_executable_alternatives_fixture();
    for name in ["/usr/sbin/iptables", "/sbin/iptables"] {
        let path = Path::new(name);
        let admitted = admit_inrou_root_custodied_executable_entry_with(
            path,
            |path| metadata.get(path).copied(),
            |path| links.get(path).cloned(),
        )
        .expect("root-custodied merged-/usr and alternatives entries must be admitted");
        assert_eq!(admitted, path);
        assert_eq!(
            admitted.file_name(),
            Some(OsStr::new("iptables")),
            "xtables must receive the original iptables entry name for argv[0] dispatch"
        );
        assert_ne!(admitted, Path::new("/usr/sbin/xtables-nft-multi"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn inrou_executable_entry_admission_rejects_untrusted_alias_chain_and_target() {
    let (metadata, links) = inrou_executable_alternatives_fixture();
    let alternatives = Path::new("/etc/alternatives");
    let alias = Path::new("/etc/alternatives/iptables");
    let resolved = Path::new("/usr/sbin/xtables-nft-multi");
    let mut cases = Vec::new();
    for path in [alternatives, alias, resolved] {
        for field in ["uid", "gid"] {
            let mut invalid = metadata[path];
            if field == "uid" {
                invalid.uid = 70_000;
            } else {
                invalid.gid = 70_000;
            }
            cases.push((path, invalid));
        }
    }
    for mode in [0o040777, 0o100755] {
        cases.push((
            alternatives,
            InrouExecutablePathMetadata {
                mode,
                ..metadata[alternatives]
            },
        ));
    }
    for mode in [0o104755, 0o102755, 0o100777, 0o100644, 0o040755] {
        cases.push((
            resolved,
            InrouExecutablePathMetadata {
                mode,
                ..metadata[resolved]
            },
        ));
    }
    for path in [alias, resolved] {
        cases.push((
            path,
            InrouExecutablePathMetadata {
                links: 2,
                ..metadata[path]
            },
        ));
    }
    for (path, invalid) in cases {
        let mut entries = metadata.clone();
        entries.insert(path.to_path_buf(), invalid);
        assert!(
            admit_inrou_root_custodied_executable_entry_with(
                Path::new("/usr/sbin/iptables"),
                |path| entries.get(path).copied(),
                |path| links.get(path).cloned(),
            )
            .is_none(),
            "must reject unchecked intermediate/target custody at {}: {invalid:?}",
            path.display()
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn inrou_executable_entry_admission_rejects_changed_or_cyclic_aliases() {
    let (metadata, links) = inrou_executable_alternatives_fixture();
    let alias = Path::new("/etc/alternatives/iptables");
    let candidate = Path::new("/usr/sbin/iptables");
    for target in [
        "/usr/sbin/iptables",
        "/missing",
        "xtables//multi",
        "xtables/",
        "/usr/sbin/xtables-nft-multi/.",
    ] {
        let mut targets = links.clone();
        targets.insert(alias.to_path_buf(), PathBuf::from(target));
        assert!(
            admit_inrou_root_custodied_executable_entry_with(
                candidate,
                |path| metadata.get(path).copied(),
                |path| targets.get(path).cloned(),
            )
            .is_none(),
            "must reject malformed, cyclic or unresolved target {target}"
        );
    }
    let mut reads = 0;
    assert!(
        admit_inrou_root_custodied_executable_entry_with(
            candidate,
            |path| metadata.get(path).copied(),
            |path| {
                if path == alias {
                    reads += 1;
                    if reads > 1 {
                        return Some(PathBuf::from("/usr/sbin/other"));
                    }
                }
                links.get(path).cloned()
            },
        )
        .is_none(),
        "a changed intermediate alias must fail admission"
    );
    let mut inspections = 0;
    assert!(
        admit_inrou_root_custodied_executable_entry_with(
            candidate,
            |path| {
                let mut entry = metadata.get(path).copied()?;
                if path == alias {
                    inspections += 1;
                    if inspections > 1 {
                        entry.inode += 1;
                    }
                }
                Some(entry)
            },
            |path| links.get(path).cloned(),
        )
        .is_none(),
        "a replaced intermediate inode must fail admission"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn inrou_public_host_slot_zero_requires_a_locked_service_account() -> Result<()> {
    let identity = PortableVmChildIdentity {
        uid: 70_000,
        gid: 70_000,
        supplementary_gids: vec![108],
    };
    validate_inrou_local_nsswitch("passwd: files\ngroup: files\nhosts: files dns\n")?;
    validate_inrou_local_nsswitch("passwd: files\ngroup: files\nSuBiD: files\n")?;
    for invalid in [
        "passwd: files sss\ngroup: files\n",
        "passwd: files\ngroup: compat\n",
        "passwd: files\n",
        "passwd: files\npasswd: files\ngroup: files\n",
        "passwd: files\ngroup: files\nSUBID: sss\n",
    ] {
        assert_eyre_error_contains_any(
            &validate_inrou_local_nsswitch(invalid)
                .expect_err("remote, missing, or ambiguous NSS identity sources must fail closed"),
            &[
                "/etc/nsswitch.conf",
                "NSS resolution",
                "requires deterministic `subid: files` resolution",
            ],
        );
    }

    let passwd = "root:x:0:0:root:/root:/bin/sh\niroha-inrou-0:x:70000:70000::/nonexistent:/usr/sbin/nologin\n";
    assert_eq!(
        validate_inrou_reserved_passwd(passwd, &identity)?,
        PathBuf::from("/usr/sbin/nologin")
    );
    for invalid in [
        "root:x:0:0:root:/root:/bin/sh\nother:x:70000:70000::/nonexistent:/usr/sbin/nologin\n",
        "root:x:0:0:root:/root:/bin/sh\n70000:x:70000:70000::/nonexistent:/usr/sbin/nologin\n",
        "root:x:0:0:root:/root:/bin/sh\niroha-inrou-1:x:70000:70000::/nonexistent:/usr/sbin/nologin\n",
        "root:x:0:0:root:/root:/bin/sh\niroha-inrou-0:x:70000:70001::/nonexistent:/usr/sbin/nologin\n",
        "root:x:0:0:root:/root:/bin/sh\niroha-inrou-0:x:70000:70000::/tmp/inrou:/usr/sbin/nologin\n",
        "root:x:0:0:root:/root:/bin/sh\niroha-inrou-0:x:70000:70000::/nonexistent:/bin/sh\n",
        "other:x:1234:70000::/nonexistent:/usr/sbin/nologin\niroha-inrou-0:x:70000:70000::/nonexistent:/usr/sbin/nologin\n",
    ] {
        assert_eyre_error_contains(
            &validate_inrou_reserved_passwd(invalid, &identity)
                .expect_err("an ambiguous or login-capable service passwd row must fail closed"),
            "passwd",
        );
    }

    let group = "root:x:0:\nkvm:x:108:\niroha-inrou-0:x:70000:\n";
    validate_inrou_reserved_group(group, &identity)?;
    for invalid in [
        "root:x:0:\nkvm:x:108:\nother:x:70000:\n",
        "root:x:0:\nkvm:x:108:\niroha-inrou-1:x:70000:\n",
        "root:x:0:\n108:x:108:\niroha-inrou-0:x:70000:\n",
        "root:x:0:\ndocker:x:999:iroha-inrou-0\niroha-inrou-0:x:70000:\n",
        "root:x:0:\niroha-inrou-0:x:70000:iroha-inrou-0\n",
    ] {
        assert_eyre_error_contains(
            &validate_inrou_reserved_group(invalid, &identity)
                .expect_err("ambiguous identity groups or memberships must fail closed"),
            "group",
        );
    }
    validate_inrou_reserved_shadow("iroha-inrou-0:!:20000:0:99999:7:::\n", &identity)?;
    let _unlocked_shadow_error =
        validate_inrou_reserved_shadow("iroha-inrou-0:$6$hash:20000:0:99999:7:::\n", &identity)
            .expect_err("an unlocked password must fail closed");
    let _wrong_slot_shadow_error =
        validate_inrou_reserved_shadow("iroha-inrou-1:!:20000:0:99999:7:::\n", &identity)
            .expect_err("a shadow row for a different canonical slot must fail closed");
    validate_inrou_reserved_gshadow("iroha-inrou-0:!::\n", &identity)?;
    for invalid in [
        "iroha-inrou-1:!::\n",
        "iroha-inrou-0:!:root:iroha-inrou-0\n",
        "docker:!:iroha-inrou-0:\niroha-inrou-0:!::\n",
    ] {
        let _gshadow_membership_error = validate_inrou_reserved_gshadow(invalid, &identity)
            .expect_err("gshadow administrators or members must fail closed");
    }

    validate_inrou_subordinate_id_unmapped("alice:100000:65536\n", "subuid", 99_999, &identity)?;
    validate_inrou_subordinate_id_unmapped("alice:100000:65536\n", "subuid", 165_536, &identity)?;
    for covered in [100_000, 165_535] {
        let _covered_subid_error = validate_inrou_subordinate_id_unmapped(
            "alice:100000:65536\n",
            "subuid",
            covered,
            &identity,
        )
        .expect_err("both subordinate-range boundaries must reserve the child id");
    }
    let _highest_subid_error = validate_inrou_subordinate_id_unmapped(
        "alice:4294967294:1\n",
        "subuid",
        u32::MAX - 1,
        &identity,
    )
    .expect_err("the highest valid subordinate id range must be enforced");
    for forbidden_owner in ["iroha-inrou-0:200000:1\n", "70000:200000:1\n"] {
        let _forbidden_subid_owner_error =
            validate_inrou_subordinate_id_unmapped(forbidden_owner, "subuid", 70_000, &identity)
                .expect_err("service and numeric identity owners must not receive subids");
    }
    for malformed in [
        "alice:100000:0\n",
        "alice:4294967295:2\n",
        "alice:not-a-number:1\n",
        "alice:100000\n",
    ] {
        let _malformed_subid_error =
            validate_inrou_subordinate_id_unmapped(malformed, "subgid", 70_000, &identity)
                .expect_err("malformed, empty, or overflowing subordinate ranges must fail closed");
    }
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_same_host_identity_databases_accept_all_four_slots() -> Result<()> {
    let passwd = concat!(
        "root:x:0:0:root:/root:/bin/sh\n",
        "iroha-inrou-0:x:70000:70000::/nonexistent:/usr/sbin/nologin\n",
        "iroha-inrou-1:x:70001:70001::/nonexistent:/usr/sbin/nologin\n",
        "iroha-inrou-2:x:70002:70002::/nonexistent:/usr/sbin/nologin\n",
        "iroha-inrou-3:x:70003:70003::/nonexistent:/usr/sbin/nologin\n",
    );
    let group = concat!(
        "root:x:0:\n",
        "kvm:x:108:\n",
        "iroha-inrou-0:x:70000:\n",
        "iroha-inrou-1:x:70001:\n",
        "iroha-inrou-2:x:70002:\n",
        "iroha-inrou-3:x:70003:\n",
    );
    let shadow = concat!(
        "iroha-inrou-0:!:20000:0:99999:7:::\n",
        "iroha-inrou-1:!:20000:0:99999:7:::\n",
        "iroha-inrou-2:!:20000:0:99999:7:::\n",
        "iroha-inrou-3:!:20000:0:99999:7:::\n",
    );
    let gshadow = concat!(
        "iroha-inrou-0:!::\n",
        "iroha-inrou-1:!::\n",
        "iroha-inrou-2:!::\n",
        "iroha-inrou-3:!::\n",
    );
    for slot in
        0..iroha_config::parameters::defaults::soracloud_runtime::INROU_PORTABLE_VM_ID_SLOT_COUNT
    {
        let id = SORACLOUD_INROU_ID_BASE + slot;
        let identity = PortableVmChildIdentity {
            uid: id,
            gid: id,
            supplementary_gids: vec![108],
        };
        validate_portable_vm_child_identity_values(&identity)?;
        assert_eq!(
            validate_inrou_reserved_passwd(passwd, &identity)?,
            PathBuf::from("/usr/sbin/nologin")
        );
        validate_inrou_reserved_group(group, &identity)?;
        validate_inrou_reserved_shadow(shadow, &identity)?;
        validate_inrou_reserved_gshadow(gshadow, &identity)?;
        validate_inrou_subordinate_id_unmapped(
            "alice:200000:65536\n",
            "subuid",
            identity.uid,
            &identity,
        )?;
    }
    Ok(())
}
#[test]
fn portable_vm_kvm_device_custody_fails_closed() {
    let identity = PortableVmChildIdentity {
        uid: 70_000,
        gid: 70_001,
        supplementary_gids: vec![108],
    };
    let secure = PortableVmKvmDeviceAccess {
        uid: 0,
        gid: 108,
        mode: 0o660,
        hard_links: 1,
        rdev: SORACLOUD_INROU_KVM_DEVICE_RDEV,
        is_character_device: true,
    };
    for insecure in [
        PortableVmKvmDeviceAccess { uid: 1, ..secure },
        PortableVmKvmDeviceAccess {
            mode: 0o666,
            ..secure
        },
        PortableVmKvmDeviceAccess {
            mode: 0o640,
            ..secure
        },
        PortableVmKvmDeviceAccess {
            hard_links: 2,
            ..secure
        },
        PortableVmKvmDeviceAccess {
            rdev: SORACLOUD_INROU_KVM_DEVICE_RDEV + 1,
            ..secure
        },
        PortableVmKvmDeviceAccess {
            is_character_device: false,
            ..secure
        },
    ] {
        assert_eyre_error_contains(
            &validate_portable_vm_kvm_identity(&identity, insecure)
                .expect_err("insecure `/dev/kvm` custody must fail closed"),
            "`/dev/kvm`",
        );
    }
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_qmp_uses_only_the_anonymous_stdio_socketpair() -> Result<()> {
    let mut command = Command::new("unused-qemu-test-command");
    let _supervisor_qmp = configure_inrou_qmp_stdio(&mut command)?;
    let qmp_args = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(qmp_args, ["-qmp", "stdio", "-serial", "none"]);
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_startup_probe_stderr_stops_with_an_open_descendant_writer() -> Result<()> {
    let (reader, _retained_descendant_writer) = std::os::unix::net::UnixStream::pair()?;
    let cancellation = reader.try_clone()?;
    let drain = thread::spawn(move || drain_host_command_stdout_bounded(reader, 16 * 1024));
    let started = std::time::Instant::now();
    let captured = finish_inrou_startup_probe_stderr_bounded(drain, &cancellation)?;
    assert_eq!(captured, (vec![], false));
    assert!(started.elapsed() < SORACLOUD_INROU_LOG_DRAIN_STOP_TIMEOUT * 3);
    Ok(())
}
#[cfg(not(windows))]
#[test]
fn inrou_startup_probe_reports_the_actual_launcher_exit() -> Result<()> {
    let mut child = Command::new("/bin/sh").args(["-c", "exit 42"]).spawn()?;
    child.wait()?;
    let error = require_inrou_launcher_running(&mut child)
        .expect_err("an exited launcher cannot become ready");
    assert!(error.to_string().contains("status"));
    assert!(error.to_string().contains("42"));
    Ok(())
}
#[test]
fn inrou_startup_probe_stderr_retains_bounded_failure_and_sanitizes_controls() -> Result<()> {
    let prefix = b"qemu: Invalid parameter 'exit-with-parent'\n\x1b[31m";
    let mut bytes = prefix.to_vec();
    bytes.extend(std::iter::repeat_n(b'x', 32 * 1024));
    let captured = drain_host_command_stdout_bounded(io::Cursor::new(bytes), 16 * 1024)?;
    assert_eq!(captured.0.len(), 16 * 1024);
    assert!(captured.1);
    let message = inrou_startup_probe_stderr_context(&Ok(captured));
    assert!(message.contains("Invalid parameter 'exit-with-parent'"));
    assert!(message.contains("stderr truncated"));
    assert!(!message.chars().any(char::is_control));
    let empty = inrou_startup_probe_stderr_context(&Ok((vec![], false)));
    assert!(empty.contains("stderr was empty"));
    let failed = inrou_startup_probe_stderr_context(&Err(eyre::eyre!("drain failed")));
    assert!(failed.contains("drain failed"));
    Ok(())
}
#[cfg(not(windows))]
#[test]
fn inrou_child_termination_kills_and_reaps_without_blocking() -> Result<()> {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "while :; do :; done"])
        .spawn()?;
    let started_at = std::time::Instant::now();
    let status = terminate_inrou_child_bounded(&mut child)?;
    assert!(!status.success());
    assert!(started_at.elapsed() < SORACLOUD_INROU_CHILD_STOP_TIMEOUT);
    assert!(
        child.try_wait()?.is_some(),
        "the killed child must be reaped"
    );
    Ok(())
}
#[cfg(not(windows))]
#[test]
fn inrou_host_command_runner_enforces_deadline() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let helper = temp_dir.path().join("inrou-never-finishes");
    fs::write(&helper, "#!/bin/sh\nwhile :; do :; done\n")?;
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))?;

    let error = run_host_command_with_timeout(&helper, &[], Duration::from_millis(50))
        .expect_err("a stuck host command must be terminated at its deadline");
    assert!(error.to_string().contains("execution deadline"));
    Ok(())
}
#[cfg(not(windows))]
#[test]
fn inrou_host_command_capture_caps_output_and_enforces_deadline() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let oversized = temp_dir.path().join("inrou-oversized-output");
    fs::write(
        &oversized,
        "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 70000 ]; do printf x; i=$((i + 1)); done\n",
    )?;
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o700))?;
    let error =
        run_host_command_capture_stdout_bounded(&oversized, &[], Duration::from_secs(5), 64 * 1024)
            .expect_err("oversized host-command output must be rejected");
    assert!(error.to_string().contains("stdout limit"));

    let stalled = temp_dir.path().join("inrou-stalled-output");
    fs::write(&stalled, "#!/bin/sh\nwhile :; do :; done\n")?;
    fs::set_permissions(&stalled, fs::Permissions::from_mode(0o700))?;
    let error =
        run_host_command_capture_stdout_bounded(&stalled, &[], Duration::from_millis(50), 64)
            .expect_err("stalled host-command output must be terminated");
    assert!(error.to_string().contains("execution deadline"));
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_runtime_log_drain_caps_output_and_marks_truncation() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let directory = secure_test_inrou_disk_directory(&temp_dir)?;
    let log_path = temp_dir.path().join("bounded.log");
    let log = open_inrou_runtime_log(&directory, OsStr::new("bounded.log"), "test Inrou log")?;
    let oversized = vec![
        b'x';
        usize::try_from(SORACLOUD_INROU_LOG_MAX_BYTES)
            .expect("fixture log size fits usize")
            + 1_024
    ];

    drain_inrou_runtime_log_bounded(io::Cursor::new(oversized), log)?;

    let contents = fs::read(&log_path)?;
    assert_eq!(contents.len() as u64, SORACLOUD_INROU_LOG_MAX_BYTES);
    assert!(contents.ends_with(SORACLOUD_INROU_LOG_TRUNCATION_MARKER));
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_runtime_logs_reject_links_and_unsafe_permissions() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let directory = secure_test_inrou_disk_directory(&temp_dir)?;
    let target = temp_dir.path().join("target.log");
    fs::write(&target, b"retain-me")?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;

    let symbolic = temp_dir.path().join("symbolic.log");
    std::os::unix::fs::symlink(&target, &symbolic)?;
    open_inrou_runtime_log(&directory, OsStr::new("symbolic.log"), "test Inrou log")
        .expect_err("a runtime log must not follow a symbolic link");

    let hard = temp_dir.path().join("hard.log");
    fs::hard_link(&target, &hard)?;
    open_inrou_runtime_log(&directory, OsStr::new("target.log"), "test Inrou log")
        .expect_err("a multiply linked runtime log must fail before truncation");
    assert_eq!(fs::read(&target)?, b"retain-me");
    fs::remove_file(hard)?;

    fs::set_permissions(&target, fs::Permissions::from_mode(0o644))?;
    open_inrou_runtime_log(&directory, OsStr::new("target.log"), "test Inrou log")
        .expect_err("a runtime log readable by other users must fail closed");
    assert_eq!(fs::read(&target)?, b"retain-me");
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_disk_install_never_replaces_existing_state() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let directory = secure_test_inrou_disk_directory(&temp_dir)?;
    let installed = temp_dir.path().join("installed.raw");
    fs::write(&installed, b"old!")?;
    fs::set_permissions(&installed, fs::Permissions::from_mode(0o600))?;
    let mut staged = create_unique_inrou_disk_staging_file(&directory, "installed.raw")?;
    staged.file.write_all(b"new!")?;
    staged.file.sync_all()?;

    assert_eyre_error_contains(
        &install_staged_inrou_disk(
            &directory,
            &mut staged,
            OsStr::new("installed.raw"),
            Some(4),
        )
        .expect_err("installing a staged disk must never replace existing lease state"),
        "without replacing existing state",
    );
    assert_eq!(fs::read(&installed)?, b"old!");
    assert_eq!(fs::read(directory.path().join(&staged.name))?, b"new!");
    Ok(())
}
#[test]
fn build_inrou_portable_network_config_matches_predictable_interface_names() {
    let network_config = build_inrou_portable_network_config();
    assert!(network_config.contains("match:\n      name: \"e*\""));
    assert!(network_config.contains("dhcp4: true"));
    assert!(!network_config.contains("  eth0:\n"));
}
#[test]
fn inrou_bundle_member_paths_require_canonical_portable_components() {
    assert_eq!(
        canonical_inrou_bundle_member_components("/app/bin/service")
            .expect("canonical bundle member"),
        ["app", "bin", "service"]
    );
    for invalid in [
        "app/bin/service",
        "/",
        "//app/bin/service",
        "/app/bin/service/",
        "/app/../service",
        "/app/./service",
        "/app/servicé",
        "/app/CON",
        "/app/service:stream",
        "/app/service name",
        "/app/service!",
        "/app/service.",
    ] {
        let _ = canonical_inrou_bundle_member_components(invalid)
            .expect_err("nonportable bundle member must fail");
    }
    let _ = canonical_inrou_bundle_member_components(&format!("/{}", "a".repeat(256)))
        .expect_err("bundle member beyond the canonical USTAR path bound must fail");
}
#[cfg(unix)]
#[test]
fn inrou_bundle_member_resolution_rejects_symbolic_link_escape() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let bundle_root = temp_dir.path().join("bundle");
    let outside = temp_dir.path().join("outside");
    fs::create_dir_all(&bundle_root)?;
    fs::create_dir_all(&outside)?;
    fs::write(outside.join("service"), b"outside")?;
    std::os::unix::fs::symlink(&outside, bundle_root.join("app"))?;
    let _ = resolve_inrou_bundle_member_path(&bundle_root, "/app/service")
        .expect_err("symbolic-link escape must fail");
    Ok(())
}
#[test]
fn systemd_write_path_quoting_blocks_specifier_and_token_substitution() {
    assert_eq!(
        systemd_quote_path("/var/lib/a path/%n/\"quoted\"/\\tail"),
        "\"/var/lib/a path/%%n/\\\"quoted\\\"/\\\\tail\""
    );
}
#[test]
fn systemd_mount_path_escaping_is_exact_and_collision_free() -> Result<()> {
    assert_eq!(
        systemd_escape_path("/var/lib/soracloud/volumes/index_state.v1")?,
        "var-lib-soracloud-volumes-index_state.v1"
    );
    assert_eq!(
        systemd_escape_path("/var/lib/soracloud/volumes/index-state")?,
        r"var-lib-soracloud-volumes-index\x2dstate"
    );
    assert_ne!(systemd_escape_path("/a/b")?, systemd_escape_path("/a-b")?);
    Ok(())
}
#[test]
fn inrou_lease_filesystem_uuid_is_deterministic_and_replica_bound() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (_temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let volume = replica_plan
        .lease_volumes
        .iter()
        .find(|volume| volume.kind == SoraLeaseVolumeKindV1::ServiceLeaseVolume)
        .expect("data volume");
    let first = inrou_lease_filesystem_uuid(&replica_plan, volume)?;
    assert_eq!(first, inrou_lease_filesystem_uuid(&replica_plan, volume)?);
    assert!(is_canonical_inrou_filesystem_uuid(&first));
    let mut replacement_plan = replica_plan.clone();
    replacement_plan.local_replica_slots = vec![2];
    replacement_plan.local_replicas[0].replica_slot = 2;
    assert_ne!(
        first,
        inrou_lease_filesystem_uuid(&replacement_plan, volume)?,
        "a disk UUID from one replica must not attest another replica"
    );
    let mut replacement_incarnation = replica_plan.clone();
    replacement_incarnation.local_replicas[0].placement_incarnation =
        Hash::new(b"replacement-placement-incarnation").to_string();
    assert_ne!(
        first,
        inrou_lease_filesystem_uuid(&replacement_incarnation, volume)?,
        "a disk UUID from one placement incarnation must not attest another"
    );
    let mut replacement_volume = volume.clone();
    replacement_volume.volume_name = "private_state".to_owned();
    replacement_volume.kind = SoraLeaseVolumeKindV1::ConfidentialLeaseVolume;
    assert_ne!(
        first,
        inrou_lease_filesystem_uuid(&replica_plan, &replacement_volume)?
    );
    Ok(())
}
#[test]
fn build_inrou_user_data_projects_isolated_portable_block_mounts() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (_temp_dir, replica_plan, cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    assert_eq!(
        replica_plan
            .effective_env
            .get("SORACLOUD_SERVICE_VERSION")
            .map(String::as_str),
        Some(bundle.service.service_version.as_str())
    );
    let data_mounts = vec![InrouDataVolumeMount {
        mount_path: "/var/lib/soracloud/volumes/index_state".to_owned(),
        kind: InrouDataVolumeMountKind::BlockDevice {
            device_serial: "sora-index_state".to_owned(),
            filesystem_type: "ext4".to_owned(),
            filesystem_uuid: "11111111-2222-8333-8444-555555555555".to_owned(),
            mount_options: INROU_PORTABLE_VOLUME_MOUNT_OPTIONS.to_owned(),
            initialize_filesystem: true,
        },
    }];
    let user_data = build_inrou_user_data(
        &cache_key,
        bundle
            .service
            .route
            .as_ref()
            .expect("route")
            .service_port
            .get(),
        &bundle.container.resources,
        &data_mounts,
        Duration::from_millis(12_345),
        Some("127.0.0.1 model.internal\n"),
        Some(PortableVmBundleBinding {
            expected_hash: bundle.container.bundle_hash,
            exact_bytes: 21,
            maximum_bytes: 512 * 1024 * 1024,
        }),
    )?;
    assert!(user_data.contains("/dev/disk/by-id/virtio-sora_bundle"));
    assert!(user_data.contains("export SORACLOUD_SERVICE_VERSION='2026.02.0'"));
    assert!(user_data.contains("/var/lib/soracloud/materialization/bundle"));
    assert!(user_data.contains("hashlib.blake2b(digest_size=32)"));
    assert!(user_data.contains("bundle_exact_bytes='21'"));
    assert!(user_data.contains("bundle_max_bytes='536870912'"));
    assert!(user_data.contains("while remaining:"));
    assert!(user_data.contains("source_handle.read(min(65536, remaining))"));
    assert!(user_data.contains("if total != exact_bytes:"));
    assert!(user_data.contains(".bundle-stage.XXXXXX"));
    assert!(user_data.contains(".bundle-backup.XXXXXX"));
    assert!(user_data.contains("multiple interrupted PortableVm bundle backups"));
    assert!(user_data.contains("mv -- \"$bundle_backup\" \"$bundle_root\""));
    assert!(user_data.contains("mv -- \"$bundle_stage\" \"$bundle_root\""));
    assert!(!user_data.contains(".bundle_hash"));
    assert!(!user_data.contains("urllib"));
    assert!(!user_data.contains("datasource_url"));
    assert!(!user_data.contains("http://"));
    assert!(!user_data.contains("https://"));
    assert!(!user_data.contains("rm -rf \"$bundle_root\""));
    assert!(user_data.contains("chown root:root -- /var/lib/soracloud/materialization"));
    assert!(user_data.contains("chmod 0755 -- /var/lib/soracloud/materialization"));
    assert!(user_data.contains("chown inrou:inrou -- /var/lib/soracloud/service"));
    assert!(user_data.contains("chmod 0750 -- /var/lib/soracloud/service"));
    assert!(user_data.contains("chown root:root -- /var/lib/soracloud/volumes"));
    assert!(user_data.contains("chmod 0755 -- /var/lib/soracloud/volumes"));
    assert!(user_data.contains("chown -R root:root -- \"$bundle_stage\""));
    assert!(user_data.contains("chmod -R a+rX,go-w,u-s,g-s -- \"$bundle_stage\""));
    assert!(!user_data.contains("chown -R inrou:inrou"));
    assert!(
        !user_data
            .contains("mkdir -p /var/lib/soracloud/service /var/lib/soracloud/materialization")
    );
    assert!(user_data.contains("/etc/soracloud/allowlist-hosts"));
    assert!(user_data.contains("127.0.0.1 model.internal"));
    assert!(user_data.contains("mktemp /run/inrou-prepare/soracloud-hosts.XXXXXX"));
    assert!(!user_data.contains("/tmp/soracloud-hosts"));
    assert!(user_data.contains("mktemp /run/inrou-prepare/soracloud-bundle.XXXXXX.tgz"));
    assert!(!user_data.contains("/tmp/soracloud-bundle"));
    assert!(user_data.contains("/dev/disk/by-id/virtio-sora-index_state"));
    assert!(user_data.contains("Inrou volume mount path must not be pre-mounted: $mount_path"));
    assert!(user_data.contains("if mountpoint -q \"$mount_path\"; then"));
    assert_eq!(
        user_data
            .matches("mkfs.ext4 -F -E nodiscard -U \"$expected_uuid\" \"$expected_device\"",)
            .count(),
        1,
        "only an explicitly new volume may be formatted, exactly once"
    );
    assert!(
        user_data
            .contains("new Inrou PortableVm volume contains an unexpected filesystem identity")
    );
    assert!(!user_data.contains("reformat"));
    assert!(!user_data.contains("mount -t"));
    assert!(!user_data.contains("umount"));
    assert!(!user_data.contains("nofail"));
    assert!(!user_data.contains(".inrou-volume-check"));
    assert!(user_data.contains("expected_device=$(readlink -f -- \"$device_path\")"));
    assert!(user_data.contains("expected_device_identity=$(stat -c '%t:%T'"));
    assert!(user_data.contains("findmnt -n -o SOURCE --target \"$mount_path\""));
    assert!(user_data.contains("findmnt -n -o FSTYPE --target \"$mount_path\""));
    assert!(user_data.contains("findmnt -n -o OPTIONS --target \"$mount_path\""));
    assert!(user_data.contains(
        "for required_option in rw nosuid nodev noexec nosymfollow errors=remount-ro; do"
    ));
    assert!(user_data.contains("mounted_uuid=$(blkid -s UUID -o value"));
    assert!(user_data.contains("chown inrou:inrou -- \"$mount_path\""));
    assert!(user_data.contains("chmod 0700 -- \"$mount_path\""));
    assert!(!user_data.contains("chown inrou:inrou -- \"$mount_path\" 2>/dev/null || true"));
    assert!(!user_data.contains("chmod 0700 -- \"$mount_path\" 2>/dev/null || true"));
    assert!(user_data.contains("mounted_owner=$(stat -c '%u:%g' -- \"$mount_path\")"));
    assert!(user_data.contains("mounted_mode=$(stat -c '%a' -- \"$mount_path\")"));
    assert!(user_data.contains("mktemp \"$mount_path/.inrou-attest.XXXXXX\""));
    assert!(user_data.contains("sync -f \"$probe_path\""));
    assert_eq!(user_data.matches("StandardOutput=null").count(), 3);
    assert_eq!(user_data.matches("StandardError=null").count(), 3);
    assert_eq!(user_data.matches("LimitCORE=0").count(), 3);
    assert!(!user_data.contains("/dev/console"));
    assert!(!user_data.contains("journal+console"));
    assert!(user_data.contains("TimeoutStopSec=12345ms"));
    assert!(user_data.contains("/etc/systemd/system/inrou-prepare.service"));
    assert!(user_data.contains("/etc/systemd/system/var-lib-soracloud-volumes-index_state.mount"));
    assert!(user_data.contains(
        "/etc/systemd/system/var-lib-soracloud-volumes-index_state-inrou-attest.service"
    ));
    assert!(user_data.contains("What=/dev/disk/by-id/virtio-sora-index_state"));
    assert!(user_data.contains("Where=/var/lib/soracloud/volumes/index_state"));
    assert!(user_data.contains("Type=ext4"));
    assert!(user_data.contains("Options=rw,nosuid,nodev,noexec,nosymfollow,errors=remount-ro"));
    assert!(user_data.contains("DirectoryMode=0700"));
    assert!(user_data.contains("TimeoutSec=15s"));
    assert!(user_data.contains("Before=inrou-app.service"));
    assert!(user_data.contains("Requires=inrou-prepare.service"));
    assert!(user_data.contains(
        "Requires=var-lib-soracloud-volumes-index_state.mount var-lib-soracloud-volumes-index_state-inrou-attest.service"
    ));
    assert!(user_data.contains(
        "After=var-lib-soracloud-volumes-index_state.mount var-lib-soracloud-volumes-index_state-inrou-attest.service"
    ));
    assert!(user_data.contains("BindsTo=var-lib-soracloud-volumes-index_state.mount"));
    assert!(
        user_data.contains("AssertPathIsMountPoint=\"/var/lib/soracloud/volumes/index_state\"")
    );
    assert!(user_data.contains("PrivateMounts=true"));
    assert!(!user_data.contains("PermissionsStartOnly"));
    assert!(!user_data.contains("ExecStartPre="));
    assert!(!user_data.contains("listener_inodes"));
    assert!(!user_data.contains("/proc/net/tcp"));
    assert!(!user_data.contains("os.kill"));
    assert!(!user_data.contains("SIGKILL"));
    assert!(!user_data.contains("CAP_SYS_ADMIN"));
    assert!(user_data.contains("CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER"));
    assert!(user_data.contains("ProtectSystem=strict"));
    assert!(user_data.contains("RuntimeDirectory=inrou-prepare"));
    assert!(user_data.contains("RuntimeDirectoryMode=0700"));
    assert!(user_data.contains(
        "ReadWritePaths=/etc/hosts /run/inrou-prepare /var/lib/soracloud/materialization /var/lib/soracloud/service /var/lib/soracloud/volumes"
    ));
    assert_eq!(
        user_data.matches("NoNewPrivileges=true").count(),
        3,
        "preparation, attestation, and tenant app services must prohibit privilege gain"
    );
    assert_eq!(
        user_data.matches("RestrictSUIDSGID=true").count(),
        3,
        "all generated services must prohibit set-ID file creation"
    );
    for hardening in [
        "NoNewPrivileges=true",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "RestrictSUIDSGID=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "PrivateDevices=true",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectKernelLogs=true",
        "ProtectControlGroups=true",
        "ProtectClock=true",
        "LockPersonality=true",
        "RestrictNamespaces=true",
    ] {
        assert!(
            user_data.contains(hardening),
            "Inrou app unit omits `{hardening}`"
        );
    }
    assert_eq!(
        user_data.matches("PrivateTmp=true\n").count(),
        1,
        "only the volume-attestation unit may have a private uncapped temporary directory"
    );
    assert!(user_data.contains(
        "ReadWritePaths=\"/var/lib/soracloud/service\" \"/var/lib/soracloud/volumes/index_state\""
    ));
    assert!(user_data.contains(
        "TemporaryFileSystem=/var/lib/soracloud/service:rw,nosuid,nodev,noexec,mode=0700,uid=1000,gid=1000,size=2147483648"
    ));
    assert!(user_data.contains("LimitNOFILE=512"));
    assert!(user_data.contains("TasksMax=64"));
    assert!(user_data.contains("CPUAccounting=true"));
    assert!(user_data.contains("CPUQuotaPeriodSec=100ms"));
    assert!(user_data.contains("CPUQuota=75%"));
    assert!(user_data.contains("MemoryAccounting=true"));
    assert!(user_data.contains("MemoryMax=536870912"));
    assert!(user_data.contains("MemorySwapMax=0"));
    assert!(
        user_data.contains("ReadOnlyPaths=/var/lib/soracloud/materialization /tmp /var/tmp /run")
    );
    assert!(user_data.contains("InaccessiblePaths=/dev/shm /dev/mqueue"));
    assert!(user_data.contains("disable_root: true"));
    assert!(user_data.contains("ssh_pwauth: false"));
    assert!(user_data.contains("    groups: []"));
    assert!(
        user_data.contains("install -d -o root -g root -m 0755 /var/lib/soracloud/materialization")
    );
    assert!(user_data.contains("install -d -o inrou -g inrou -m 0750 /var/lib/soracloud/service"));
    assert!(user_data.contains("install -d -o root -g root -m 0755 /var/lib/soracloud/volumes"));
    assert!(user_data.contains("usermod --lock --shell /usr/sbin/nologin root"));
    assert_eq!(
        user_data.matches("    shell: /usr/sbin/nologin\n").count(),
        2,
        "both root and the tenant account must have a non-login shell"
    );
    assert_eq!(
        user_data.matches("    lock_passwd: true\n").count(),
        2,
        "both root and the tenant account must have locked passwords"
    );
    assert!(
        user_data.contains("systemctl mask --now ssh.service ssh.socket sshd.service sshd.socket")
    );
    assert!(user_data.contains(INROU_GUEST_HARDENING_MARKER_PATH));
    assert!(user_data.contains("root_shadow_entry=$(getent shadow root"));
    assert!(user_data.contains("Inrou guest root password must remain locked"));
    assert!(user_data.contains("root_shell=${root_passwd_entry##*:}"));
    assert!(user_data.contains("Inrou guest root shell must be /usr/sbin/nologin"));
    assert!(user_data.contains("for unit in ssh.service ssh.socket sshd.service sshd.socket"));
    assert!(user_data.contains("readlink -f -- \"$mask_path\""));
    assert!(user_data.contains("systemctl --quiet is-active \"$unit\""));
    for marker_line in INROU_GUEST_HARDENING_MARKER_BODY.lines() {
        assert!(user_data.contains(marker_line));
    }
    assert!(user_data.contains("chmod 0444 -- \"$hardening_tmp\""));
    assert!(user_data.contains("mv -- \"$hardening_tmp\" \"$hardening_marker\""));
    assert!(!user_data.contains("ssh_authorized_keys"));
    assert!(!user_data.contains("shell: /bin/bash"));
    assert!(!user_data.contains("groups: [sudo]"));
    assert!(!user_data.contains("NOPASSWD"));
    assert!(!user_data.contains("mount.nfs"));
    assert!(!user_data.contains("virtiofs"));
    Ok(())
}
#[test]
fn build_inrou_user_data_projects_exact_guest_resource_limits() -> Result<()> {
    let mut bundle = sample_inrou_test_bundle()?;
    bundle.container.resources.cpu_millis =
        std::num::NonZeroU32::new(1_230).expect("exact CPU limit");
    bundle.container.resources.memory_bytes =
        NonZeroU64::new(384 * 1024 * 1024).expect("exact memory limit");
    bundle.container.resources.ephemeral_storage_bytes =
        NonZeroU64::new(12 * 1024 * 1024).expect("aligned nonzero storage limit");
    bundle.container.resources.max_open_files_per_process =
        std::num::NonZeroU32::new(777).expect("nonzero file limit");
    bundle.container.resources.max_tasks =
        std::num::NonZeroU16::new(123).expect("nonzero task limit");
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle.validate_for_admission()?;
    let (_temp_dir, _replica_plan, mut cache_key) =
        materialize_inrou_replica_plan_for_tests(&bundle)?;
    cache_key
        .effective_env
        .insert("TMPDIR".to_owned(), "/tmp".to_owned());
    cache_key
        .effective_env
        .insert("TMP".to_owned(), "/var/tmp".to_owned());
    cache_key
        .effective_env
        .insert("TEMP".to_owned(), "/run".to_owned());

    let user_data = build_inrou_user_data(
        &cache_key,
        8080,
        &bundle.container.resources,
        &[],
        Duration::from_secs(10),
        None,
        None,
    )?;

    assert_eq!(user_data.matches("LimitNOFILE=777\n").count(), 1);
    assert_eq!(user_data.matches("TasksMax=123\n").count(), 1);
    assert_eq!(user_data.matches("CPUQuotaPeriodSec=100ms\n").count(), 1);
    assert_eq!(user_data.matches("CPUQuota=123%\n").count(), 1);
    assert_eq!(user_data.matches("MemoryMax=402653184\n").count(), 1);
    assert_eq!(user_data.matches("MemorySwapMax=0\n").count(), 1);
    assert_eq!(
        user_data
            .matches(
                "TemporaryFileSystem=/var/lib/soracloud/service:rw,nosuid,nodev,noexec,mode=0700,uid=1000,gid=1000,size=12582912\n",
            )
            .count(),
        1
    );
    assert_eq!(
        user_data.matches("PrivateTmp=true\n").count(),
        0,
        "without a leased volume there is no attestation unit, and neither preparation nor the tenant app may receive a private uncapped /tmp"
    );
    assert!(
        user_data.contains("ReadOnlyPaths=/var/lib/soracloud/materialization /tmp /var/tmp /run\n")
    );
    assert!(user_data.contains("InaccessiblePaths=/dev/shm /dev/mqueue\n"));
    assert!(user_data.contains("ReadWritePaths=\"/var/lib/soracloud/service\"\n"));
    assert!(user_data.contains("mkdir -p -- /var/lib/soracloud/service/tmp\n"));
    assert!(user_data.contains("chmod 0700 -- /var/lib/soracloud/service/tmp\n"));
    for (name, requested, enforced) in [
        (
            "TMPDIR",
            "export TMPDIR='/tmp'\n",
            "export TMPDIR=/var/lib/soracloud/service/tmp\n",
        ),
        (
            "TMP",
            "export TMP='/var/tmp'\n",
            "export TMP=/var/lib/soracloud/service/tmp\n",
        ),
        (
            "TEMP",
            "export TEMP='/run'\n",
            "export TEMP=/var/lib/soracloud/service/tmp\n",
        ),
    ] {
        let requested_position = user_data
            .find(requested)
            .unwrap_or_else(|| panic!("missing requested {name} fixture"));
        let enforced_position = user_data
            .find(enforced)
            .unwrap_or_else(|| panic!("missing enforced {name} projection"));
        assert!(
            enforced_position > requested_position,
            "the runtime-owned {name} projection must override tenant input"
        );
    }
    Ok(())
}
#[test]
fn build_inrou_user_data_rejects_unrepresentable_resource_limits() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (_temp_dir, _replica_plan, cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let mut resources = bundle.container.resources;
    resources.cpu_millis = std::num::NonZeroU32::new(751).expect("nonzero unaligned CPU fixture");

    assert_report_contains(
        &build_inrou_user_data(
            &cache_key,
            8080,
            &resources,
            &[],
            Duration::from_secs(10),
            None,
            None,
        )
        .expect_err("an unrepresentable CPU quota must fail before cloud-init generation"),
        "multiple of 10 millicores",
    );
    Ok(())
}
#[test]
fn inrou_data_volume_mount_validation_reserves_system_and_custody_paths() {
    validate_inrou_data_volume_mount_path("index_state", "/var/lib/soracloud/volumes/index_state")
        .expect("exact volume-name binding is canonical");
    validate_inrou_guest_data_mount_path("/var/lib/soracloud/volumes/index_state")
        .expect("one canonical child is a safe generated mount");

    for invalid in [
        "/",
        "/etc",
        "/var/lib/soracloud/service",
        "/var/lib/soracloud/materialization",
        "/var/lib/soracloud/volumes",
        "/var/lib/soracloud/volumes/index_state/nested",
    ] {
        let _ = validate_inrou_guest_data_mount_path(invalid)
            .expect_err("system, custody, root, and nested paths must fail closed");
    }
    let _ =
        validate_inrou_data_volume_mount_path("index_state", "/var/lib/soracloud/volumes/other")
            .expect_err("runtime path must remain bound to its canonical volume name");
    assert_eq!(
        portable_vm_block_device_serial("index_state").expect("bounded exact serial"),
        "sora-index_state"
    );
    let _ = portable_vm_block_device_serial("same_prefix_name_a")
        .expect_err("volume names may not be truncated into colliding virtio serials");
    let _ = portable_vm_block_device_serial("same_prefix_name_b")
        .expect_err("volume names may not be truncated into colliding virtio serials");
}
#[test]
fn build_inrou_user_data_never_formats_existing_portable_block_mounts() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (_temp_dir, _replica_plan, cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let data_mounts = vec![InrouDataVolumeMount {
        mount_path: "/var/lib/soracloud/volumes/index_state".to_owned(),
        kind: InrouDataVolumeMountKind::BlockDevice {
            device_serial: "sora-index_state".to_owned(),
            filesystem_type: "ext4".to_owned(),
            filesystem_uuid: "11111111-2222-8333-8444-555555555555".to_owned(),
            mount_options: INROU_PORTABLE_VOLUME_MOUNT_OPTIONS.to_owned(),
            initialize_filesystem: false,
        },
    }];

    let user_data = build_inrou_user_data(
        &cache_key,
        8080,
        &bundle.container.resources,
        &data_mounts,
        Duration::from_secs(10),
        None,
        None,
    )?;

    assert!(!user_data.contains("mkfs.ext4"));
    assert!(!user_data.contains("reformat"));
    assert!(user_data.contains(
        "actual_filesystem=$(blkid -s TYPE -o value \"$expected_device\" 2>/dev/null || true)"
    ));
    assert!(user_data.contains(
        "actual_uuid=$(blkid -s UUID -o value \"$expected_device\" 2>/dev/null || true)"
    ));
    assert!(user_data.contains("Options=rw,nosuid,nodev,noexec,nosymfollow,errors=remount-ro"));
    assert!(!user_data.contains("mount -t"));
    assert!(!user_data.contains("umount"));
    assert!(!user_data.contains("nofail"));
    Ok(())
}
#[test]
fn build_inrou_user_data_rejects_invalid_portable_bundle_lengths() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (_temp_dir, _replica_plan, cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let _ = build_inrou_user_data(
        &cache_key,
        8080,
        &bundle.container.resources,
        &[],
        Duration::from_secs(10),
        None,
        Some(PortableVmBundleBinding {
            expected_hash: bundle.container.bundle_hash,
            exact_bytes: 0,
            maximum_bytes: 1024,
        }),
    )
    .expect_err("empty portable bundle binding must fail");
    let _ = build_inrou_user_data(
        &cache_key,
        8080,
        &bundle.container.resources,
        &[],
        Duration::from_secs(10),
        None,
        Some(PortableVmBundleBinding {
            expected_hash: bundle.container.bundle_hash,
            exact_bytes: 1025,
            maximum_bytes: 1024,
        }),
    )
    .expect_err("portable bundle binding beyond its byte limit must fail");
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn ensure_inrou_portable_root_disk_copies_once_and_reuses_existing_rootfs() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let base_rootfs_image_path = temp_dir.path().join("base-rootfs.ext4");
    fs::write(&base_rootfs_image_path, b"base-rootfs-v1")?;
    let root_volume = replica_plan
        .lease_volumes
        .iter()
        .find(|volume| volume.kind == SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)
        .expect("root volume");
    let base_binding = Hash::new(b"authenticated-base-rootfs-v1");
    let first_root_disk =
        ensure_inrou_portable_root_disk(&base_rootfs_image_path, root_volume, base_binding)?;
    assert_eq!(fs::read(&first_root_disk.image_path)?, b"base-rootfs-v1");
    fs::write(&base_rootfs_image_path, b"base-rootfs-v2")?;
    let second_root_disk =
        ensure_inrou_portable_root_disk(&base_rootfs_image_path, root_volume, base_binding)?;
    assert_eq!(first_root_disk.image_path, second_root_disk.image_path);
    assert_eq!(fs::read(&second_root_disk.image_path)?, b"base-rootfs-v1");
    Ok(())
}
#[cfg(unix)]
#[test]
fn reusable_inrou_disks_reject_links_and_unsafe_permissions() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let disk = temp_dir.path().join("disk.raw");
    fs::write(&disk, b"disk")?;
    fs::set_permissions(&disk, fs::Permissions::from_mode(0o600))?;
    validate_reusable_inrou_disk(&disk, Some(4))?;
    assert_eyre_error_contains(
        &validate_reusable_inrou_disk(&disk, Some(5))
            .expect_err("a reusable raw disk must retain its configured length"),
        "instead of the required",
    );

    let symbolic = temp_dir.path().join("symbolic.raw");
    std::os::unix::fs::symlink(&disk, &symbolic)?;
    assert_eyre_error_contains(
        &validate_reusable_inrou_disk(&symbolic, None)
            .expect_err("a reusable disk must not follow symbolic links"),
        "must be a regular file",
    );

    let hard = temp_dir.path().join("hard.raw");
    fs::hard_link(&disk, &hard)?;
    assert_eyre_error_contains(
        &validate_reusable_inrou_disk(&disk, None)
            .expect_err("a multiply linked reusable disk must fail closed"),
        "must have exactly one hard link",
    );
    fs::remove_file(hard)?;

    fs::set_permissions(&disk, fs::Permissions::from_mode(0o622))?;
    assert_eyre_error_contains(
        &validate_reusable_inrou_disk(&disk, None)
            .expect_err("a disk writable by other users must fail closed"),
        "owner-writable and inaccessible",
    );
    fs::set_permissions(&disk, fs::Permissions::from_mode(0o400))?;
    assert_eyre_error_contains(
        &validate_reusable_inrou_disk(&disk, None)
            .expect_err("a reusable disk must remain writable by its owner"),
        "owner-writable and inaccessible",
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn delegated_inrou_disk_validation_pins_the_predelegation_inode() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let original = temp_dir.path().join("original.raw");
    let substitute = temp_dir.path().join("substitute.raw");
    fs::write(&original, b"disk")?;
    fs::write(&substitute, b"disk")?;
    fs::set_permissions(&original, fs::Permissions::from_mode(0o660))?;
    fs::set_permissions(&substitute, fs::Permissions::from_mode(0o660))?;
    let delegated_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&original)?;
    let metadata = delegated_file.metadata()?;
    let custody = InrouDiskCustody {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: 0o660,
    };

    validate_inrou_disk_under_exact_custody(&original, &delegated_file, 4, custody)?;
    assert_eyre_error_contains(
        &validate_inrou_disk_under_exact_custody(&substitute, &delegated_file, 4, custody)
            .expect_err("a same-shape path substitution must not authenticate another inode"),
        "changed during exact custody validation",
    );
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn reclaimed_inrou_disk_skips_only_its_exact_custody_descriptor() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let disk = fs::File::create(temp_dir.path().join("disk.raw"))?;
    let metadata = disk.metadata()?;
    let pid = std::process::id();
    ensure_no_process_open_file(&metadata, pid, disk.as_raw_fd())?;

    let transferred = disk.try_clone()?;
    let error = ensure_no_process_open_file(&metadata, pid, disk.as_raw_fd())
        .expect_err("every additional descriptor must block custody reuse");
    assert!(
        error
            .to_string()
            .contains("still has the reclaimed QEMU disk open")
    );
    drop(transferred);

    acquire_inrou_write_lease(&disk)?.release()?;
    let separately_opened = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(temp_dir.path().join("disk.raw"))?;
    assert!(
        acquire_inrou_write_lease(&disk).is_err(),
        "a separately opened file description must block the write lease"
    );
    drop(separately_opened);
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn portable_vm_identity_barrier_rejects_an_active_uid_or_gid() {
    let identity = PortableVmChildIdentity {
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
        supplementary_gids: Vec::new(),
    };
    let error = ensure_no_process_with_inrou_identity(&identity)
        .expect_err("the current test process proves this uid/gid is already active");
    assert!(error.to_string().contains("is already active in process"));
}
#[cfg(unix)]
#[test]
fn inrou_disk_directory_rejects_replaceable_or_linked_custody() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let temp_root = canonical_test_runtime_state_dir(&temp_dir)?;
    let secure = temp_root.join("secure-volume");
    assert_eq!(
        ensure_secure_inrou_disk_directory(&secure)?.path(),
        fs::canonicalize(&secure)?.as_path()
    );
    assert_eq!(fs::metadata(&secure)?.permissions().mode() & 0o777, 0o700);

    fs::set_permissions(&secure, fs::Permissions::from_mode(0o770))?;
    assert_eyre_error_contains(
        &ensure_secure_inrou_disk_directory(&secure)
            .expect_err("a group-writable disk directory must fail closed"),
        "custody permits path replacement",
    );

    let linked = temp_root.join("linked-volume");
    std::os::unix::fs::symlink(&temp_root, &linked)?;
    assert_eyre_error_contains(
        &ensure_secure_inrou_disk_directory(&linked)
            .expect_err("a disk-directory symbolic link must fail closed"),
        "symlink or non-directory component",
    );

    let real_parent = temp_root.join("real-parent");
    fs::create_dir(&real_parent)?;
    let linked_parent = temp_root.join("linked-parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent)?;
    assert_eyre_error_contains(
        &ensure_secure_inrou_disk_directory(&linked_parent.join("nested-volume"))
            .expect_err("a symbolic-link ancestor must fail before disk creation or delegation"),
        "symlink or non-directory component",
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_disk_directory_rejects_component_swap_while_opening() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let temp_root = canonical_test_runtime_state_dir(&temp_dir)?;
    let target = temp_root.join("swap-target");
    let displaced = temp_root.join("swap-target-displaced");
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
    let mut swapped = false;

    let error = ensure_secure_inrou_disk_directory_with_hook(&target, |observed| {
        if !swapped && observed == target {
            swapped = true;
            fs::rename(&target, &displaced)?;
            fs::create_dir(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    })
    .expect_err("a directory component replacement between stat and open must fail closed");

    assert!(swapped, "the deterministic swap hook must have executed");
    assert_eyre_error_contains(&error, "changed while it was opened");
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_disk_directory_tolerates_unrelated_child_creation_while_opening() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let temp_root = canonical_test_runtime_state_dir(&temp_dir)?;
    let target = temp_root.join("stable-target");
    let unrelated = temp_root.join("unrelated-child");
    let mut created = false;

    let pinned = ensure_secure_inrou_disk_directory_with_hook(&target, |observed| {
        if !created && observed == temp_root {
            fs::create_dir(&unrelated)?;
            fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o700))?;
            created = true;
        }
        Ok(())
    })?;

    assert!(created, "the deterministic directory-churn hook must run");
    assert_eq!(pinned.path(), target);
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_disk_mutations_remain_on_pinned_directory_after_path_replacement() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let temp_root = canonical_test_runtime_state_dir(&temp_dir)?;
    let target = temp_root.join("pinned-target");
    let displaced = temp_root.join("pinned-target-displaced");
    let pinned = ensure_secure_inrou_disk_directory(&target)?;
    fs::rename(&target, &displaced)?;
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;

    write_inrou_bytes_at(&pinned, OsStr::new("sentinel"), b"pinned", false)?;

    assert_eq!(fs::read(displaced.join("sentinel"))?, b"pinned");
    assert!(!target.join("sentinel").exists());
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_disk_staging_cleanup_refuses_replaced_name() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let directory = secure_test_inrou_disk_directory(&temp_dir)?;
    let mut staging = create_unique_inrou_disk_staging_file(&directory, "lease.raw")?;
    staging.file.write_all(b"owned")?;
    staging.file.sync_all()?;
    let original_name = directory.path().join(&staging.name);
    let displaced = directory.path().join("owned-stage-displaced");
    fs::rename(&original_name, &displaced)?;
    fs::write(&original_name, b"replacement")?;
    fs::set_permissions(&original_name, fs::Permissions::from_mode(0o600))?;

    assert_eyre_error_contains(
        &remove_inrou_disk_staging_file(&directory, &staging)
            .expect_err("cleanup must never unlink a replaced staging name"),
        "refused to remove a replaced",
    );
    assert_eq!(fs::read(&original_name)?, b"replacement");
    assert_eq!(fs::read(&displaced)?, b"owned");
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_root_disk_binding_covers_bundle_volume_and_replica_identity() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let inrou_plan = replica_plan.inrou.as_ref().expect("Inrou plan");
    let root_volume = replica_plan
        .lease_volumes
        .iter()
        .find(|volume| volume.kind == SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)
        .expect("root volume");
    let original = inrou_root_disk_binding(&bundle, &replica_plan, inrou_plan, root_volume)?;

    let mut replacement = bundle.clone();
    replacement.container.bundle_hash = Hash::new(b"replacement-signed-bundle");
    assert_ne!(
        original,
        inrou_root_disk_binding(&replacement, &replica_plan, inrou_plan, root_volume)?
    );

    let mut replacement_replica = replica_plan.clone();
    replacement_replica.local_replica_slots = vec![2];
    replacement_replica.local_replicas[0].replica_slot = 2;
    let replacement_replica_binding =
        inrou_root_disk_binding(&bundle, &replacement_replica, inrou_plan, root_volume)?;
    assert_ne!(
        original, replacement_replica_binding,
        "a root-disk sidecar from one replica must not authenticate another replica"
    );
    let substituted_root_directory = secure_test_inrou_disk_directory(&temp_dir)?;
    write_inrou_root_disk_binding(
        &substituted_root_directory,
        OsStr::new("substituted-rootfs.ext4"),
        original,
    )?;
    assert_eyre_error_contains(
        &validate_optional_inrou_root_disk_binding(
            &substituted_root_directory,
            OsStr::new("substituted-rootfs.ext4"),
            replacement_replica_binding,
        )
        .expect_err("a copied root-disk sidecar must fail replica attestation"),
        "different authenticated replica contract",
    );

    let mut mismatched_plan = inrou_plan.clone();
    mismatched_plan.rootfs_image_path = "/inrou/other-rootfs.ext4".to_owned();
    assert_eyre_error_contains(
        &inrou_root_disk_binding(&bundle, &replica_plan, &mismatched_plan, root_volume)
            .expect_err("an unsigned rootfs plan substitution must fail closed"),
        "does not match the signed bundle",
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_lease_disk_binding_covers_the_admitted_revision_and_volume_contract() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let volume = replica_plan
        .lease_volumes
        .iter()
        .find(|volume| volume.kind != SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)
        .expect("non-root lease volume");
    let filesystem_uuid = inrou_lease_filesystem_uuid(&replica_plan, volume)?;
    let original = inrou_lease_disk_binding(&replica_plan, volume, &filesystem_uuid)?;

    let mut replacement_plan = replica_plan.clone();
    replacement_plan.bundle_hash = Hash::new(b"replacement-bundle").to_string();
    assert_ne!(
        original,
        inrou_lease_disk_binding(&replacement_plan, volume, &filesystem_uuid)?
    );

    let mut replacement_replica_plan = replica_plan.clone();
    replacement_replica_plan.local_replica_slots = vec![2];
    replacement_replica_plan.local_replicas[0].replica_slot = 2;
    let replacement_uuid = inrou_lease_filesystem_uuid(&replacement_replica_plan, volume)?;
    let replacement_replica_binding =
        inrou_lease_disk_binding(&replacement_replica_plan, volume, &replacement_uuid)?;
    assert_ne!(
        original, replacement_replica_binding,
        "a non-root disk sidecar from one replica must not authenticate another replica"
    );
    let substituted_sidecar_directory = secure_test_inrou_disk_directory(&temp_dir)?;
    write_inrou_lease_disk_sidecar(
        &substituted_sidecar_directory,
        OsStr::new("substituted-lease.raw.binding-v1"),
        original,
        "test Inrou lease-disk binding",
    )?;
    assert_eyre_error_contains(
        &validate_optional_inrou_lease_disk_sidecar(
            &substituted_sidecar_directory,
            OsStr::new("substituted-lease.raw.binding-v1"),
            replacement_replica_binding,
            "test Inrou lease-disk binding",
        )
        .expect_err("a copied lease-disk sidecar must fail replica attestation"),
        "does not match the admitted Inrou lease-disk identity",
    );

    let mut replacement_volume = volume.clone();
    replacement_volume.max_total_bytes += 1;
    assert_ne!(
        original,
        inrou_lease_disk_binding(&replica_plan, &replacement_volume, &filesystem_uuid)?
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn ensure_inrou_portable_root_disk_is_a_standalone_authenticated_copy() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let base_rootfs_image_path = temp_dir.path().join("base-rootfs.ext4");
    fs::write(&base_rootfs_image_path, b"base-rootfs-v1")?;
    let root_volume = replica_plan
        .lease_volumes
        .iter()
        .find(|volume| volume.kind == SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)
        .expect("root volume");
    let base_binding = Hash::new(b"authenticated-base-rootfs-v1");
    let root_disk =
        ensure_inrou_portable_root_disk(&base_rootfs_image_path, root_volume, base_binding)?;
    let root_disk_path = root_disk.image_path;
    assert_eq!(
        root_disk_path.file_name().and_then(|name| name.to_str()),
        Some("rootfs.ext4")
    );
    assert_eq!(fs::read(&root_disk_path)?, b"base-rootfs-v1");
    assert!(inrou_root_disk_binding_path(&root_disk_path)?.is_file());
    fs::remove_file(&root_disk_path)?;
    let retried =
        ensure_inrou_portable_root_disk(&base_rootfs_image_path, root_volume, base_binding)?;
    assert_eq!(retried.image_path, root_disk_path);
    assert_eq!(fs::read(retried.image_path)?, b"base-rootfs-v1");
    Ok(())
}
#[cfg(unix)]
#[test]
fn ensure_inrou_portable_root_disk_reuse_requires_matching_authenticated_base() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let root_volume = replica_plan
        .lease_volumes
        .iter()
        .find(|volume| volume.kind == SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)
        .expect("root volume");
    let base_rootfs = temp_dir.path().join("base-rootfs.ext4");
    let base_bytes = b"authenticated-base-rootfs";
    fs::write(&base_rootfs, base_bytes)?;
    let base_binding = Hash::new(b"authenticated-base-rootfs-v1");
    let root_disk = ensure_inrou_portable_root_disk(&base_rootfs, root_volume, base_binding)?;
    let root_disk_path = root_disk.image_path;
    let mutated = vec![0xA5; base_bytes.len()];
    fs::write(&root_disk_path, &mutated)?;
    let reused = ensure_inrou_portable_root_disk(&base_rootfs, root_volume, base_binding)?;
    assert_eq!(reused.image_path, root_disk_path);
    assert_eq!(fs::read(&reused.image_path)?, mutated);
    let error = ensure_inrou_portable_root_disk(
        &base_rootfs,
        root_volume,
        Hash::new(b"authenticated-base-rootfs-v2"),
    )
    .expect_err("a root disk from another authenticated base must not be reused");
    assert!(
        error
            .to_string()
            .contains("different authenticated replica contract")
    );
    fs::remove_file(inrou_root_disk_binding_path(&root_disk_path)?)?;
    assert_eyre_error_contains(
        &ensure_inrou_portable_root_disk(&base_rootfs, root_volume, base_binding)
            .expect_err("an existing unbound root disk must fail closed"),
        "has no authenticated replica binding",
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn ensure_inrou_portable_root_disk_rejects_base_larger_than_budget() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let base_rootfs_image_path = temp_dir.path().join("base-rootfs.ext4");
    fs::write(&base_rootfs_image_path, b"larger-than-budget")?;
    let mut root_volume = replica_plan
        .lease_volumes
        .iter()
        .find(|volume| volume.kind == SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)
        .expect("root volume")
        .clone();
    root_volume.max_total_bytes = 4;
    let error = ensure_inrou_portable_root_disk(
        &base_rootfs_image_path,
        &root_volume,
        Hash::new(b"authenticated-oversized-base-rootfs"),
    )
    .expect_err("oversized base rootfs should fail before copying");
    let message = error.to_string();
    assert!(message.contains("exceeds root lease budget"));
    assert!(message.contains(root_volume.volume_name.as_str()));
    let root_disk_path = PathBuf::from(&root_volume.local_materialization_dir).join("rootfs.ext4");
    assert!(
        !root_disk_path.exists(),
        "oversized base rootfs must not leave a raw root disk behind"
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn portable_lease_disk_creation_never_exports_a_staging_path_to_qemu_img() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let qemu_img = temp_dir.path().join("must-not-run-qemu-img");
    let invocation_marker = temp_dir.path().join("qemu-img-invoked");
    fs::write(
        &qemu_img,
        format!(
            "#!/bin/sh\nprintf invoked >{}\nexit 19\n",
            invocation_marker.display()
        ),
    )?;
    fs::set_permissions(&qemu_img, fs::Permissions::from_mode(0o755))?;

    let disks = ensure_inrou_portable_lease_disks(&qemu_img, &replica_plan)?;
    assert_eq!(disks.len(), 1);
    assert!(
        !invocation_marker.exists(),
        "raw-disk creation must never export a mutable staging pathname to qemu-img"
    );
    let lease_volume = replica_plan
        .lease_volumes
        .iter()
        .find(|volume| volume.kind != SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)
        .expect("replica-private data volume");
    let lease_dir = PathBuf::from(&lease_volume.local_materialization_dir);
    let lease_disk = lease_dir.join("lease.raw");
    assert!(lease_disk.is_file());
    assert!(
        inrou_lease_disk_sidecar_path(&lease_disk, "binding-v1")?.is_file(),
        "the authenticated pending binding must accompany raw-disk creation"
    );
    assert!(!inrou_lease_disk_sidecar_path(&lease_disk, "initialized-v1")?.exists());
    assert!(fs::read_dir(&lease_dir)?.all(|entry| {
        !entry
            .expect("directory entry")
            .file_name()
            .to_string_lossy()
            .contains(".inrou-stage-")
    }));
    Ok(())
}
#[cfg(unix)]
#[test]
fn ensure_inrou_portable_lease_disks_create_reusable_raw_images() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let qemu_img = temp_dir.path().join("deliberately-absent-qemu-img");
    let disks = ensure_inrou_portable_lease_disks(&qemu_img, &replica_plan)?;
    assert_eq!(disks.len(), 1);
    assert_eq!(
        disks[0]
            .image_path
            .file_name()
            .and_then(|name| name.to_str()),
        Some("lease.raw")
    );
    assert_eq!(disks[0].device_serial, "sora-index_state");
    assert_eq!(disks[0].filesystem_type, INROU_PORTABLE_VOLUME_FILESYSTEM);
    assert!(is_canonical_inrou_filesystem_uuid(
        &disks[0].filesystem_uuid
    ));
    assert_eq!(disks[0].mount_options, INROU_PORTABLE_VOLUME_MOUNT_OPTIONS);
    assert!(
        disks[0].initialize_filesystem,
        "only the atomically installed new raw disk may request guest formatting"
    );
    assert!(disks[0].binding_path.is_file());
    assert!(!disks[0].initialized_marker_path.exists());
    let second_disks = ensure_inrou_portable_lease_disks(&qemu_img, &replica_plan)?;
    assert_eq!(second_disks[0].image_path, disks[0].image_path);
    assert_eq!(second_disks[0].filesystem_uuid, disks[0].filesystem_uuid);
    assert!(
        second_disks[0].initialize_filesystem,
        "a crash before guest formatting must keep initialization idempotently pending"
    );
    let disk_metadata = fs::metadata(&second_disks[0].image_path)?;
    fs::set_permissions(
        &second_disks[0].image_path,
        fs::Permissions::from_mode(0o660),
    )?;
    let delegated_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&second_disks[0].image_path)?;
    assert_eyre_error_contains(
        &validate_inrou_disk_under_exact_custody(
            &second_disks[0].image_path,
            &delegated_file,
            second_disks[0].exact_bytes,
            InrouDiskCustody {
                uid: disk_metadata.uid(),
                gid: disk_metadata.gid(),
                mode: 0o640,
            },
        )
        .expect_err("delegated disks must retain their exact writable custody mode"),
        "outside exact uid",
    );
    mark_inrou_portable_lease_disks_initialized(
        &second_disks,
        &[delegated_file],
        InrouDiskCustody {
            uid: disk_metadata.uid(),
            gid: disk_metadata.gid(),
            mode: 0o660,
        },
    )?;
    assert!(second_disks[0].initialized_marker_path.is_file());
    fs::set_permissions(
        &second_disks[0].image_path,
        fs::Permissions::from_mode(0o600),
    )?;

    let initialized_disks = ensure_inrou_portable_lease_disks(&qemu_img, &replica_plan)?;
    assert!(
        !initialized_disks[0].initialize_filesystem,
        "only a healthy guest may commit initialization and permanently disable formatting"
    );
    fs::write(
        &initialized_disks[0].binding_path,
        Hash::new(b"substituted-lease-binding").to_string(),
    )?;
    assert_eyre_error_contains(
        &ensure_inrou_portable_lease_disks(&qemu_img, &replica_plan)
            .expect_err("a substituted lease binding must fail closed"),
        "does not match the admitted Inrou lease-disk identity",
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn inrou_post_health_marker_commit_uses_the_retained_lease_directory() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let (temp_dir, replica_plan, _cache_key) = materialize_inrou_replica_plan_for_tests(&bundle)?;
    let disks = ensure_inrou_portable_lease_disks(
        &temp_dir.path().join("deliberately-absent-qemu-img"),
        &replica_plan,
    )?;
    assert_eq!(disks.len(), 1);
    let original_directory = disks[0].directory.path().to_path_buf();
    let displaced_directory = original_directory.with_file_name(format!(
        "{}-displaced",
        original_directory
            .file_name()
            .and_then(OsStr::to_str)
            .expect("fixture volume directory is UTF-8")
    ));
    fs::rename(&original_directory, &displaced_directory)?;
    fs::create_dir(&original_directory)?;
    fs::set_permissions(&original_directory, fs::Permissions::from_mode(0o700))?;

    let delegated_file = fs::File::from(
        rustix::fs::openat(
            &disks[0].directory.directory,
            &disks[0].image_name,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    rustix::fs::fchmod(&delegated_file, rustix::fs::Mode::from_raw_mode(0o660))?;
    let delegated_metadata = delegated_file.metadata()?;
    mark_inrou_portable_lease_disks_initialized(
        &disks,
        &[delegated_file],
        InrouDiskCustody {
            uid: delegated_metadata.uid(),
            gid: delegated_metadata.gid(),
            mode: 0o660,
        },
    )?;

    assert!(
        displaced_directory
            .join(&disks[0].initialized_marker_name)
            .is_file()
    );
    assert!(
        !original_directory
            .join(&disks[0].initialized_marker_name)
            .exists()
    );
    Ok(())
}
#[test]
fn portable_smoke_operator_preseed_artifact_is_authenticated_and_isa_scoped() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let kernel_image = temp_dir.path().join("vmlinux");
    let rootfs_image = temp_dir.path().join("rootfs.ext4");
    let initrd_image = temp_dir.path().join("initrd.img");
    fs::write(&kernel_image, b"portable-smoke-kernel")?;
    fs::write(&rootfs_image, b"portable-smoke-rootfs")?;
    fs::write(&initrd_image, b"portable-smoke-initrd")?;
    let (store, artifact) = create_portable_inrou_operator_preseed_artifact(
        &temp_dir,
        SoraInrouGuestIsaV1::X8664,
        &kernel_image,
        &rootfs_image,
        Some(&initrd_image),
    )?;
    let manifest_digest = parse_sorafs_manifest_digest_hex(&artifact.manifest_digest_hex)?;
    let stored = store
        .manifest_by_digest(&manifest_digest)
        .expect("authenticated portable-smoke manifest");
    assert_eq!(
        decode_content_cid(&artifact.content_cid).as_deref(),
        Some(stored.manifest_cid())
    );
    assert_eq!(
        artifact.manifest_digest_hex,
        hex::encode(stored.manifest_digest())
    );
    assert_eq!(
        stored
            .files()
            .iter()
            .map(|file| file.path.join("/"))
            .collect::<Vec<_>>(),
        vec![
            "x86_64/initrd.img".to_owned(),
            "x86_64/rootfs.ext4".to_owned(),
            "x86_64/vmlinux".to_owned(),
        ]
    );
    let empty_rootfs = temp_dir.path().join("empty-rootfs.ext4");
    fs::write(&empty_rootfs, b"")?;
    let empty_error = match create_portable_inrou_operator_preseed_artifact(
        &temp_dir,
        SoraInrouGuestIsaV1::X8664,
        &kernel_image,
        &empty_rootfs,
        None,
    ) {
        Ok(_) => panic!("an empty guest member must fail before publication"),
        Err(error) => error,
    };
    assert_report_contains(&empty_error, "must be a nonempty regular file");
    Ok(())
}
#[cfg(unix)]
#[test]
fn portable_smoke_application_bundle_excludes_guest_artifacts() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let parent = secure_test_inrou_disk_directory(&temp_dir)?;
    let archive = create_inrou_application_bundle_archive_for_linux_test()?;
    let cache_path = temp_dir.path().join("application-bundle.tgz");
    fs::write(&cache_path, &archive)?;
    let bundle_root = ensure_native_bundle_extracted(
        &cache_path,
        Hash::new(&archive),
        &parent,
        OsStr::new("application-bundle"),
        "/bin/sh",
        canonical_inrou_test_archive_limits(),
    )?;
    assert!(bundle_root.path().join("bin/sh").is_file());
    let health_server_path = bundle_root.path().join("app/inrou-health.py");
    assert!(health_server_path.is_file());
    let health_server = fs::read_to_string(health_server_path)?;
    assert_eq!(health_server, INROU_HEALTH_SERVER_PY);
    for attestation_source in [
        "/attestation-v1",
        "resource.RLIMIT_NOFILE",
        "/proc/self/cgroup",
        "pids.max",
        "cpu.max",
        "memory.max",
        "memory.swap.max",
        "/proc/self/mountinfo",
        "os.statvfs(SERVICE_ROOT)",
        ".inrou-guest-hardening-v1",
        "ssh.service",
        "ssh_port_22_listening",
    ] {
        assert!(
            health_server.contains(attestation_source),
            "portable smoke server omits `{attestation_source}`"
        );
    }
    assert!(!bundle_root.path().join("inrou").exists());
    Ok(())
}
