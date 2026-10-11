fn canonical_inrou_test_peer_id() -> &'static str {
    static PEER_ID: OnceLock<String> = OnceLock::new();
    PEER_ID.get_or_init(|| ALICE_ID.expect_single_signatory().to_string())
}

fn assert_eyre_error_contains(error: eyre::Report, expected: &str) {
    let message = format!("{error:#}");
    assert!(
        message.contains(expected),
        "expected error containing {expected:?}, got {message:?}"
    );
}

#[cfg(target_os = "linux")]
fn assert_eyre_error_contains_any(error: eyre::Report, expected: &[&str]) {
    let message = format!("{error:#}");
    assert!(
        expected.iter().any(|fragment| message.contains(fragment)),
        "expected error containing one of {expected:?}, got {message:?}"
    );
}

#[test]
fn remote_hydration_provider_gate_honors_a_lower_newer_advert() {
    let one = NonZeroUsize::new(1).expect("nonzero stream limit");
    let two = NonZeroUsize::new(2).expect("nonzero stream limit");
    let gate = Arc::new(RemoteHydrationProviderGate::new(10, two));
    let first = gate.acquire(10, two).expect("first provider permit");
    let second = gate.acquire(10, two).expect("second provider permit");
    let (attempted_sender, attempted_receiver) = mpsc::channel();
    let (acquired_sender, acquired_receiver) = mpsc::channel();

    let (updated, blocked_with_two, blocked_with_one, acquired) = thread::scope(|scope| {
        let worker_gate = Arc::clone(&gate);
        let worker = scope.spawn(move || {
            attempted_sender
                .send(())
                .expect("test attempt observer remains connected");
            let permit = worker_gate
                .acquire(11, one)
                .expect("the newest advert remains admissible");
            acquired_sender
                .send(())
                .expect("test acquisition observer remains connected");
            drop(permit);
        });
        attempted_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("newer advert acquisition must start");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let updated = loop {
            if gate.state.lock().advert_issued_at == 11 {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            thread::yield_now();
        };
        let blocked_with_two = matches!(
            acquired_receiver.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        drop(first);
        let blocked_with_one = matches!(
            acquired_receiver.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        drop(second);
        let acquired = acquired_receiver
            .recv_timeout(Duration::from_secs(2))
            .is_ok();
        worker.join().expect("provider-gate worker must not panic");
        (updated, blocked_with_two, blocked_with_one, acquired)
    });

    assert!(updated, "the newer advert must update the active gate");
    assert!(blocked_with_two);
    assert!(blocked_with_one);
    assert!(acquired);
    assert!(
        gate.acquire(
            10,
            NonZeroUsize::new(8).expect("nonzero stale stream limit")
        )
        .is_none(),
        "a delayed older advert must not raise or enter the newer gate"
    );
}

#[test]
fn bounded_hydration_tasks_respect_worker_limit_and_input_error_order() {
    use std::sync::{
        Condvar,
        atomic::{AtomicUsize, Ordering},
    };

    let tasks = [0_usize, 1, 2, 3, 4, 5, 6, 7, 8];
    let active = AtomicUsize::new(0);
    let maximum_active = AtomicUsize::new(0);
    let release_gate = (Mutex::new(false), Condvar::new());
    let (started_sender, started_receiver) = mpsc::channel();
    let (mut executed, result) = thread::scope(|scope| {
        let runner = scope.spawn(|| {
            run_bounded_hydration_tasks(
                &tasks,
                NonZeroUsize::new(4).expect("nonzero worker count"),
                |task| {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum_active.fetch_max(current, Ordering::SeqCst);
                    started_sender
                        .send(*task)
                        .expect("test start observer remains connected");
                    let (released, wake) = &release_gate;
                    let mut released = released.lock().expect("release gate lock");
                    while !*released {
                        released = wake.wait(released).expect("release gate wait");
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                    match *task {
                        0 => Err(eyre::eyre!("task zero failed")),
                        2 => Err(eyre::eyre!("task two failed")),
                        _ => Ok(()),
                    }
                },
            )
        });
        let mut executed = Vec::new();
        for _ in 0..4 {
            match started_receiver.recv_timeout(Duration::from_secs(2)) {
                Ok(task) => executed.push(task),
                Err(_) => break,
            }
        }
        let (released, wake) = &release_gate;
        *released.lock().expect("release gate lock") = true;
        wake.notify_all();
        let result = runner.join().expect("hydration coordinator must not panic");
        (executed, result)
    });
    let error = result.expect_err("the earliest input error must be returned");

    assert_eq!(maximum_active.load(Ordering::SeqCst), 4);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(error.to_string().contains("task zero failed"));
    executed.sort_unstable();
    assert_eq!(executed, vec![0, 1, 2, 3]);

    let completed = AtomicUsize::new(0);
    run_bounded_hydration_tasks(
        &tasks,
        NonZeroUsize::new(4).expect("nonzero worker count"),
        |_| {
            completed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .expect("successful waves must reuse workers until every task completes");
    assert_eq!(completed.load(Ordering::SeqCst), tasks.len());

    let error = run_bounded_hydration_tasks(
        &[0_usize],
        NonZeroUsize::new(
            iroha_config::parameters::defaults::soracloud_runtime::HYDRATION_CONCURRENCY_MAX + 1,
        )
        .expect("V1 hydration limit plus one is nonzero"),
        |_| Ok(()),
    )
    .expect_err("the helper must reject a programmatic worker count above the V1 ceiling");
    assert!(error.to_string().contains("hydration worker count"));
}

#[test]
fn inrou_cgroup_release_requires_both_teardown_attestations() {
    for (direct_child_exited, cgroup_empty, expected) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        assert_eq!(
            InrouWorkerTeardownAttestations {
                direct_child_exited,
                cgroup_empty,
            }
            .release_authorized(),
            expected
        );
    }
}

#[test]
fn storage_path_components_are_deterministic_and_collision_resistant() {
    let slash = storage_path_component("tenant/service");
    let question = storage_path_component("tenant?service");
    assert_eq!(
        sanitize_path_component("tenant/service"),
        sanitize_path_component("tenant?service"),
        "the legacy lossy spelling demonstrates the collision being prevented"
    );
    assert_ne!(slash, question);
    assert_eq!(slash, storage_path_component("tenant/service"));
    assert_ne!(
        storage_path_component("Service"),
        storage_path_component("service")
    );
    for component in [
        slash,
        question,
        storage_path_component(".."),
        storage_path_component(""),
    ] {
        assert!(component.len() <= 255);
        assert_ne!(component, ".");
        assert_ne!(component, "..");
        assert!(
            component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        );
    }
}

#[test]
fn config_export_paths_are_canonical_and_preserved_exactly() {
    assert_eq!(
        sanitized_relative_export_path("runtime/ui-settings.v1_json")
            .expect("canonical config export path"),
        PathBuf::from("runtime/ui-settings.v1_json")
    );
    for invalid in [
        "runtime/a:b.json",
        "runtime/a?b.json",
        "runtime/a b.json",
        "runtime/café.json",
        "runtime/./app.json",
    ] {
        let _ = sanitized_relative_export_path(invalid)
            .expect_err("runtime must reject a path admission would reject");
    }
}
#[test]
fn bounded_soracloud_http_response_accepts_exact_limit() -> Result<()> {
    for declared_length in [None, Some(8)] {
        let mut reader = io::Cursor::new(b"12345678");
        let body = read_soracloud_http_response_body_bounded(&mut reader, declared_length, 8)?;
        assert_eq!(body, b"12345678");
    }
    Ok(())
}
#[test]
fn bounded_soracloud_http_response_rejects_body_overflow() {
    let mut reader = io::Cursor::new(b"123456789");
    let error = read_soracloud_http_response_body_bounded(&mut reader, None, 8)
        .expect_err("max-plus-one response body must fail");
    assert!(
        error.to_string().contains("exceeds the 8-byte limit"),
        "unexpected error: {error:?}"
    );
}
#[test]
fn bounded_regular_file_rejects_oversized_metadata_before_reading() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let path = temp_dir.path().join("oversized-state.json");
    let file = fs::File::create(&path)?;
    file.set_len(9)?;
    let error = read_soracloud_regular_file_bounded(&path, 8, "test state")
        .expect_err("max-plus-one state file must fail");
    assert!(error.to_string().contains("exceeding the 8-byte limit"));
    Ok(())
}
#[test]
fn remote_hydration_http_client_does_not_follow_redirects() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept redirect fixture request");
        let mut request = [0_u8; 1_024];
        let _ = stream.read(&mut request);
        write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: http://{address}/target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write redirect fixture response");
    });
    let base_url = reqwest::Url::parse(&format!("http://{address}/"))?;
    let response = build_remote_hydration_http_client(&base_url)?
        .get(base_url.join("source")?)
        .send()?;
    handle.join().expect("redirect fixture thread");
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    Ok(())
}
#[test]
fn soracloud_egress_url_rejects_ambiguous_or_credentialed_targets() {
    for valid in [
        "http://example.com/path?query=1",
        "https://example.com:8443/",
        "https://8.8.8.8/",
        "https://[2001:4860:4860::8888]/",
    ] {
        assert!(
            parse_soracloud_egress_url(valid).is_some(),
            "valid egress URL was rejected: {valid}"
        );
    }
    for invalid in [
        " example.com",
        "example.com",
        "ftp://example.com/file",
        "http://user@example.com/",
        "http://user:password@example.com/",
        "http://@example.com/",
        "http://example.com:0/",
        "http://example.com/path#fragment",
        "http:\\example.com\\path",
    ] {
        assert!(
            parse_soracloud_egress_url(invalid).is_none(),
            "ambiguous egress URL was accepted: {invalid}"
        );
    }
}
#[test]
fn soracloud_egress_rejects_special_use_and_mixed_dns_answers() {
    for address in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
    ] {
        let address = address.parse::<IpAddr>().expect("valid IP fixture");
        assert!(
            !soracloud_egress_ip_is_public(address),
            "special-use address was admitted: {address}"
        );
    }
    for address in ["1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"] {
        let address = address.parse::<IpAddr>().expect("valid IP fixture");
        assert!(
            soracloud_egress_ip_is_public(address),
            "public address was rejected: {address}"
        );
    }
    assert!(
        validate_soracloud_egress_socket_addrs(
            vec![
                "8.8.8.8:443".parse().expect("public fixture"),
                "127.0.0.1:443".parse().expect("loopback fixture"),
            ],
            443,
            false,
        )
        .is_none(),
        "a mixed public/special-use DNS answer must fail closed"
    );
    assert!(
        validate_soracloud_egress_socket_addrs(
            vec![
                "8.8.8.8:443".parse().expect("public fixture");
                SORACLOUD_EGRESS_DNS_MAX_ADDRESSES_V1 + 1
            ],
            443,
            false,
        )
        .is_none(),
        "an oversized DNS answer set must fail closed"
    );
    let private_origin =
        reqwest::Url::parse("https://192.168.1.1/").expect("valid private-address URL fixture");
    assert!(
        build_remote_hydration_http_client(&private_origin).is_err(),
        "remote hydration must reject a provider pinned to a private address"
    );
}
#[test]
fn url_host_ip_literal_parser_handles_bracketed_ipv6() {
    assert_eq!(
        parse_url_host_ip_literal("[::1]"),
        Some("::1".parse().expect("IPv6 loopback fixture"))
    );
    assert_eq!(
        parse_url_host_ip_literal("8.8.8.8"),
        Some("8.8.8.8".parse().expect("IPv4 fixture"))
    );
    for non_literal in ["provider.example", "[::1", "::1]"] {
        assert_eq!(
            parse_url_host_ip_literal(non_literal),
            None,
            "non-literal host was parsed: {non_literal}"
        );
    }
}
#[test]
fn provider_base_url_requires_public_https_origin_root() {
    for valid in [
        "provider.example",
        "provider.example/",
        "https://provider.example",
        "https://provider.example/",
        "https://8.8.8.8:8443/",
        "https://[2001:4860:4860::8888]/",
    ] {
        assert!(
            normalize_provider_base_url(valid).is_some(),
            "valid provider origin was rejected: {valid}"
        );
    }
    for invalid in [
        " http://provider.example",
        "http://provider.example",
        "https://user@provider.example/",
        "https://user:password@provider.example/",
        "https://provider.example/path",
        "https://provider.example/..",
        "https://provider.example/?query=1",
        "https://provider.example/#fragment",
        "https://*.provider.example/",
        "https://localhost/",
        "https://localhost./",
        "https://provider.localhost/",
        "https://provider.localhost./",
        "https://127.0.0.1/",
        "https://127.1/",
        "https://2130706433/",
        "https://0x7f000001/",
        "https://017700000001/",
        "https://10.0.0.1/",
        "https://100.64.0.1/",
        "https://172.16.0.1/",
        "https://192.0.0.1/",
        "https://192.0.2.1/",
        "https://192.168.0.1/",
        "https://192.88.99.1/",
        "https://169.254.1.1/",
        "https://198.18.0.1/",
        "https://198.51.100.1/",
        "https://203.0.113.1/",
        "https://224.0.0.1/",
        "https://240.0.0.1/",
        "https://0.0.0.0/",
        "https://[::]/",
        "https://[::1]/",
        "https://[::127.0.0.1]/",
        "https://[::ffff:127.0.0.1]/",
        "https://[64:ff9b::7f00:1]/",
        "https://[fc00::1]/",
        "https://[fec0::1]/",
        "https://[fe80::1]/",
        "https://[ff02::1]/",
        "https://[2001::1]/",
        "https://[2001:db8::1]/",
        "https://[2002:0808:0808::1]/",
        "https://[3fff::1]/",
    ] {
        assert!(
            normalize_provider_base_url(invalid).is_none(),
            "invalid provider origin was accepted: {invalid}"
        );
    }
}
#[test]
fn remote_provider_test_fixture_url_allows_only_loopback_http() {
    assert!(
        normalize_provider_base_url("http://127.0.0.1:8080/").is_none(),
        "production normalizer must reject fixture HTTP"
    );
    assert!(
        normalize_remote_provider_base_url("http://127.0.0.1:8080/").is_some(),
        "test-only remote normalizer must admit a loopback fixture"
    );
    assert!(
        normalize_remote_provider_base_url("http://[::1]:8080/").is_some(),
        "test-only remote normalizer must admit an IPv6 loopback fixture"
    );
    assert!(
        normalize_remote_provider_base_url("http://192.168.1.1:8080/").is_none(),
        "test-only remote normalizer must not admit non-loopback HTTP"
    );
}
#[test]
fn bounded_soracloud_http_response_rejects_oversized_header_before_reading() {
    struct PanicReader;
    impl io::Read for PanicReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            panic!("oversized Content-Length must reject before reading");
        }
    }
    let error = read_soracloud_http_response_body_bounded(&mut PanicReader, Some(9), 8)
        .expect_err("max-plus-one Content-Length must fail");
    assert!(
        error.to_string().contains("Content-Length 9"),
        "unexpected error: {error:?}"
    );
}
#[test]
fn bounded_soracloud_http_response_rejects_misreported_length() {
    for declared_length in [Some(7), Some(9)] {
        let mut reader = io::Cursor::new(b"12345678");
        let error = read_soracloud_http_response_body_bounded(&mut reader, declared_length, 16)
            .expect_err("misreported Content-Length must fail");
        assert!(
            error.to_string().contains("does not match Content-Length"),
            "unexpected error: {error:?}"
        );
    }
}
include!("../response_bounds_tests.rs");
fn run_low_gas_soracloud_syscall(
    host: &mut SoracloudIvmHost,
    syscall: u32,
    pointer_type: PointerType,
    request_payload: &[u8],
) -> Result<VMError> {
    let mut code = Vec::new();
    code.extend_from_slice(&ivm::encoding::wide::encode_syscallx(syscall).to_le_bytes());
    code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    // SCALLX consumes five gas. The single remaining unit is deliberately
    // below the header-derived request quote, so dispatch must trap before
    // invoking the host syscall body.
    let mut vm = IVM::new(6);
    vm.load_code(&code)?;
    let request_tlv = make_pointer_tlv(pointer_type, request_payload);
    let request_ptr = vm.alloc_input_tlv(&request_tlv)?;
    vm.set_register(10, request_ptr);
    let error = vm
        .run_with_host(host)
        .expect_err("insufficient gas must reject the Soracloud syscall");
    assert_eq!(vm.register(10), request_ptr);
    Ok(error)
}
fn store_owned_heap_tlv(vm: &mut IVM, tlv: &[u8]) -> u64 {
    let pointer = vm
        .alloc_heap(u64::try_from(tlv.len()).expect("TLV length fits u64"))
        .expect("allocate owned HEAP TLV");
    vm.store_bytes(pointer, tlv).expect("store owned HEAP TLV");
    pointer
}
#[test]
fn soracloud_ivm_host_rejects_the_state_backed_axt_surface() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let runtime_request = sample_ordered_mailbox_request(
        &bundle,
        "query",
        sample_mailbox_message(&bundle, "query", b"axt-boundary".to_vec()),
    );
    let mut host = SoracloudIvmHost::new(
        runtime_request,
        temp_dir.path().to_path_buf(),
        BTreeMap::new(),
    );
    assert!(
        host.allows_syscall(ivm::SyscallPolicy::AbiV1, ivm_syscalls::SYSCALL_IROHA_HASH,),
        "state-free core helpers remain available"
    );
    for syscall in [
        ivm_syscalls::SYSCALL_AXT_BEGIN,
        ivm_syscalls::SYSCALL_AXT_TOUCH,
        ivm_syscalls::SYSCALL_AXT_COMMIT,
        ivm_syscalls::SYSCALL_VERIFY_DS_PROOF,
    ] {
        assert!(!host.allows_syscall(ivm::SyscallPolicy::AbiV1, syscall));
        let mut vm = IVM::new(u64::MAX);
        assert_eq!(
            host.prepare_syscall(syscall, &vm),
            Err(VMError::UnknownSyscall(syscall))
        );
        assert_eq!(
            host.syscall(syscall, &mut vm),
            Err(VMError::UnknownSyscall(syscall))
        );
        let mut code = Vec::new();
        code.extend_from_slice(&ivm::encoding::wide::encode_syscallx(syscall).to_le_bytes());
        code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        vm.load_code(&code)?;
        assert_eq!(
            vm.run_with_host(&mut host),
            Err(VMError::UnknownSyscall(syscall))
        );
    }
    Ok(())
}
#[test]
fn soracloud_request_decoder_accepts_owned_heap_and_rejects_unowned_heap() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let runtime_request = sample_ordered_mailbox_request(
        &bundle,
        "query",
        sample_mailbox_message(&bundle, "query", b"request-decoder".to_vec()),
    );
    let host = SoracloudIvmHost::new(
        runtime_request,
        temp_dir.path().to_path_buf(),
        BTreeMap::new(),
    );
    let request = SoracloudHostRequestEnvelopeV1 {
        schema_version: iroha_data_model::soracloud::SORACLOUD_HOST_REQUEST_VERSION_V1,
        operation: SoracloudHostOperationV1::ReadConfig,
        payload: SoracloudHostRequestPayloadV1::ReadConfig(
            iroha_data_model::soracloud::SoracloudReadConfigRequestV1 {
                config_name: "ui/settings".to_owned(),
            },
        ),
    };
    let payload = norito::to_bytes(&request)?;
    let tlv = make_pointer_tlv(PointerType::SoracloudRequest, &payload);
    let mut vm = IVM::new(u64::MAX);
    let pointer = store_owned_heap_tlv(&mut vm, &tlv);
    vm.set_register(10, pointer);
    let (decoded, request_bytes) = host.read_request_payload(
        &vm,
        SoracloudHostOperationV1::ReadConfig,
        SYSCALL_SORACLOUD_READ_CONFIG,
    )?;
    assert!(matches!(
        decoded,
        SoracloudHostRequestPayloadV1::ReadConfig(_)
    ));
    assert_eq!(request_bytes, payload.len());
    let mut forged = IVM::new(u64::MAX);
    forged.store_bytes(Memory::HEAP_START, &tlv)?;
    forged.set_register(10, Memory::HEAP_START);
    assert!(
        host.read_request_payload(
            &forged,
            SoracloudHostOperationV1::ReadConfig,
            SYSCALL_SORACLOUD_READ_CONFIG,
        )
        .is_err(),
        "an unallocated HEAP envelope must fail provenance validation"
    );
    assert_eq!(host.metering_query_count(), 0);
    assert_eq!(host.metering_allocation_count(), 0);
    Ok(())
}
#[test]
fn soracloud_public_input_spills_to_heap_from_heap_backed_name() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let runtime_request = sample_ordered_mailbox_request(
        &bundle,
        "query",
        sample_mailbox_message(&bundle, "query", b"public-input".to_vec()),
    );
    let input_name: Name = "_request_body".parse()?;
    let response_payload = vec![0xA5; Memory::INPUT_SIZE as usize + 1];
    let response_tlv = make_pointer_tlv(PointerType::Blob, &response_payload);
    let mut host = SoracloudIvmHost::new(
        runtime_request,
        temp_dir.path().to_path_buf(),
        BTreeMap::new(),
    )
    .with_public_inputs(BTreeMap::from([(input_name.clone(), response_tlv)]));
    let mut code = Vec::new();
    code.extend_from_slice(
        &ivm::encoding::wide::encode_syscallx(ivm_syscalls::SYSCALL_GET_PUBLIC_INPUT).to_le_bytes(),
    );
    code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(u64::MAX);
    vm.load_code(&code)?;
    let name_payload = norito::to_bytes(&input_name)?;
    let name_tlv = make_pointer_tlv(PointerType::Name, &name_payload);
    let name_pointer = store_owned_heap_tlv(&mut vm, &name_tlv);
    vm.set_register(10, name_pointer);
    vm.run_with_host(&mut host)?;
    let response_pointer = vm.register(10);
    assert!(
        (Memory::HEAP_START..Memory::INPUT_START).contains(&response_pointer),
        "oversized public input must use owned HEAP storage"
    );
    let response = vm.validate_tlv(response_pointer)?;
    assert_eq!(response.type_id, PointerType::Blob);
    assert_eq!(response.payload, response_payload.as_slice());
    Ok(())
}
#[test]
fn soracloud_vm_output_decoder_enforces_heap_ownership() -> Result<()> {
    let response_payload = vec![0x5A; Memory::INPUT_SIZE as usize + 1];
    let response_tlv = make_pointer_tlv(PointerType::Blob, &response_payload);
    let (mut vm, output_kind) = soracloud_echo_vm(&response_tlv, EntrypointValueKindV1::Blob)?;
    let response_pointer = vm.public_call_result_word(0)?;
    assert!((Memory::HEAP_START..Memory::INPUT_START).contains(&response_pointer));
    let (decoded, content_type) =
        decode_vm_output(&vm, output_kind, "query", "read", "service", "v1")
            .map_err(|error| eyre::eyre!("{}", error.message))?;
    assert_eq!(decoded, response_payload);
    assert_eq!(content_type.as_deref(), Some("application/octet-stream"));
    let unowned = Memory::HEAP_START + vm.memory.heap_limit()
        - u64::try_from(response_tlv.len()).expect("fixture envelope fits heap");
    vm.store_bytes(unowned, &response_tlv)?;
    assert!(
        vm.validate_tlv(unowned).is_err(),
        "bytes in unused heap capacity are unowned"
    );
    vm.memory.store_u64(vm.register(10), unowned)?;
    assert!(
        decode_vm_output(&vm, output_kind, "query", "read", "service", "v1").is_err(),
        "a genuine completed table must still reject an unallocated HEAP response"
    );
    vm.memory.store_u64(vm.register(10), response_pointer)?;
    assert_eq!(
        decode_vm_output(&vm, output_kind, "query", "read", "service", "v1")?.0,
        response_payload,
        "restored original owned result remains valid"
    );
    Ok(())
}
#[test]
fn prepared_runtime_cache_uses_dedicated_idle_capacity() {
    let runtime = iroha_config::parameters::actual::SoracloudRuntime {
        hydration_concurrency: NonZeroUsize::new(1).expect("nonzero hydration concurrency"),
        prepared_runtime_cache_capacity: NonZeroUsize::new(3)
            .expect("nonzero prepared runtime cache capacity"),
        ..Default::default()
    };
    let config = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
    let cache = SoracloudPreparedRuntimeCache::from_config(&config);

    assert_eq!(cache.max_idle_runtimes, 3);
}
#[test]
fn prepared_runtime_cache_rejects_oversized_artifact_before_reading() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifact_path = temp_dir.path().join("oversized.to");
    let artifact = vec![0xA5; 65];
    fs::write(&artifact_path, &artifact)?;
    let cache = SoracloudPreparedRuntimeCache::new(
        64,
        NonZeroUsize::new(1).expect("non-zero runtime bound"),
    );
    let error = match cache.prepare(&artifact_path, Hash::new(&artifact)) {
        Ok(_) => panic!("oversized prepared artifact must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Internal);
    let stats = cache.stats();
    assert_eq!(stats.metadata_validations, 1);
    assert_eq!(stats.artifact_reads, 0);
    assert_eq!(stats.artifact_hashes, 0);
    assert_eq!(stats.contract_preparations, 0);
    assert_eq!(stats.prepared_entries, 0);
    assert_eq!(stats.retained_artifact_bytes, 0);
    assert_eq!(stats.idle_runtimes, 0);
    Ok(())
}
#[test]
fn prepared_soracloud_runtime_never_collects_zk_traces() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifact = simple_soracloud_contract_artifact(&["trace_off"]);
    let artifact_path = temp_dir.path().join("trace-off.to");
    fs::write(&artifact_path, &artifact)?;
    let cache = SoracloudPreparedRuntimeCache::new(
        u64::try_from(artifact.len())?,
        NonZeroUsize::new(1).expect("non-zero runtime bound"),
    );
    let prepared = cache
        .prepare(&artifact_path, Hash::new(&artifact))
        .map_err(|error| eyre::eyre!("{}", error.message))?;
    let runtime = cache
        .checkout(&prepared)
        .map_err(|error| eyre::eyre!("{}", error.message))?;
    assert!(!runtime.zk_trace_enabled());
    Ok(())
}
#[test]
fn overlapping_soracloud_runtimes_return_with_their_own_templates() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifact = simple_soracloud_contract_artifact(&["overlap"]);
    let artifact_path = temp_dir.path().join("overlap.to");
    fs::write(&artifact_path, &artifact)?;
    let cache = SoracloudPreparedRuntimeCache::new(
        u64::try_from(artifact.len())?,
        NonZeroUsize::new(2).expect("non-zero runtime bound"),
    );
    let prepared = cache
        .prepare(&artifact_path, Hash::new(&artifact))
        .map_err(|error| eyre::eyre!("{}", error.message))?;
    let first = cache
        .checkout(&prepared)
        .map_err(|error| eyre::eyre!("{}", error.message))?;
    let second_allocation = {
        let mut second = cache
            .checkout(&prepared)
            .map_err(|error| eyre::eyre!("{}", error.message))?;
        let allocation = second.memory.load_region(0, 1)?.as_ptr();
        second.memory.preload_input(0, &[0xA5])?;
        allocation
    };
    let third = cache
        .checkout(&prepared)
        .map_err(|error| eyre::eyre!("{}", error.message))?;
    assert_eq!(third.memory.load_region(0, 1)?.as_ptr(), second_allocation);
    assert_eq!(
        third.memory.load_region(Memory::INPUT_START, 1)?,
        [0],
        "the cold overlapping runtime must reset against its own template"
    );
    let stats = cache.stats();
    assert_eq!(stats.runtime_allocations, 2);
    assert_eq!(stats.prepared_loads, 2);
    assert_eq!(stats.template_builds, 2);
    assert_eq!(stats.runtime_reuses, 1);
    assert_eq!(stats.dirty_resets, 1);
    assert_eq!(stats.runtime_returns, 1);
    drop((third, first));
    Ok(())
}
#[test]
fn artifact_cache_verification_rejects_substitution_and_size_overrun() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let cache_path = temp_dir.path().join("artifact.bin");
    let expected_bytes = b"authenticated-artifact";
    let expected_hash = Hash::new(expected_bytes);
    fs::write(&cache_path, expected_bytes)?;
    let fingerprint = verify_cached_soracloud_artifact(
        &cache_path,
        expected_hash,
        u64::try_from(expected_bytes.len())?,
    )
    .map_err(|error| eyre::eyre!("{}", error.message))?;
    assert_eq!(fingerprint.bytes, u64::try_from(expected_bytes.len())?);
    fs::write(&cache_path, b"substituted-artifact")?;
    let substituted = verify_cached_soracloud_artifact(&cache_path, expected_hash, u64::MAX)
        .expect_err("substituted cache bytes must fail");
    assert_eq!(
        substituted.kind,
        SoracloudRuntimeExecutionErrorKind::Internal
    );
    fs::write(&cache_path, expected_bytes)?;
    let oversized = verify_cached_soracloud_artifact(
        &cache_path,
        expected_hash,
        u64::try_from(expected_bytes.len() - 1)?,
    )
    .expect_err("cache bytes above their class budget must fail");
    assert_eq!(oversized.kind, SoracloudRuntimeExecutionErrorKind::Internal);
    Ok(())
}
#[cfg(unix)]
#[test]
fn artifact_cache_verification_rejects_symbolic_and_hard_links() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let target = temp_dir.path().join("target.bin");
    let symbolic = temp_dir.path().join("symbolic.bin");
    let hard = temp_dir.path().join("hard.bin");
    let bytes = b"authenticated-artifact";
    let expected_hash = Hash::new(bytes);
    fs::write(&target, bytes)?;
    std::os::unix::fs::symlink(&target, &symbolic)?;
    verify_cached_soracloud_artifact(&symbolic, expected_hash, u64::MAX)
        .expect_err("symbolic-link cache entry must fail");
    fs::hard_link(&target, &hard)?;
    verify_cached_soracloud_artifact(&hard, expected_hash, u64::MAX)
        .expect_err("multiply linked cache entry must fail");
    Ok(())
}
#[test]
fn artifact_plans_reverify_hash_named_cache_entries() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.service.artifacts.clear();
    let bundle_bytes = simple_soracloud_contract_artifact(&["query"]);
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let cache_path = temp_dir
        .path()
        .join(hash_cache_name(bundle.container.bundle_hash));
    let cache_budgets = iroha_config::parameters::actual::SoracloudRuntimeCacheBudgets::default();
    fs::write(&cache_path, b"substituted")?;
    let plans = build_artifact_plans(&bundle, temp_dir.path(), &cache_budgets);
    assert!(!plans[0].available_locally);
    fs::write(&cache_path, &bundle_bytes)?;
    let plans = build_artifact_plans(&bundle, temp_dir.path(), &cache_budgets);
    assert!(plans[0].available_locally);
    fs::write(&cache_path, b"changed-after-plan")?;
    assert!(
        verify_cached_soracloud_artifact(
            &cache_path,
            bundle.container.bundle_hash,
            cache_budgets.bundle_bytes.get(),
        )
        .is_err(),
        "a cache entry changed after planning must be rejected when hydration revalidates it"
    );
    Ok(())
}
#[test]
fn atomic_write_installs_complete_bytes_without_legacy_tmp_aliases() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let destination = temp_dir.path().join("state.json");
    let legacy_tmp = destination.with_extension("tmp");
    fs::write(&legacy_tmp, b"attacker-controlled")?;
    write_bytes_atomic(&destination, b"first")?;
    assert_eq!(fs::read(&destination)?, b"first");
    assert_eq!(fs::read(&legacy_tmp)?, b"attacker-controlled");
    write_bytes_atomic(&destination, b"second")?;
    assert_eq!(fs::read(&destination)?, b"second");
    assert_eq!(fs::read(&legacy_tmp)?, b"attacker-controlled");
    for entry in fs::read_dir(temp_dir.path())? {
        let entry = entry?;
        if entry.path() != legacy_tmp {
            assert!(
                !entry.file_name().to_string_lossy().ends_with(".tmp"),
                "owned atomic-write temporary files must not remain"
            );
        }
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn portable_vm_bundle_block_stage_verifies_and_pads_before_replacement() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let materialization_dir = secure_test_inrou_disk_directory(&temp_dir)?;
    let cache_path = temp_dir.path().join("bundle.tgz");
    let bundle_bytes = b"authenticated-bundle";
    let expected_hash = Hash::new(bundle_bytes);
    fs::write(&cache_path, bundle_bytes)?;
    let (staged, exact_bytes) = stage_portable_vm_bundle_block_device(
        &materialization_dir,
        &cache_path,
        expected_hash,
        u64::try_from(bundle_bytes.len())?,
    )?;
    assert_eq!(exact_bytes, u64::try_from(bundle_bytes.len())?);
    let staged_bytes = fs::read(&staged)?;
    assert_eq!(staged_bytes.len() % INROU_PORTABLE_BLOCK_SECTOR_BYTES, 0);
    assert_eq!(&staged_bytes[..bundle_bytes.len()], bundle_bytes);
    assert!(
        staged_bytes[bundle_bytes.len()..]
            .iter()
            .all(|byte| *byte == 0)
    );
    fs::write(&cache_path, b"substituted-bundle")?;
    let _ = stage_portable_vm_bundle_block_device(
        &materialization_dir,
        &cache_path,
        expected_hash,
        u64::MAX,
    )
    .expect_err("substituted bundle must fail before replacing the verified block device");
    assert_eq!(fs::read(staged)?, staged_bytes);
    Ok(())
}
#[cfg(unix)]
#[test]
fn portable_vm_cloud_init_seed_contains_only_nocloud_documents() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let secret_bytes = b"portable-seed-secret-sentinel".to_vec();
    let mut deployment = sample_deployment_state(&bundle);
    deployment.service_secrets.insert(
        "db/portable-seed-password".to_owned(),
        SoraServiceSecretEntryV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_SECRET_ENTRY_VERSION_V1,
            secret_name: "db/portable-seed-password".to_owned(),
            envelope: SecretEnvelopeV1 {
                schema_version: SECRET_ENVELOPE_VERSION_V1,
                encryption: SecretEnvelopeEncryptionV1::ClientCiphertext,
                key_id: "kms/portable-seed-test".to_owned(),
                key_version: std::num::NonZeroU32::new(1).expect("non-zero"),
                nonce: vec![1, 2, 3, 4],
                ciphertext: secret_bytes.clone(),
                commitment: Hash::new(&secret_bytes),
                aad_digest: None,
            },
            last_update_sequence: 1,
        },
    );
    let effective_env = build_effective_service_environment(&bundle, &deployment)?;
    assert!(
        effective_env
            .values()
            .all(|value| !value.contains("portable-seed-secret-sentinel"))
    );
    let (_plan_root, replica_plan, mut cache_key) =
        materialize_inrou_replica_plan_for_tests(&bundle)?;
    cache_key.effective_env = effective_env;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let materialization_dir = secure_test_inrou_disk_directory(&temp_dir)?;
    let user_data = build_inrou_user_data(
        &replica_plan,
        &cache_key,
        8080,
        &bundle.container.resources,
        &[],
        Duration::from_secs(10),
        None,
        None,
    )?;
    assert!(!user_data.contains("portable-seed-secret-sentinel"));
    assert!(!user_data.contains("db/portable-seed-password"));
    assert!(!user_data.contains("kms/portable-seed-test"));
    let seed_root = write_inrou_cloud_init_documents(
        &materialization_dir,
        &cache_key,
        &build_inrou_portable_network_config(),
        &user_data,
    )?;
    let mut members = fs::read_dir(seed_root.path())?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<Vec<_>>>()?;
    members.sort();
    assert_eq!(
        members,
        vec![
            "meta-data".to_owned(),
            "network-config".to_owned(),
            "user-data".to_owned()
        ]
    );
    assert!(
        !seed_root
            .path()
            .join(INROU_PORTABLE_BUNDLE_BLOCK_MEMBER)
            .exists()
    );
    Ok(())
}
#[test]
fn portable_vm_qemu_args_attach_seed_and_bundle_read_only_without_url() -> Result<()> {
    let profile = portable_vm_guest_machine_profile(SoraInrouGuestIsaV1::X8664);
    let mut command = Command::new("qemu-system-test");
    append_portable_vm_vvfat_drive(&mut command, profile, Path::new("seed,documents"))?;
    append_portable_vm_drive_with_serial(
        &mut command,
        profile,
        "bundle",
        Path::new("bundle,verified.raw"),
        "raw",
        true,
        false,
        Some(INROU_PORTABLE_BUNDLE_DEVICE_SERIAL),
    )?;
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(args.iter().any(|arg| {
        arg == "driver=vvfat,node-name=seed,dir=seed,,documents,label=cidata,read-only=on"
    }));
    assert!(args.iter().any(|arg| arg == "virtio-blk-pci,drive=seed"));
    assert!(args.iter().any(|arg| {
        arg == "if=none,id=bundle,format=raw,readonly=on,discard=ignore,file=bundle,,verified.raw"
    }));
    assert!(
        args.iter()
            .any(|arg| arg == "virtio-blk-pci,drive=bundle,serial=sora_bundle")
    );
    assert!(
        args.iter()
            .all(|arg| !arg.contains("http://") && !arg.contains("https://"))
    );
    let kernel_cmdline = portable_vm_kernel_cmdline(profile);
    assert!(!kernel_cmdline.contains("console="));
    assert!(!kernel_cmdline.contains("ds=nocloud-net"));
    assert!(!kernel_cmdline.contains("http://"));
    assert!(!kernel_cmdline.contains("https://"));
    Ok(())
}
#[cfg(unix)]
#[test]
fn native_inrou_bundle_extraction_replaces_stale_root_transactionally() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let parent = secure_test_inrou_disk_directory(&temp_dir)?;
    let cache_path = temp_dir.path().join("bundle.tgz");
    let bundle_root = temp_dir.path().join("bundle-root");
    let archive = canonical_inrou_test_archive(&[
        ("app/service", 0o755, b"#!/bin/sh\nexit 0\n"),
        ("data/version.txt", 0o644, b"v2\n"),
    ])?;
    let bundle_hash = Hash::new(&archive);
    fs::write(&cache_path, &archive)?;
    fs::create_dir(&bundle_root)?;
    fs::write(bundle_root.join("stale.txt"), b"stale")?;
    fs::write(bundle_root.join(".bundle_hash"), bundle_hash.to_string())?;
    ensure_native_bundle_extracted(
        &cache_path,
        bundle_hash,
        &parent,
        OsStr::new("bundle-root"),
        "/app/service",
        canonical_inrou_test_archive_limits(),
    )?;
    assert_eq!(
        fs::read(bundle_root.join("app/service"))?,
        b"#!/bin/sh\nexit 0\n"
    );
    assert_eq!(fs::read(bundle_root.join("data/version.txt"))?, b"v2\n");
    assert!(!bundle_root.join("stale.txt").exists());
    assert!(!bundle_root.join(".bundle_hash").exists());
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(bundle_root.join("app/service"))?
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_no_inrou_transaction_paths(temp_dir.path(), "bundle-root")?;
    fs::write(bundle_root.join("app/service"), b"tampered")?;
    ensure_native_bundle_extracted(
        &cache_path,
        Hash::new(&archive),
        &parent,
        OsStr::new("bundle-root"),
        "/app/service",
        canonical_inrou_test_archive_limits(),
    )?;
    assert_eq!(
        fs::read(bundle_root.join("app/service"))?,
        b"#!/bin/sh\nexit 0\n"
    );
    assert_no_inrou_transaction_paths(temp_dir.path(), "bundle-root")
}
#[cfg(unix)]
#[test]
fn native_inrou_bundle_rejection_preserves_live_root() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let parent = secure_test_inrou_disk_directory(&temp_dir)?;
    let cache_path = temp_dir.path().join("bundle.tgz");
    let bundle_root = temp_dir.path().join("bundle-root");
    let archive = canonical_inrou_test_archive(&[("app/not-the-entrypoint", 0o755, b"payload")])?;
    fs::write(&cache_path, &archive)?;
    fs::create_dir(&bundle_root)?;
    fs::write(bundle_root.join("live.txt"), b"keep-live")?;
    let error = ensure_native_bundle_extracted(
        &cache_path,
        Hash::new(&archive),
        &parent,
        OsStr::new("bundle-root"),
        "/app/service",
        canonical_inrou_test_archive_limits(),
    )
    .expect_err("a bundle without its declared entrypoint must fail");
    assert!(error.to_string().contains("entrypoint"));
    assert_eq!(fs::read(bundle_root.join("live.txt"))?, b"keep-live");
    assert!(!bundle_root.join("app").exists());
    assert_no_inrou_transaction_paths(temp_dir.path(), "bundle-root")
}
#[cfg(unix)]
#[test]
fn native_inrou_bundle_rejects_linked_live_root_without_touching_target() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let parent = secure_test_inrou_disk_directory(&temp_dir)?;
    let cache_path = temp_dir.path().join("bundle.tgz");
    let bundle_root = temp_dir.path().join("bundle-root");
    let external = temp_dir.path().join("external");
    let archive = canonical_inrou_test_archive(&[("app/service", 0o755, b"new-service")])?;
    fs::write(&cache_path, &archive)?;
    fs::create_dir(&external)?;
    fs::write(external.join("sentinel"), b"external")?;
    std::os::unix::fs::symlink(&external, &bundle_root)?;
    let error = ensure_native_bundle_extracted(
        &cache_path,
        Hash::new(&archive),
        &parent,
        OsStr::new("bundle-root"),
        "/app/service",
        canonical_inrou_test_archive_limits(),
    )
    .expect_err("a linked live root must fail closed");
    let error_chain = format!("{error:?}");
    assert!(
        error_chain.contains("not a real directory"),
        "unexpected linked-root failure: {error_chain}"
    );
    assert_eq!(fs::read(external.join("sentinel"))?, b"external");
    assert!(fs::symlink_metadata(&bundle_root)?.file_type().is_symlink());
    assert_no_inrou_transaction_paths(temp_dir.path(), "bundle-root")
}
#[cfg(unix)]
#[test]
fn native_inrou_bundle_recovers_one_interrupted_backup_before_installing() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let parent = secure_test_inrou_disk_directory(&temp_dir)?;
    let cache_path = temp_dir.path().join("bundle.tgz");
    let bundle_root = temp_dir.path().join("bundle-root");
    let interrupted_backup = temp_dir
        .path()
        .join(".bundle-root.inrou-backup-interrupted");
    let archive = canonical_inrou_test_archive(&[("app/service", 0o755, b"recovered-service")])?;
    fs::write(&cache_path, &archive)?;
    fs::create_dir(&interrupted_backup)?;
    fs::write(interrupted_backup.join("old-live"), b"recover-me")?;
    ensure_native_bundle_extracted(
        &cache_path,
        Hash::new(&archive),
        &parent,
        OsStr::new("bundle-root"),
        "/app/service",
        canonical_inrou_test_archive_limits(),
    )?;
    assert_eq!(
        fs::read(bundle_root.join("app/service"))?,
        b"recovered-service"
    );
    assert!(!bundle_root.join("old-live").exists());
    assert!(!interrupted_backup.exists());
    assert_no_inrou_transaction_paths(temp_dir.path(), "bundle-root")
}
#[cfg(unix)]
#[test]
fn atomic_write_replaces_destination_links_without_touching_alias_targets() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let external = temp_dir.path().join("external");
    let symbolic_destination = temp_dir.path().join("symbolic-destination");
    fs::write(&external, b"external")?;
    std::os::unix::fs::symlink(&external, &symbolic_destination)?;
    write_bytes_atomic(&symbolic_destination, b"replacement")?;
    assert_eq!(fs::read(&symbolic_destination)?, b"replacement");
    assert_eq!(fs::read(&external)?, b"external");
    assert!(
        !fs::symlink_metadata(&symbolic_destination)?
            .file_type()
            .is_symlink()
    );
    let hard_target = temp_dir.path().join("hard-target");
    let hard_destination = temp_dir.path().join("hard-destination");
    fs::write(&hard_target, b"hard-target")?;
    fs::hard_link(&hard_target, &hard_destination)?;
    write_bytes_atomic(&hard_destination, b"replacement")?;
    assert_eq!(fs::read(&hard_destination)?, b"replacement");
    assert_eq!(fs::read(&hard_target)?, b"hard-target");
    Ok(())
}
#[test]
fn prepared_runtime_cache_evicts_lru_artifact_at_byte_budget() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let first = simple_soracloud_contract_artifact(&["first"]);
    let second = simple_soracloud_contract_artifact(&["second"]);
    let first_path = temp_dir.path().join("first.to");
    let second_path = temp_dir.path().join("second.to");
    fs::write(&first_path, &first)?;
    fs::write(&second_path, &second)?;
    let byte_budget = u64::try_from(first.len().max(second.len()))?;
    let cache = SoracloudPreparedRuntimeCache::new(
        byte_budget,
        NonZeroUsize::new(2).expect("non-zero runtime bound"),
    );
    cache
        .prepare(&first_path, Hash::new(&first))
        .map_err(|error| eyre::eyre!("{}", error.message))?;
    cache
        .prepare(&second_path, Hash::new(&second))
        .map_err(|error| eyre::eyre!("{}", error.message))?;
    let stats = cache.stats();
    assert_eq!(stats.metadata_validations, 4);
    assert_eq!(stats.artifact_reads, 2);
    assert_eq!(stats.artifact_hashes, 2);
    assert_eq!(stats.contract_preparations, 2);
    assert_eq!(stats.runtime_allocations, 2);
    assert_eq!(stats.prepared_loads, 2);
    assert_eq!(stats.template_builds, 2);
    assert_eq!(stats.invalidations, 0);
    assert_eq!(stats.evictions, 1);
    assert_eq!(stats.prepared_entries, 1);
    assert_eq!(stats.retained_artifact_bytes, u64::try_from(second.len())?);
    assert_eq!(stats.idle_runtimes, 1);
    Ok(())
}
#[test]
fn runtime_error_summary_includes_nested_causes() {
    let error = eyre::eyre!("serial console: missing python3")
        .wrap_err("Inrou PortableVm failed healthcheck during startup")
        .wrap_err("start inrou Soracloud service `hayahi_live` revision `v1` replica 1");
    let summary = runtime_error_summary(&error);
    assert!(summary.contains("start inrou Soracloud service"));
    assert!(summary.contains("Inrou PortableVm failed healthcheck during startup"));
    assert!(summary.contains("serial console: missing python3"));
}
#[test]
fn runtime_submission_transaction_checked_signing_verifies() -> Result<()> {
    let authority = AccountId::new(ALICE_KEYPAIR.public_key().clone());
    let payload = build_soracloud_runtime_submission_payload(
        iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                [0x15; Hash::LENGTH],
            )),
        ),
        authority.clone(),
        InstructionBox::from(Log::new(Level::INFO, "checked runtime signing".into())),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        "/internal/soracloud/runtime/test",
    )?;
    let tx = sign_soracloud_runtime_submission_payload(
        payload,
        &ALICE_KEYPAIR,
        "/internal/soracloud/runtime/test",
    )?;
    tx.verify_signature()
        .wrap_err("verify checked Soracloud runtime submission signature")?;
    assert_eq!(tx.authority(), &authority);
    Ok(())
}
use sorafs_node::{NodeHandle, config::StorageConfig};
#[test]
fn local_read_snapshot_allows_bounded_lag_but_rejects_wrong_tip() {
    let committed = Hash::prehashed([0x11; Hash::LENGTH]);
    let stale = Hash::prehashed([0x22; Hash::LENGTH]);
    assert!(local_read_snapshot_covers_committed_state(
        100,
        Some(committed),
        100,
        Some(committed),
    ));
    assert!(!local_read_snapshot_covers_committed_state(
        100,
        Some(stale),
        100,
        Some(committed),
    ));
    assert!(local_read_snapshot_covers_committed_state(
        99,
        Some(stale),
        100,
        Some(committed),
    ));
    assert!(!local_read_snapshot_covers_committed_state(
        100_u64.saturating_sub(SORACLOUD_LOCAL_READ_MAX_SNAPSHOT_LAG_BLOCKS + 1),
        Some(stale),
        100,
        Some(committed),
    ));
    assert!(!local_read_snapshot_covers_committed_state(
        101,
        Some(stale),
        100,
        Some(committed),
    ));
}
fn load_deployment_bundle_fixture() -> Result<SoraDeploymentBundleV1> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/soracloud/sora_deployment_bundle_v1.json");
    let raw = fs::read_to_string(path)?;
    let mut bundle: SoraDeploymentBundleV1 = norito::json::from_str(&raw)?;
    for artifact in &mut bundle.service.artifacts {
        artifact.artifact_hash = Hash::new(artifact.artifact_path.as_bytes());
    }
    Ok(bundle)
}
fn load_agent_manifest_fixture() -> Result<AgentApartmentManifestV1> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/soracloud/agent_apartment_manifest_v1.json");
    let raw = fs::read_to_string(path)?;
    Ok(norito::json::from_str(&raw)?)
}
fn test_state() -> Result<Arc<State>> {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    Ok(Arc::new(State::new_for_testing(World::new(), kura, query)))
}
struct RuntimeFixture {
    manager: SoracloudRuntimeManager,
    temp_dir: tempfile::TempDir,
}
impl RuntimeFixture {
    fn new(state: &Arc<State>) -> Result<Self> {
        Self::configured(state, |config| config)
    }
    fn configured(
        state: &Arc<State>,
        configure: impl FnOnce(SoracloudRuntimeManagerConfig) -> SoracloudRuntimeManagerConfig,
    ) -> Result<Self> {
        let temp_dir = canonical_runtime_fixture_tempdir()?;
        let config = test_runtime_manager_config(temp_dir.path().to_path_buf());
        let config = configure(config);
        let manager = SoracloudRuntimeManager::new(config, Arc::clone(state));
        Ok(Self { manager, temp_dir })
    }
    fn path(&self) -> &Path {
        self.temp_dir.path()
    }
}
#[test]
fn soracloud_runtime_submission_payload_binds_fee_intent_without_legacy_metadata() -> Result<()> {
    let authority = AccountId::new(ALICE_KEYPAIR.public_key().clone());
    let intent = iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None);
    let payload = build_soracloud_runtime_submission_payload(
        iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                [0x15; Hash::LENGTH],
            )),
        ),
        authority,
        InstructionBox::from(Log::new(Level::INFO, "fee intent".into())),
        intent.clone(),
        "/internal/soracloud/runtime/test",
    )?;
    assert_eq!(payload.fee_payment, intent);
    assert!(payload.metadata.get("gas_asset_id").is_none());
    assert!(payload.metadata.get("fee_sponsor").is_none());
    Ok(())
}
#[test]
fn soracloud_runtime_submission_builds_exact_sponsor_revision() {
    let program_id = iroha_data_model::nexus::FeeSponsorProgramId::new(
        AccountId::new(ALICE_KEYPAIR.public_key().clone()),
        "runtime".parse().expect("program name"),
    );
    let submission = iroha_config::parameters::actual::SoracloudRuntimeSubmission {
        fee_payer: iroha_config::parameters::actual::SoracloudRuntimeFeePayer::Sponsor {
            program_id: program_id.clone(),
            program_revision: 7,
        },
        signer: None,
    };
    let iroha_data_model::transaction::FeePaymentIntent::Sponsor(intent) =
        submission.fee_payment_intent()
    else {
        panic!("sponsor config must create a sponsor fee intent");
    };
    assert_eq!(intent.program_id, program_id);
    assert_eq!(intent.program_revision, 7);
}
fn sample_agent_record() -> Result<SoraAgentApartmentRecordV1> {
    let manifest = load_agent_manifest_fixture()?;
    Ok(SoraAgentApartmentRecordV1 {
        schema_version: SORA_AGENT_APARTMENT_RECORD_VERSION_V1,
        manifest_hash: Hash::prehashed([0xAA; Hash::LENGTH]),
        deployed_sequence: 1,
        lease_started_height: 1,
        lease_expires_height: 42,
        last_renewed_height: 1,
        restart_count: 0,
        last_restart_sequence: None,
        last_restart_reason: None,
        process_generation: 7,
        process_started_sequence: 1,
        last_active_sequence: 9,
        last_checkpoint_sequence: None,
        checkpoint_count: 0,
        persistent_state: SoraAgentPersistentStateV1 {
            total_bytes: 0,
            key_sizes: BTreeMap::new(),
        },
        revoked_policy_capabilities: BTreeSet::from(["wallet.sign".to_string()]),
        pending_wallet_requests: BTreeMap::new(),
        wallet_daily_spend: BTreeMap::new(),
        mailbox_queue: Vec::new(),
        autonomy_budget_ceiling_units: 500,
        autonomy_budget_remaining_units: 325,
        artifact_allowlist: BTreeMap::new(),
        autonomy_run_history: Vec::new(),
        manifest,
    })
}
fn sample_runtime_state(bundle: &SoraDeploymentBundleV1) -> SoraServiceRuntimeStateV1 {
    SoraServiceRuntimeStateV1 {
        schema_version: SORA_SERVICE_RUNTIME_STATE_VERSION_V1,
        service_name: bundle.service.service_name.clone(),
        active_service_version: bundle.service.service_version.clone(),
        health_status: SoraServiceHealthStatusV1::Healthy,
        load_factor_bps: 425,
        materialized_bundle_hash: bundle.container.bundle_hash,
    }
}
fn sample_deployment_state(bundle: &SoraDeploymentBundleV1) -> SoraServiceDeploymentStateV1 {
    let service_lease = (bundle.service.execution_plane
        == iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService)
        .then_some(iroha_data_model::soracloud::SoraServiceLeaseStateV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_LEASE_STATE_VERSION_V1,
            economic_clock:
                iroha_data_model::soracloud::SoraServiceLeaseClockV1::CanonicalBlockHeight,
            status: iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
            quota_class: "taira-open".to_owned(),
            replica_count: bundle.service.replicas,
            deployment_deposit: "1".parse().expect("deployment deposit"),
            prepaid_runtime_balance: "50".parse().expect("runtime balance"),
            runtime_price_per_block: "0.00025".parse().expect("runtime price"),
            storage_price_per_gib_block: "0.000025".parse().expect("storage price"),
            egress_price_per_mib: "0.000005".parse().expect("egress price"),
            lease_started_height: 1,
            lease_expires_height: 100,
            reporting_epoch: 1,
            settled_egress_bytes: 0,
            egress_reporter_checkpoints: Vec::new(),
            accounted_egress_bytes: 0,
            last_status_reason: None,
        });
    let lease_volume_states = service_lease.as_ref().map_or_else(Vec::new, |lease| {
        bundle
            .service
            .lease_volumes
            .iter()
            .map(
                |volume| iroha_data_model::soracloud::SoraServiceLeaseVolumeStateV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_SERVICE_LEASE_VOLUME_STATE_VERSION_V1,
                    economic_clock:
                        iroha_data_model::soracloud::SoraServiceLeaseClockV1::CanonicalBlockHeight,
                    volume_name: volume.volume_name.clone(),
                    kind: volume.kind,
                    storage_class: volume.storage_class,
                    mount_path: volume.mount_path.clone(),
                    max_total_bytes: volume.max_total_bytes.get(),
                    lease_started_height: lease.lease_started_height,
                    lease_expires_height: lease.lease_expires_height,
                    authoritative_generation: 1,
                },
            )
            .collect()
    });
    SoraServiceDeploymentStateV1 {
        schema_version: SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
        service_name: bundle.service.service_name.clone(),
        current_service_version: bundle.service.service_version.clone(),
        current_service_manifest_hash: bundle.service_manifest_hash(),
        current_container_manifest_hash: bundle.container_manifest_hash(),
        revision_count: 1,
        process_generation: 5,
        process_started_sequence: 11,
        active_rollout: None,
        last_rollout: None,
        config_generation: 0,
        secret_generation: 0,
        service_configs: BTreeMap::new(),
        service_secrets: BTreeMap::new(),
        fhe_policy_records: BTreeMap::new(),
        service_lease,
        lease_volume_states,
    }
}
fn sample_lease_egress_checkpoint(
    reporting_epoch: u64,
    service_version: String,
    lease_started_height: u64,
    replica_slot: u16,
    placement_incarnation: Hash,
    validator_account_id: AccountId,
    accounted_egress_bytes: u64,
    finalize_reporter: bool,
) -> iroha_data_model::soracloud::SoraServiceLeaseEgressCheckpointV1 {
    iroha_data_model::soracloud::SoraServiceLeaseEgressCheckpointV1 {
        reporting_epoch,
        assignment: iroha_data_model::soracloud::SoraServiceLeaseReporterAssignmentV1 {
            schema_version:
                iroha_data_model::soracloud::SORA_SERVICE_LEASE_REPORTER_ASSIGNMENT_VERSION_V1,
            service_version,
            placement: SoraInrouReplicaPlacementV1 {
                replica_slot,
                economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
                lease_started_height,
                placement_incarnation,
                host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
                validator_account_id,
                peer_id: canonical_inrou_test_peer_id().to_owned(),
                selected_guest_isa: SoraInrouGuestIsaV1::X8664,
            },
            placement_reconciled_at_ms: 1,
        },
        accounted_egress_bytes,
        last_updated_height: lease_started_height,
        finalize_reporter,
    }
}
fn sample_service_audit_event(
    bundle: &SoraDeploymentBundleV1,
    sequence: u64,
) -> iroha_data_model::soracloud::SoraServiceAuditEventV1 {
    iroha_data_model::soracloud::SoraServiceAuditEventV1 {
        schema_version: iroha_data_model::soracloud::SORA_SERVICE_AUDIT_EVENT_VERSION_V1,
        sequence,
        block_height: sequence,
        block_timestamp_ms: sequence.saturating_mul(1_000),
        action: SoraServiceLifecycleActionV1::Deploy,
        service_name: bundle.service.service_name.clone(),
        from_version: None,
        to_version: bundle.service.service_version.clone(),
        service_manifest_hash: Hash::new(b"runtime-test-service-manifest"),
        container_manifest_hash: Hash::new(b"runtime-test-container-manifest"),
        process_generation: 1,
        config_generation: 0,
        secret_generation: 0,
        config_snapshot_hash:
            iroha_data_model::soracloud::derive_soracloud_service_config_snapshot_hash_v1(
                &BTreeMap::new(),
            ),
        secret_snapshot_hash:
            iroha_data_model::soracloud::derive_soracloud_service_secret_snapshot_hash_v1(
                &BTreeMap::new(),
            ),
        governance_tx_hash: None,
        binding_name: None,
        state_key: None,
        config_mutations: Vec::new(),
        secret_mutations: Vec::new(),
        rollout_state: None,
        policy_name: None,
        policy_snapshot_hash: None,
        jurisdiction_tag: None,
        consent_evidence_hash: None,
        break_glass: None,
        break_glass_reason: None,
        lease_usage: None,
        service_lease_commitment: None,
        lease_reporting_epoch_rollover: None,
        signer: ALICE_KEYPAIR.public_key().clone(),
    }
}
fn sample_app_infra_audit_event(
    sequence: u64,
) -> iroha_data_model::soracloud::SoraAppInfraAuditEventV1 {
    iroha_data_model::soracloud::SoraAppInfraAuditEventV1 {
        schema_version: iroha_data_model::soracloud::SORA_APP_INFRA_AUDIT_EVENT_VERSION_V1,
        sequence,
        action: iroha_data_model::soracloud::SoraAppInfraActionV1::Deploy,
        app_name: "runtime_clock_app".parse().expect("valid app name"),
        from_version: None,
        to_version: "1.0.0".to_owned(),
        app_manifest_hash: Hash::new(b"runtime-clock-app-manifest"),
        service_count: 1,
        signer: ALICE_KEYPAIR.public_key().clone(),
    }
}

#[test]
fn audit_sequence_allows_zero_only_for_an_empty_world() -> Result<()> {
    let state = test_state()?;
    let view = state.view();
    assert_eq!(current_soracloud_audit_sequence(view.world())?, 0);
    Ok(())
}

#[test]
fn audit_sequence_rejects_deployment_without_audit_history() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let mut state = test_state()?;
    let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
    world
        .soracloud_service_deployments_mut_for_testing()
        .insert(
            bundle.service.service_name.clone(),
            sample_deployment_state(&bundle),
        );
    let view = state.view();

    let error = current_soracloud_audit_sequence(view.world())
        .expect_err("a deployment without audit history must fail closed");
    assert!(
        error.to_string().contains("audit history is empty"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn non_service_event_advances_audit_clock_without_a_service_event() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let deployment = sample_deployment_state(&bundle);
    let exact_head = deployment_lifecycle_sequence_lower_bound(&deployment);
    let mut state = test_state()?;
    let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
    world
        .soracloud_service_deployments_mut_for_testing()
        .insert(bundle.service.service_name.clone(), deployment);
    world
        .soracloud_app_infra_audit_events_mut_for_testing()
        .insert(exact_head, sample_app_infra_audit_event(exact_head));
    let view = state.view();

    assert!(
        view.world()
            .soracloud_service_audit_events()
            .iter()
            .next()
            .is_none(),
        "the regression must not rely on a service audit event"
    );
    assert_eq!(current_soracloud_audit_sequence(view.world())?, exact_head);
    Ok(())
}

#[test]
fn audit_sequence_rejects_miskeyed_non_service_event() -> Result<()> {
    let mut state = test_state()?;
    let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
    world
        .soracloud_app_infra_audit_events_mut_for_testing()
        .insert(12, sample_app_infra_audit_event(11));
    let view = state.view();

    let error = current_soracloud_audit_sequence(view.world())
        .expect_err("a non-service audit key must match its embedded sequence");
    assert!(
        error.to_string().contains("app-infra audit key `12`")
            && error.to_string().contains("embedded sequence `11`"),
        "unexpected miskeyed app-audit error: {error}"
    );
    Ok(())
}

#[test]
fn audit_sequence_rejects_head_behind_deployment_lifecycle() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let deployment = sample_deployment_state(&bundle);
    assert_eq!(deployment_lifecycle_sequence_lower_bound(&deployment), 11);
    let mut state = test_state()?;
    let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
    world
        .soracloud_service_deployments_mut_for_testing()
        .insert(bundle.service.service_name.clone(), deployment);
    world
        .soracloud_service_audit_events_mut_for_testing()
        .insert(10, sample_service_audit_event(&bundle, 10));
    let view = state.view();

    let error = current_soracloud_audit_sequence(view.world())
        .expect_err("a rewound audit head must fail closed");
    assert!(
        error
            .to_string()
            .contains("behind lifecycle lower bound `11`"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn audit_sequence_accepts_exact_canonical_lifecycle_head() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let deployment = sample_deployment_state(&bundle);
    let exact_head = deployment_lifecycle_sequence_lower_bound(&deployment);
    let mut state = test_state()?;
    let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
    world
        .soracloud_service_deployments_mut_for_testing()
        .insert(bundle.service.service_name.clone(), deployment);
    world
        .soracloud_service_audit_events_mut_for_testing()
        .insert(exact_head, sample_service_audit_event(&bundle, exact_head));
    let view = state.view();

    assert_eq!(current_soracloud_audit_sequence(view.world())?, exact_head);
    Ok(())
}

#[test]
fn lease_volume_plans_project_exact_authoritative_state() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let mut deployment = sample_deployment_state(&bundle);
    deployment
        .service_lease
        .as_mut()
        .expect("hosted lease")
        .lease_expires_height = 91;
    for volume in &mut deployment.lease_volume_states {
        volume.lease_expires_height = 91;
    }
    deployment.lease_volume_states[0].authoritative_generation = 7;
    let temp_dir = canonical_runtime_fixture_tempdir()?;

    let plans = build_lease_volume_plans(
        &bundle,
        &deployment,
        temp_dir.path(),
        bundle.service.service_name.as_ref(),
        &bundle.service.service_version,
    )?;

    assert_eq!(plans.len(), bundle.service.lease_volumes.len());
    for (plan, authoritative) in plans.iter().zip(&deployment.lease_volume_states) {
        assert_eq!(plan.volume_name, authoritative.volume_name.to_string());
        assert_eq!(plan.kind, authoritative.kind);
        assert_eq!(plan.storage_class, authoritative.storage_class);
        assert_eq!(plan.mount_path, authoritative.mount_path);
        assert_eq!(plan.max_total_bytes, authoritative.max_total_bytes);
        assert_eq!(
            plan.lease_expires_height,
            authoritative.lease_expires_height
        );
        assert_eq!(
            plan.authoritative_generation,
            authoritative.authoritative_generation
        );
    }
    assert_eq!(plans[0].lease_expires_height, 91);
    assert_eq!(plans[0].authoritative_generation, 7);
    Ok(())
}

#[test]
fn lease_volume_plans_require_exact_authoritative_names() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let mut missing = sample_deployment_state(&bundle);
    missing.lease_volume_states.remove(0);

    let error = build_lease_volume_plans(
        &bundle,
        &missing,
        temp_dir.path(),
        bundle.service.service_name.as_ref(),
        &bundle.service.service_version,
    )
    .expect_err("a missing authoritative volume state must fail closed");
    assert!(
        matches!(error.downcast_ref::<iroha_data_model::soracloud::SoracloudManifestError>(), Some(iroha_data_model::soracloud::SoracloudManifestError::InvalidField { field: "lease_volume_states", reason, .. }) if reason.contains("exact one-to-one")),
        "unexpected error: {error}"
    );

    let mut unexpected = sample_deployment_state(&bundle);
    let mut unexpected_state = unexpected.lease_volume_states[0].clone();
    unexpected_state.volume_name = "unexpected_volume".parse().expect("volume name");
    unexpected.lease_volume_states.push(unexpected_state);
    let error = build_lease_volume_plans(
        &bundle,
        &unexpected,
        temp_dir.path(),
        bundle.service.service_name.as_ref(),
        &bundle.service.service_version,
    )
    .expect_err("an unexpected authoritative volume state must fail closed");
    assert!(
        matches!(error.downcast_ref::<iroha_data_model::soracloud::SoracloudManifestError>(), Some(iroha_data_model::soracloud::SoracloudManifestError::InvalidField { field: "lease_volume_states", reason, .. }) if reason.contains("exact one-to-one")),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn lease_volume_plans_require_exact_economically_billed_replica_count() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let mut deployment = sample_deployment_state(&bundle);
    deployment
        .service_lease
        .as_mut()
        .expect("hosted-service lease")
        .replica_count = std::num::NonZeroU16::new(2).expect("nonzero");
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let error = build_lease_volume_plans(
        &bundle,
        &deployment,
        temp_dir.path(),
        bundle.service.service_name.as_ref(),
        &bundle.service.service_version,
    )
    .expect_err("runtime materialization must reject under-billed replica storage");
    assert!(matches!(
        error.downcast_ref::<iroha_data_model::soracloud::SoracloudManifestError>(),
        Some(
            iroha_data_model::soracloud::SoracloudManifestError::InvalidField {
                field: "service_lease.replica_count",
                ..
            }
        )
    ));
    Ok(())
}

#[test]
fn lease_volume_plans_reject_authoritative_binding_mismatches() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let baseline = sample_deployment_state(&bundle);
    let mut mismatches = Vec::new();

    let mut kind = baseline.clone();
    kind.lease_volume_states[0].kind = SoraLeaseVolumeKindV1::ConfidentialLeaseVolume;
    mismatches.push(("kind", kind));
    let mut storage_class = baseline.clone();
    storage_class.lease_volume_states[0].storage_class =
        iroha_data_model::sorafs::pin_registry::StorageClass::Hot;
    mismatches.push(("storage_class", storage_class));
    let mut mount_path = baseline.clone();
    mount_path.lease_volume_states[0].mount_path = "/different".to_owned();
    mismatches.push(("mount_path", mount_path));
    let mut max_total_bytes = baseline;
    max_total_bytes.lease_volume_states[0].max_total_bytes += 1;
    mismatches.push(("max_total_bytes", max_total_bytes));

    for (field, deployment) in mismatches {
        let error = build_lease_volume_plans(
            &bundle,
            &deployment,
            temp_dir.path(),
            bundle.service.service_name.as_ref(),
            &bundle.service.service_version,
        )
        .expect_err("an authoritative binding mismatch must fail closed");
        assert!(
            matches!(
                error.downcast_ref::<iroha_data_model::soracloud::SoracloudManifestError>(),
                Some(
                    iroha_data_model::soracloud::SoracloudManifestError::InvalidField {
                        field: "lease_volume_states",
                        ..
                    }
                )
            ),
            "mutation {field} must fail the canonical volume binding: {error:?}"
        );
    }
    Ok(())
}

#[test]
fn authoritative_lease_egress_requires_exact_revision_and_reporting_epoch() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let mut deployment = sample_deployment_state(&bundle);
    let lease = deployment.service_lease.as_mut().expect("service lease");
    let reporting_epoch = lease.reporting_epoch;
    let lease_started_height = lease.lease_started_height;
    lease.egress_reporter_checkpoints = vec![
        sample_lease_egress_checkpoint(
            reporting_epoch,
            bundle.service.service_version.clone(),
            lease_started_height,
            1,
            Hash::new(b"former-placement"),
            BOB_ID.clone(),
            11,
            true,
        ),
        sample_lease_egress_checkpoint(
            reporting_epoch,
            bundle.service.service_version.clone(),
            lease_started_height,
            1,
            Hash::new(b"placement-1"),
            ALICE_ID.clone(),
            37,
            false,
        ),
    ];
    lease.egress_reporter_checkpoints.sort_by(|left, right| {
        (
            left.reporting_epoch,
            left.assignment.service_version.as_str(),
            left.assignment.placement.replica_slot,
            left.assignment.placement.placement_incarnation,
            &left.assignment.placement.validator_account_id,
        )
            .cmp(&(
                right.reporting_epoch,
                right.assignment.service_version.as_str(),
                right.assignment.placement.replica_slot,
                right.assignment.placement.placement_incarnation,
                &right.assignment.placement.validator_account_id,
            ))
    });
    lease
        .refresh_accounted_egress_bytes()
        .expect("exact egress aggregate");
    let mut state = test_state()?;
    let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
    insert_service_deployment_fixture(world, &bundle, deployment);
    insert_inrou_service_placement_record_fixture(
        world,
        &bundle,
        vec![SoraInrouReplicaPlacementV1 {
            replica_slot: 1,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            lease_started_height: 1,
            placement_incarnation: Hash::new(b"placement-1"),
            host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
            validator_account_id: ALICE_ID.clone(),
            peer_id: canonical_inrou_test_peer_id().to_owned(),
            selected_guest_isa: SoraInrouGuestIsaV1::X8664,
        }],
    );
    let fixture = RuntimeFixture::new(&state)?;
    let view = state.view();

    assert_eq!(
        fixture
            .manager
            .authoritative_service_reporting_epoch_egress_bytes(
                &view,
                bundle.service.service_name.as_ref(),
                &bundle.service.service_version,
                1,
                reporting_epoch,
            )?,
        48
    );
    for (service_version, candidate_epoch) in [
        ("missing-revision", reporting_epoch),
        (bundle.service.service_version.as_str(), reporting_epoch + 1),
    ] {
        let error = fixture
            .manager
            .authoritative_service_reporting_epoch_egress_bytes(
                &view,
                bundle.service.service_name.as_ref(),
                service_version,
                1,
                candidate_epoch,
            )
            .expect_err("non-exact authoritative lease egress must fail closed");
        assert!(
            error.to_string().contains("no authoritative lease egress"),
            "unexpected error: {error}"
        );
    }
    Ok(())
}

#[test]
fn authoritative_lease_egress_rejects_active_inrou_rollout() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let mut deployment = sample_deployment_state(&bundle);
    let lease = deployment.service_lease.as_ref().expect("service lease");
    let reporting_epoch = lease.reporting_epoch;
    let lease_started_height = lease.lease_started_height;
    deployment.active_rollout = Some(SoraServiceRolloutStateV1 {
        schema_version: SORA_SERVICE_ROLLOUT_STATE_VERSION_V1,
        rollout_handle: "retired-inrou-canary".to_owned(),
        baseline_version: "2026.01.0".to_owned(),
        candidate_version: bundle.service.service_version.clone(),
        canary_percent: 25,
        traffic_percent: 25,
        stage: SoraRolloutStageV1::Canary,
        health_failures: 0,
        max_health_failures: 3,
        health_window_secs: 30,
        created_sequence: 7,
        updated_sequence: 7,
    });
    let mut state = test_state()?;
    insert_service_deployment_fixture(
        &mut Arc::get_mut(&mut state).expect("unique test state").world,
        &bundle,
        deployment,
    );
    let fixture = RuntimeFixture::new(&state)?;
    let view = state.view();

    let error = fixture
        .manager
        .authoritative_service_reporting_epoch_egress_bytes(
            &view,
            bundle.service.service_name.as_ref(),
            &bundle.service.service_version,
            lease_started_height,
            reporting_epoch,
        )
        .expect_err("first-release Inrou egress must reject an active rollout");
    assert!(
        error
            .to_string()
            .contains("unsupported active Inrou canary"),
        "unexpected error: {error:?}"
    );
    Ok(())
}

#[test]
fn authoritative_lease_egress_rejects_cross_placement_u64_overflow() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let mut deployment = sample_deployment_state(&bundle);
    let lease = deployment.service_lease.as_mut().expect("service lease");
    let reporting_epoch = lease.reporting_epoch;
    let lease_started_height = lease.lease_started_height;
    lease.egress_reporter_checkpoints = vec![
        sample_lease_egress_checkpoint(
            reporting_epoch,
            bundle.service.service_version.clone(),
            lease_started_height,
            1,
            Hash::new(b"former-placement"),
            BOB_ID.clone(),
            u64::MAX,
            true,
        ),
        sample_lease_egress_checkpoint(
            reporting_epoch,
            bundle.service.service_version.clone(),
            lease_started_height,
            1,
            Hash::new(b"placement-1"),
            ALICE_ID.clone(),
            1,
            false,
        ),
    ];
    lease.egress_reporter_checkpoints.sort_by(|left, right| {
        (
            left.reporting_epoch,
            left.assignment.service_version.as_str(),
            left.assignment.placement.replica_slot,
            left.assignment.placement.placement_incarnation,
            &left.assignment.placement.validator_account_id,
        )
            .cmp(&(
                right.reporting_epoch,
                right.assignment.service_version.as_str(),
                right.assignment.placement.replica_slot,
                right.assignment.placement.placement_incarnation,
                &right.assignment.placement.validator_account_id,
            ))
    });
    lease
        .refresh_accounted_egress_bytes()
        .expect("u128 lease aggregate must represent the cross-placement sum");
    let mut state = test_state()?;
    let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
    insert_service_deployment_fixture(world, &bundle, deployment);
    insert_inrou_service_placement_record_fixture(
        world,
        &bundle,
        vec![SoraInrouReplicaPlacementV1 {
            replica_slot: 1,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            lease_started_height: 1,
            placement_incarnation: Hash::new(b"placement-1"),
            host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
            validator_account_id: ALICE_ID.clone(),
            peer_id: canonical_inrou_test_peer_id().to_owned(),
            selected_guest_isa: SoraInrouGuestIsaV1::X8664,
        }],
    );
    let fixture = RuntimeFixture::new(&state)?;
    let view = state.view();

    let error = fixture
        .manager
        .authoritative_service_reporting_epoch_egress_bytes(
            &view,
            bundle.service.service_name.as_ref(),
            &bundle.service.service_version,
            1,
            reporting_epoch,
        )
        .expect_err("the local u64 revision counter must fail closed on overflow");
    assert!(
        error
            .to_string()
            .contains("exceeds the local u64 revision counter"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn reporter_target_epoch_advances_only_for_a_missing_identity_at_the_exact_cap() -> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let mut deployment = sample_deployment_state(&bundle);
    let lease = deployment.service_lease.as_mut().expect("service lease");
    let reporting_epoch = lease.reporting_epoch;
    let lease_started_height = lease.lease_started_height;
    lease.egress_reporter_checkpoints = (0..SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1)
        .map(|index| {
            sample_lease_egress_checkpoint(
                reporting_epoch,
                format!("retired-{index:04}"),
                lease_started_height,
                1,
                Hash::new(Encode::encode(&("retired-placement", index))),
                BOB_ID.clone(),
                1,
                true,
            )
        })
        .collect();
    let exact = &mut lease.egress_reporter_checkpoints[0];
    exact.assignment.service_version = bundle.service.service_version.clone();
    exact.assignment.placement.replica_slot = 1;
    exact.assignment.placement.placement_incarnation = Hash::new(b"placement-1");
    exact.assignment.placement.validator_account_id = ALICE_ID.clone();
    lease
        .refresh_accounted_egress_bytes()
        .expect("exact capped reporter aggregate");
    let mut state = test_state()?;
    let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
    insert_service_deployment_fixture(world, &bundle, deployment);
    let fixture = RuntimeFixture::configured(&state, |config| {
        config.with_local_host_identity(ALICE_ID.clone(), canonical_inrou_test_peer_id())
    })?;
    let view = state.view();
    assert_eq!(
        fixture
            .manager
            .authoritative_service_lease_reporter_target_epoch(
                &view,
                bundle.service.service_name.as_ref(),
                1,
                &bundle.service.service_version,
                1,
                Hash::new(b"placement-1"),
            ),
        Some(reporting_epoch),
        "an admitted identity must stay in the current epoch"
    );
    assert_eq!(
        fixture
            .manager
            .authoritative_service_lease_reporter_target_epoch(
                &view,
                bundle.service.service_name.as_ref(),
                1,
                &bundle.service.service_version,
                2,
                Hash::new(b"placement-2"),
            ),
        reporting_epoch.checked_add(1),
        "only a missing identity at the exact cap may request the checked successor"
    );
    assert!(
        fixture
            .manager
            .authoritative_service_lease_reporter_checkpoint(
                &view,
                bundle.service.service_name.as_ref(),
                2,
                reporting_epoch,
                &bundle.service.service_version,
                1,
                Hash::new(b"placement-1"),
            )
            .is_none(),
        "a checkpoint from another lease incarnation must not be reused"
    );
    Ok(())
}

#[test]
fn collect_active_versions_rejects_out_of_range_rollout_weight() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let mut deployment = sample_deployment_state(&bundle);
    deployment.active_rollout = Some(SoraServiceRolloutStateV1 {
        schema_version: SORA_SERVICE_ROLLOUT_STATE_VERSION_V1,
        rollout_handle: "rollout-7".to_owned(),
        baseline_version: bundle.service.service_version.clone(),
        candidate_version: "2099.1.0".to_owned(),
        canary_percent: 25,
        traffic_percent: 101,
        stage: SoraRolloutStageV1::Canary,
        health_failures: 0,
        max_health_failures: 3,
        health_window_secs: 30,
        created_sequence: 7,
        updated_sequence: 7,
    });

    let error = collect_active_versions(&deployment)
        .expect_err("out-of-range rollout weights must not be clamped");
    assert!(
        error.to_string().contains("traffic_percent 101"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn collect_active_versions_uses_explicit_baseline_without_revision_fallback() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let mut deployment = sample_deployment_state(&bundle);
    deployment.active_rollout = Some(SoraServiceRolloutStateV1 {
        schema_version: SORA_SERVICE_ROLLOUT_STATE_VERSION_V1,
        rollout_handle: "rollout-8".to_owned(),
        baseline_version: "2026.1.0".to_owned(),
        candidate_version: bundle.service.service_version.clone(),
        canary_percent: 25,
        traffic_percent: 25,
        stage: SoraRolloutStageV1::Canary,
        health_failures: 0,
        max_health_failures: 3,
        health_window_secs: 30,
        created_sequence: 8,
        updated_sequence: 8,
    });

    assert_eq!(
        collect_active_versions(&deployment)?,
        vec![
            (
                "2026.1.0".to_owned(),
                SoracloudRuntimeRevisionRole::Active,
                75,
            ),
            (
                bundle.service.service_version.clone(),
                SoracloudRuntimeRevisionRole::CanaryCandidate,
                25,
            ),
        ]
    );
    Ok(())
}

#[test]
fn inrou_placement_reconcile_rejects_active_rollout() -> Result<()> {
    let mut candidate = sample_inrou_test_bundle()?;
    candidate.service.service_version = "2026.2.0".to_owned();
    let mut baseline = candidate.clone();
    baseline.service.service_version = "2026.1.0".to_owned();

    let mut deployment = sample_deployment_state(&candidate);
    deployment.active_rollout = Some(SoraServiceRolloutStateV1 {
        schema_version: SORA_SERVICE_ROLLOUT_STATE_VERSION_V1,
        rollout_handle: "rollout-explicit-baseline".to_owned(),
        baseline_version: baseline.service.service_version.clone(),
        candidate_version: candidate.service.service_version.clone(),
        canary_percent: 25,
        traffic_percent: 25,
        stage: SoraRolloutStageV1::Canary,
        health_failures: 0,
        max_health_failures: 3,
        health_window_secs: 30,
        created_sequence: 9,
        updated_sequence: 9,
    });

    let mut state = test_state()?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &baseline);
        insert_service_revision_fixture(world, &candidate);
        insert_service_deployment_fixture(world, &candidate, deployment);
        insert_inrou_service_placement_record_fixture(world, &baseline, Vec::new());
        insert_inrou_service_placement_record_fixture(world, &candidate, Vec::new());
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    let view = state.view();
    let bundle_registry = collect_service_revision_registry(&view);

    let error = manager
        .inrou_placement_reconcile_needed(&view, &bundle_registry)
        .expect_err("first-release Inrou placement reconciliation must reject active rollout");
    assert!(
        error
            .to_string()
            .contains("unsupported active Inrou canary"),
        "unexpected error: {error:?}"
    );
    Ok(())
}

#[test]
fn inrou_placement_reconcile_tracks_host_availability_drift_without_retrying_stable_loss()
-> Result<()> {
    let bundle = sample_inrou_test_bundle()?;
    let deployment = sample_deployment_state(&bundle);
    let mut state = test_state()?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
    }
    let local_peer_id = canonical_inrou_test_peer_id();
    insert_inrou_service_placement_fixture(&mut state, &bundle, local_peer_id, [1]);
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        assert!(
            manager.inrou_placement_reconcile_needed(&view, &bundle_registry)?,
            "an available placement with no exact active host advert must reconcile"
        );
    }
    drop(manager);

    let placement_key = (
        bundle.service.service_name.to_string(),
        bundle.service.service_version.clone(),
    );
    let placements = Arc::get_mut(&mut state)
        .expect("runtime manager released its state reference")
        .world
        .soracloud_inrou_service_placements_mut_for_testing();
    let mut placement_record = {
        let snapshot = placements.view();
        snapshot
            .get(&placement_key)
            .cloned()
            .expect("Inrou placement record")
    };
    placement_record
        .placements
        .first_mut()
        .expect("Inrou placement")
        .host_availability = SoraInrouReplicaHostAvailabilityV1::Unavailable;
    placements.insert(placement_key, placement_record);
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    let view = state.view();
    let bundle_registry = collect_service_revision_registry(&view);
    assert!(
        !manager.inrou_placement_reconcile_needed(&view, &bundle_registry)?,
        "a retained unavailable placement must not submit endless reconciliation retries while its exact host remains absent"
    );
    Ok(())
}

fn soracloud_entrypoint(name: &str, entry_pc: u64) -> ivm::EmbeddedEntrypointDescriptor {
    ivm::EmbeddedEntrypointDescriptor {
        name: name.to_owned(),
        kind: EntryPointKind::View,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit,
                ],
            },
        ),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: Some(true),
        access_hints_skipped: Vec::new(),
        triggers: Vec::new(),
        entry_pc,
    }
}
fn soracloud_contract_artifact_with_functions(
    functions: Vec<(ivm::EmbeddedEntrypointDescriptor, Vec<u32>)>,
) -> Vec<u8> {
    let metadata = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let mut entrypoints = Vec::new();
    let mut callables = Vec::new();
    let mut code_words = Vec::new();
    for (mut entry, body) in functions {
        entry.entry_pc = u64::try_from(code_words.len() * 4).expect("fixture PC fits u64");
        callables.push(ivm::call::EmbeddedCallableV1 {
            entry_pc: entry.entry_pc,
            frame_bytes: 0,
            arguments: entry.argument_schema.as_ref().map_or_else(
                ivm::call::CallSchemaV1::empty,
                |schema| {
                    ivm::call::CallSchemaV1::from_entrypoint_arguments(schema)
                        .expect("fixture public argument schema")
                },
            ),
            results: ivm::call::CallSchemaV1::from_entrypoint_type(
                entry.return_schema.as_ref().expect("fixture return schema"),
            )
            .expect("fixture public result schema"),
        });
        entrypoints.push(entry);
        code_words.extend(body);
    }
    let contract_interface = ivm::EmbeddedContractInterfaceV1 {
        permissions: Vec::new(),
        events: Vec::new(),
        callables,
        seiyaku_name: "TestContract".to_owned(),
        compiler_fingerprint: "irohad-soracloud-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints,
        error_messages: Vec::new(),
        error_types: Vec::new(),
        enum_types: Vec::new(),
        states: Vec::new(),
    };
    let mut bytes = metadata.encode();
    bytes.extend_from_slice(&contract_interface.encode_section());
    for word in code_words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn soracloud_unit_return_words() -> Vec<u32> {
    use ivm::{encoding::wide as enc, instruction::wide};
    vec![
        enc::encode_store(wide::memory::STORE64, 12, 0, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 10, 12, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 1),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
    ]
}
fn simple_soracloud_contract_artifact(entrypoints: &[&str]) -> Vec<u8> {
    soracloud_contract_artifact_with_functions(
        entrypoints
            .iter()
            .map(|name| (soracloud_entrypoint(name, 0), soracloud_unit_return_words()))
            .collect(),
    )
}
fn soracloud_leaf(kind: EntrypointValueKindV1) -> ivm::EntrypointValueTypeV1 {
    ivm::EntrypointValueTypeV1 {
        nodes: vec![EntrypointValueTypeNodeV1::Leaf(kind)],
    }
}
fn soracloud_typed_entrypoint(
    name: &str,
    fields: &[(&str, EntrypointValueKindV1)],
    result: ivm::EntrypointValueTypeV1,
) -> ivm::EmbeddedEntrypointDescriptor {
    let mut entrypoint = soracloud_entrypoint(name, 0);
    entrypoint.argument_schema = (!fields.is_empty()).then(|| ivm::EntrypointArgumentSchemaV1 {
        fields: fields
            .iter()
            .map(|(name, kind)| {
                iroha_data_model::smart_contract::entrypoint::EntrypointArgumentFieldV1 {
                    name: (*name).to_owned(),
                    ty: soracloud_leaf(*kind),
                }
            })
            .collect(),
    });
    entrypoint.params = fields
        .iter()
        .map(
            |(name, kind)| iroha_data_model::smart_contract::manifest::EntrypointParamDescriptor {
                name: (*name).to_owned(),
                type_name: soracloud_leaf(*kind)
                    .canonical_type_name()
                    .expect("leaf type name"),
            },
        )
        .collect();
    entrypoint.return_type = result.canonical_type_name();
    entrypoint.return_schema = Some(result);
    entrypoint
}
fn soracloud_echo_return_words(argument_index: u8) -> Vec<u32> {
    use ivm::{encoding::wide as enc, instruction::wide};
    vec![
        enc::encode_load(
            wide::memory::LOAD64,
            5,
            10,
            i8::try_from(argument_index * 8).expect("fixture argument offset"),
        ),
        enc::encode_store(wide::memory::STORE64, 12, 5, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 10, 12, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 1),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
    ]
}
fn soracloud_query_echo_artifact(name: &str, metadata: bool) -> Vec<u8> {
    soracloud_contract_artifact_with_functions(vec![(
        soracloud_typed_entrypoint(
            name,
            &[
                (
                    "_request_body",
                    if metadata {
                        EntrypointValueKindV1::Blob
                    } else {
                        EntrypointValueKindV1::Json
                    },
                ),
                ("_request_meta", EntrypointValueKindV1::Json),
                ("observed_height", EntrypointValueKindV1::Int),
            ],
            soracloud_leaf(EntrypointValueKindV1::Json),
        ),
        soracloud_echo_return_words(u8::from(metadata)),
    )])
}
fn soracloud_update_artifact(names: &[&str]) -> Vec<u8> {
    soracloud_contract_artifact_with_functions(
        names
            .iter()
            .map(|name| {
                (
                    soracloud_typed_entrypoint(
                        name,
                        &[
                            ("_request_body", EntrypointValueKindV1::Blob),
                            ("execution_sequence", EntrypointValueKindV1::Int),
                            ("observed_height", EntrypointValueKindV1::Int),
                        ],
                        ivm::EntrypointValueTypeV1 {
                            nodes: vec![EntrypointValueTypeNodeV1::Unit],
                        },
                    ),
                    soracloud_unit_return_words(),
                )
            })
            .collect(),
    )
}
fn soracloud_echo_vm(
    body_tlv: &[u8],
    kind: EntrypointValueKindV1,
) -> Result<(IVM, SoracloudOutputKind)> {
    let bundle = load_deployment_bundle_fixture()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let request = sample_ordered_mailbox_request(
        &bundle,
        "query",
        sample_mailbox_message(&bundle, "query", b"echo".to_vec()),
    );
    let artifact = soracloud_contract_artifact_with_functions(vec![(
        soracloud_typed_entrypoint("echo", &[("_request_body", kind)], soracloud_leaf(kind)),
        soracloud_echo_return_words(0),
    )]);
    let contract = prepare_contract(Arc::from(artifact))?;
    let mut vm = IVM::new(u64::MAX);
    vm.load_prepared(&contract)?;
    let (arguments, output_kind) = prepare_soracloud_invocation(
        &mut vm,
        &contract,
        "echo",
        SoracloudInvocationInput {
            body_tlv,
            metadata_tlv: None,
            execution_sequence: None,
            observed_height: 17,
        },
    )?;
    vm.set_host(
        SoracloudIvmHost::new(request, temp_dir.path().to_path_buf(), BTreeMap::new())
            .with_prepared_arguments(arguments),
    );
    vm.run()?;
    Ok((vm, output_kind))
}
fn bundle_handler(
    bundle: &SoraDeploymentBundleV1,
    handler_name: &str,
) -> iroha_data_model::soracloud::SoraServiceHandlerV1 {
    bundle
        .service
        .handlers
        .iter()
        .find(|handler| handler.handler_name.as_ref() == handler_name)
        .cloned()
        .expect("fixture handler must exist")
}
fn sample_mailbox_message(
    bundle: &SoraDeploymentBundleV1,
    handler_name: &str,
    payload_bytes: Vec<u8>,
) -> SoraServiceMailboxMessageV1 {
    let payload_commitment = Hash::new(&payload_bytes);
    let mut message = SoraServiceMailboxMessageV1 {
        schema_version: SORA_SERVICE_MAILBOX_MESSAGE_VERSION_V1,
        message_id: Hash::prehashed([0; Hash::LENGTH]),
        from_service: "scheduler".parse().expect("literal name"),
        from_service_version: "scheduler-v1".to_owned(),
        from_handler: "dispatch".parse().expect("literal name"),
        to_service: bundle.service.service_name.clone(),
        to_service_version: bundle.service.service_version.clone(),
        to_handler: handler_name.parse().expect("fixture handler name"),
        payload_bytes,
        payload_commitment,
        delivery_delay_blocks: 0,
        enqueue_sequence: 6,
        enqueue_height: 5,
        available_after_height: 5,
        expires_at_height: 6,
    };
    message.message_id = derive_soracloud_mailbox_message_id_v1(&message);
    message
}
fn sample_ordered_mailbox_request(
    bundle: &SoraDeploymentBundleV1,
    handler_name: &str,
    mailbox_message: SoraServiceMailboxMessageV1,
) -> SoracloudOrderedMailboxExecutionRequest {
    SoracloudOrderedMailboxExecutionRequest {
        observed_height: 5,
        observed_block_hash: None,
        observed_sequence: 7,
        deployment: sample_deployment_state(bundle),
        bundle: bundle.clone(),
        handler: Some(bundle_handler(bundle, handler_name)),
        mailbox_message,
        runtime_state: Some(sample_runtime_state(bundle)),
        authoritative_pending_mailbox_messages: 1,
    }
}
fn sample_published_inrou_guest_image_artifact(seed: u8) -> SoraPublishedInrouGuestImageArtifactV1 {
    SoraPublishedInrouGuestImageArtifactV1 {
        manifest_digest_hex: hex::encode([seed; 32]),
        content_cid: encode_content_cid(&sorafs_manifest::canonical_manifest_root_cid([seed; 32])),
    }
}
fn sample_inrou_test_bundle() -> Result<SoraDeploymentBundleV1> {
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.container.runtime = SoraContainerRuntimeV1::Inrou;
    bundle.container.inrou = Some(iroha_data_model::soracloud::SoraInrouManifestV1 {
        schema_version: iroha_data_model::soracloud::SORA_INROU_MANIFEST_VERSION_V1,
        guest_images: BTreeMap::from([
            (
                SoraInrouGuestIsaV1::X8664,
                SoraInrouGuestImageV1 {
                    kernel_image_path: "/inrou/x86_64/vmlinux".to_owned(),
                    rootfs_image_path: "/inrou/x86_64/rootfs.ext4".to_owned(),
                    initrd_image_path: Some("/inrou/x86_64/initrd.img".to_owned()),
                    published_artifact: sample_published_inrou_guest_image_artifact(0x31),
                },
            ),
            (
                SoraInrouGuestIsaV1::Aarch64,
                SoraInrouGuestImageV1 {
                    kernel_image_path: "/inrou/aarch64/vmlinux".to_owned(),
                    rootfs_image_path: "/inrou/aarch64/rootfs.ext4".to_owned(),
                    initrd_image_path: Some("/inrou/aarch64/initrd.img".to_owned()),
                    published_artifact: sample_published_inrou_guest_image_artifact(0x32),
                },
            ),
        ]),
    });
    bundle.container.entrypoint = "/bin/sh".to_owned();
    bundle.container.args = vec!["-lc".to_owned(), "echo inrou-test".to_owned()];
    bundle.container.capabilities.network = SoraNetworkPolicyV1::Isolated;
    bundle.container.lifecycle.start_grace_secs = std::num::NonZeroU32::new(180).expect("nonzero");
    bundle.service.execution_plane =
        iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService;
    bundle.service.replicas = std::num::NonZeroU16::new(1).expect("replica");
    bundle.service.placement_targets =
        BTreeSet::from([iroha_data_model::soracloud::SoraInrouPlacementTargetV1 {
            validator_account_id: ALICE_ID.clone(),
            peer_id: canonical_inrou_test_peer_id().to_owned(),
        }]);
    bundle.service.state_bindings.clear();
    bundle.service.handlers.clear();
    bundle.service.artifacts.clear();
    bundle.service.lease_volumes = vec![
        iroha_data_model::soracloud::SoraLeaseVolumeBindingV1 {
            volume_name: "root_disk".parse().expect("volume"),
            kind: SoraLeaseVolumeKindV1::PersistentRootLeaseVolume,
            storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Warm,
            mount_path: "/".to_owned(),
            max_total_bytes: std::num::NonZeroU64::new(16 * 1024 * 1024 * 1024).expect("bytes"),
        },
        iroha_data_model::soracloud::SoraLeaseVolumeBindingV1 {
            volume_name: "index_state".parse().expect("volume"),
            kind: SoraLeaseVolumeKindV1::ServiceLeaseVolume,
            storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Warm,
            mount_path: "/var/lib/soracloud/volumes/index_state".to_owned(),
            max_total_bytes: std::num::NonZeroU64::new(128 * 1024 * 1024).expect("bytes"),
        },
    ];
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    Ok(bundle)
}
fn sample_inrou_runtime_plan(
    bundle: &SoraDeploymentBundleV1,
    selected_guest_isa: SoraInrouGuestIsaV1,
) -> SoracloudRuntimeInrouPlan {
    let image = bundle
        .container
        .inrou
        .as_ref()
        .expect("Inrou fixture manifest")
        .guest_images
        .get(&selected_guest_isa)
        .expect("selected guest-image fixture");
    SoracloudRuntimeInrouPlan {
        selected_guest_isa,
        kernel_image_path: image.kernel_image_path.clone(),
        rootfs_image_path: image.rootfs_image_path.clone(),
        initrd_image_path: image.initrd_image_path.clone(),
        root_volume_name: "root_disk".to_owned(),
    }
}
fn insert_inrou_service_placement_fixture(
    state: &mut Arc<State>,
    bundle: &SoraDeploymentBundleV1,
    local_peer_id: &str,
    replica_slots: impl IntoIterator<Item = u16>,
) {
    let selected_guest_isa =
        current_host_inrou_guest_isa().expect("tests require a supported Inrou host ISA");
    let placements = replica_slots
        .into_iter()
        .map(|replica_slot| SoraInrouReplicaPlacementV1 {
            replica_slot,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            lease_started_height: 1,
            placement_incarnation: Hash::new(Encode::encode(&("placement", replica_slot))),
            host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
            validator_account_id: ALICE_ID.clone(),
            peer_id: local_peer_id.to_owned(),
            selected_guest_isa,
        })
        .collect::<Vec<_>>();
    insert_active_public_lane_validator_fixture(state.as_ref(), local_peer_id);
    let world = &mut Arc::get_mut(state).expect("unique test state").world;
    insert_inrou_service_placement_record_fixture(world, bundle, placements);
}
fn insert_active_public_lane_validator_fixture(state: &State, local_peer_id: &str) {
    let lane_id = iroha_model_base::topology::LaneId::SINGLE;
    // This fixture commits only world state, so its tenure must start at
    // the exact snapshot height rather than an uncommitted next block.
    let activation_height = committed_height(&state.view());
    let next_height = state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing()
        .public_lane_validators_mut_for_testing()
        .insert(
            (lane_id, ALICE_ID.clone()),
            iroha_data_model::nexus::PublicLaneValidatorRecord {
                lane_id,
                validator: ALICE_ID.clone(),
                peer_id: local_peer_id
                    .parse()
                    .expect("canonical Inrou test peer identifier"),
                stake_account: ALICE_ID.clone(),
                total_stake: Quantity::from(1_u64),
                self_stake: Quantity::from(1_u64),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit Inrou public-lane validator fixture");
}
#[test]
fn inrou_fixture_validator_is_active_in_the_unchanged_snapshot() -> Result<()> {
    let state = test_state()?;
    let before = committed_height(&state.view());
    let local_peer = canonical_inrou_test_peer_id();
    insert_active_public_lane_validator_fixture(state.as_ref(), local_peer);
    let view = state.view();
    assert_eq!(committed_height(&view), before);
    assert!(
        iroha_core::soracloud_runtime::soracloud_validator_has_active_peer_binding(
            view.world(),
            &ALICE_ID,
            local_peer,
            before,
            |lane_id| view.is_lane_active_for_authority(lane_id),
        )
    );
    assert!(
        !iroha_core::soracloud_runtime::soracloud_validator_has_active_peer_binding(
            view.world(),
            &ALICE_ID,
            "foreign peer",
            before,
            |lane_id| view.is_lane_active_for_authority(lane_id),
        )
    );
    Ok(())
}
fn insert_inrou_service_placement_record_fixture(
    world: &mut World,
    bundle: &SoraDeploymentBundleV1,
    placements: Vec<SoraInrouReplicaPlacementV1>,
) {
    world
        .soracloud_inrou_service_placements_mut_for_testing()
        .insert(
            (
                bundle.service.service_name.to_string(),
                bundle.service.service_version.clone(),
            ),
            iroha_data_model::soracloud::SoraInrouServicePlacementRecordV1 {
                schema_version:
                    iroha_data_model::soracloud::SORA_INROU_SERVICE_PLACEMENT_RECORD_VERSION_V1,
                service_name: bundle.service.service_name.clone(),
                service_version: bundle.service.service_version.clone(),
                desired_replica_count: bundle.service.replicas.get(),
                eligible_validator_count: 1,
                placements,
                reconciled_at_ms: 1,
                last_error: None,
            },
        );
}
fn insert_local_inrou_service_placement_fixture(
    state: &mut Arc<State>,
    bundle: &SoraDeploymentBundleV1,
    local_peer_id: &str,
    selected_guest_isa: SoraInrouGuestIsaV1,
) {
    insert_active_public_lane_validator_fixture(state.as_ref(), local_peer_id);
    let world = &mut Arc::get_mut(state).expect("unique test state").world;
    insert_inrou_service_placement_record_fixture(
        world,
        bundle,
        vec![SoraInrouReplicaPlacementV1 {
            replica_slot: 1,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            lease_started_height: 1,
            placement_incarnation: Hash::new(b"placement-1"),
            host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
            validator_account_id: ALICE_ID.clone(),
            peer_id: local_peer_id.to_owned(),
            selected_guest_isa,
        }],
    );
}
fn insert_local_inrou_host_capability_fixture(
    state: &mut Arc<State>,
    bundle: &SoraDeploymentBundleV1,
    local_peer_id: &str,
    selected_guest_isa: SoraInrouGuestIsaV1,
) {
    let trusted_guest_artifact = bundle
        .container
        .inrou
        .as_ref()
        .expect("Inrou fixture manifest")
        .guest_images
        .get(&selected_guest_isa)
        .expect("selected guest-image fixture")
        .published_artifact
        .clone();
    let capability = SoraInrouHostCapabilityRecordV1 {
        schema_version: SORA_INROU_HOST_CAPABILITY_RECORD_VERSION_V1,
        validator_account_id: ALICE_ID.clone(),
        peer_id: local_peer_id.to_owned(),
        supported_guest_isas: BTreeSet::from([selected_guest_isa]),
        trusted_guest_artifact,
        max_hosted_replica_capacity: SORA_INROU_HOSTED_REPLICA_CAPACITY_V1,
        max_cpu_millis: u32::MAX,
        max_memory_bytes: u64::MAX,
        max_storage_bytes: u64::MAX,
        advertised_at_ms: 1,
        heartbeat_expires_at_ms: u64::MAX,
    };
    capability
        .validate()
        .expect("valid local Inrou host capability fixture");
    Arc::get_mut(state)
        .expect("unique test state")
        .world
        .soracloud_inrou_host_capabilities_mut_for_testing()
        .insert(ALICE_ID.clone(), capability);
}
fn materialize_inrou_replica_plan_for_tests(
    bundle: &SoraDeploymentBundleV1,
) -> Result<(
    tempfile::TempDir,
    SoracloudRuntimeServicePlan,
    HostedHttpWorkerCacheKey,
)> {
    bundle.validate_for_admission()?;
    let mut state = test_state()?;
    let deployment_state = sample_deployment_state(bundle);
    let process_generation = deployment_state.process_generation;
    let local_peer_id = canonical_inrou_test_peer_id();
    let selected_guest_isa =
        current_host_inrou_guest_isa().expect("tests require a supported Inrou host ISA");
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, bundle, deployment_state);
    }
    insert_local_inrou_service_placement_fixture(
        &mut state,
        bundle,
        local_peer_id,
        selected_guest_isa,
    );
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let config = test_runtime_manager_config(state_dir.clone())
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    validate_soracloud_runtime_manager_posture(&config)
        .wrap_err("validate Inrou replica-plan fixture runtime posture")?;
    let manager = SoracloudRuntimeManager::new(config, Arc::clone(&state));
    {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        // This fixture projects an already-authoritative local placement.
        // Runtime host discovery remains enforced by `reconcile_once`.
        let snapshot = build_runtime_snapshot(
            &view,
            &bundle_registry,
            &manager.config.state_dir,
            manager.artifacts_root(),
            &manager.config.cache_budgets,
            manager.config.local_validator_account_id.as_ref(),
            manager.config.local_peer_id.as_deref(),
            true,
        )?;
        let revision_plan = snapshot
            .services
            .get(bundle.service.service_name.as_ref())
            .and_then(|versions| versions.get(&bundle.service.service_version))
            .ok_or_else(|| {
                eyre::eyre!(
                    "Inrou replica-plan fixture revision is absent from the production snapshot"
                )
            })?;
        if revision_plan.local_replica_slots.as_slice() != [1] {
            eyre::bail!(
                "Inrou replica-plan fixture expected local replica slot 1, found {:?}",
                revision_plan.local_replica_slots
            );
        }
        manager.write_service_materializations(&snapshot, &bundle_registry, &view)?;
    }
    let service_dir = state_dir
        .join("services")
        .join(storage_path_component(bundle.service.service_name.as_ref()))
        .join(storage_path_component(&bundle.service.service_version));
    let replica_plan: SoracloudRuntimeServicePlan = read_json_optional(
        service_dir
            .join("replicas/replica-0001/runtime_plan.json")
            .as_path(),
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test runtime plan",
    )?
    .ok_or_else(|| eyre::eyre!("materialized Inrou replica runtime plan is missing"))?;
    let placement = exact_inrou_replica_placement(&replica_plan)?.clone();
    let cache_key = HostedHttpWorkerCacheKey {
        runtime: bundle.container.runtime,
        guest_isa: replica_plan
            .inrou
            .as_ref()
            .map(|inrou| inrou.selected_guest_isa),
        service_name: bundle.service.service_name.to_string(),
        service_version: bundle.service.service_version.clone(),
        replica_slot: 1,
        lease_started_height: placement.lease_started_height,
        placement_incarnation: placement.placement_incarnation,
        validator_account_id: placement.validator_account_id,
        peer_id: placement.peer_id,
        bundle_hash: replica_plan.bundle_hash.clone(),
        bundle_path: replica_plan.bundle_path.clone(),
        entrypoint: replica_plan.entrypoint.clone(),
        process_generation,
        args: bundle.container.args.clone(),
        effective_env: replica_plan.effective_env.clone(),
        healthcheck_path: bundle.container.lifecycle.healthcheck_path.clone(),
        service_data_dir: build_native_service_data_dir(
            &state_dir,
            bundle.service.service_name.as_ref(),
        ),
    };
    Ok((temp_dir, replica_plan, cache_key))
}
