const INROU_HEALTH_SERVER_PY: &str = include_str!("fixtures/inrou_health_server.py");

#[test]
fn probe_hosted_http_health_accepts_paths_without_a_leading_slash() -> Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0_u8; 1024];
            let read = std::io::Read::read(&mut stream, &mut request).unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..read]);
            let status_line = if request.starts_with("GET /healthz HTTP/1.1") {
                "HTTP/1.1 200 OK\r\n"
            } else {
                "HTTP/1.1 404 Not Found\r\n"
            };
            let body = if request.starts_with("GET /healthz HTTP/1.1") {
                b"ok\n".as_slice()
            } else {
                b"".as_slice()
            };
            let response = format!(
                "{status_line}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
            let _ = std::io::Write::write_all(&mut stream, body);
        }
    });
    probe_hosted_http_health(&format!("http://{address}"), Some("healthz"))?;
    handle.join().expect("fixture thread should complete");
    Ok(())
}
#[test]
fn fetch_hosted_http_text_accepts_paths_without_a_leading_slash() -> Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0_u8; 1024];
            let read = std::io::Read::read(&mut stream, &mut request).unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..read]);
            let (status_line, body) = if request.starts_with("GET /root-slot HTTP/1.1") {
                ("HTTP/1.1 200 OK\r\n", b"replica-1\n".as_slice())
            } else {
                ("HTTP/1.1 404 Not Found\r\n", b"".as_slice())
            };
            let response = format!(
                "{status_line}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
            let _ = std::io::Write::write_all(&mut stream, body);
        }
    });
    let body = fetch_hosted_http_text(&format!("http://{address}"), "root-slot")?;
    handle.join().expect("fixture thread should complete");
    assert_eq!(body, "replica-1\n");
    Ok(())
}
#[test]
fn execute_ordered_mailbox_retries_when_local_bundle_cache_is_missing() -> Result<()> {
    let state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let artifact_bytes = simple_soracloud_contract_artifact(&["apply_update"]);
    bundle.container.bundle_hash = Hash::new(&artifact_bytes);
    let temp_dir = tempfile::tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"missing-bundle".to_vec()),
    );
    let error = handle
        .execute_ordered_mailbox(request)
        .expect_err("missing local bundle must remain retryable");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    Ok(())
}

#[test]
fn vm_deferrals_are_local_unavailable_and_never_deterministic_faults() -> Result<()> {
    use ivm::ExecutionDeferral;
    let bundle = load_deployment_bundle_fixture()?;
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"retry-me".to_vec()),
    );
    let active = VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity);
    let allocation =
        VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::DemandOverflow);
    for (error, label) in [
        (active, "execution_deferred"),
        (
            VMError::ExecutionDeferred(ExecutionDeferral::VerificationCancelled),
            "execution_deferred",
        ),
        (
            VMError::ExecutionDeferred(ExecutionDeferral::NativeVerificationMemoryUnavailable),
            "execution_deferred",
        ),
        (
            VMError::ExecutionDeferred(ExecutionDeferral::VerifierInitializationUnavailable),
            "execution_deferred",
        ),
        (allocation, "allocation_deferred"),
        // Typed boundary control; actual allocator refusal is exercised by Core's
        // existing global allocator in the native World-cut publication tests.
        (
            VMError::AllocatorDeferred(
                iroha_allocation::AllocatorRefusal::try_from(
                    iroha_allocation::ChargedBufferError::Allocator {
                        requested_bytes: 73,
                    },
                )
                .unwrap(),
            ),
            "allocator_deferred",
        ),
    ] {
        assert_eq!(vm_error_label(&error), label);
        assert_eq!(
            vm_error_kind(&error),
            SoracloudRuntimeExecutionErrorKind::Unavailable,
        );
        let result = ordered_mailbox_vm_failure(request.clone(), &error)
            .expect_err("local deferral must not produce a durable mailbox result");
        assert_eq!(result.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    }
    assert_eq!(vm_error_label(&VMError::OutOfGas), "out_of_gas");
    assert_eq!(
        vm_error_kind(&VMError::OutOfGas),
        SoracloudRuntimeExecutionErrorKind::Internal,
    );
    let deterministic = ordered_mailbox_vm_failure(request, &VMError::OutOfGas)
        .expect("guest gas exhaustion is a deterministic runtime result");
    assert_eq!(
        deterministic
            .runtime_state
            .expect("runtime state")
            .health_status,
        SoraServiceHealthStatusV1::Degraded,
    );
    Ok(())
}
#[test]
fn vm_decode_deferral_retains_original_owner_and_refuses_durable_mailbox_results() -> Result<()> {
    let bytes = norito::encode_canonical(&vec![31_u8; 16]).unwrap();
    let original = norito::core::with_decode_limits_scope(
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || {
            norito::decode_canonical_for_admission::<Vec<u8>>(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
        },
    )
    .unwrap_err()
    .into_local_refusal()
    .unwrap();
    assert_eq!(
        original.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit,
    );
    let bundle = load_deployment_bundle_fixture()?;
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"decode-retry".to_vec()),
    );
    let direct = VMError::DecodeDeferred(original.clone());
    let nested = VMError::Metered {
        gas: 41,
        source: Box::new(VMError::Metered {
            gas: 19,
            source: Box::new(VMError::DecodeDeferred(original.clone())),
        }),
    };
    for error in [direct, nested] {
        assert_eq!(vm_error_label(&error), "decode_deferred");
        assert_eq!(
            vm_error_kind(&error),
            SoracloudRuntimeExecutionErrorKind::Unavailable,
        );
        assert_eq!(error.fault_kind(), None);
        assert_eq!(error.metered_gas(), None);
        let failure = ordered_mailbox_vm_failure(request.clone(), &error)
            .expect_err("original local decoder refusal must not create a durable mailbox result");
        assert_eq!(
            failure.kind,
            SoracloudRuntimeExecutionErrorKind::Unavailable
        );
        let VMError::DecodeDeferred(retained) = error.as_unmetered() else {
            panic!("daemon inspection must preserve the original decoder owner");
        };
        assert_eq!(retained, &original);
        let (gas, unmetered) = error.split_metered();
        assert_eq!(gas, None);
        let VMError::DecodeDeferred(retained) = unmetered else {
            panic!("consuming split must move the original decoder owner");
        };
        assert_eq!(retained, original);
    }
    assert_eq!(
        norito::decode_canonical_for_admission::<Vec<u8>>(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .unwrap(),
        vec![31_u8; 16],
    );
    Ok(())
}

#[test]
fn vm_verification_deferral_moves_original_owner_and_refuses_mailbox_results() -> Result<()> {
    // A real canonical read supplies the original shared owner; this test does not
    // pretend that an MSM allocator failed or perform cryptographic verification.
    let bytes = norito::encode_canonical(&vec![53_u8; 16]).unwrap();
    let bundle = load_deployment_bundle_fixture()?;
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"verification-retry".to_vec()),
    );
    for nested in [false, true] {
        let original = norito::core::with_decode_limits_scope(
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                norito::decode_canonical_for_admission::<Vec<u8>>(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
            },
        )
        .unwrap_err()
        .into_local_refusal()
        .unwrap();
        let expected = original.clone();
        let mut error = VMError::VerificationDeferred(
            iroha_core_zk::VerificationRefusal::from_decode_refusal(original),
        );
        if nested {
            error = VMError::Metered {
                gas: 17,
                source: Box::new(VMError::Metered {
                    gas: 29,
                    source: Box::new(error),
                }),
            };
        }
        assert_eq!(vm_error_label(&error), "verification_deferred");
        assert_eq!(
            vm_error_kind(&error),
            SoracloudRuntimeExecutionErrorKind::Unavailable
        );
        assert_eq!(error.fault_kind(), None);
        assert_eq!(error.metered_gas(), None);
        assert_eq!(
            error.execution_deferral(),
            Some(ivm::ExecutionDeferral::ActiveMemoryCapacity)
        );
        let refusal = ordered_mailbox_vm_failure(request.clone(), &error)
            .expect_err("unfinished verification cannot produce durable mailbox output");
        assert_eq!(
            refusal.kind,
            SoracloudRuntimeExecutionErrorKind::Unavailable
        );
        let (gas, moved) = error.split_metered();
        assert_eq!(gas, None);
        let VMError::VerificationDeferred(owner) = moved else {
            panic!("lost original verification cause");
        };
        assert_eq!(owner.decode_refusal(), Some(&expected));
        assert_eq!(owner.into_decode_refusal().unwrap(), expected);
    }
    assert_eq!(
        norito::decode_canonical_for_admission::<Vec<u8>>(
            &bytes,
            norito::canonical_decode_limits(bytes.len())
        )
        .unwrap(),
        vec![53_u8; 16]
    );
    Ok(())
}

#[test]
fn vm_nested_call_faults_keep_distinct_deterministic_mailbox_labels_when_metered() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"nested-call".to_vec()),
    );
    let permission = deterministic_mailbox_failure_result(
        request.clone(),
        "permission_denied",
        SoraServiceHealthStatusV1::Degraded,
    );
    let mut commitments = Vec::new();
    let cases: [(fn() -> VMError, &str); 2] = [
        (|| VMError::ReentrantCall, "reentrant_call"),
        (|| VMError::CallDepthExceeded, "call_depth_exceeded"),
    ];
    for (make_error, label) in cases {
        let expected = deterministic_mailbox_failure_result(
            request.clone(),
            label,
            SoraServiceHealthStatusV1::Degraded,
        );
        assert_ne!(
            expected.runtime_receipt.result_commitment,
            permission.runtime_receipt.result_commitment,
            "distinct canonical faults must not collapse into a coarse permission label"
        );
        commitments.push(expected.runtime_receipt.result_commitment);
        let error = make_error();
        let metered = VMError::metered(7, make_error());
        assert_eq!(metered.metered_gas(), Some(7));
        for error in [error, metered] {
            assert_eq!(vm_error_label(&error), label);
            assert_eq!(
                vm_error_kind(&error),
                SoracloudRuntimeExecutionErrorKind::Internal,
            );
            assert!(error.execution_deferral().is_none());
            let actual = ordered_mailbox_vm_failure(request.clone(), &error)
                .expect("nested-call refusal is a deterministic runtime result");
            assert_eq!(actual, expected);
            assert_eq!(
                actual.runtime_state.expect("runtime state").health_status,
                SoraServiceHealthStatusV1::Degraded
            );
            assert!(actual.state_mutations.is_empty());
            assert!(actual.outbound_mailbox_messages.is_empty());
            assert!(actual.response_bytes.is_empty());
            assert_eq!(
                actual.runtime_receipt.mailbox_message_id,
                Some(request.mailbox_message.message_id)
            );
        }
    }
    assert_ne!(
        commitments[0], commitments[1],
        "distinct guest faults must have distinct receipts"
    );
    Ok(())
}
#[test]
fn warmed_ordered_mailbox_invalidates_a_changed_bundle_file() -> Result<()> {
    let state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let artifact_bytes = simple_soracloud_contract_artifact(&["apply_update"]);
    bundle.container.bundle_hash = Hash::new(&artifact_bytes);
    let temp_dir = tempfile::tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    let bundle_path = artifacts_root.join(hash_cache_name(bundle.container.bundle_hash));
    fs::write(&bundle_path, &artifact_bytes)?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"validated".to_vec()),
    );
    let first = handle
        .execute_ordered_mailbox(request.clone())
        .map_err(|error| eyre::eyre!("{error:?}"))?;
    assert_eq!(
        first.runtime_state.expect("runtime state").health_status,
        SoraServiceHealthStatusV1::Healthy
    );
    fs::write(&bundle_path, b"tampered Soracloud bundle")?;
    let changed = handle
        .execute_ordered_mailbox(request)
        .map_err(|error| eyre::eyre!("{error:?}"))?;
    assert_eq!(
        changed
            .runtime_state
            .expect("changed runtime state")
            .health_status,
        SoraServiceHealthStatusV1::Degraded
    );
    let stats = handle.ivm_runtime_cache_stats();
    assert_eq!(stats.artifact_reads, 2);
    assert_eq!(stats.artifact_hashes, 2);
    assert_eq!(stats.contract_preparations, 1);
    assert_eq!(stats.runtime_allocations, 1);
    assert_eq!(stats.invalidations, 1);
    assert_eq!(stats.prepared_entries, 0);
    assert_eq!(stats.idle_runtimes, 0);
    Ok(())
}
#[test]
fn execute_local_read_fails_closed_when_runtime_snapshot_is_behind() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let bundle_bytes = b"ivm bundle bytes".to_vec();
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.container.bundle_hash)),
        &bundle_bytes,
    )?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        world.soracloud_service_revisions_mut_for_testing().insert(
            (
                bundle.service.service_name.to_string(),
                bundle.service.service_version.clone(),
            ),
            bundle.clone(),
        );
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(
                bundle.service.service_name.clone(),
                sample_deployment_state(&bundle),
            );
        world.soracloud_service_runtime_mut_for_testing().insert(
            bundle.service.service_name.clone(),
            sample_runtime_state(&bundle),
        );
    }
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    manager.snapshot.write().observed_height = 99;
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let error = handle
        .execute_local_read(SoracloudLocalReadRequest {
            observed_height: 0,
            observed_block_hash: None,
            service_name: bundle.service.service_name.to_string(),
            service_version: bundle.service.service_version.clone(),
            handler_name: "query".to_owned(),
            handler_class: iroha_core::soracloud_runtime::SoracloudLocalReadKind::Query,
            request_method: "GET".to_owned(),
            request_path: "/app/query".to_owned(),
            handler_path: "/".to_owned(),
            request_query: None,
            request_headers: BTreeMap::new(),
            request_body: Vec::new(),
            request_commitment: Hash::new(b"stale-query"),
        })
        .expect_err("stale runtime snapshots must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    Ok(())
}
