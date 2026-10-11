fn store_scanner_attachment(tenant_key: &str, body: &[u8], content_type: &str) -> String {
    let id = attachment_body_id(body);
    let meta = super::super::zk_attachments::AttachmentMeta {
        id: id.clone(),
        content_type: content_type.to_owned(),
        size: body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.to_owned()),
        provenance: Some(fixture_attachment_provenance(body, content_type)),
        zk1_tags: None,
    };
    ensure_tenant_dir(tenant_key);
    fs::write(attachment_bin_path(tenant_key, &id), body).expect("write scanner attachment body");
    fs::write(
        attachment_meta_path(tenant_key, &id),
        norito::json::to_json_pretty(&meta).expect("scanner attachment metadata JSON"),
    )
    .expect("write scanner attachment metadata");
    id
}

#[test]
fn scan_and_report_single_attachment() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    // Create an attachment manually
    let body = fixture_attachment_bytes();
    let id = attachment_body_id(&body);
    let tenant_key = anon_tenant_key();
    let meta = super::super::zk_attachments::AttachmentMeta {
        id: id.clone(),
        content_type: "application/x-norito".to_string(),
        size: body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(&body, "application/x-norito")),
        zk1_tags: None,
    };
    ensure_tenant_dir(&tenant_key);
    fs::write(attachment_bin_path(&tenant_key, &id), &body).unwrap();
    fs::write(
        attachment_meta_path(&tenant_key, &id),
        norito::json::to_json_pretty(&meta).unwrap(),
    )
    .unwrap();
    // Run one scan
    let stats = super::block_on_scan().expect("run prover scan");
    assert_eq!(stats.processed_reports, 1, "one report created");
    assert_eq!(stats.budget_exhausted, None);
    let rep = load_report(&id).expect("report exists");
    assert!(rep.ok);
    assert_eq!(rep.content_type, "application/x-norito");
    assert_eq!(rep.size, body.len() as u64);
    assert_eq!(
        rep.backend.as_deref(),
        Some(fixture_attachment().backend.as_str())
    );
    assert!(rep.proof_hash.is_some());
    assert!(rep.proofs.is_empty());
    assert_eq!(
        rep.latency_ms,
        rep.processed_ms.saturating_sub(rep.created_ms)
    );
}

#[test]
fn report_capacity_eviction_does_not_requeue_completed_attachment() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    let body = fixture_attachment_bytes();
    let id = store_scanner_attachment(&tenant_key, &body, "application/x-norito");

    let first = block_on_scan().expect("run first prover scan");
    assert_eq!(first.processed_reports, 1);
    let initial_report = load_report(&id).expect("initial report");
    assert!(initial_report.ok);
    assert!(
        persist_prover_processing_receipt_if_referenced(&ProverProcessingReceipt {
            version: ZK_PROVER_PROCESSING_STATE_VERSION,
            id: id.clone(),
            processed_ms: initial_report.processed_ms,
            terminal: false,
            retry_not_before_ms: Some(u64::MAX),
            retry_count: 1,
            completed_proof_indices: Vec::new(),
            processing_context_hash: None,
        })
        .expect("persist a simulated crash-window provisional receipt")
    );
    assert_eq!(
        prover_processing_decision(&id, crate::utils::unix_now_ms()),
        ProverProcessingDecision::Suppress
    );

    let replacement = sample_report("f".repeat(ATTACHMENT_ID_HEX_LEN), true, None, "test", 1);
    save_report_with_limits(
        &replacement,
        1,
        iroha_config::parameters::defaults::torii::ZK_PROVER_REPORTS_MAX_BYTES,
    )
    .expect("capacity-limited report store accepts replacement report");
    assert!(
        load_report(&id).is_none(),
        "capacity enforcement must evict the original report"
    );
    assert!(
        load_prover_processing_receipt(&id)
            .expect("eviction-secured processing receipt")
            .terminal,
        "report eviction must finalize the committed disposition first"
    );

    let second = block_on_scan().expect("run second prover scan");
    assert_eq!(
        second.processed_reports, 0,
        "a durable receipt must suppress verification after report eviction"
    );
    assert!(load_report(&id).is_none());
}

#[test]
fn report_persistence_failure_leaves_a_retryable_provisional_receipt() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    let body = fixture_attachment_bytes();
    let id = store_scanner_attachment(&tenant_key, &body, "application/x-norito");
    super::init_persistence().expect("initialize production report persistence");
    struct ResetSaveFailure;
    impl Drop for ResetSaveFailure {
        fn drop(&mut self) {
            super::TEST_REPORT_SAVE_FAILURE.store(false, AtomicOrdering::SeqCst);
        }
    }
    let _reset = ResetSaveFailure;
    super::TEST_REPORT_SAVE_FAILURE.store(true, AtomicOrdering::SeqCst);
    let error =
        process_attachment_once(&id).expect_err("report publication failure must be visible");
    assert_eq!(error.kind(), IoErrorKind::Other);
    assert_eq!(error.to_string(), "injected report publication failure");
    assert!(
        !super::TEST_REPORT_SAVE_FAILURE.load(AtomicOrdering::SeqCst),
        "fault must be reached after verification and provisional receipt publication"
    );
    assert_eq!(proof_verification_attempt_count(), 1);
    assert!(
        try_load_report(&id)
            .expect("report lookup remains healthy")
            .is_none()
    );
    let provisional = load_prover_processing_receipt(&id).expect("durable provisional receipt");
    assert!(!provisional.terminal);
    assert_eq!(provisional.retry_count, 1);
    let retry_at = provisional
        .retry_not_before_ms
        .expect("recorded retry deadline");
    assert!(retry_at > provisional.processed_ms);
    for before_deadline in [provisional.processed_ms, retry_at - 1] {
        assert_eq!(
            prover_processing_decision(&id, before_deadline),
            ProverProcessingDecision::Suppress,
            "the provisional receipt must suppress retries throughout its backoff"
        );
    }
    assert_eq!(
        prover_processing_decision(&id, retry_at),
        ProverProcessingDecision::Due { retry_count: 1 }
    );
    assert_eq!(
        prover_processing_decision(&id, u64::MAX),
        ProverProcessingDecision::Due { retry_count: 1 },
        "a missing report must not be hidden behind a terminal receipt"
    );
}

#[test]
fn successful_report_finalizes_a_suppressed_provisional_receipt_without_reverification() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    let body = fixture_attachment_bytes();
    let id = store_scanner_attachment(&tenant_key, &body, "application/x-norito");
    assert_eq!(
        block_on_scan().expect("run prover scan").processed_reports,
        1
    );
    let report = load_report(&id).expect("successful report");
    assert!(report.ok);
    assert!(
        persist_prover_processing_receipt_if_referenced(&ProverProcessingReceipt {
            version: ZK_PROVER_PROCESSING_STATE_VERSION,
            id: id.clone(),
            processed_ms: report.processed_ms,
            terminal: false,
            retry_not_before_ms: Some(u64::MAX),
            retry_count: 1,
            completed_proof_indices: Vec::new(),
            processing_context_hash: None,
        })
        .expect("replace terminal receipt with crash-window fixture")
    );
    let location = AttachmentLocation { tenant_key, id };

    assert!(
        !attachment_needs_processing(&location).expect("inspect processing disposition"),
        "a persisted successful report must finalize the receipt without verification"
    );
    assert_eq!(
        prover_processing_decision(&location.id, crate::utils::unix_now_ms()),
        ProverProcessingDecision::Suppress
    );
}

#[test]
fn failed_report_with_explicit_null_disposition_is_rejected() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    let body = fixture_attachment_bytes();
    let id = store_scanner_attachment(&tenant_key, &body, "application/x-norito");
    let mut report = sample_report(
        id.clone(),
        false,
        Some("failure with explicit null retry disposition"),
        "application/x-norito",
        crate::utils::unix_now_ms(),
    );
    report.processing = None;
    assert_eq!(
        save_report(&report)
            .expect_err("a report without a processing disposition must not persist")
            .kind(),
        IoErrorKind::InvalidData
    );
}

#[test]
fn malformed_report_file_stops_processing_fail_closed() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    let body = fixture_attachment_bytes();
    let id = store_scanner_attachment(&tenant_key, &body, "application/x-norito");
    ensure_dirs().expect("create prover directories");
    fs::write(report_path_from_sanitized(&id), b"{not a report")
        .expect("persist malformed report fixture");

    let error = block_on_scan().expect_err("malformed report must be a persistence failure");
    assert_eq!(error.kind(), IoErrorKind::InvalidData);
    assert_eq!(
        fs::read(report_path_from_sanitized(&id)).expect("malformed report remains quarantined"),
        b"{not a report"
    );
}

#[test]
fn committed_terminal_failure_repairs_a_due_provisional_receipt() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    let body = fixture_attachment_bytes();
    let id = store_scanner_attachment(&tenant_key, &body, "application/x-norito");
    let location = AttachmentLocation {
        tenant_key,
        id: id.clone(),
    };
    assert!(attachment_needs_processing(&location).expect("inspect processing disposition"));
    let terminal = sample_report(
        id.clone(),
        false,
        Some("terminal verification failure"),
        "application/x-norito",
        crate::utils::unix_now_ms(),
    );
    save_report(&terminal).expect("persist terminal report before simulated crash");
    assert!(
        persist_prover_processing_receipt_if_referenced(&ProverProcessingReceipt {
            version: ZK_PROVER_PROCESSING_STATE_VERSION,
            id: id.clone(),
            processed_ms: terminal.processed_ms,
            terminal: false,
            retry_not_before_ms: Some(0),
            retry_count: 1,
            completed_proof_indices: Vec::new(),
            processing_context_hash: None,
        })
        .expect("persist simulated pre-report provisional receipt")
    );

    assert!(
        !attachment_needs_processing(&location).expect("inspect processing disposition"),
        "the committed terminal disposition must suppress repeat verification"
    );
    assert_eq!(
        prover_processing_decision(&id, u64::MAX),
        ProverProcessingDecision::Suppress
    );
}

#[test]
fn cross_tenant_duplicate_uses_one_receipt_even_without_a_report() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let first_tenant = anon_tenant_key();
    let second_tenant = "4".repeat(TENANT_KEY_HEX_LEN);
    let body = fixture_attachment_bytes();
    let id = store_scanner_attachment(&first_tenant, &body, "application/x-norito");
    assert_eq!(
        store_scanner_attachment(&second_tenant, &body, "application/x-norito"),
        id
    );

    let first = block_on_scan().expect("run first prover scan");
    assert_eq!(
        first.processed_reports, 1,
        "content identity must deduplicate tenant-local copies"
    );
    assert_eq!(
        prover_processing_decision(&id, crate::utils::unix_now_ms()),
        ProverProcessingDecision::Suppress
    );
    {
        let _guard = report_summary_lock().lock();
        delete_report_files_locked(&id).expect("remove evictable report files");
    }
    assert!(load_report(&id).is_none());

    let second = block_on_scan().expect("run second prover scan");
    assert_eq!(
        second.processed_reports, 0,
        "the shared content receipt must remain authoritative without a report"
    );
}

#[test]
fn retryable_mixed_list_reuses_successful_proof_results() {
    let _env = TestDataDirGuard::new();
    let tenant_key = anon_tenant_key();
    let successful = fixture_attachment();
    let mut retryable = successful.clone();
    retryable.vk_ref = VerifyingKeyId::new(retryable.backend.clone(), "temporarily-missing-vk");
    let list = ProofAttachmentList::try_from(vec![successful, retryable])
        .expect("two proofs fit the bounded attachment list");
    let body = norito::encode_canonical(&list).expect("canonical attachment list");
    let max_scan_bytes = u64::try_from(body.len())
        .expect("test attachment length fits u64")
        .saturating_add(TEST_SCAN_BUDGET_MARGIN_BYTES)
        .max(ATTACHMENT_DISCOVERY_BYTES_PER_LOCATION.saturating_mul(8));
    configure_test_cfg_with_state_and_scan_bytes(Vec::new(), fixture_state(), max_scan_bytes);
    let id = store_scanner_attachment(&tenant_key, &body, "application/x-norito");

    let first = block_on_scan().expect("run first prover scan");
    assert_eq!(first.processed_reports, 1);
    assert_eq!(
        proof_verification_attempt_count(),
        1,
        "only the verifier-eligible sibling reaches cryptographic verification"
    );
    let first_report = load_report(&id).expect("mixed-list retry report");
    let first_processing = first_report
        .processing
        .as_ref()
        .expect("processing disposition");
    assert_eq!(first_processing.completed_proof_indices, vec![0]);
    let first_context_hash = first_processing
        .processing_context_hash
        .clone()
        .expect("a reusable proof result is bound to its verifier context");
    assert!(
        persist_prover_processing_receipt_if_referenced(&ProverProcessingReceipt {
            version: ZK_PROVER_PROCESSING_STATE_VERSION,
            id: id.clone(),
            processed_ms: first_report.processed_ms.saturating_sub(1),
            terminal: false,
            retry_not_before_ms: Some(0),
            retry_count: 1,
            completed_proof_indices: Vec::new(),
            processing_context_hash: None,
        })
        .expect("persist an older provisional receipt")
    );
    assert_eq!(
        completed_proof_cache_for_retry(&id)
            .expect("load the completed proof cache")
            .indices,
        vec![0],
        "a committed retry report must win over its older provisional receipt"
    );
    let newer_context_hash = "b".repeat(64);
    assert!(
        persist_prover_processing_receipt_if_referenced(&ProverProcessingReceipt {
            version: ZK_PROVER_PROCESSING_STATE_VERSION,
            id: id.clone(),
            processed_ms: first_report.processed_ms.saturating_add(1),
            terminal: false,
            retry_not_before_ms: Some(0),
            retry_count: 2,
            completed_proof_indices: vec![0],
            processing_context_hash: Some(newer_context_hash.clone()),
        })
        .expect("persist a newer in-flight checkpoint")
    );
    assert_eq!(
        committed_report_processing_decision(&id, u64::MAX)
            .expect("load the committed report processing decision"),
        Some(ProverProcessingDecision::Due { retry_count: 2 }),
        "an older committed retry report must not roll back a newer checkpoint"
    );
    let reconciled = load_prover_processing_receipt(&id).expect("reconciled retry receipt");
    assert_eq!(reconciled.retry_count, 2);
    assert_eq!(
        reconciled.processing_context_hash.as_deref(),
        Some(newer_context_hash.as_str())
    );
    {
        let _guard = report_summary_lock().lock();
        delete_report_files_locked(&id).expect("evict retry report");
    }
    assert!(
        persist_prover_processing_receipt_if_referenced(&ProverProcessingReceipt {
            version: ZK_PROVER_PROCESSING_STATE_VERSION,
            id: id.clone(),
            processed_ms: first_report.processed_ms,
            terminal: false,
            retry_not_before_ms: Some(0),
            retry_count: 1,
            completed_proof_indices: vec![0],
            processing_context_hash: Some(first_context_hash),
        })
        .expect("make the mixed-list retry immediately due")
    );

    let second = block_on_scan().expect("run second prover scan");
    assert_eq!(second.processed_reports, 1);
    assert_eq!(
        proof_verification_attempt_count(),
        1,
        "a report eviction and retry must reuse successful sibling verification"
    );
    let second_report = load_report(&id).expect("second mixed-list retry report");
    assert!(second_report.proofs[0].ok);
    assert_eq!(
        second_report.proofs[0].circuit_id.as_deref(),
        Some("stark/fri/poseidon-x7-goldilocks-6x64-v1:torii-worker-v1"),
        "a cached proof report must preserve registry circuit attribution"
    );
    assert!(!second_report.proofs[1].ok);
    let second_processing = second_report
        .processing
        .as_ref()
        .expect("retry processing disposition");
    assert_eq!(second_processing.completed_proof_indices, vec![0]);
    let second_context_hash = second_processing
        .processing_context_hash
        .clone()
        .expect("retry cache context hash");

    {
        let _guard = report_summary_lock().lock();
        delete_report_files_locked(&id).expect("evict second retry report");
    }
    assert!(
        persist_prover_processing_receipt_if_referenced(&ProverProcessingReceipt {
            version: ZK_PROVER_PROCESSING_STATE_VERSION,
            id: id.clone(),
            processed_ms: second_report.processed_ms,
            terminal: false,
            retry_not_before_ms: Some(0),
            retry_count: 2,
            completed_proof_indices: vec![0],
            processing_context_hash: Some(second_context_hash.clone()),
        })
        .expect("make the second mixed-list retry immediately due")
    );
    let attempts_before_reconfigure = proof_verification_attempt_count();
    let changed_state = fixture_state_with_vk_window_and_zk(None, None, |zk| {
        zk.pipa_r.enabled = true;
        zk.max_verify_batch = zk.max_verify_batch.saturating_add(1);
    });
    configure_test_cfg_with_state_and_scan_bytes(Vec::new(), changed_state, max_scan_bytes);
    set_proof_verification_attempt_count(attempts_before_reconfigure);

    let third = block_on_scan().expect("run third prover scan");
    assert_eq!(third.processed_reports, 1);
    assert_eq!(
        proof_verification_attempt_count(),
        attempts_before_reconfigure + 1,
        "a verifier policy change must invalidate the cached success"
    );
    let third_report = load_report(&id).expect("third mixed-list retry report");
    let third_context_hash = third_report
        .processing
        .as_ref()
        .and_then(|processing| processing.processing_context_hash.as_ref())
        .expect("recomputed retry context hash");
    assert_ne!(third_context_hash, &second_context_hash);
}

#[test]
fn attachment_file_loading_is_bounded_and_metadata_size_is_not_trusted() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let oversized_id = format!("{:064x}", 0xBAD0u64);
    let oversized_path = attachment_bin_path(&tenant_key, &oversized_id);
    fs::write(
        &oversized_path,
        vec![0_u8; PROOF_ATTACHMENT_BODY_MAX_BYTES_V1 as usize + 1],
    )
    .expect("write oversized body fixture");
    let oversized = load_attachment_body(&AttachmentLocation {
        tenant_key: tenant_key.clone(),
        id: oversized_id,
    })
    .expect("oversized regular file is classified");
    assert_eq!(
        oversized.observed_size,
        PROOF_ATTACHMENT_BODY_MAX_BYTES_V1 + 1
    );
    assert_eq!(oversized.bytes_read, 0);
    assert!(
        oversized
            .body
            .expect_err("oversized body must not be read")
            .contains("first-release limit")
    );
    let id = format!("{:064x}", 0xBAD1u64);
    let body = fixture_attachment_bytes();
    fs::write(attachment_bin_path(&tenant_key, &id), &body)
        .expect("write canonical attachment body");
    let meta = super::super::zk_attachments::AttachmentMeta {
        id: id.clone(),
        content_type: "application/x-norito".to_owned(),
        size: 1,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(&body, "application/x-norito")),
        zk1_tags: None,
    };
    fs::write(
        attachment_meta_path(&tenant_key, &id),
        norito::json::to_json_pretty(&meta).expect("metadata JSON"),
    )
    .expect("write mismatched metadata");
    let error = process_attachment_once(&id)
        .expect_err("persisted metadata/body size mismatch must be a storage failure");
    assert!(error.to_string().contains("metadata size"));
}
#[test]
fn nonregular_attachment_body_produces_a_zero_read_rejection_report() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let id = format!("{:064x}", 0xBAD4u64);
    fs::create_dir(attachment_bin_path(&tenant_key, &id)).expect("create nonregular body entry");
    let meta = super::super::zk_attachments::AttachmentMeta {
        id: id.clone(),
        content_type: "application/x-norito".to_owned(),
        size: 0,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(&[], "application/x-norito")),
        zk1_tags: None,
    };
    fs::write(
        attachment_meta_path(&tenant_key, &id),
        norito::json::to_json_pretty(&meta).expect("metadata JSON"),
    )
    .expect("write nonregular-body metadata");
    let loc = AttachmentLocation {
        tenant_key,
        id: id.clone(),
    };
    let loaded = load_attachment_body(&loc).expect("nonregular body is classified");
    assert_eq!(loaded.observed_size, 0);
    assert_eq!(loaded.bytes_read, 0);
    assert!(
        loaded
            .body
            .expect_err("nonregular body must be rejected")
            .contains("securely open")
    );
    let error = process_attachment_once(&id)
        .expect_err("nonregular persisted body must be a storage failure");
    // Directory discovery securely opens each entry before yielding metadata;
    // it can reject the same nonregular body before the body-loader wrapper.
    assert_eq!(error.kind(), IoErrorKind::InvalidData);
    assert!(error.to_string().contains("regular file"));
    assert!(
        try_load_report(&id)
            .expect("inspect report absence")
            .is_none()
    );
}
#[cfg(unix)]
#[test]
fn attachment_body_secure_open_rejects_symlinks_without_reading() {
    use std::os::unix::fs::symlink;
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let id = format!("{:064x}", 0xBAD5u64);
    let target = attachments_root_dir()
        .join(&tenant_key)
        .join("symlink-target.bin");
    fs::write(&target, fixture_attachment_bytes()).expect("write symlink target");
    symlink(&target, attachment_bin_path(&tenant_key, &id)).expect("create body symlink");
    let loaded = load_attachment_body(&AttachmentLocation { tenant_key, id })
        .expect("symlink body is classified");
    assert_eq!(loaded.bytes_read, 0);
    assert!(
        loaded
            .body
            .expect_err("symlink body must be rejected")
            .contains("securely open")
    );
}
#[cfg(unix)]
#[test]
fn attachment_body_secure_open_rejects_a_symlinked_tenant_anchor() {
    use std::os::unix::fs::symlink;
    let env = TestDataDirGuard::new();
    init_test_cfg();
    let tenant_key = anon_tenant_key();
    fs::create_dir_all(attachments_root_dir()).expect("create attachment root");
    let outside = env.path().join("outside-tenant");
    fs::create_dir(&outside).expect("create outside tenant directory");
    let id = format!("{:064x}", 0xBAD8u64);
    fs::write(
        outside.join(format!("{id}.bin")),
        fixture_attachment_bytes(),
    )
    .expect("write body outside attachment root");
    symlink(&outside, attachments_root_dir().join(&tenant_key))
        .expect("create tenant directory symlink");
    let loaded = load_attachment_body(&AttachmentLocation { tenant_key, id })
        .expect("symlink-anchored body is classified");
    assert_eq!(loaded.observed_size, 0);
    assert_eq!(loaded.bytes_read, 0);
    assert!(loaded.body.is_err());
}
#[cfg(any(unix, windows))]
#[test]
fn attachment_body_secure_open_rejects_hard_links_without_reading() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let id = format!("{:064x}", 0xBAD7u64);
    let target = attachments_root_dir()
        .join(&tenant_key)
        .join("hard-link-target.bin");
    fs::write(&target, fixture_attachment_bytes()).expect("write hard-link target");
    fs::hard_link(&target, attachment_bin_path(&tenant_key, &id)).expect("create body hard link");
    let loaded = load_attachment_body(&AttachmentLocation { tenant_key, id })
        .expect("hard-linked body is classified");
    assert_eq!(loaded.observed_size, 0);
    assert_eq!(loaded.bytes_read, 0);
    assert!(
        loaded
            .body
            .expect_err("hard-linked body must be rejected")
            .contains("securely open")
    );
}
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn attachment_body_secure_open_rejects_fifo_without_blocking_or_reading() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let id = format!("{:064x}", 0xBAD6u64);
    let fifo_path = attachment_bin_path(&tenant_key, &id);
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo_path,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .expect("create FIFO body entry");
    let started = std::time::Instant::now();
    let loaded = load_attachment_body(&AttachmentLocation { tenant_key, id })
        .expect("FIFO body is classified");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(loaded.bytes_read, 0);
    assert!(loaded.body.is_err());
}
#[test]
fn attachment_body_loader_accepts_the_closed_eight_mib_boundary() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let id = format!("{:064x}", 0xBAD3u64);
    fs::write(
        attachment_bin_path(&tenant_key, &id),
        vec![0_u8; PROOF_ATTACHMENT_BODY_MAX_BYTES_V1 as usize],
    )
    .expect("write exact-cap body fixture");
    let loaded = load_attachment_body(&AttachmentLocation { tenant_key, id })
        .expect("exact-cap body is present");
    assert_eq!(loaded.observed_size, PROOF_ATTACHMENT_BODY_MAX_BYTES_V1);
    assert_eq!(loaded.bytes_read, PROOF_ATTACHMENT_BODY_MAX_BYTES_V1);
    let body = loaded
        .body
        .expect("exact-cap body is within the closed limit");
    let decode_error = decode_proof_attachments("application/x-norito", &body)
        .expect_err("zero bytes are not a canonical attachment frame");
    assert!(
        !decode_error.contains("exceeds the"),
        "exact-cap input was rejected as oversized: {decode_error}"
    );
}
#[test]
fn immutable_snapshot_survives_path_replacement_without_reread() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let body = fixture_attachment_bytes();
    let id = attachment_body_id(&body);
    let loc = AttachmentLocation {
        tenant_key: tenant_key.clone(),
        id: id.clone(),
    };
    let meta = super::super::zk_attachments::AttachmentMeta {
        id: id.clone(),
        content_type: "application/x-norito".to_owned(),
        size: body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(&body, "application/x-norito")),
        zk1_tags: None,
    };
    fs::write(attachment_bin_path(&tenant_key, &id), &body)
        .expect("write canonical attachment snapshot body");
    fs::write(
        attachment_meta_path(&tenant_key, &id),
        norito::json::to_json_pretty(&meta).expect("metadata JSON"),
    )
    .expect("write canonical attachment snapshot metadata");
    ensure_prover_processing_reference(&tenant_key, &id)
        .expect("scanner creates a durable live-content reference before snapshotting");
    let snapshot = match load_attachment_snapshot(&loc, body.len() as u64)
        .expect("load snapshot")
        .expect("snapshot files are present")
    {
        AttachmentSnapshotLoad::Ready(snapshot) => snapshot,
        AttachmentSnapshotLoad::DeferredForByteBudget { .. } => {
            panic!("canonical fixture fits its exact read budget")
        }
    };
    assert_eq!(snapshot.body_load.bytes_read, body.len() as u64);
    fs::write(
        attachment_bin_path(&tenant_key, &id),
        vec![0_u8; PROOF_ATTACHMENT_BODY_MAX_BYTES_V1 as usize + 1],
    )
    .expect("replace path after immutable snapshot acquisition");
    let report = process_attachment_snapshot_at(&loc, snapshot)
        .expect("process immutable snapshot")
        .expect("immutable snapshot produces a report");
    assert!(report.ok, "path replacement affected snapshot: {report:?}");
    assert_eq!(report.size, body.len() as u64);
}
#[test]
fn same_size_body_substitution_is_rejected_by_content_address() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let body = fixture_attachment_bytes();
    let id = attachment_body_id(&body);
    let mut substituted = body.clone();
    substituted[0] ^= 0x01;
    assert_eq!(substituted.len(), body.len());
    let meta = super::super::zk_attachments::AttachmentMeta {
        id: id.clone(),
        content_type: "application/x-norito".to_owned(),
        size: body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(&body, "application/x-norito")),
        zk1_tags: None,
    };
    fs::write(attachment_bin_path(&tenant_key, &id), substituted)
        .expect("write same-size substituted body");
    fs::write(
        attachment_meta_path(&tenant_key, &id),
        norito::json::to_json_pretty(&meta).expect("metadata JSON"),
    )
    .expect("write original content-address metadata");
    let error = process_attachment_once(&id)
        .expect_err("content-address substitution must be a storage failure");
    assert!(
        error.to_string().contains("body digest"),
        "substitution rejected for the wrong reason: {error}"
    );
}
#[test]
fn snapshot_metadata_and_provenance_invariants_fail_closed() {
    let body = fixture_attachment_bytes();
    let id = attachment_body_id(&body);
    let tenant_key = anon_tenant_key();
    let loc = AttachmentLocation {
        tenant_key: tenant_key.clone(),
        id: id.clone(),
    };
    let base = super::super::zk_attachments::AttachmentMeta {
        id: id.clone(),
        content_type: "application/x-norito".to_owned(),
        size: body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key),
        provenance: Some(fixture_attachment_provenance(&body, "application/x-norito")),
        zk1_tags: None,
    };
    let body_load = AttachmentBodyLoad {
        observed_size: body.len() as u64,
        bytes_read: body.len() as u64,
        body: Ok(body),
    };
    validate_attachment_snapshot(&loc, &base, &body_load)
        .expect("canonical metadata and provenance must validate");
    let mut forged = base.clone();
    forged.id = "0".repeat(ATTACHMENT_ID_HEX_LEN);
    assert!(
        validate_attachment_snapshot(&loc, &forged, &body_load)
            .expect_err("metadata id mismatch must reject")
            .to_string()
            .contains("metadata id")
    );
    let mut forged = base.clone();
    forged.tenant = Some("0".repeat(TENANT_KEY_HEX_LEN));
    assert!(
        validate_attachment_snapshot(&loc, &forged, &body_load)
            .expect_err("metadata tenant mismatch must reject")
            .to_string()
            .contains("metadata tenant")
    );
    let mut forged = base.clone();
    forged.provenance = None;
    assert!(
        validate_attachment_snapshot(&loc, &forged, &body_load)
            .expect_err("missing provenance must reject")
            .to_string()
            .contains("provenance is required")
    );
    let mut forged = base.clone();
    forged
        .provenance
        .as_mut()
        .expect("fixture provenance")
        .sanitizer
        .verdict = "rejected".to_owned();
    assert!(
        validate_attachment_snapshot(&loc, &forged, &body_load)
            .expect_err("non-accepted sanitizer verdict must reject")
            .to_string()
            .contains("verdict")
    );
    let mut forged = base.clone();
    let incorrect_expanded_size = forged.size.saturating_add(1);
    forged
        .provenance
        .as_mut()
        .expect("fixture provenance")
        .sanitizer
        .expanded_bytes = incorrect_expanded_size;
    assert!(
        validate_attachment_snapshot(&loc, &forged, &body_load)
            .expect_err("expanded-size mismatch must reject")
            .to_string()
            .contains("expanded size")
    );
    let mut forged = base.clone();
    forged
        .provenance
        .as_mut()
        .expect("fixture provenance")
        .hashes
        .blake2b_256 = "0".repeat(ATTACHMENT_ID_HEX_LEN);
    assert!(
        validate_attachment_snapshot(&loc, &forged, &body_load)
            .expect_err("provenance Blake2b mismatch must reject")
            .to_string()
            .contains("Blake2b-256")
    );
    let mut forged = base.clone();
    forged
        .provenance
        .as_mut()
        .expect("fixture provenance")
        .hashes
        .sha256 = "0".repeat(64);
    assert!(
        validate_attachment_snapshot(&loc, &forged, &body_load)
            .expect_err("provenance SHA-256 mismatch must reject")
            .to_string()
            .contains("SHA-256")
    );
    let mut forged = base.clone();
    forged
        .provenance
        .as_mut()
        .expect("fixture provenance")
        .sniffed_type = "application/json".to_owned();
    assert!(
        validate_attachment_snapshot(&loc, &forged, &body_load)
            .expect_err("provenance media mismatch must reject")
            .to_string()
            .contains("media type")
    );
    let mut forged = base;
    forged.content_type = "application/json".to_owned();
    forged
        .provenance
        .as_mut()
        .expect("fixture provenance")
        .sniffed_type = "application/json".to_owned();
    assert!(
        validate_attachment_snapshot(&loc, &forged, &body_load)
            .expect_err("forged matching media labels must not override body sniffing")
            .to_string()
            .contains("media type")
    );
}
#[test]
fn first_release_scanner_rejects_retired_root_attachment_layout() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    fs::create_dir_all(attachments_root_dir()).expect("create attachment root");
    let body = fixture_attachment_bytes();
    let id = attachment_body_id(&body);
    let meta = super::super::zk_attachments::AttachmentMeta {
        id: id.clone(),
        content_type: "application/x-norito".to_owned(),
        size: body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: None,
        provenance: Some(fixture_attachment_provenance(&body, "application/x-norito")),
        zk1_tags: None,
    };
    fs::write(attachments_root_dir().join(format!("{id}.bin")), body)
        .expect("write retired root body");
    fs::write(
        attachments_root_dir().join(format!("{id}.json")),
        norito::json::to_json_pretty(&meta).expect("retired metadata JSON"),
    )
    .expect("write retired root metadata");
    let mut stream = AttachmentDirectoryStream::open(attachments_root_dir())
        .expect("open attachment discovery stream");
    let error = discover_attachment_window(
        &mut stream,
        AttachmentDiscoveryGeometry {
            max_locations: 4,
            max_work_items: 16,
        },
        std::time::Instant::now(),
        1_000,
        |_| Ok(true),
    )
    .expect_err("retired root layout must fail closed");
    assert!(error.to_string().contains("non-canonical tenant"));
    assert!(
        find_attachment_location(&id)
            .expect_err("direct lookup must reject retired root layout")
            .to_string()
            .contains("non-canonical tenant")
    );
    assert!(
        process_attachment_once(&id)
            .expect_err("direct processing must reject retired root layout")
            .to_string()
            .contains("non-canonical tenant")
    );
}
#[test]
fn attachment_discovery_geometry_has_exact_boundaries_and_saturates() {
    assert_eq!(
        AttachmentDiscoveryGeometry::from_scan_bytes(0),
        AttachmentDiscoveryGeometry {
            max_locations: 0,
            max_work_items: 0,
        }
    );
    assert_eq!(
        AttachmentDiscoveryGeometry::from_scan_bytes(ATTACHMENT_DISCOVERY_BYTES_PER_LOCATION - 1),
        AttachmentDiscoveryGeometry {
            max_locations: 1,
            max_work_items: ATTACHMENT_DISCOVERY_WORK_PER_LOCATION,
        }
    );
    assert_eq!(
        AttachmentDiscoveryGeometry::from_scan_bytes(ATTACHMENT_DISCOVERY_BYTES_PER_LOCATION + 1)
            .max_locations,
        2
    );
    let saturated = AttachmentDiscoveryGeometry::from_scan_bytes(u64::MAX);
    assert_eq!(
        saturated.max_locations,
        ATTACHMENT_DISCOVERY_MAX_LOCATIONS as usize
    );
    assert_eq!(
        saturated.max_work_items,
        ATTACHMENT_DISCOVERY_MAX_WORK_ITEMS
    );
}
#[test]
fn complete_attachment_discovery_window_is_canonically_ordered() {
    let _env = TestDataDirGuard::new();
    let tenant_keys = [format!("{:064x}", 2_u8), format!("{:064x}", 1_u8)];
    let ids = [format!("{:064x}", 12_u8), format!("{:064x}", 11_u8)];
    for tenant_key in &tenant_keys {
        ensure_tenant_dir(tenant_key);
        for id in &ids {
            fs::write(attachment_meta_path(tenant_key, id), b"{}")
                .expect("write discovery metadata fixture");
        }
    }
    let mut expected: Vec<_> = ids
        .iter()
        .map(|id| AttachmentLocation {
            tenant_key: tenant_keys[1].clone(),
            id: id.clone(),
        })
        .collect();
    expected.sort_unstable();
    let mut stream = AttachmentDirectoryStream::open(attachments_root_dir())
        .expect("open attachment discovery stream");
    let discovery = discover_attachment_window(
        &mut stream,
        AttachmentDiscoveryGeometry {
            max_locations: tenant_keys.len() * ids.len() + 1,
            max_work_items: 64,
        },
        std::time::Instant::now(),
        1_000,
        |_| Ok(true),
    )
    .expect("discover canonical window");
    assert!(discovery.sweep_complete);
    assert_eq!(discovery.budget_reason(), None);
    assert_eq!(discovery.locations, expected);
}
#[test]
fn attachment_discovery_retry_queue_is_canonical_and_hard_bounded() {
    let _env = TestDataDirGuard::new();
    fs::create_dir_all(attachments_root_dir()).expect("create attachment root");
    let hard_cap = ATTACHMENT_DISCOVERY_MAX_LOCATIONS as usize;
    let tenant_key = format!("{:064x}", 5_u8);
    let locations: Vec<_> = (0..=hard_cap)
        .rev()
        .map(|value| AttachmentLocation {
            tenant_key: tenant_key.clone(),
            id: format!("{value:064x}"),
        })
        .collect();
    retry_pending_attachment_locations(locations);
    retry_pending_attachment_locations(vec![AttachmentLocation {
        tenant_key: format!("{:064x}", 4_u8),
        id: format!("{:064x}", hard_cap - 1),
    }]);
    let state_guard = attachment_discovery_state().lock();
    let queued = &state_guard.as_ref().expect("retry state").retry_locations;
    assert_eq!(queued.len(), hard_cap);
    assert!(queued.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(queued[0].tenant_key, format!("{:064x}", 4_u8));
    assert_eq!(queued[0].id, format!("{:064x}", hard_cap - 1));
    drop(state_guard);
    *attachment_discovery_state().lock() = None;
}
#[test]
fn discovery_tolerates_completed_deletion_without_restarting_a_retained_cursor() {
    let _env = TestDataDirGuard::new();
    let root = attachments_root_dir();
    let tenant_key = format!("{:064x}", 6_u8);
    let tenant_dir = root.join(&tenant_key);
    fs::create_dir_all(&tenant_dir).expect("create tenant directory");
    fs::write(tenant_dir.join(format!("{:064x}.json", 1_u8)), b"{}")
        .expect("write retained-cursor fixture");
    let mut stream = AttachmentDirectoryStream::open(root.clone()).expect("open retained cursor");
    assert!(matches!(
        stream.step().expect("enter tenant directory"),
        AttachmentDirectoryStep::Advanced
    ));
    assert!(
        stream.current_tenant.is_some(),
        "fixture must park the retained cursor inside the tenant"
    );
    *attachment_discovery_state().lock() = Some(AttachmentDiscoveryState {
        root: root.clone(),
        stream: Some(stream),
        retry_locations: Vec::new(),
    });

    fs::remove_dir_all(&tenant_dir).expect("simulate a completed tenant deletion");

    let discovery = discover_pending_attachment_locations(
        AttachmentDiscoveryGeometry {
            max_locations: 4,
            max_work_items: 16,
        },
        std::time::Instant::now(),
        1_000,
    )
    .expect("a completed deletion must not invalidate the retained directory cursor");
    assert!(discovery.sweep_complete);
    assert!(discovery.locations.is_empty());
    *attachment_discovery_state().lock() = None;
}
#[test]
fn bounded_attachment_discovery_cursor_reaches_every_later_entry() {
    let _env = TestDataDirGuard::new();
    let tenant_key = format!("{:064x}", 3_u8);
    ensure_tenant_dir(&tenant_key);
    let expected: Vec<_> = (20_u8..25)
        .map(|value| AttachmentLocation {
            tenant_key: tenant_key.clone(),
            id: format!("{value:064x}"),
        })
        .collect();
    for location in &expected {
        fs::write(
            attachment_meta_path(&location.tenant_key, &location.id),
            b"{}",
        )
        .expect("write discovery metadata fixture");
    }
    let mut stream = AttachmentDirectoryStream::open(attachments_root_dir())
        .expect("open attachment discovery stream");
    let geometry = AttachmentDiscoveryGeometry {
        max_locations: 2,
        max_work_items: 64,
    };
    let mut discovered = Vec::new();
    let mut completed = false;
    for _ in 0..8 {
        let window = discover_attachment_window(
            &mut stream,
            geometry,
            std::time::Instant::now(),
            1_000,
            |_| Ok(true),
        )
        .expect("discover bounded window");
        assert!(window.locations.len() <= geometry.max_locations);
        assert!(window.locations.windows(2).all(|pair| pair[0] < pair[1]));
        completed = window.sweep_complete;
        let budget_reason = window.budget_reason();
        discovered.extend(window.locations);
        if completed {
            break;
        }
        assert_eq!(budget_reason, Some("work"));
    }
    assert!(completed, "bounded cursor must finish the directory sweep");
    discovered.sort_unstable();
    assert_eq!(discovered, expected);
}
#[test]
fn attachment_discovery_work_and_time_boundaries_do_not_consume_later_entries() {
    let _env = TestDataDirGuard::new();
    let tenant_key = format!("{:064x}", 4_u8);
    let id = format!("{:064x}", 30_u8);
    ensure_tenant_dir(&tenant_key);
    fs::write(attachment_meta_path(&tenant_key, &id), b"{}")
        .expect("write discovery metadata fixture");
    let mut stream = AttachmentDirectoryStream::open(attachments_root_dir())
        .expect("open attachment discovery stream");
    let timed_out = discover_attachment_window(
        &mut stream,
        AttachmentDiscoveryGeometry {
            max_locations: 4,
            max_work_items: 4,
        },
        std::time::Instant::now(),
        0,
        |_| Ok(true),
    )
    .expect("observe time boundary");
    assert_eq!(timed_out.work_items, 0);
    assert_eq!(timed_out.budget_reason(), Some("time"));
    assert_eq!(timed_out.pending_estimate(), 1);
    let work_limited = discover_attachment_window(
        &mut stream,
        AttachmentDiscoveryGeometry {
            max_locations: 4,
            max_work_items: 1,
        },
        std::time::Instant::now(),
        1_000,
        |_| Ok(true),
    )
    .expect("observe work boundary");
    assert_eq!(work_limited.work_items, 1);
    assert!(work_limited.locations.is_empty());
    assert_eq!(work_limited.budget_reason(), Some("work"));
    assert_eq!(work_limited.pending_estimate(), 1);
    let resumed = discover_attachment_window(
        &mut stream,
        AttachmentDiscoveryGeometry {
            max_locations: 4,
            max_work_items: 8,
        },
        std::time::Instant::now(),
        1_000,
        |_| Ok(true),
    )
    .expect("resume bounded discovery");
    assert!(resumed.sweep_complete);
    assert_eq!(
        resumed.locations,
        vec![AttachmentLocation { tenant_key, id }]
    );
}
#[test]
fn oversized_first_attachment_cannot_starve_later_valid_work() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let oversized_body = vec![0_u8; PROOF_ATTACHMENT_BODY_MAX_BYTES_V1 as usize + 1];
    let oversized_id = attachment_body_id(&oversized_body);
    let oversized_meta = super::super::zk_attachments::AttachmentMeta {
        id: oversized_id.clone(),
        content_type: "application/x-norito".to_owned(),
        size: oversized_body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(
            &oversized_body,
            "application/x-norito",
        )),
        zk1_tags: None,
    };
    fs::write(
        attachment_bin_path(&tenant_key, &oversized_id),
        oversized_body,
    )
    .expect("write oversized first body");
    fs::write(
        attachment_meta_path(&tenant_key, &oversized_id),
        norito::json::to_json_pretty(&oversized_meta).expect("oversized metadata JSON"),
    )
    .expect("write oversized first metadata");
    let valid_body = fixture_attachment_bytes();
    let valid_id = attachment_body_id(&valid_body);
    let valid_meta = super::super::zk_attachments::AttachmentMeta {
        id: valid_id.clone(),
        content_type: "application/x-norito".to_owned(),
        size: valid_body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(
            &valid_body,
            "application/x-norito",
        )),
        zk1_tags: None,
    };
    fs::write(attachment_bin_path(&tenant_key, &valid_id), &valid_body)
        .expect("write later valid body");
    fs::write(
        attachment_meta_path(&tenant_key, &valid_id),
        norito::json::to_json_pretty(&valid_meta).expect("valid metadata JSON"),
    )
    .expect("write later valid metadata");
    let error = super::block_on_scan()
        .expect_err("an oversized persisted body must fail the storage scan closed");
    assert!(
        error.to_string().contains("first-release limit"),
        "unexpected oversized-body error: {error}"
    );
    assert!(
        load_report(&oversized_id).is_none(),
        "storage corruption must not be committed as an application report"
    );
    assert!(
        load_report(&valid_id).expect("drained valid report").ok,
        "already-scheduled valid work must be drained before the scan returns its first error"
    );
}
#[test]
fn attachment_metadata_loading_rejects_oversized_files_before_parsing() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let id = format!("{:064x}", 0xBAD2u64);
    fs::write(
        attachment_meta_path(&tenant_key, &id),
        vec![b' '; crate::zk_attachments::ATTACHMENT_META_FILE_MAX_BYTES as usize + 1],
    )
    .expect("write oversized metadata fixture");
    let error = load_attachment_meta(&AttachmentLocation { tenant_key, id })
        .expect_err("oversized metadata must fail before JSON parsing");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
#[test]
fn scan_respects_byte_budget() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    let budget = super::cfg_max_scan_bytes().max(2);
    let budget = usize::try_from(budget).unwrap_or(usize::MAX);
    let first_size = budget.saturating_sub(1).max(1);
    let sizes = [first_size, 2usize];
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    // Create two attachments totalling more than the configured byte budget.
    for (index, size) in sizes.into_iter().enumerate() {
        let mut body = vec![b' '; size];
        body[0] = b'0' + u8::try_from(index).expect("small fixture index");
        let id = attachment_body_id(&body);
        let meta = super::super::zk_attachments::AttachmentMeta {
            id: id.clone(),
            content_type: "application/octet-stream".to_string(),
            size: body.len() as u64,
            created_ms: crate::utils::unix_now_ms(),
            tenant: Some(tenant_key.clone()),
            provenance: Some(fixture_attachment_provenance(
                &body,
                "application/octet-stream",
            )),
            zk1_tags: None,
        };
        fs::write(attachment_bin_path(&tenant_key, &id), body).unwrap();
        fs::write(
            attachment_meta_path(&tenant_key, &id),
            norito::json::to_json_pretty(&meta).unwrap(),
        )
        .unwrap();
    }
    let stats = super::block_on_scan().expect("run prover scan");
    assert_eq!(
        stats.processed_reports, 1,
        "only first attachment fits budget"
    );
    assert_eq!(stats.budget_exhausted, Some("bytes"));
    assert_eq!(stats.remaining_pending, 1);
    assert!(sizes.contains(
        &usize::try_from(stats.bytes_processed).expect("processed byte count fits usize")
    ));
}
#[test]
fn deferred_attachment_cannot_head_of_line_block_later_fitting_work() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    let budget = cfg_max_scan_bytes();
    assert!(budget > 8, "test scan budget must leave a tail");
    let first_size = usize::try_from(budget - 4).expect("test budget fits usize");
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let mut first_body = vec![b'a'; first_size];
    first_body[0] = b'"';
    *first_body.last_mut().expect("non-empty first body") = b'"';
    let first_id = (0_u32..=u32::MAX)
        .find_map(|nonce| {
            first_body[1..5].copy_from_slice(&nonce.to_le_bytes());
            for byte in &mut first_body[1..5] {
                *byte = b'a' + (*byte % 26);
            }
            let id = attachment_body_id(&first_body);
            (id.as_bytes()[0] <= b'7').then_some(id)
        })
        .expect("find a lower-half content id for the leading body");
    const JSON_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let (second_id, second_body, third_id, third_body) = (0_u32..=u32::MAX)
        .find_map(|nonce| {
            let alphabet_len =
                u32::try_from(JSON_ALPHABET.len()).expect("alphabet length fits u32");
            let index = |shift: u32| {
                usize::try_from((nonce.rotate_left(shift) % alphabet_len) as u64)
                    .expect("alphabet index fits usize")
            };
            let second_body = vec![
                b'"',
                JSON_ALPHABET[index(0)],
                JSON_ALPHABET[index(7)],
                JSON_ALPHABET[index(13)],
                b'"',
            ];
            let third_body = vec![
                b'"',
                JSON_ALPHABET[index(19)],
                JSON_ALPHABET[index(25)],
                b'"',
            ];
            let second_id = attachment_body_id(&second_body);
            let third_id = attachment_body_id(&third_body);
            (first_id < second_id && second_id < third_id).then_some((
                second_id,
                second_body,
                third_id,
                third_body,
            ))
        })
        .expect("find ordered small content-addressed fixtures");
    let fixtures = [
        (first_id.clone(), first_body),
        (second_id.clone(), second_body),
        (third_id.clone(), third_body),
    ];
    for (id, body) in fixtures {
        let meta = super::super::zk_attachments::AttachmentMeta {
            id: id.clone(),
            content_type: "application/octet-stream".to_owned(),
            size: body.len() as u64,
            created_ms: crate::utils::unix_now_ms(),
            tenant: Some(tenant_key.clone()),
            provenance: Some(fixture_attachment_provenance(
                &body,
                "application/octet-stream",
            )),
            zk1_tags: None,
        };
        fs::write(attachment_bin_path(&tenant_key, &id), &body).expect("write budget-order body");
        fs::write(
            attachment_meta_path(&tenant_key, &id),
            norito::json::to_json_pretty(&meta).expect("budget-order metadata JSON"),
        )
        .expect("write budget-order metadata");
    }
    let stats = block_on_scan().expect("run prover scan");
    assert_eq!(stats.processed_reports, 2);
    assert_eq!(stats.bytes_processed, budget);
    assert_eq!(stats.remaining_pending, 1);
    assert_eq!(stats.budget_exhausted, Some("bytes"));
    assert!(load_report(&first_id).is_some());
    assert!(
        load_report(&second_id).is_none(),
        "the body that does not fit must remain pending without being read"
    );
    assert!(
        load_report(&third_id).is_some(),
        "a later body that fits the remaining budget must still be processed"
    );
}
#[test]
fn snapshot_that_crosses_time_budget_is_charged_and_completed_once() {
    let body = fixture_attachment_bytes();
    let body_size = body.len() as u64;
    let max_scan_millis = 100;
    let _env = TestDataDirGuard::new();
    configure_test_cfg(iroha_config::parameters::defaults::torii::zk_prover_allowed_circuits());
    let _delay_reset = SnapshotLoadDelayReset;
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let id = attachment_body_id(&body);
    let meta = super::super::zk_attachments::AttachmentMeta {
        id: id.clone(),
        content_type: "application/x-norito".to_owned(),
        size: body_size,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(&body, "application/x-norito")),
        zk1_tags: None,
    };
    fs::write(attachment_bin_path(&tenant_key, &id), body).expect("write delayed snapshot body");
    fs::write(
        attachment_meta_path(&tenant_key, &id),
        norito::json::to_json_pretty(&meta).expect("delayed snapshot metadata JSON"),
    )
    .expect("write delayed snapshot metadata");
    super::TEST_MAX_SCAN_MILLIS_OVERRIDE.store(max_scan_millis, AtomicOrdering::SeqCst);
    super::TEST_SNAPSHOT_LOAD_DELAY_MS.store(150, AtomicOrdering::SeqCst);
    let stats = block_on_scan().expect("run prover scan");
    assert_eq!(stats.processed_reports, 1);
    assert_eq!(stats.bytes_processed, body_size);
    // A bounded discovery cursor may still advertise one unknown location
    // when its time window closes; the accepted snapshot itself completed.
    assert!(stats.remaining_pending <= 1);
    assert_eq!(stats.budget_exhausted, Some("time"));
    assert!(stats.duration_ms >= max_scan_millis);
    assert!(
        load_report(&id).expect("cross-budget snapshot report").ok,
        "an immutable snapshot read before the time check must complete exactly once"
    );
    let attempts = proof_verification_attempt_count();
    super::TEST_MAX_SCAN_MILLIS_OVERRIDE.store(0, AtomicOrdering::SeqCst);
    super::TEST_SNAPSHOT_LOAD_DELAY_MS.store(0, AtomicOrdering::SeqCst);
    let completed = block_on_scan().expect("finish the retained discovery cursor");
    assert_eq!(completed.processed_reports, 0);
    assert_eq!(completed.bytes_processed, 0);
    assert_eq!(completed.remaining_pending, 0);
    assert_eq!(
        proof_verification_attempt_count(),
        attempts,
        "cross-budget snapshot must never be verified twice"
    );
}
#[test]
fn scan_bounds_concurrency() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    super::TEST_PROCESSING_DELAY_MS.store(50, AtomicOrdering::SeqCst);
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    // Create four small attachments to trigger overlapping work.
    for idx in 0_u8..4 {
        let mut body = vec![b' '; 16];
        body[0] = b'0' + idx;
        let id = attachment_body_id(&body);
        let meta = super::super::zk_attachments::AttachmentMeta {
            id: id.clone(),
            content_type: "application/octet-stream".to_string(),
            size: body.len() as u64,
            created_ms: crate::utils::unix_now_ms(),
            tenant: Some(tenant_key.clone()),
            provenance: Some(fixture_attachment_provenance(
                &body,
                "application/octet-stream",
            )),
            zk1_tags: None,
        };
        fs::write(attachment_bin_path(&tenant_key, &id), body).unwrap();
        fs::write(
            attachment_meta_path(&tenant_key, &id),
            norito::json::to_json_pretty(&meta).unwrap(),
        )
        .unwrap();
    }
    let stats = super::block_on_scan().expect("run prover scan");
    assert_eq!(stats.budget_exhausted, None);
    assert_eq!(stats.processed_reports, 4);
    let observed = super::MAX_INFLIGHT_OBSERVED.load(AtomicOrdering::SeqCst);
    assert!(observed > 1, "the fixture must exercise overlapping work");
    assert!(
        observed <= super::cfg_max_inflight(),
        "observed inflight {} exceeds cap",
        observed
    );
    super::TEST_PROCESSING_DELAY_MS.store(0, AtomicOrdering::SeqCst);
}
#[tokio::test(flavor = "current_thread")]
async fn scan_once_handles_current_thread_runtime() {
    let _env = TestDataDirGuard::new();
    init_test_cfg();
    super::super::zk_attachments::init_persistence()
        .expect("initialize production attachment persistence");
    super::init_persistence().expect("initialize production report persistence");
    assert_eq!(super::scan_once().expect("run one prover scan"), 0);
}
#[test]
fn zk1_extracts_tags_prof_and_ipak() {
    let mut v = b"ZK1\0".to_vec();
    // PROF with 0 payload
    v.extend_from_slice(b"PROF");
    v.extend_from_slice(&0u32.to_le_bytes());
    // IPAK with 4-byte payload
    v.extend_from_slice(b"IPAK");
    v.extend_from_slice(&4u32.to_le_bytes());
    v.extend_from_slice(&5u32.to_le_bytes());
    let tags = parse_zk1_tags(&v).expect("valid bounded ZK1 envelope");
    assert!(tags.starts_with(&["PROF".to_string(), "IPAK".to_string()]));
}
#[test]
fn zk1_tlv_count_is_bounded_and_duplicate_tags_are_compacted() {
    let mut envelope = b"ZK1\0".to_vec();
    for _ in 0..ZK1_MAX_TLV_COUNT {
        envelope.extend_from_slice(b"PROF");
        envelope.extend_from_slice(&0u32.to_le_bytes());
    }
    assert_eq!(parse_zk1_tags(&envelope), Ok(vec!["PROF".to_string()]));
    envelope.extend_from_slice(b"IPAK");
    envelope.extend_from_slice(&0u32.to_le_bytes());
    let error = parse_zk1_tags(&envelope).expect_err("65th TLV must be rejected");
    assert!(error.contains("too many ZK1 TLVs"));
    let decode_error = decode_proof_attachments("application/x-zk1", &envelope)
        .expect_err("prover ingress must apply the same TLV limit");
    assert!(decode_error.contains("too many ZK1 TLVs"));
    assert!(
        parse_zk1_tags(&envelope).is_err(),
        "invalid envelopes must not expose partial tag metadata"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_worker_processes_pending_attachments() {
    let _env = TestDataDirGuard::new();
    configure_test_cfg(Vec::new());
    // Prepare attachment directory with one valid proof attachment and one malformed ZK1 payload.
    let tenant_key = anon_tenant_key();
    ensure_tenant_dir(&tenant_key);
    let ok_body = fixture_attachment_bytes();
    let ok_id = attachment_body_id(&ok_body);
    fs::write(attachment_bin_path(&tenant_key, &ok_id), &ok_body).expect("write ok body");
    let ok_meta = super::super::zk_attachments::AttachmentMeta {
        id: ok_id.clone(),
        content_type: "application/x-norito".to_string(),
        size: ok_body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(
            &ok_body,
            "application/x-norito",
        )),
        zk1_tags: None,
    };
    fs::write(
        attachment_meta_path(&tenant_key, &ok_id),
        norito::json::to_json_pretty(&ok_meta).expect("ok meta json"),
    )
    .expect("write ok meta");
    let mut err_body = b"ZK1\0".to_vec();
    err_body.extend_from_slice(b"PROF");
    err_body.extend_from_slice(&10u32.to_le_bytes());
    let err_id = attachment_body_id(&err_body);
    fs::write(attachment_bin_path(&tenant_key, &err_id), &err_body).expect("write err body");
    let err_meta = super::super::zk_attachments::AttachmentMeta {
        id: err_id.clone(),
        content_type: "application/x-zk1".to_string(),
        size: err_body.len() as u64,
        created_ms: crate::utils::unix_now_ms(),
        tenant: Some(tenant_key.clone()),
        provenance: Some(fixture_attachment_provenance(
            &err_body,
            "application/x-zk1",
        )),
        zk1_tags: None,
    };
    fs::write(
        attachment_meta_path(&tenant_key, &err_id),
        norito::json::to_json_pretty(&err_meta).expect("err meta json"),
    )
    .expect("write err meta");
    let shutdown = ShutdownSignal::new();
    let worker = super::start_worker(shutdown.clone()).expect("start prover worker");
    use tokio::time::{Duration, Instant, sleep};
    // The mandatory STARK fixture does real cryptographic work even in debug builds.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut ok_report_ready = false;
    let mut err_ready = false;
    while Instant::now() < deadline {
        if !ok_report_ready {
            ok_report_ready = super::load_report(&ok_id).is_some();
        }
        if !err_ready {
            err_ready = super::load_report(&err_id)
                .map(|rep| !rep.ok)
                .unwrap_or(false);
        }
        if ok_report_ready && err_ready {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    shutdown.send();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(60), worker)
            .await
            .expect("prover worker observes shutdown")
            .expect("prover worker joins"),
        crate::ToriiCriticalWorkerExit::StoppedByShutdown
    );
    assert!(ok_report_ready, "Proof attachment should produce a report");
    assert!(
        err_ready,
        "Malformed Norito attachment should produce an error report"
    );
    assert_eq!(
        super::scan_once().expect("run final prover scan"),
        0,
        "worker should drain pending attachments"
    );
}
