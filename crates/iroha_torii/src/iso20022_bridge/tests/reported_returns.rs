// Reported returns preserve the original successful payment and never assert a reverse transfer.

fn record_report_original(
    runtime: &Iso20022BridgeRuntime,
    original_id: &str,
    settled: bool,
) -> String {
    let hash = "13".repeat(32);
    let mut metadata = inbound_metadata(original_id, "pacs.008");
    metadata.payload_hash = Some(sha256_hex(original_id.as_bytes()));
    assert!(runtime.check_and_record_inbound(original_id, metadata));
    assert!(runtime.update_message_context(
        original_id,
        IsoMessageContext {
            settlement_amount: Some("10".to_owned()),
            settlement_currency: Some("USD".to_owned()),
            ..IsoMessageContext::default()
        }
    ));
    runtime.mark_accepted(original_id, &hash);
    if settled {
        assert!(runtime.mark_settled(original_id, SystemTime::now()));
    }
    hash
}

fn record_settled_report_original(runtime: &Iso20022BridgeRuntime, original_id: &str) -> String {
    record_report_original(runtime, original_id, true)
}

fn reported_return_message(
    original_id: &str,
    lifecycle_id: &str,
    amount: &str,
    currency: &str,
) -> ParsedMessage {
    parse_message("pacs.004", format!(
        "MsgId={lifecycle_id}\nCreDtTm=2025-01-01T00:00:00Z\nOrgnlGrpInf/OrgnlMsgId={original_id}\nTxInf[0]/OrgnlInstrId=external-instruction\nTxInf[0]/RtrdInstdAmt={amount}\nTxInf[0]/RtrdInstdAmtCcy={currency}\nTxInf[0]/RtrdRsn/Cd=AC01"
    ).as_bytes()).expect("parsed return")
}

#[test]
fn reported_return_journal_recovers_without_rewriting_original_settlement() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let original_id = "return-journal-original";
    let lifecycle_id = "return-journal-report";
    let hash = record_settled_report_original(&runtime, original_id);
    record_lifecycle(&runtime, lifecycle_id, "pacs.004");
    let parsed = reported_return_message(original_id, lifecycle_id, "5.00", "USD");
    let messages_dir = store.path().join("messages");
    let original_path = messages_dir.join(message_filename(original_id));
    let original_bytes = fs::read(&original_path).expect("original durable bytes");
    let backup_dir = store.path().join("messages-backup");
    fs::rename(&messages_dir, &backup_dir).expect("move message store aside");
    fs::write(&messages_dir, b"block lifecycle materialization").expect("write blocker");
    let (outcome, report) = runtime
        .apply_inbound_lifecycle_message_with_status(lifecycle_id, "pacs.004", &parsed)
        .expect("journal commits the return report");
    assert_eq!(outcome.action(), "recorded_return");
    assert_eq!(
        report.reported_return_json()["original_transaction_hash"].as_str(),
        Some(hash.as_str())
    );
    assert_eq!(report.reported_return_json()["amount"].as_str(), Some("5"));
    assert_eq!(
        report.reported_return_json()["disposition"].as_str(),
        Some("external_report")
    );
    assert!(report.transaction_hash().is_none());
    assert!(report.settled_at().is_none());
    assert!(!runtime.lifecycle_persistence_is_healthy());
    assert!(lifecycle_journal_path(store.path()).is_file());
    assert_eq!(
        runtime.message_status(original_id).unwrap().pacs002_code(),
        "ACSC"
    );
    fs::remove_file(&messages_dir).expect("remove blocker");
    fs::rename(&backup_dir, &messages_dir).expect("restore message store");
    drop(runtime);
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .expect("recover journal")
        .expect("enabled");
    assert!(reloaded.lifecycle_persistence_is_healthy());
    assert!(!lifecycle_journal_path(store.path()).exists());
    assert_eq!(
        fs::read(&original_path).expect("original survives restart"),
        original_bytes
    );
    assert_eq!(
        reloaded.message_status(original_id).unwrap().pacs002_code(),
        "ACSC"
    );
    let recovered = reloaded
        .message_status(lifecycle_id)
        .expect("durable report");
    assert_eq!(
        recovered.reported_return_json(),
        report.reported_return_json()
    );
    assert_eq!(recovered.status_label(), "Accepted");
    assert!(recovered.transaction_hash().is_none());
    assert!(recovered.settled_at().is_none());
}

#[test]
fn reported_return_rejects_terms_outside_original_payment() {
    for (amount, currency) in [("0", "USD"), ("11", "USD"), ("10", "EUR")] {
        let runtime = sample_runtime();
        record_settled_report_original(&runtime, "return-terms-original");
        record_lifecycle(&runtime, "return-terms-report", "pacs.004");
        let parsed = reported_return_message(
            "return-terms-original",
            "return-terms-report",
            amount,
            currency,
        );
        assert!(
            runtime
                .apply_inbound_lifecycle_message("return-terms-report", "pacs.004", &parsed)
                .is_err()
        );
        assert_eq!(
            runtime
                .message_status("return-terms-original")
                .unwrap()
                .pacs002_code(),
            "ACSC"
        );
        assert_eq!(
            runtime
                .message_status("return-terms-report")
                .unwrap()
                .status_label(),
            "Pending"
        );
    }
}

#[test]
fn reported_return_codec_rejects_native_refund_claims_and_invalid_terms() {
    let report = IsoReportedReturn {
        disposition: IsoReturnReportDisposition::ExternalReport,
        original_payload_hash: None,
        original_message_id: "original".to_owned(),
        original_transaction_hash: Some("15".repeat(32)),
        amount: "10".to_owned(),
        currency: "USD".to_owned(),
        reason_code: Some("AC01".to_owned()),
    };
    let canonical = reported_return_value(Some(&report));
    assert_eq!(reported_return_from_value(&canonical), Ok(Some(report)));
    assert_eq!(reported_return_from_value(&JsonValue::Null), Ok(None));
    assert!(reported_return_from_value(&JsonValue::from(false)).is_err());
    for (field, value) in [
        ("disposition", "refunded"),
        ("original_transaction_hash", "not-a-canonical-hash"),
        ("amount", "0"),
        ("amount", "10.0"),
        ("currency", "usd"),
        ("original_message_id", ""),
    ] {
        let mut changed = canonical.clone();
        changed
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), JsonValue::from(value));
        assert!(
            reported_return_from_value(&changed).is_err(),
            "accepted {field}={value}"
        );
    }
    let mut local = canonical.clone();
    local.as_object_mut().unwrap().insert(
        "disposition".to_owned(),
        JsonValue::from("original_not_submitted"),
    );
    assert!(
        reported_return_from_value(&local).is_err(),
        "a local observation cannot retain a native carrier claim"
    );
    local
        .as_object_mut()
        .unwrap()
        .insert("original_transaction_hash".to_owned(), JsonValue::Null);
    assert!(
        reported_return_from_value(&local).is_err(),
        "an immutable source anchor is mandatory"
    );
    local.as_object_mut().unwrap().insert(
        "original_payload_hash".to_owned(),
        JsonValue::from("25".repeat(32)),
    );
    assert!(reported_return_from_value(&local).is_ok());
    let mut extra = canonical;
    extra.as_object_mut().unwrap().insert(
        "reverse_transaction_hash".to_owned(),
        JsonValue::from("16".repeat(32)),
    );
    assert!(reported_return_from_value(&extra).is_err());
}

#[test]
fn reported_return_record_rejects_invented_native_execution_after_restart() {
    let runtime = sample_runtime();
    record_settled_report_original(&runtime, "persist-return-original");
    record_lifecycle(&runtime, "persist-return-report", "pacs.004");
    let parsed = reported_return_message(
        "persist-return-original",
        "persist-return-report",
        "10",
        "USD",
    );
    runtime
        .apply_inbound_lifecycle_message("persist-return-report", "pacs.004", &parsed)
        .expect("record report");
    let record = runtime.records.get("persist-return-report").unwrap();
    let canonical = persisted_record_value("persist-return-report", &record);
    assert!(persisted_record_from_value(&canonical).is_some());
    for (field, value) in [
        ("ledger_tx_queued", JsonValue::from(true)),
        ("transaction_hash", JsonValue::from("17".repeat(32))),
        ("settled_at_ms", JsonValue::from(100_u64)),
        ("state", JsonValue::from("Rejected")),
    ] {
        let mut changed = canonical.clone();
        let object = changed.as_object_mut().unwrap();
        object.insert(field.to_owned(), value);
        object.remove(ISO_PERSISTED_RECORD_DIGEST_FIELD);
        let digest = persisted_record_digest(&JsonValue::Object(object.clone()));
        object.insert(
            ISO_PERSISTED_RECORD_DIGEST_FIELD.to_owned(),
            JsonValue::from(digest),
        );
        assert!(persisted_record_digest_matches(object));
        assert!(
            persisted_record_from_value(&changed).is_none(),
            "accepted invented {field}"
        );
    }
}

#[test]
fn reported_return_rejects_multiple_payment_legs() {
    let runtime = sample_runtime();
    record_settled_report_original(&runtime, "multi-return-original");
    record_lifecycle(&runtime, "multi-return-report", "pacs.004");
    let parsed = parse_message("pacs.004", b"MsgId=multi-return-report\nCreDtTm=2025-01-01T00:00:00Z\nOrgnlGrpInf/OrgnlMsgId=multi-return-original\nTxInf[0]/OrgnlInstrId=original-instr\nTxInf[0]/RtrdInstdAmt=5\nTxInf[0]/RtrdInstdAmtCcy=USD\nTxInf[0]/RtrdRsn/Cd=AC01\nTxInf[1]/OrgnlInstrId=other-instr\nTxInf[1]/RtrdInstdAmt=5\nTxInf[1]/RtrdInstdAmtCcy=USD\nTxInf[1]/RtrdRsn/Cd=AC01").expect("two return legs parse");
    assert!(
        runtime
            .apply_inbound_lifecycle_message("multi-return-report", "pacs.004", &parsed)
            .is_err()
    );
    assert_eq!(
        runtime
            .message_status("multi-return-original")
            .unwrap()
            .pacs002_code(),
        "ACSC"
    );
}

#[test]
fn reported_return_pending_survives_restart_and_terminal_original_projection() {
    for applied in [false, true] {
        let store = TempDir::new().unwrap();
        let mut config = sample_config();
        config.store_dir = Some(store.path().to_path_buf());
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .unwrap()
            .unwrap();
        let hash = record_report_original(&runtime, "pending-original", false);
        record_lifecycle(&runtime, "pending-report", "pacs.004");
        let parsed = reported_return_message("pending-original", "pending-report", "5", "USD");
        let (_, report) = runtime
            .apply_inbound_lifecycle_message_with_status("pending-report", "pacs.004", &parsed)
            .unwrap();
        assert_eq!(report.status_label(), "Pending");
        assert_eq!(
            runtime
                .pending_return_originals
                .get("pending-original")
                .as_deref(),
            Some(&1)
        );
        // Original projection may commit independently before return finalization or a crash.
        if applied {
            assert!(
                runtime.mark_transaction_applied(
                    &hash,
                    SystemTime::UNIX_EPOCH + Duration::from_secs(12)
                )
            );
        } else {
            assert!(runtime.mark_transaction_rejected(&hash, None));
        }
        let original_before = persisted_record_value(
            "pending-original",
            &runtime.records.get("pending-original").unwrap(),
        );
        drop(runtime);
        let reloaded = Iso20022BridgeRuntime::from_config(&config)
            .unwrap()
            .unwrap();
        let pending = reloaded.pending_return_transactions();
        assert_eq!(pending.get(&hash), Some(&vec!["pending-report".to_owned()]));
        reloaded
            .resolve_pending_return_reports(&hash, &pending[&hash], applied)
            .unwrap();
        let report = reloaded.message_status("pending-report").unwrap();
        assert_eq!(
            report.reported_return_json()["disposition"].as_str(),
            Some(if applied {
                "external_report"
            } else {
                "original_rejected"
            })
        );
        assert_eq!(
            report.status_label(),
            if applied { "Accepted" } else { "Rejected" }
        );
        assert!(report.transaction_hash().is_none());
        assert!(report.settled_at().is_none());
        assert!(reloaded.pending_return_transactions().is_empty());
        assert!(
            !reloaded
                .pending_return_originals
                .contains_key("pending-original")
        );
        assert_eq!(
            persisted_record_value(
                "pending-original",
                &reloaded.records.get("pending-original").unwrap()
            ),
            original_before
        );
    }
}

#[test]
fn reported_return_pending_pins_original_through_retention_and_restart() {
    let store = TempDir::new().unwrap();
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    config.store_retention_secs = 1;
    config.store_max_records = 2;
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .unwrap()
        .unwrap();
    let hash = record_report_original(&runtime, "pinned-original", false);
    record_lifecycle(&runtime, "pinned-report", "pacs.004");
    let parsed = reported_return_message("pinned-original", "pinned-report", "5", "USD");
    runtime
        .apply_inbound_lifecycle_message("pinned-report", "pacs.004", &parsed)
        .unwrap();
    assert!(runtime.mark_transaction_applied(&hash, SystemTime::now()));
    runtime
        .try_transition_existing("pinned-original", |record| {
            record.updated_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        })
        .unwrap();
    runtime.compact_persisted_records();
    assert!(runtime.message_status("pinned-original").is_some());
    assert!(matches!(
        runtime.admit_inbound(
            "over-capacity",
            inbound_metadata("over-capacity", "pacs.008"),
            runtime.compatibility_test_parties(&inbound_metadata("over-capacity", "pacs.008")),
            false
        ),
        Err(IsoAdmissionError::ProtectedCapacity)
    ));
    drop(runtime);
    let reloaded = Iso20022BridgeRuntime::from_config(&config)
        .unwrap()
        .unwrap();
    assert!(reloaded.message_status("pinned-original").is_some());
    assert_eq!(
        reloaded
            .pending_return_originals
            .get("pinned-original")
            .as_deref(),
        Some(&1)
    );
    let pending = reloaded.pending_return_transactions();
    reloaded
        .resolve_pending_return_reports(&hash, &pending[&hash], true)
        .unwrap();
    assert!(
        !reloaded
            .pending_return_originals
            .contains_key("pinned-original")
    );
    reloaded.compact_persisted_records();
    assert!(reloaded.message_status("pinned-original").is_none());
    assert_eq!(
        reloaded
            .message_status("pinned-report")
            .unwrap()
            .reported_return_json()["disposition"]
            .as_str(),
        Some("external_report")
    );
}

#[tokio::test]
async fn reported_return_before_carrier_assignment_retains_binding_and_wakes_projection() {
    let runtime = sample_runtime();
    let mut metadata = inbound_metadata("early-original", "pacs.008");
    metadata.payload_hash = Some(sha256_hex(b"early original exact XML"));
    assert!(runtime.check_and_record_inbound("early-original", metadata));
    record_lifecycle(&runtime, "early-report", "pacs.004");
    let parsed = reported_return_message("early-original", "early-report", "5", "USD");
    let (_, report) = runtime
        .apply_inbound_lifecycle_message_with_status("early-report", "pacs.004", &parsed)
        .unwrap();
    assert_eq!(
        report.reported_return_json()["disposition"].as_str(),
        Some("pending_original")
    );
    assert!(report.reported_return_json()["original_transaction_hash"].is_null());
    assert!(runtime.pending_return_transactions().is_empty());
    tokio::time::timeout(Duration::from_secs(1), runtime.projection_work_available())
        .await
        .unwrap();
    assert!(runtime.update_message_context(
        "early-original",
        IsoMessageContext {
            settlement_amount: Some("10".to_owned()),
            settlement_currency: Some("USD".to_owned()),
            ..IsoMessageContext::default()
        }
    ));
    let hash = "21".repeat(32);
    runtime.mark_accepted("early-original", &hash);
    tokio::time::timeout(Duration::from_secs(1), runtime.projection_work_available())
        .await
        .unwrap();
    let pending = runtime.pending_return_transactions();
    assert_eq!(pending[&hash], vec!["early-report"]);
    runtime
        .resolve_pending_return_reports(&hash, &pending[&hash], true)
        .unwrap();
    assert_eq!(
        runtime
            .message_status("early-report")
            .unwrap()
            .reported_return_json()["original_transaction_hash"]
            .as_str(),
        Some(hash.as_str())
    );
}

#[test]
fn reported_return_pending_resolution_rechecks_exact_parties_terms_and_reference() {
    for corruption in ["amount", "currency", "payload", "party"] {
        let runtime = sample_runtime();
        let hash = record_report_original(&runtime, "rechecked-original", false);
        record_lifecycle(&runtime, "rechecked-report", "pacs.004");
        let parsed = reported_return_message("rechecked-original", "rechecked-report", "5", "USD");
        runtime
            .apply_inbound_lifecycle_message("rechecked-report", "pacs.004", &parsed)
            .unwrap();
        // Deliberately model invalid source replacement/terms at the final journal boundary.
        {
            let mut original = runtime.records.get_mut("rechecked-original").unwrap();
            match corruption {
                "amount" => original.context.settlement_amount = Some("4".to_owned()),
                "currency" => original.context.settlement_currency = Some("EUR".to_owned()),
                "payload" => original.metadata.payload_hash = Some("22".repeat(32)),
                "party" => original.parties.counterparty_participant_id = "other-bank".to_owned(),
                _ => unreachable!(),
            }
        }
        let pending = runtime.pending_return_transactions();
        runtime
            .resolve_pending_return_reports(&hash, &pending[&hash], true)
            .unwrap();
        let report = runtime.message_status("rechecked-report").unwrap();
        assert_eq!(
            report.reported_return_json()["disposition"].as_str(),
            Some("invalid_terms"),
            "{corruption}"
        );
        assert_eq!(report.status_label(), "Rejected");
        assert!(report.settled_at().is_none());
    }
}

#[test]
fn reported_return_recovers_when_finalization_journal_fails_after_original_applies() {
    let store = TempDir::new().unwrap();
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .unwrap()
        .unwrap();
    let hash = record_report_original(&runtime, "retry-original", false);
    record_lifecycle(&runtime, "retry-report", "pacs.004");
    runtime
        .apply_inbound_lifecycle_message(
            "retry-report",
            "pacs.004",
            &reported_return_message("retry-original", "retry-report", "5", "USD"),
        )
        .unwrap();
    assert!(
        runtime.mark_transaction_applied(&hash, SystemTime::UNIX_EPOCH + Duration::from_secs(12))
    );
    let original_path = store
        .path()
        .join("messages")
        .join(message_filename("retry-original"));
    let original_bytes = fs::read(&original_path).unwrap();
    let operations = store.path().join(ISO_PERSISTED_LIFECYCLE_OPERATION_DIR);
    let backup = store.path().join("operations-backup");
    fs::rename(&operations, &backup).unwrap();
    fs::write(&operations, b"refuse return finalization journal").unwrap();
    let pending = runtime.pending_return_transactions();
    assert_eq!(
        runtime.resolve_pending_return_reports(&hash, &pending[&hash], true),
        Err(IsoStatusHistoryLimitError::Persistence)
    );
    assert_eq!(
        runtime
            .message_status("retry-report")
            .unwrap()
            .reported_return_json()["disposition"]
            .as_str(),
        Some("pending_original")
    );
    fs::remove_file(&operations).unwrap();
    fs::rename(&backup, &operations).unwrap();
    drop(runtime);
    let restored = Iso20022BridgeRuntime::from_config(&config)
        .unwrap()
        .unwrap();
    let pending = restored.pending_return_transactions();
    restored
        .resolve_pending_return_reports(&hash, &pending[&hash], true)
        .unwrap();
    assert_eq!(
        restored
            .message_status("retry-report")
            .unwrap()
            .reported_return_json()["disposition"]
            .as_str(),
        Some("external_report")
    );
    assert_eq!(fs::read(&original_path).unwrap(), original_bytes);
}

#[test]
fn reported_return_authorization_survives_same_original_carrier_assignment() {
    let runtime = sample_runtime();
    let mut metadata = inbound_metadata("assigned-original", "pacs.008");
    metadata.payload_hash = Some(sha256_hex(b"immutable assigned original"));
    assert!(runtime.check_and_record_inbound("assigned-original", metadata));
    let parsed = reported_return_message("assigned-original", "assigned-report", "5", "USD");
    let authorization = runtime
        .compatibility_lifecycle_authorization("pacs.004", &parsed)
        .unwrap();
    assert!(
        authorization
            .original
            .as_ref()
            .unwrap()
            .transaction_hash
            .is_none()
    );
    // The builder finishes between participant authorization and durable report admission.
    assert!(runtime.update_message_context(
        "assigned-original",
        IsoMessageContext {
            settlement_amount: Some("10".to_owned()),
            settlement_currency: Some("USD".to_owned()),
            ..IsoMessageContext::default()
        }
    ));
    let hash = "23".repeat(32);
    runtime.mark_accepted("assigned-original", &hash);
    record_lifecycle(&runtime, "assigned-report", "pacs.004");
    let (_, report) = runtime
        .apply_inbound_lifecycle_message_with_evidence(
            "assigned-report",
            "pacs.004",
            &parsed,
            &authorization,
            None,
        )
        .unwrap();
    assert_eq!(
        report.reported_return_json()["original_transaction_hash"].as_str(),
        Some(hash.as_str())
    );
    assert_eq!(
        report.reported_return_json()["disposition"].as_str(),
        Some("pending_original")
    );
}

#[tokio::test]
async fn reported_return_pre_carrier_rejection_recovers_as_local_observation_only() {
    for assigned in [false, true] {
        let store = TempDir::new().unwrap();
        let mut config = sample_config();
        config.store_dir = Some(store.path().to_path_buf());
        let runtime = Iso20022BridgeRuntime::from_config(&config)
            .unwrap()
            .unwrap();
        let mut metadata = inbound_metadata("unsubmitted-original", "pacs.008");
        metadata.payload_hash = Some(sha256_hex(b"exact unsubmitted original"));
        assert!(runtime.check_and_record_inbound("unsubmitted-original", metadata));
        record_lifecycle(&runtime, "unsubmitted-report", "pacs.004");
        runtime
            .apply_inbound_lifecycle_message(
                "unsubmitted-report",
                "pacs.004",
                &reported_return_message("unsubmitted-original", "unsubmitted-report", "5", "USD"),
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.projection_work_available())
            .await
            .unwrap();
        runtime.resolve_unsubmitted_return_reports().unwrap();
        assert_eq!(
            runtime
                .message_status("unsubmitted-report")
                .unwrap()
                .reported_return_json()["disposition"]
                .as_str(),
            Some("pending_original")
        );
        if assigned {
            runtime.mark_accepted("unsubmitted-original", &"24".repeat(32));
        }
        assert!(runtime.mark_rejected(
            "unsubmitted-original",
            Some("local payment construction failed".to_owned()),
            None
        ));
        tokio::time::timeout(Duration::from_secs(1), runtime.projection_work_available())
            .await
            .unwrap();
        let before = persisted_record_value(
            "unsubmitted-original",
            &runtime.records.get("unsubmitted-original").unwrap(),
        );
        drop(runtime);
        let restored = Iso20022BridgeRuntime::from_config(&config)
            .unwrap()
            .unwrap();
        restored.resolve_unsubmitted_return_reports().unwrap();
        let report = restored.message_status("unsubmitted-report").unwrap();
        assert_eq!(
            report.reported_return_json()["disposition"].as_str(),
            Some(if assigned {
                "pending_original"
            } else {
                "original_not_submitted"
            })
        );
        assert!(report.transaction_hash().is_none());
        assert!(report.settled_at().is_none());
        assert_eq!(
            restored
                .pending_return_originals
                .contains_key("unsubmitted-original"),
            assigned
        );
        if !assigned {
            assert_eq!(report.status_label(), "Rejected");
            assert!(report.reported_return_json()["original_transaction_hash"].is_null());
            assert_eq!(
                report.rejection_reason_code(),
                Some("PRTRY:ORIGINAL_NOT_SUBMITTED")
            );
        }
        assert_eq!(
            persisted_record_value(
                "unsubmitted-original",
                &restored.records.get("unsubmitted-original").unwrap()
            ),
            before
        );
    }
}

#[tokio::test]
async fn reported_return_repeated_original_rejection_does_not_republish() {
    let store = TempDir::new().unwrap();
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .unwrap()
        .unwrap();
    let hash = record_report_original(&runtime, "rejected-original", false);
    record_lifecycle(&runtime, "waiting-report", "pacs.004");
    runtime
        .apply_inbound_lifecycle_message(
            "waiting-report",
            "pacs.004",
            &reported_return_message("rejected-original", "waiting-report", "5", "USD"),
        )
        .unwrap();
    // The distinct local expiry is still superseded by the authentic canonical rejection.
    assert!(runtime.mark_transaction_expired(&hash));
    assert_eq!(
        runtime
            .message_status("rejected-original")
            .unwrap()
            .rejection_reason_code(),
        Some("ED07")
    );
    assert!(runtime.mark_transaction_rejected(&hash, None));
    assert_eq!(
        runtime
            .message_status("rejected-original")
            .unwrap()
            .rejection_reason_code(),
        Some("PRTRY:TX_REJECTED")
    );
    runtime.projection_work_available().await;
    let before = persisted_record_value(
        "rejected-original",
        &runtime.records.get("rejected-original").unwrap(),
    );
    // Leave report finalization pending, as after a refused report-journal publication.
    for _ in 0..4 {
        assert!(runtime.mark_transaction_rejected(&hash, None));
        assert_eq!(
            persisted_record_value(
                "rejected-original",
                &runtime.records.get("rejected-original").unwrap()
            ),
            before
        );
    }
    let wakeup = runtime.projection_work_available();
    tokio::pin!(wakeup);
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(
            std::future::Future::poll(wakeup.as_mut(), cx).is_pending()
        ))
        .await
    );
    let pending = runtime.pending_return_transactions();
    assert_eq!(pending[&hash], vec!["waiting-report"]);
    runtime
        .resolve_pending_return_reports(&hash, &pending[&hash], false)
        .unwrap();
    assert_eq!(
        runtime
            .message_status("waiting-report")
            .unwrap()
            .reported_return_json()["disposition"]
            .as_str(),
        Some("original_rejected")
    );
}
