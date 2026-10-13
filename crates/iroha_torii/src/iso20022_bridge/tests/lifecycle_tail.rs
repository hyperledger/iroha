#[test]
fn sese025_outbox_refuses_unsettled_or_incomplete_records() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    assert!(runtime.check_and_record_message("sese.023:INCOMPLETE"));
    runtime.update_message_context(
        "sese.023:INCOMPLETE",
        IsoMessageContext {
            settlement_amount: Some("15".to_owned()),
            settlement_currency: Some("USD".to_owned()),
            settlement_quantity: Some("1".to_owned()),
            settlement_movement_type: Some("DELI".to_owned()),
            settlement_payment_type: Some("APMT".to_owned()),
            plan_execution_order: Some("DELIVERY_THEN_PAYMENT".to_owned()),
            plan_atomicity: Some("ALL_OR_NOTHING".to_owned()),
            ..IsoMessageContext::default()
        },
    );
    let pending = runtime
        .message_status("sese.023:INCOMPLETE")
        .expect("pending");
    let err = crate::iso_sese025_xml(&pending).expect_err("unsettled must fail");
    assert_outbox_error_contains(err, "requires a settled");
    runtime.mark_settled("sese.023:INCOMPLETE", SystemTime::now());
    runtime.update_message_context(
        "sese.023:INCOMPLETE",
        IsoMessageContext {
            settlement_amount: Some("15".to_owned()),
            settlement_currency: Some("USD".to_owned()),
            settlement_quantity: Some("1".to_owned()),
            settlement_movement_type: Some("DELI".to_owned()),
            settlement_payment_type: Some("APMT".to_owned()),
            plan_execution_order: Some("DELIVERY_THEN_PAYMENT".to_owned()),
            ..IsoMessageContext::default()
        },
    );
    runtime.mark_settled("sese.023:INCOMPLETE", SystemTime::now());
    let incomplete = runtime
        .message_status("sese.023:INCOMPLETE")
        .expect("settled");
    let err = crate::iso_sese025_xml(&incomplete).expect_err("missing atomicity must fail");
    assert_outbox_error_contains(err, "plan_atomicity");
}
#[test]
fn queued_message_reports_acsp() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let message_id = "m_queue";
    assert!(runtime.check_and_record_message(message_id));
    runtime.mark_queued(message_id);
    let status = runtime.message_status(message_id).expect("status");
    assert_eq!(status.pacs002_code(), "ACSP");
    assert_eq!(status.derived_status(), Pacs002Status::Acsp);
}
#[test]
fn hold_message_reports_pdng() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let message_id = "m_hold";
    assert!(runtime.check_and_record_message(message_id));
    runtime.mark_hold(message_id, Some("PDNG"));
    let status = runtime.message_status(message_id).expect("status");
    assert_eq!(status.pacs002_code(), "PDNG");
    assert_eq!(status.hold_reason_code(), Some("PDNG"));
}
#[test]
fn terminal_public_mutators_do_not_regress_records() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");

    assert!(runtime.check_and_record_message("settled-terminal"));
    runtime.mark_accepted("settled-terminal", "tx-settled-terminal");
    assert!(runtime.mark_settled("settled-terminal", SystemTime::now()));
    assert!(!runtime.mark_hold("settled-terminal", Some("PDNG")));
    assert!(!runtime.mark_queued("settled-terminal"));
    assert!(!runtime.mark_rejected(
        "settled-terminal",
        Some("late rejection".to_owned()),
        Some("RJCT"),
    ));
    let settled = runtime.mark_accepted("settled-terminal", "tx-replacement");
    assert_eq!(settled.pacs002_code(), "ACSC");
    assert_eq!(settled.transaction_hash(), Some("tx-settled-terminal"));

    assert!(runtime.check_and_record_message("rejected-terminal"));
    assert!(runtime.mark_rejected(
        "rejected-terminal",
        Some("definitive rejection".to_owned()),
        Some("BE01"),
    ));
    assert!(!runtime.mark_hold("rejected-terminal", Some("PDNG")));
    assert!(!runtime.mark_queued("rejected-terminal"));
    assert!(!runtime.mark_settled("rejected-terminal", SystemTime::now()));
    let rejected = runtime.mark_accepted("rejected-terminal", "tx-late-success");
    assert_eq!(rejected.pacs002_code(), "RJCT");
    assert_eq!(rejected.rejection_reason_code(), Some("BE01"));
    assert_eq!(rejected.transaction_hash(), None);
}
#[test]
fn change_message_reports_acwc() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let message_id = "m_acwc";
    assert!(runtime.check_and_record_message(message_id));
    runtime.add_change_reason_code(message_id, "VAL_DATE_SHIFT");
    runtime.add_change_reason_code(message_id, "VAL_DATE_SHIFT");
    let status = runtime.message_status(message_id).expect("status");
    assert_eq!(status.pacs002_code(), "ACWC");
    assert_eq!(
        status.change_reason_codes(),
        &["VAL_DATE_SHIFT".to_owned()][..]
    );
}
#[test]
fn transaction_rejection_marks_message() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let message_id = "m_reject";
    assert!(runtime.check_and_record_message(message_id));
    runtime.mark_accepted(message_id, "tx-reject");
    let reason = TransactionRejectionReason::LimitCheck(TransactionLimitError {
        reason: "too many instructions".to_owned(),
    });
    runtime.mark_transaction_rejected("tx-reject", Some(&reason));
    let status = runtime.message_status(message_id).expect("status");
    assert_eq!(status.pacs002_code(), "RJCT");
    assert_eq!(status.transaction_hash(), Some("tx-reject"));
    assert_eq!(status.rejection_reason_code(), Some("BE01"));
    assert_eq!(
        status.detail(),
        Some("Transaction limit check failed: too many instructions"),
    );
}
#[test]
fn axt_rejection_produces_prtry_code_and_detail() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let message_id = "m_axt_reject";
    assert!(runtime.check_and_record_message(message_id));
    runtime.mark_accepted(message_id, "tx-axt");
    let ctx = AxtRejectContext {
        reason: AxtRejectReason::HandleEra,
        dataspace: Some(DataSpaceId::new(11)),
        lane: Some(LaneId::new(2)),
        snapshot_version: Some(99),
        detail: "handle era differs from the exact active policy era".to_owned(),
        active_handle_era: Some(7),
        next_handle_counter: Some(4),
    };
    let reason = TransactionRejectionReason::Validation(ValidationFail::AxtReject(ctx));
    runtime.mark_transaction_rejected("tx-axt", Some(&reason));
    let status = runtime.message_status(message_id).expect("status");
    assert_eq!(status.pacs002_code(), "RJCT");
    assert_eq!(status.rejection_reason_code(), Some("PRTRY:AXT_HANDLE_ERA"));
    let detail = status.detail().expect("detail");
    assert!(
        detail.contains("AXT rejection"),
        "detail missing AXT label: {detail}"
    );
    assert!(
        detail.contains("snapshot_version=99"),
        "detail missing snapshot version: {detail}"
    );
    assert!(
        detail.contains("dsid=11") && detail.contains("lane=2"),
        "detail missing ids: {detail}"
    );
    assert!(
        detail.contains("active_handle_era=7") && detail.contains("next_handle_counter=4"),
        "detail missing hints: {detail}"
    );
}
#[test]
fn transaction_expiry_marks_message() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let message_id = "m_expired";
    assert!(runtime.check_and_record_message(message_id));
    runtime.mark_accepted(message_id, "tx-expired");
    runtime.mark_transaction_expired("tx-expired");
    let status = runtime.message_status(message_id).expect("status");
    assert_eq!(status.pacs002_code(), "RJCT");
    assert_eq!(status.transaction_hash(), Some("tx-expired"));
    assert_eq!(status.rejection_reason_code(), Some("ED07"));
    assert_eq!(
        status.detail(),
        Some("transaction expired before admission")
    );
}
#[test]
fn lifecycle_rejects_replayed_payload_hash() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let first = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.002",
        None,
        Some("status-1".to_owned()),
        None,
        "same-payload-hash".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    let replay = IsoMessageMetadata::inbound(
        "generic-iso20022",
        "pacs.002",
        None,
        Some("status-2".to_owned()),
        None,
        "same-payload-hash".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(runtime.check_and_record_inbound("status-1", first));
    assert!(!runtime.check_and_record_inbound("status-2", replay));
}
#[test]
fn lifecycle_pacs002_settles_known_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "orig-1", "pacs.008");
    runtime.mark_accepted("orig-1", "tx-orig-1");
    let parsed = parse_message("pacs.002", b"MsgId=status-1\nOrgnlMsgId=orig-1\nTxSts=ACSC")
        .expect("pacs.002 parsed");
    let metadata = runtime
        .validate_profile_submission(runtime.default_profile(), "pacs.002", &parsed, b"pacs2")
        .expect("profile accepts pacs.002");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("pacs.002", &parsed).expect("lifecycle id");
    assert_eq!(lifecycle_id, "status-1");
    assert!(runtime.check_and_record_inbound(&lifecycle_id, metadata));
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "pacs.002", &parsed)
        .expect("lifecycle applied");
    assert_eq!(outcome.referenced_message_id(), Some("orig-1"));
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.lifecycle_status_code(), Some("ACSC"));
    assert_eq!(outcome.action(), "marked_settled");
    assert_eq!(
        runtime
            .message_status("status-1")
            .expect("lifecycle status")
            .status_label(),
        "Accepted"
    );
    assert_eq!(
        runtime
            .message_status("orig-1")
            .expect("original status")
            .pacs002_code(),
        "ACSC"
    );
}
#[test]
fn lifecycle_profile_mismatch_does_not_mutate_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "profile-original", "pacs.008");
    runtime.mark_accepted("profile-original", "tx-profile-original");
    let parsed = parse_message(
        "pacs.002",
        b"MsgId=profile-status\nOrgnlMsgId=profile-original\nTxSts=ACSC",
    )
    .expect("pacs.002 parsed");
    let lifecycle_metadata = IsoMessageMetadata::inbound(
        "swift-cbpr-plus",
        "pacs.002",
        Some("swift.cbprplus.02".to_owned()),
        Some("profile-status-biz".to_owned()),
        None,
        "profile-status-payload".to_owned(),
        "snapshot".to_owned(),
        false,
    );
    assert!(runtime.check_and_record_inbound("profile-status", lifecycle_metadata));
    let outcome = runtime
        .apply_inbound_lifecycle_message("profile-status", "pacs.002", &parsed)
        .expect("lifecycle recorded");
    assert_eq!(outcome.action(), "ignored_profile_mismatch");
    assert_eq!(
        runtime
            .message_status("profile-original")
            .expect("original")
            .pacs002_code(),
        "ACSP"
    );
}
#[test]
fn lifecycle_rejects_settlement_without_an_original_transaction_hash() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "in-flight-original", "pacs.008");
    let parsed = parse_message(
        "pacs.002",
        b"MsgId=in-flight-status\nOrgnlMsgId=in-flight-original\nTxSts=ACSC",
    )
    .expect("pacs.002 parsed");
    record_lifecycle(&runtime, "in-flight-status", "pacs.002");
    let error = runtime
        .apply_inbound_lifecycle_message("in-flight-status", "pacs.002", &parsed)
        .expect_err("settlement without an exact original transaction hash must fail closed");
    assert!(matches!(error, MsgError::ValidationFailed));
    assert_eq!(
        runtime
            .message_status("in-flight-original")
            .expect("original")
            .pacs002_code(),
        "ACTC"
    );
}
#[test]
fn lifecycle_apply_returns_snapshot_before_retention_compaction() {
    let store = TempDir::new().expect("tempdir");
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_path_buf());
    let mut runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    runtime.store_retention = std::time::Duration::from_nanos(1);
    record_original(&runtime, "compact-lifecycle-original", "pacs.008");
    assert!(runtime.mark_queued("compact-lifecycle-original"));
    let parsed = parse_message(
        "pacs.002",
        b"MsgId=compact-lifecycle-response\nOrgnlMsgId=compact-lifecycle-original\nTxSts=ACSP",
    )
    .expect("pacs.002 parsed");
    record_lifecycle(&runtime, "compact-lifecycle-response", "pacs.002");

    let (outcome, snapshot) = runtime
        .apply_inbound_lifecycle_message_with_status(
            "compact-lifecycle-response",
            "pacs.002",
            &parsed,
        )
        .expect("lifecycle response snapshot");
    assert_eq!(outcome.action(), "marked_processing");
    assert_eq!(snapshot.message_id(), "compact-lifecycle-response");
    assert_eq!(snapshot.status_label(), "Accepted");

    std::thread::sleep(std::time::Duration::from_millis(1));
    runtime.compact_persisted_records();
    assert!(
        runtime
            .message_status("compact-lifecycle-response")
            .is_none()
    );
    assert_eq!(snapshot.status_label(), "Accepted");
}
#[test]
fn lifecycle_pacs002_rejects_unknown_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let parsed = parse_message(
        "pacs.002",
        b"MsgId=orphan-status\nOrgnlMsgId=unknown-original\nTxSts=ACSP",
    )
    .expect("pacs.002 parsed");
    record_lifecycle(&runtime, "orphan-status", "pacs.002");

    let error = runtime
        .apply_inbound_lifecycle_message("orphan-status", "pacs.002", &parsed)
        .expect_err("an unknown payment original must fail closed");
    assert!(matches!(error, MsgError::ValidationFailed));
    assert_eq!(
        runtime
            .message_status("orphan-status")
            .expect("admitted lifecycle identity remains reserved")
            .status_label(),
        "Pending"
    );
}
#[test]
fn checked_in_pacs002_fixture_settles_known_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "STATUS-ORIG-1", "pacs.008");
    runtime.mark_accepted("STATUS-ORIG-1", "tx-status-orig-1");
    let parsed =
        parse_message("pacs.002", PACS002_FIXTURE_XML.as_bytes()).expect("pacs.002 fixture");
    let metadata = runtime
        .validate_profile_submission(
            runtime.default_profile(),
            "pacs.002",
            &parsed,
            PACS002_FIXTURE_XML.as_bytes(),
        )
        .expect("profile accepts pacs.002 fixture");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("pacs.002", &parsed).expect("lifecycle id");
    assert_eq!(lifecycle_id, "STATUS-FIXTURE-1");
    assert!(runtime.check_and_record_inbound(&lifecycle_id, metadata));
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "pacs.002", &parsed)
        .expect("lifecycle applied");
    assert_eq!(outcome.referenced_message_id(), Some("STATUS-ORIG-1"));
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.lifecycle_status_code(), Some("ACSC"));
    assert_eq!(outcome.action(), "marked_settled");
    assert_eq!(
        runtime
            .message_status("STATUS-ORIG-1")
            .expect("original status")
            .pacs002_code(),
        "ACSC"
    );
    assert_eq!(
        runtime
            .message_status(&lifecycle_id)
            .expect("lifecycle status")
            .status_label(),
        "Accepted"
    );
}
#[test]
fn lifecycle_pacs002_uses_group_header_msgid_not_transaction_status_id() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "orig-status-shadow", "pacs.008");
    runtime.mark_accepted("orig-status-shadow", "tx-status-shadow");
    let payload = br#"
<pacs:Document xmlns:pacs="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">
  <pacs:FIToFIPmtStsRpt>
<pacs:GrpHdr>
  <pacs:MsgId>status-group-id</pacs:MsgId>
  <pacs:CreDtTm>2025-01-01T00:10:00Z</pacs:CreDtTm>
</pacs:GrpHdr>
<pacs:OrgnlGrpInfAndSts>
  <pacs:OrgnlMsgId>orig-status-shadow</pacs:OrgnlMsgId>
  <pacs:OrgnlMsgNmId>pacs.008.001.08</pacs:OrgnlMsgNmId>
</pacs:OrgnlGrpInfAndSts>
<pacs:TxInfAndSts>
  <pacs:StsId>status-transaction-shadow</pacs:StsId>
  <pacs:TxSts>ACSC</pacs:TxSts>
</pacs:TxInfAndSts>
  </pacs:FIToFIPmtStsRpt>
</pacs:Document>
"#;
    let parsed = parse_message("pacs.002", payload).expect("pacs.002 parsed");
    let metadata = runtime
        .validate_profile_submission(runtime.default_profile(), "pacs.002", &parsed, payload)
        .expect("profile accepts pacs.002");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("pacs.002", &parsed).expect("lifecycle id");
    assert_eq!(metadata.business_message_id(), Some("status-group-id"));
    assert_eq!(
        parsed.field_text("StsId"),
        Some("status-transaction-shadow")
    );
    assert_eq!(lifecycle_id, "status-group-id");
    assert!(runtime.check_and_record_inbound(&lifecycle_id, metadata));
    assert!(!runtime.check_and_record_message("status-group-id"));
    assert!(runtime.check_and_record_message("status-transaction-shadow"));
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "pacs.002", &parsed)
        .expect("lifecycle applied");
    assert_eq!(outcome.referenced_message_id(), Some("orig-status-shadow"));
    assert_eq!(outcome.action(), "marked_settled");
    assert_eq!(
        runtime
            .message_status("orig-status-shadow")
            .expect("original status")
            .pacs002_code(),
        "ACSC"
    );
}
#[test]
fn lifecycle_pacs002_ignores_non_payment_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "orig-status-securities", "sese.023");
    runtime.mark_accepted("orig-status-securities", "tx-status-securities");
    let parsed = parse_message(
        "pacs.002",
        b"MsgId=status-securities\nOrgnlMsgId=orig-status-securities\nTxSts=ACSC",
    )
    .expect("pacs.002 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("pacs.002", &parsed).expect("lifecycle id");
    record_lifecycle(&runtime, &lifecycle_id, "pacs.002");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "pacs.002", &parsed)
        .expect("lifecycle applied");
    assert_eq!(
        outcome.referenced_message_id(),
        Some("orig-status-securities")
    );
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.action(), "ignored_message_family_mismatch");
    assert_eq!(
        runtime
            .message_status("orig-status-securities")
            .expect("original status")
            .pacs002_code(),
        "ACSP"
    );
}
#[test]
fn lifecycle_pacs004_retains_unsettled_original_report() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let original_hash = record_report_original(&runtime, "orig-return", false);
    let parsed = parse_message(
        "pacs.004",
        b"MsgId=return-1\nCreDtTm=2025-01-01T00:00:00Z\nOrgnlGrpInf/OrgnlMsgId=orig-return\nTxInf[0]/OrgnlInstrId=instr-1\nTxInf[0]/RtrdInstdAmt=10.00\nTxInf[0]/RtrdInstdAmtCcy=USD\nTxInf[0]/RtrdRsn/Cd=AC01",
    )
    .expect("pacs.004 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("pacs.004", &parsed).expect("lifecycle id");
    record_lifecycle(&runtime, &lifecycle_id, "pacs.004");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "pacs.004", &parsed)
        .expect("lifecycle applied");
    assert_eq!(outcome.referenced_message_id(), Some("orig-return"));
    assert_eq!(outcome.lifecycle_reason_code(), Some("AC01"));
    assert_eq!(outcome.action(), "recorded_return");
    let original = runtime
        .message_status("orig-return")
        .expect("original status");
    assert_eq!(original.status_label(), "Accepted");
    assert_eq!(original.pacs002_code(), "ACSP");
    assert_eq!(original.transaction_hash(), Some(original_hash.as_str()));
    assert!(original.settled_at().is_none());
    let lifecycle = runtime
        .message_status("return-1")
        .expect("lifecycle status");
    assert_eq!(lifecycle.status_label(), "Pending");
    assert_eq!(lifecycle.pacs002_code(), "ACTC");
    assert_eq!(
        lifecycle.reported_return_json()["disposition"].as_str(),
        Some("pending_original")
    );
    assert_eq!(
        lifecycle.detail(),
        Some("recorded inbound ISO 20022 pacs.004 lifecycle message")
    );
}
#[test]
fn settled_original_accepts_pacs004_return_without_losing_success_evidence() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let original_hash = record_settled_report_original(&runtime, "settled-return");
    let parsed = parse_message(
        "pacs.004",
        b"MsgId=late-return\nCreDtTm=2025-01-01T00:00:00Z\nOrgnlGrpInf/OrgnlMsgId=settled-return\nTxInf[0]/OrgnlInstrId=instr-1\nTxInf[0]/RtrdInstdAmt=10.00\nTxInf[0]/RtrdInstdAmtCcy=USD\nTxInf[0]/RtrdRsn/Cd=AC01",
    )
    .expect("pacs.004 parsed");
    record_lifecycle(&runtime, "late-return", "pacs.004");
    let outcome = runtime
        .apply_inbound_lifecycle_message("late-return", "pacs.004", &parsed)
        .expect("late lifecycle recorded");
    assert_eq!(outcome.action(), "recorded_return");
    let original = runtime
        .message_status("settled-return")
        .expect("settled original");
    assert_eq!(original.status_label(), "Accepted");
    assert_eq!(original.pacs002_code(), "ACSC");
    assert_eq!(original.transaction_hash(), Some(original_hash.as_str()));
    assert!(original.settled_at().is_some());
    assert_eq!(original.rejection_reason_code(), None);
}
#[test]
fn rejected_original_rejects_late_success_without_transaction_evidence() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "rejected-status", "pacs.008");
    assert!(runtime.mark_rejected(
        "rejected-status",
        Some("definitive rejection".to_owned()),
        Some("BE01")
    ));
    let parsed = parse_message(
        "pacs.002",
        b"MsgId=late-success\nOrgnlMsgId=rejected-status\nTxSts=ACSC",
    )
    .expect("pacs.002 parsed");
    record_lifecycle(&runtime, "late-success", "pacs.002");
    let error = runtime
        .apply_inbound_lifecycle_message("late-success", "pacs.002", &parsed)
        .expect_err("late success without exact transaction evidence must fail closed");
    assert!(matches!(error, MsgError::ValidationFailed));
    let original = runtime
        .message_status("rejected-status")
        .expect("rejected original");
    assert_eq!(original.status_label(), "Rejected");
    assert_eq!(original.pacs002_code(), "RJCT");
    assert_eq!(original.rejection_reason_code(), Some("BE01"));
    assert_eq!(original.detail(), Some("definitive rejection"));
}
#[test]
fn checked_in_pacs004_fixture_records_linked_external_report() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_settled_report_original(&runtime, "ORIGINAL-008");
    let parsed =
        parse_message("pacs.004", PACS004_FIXTURE_XML.as_bytes()).expect("pacs.004 fixture");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("pacs.004", &parsed).expect("lifecycle id");
    assert_eq!(lifecycle_id, "RETURN-FIXTURE-1");
    record_lifecycle(&runtime, &lifecycle_id, "pacs.004");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "pacs.004", &parsed)
        .expect("lifecycle applied");
    assert_eq!(outcome.referenced_message_id(), Some("ORIGINAL-008"));
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.lifecycle_status_code(), Some("RJCT"));
    assert_eq!(outcome.lifecycle_reason_code(), Some("AC01"));
    assert_eq!(outcome.action(), "recorded_return");
    let original = runtime
        .message_status("ORIGINAL-008")
        .expect("original status");
    assert_eq!(original.status_label(), "Accepted");
    assert_eq!(original.pacs002_code(), "ACSC");
    assert_eq!(original.rejection_reason_code(), None);
    assert_eq!(original.detail(), None);
    assert_eq!(
        runtime
            .message_status(&lifecycle_id)
            .expect("lifecycle status")
            .status_label(),
        "Accepted"
    );
}
#[test]
fn lifecycle_camt056_marks_known_original_cancellation_requested() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "orig-cancel", "pacs.008");
    runtime.mark_accepted("orig-cancel", "tx-cancel");
    let parsed = parse_message(
        "camt.056",
        b"Assgnmt/Id=cancel-2\nAssgnmt/CreDtTm=2025-01-01T00:00:00Z\nUndrlyg/TxInf/OrgnlGrpInf/OrgnlMsgId=orig-cancel\nUndrlyg/TxInf/CxlRsnInf/Rsn/Cd=CUST\nUndrlyg/TxInf/CxlRsnInf/AddtlInf=customer requested recall",
    )
    .expect("camt.056 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("camt.056", &parsed).expect("lifecycle id");
    assert_eq!(lifecycle_id, "cancel-2");
    record_lifecycle(&runtime, &lifecycle_id, "camt.056");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "camt.056", &parsed)
        .expect("lifecycle applied");
    assert_eq!(outcome.referenced_message_id(), Some("orig-cancel"));
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.lifecycle_status_code(), Some("PDNG"));
    assert_eq!(outcome.lifecycle_reason_code(), Some("CUST"));
    assert_eq!(outcome.action(), "marked_cancellation_requested");
    let original = runtime
        .message_status("orig-cancel")
        .expect("original status");
    assert_eq!(original.status_label(), "Accepted");
    assert_eq!(original.pacs002_code(), "ACSP");
    assert_eq!(original.hold_reason_code(), Some("CUST"));
    assert!(
        original
            .change_reason_codes()
            .iter()
            .any(|code| code == "CANCELLATION_REQUESTED"),
        "expected cancellation reason to be recorded: {:?}",
        original.change_reason_codes()
    );
    let lifecycle = runtime
        .message_status("cancel-2")
        .expect("lifecycle status");
    assert_eq!(lifecycle.status_label(), "Accepted");
    assert_eq!(
        lifecycle.detail(),
        Some("recorded inbound ISO 20022 camt.056 lifecycle message")
    );
}
#[test]
fn checked_in_camt056_fixture_marks_original_cancellation_requested() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "CANCEL-ORIG-1", "pacs.008");
    runtime.mark_accepted("CANCEL-ORIG-1", "tx-cancel-orig-1");
    let parsed =
        parse_message("camt.056", CAMT056_FIXTURE_XML.as_bytes()).expect("camt.056 fixture");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("camt.056", &parsed).expect("lifecycle id");
    assert_eq!(lifecycle_id, "CANCEL-FIXTURE-1");
    record_lifecycle(&runtime, &lifecycle_id, "camt.056");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "camt.056", &parsed)
        .expect("lifecycle applied");
    assert_eq!(outcome.referenced_message_id(), Some("CANCEL-ORIG-1"));
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.lifecycle_status_code(), Some("PDNG"));
    assert_eq!(outcome.lifecycle_reason_code(), Some("CUST"));
    assert_eq!(outcome.action(), "marked_cancellation_requested");
    let original = runtime
        .message_status("CANCEL-ORIG-1")
        .expect("original status");
    assert_eq!(original.status_label(), "Accepted");
    assert_eq!(original.pacs002_code(), "ACSP");
    assert_eq!(original.hold_reason_code(), Some("CUST"));
    assert!(
        original
            .change_reason_codes()
            .iter()
            .any(|code| code == "CANCELLATION_REQUESTED"),
        "expected cancellation reason to be recorded: {:?}",
        original.change_reason_codes()
    );
    assert_eq!(
        runtime
            .message_status(&lifecycle_id)
            .expect("lifecycle status")
            .status_label(),
        "Accepted"
    );
}
#[test]
fn lifecycle_pacs004_ignores_non_payment_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "orig-return-securities", "sese.023");
    runtime.mark_accepted("orig-return-securities", "tx-return-securities");
    let parsed = parse_message(
        "pacs.004",
        b"MsgId=return-securities\nCreDtTm=2025-01-01T00:00:00Z\nOrgnlGrpInf/OrgnlMsgId=orig-return-securities\nTxInf[0]/OrgnlInstrId=instr-1\nTxInf[0]/RtrdInstdAmt=10.00\nTxInf[0]/RtrdInstdAmtCcy=USD\nTxInf[0]/RtrdRsn/Cd=AC01",
    )
    .expect("pacs.004 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("pacs.004", &parsed).expect("lifecycle id");
    record_lifecycle(&runtime, &lifecycle_id, "pacs.004");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "pacs.004", &parsed)
        .expect("lifecycle applied");
    assert_eq!(
        outcome.referenced_message_id(),
        Some("orig-return-securities")
    );
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.action(), "ignored_message_family_mismatch");
    let original = runtime
        .message_status("orig-return-securities")
        .expect("original status");
    assert_eq!(original.status_label(), "Accepted");
    assert_eq!(original.pacs002_code(), "ACSP");
    assert_eq!(original.rejection_reason_code(), None);
}
#[test]
fn lifecycle_pacs004_rejects_conflicting_original_references() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    for original_id in ["orig-return-a", "orig-return-b"] {
        record_original(&runtime, original_id, "pacs.008");
        runtime.mark_accepted(original_id, &format!("tx-{original_id}"));
    }
    let parsed = parse_message(
        "pacs.004",
        b"MsgId=return-conflict\nCreDtTm=2025-01-01T00:00:00Z\nOrgnlGrpInf/OrgnlMsgId=orig-return-a\nTxInf[0]/OrgnlGrpInf/OrgnlMsgId=orig-return-b\nTxInf[0]/OrgnlInstrId=instr-1\nTxInf[0]/RtrdInstdAmt=10.00\nTxInf[0]/RtrdInstdAmtCcy=USD\nTxInf[0]/RtrdRsn/Cd=AC01",
    )
    .expect("conflicting pacs.004 parsed");
    let err = Iso20022BridgeRuntime::lifecycle_message_id("pacs.004", &parsed)
        .expect_err("conflicting pacs.004 references must reject lifecycle id derivation");
    assert!(matches!(err, MsgError::ValidationFailed));
    let err = runtime
        .apply_inbound_lifecycle_message("return-conflict", "pacs.004", &parsed)
        .expect_err("conflicting pacs.004 references must not apply to either original");
    assert!(matches!(err, MsgError::ValidationFailed));
    for original_id in ["orig-return-a", "orig-return-b"] {
        let status = runtime
            .message_status(original_id)
            .expect("candidate original remains recorded");
        assert_eq!(status.status_label(), "Accepted");
        assert_eq!(status.pacs002_code(), "ACSP");
        assert_eq!(status.rejection_reason_code(), None);
    }
}
#[test]
fn lifecycle_camt056_rejects_unknown_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let parsed = parse_message(
        "camt.056",
        b"Assgnmt/Id=cancel-1\nAssgnmt/CreDtTm=2025-01-01T00:00:00Z\nUndrlyg/TxInf/OrgnlGrpInf/OrgnlMsgId=missing-original\nUndrlyg/TxInf/CxlRsnInf/Rsn/Cd=CUST",
    )
    .expect("camt.056 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("camt.056", &parsed).expect("lifecycle id");
    record_lifecycle(&runtime, &lifecycle_id, "camt.056");
    let error = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "camt.056", &parsed)
        .expect_err("an unknown cancellation original must fail closed");
    assert!(matches!(error, MsgError::ValidationFailed));
    assert!(runtime.message_status("missing-original").is_none());
    assert_eq!(
        runtime
            .message_status("cancel-1")
            .expect("admitted lifecycle identity remains reserved")
            .status_label(),
        "Pending"
    );
}
#[test]
fn lifecycle_camt056_ignores_non_payment_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "orig-cancel-securities", "sese.023");
    runtime.mark_accepted("orig-cancel-securities", "tx-cancel-securities");
    let parsed = parse_message(
        "camt.056",
        b"Assgnmt/Id=cancel-securities\nAssgnmt/CreDtTm=2025-01-01T00:00:00Z\nUndrlyg/TxInf/OrgnlGrpInf/OrgnlMsgId=orig-cancel-securities\nUndrlyg/TxInf/CxlRsnInf/Rsn/Cd=CUST",
    )
    .expect("camt.056 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("camt.056", &parsed).expect("lifecycle id");
    record_lifecycle(&runtime, &lifecycle_id, "camt.056");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "camt.056", &parsed)
        .expect("lifecycle applied");
    assert_eq!(
        outcome.referenced_message_id(),
        Some("orig-cancel-securities")
    );
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.action(), "ignored_message_family_mismatch");
    let original = runtime
        .message_status("orig-cancel-securities")
        .expect("original status");
    assert_eq!(original.pacs002_code(), "ACSP");
    assert_eq!(original.hold_reason_code(), None);
    assert!(original.change_reason_codes().is_empty());
}
#[test]
fn lifecycle_camt056_rejects_conflicting_original_references() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    for original_id in ["orig-cancel-a", "orig-cancel-b"] {
        record_original(&runtime, original_id, "pacs.008");
        runtime.mark_accepted(original_id, &format!("tx-{original_id}"));
    }
    let parsed = parse_message(
        "camt.056",
        b"Assgnmt/Id=cancel-conflict\nAssgnmt/CreDtTm=2025-01-01T00:00:00Z\nUndrlyg/TxInf/OrgnlGrpInf/OrgnlMsgId=orig-cancel-a\nUndrlyg/TxInf[1]/OrgnlGrpInf/OrgnlMsgId=orig-cancel-b\nUndrlyg/TxInf/CxlRsnInf/Rsn/Cd=CUST",
    )
    .expect("conflicting camt.056 parsed");
    let err = Iso20022BridgeRuntime::lifecycle_message_id("camt.056", &parsed)
        .expect_err("conflicting camt.056 references must reject lifecycle id derivation");
    assert!(matches!(err, MsgError::ValidationFailed));
    let err = runtime
        .apply_inbound_lifecycle_message("cancel-conflict", "camt.056", &parsed)
        .expect_err("conflicting camt.056 references must not apply to either original");
    assert!(matches!(err, MsgError::ValidationFailed));
    for original_id in ["orig-cancel-a", "orig-cancel-b"] {
        let status = runtime
            .message_status(original_id)
            .expect("candidate original remains recorded");
        assert_eq!(status.status_label(), "Accepted");
        assert_eq!(status.pacs002_code(), "ACSP");
        assert_eq!(status.hold_reason_code(), None);
        assert!(status.change_reason_codes().is_empty());
    }
}
#[test]
fn lifecycle_sese024_marks_prefixed_settlement_instruction_pending() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "sese.023:settle-status", "sese.023");
    assert!(runtime.mark_queued("sese.023:settle-status"));
    let parsed = parse_message(
        "sese.024",
        b"TxId=settle-status\nSttlmDt=2025-01-02\nSttlmSts=PEND\nRsnCd=NORE\nAddtlInf=awaiting matching",
    )
    .expect("sese.024 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("sese.024", &parsed).expect("lifecycle id");
    assert_eq!(lifecycle_id, "sese.024:settle-status");
    record_lifecycle(&runtime, &lifecycle_id, "sese.024");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "sese.024", &parsed)
        .expect("lifecycle applied");
    assert_eq!(
        outcome.referenced_message_id(),
        Some("sese.023:settle-status")
    );
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.lifecycle_status_code(), Some("PEND"));
    assert_eq!(outcome.lifecycle_reason_code(), Some("NORE"));
    assert_eq!(outcome.action(), "marked_pending");
    let original = runtime
        .message_status("sese.023:settle-status")
        .expect("settlement instruction status");
    assert_eq!(original.status_label(), "Pending");
    assert_eq!(original.pacs002_code(), "PDNG");
    assert_eq!(original.hold_reason_code(), Some("NORE"));
    let lifecycle = runtime
        .message_status(&lifecycle_id)
        .expect("lifecycle status");
    assert_eq!(lifecycle.status_label(), "Accepted");
    assert_eq!(
        lifecycle.detail(),
        Some("recorded inbound ISO 20022 sese.024 lifecycle message")
    );
}
#[test]
fn lifecycle_sese024_rejects_unknown_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    let parsed = parse_message(
        "sese.024",
        b"TxId=missing-status\nSttlmSts=PART\nRsnCd=NARR",
    )
    .expect("sese.024 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("sese.024", &parsed).expect("lifecycle id");
    assert_eq!(lifecycle_id, "sese.024:missing-status");
    record_lifecycle(&runtime, &lifecycle_id, "sese.024");
    let error = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "sese.024", &parsed)
        .expect_err("an unknown settlement original must fail closed");
    assert!(matches!(error, MsgError::ValidationFailed));
    assert!(runtime.message_status("sese.023:missing-status").is_none());
    assert_eq!(
        runtime
            .message_status(&lifecycle_id)
            .expect("admitted lifecycle identity remains reserved")
            .status_label(),
        "Pending"
    );
}
#[test]
fn lifecycle_sese024_ignores_non_settlement_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "sese.023:settle-status-wrong-family", "pacs.008");
    runtime.mark_accepted("sese.023:settle-status-wrong-family", "tx-wrong-family");
    let parsed = parse_message(
        "sese.024",
        b"TxId=settle-status-wrong-family\nSttlmSts=PEND\nRsnCd=NORE",
    )
    .expect("sese.024 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("sese.024", &parsed).expect("lifecycle id");
    record_lifecycle(&runtime, &lifecycle_id, "sese.024");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "sese.024", &parsed)
        .expect("lifecycle applied");
    assert_eq!(
        outcome.referenced_message_id(),
        Some("sese.023:settle-status-wrong-family")
    );
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.action(), "ignored_message_family_mismatch");
    let original = runtime
        .message_status("sese.023:settle-status-wrong-family")
        .expect("original status");
    assert_eq!(original.status_label(), "Accepted");
    assert_eq!(original.pacs002_code(), "ACSP");
    assert_eq!(original.hold_reason_code(), None);
}
#[test]
fn lifecycle_sese024_rejects_conflicting_settlement_references() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    for original_id in ["sese.023:settle-status-a", "sese.023:settle-status-b"] {
        record_original(&runtime, original_id, "sese.023");
    }
    let parsed = parse_message(
        "sese.024",
        b"TxId=settle-status-a\nSttlmTx/TxId=settle-status-b\nSttlmSts=PEND\nRsnCd=NORE",
    )
    .expect("conflicting sese.024 parsed");
    let err = Iso20022BridgeRuntime::lifecycle_message_id("sese.024", &parsed)
        .expect_err("conflicting sese.024 references must reject lifecycle id derivation");
    assert!(matches!(err, MsgError::ValidationFailed));
    let err = runtime
        .apply_inbound_lifecycle_message("sese.024:settle-status-a", "sese.024", &parsed)
        .expect_err("conflicting sese.024 references must not apply to either original");
    assert!(matches!(err, MsgError::ValidationFailed));
    for original_id in ["sese.023:settle-status-a", "sese.023:settle-status-b"] {
        let status = runtime
            .message_status(original_id)
            .expect("candidate settlement remains recorded");
        assert_eq!(status.pacs002_code(), "ACTC");
        assert_eq!(status.hold_reason_code(), None);
    }
}
#[test]
fn lifecycle_sese025_confirms_prefixed_settlement_instruction() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "sese.023:settle-1", "sese.023");
    assert!(runtime.mark_queued("sese.023:settle-1"));
    let parsed = parse_message(
        "sese.025",
        b"TxId=settle-1\nSttlmDt=2025-01-02\nSttlmTpAndAddtlParams/SctiesMvmntTp=DELI\nSttlmTpAndAddtlParams/Pmt=APMT\nConfSts=ACCP\nSttlmQty=100\nSttlmAmt=25.00\nSttlmCcy=USD\nPlan/ExecutionOrder=DELIVERY_THEN_PAYMENT\nPlan/Atomicity=ALL_OR_NOTHING",
    )
    .expect("sese.025 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("sese.025", &parsed).expect("lifecycle id");
    assert_eq!(lifecycle_id, "sese.025:settle-1");
    record_lifecycle(&runtime, &lifecycle_id, "sese.025");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "sese.025", &parsed)
        .expect("lifecycle applied");
    assert_eq!(outcome.referenced_message_id(), Some("sese.023:settle-1"));
    assert_eq!(outcome.action(), "marked_settled");
    assert_eq!(
        runtime
            .message_status("sese.023:settle-1")
            .expect("settlement instruction status")
            .pacs002_code(),
        "ACSC"
    );
}
#[test]
fn lifecycle_sese025_ignores_non_settlement_original() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    record_original(&runtime, "sese.023:settle-wrong-family", "pacs.008");
    runtime.mark_accepted("sese.023:settle-wrong-family", "tx-wrong-family");
    let parsed = parse_message(
        "sese.025",
        b"TxId=settle-wrong-family\nSttlmDt=2025-01-02\nSttlmTpAndAddtlParams/SctiesMvmntTp=DELI\nSttlmTpAndAddtlParams/Pmt=APMT\nConfSts=ACCP\nSttlmQty=100\nSttlmAmt=25.00\nSttlmCcy=USD\nPlan/ExecutionOrder=DELIVERY_THEN_PAYMENT\nPlan/Atomicity=ALL_OR_NOTHING",
    )
    .expect("sese.025 parsed");
    let lifecycle_id =
        Iso20022BridgeRuntime::lifecycle_message_id("sese.025", &parsed).expect("lifecycle id");
    record_lifecycle(&runtime, &lifecycle_id, "sese.025");
    let outcome = runtime
        .apply_inbound_lifecycle_message(&lifecycle_id, "sese.025", &parsed)
        .expect("lifecycle applied");
    assert_eq!(
        outcome.referenced_message_id(),
        Some("sese.023:settle-wrong-family")
    );
    assert!(outcome.referenced_message_known());
    assert_eq!(outcome.action(), "ignored_message_family_mismatch");
    assert_eq!(
        runtime
            .message_status("sese.023:settle-wrong-family")
            .expect("original status")
            .pacs002_code(),
        "ACSP"
    );
}
#[test]
fn lifecycle_sese025_rejects_conflicting_settlement_references() {
    let runtime = Iso20022BridgeRuntime::from_config(&sample_config())
        .expect("cfg")
        .expect("enabled");
    for original_id in ["sese.023:settle-a", "sese.023:settle-b"] {
        record_original(&runtime, original_id, "sese.023");
    }
    let parsed = parse_message(
        "sese.025",
        b"TxId=settle-a\nSttlmTx/TxId=settle-b\nSttlmDt=2025-01-02\nSttlmTpAndAddtlParams/SctiesMvmntTp=DELI\nSttlmTpAndAddtlParams/Pmt=APMT\nConfSts=ACCP\nSttlmQty=100\nSttlmAmt=25.00\nSttlmCcy=USD\nPlan/ExecutionOrder=DELIVERY_THEN_PAYMENT\nPlan/Atomicity=ALL_OR_NOTHING",
    )
    .expect("conflicting sese.025 parsed");
    let err = Iso20022BridgeRuntime::lifecycle_message_id("sese.025", &parsed)
        .expect_err("conflicting sese.025 references must reject lifecycle id derivation");
    assert!(matches!(err, MsgError::ValidationFailed));
    let err = runtime
        .apply_inbound_lifecycle_message("sese.025:settle-a", "sese.025", &parsed)
        .expect_err("conflicting sese.025 references must not apply to either original");
    assert!(matches!(err, MsgError::ValidationFailed));
    for original_id in ["sese.023:settle-a", "sese.023:settle-b"] {
        assert_eq!(
            runtime
                .message_status(original_id)
                .expect("candidate settlement remains recorded")
                .pacs002_code(),
            "ACTC"
        );
    }
}
