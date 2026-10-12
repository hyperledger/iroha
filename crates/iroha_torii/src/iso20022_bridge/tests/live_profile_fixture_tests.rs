//! Cross-rail MDR/XSD and checked-in securities lifecycle fixture tests.
use super::*;
#[test]
fn official_mdr_xsd_fixtures_cover_live_rail_profiles() {
    let (config, _reference_files) = sample_config_with_live_reference_data();
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let cases = vec![
        (
            "swift-cbpr-plus",
            "pacs.008",
            "pacs.008.001.08",
            "swift.cbprplus.02",
            OFFICIAL_XSD_PACS008_001_08,
            "FIToFICstmrCdtTrf",
            live_pacs008_xml(
                "SWIFT-MDR-XSD-1",
                "pacs.008.001.08",
                "swift.cbprplus.02",
                "USD",
                "10.00",
                "123e4567-e89b-12d3-a456-426614174400",
            ),
        ),
        (
            "swift-cbpr-plus",
            "pacs.002",
            "pacs.002.001.10",
            "swift.cbprplus.02",
            OFFICIAL_XSD_PACS002_001_10,
            "FIToFIPmtStsRpt",
            live_pacs002_xml(
                "SWIFT-PACS002-MDR-XSD-1",
                "pacs.002.001.10",
                "swift.cbprplus.02",
            ),
        ),
        (
            "swift-cbpr-plus",
            "pacs.004",
            "pacs.004.001.09",
            "swift.cbprplus.02",
            OFFICIAL_XSD_PACS004_001_09,
            "PmtRtr",
            live_pacs004_xml(
                "SWIFT-PACS004-00109-MDR-XSD-1",
                "pacs.004.001.09",
                "swift.cbprplus.02",
            ),
        ),
        (
            "swift-cbpr-plus",
            "pacs.004",
            "pacs.004.001.10",
            "swift.cbprplus.02",
            OFFICIAL_XSD_PACS004_001_10,
            "PmtRtr",
            live_pacs004_xml(
                "SWIFT-PACS004-MDR-XSD-1",
                "pacs.004.001.10",
                "swift.cbprplus.02",
            ),
        ),
        (
            "swift-cbpr-plus",
            "camt.056",
            "camt.056.001.08",
            "swift.cbprplus.02",
            OFFICIAL_XSD_CAMT056_001_08,
            "FIToFIPmtCxlReq",
            live_camt056_xml(
                "SWIFT-CAMT056-MDR-XSD-1",
                "camt.056.001.08",
                "swift.cbprplus.02",
            ),
        ),
        (
            "swift-cbpr-plus",
            "camt.056",
            "camt.056.001.09",
            "swift.cbprplus.02",
            OFFICIAL_XSD_CAMT056_001_09,
            "FIToFIPmtCxlReq",
            live_camt056_xml(
                "SWIFT-CAMT056-00109-MDR-XSD-1",
                "camt.056.001.09",
                "swift.cbprplus.02",
            ),
        ),
        (
            "fedwire-funds",
            "pacs.008",
            "pacs.008.001.08",
            "fedwire.funds.01",
            OFFICIAL_XSD_PACS008_001_08,
            "FIToFICstmrCdtTrf",
            live_pacs008_xml(
                "FEDWIRE-MDR-XSD-1",
                "pacs.008.001.08",
                "fedwire.funds.01",
                "USD",
                "10.00",
                "123e4567-e89b-12d3-a456-426614174401",
            ),
        ),
        (
            "fedwire-funds",
            "pacs.002",
            "pacs.002.001.10",
            "fedwire.funds.01",
            OFFICIAL_XSD_PACS002_001_10,
            "FIToFIPmtStsRpt",
            live_pacs002_xml(
                "FEDWIRE-PACS002-MDR-XSD-1",
                "pacs.002.001.10",
                "fedwire.funds.01",
            ),
        ),
        (
            "fedwire-funds",
            "pacs.004",
            "pacs.004.001.09",
            "fedwire.funds.01",
            OFFICIAL_XSD_PACS004_001_09,
            "PmtRtr",
            live_pacs004_xml(
                "FEDWIRE-PACS004-00109-MDR-XSD-1",
                "pacs.004.001.09",
                "fedwire.funds.01",
            ),
        ),
        (
            "fedwire-funds",
            "camt.056",
            "camt.056.001.08",
            "fedwire.funds.01",
            OFFICIAL_XSD_CAMT056_001_08,
            "FIToFIPmtCxlReq",
            live_camt056_xml(
                "FEDWIRE-CAMT056-MDR-XSD-1",
                "camt.056.001.08",
                "fedwire.funds.01",
            ),
        ),
        (
            "sepa-sct-inst",
            "pacs.008",
            "pacs.008.001.08",
            "sepa.sct.inst",
            OFFICIAL_XSD_PACS008_001_08,
            "FIToFICstmrCdtTrf",
            live_pacs008_xml(
                "SEPA-MDR-XSD-1",
                "pacs.008.001.08",
                "sepa.sct.inst",
                "EUR",
                "10.00",
                "123e4567-e89b-12d3-a456-426614174402",
            ),
        ),
        (
            "sepa-sct-inst",
            "pacs.002",
            "pacs.002.001.10",
            "sepa.sct.inst",
            OFFICIAL_XSD_PACS002_001_10,
            "FIToFIPmtStsRpt",
            live_pacs002_xml("SEPA-PACS002-MDR-XSD-1", "pacs.002.001.10", "sepa.sct.inst"),
        ),
        (
            "sepa-sct-inst",
            "pacs.004",
            "pacs.004.001.09",
            "sepa.sct.inst",
            OFFICIAL_XSD_PACS004_001_09,
            "PmtRtr",
            live_pacs004_xml(
                "SEPA-PACS004-00109-MDR-XSD-1",
                "pacs.004.001.09",
                "sepa.sct.inst",
            ),
        ),
        (
            "sepa-sct-inst",
            "pacs.004",
            "pacs.004.001.10",
            "sepa.sct.inst",
            OFFICIAL_XSD_PACS004_001_10,
            "PmtRtr",
            live_pacs004_xml("SEPA-PACS004-MDR-XSD-1", "pacs.004.001.10", "sepa.sct.inst"),
        ),
        (
            "sepa-sct-inst",
            "camt.056",
            "camt.056.001.08",
            "sepa.sct.inst",
            OFFICIAL_XSD_CAMT056_001_08,
            "FIToFIPmtCxlReq",
            live_camt056_xml("SEPA-CAMT056-MDR-XSD-1", "camt.056.001.08", "sepa.sct.inst"),
        ),
        (
            "sepa-sct-inst",
            "camt.056",
            "camt.056.001.09",
            "sepa.sct.inst",
            OFFICIAL_XSD_CAMT056_001_09,
            "FIToFIPmtCxlReq",
            live_camt056_xml(
                "SEPA-CAMT056-00109-MDR-XSD-1",
                "camt.056.001.09",
                "sepa.sct.inst",
            ),
        ),
        (
            "securities-csd",
            "pacs.009",
            "pacs.009.001.08",
            "securities.csd.cash",
            OFFICIAL_XSD_PACS009_001_08,
            "FICdtTrf",
            live_pacs009_xml(
                "SECURITIES-MDR-XSD-1",
                "pacs.009.001.08",
                "securities.csd.cash",
            ),
        ),
        (
            "securities-csd",
            "pacs.002",
            "pacs.002.001.10",
            "securities.csd.cash",
            OFFICIAL_XSD_PACS002_001_10,
            "FIToFIPmtStsRpt",
            live_pacs002_xml(
                "SECURITIES-PACS002-MDR-XSD-1",
                "pacs.002.001.10",
                "securities.csd.cash",
            ),
        ),
        (
            "securities-csd",
            "pacs.004",
            "pacs.004.001.09",
            "securities.csd.cash",
            OFFICIAL_XSD_PACS004_001_09,
            "PmtRtr",
            live_pacs004_xml(
                "SECURITIES-PACS004-00109-MDR-XSD-1",
                "pacs.004.001.09",
                "securities.csd.cash",
            ),
        ),
        (
            "securities-csd",
            "pacs.004",
            "pacs.004.001.10",
            "securities.csd.cash",
            OFFICIAL_XSD_PACS004_001_10,
            "PmtRtr",
            live_pacs004_xml(
                "SECURITIES-PACS004-MDR-XSD-1",
                "pacs.004.001.10",
                "securities.csd.cash",
            ),
        ),
        (
            "securities-csd",
            "camt.056",
            "camt.056.001.08",
            "securities.csd.cash",
            OFFICIAL_XSD_CAMT056_001_08,
            "FIToFIPmtCxlReq",
            live_camt056_xml(
                "SECURITIES-CAMT056-MDR-XSD-1",
                "camt.056.001.08",
                "securities.csd.cash",
            ),
        ),
        (
            "securities-csd",
            "camt.056",
            "camt.056.001.09",
            "securities.csd.cash",
            OFFICIAL_XSD_CAMT056_001_09,
            "FIToFIPmtCxlReq",
            live_camt056_xml(
                "SECURITIES-CAMT056-00109-MDR-XSD-1",
                "camt.056.001.09",
                "securities.csd.cash",
            ),
        ),
    ];
    for (profile_id, message_type, msg_def_id, expected_service, xsd, expected_root, payload) in
        cases
    {
        let expected_namespace = format!("urn:iso:std:iso:20022:tech:xsd:{msg_def_id}");
        assert_eq!(xsd_schema_target_namespace(xsd), Some(expected_namespace));
        assert_eq!(
            xsd_document_payload_root(xsd).as_deref(),
            Some(expected_root)
        );
        let parsed = parse_message(message_type, payload.as_bytes())
            .unwrap_or_else(|err| panic!("{profile_id} MDR/XSD fixture must parse: {err:?}"));
        let profile = runtime
            .resolve_profile(Some(profile_id))
            .unwrap_or_else(|| panic!("{profile_id} profile"));
        let metadata = runtime
            .validate_profile_submission(profile, message_type, &parsed, payload.as_bytes())
            .unwrap_or_else(|err| panic!("{profile_id} MDR/XSD fixture must validate: {err:?}"));
        assert_eq!(metadata.profile_id(), Some(profile_id));
        assert_eq!(metadata.business_service(), Some(expected_service));
        assert_eq!(metadata.message_type(), Some(message_type));
    }
}
#[test]
fn official_mdr_xsd_fixture_rejects_document_root_drift() {
    let pacs009_root =
        xsd_document_payload_root(OFFICIAL_XSD_PACS009_001_08).expect("pacs.009 XSD root fixture");
    assert_eq!(pacs009_root, "FICdtTrf");
    let payload = live_pacs008_xml(
        "SWIFT-MDR-XSD-DRIFT",
        "pacs.008.001.08",
        "swift.cbprplus.02",
        "USD",
        "10.00",
        "123e4567-e89b-12d3-a456-426614174450",
    )
    .replace("FIToFICstmrCdtTrf", &pacs009_root);
    let err = parse_message("pacs.008", payload.as_bytes())
        .expect_err("pacs.008 must reject a pacs.009 XSD document root");
    assert!(matches!(err, MsgError::UnknownMessageType));
}
#[test]
fn checked_in_securities_fixtures_validate_and_link_through_torii_profile() {
    let (mut config, _reference_files) = sample_config_with_live_reference_data();
    config.profiles.push(live_securities_lifecycle_profile());
    let runtime = Iso20022BridgeRuntime::from_config(&config)
        .expect("cfg")
        .expect("enabled");
    let profile = runtime
        .resolve_profile(Some("securities-csd-lifecycle-fixtures"))
        .expect("securities lifecycle profile");
    let instruction_payload = data_pdu_with_app_header(
        "SEC-INSTR-BAH-1",
        "sese.023.001.11",
        "securities.csd.cash",
        SESE023_FIXTURE_XML,
    );
    let instruction =
        parse_message("sese.023", instruction_payload.as_bytes()).expect("sese.023 fixture");
    let instruction_metadata = runtime
        .validate_profile_submission(
            profile,
            "sese.023",
            &instruction,
            instruction_payload.as_bytes(),
        )
        .expect("BAH-wrapped sese.023 fixture validates through Torii profile");
    let instruction_id = Iso20022BridgeRuntime::lifecycle_message_id("sese.023", &instruction)
        .expect("sese.023 durable id");
    assert_eq!(instruction_id, "sese.023:DVP-FIXTURE-1");
    assert_eq!(
        instruction_metadata.business_message_id(),
        Some("SEC-INSTR-BAH-1")
    );
    assert!(runtime.check_and_record_inbound(&instruction_id, instruction_metadata));
    let instruction_outcome = runtime
        .apply_inbound_lifecycle_message(&instruction_id, "sese.023", &instruction)
        .expect("record BAH-wrapped sese.023 fixture");
    assert_eq!(instruction_outcome.action(), "recorded");
    let instruction_status = runtime
        .message_status(&instruction_id)
        .expect("instruction status");
    assert_eq!(instruction_status.status_label(), "Accepted");
    assert_eq!(instruction_status.settlement_quantity(), Some("500"));
    assert_eq!(
        instruction_status.security_instrument_id(),
        Some("US0378331005")
    );
    assert_eq!(
        instruction_status.plan_execution_order(),
        Some("DELIVERY_THEN_PAYMENT")
    );
    let status_advice_payload = data_pdu_with_app_header(
        "SEC-STADV-BAH-1",
        "sese.024.001.10",
        "securities.csd.cash",
        SESE024_FIXTURE_XML,
    );
    let status_advice =
        parse_message("sese.024", status_advice_payload.as_bytes()).expect("sese.024 fixture");
    let status_advice_metadata = runtime
        .validate_profile_submission(
            profile,
            "sese.024",
            &status_advice,
            status_advice_payload.as_bytes(),
        )
        .expect("BAH-wrapped sese.024 fixture validates through Torii profile");
    let status_advice_id = Iso20022BridgeRuntime::lifecycle_message_id("sese.024", &status_advice)
        .expect("sese.024 durable id");
    assert_eq!(status_advice_id, "sese.024:DVP-FIXTURE-1");
    assert_eq!(
        status_advice_metadata.business_message_id(),
        Some("SEC-STADV-BAH-1")
    );
    assert!(runtime.check_and_record_inbound(&status_advice_id, status_advice_metadata));
    let status_advice_outcome = runtime
        .apply_inbound_lifecycle_message(&status_advice_id, "sese.024", &status_advice)
        .expect("apply BAH-wrapped sese.024 fixture");
    assert_eq!(
        status_advice_outcome.referenced_message_id(),
        Some("sese.023:DVP-FIXTURE-1")
    );
    assert_eq!(status_advice_outcome.lifecycle_status_code(), Some("PEND"));
    assert_eq!(status_advice_outcome.lifecycle_reason_code(), Some("NORE"));
    assert_eq!(status_advice_outcome.action(), "marked_pending");
    let pending_instruction = runtime
        .message_status(&instruction_id)
        .expect("pending instruction status");
    assert_eq!(pending_instruction.status_label(), "Pending");
    assert_eq!(pending_instruction.pacs002_code(), "PDNG");
    assert_eq!(pending_instruction.hold_reason_code(), Some("NORE"));
    let status_advice_record = runtime
        .message_status(&status_advice_id)
        .expect("status-advice lifecycle status");
    assert_eq!(status_advice_record.status_label(), "Accepted");
    assert_eq!(
        status_advice_record.detail(),
        Some("recorded inbound ISO 20022 sese.024 lifecycle message")
    );
    let confirmation_payload = data_pdu_with_app_header(
        "SEC-CONF-BAH-1",
        "sese.025.001.11",
        "securities.csd.cash",
        SESE025_FIXTURE_XML,
    );
    let confirmation =
        parse_message("sese.025", confirmation_payload.as_bytes()).expect("sese.025 fixture");
    let confirmation_metadata = runtime
        .validate_profile_submission(
            profile,
            "sese.025",
            &confirmation,
            confirmation_payload.as_bytes(),
        )
        .expect("BAH-wrapped sese.025 fixture validates through Torii profile");
    let confirmation_id = Iso20022BridgeRuntime::lifecycle_message_id("sese.025", &confirmation)
        .expect("sese.025 durable id");
    assert_eq!(confirmation_id, "sese.025:PVP-FIXTURE-1");
    assert_eq!(
        confirmation_metadata.business_message_id(),
        Some("SEC-CONF-BAH-1")
    );
    let confirmed_instruction_document =
        SESE023_FIXTURE_XML.replace("DVP-FIXTURE-1", "PVP-FIXTURE-1");
    let confirmed_instruction_payload = data_pdu_with_app_header(
        "SEC-INSTR-PVP-BAH-1",
        "sese.023.001.11",
        "securities.csd.cash",
        &confirmed_instruction_document,
    );
    let confirmed_instruction = parse_message("sese.023", confirmed_instruction_payload.as_bytes())
        .expect("confirmed sese.023 fixture");
    let confirmed_instruction_metadata = runtime
        .validate_profile_submission(
            profile,
            "sese.023",
            &confirmed_instruction,
            confirmed_instruction_payload.as_bytes(),
        )
        .expect("confirmed sese.023 fixture validates through Torii profile");
    let confirmed_instruction_id =
        Iso20022BridgeRuntime::lifecycle_message_id("sese.023", &confirmed_instruction)
            .expect("confirmed sese.023 durable id");
    assert_eq!(confirmed_instruction_id, "sese.023:PVP-FIXTURE-1");
    assert!(
        runtime
            .check_and_record_inbound(&confirmed_instruction_id, confirmed_instruction_metadata,)
    );
    assert!(runtime.mark_queued(&confirmed_instruction_id));
    assert!(runtime.check_and_record_inbound(&confirmation_id, confirmation_metadata));
    let confirmation_outcome = runtime
        .apply_inbound_lifecycle_message(&confirmation_id, "sese.025", &confirmation)
        .expect("apply BAH-wrapped sese.025 fixture");
    assert_eq!(
        confirmation_outcome.referenced_message_id(),
        Some("sese.023:PVP-FIXTURE-1")
    );
    assert_eq!(confirmation_outcome.action(), "marked_settled");
    let settled = runtime
        .message_status("sese.023:PVP-FIXTURE-1")
        .expect("referenced settlement status");
    assert_eq!(settled.pacs002_code(), "ACSC");
    let confirmation_status = runtime
        .message_status(&confirmation_id)
        .expect("confirmation status");
    assert_eq!(confirmation_status.settlement_quantity(), Some("250000"));
    assert_eq!(confirmation_status.plan_atomicity(), Some("ALL_OR_NOTHING"));
}
