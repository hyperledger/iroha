//! ISO 20022 schema, parser, provenance and message-stack regression tests.

use super::{
    norito_schemas::{Colr012, Linkage, Sese023, Sese025},
    *,
};
use norito::codec::{Decode, Encode};
// Helper to reset the thread-local between tests.
fn reset() {
    MESSAGE_STACK.with(|m| m.borrow_mut().clear());
}
fn populate_pacs008_minimal() {
    msg_set("MsgId", b"1");
    msg_set("IntrBkSttlmCcy", b"USD");
    msg_set("IntrBkSttlmAmt", b"100");
    msg_set("IntrBkSttlmDt", b"2024-01-01");
    msg_set("DbtrAcct", b"GB82WEST12345698765432");
    msg_set("CdtrAcct", b"GB33BUKB20201555555555");
    msg_set("DbtrAgt", b"DEUTDEFF");
    msg_set("CdtrAgt", b"DEUTDEFF");
}
fn populate_camt053_minimal() {
    msg_set("Stmt/Id", b"1");
    msg_set("Stmt/Acct/Id", b"GB82WEST12345698765432");
    msg_set("Stmt/Acct/Ccy", b"USD");
    msg_set("Stmt/Bal[0]/Amt", b"100");
    msg_set("Stmt/Bal[0]/Ccy", b"USD");
    msg_set("Stmt/Bal[0]/Cd", b"CRDT");
}
fn populate_camt052_minimal() {
    msg_set("Rpt/Id", b"RPT1");
    msg_set("Rpt/CreDtTm", b"2024-01-01T00:00:00Z");
    msg_set("Rpt/Acct/Id", b"GB82WEST12345698765432");
    msg_set("Rpt/Acct/Ccy", b"USD");
    msg_add("Rpt/Ntry");
    msg_set("Rpt/Ntry[0]/Amt", b"100.00");
    msg_set("Rpt/Ntry[0]/CdtDbtInd", b"CRDT");
    msg_set("Rpt/Ntry[0]/BookgDt", b"2024-01-01");
}
fn populate_pain001_minimal() {
    msg_set("GrpHdr/MsgId", b"MSG-1");
    msg_set("GrpHdr/CreDtTm", b"2024-01-01T10:00:00Z");
    msg_set("GrpHdr/NbOfTxs", b"1");
    msg_set("GrpHdr/InitgPty/Nm", b"Initiator");
    msg_add("PmtInf");
    msg_set("PmtInf[0]/PmtInfId", b"PMT1");
    msg_set("PmtInf[0]/ReqdExctnDt", b"2024-01-02");
    msg_set("PmtInf[0]/DbtrAcct/Id", b"GB82WEST12345698765432");
    msg_add("PmtInf[0]/CdtTrfTxInf");
    msg_set("PmtInf[0]/CdtTrfTxInf[0]/Amt", b"100");
    msg_set("PmtInf[0]/CdtTrfTxInf[0]/Ccy", b"USD");
    msg_set(
        "PmtInf[0]/CdtTrfTxInf[0]/CdtrAcct/Id",
        b"GB33BUKB20201555555555",
    );
    msg_set("PmtInf[0]/CdtTrfTxInf[0]/CdtrAgt", b"DEUTDEFF");
    msg_set("PmtInf[0]/CdtTrfTxInf[0]/EndToEndId", b"E2E1");
}
fn populate_pacs009_minimal() {
    msg_set("BizMsgIdr", b"BMSG1");
    msg_set("MsgDefIdr", b"pacs.009.001.10");
    msg_set("CreDtTm", b"2024-01-01T12:00:00Z");
    msg_set("IntrBkSttlmAmt", b"5000");
    msg_set("IntrBkSttlmCcy", b"USD");
    msg_set("IntrBkSttlmDt", b"2024-01-03");
    msg_set("InstgAgt", b"DEUTDEFF");
    msg_set("InstdAgt", b"MARKDEFF");
    msg_set("DbtrAcct", b"GB82WEST12345698765432");
    msg_set("CdtrAcct", b"GB33BUKB20201555555555");
}
fn populate_head001_minimal() {
    msg_set("AppHdr/BizMsgIdr", b"HDR-123");
    msg_set("AppHdr/MsgDefIdr", b"pacs.008.001.08");
    msg_set("AppHdr/CreDt", b"2025-01-01T12:00:00Z");
    msg_set("AppHdr/Fr/FIId/FinInstnId/BICFI", b"DEUTDEFF");
    msg_set("AppHdr/To/FIId/FinInstnId/ClrSysMmbId/MmbId", b"123456");
}
fn populate_pacs004_minimal() {
    msg_set("MsgId", b"RTRN1");
    msg_set("CreDtTm", b"2024-01-05T10:00:00Z");
    msg_set("OrgnlGrpInf/OrgnlMsgId", b"ORIG1");
    msg_add("TxInf");
    msg_set("TxInf[0]/OrgnlInstrId", b"INST1");
    msg_set("TxInf[0]/RtrdInstdAmt", b"100.00");
    msg_set("TxInf[0]/RtrdInstdAmtCcy", b"USD");
}
fn populate_pacs028_minimal() {
    msg_set("MsgId", b"REQ1");
    msg_set("CreDtTm", b"2024-01-06T09:30:00Z");
    msg_set("OrgnlGrpInf/OrgnlMsgId", b"ORIG1");
}
fn populate_pacs029_minimal() {
    msg_set("MsgId", b"STAT1");
    msg_set("CreDtTm", b"2024-01-06T09:45:00Z");
    msg_set("OrgnlGrpInf/OrgnlMsgId", b"ORIG1");
    msg_add("TxInfAndSts");
    msg_set("TxInfAndSts[0]/TxSts", b"ACSP");
}
fn populate_pain002_minimal() {
    msg_set("GrpHdr/MsgId", b"PAINSTAT1");
    msg_set("GrpHdr/CreDtTm", b"2024-01-07T08:00:00Z");
    msg_set("OrgnlGrpInfAndSts/OrgnlMsgId", b"PAIN1");
    msg_set("OrgnlGrpInfAndSts/GrpSts", b"ACSP");
}
fn populate_pacs007_minimal() {
    msg_set("MsgId", b"CXL1");
    msg_set("CreDtTm", b"2024-01-02T09:30:00Z");
    msg_set("OrgnlGrpInf/OrgnlMsgId", b"ORIG1");
    msg_add("TxInf");
    msg_set("TxInf[0]/OrgnlInstrId", b"INST1");
    msg_set("TxInf[0]/OrgnlEndToEndId", b"E2E1");
    msg_set("TxInf[0]/OrgnlTxId", b"TX1");
    msg_set("TxInf[0]/CxlRsnInf/Rsn/Cd", b"RR01");
}
fn populate_camt056_minimal() {
    msg_set("Assgnmt/Id", b"CXL2");
    msg_set("Assgnmt/CreDtTm", b"2024-01-03T11:15:00Z");
    msg_set("Undrlyg/TxInf/OrgnlGrpInf/OrgnlMsgId", b"ORIG2");
    msg_set("Undrlyg/TxInf/OrgnlInstrId", b"INST2");
    msg_set("Undrlyg/TxInf/OrgnlEndToEndId", b"E2E2");
    msg_set("Undrlyg/TxInf/OrgnlTxId", b"TX2");
    msg_set("Undrlyg/TxInf/CxlRsnInf/Rsn/Cd", b"RC01");
}
fn populate_sese023_minimal() {
    msg_set("TxId", b"DVP-SETTLEMENT-1");
    msg_set("SttlmDt", b"2024-01-02");
    msg_set("SttlmTpAndAddtlParams/SctiesMvmntTp", b"DELI");
    msg_set("SttlmTpAndAddtlParams/Pmt", b"APMT");
    msg_set("SctiesLeg/FinInstrmId", b"US0378331005");
    msg_set("SctiesLeg/Qty", b"1000");
    msg_set("CashLeg/Amt", b"1050000");
    msg_set("CashLeg/Ccy", b"USD");
    msg_set("DlvrgSttlmPties/Pty/Bic", b"DEUTDEFF");
    msg_set("DlvrgSttlmPties/Acct", b"DLVRY-ACC");
    msg_set("RcvgSttlmPties/Pty/Bic", b"MARKDEFF");
    msg_set("RcvgSttlmPties/Acct", b"RCVG-ACC");
    msg_set("Plan/ExecutionOrder", b"DELIVERY_THEN_PAYMENT");
    msg_set("Plan/Atomicity", b"ALL_OR_NOTHING");
}
fn populate_sese025_minimal() {
    msg_set("TxId", b"DVP-SETTLEMENT-1");
    msg_set("SttlmDt", b"2024-01-02");
    msg_set("SttlmTpAndAddtlParams/SctiesMvmntTp", b"DELI");
    msg_set("SttlmTpAndAddtlParams/Pmt", b"APMT");
    msg_set("ConfSts", b"ACCP");
    msg_set("SttlmQty", b"1000");
    msg_set("SttlmAmt", b"1050000");
    msg_set("SttlmCcy", b"USD");
    msg_set("Plan/ExecutionOrder", b"DELIVERY_THEN_PAYMENT");
    msg_set("Plan/Atomicity", b"ALL_OR_NOTHING");
    msg_set("RsnCd", b"SETTLED");
}
fn populate_colr012_minimal() {
    msg_set("TxId", b"COLLATERAL-EXCHANGE-1");
    msg_set("OblgtnId", b"REPO-DAILY-1");
    msg_set("Substitution/OriginalAmt", b"1000000");
    msg_set("Substitution/OriginalCcy", b"USD");
    msg_set("Substitution/SubstituteAmt", b"1005000");
    msg_set("Substitution/SubstituteCcy", b"USD");
    msg_set("Substitution/EffectiveDt", b"2024-01-05");
    msg_set("Substitution/Type", b"FULL");
    msg_set("Substitution/ReasonCd", b"HAIRCUT");
}
const PACS002_FIXTURE: &str = include_str!(r"../../../fixtures/iso20022/pacs002_fixture.xml");
const PACS004_FIXTURE: &str = include_str!(r"../../../fixtures/iso20022/pacs004_fixture.xml");
const CAMT056_FIXTURE: &str = include_str!(r"../../../fixtures/iso20022/camt056_fixture.xml");
const CAMT056_001_09_FIXTURE: &str =
    include_str!(r"../../../fixtures/iso20022/camt056_001_09_fixture.xml");
const SESE023_FIXTURE: &str = include_str!(r"../../../fixtures/iso20022/sese023_fixture.xml");
const SESE024_FIXTURE: &str = include_str!(r"../../../fixtures/iso20022/sese024_fixture.xml");
const SESE025_FIXTURE: &str = include_str!(r"../../../fixtures/iso20022/sese025_fixture.xml");
const COLR007_FIXTURE: &str = include_str!(r"../../../fixtures/iso20022/colr007_fixture.xml");
const COLR012_FIXTURE: &str = include_str!(r"../../../fixtures/iso20022/colr012_fixture.xml");
fn expected_sese023_schema() -> Sese023 {
    Sese023 {
        tx_id: "DVP-FIXTURE-1".to_owned(),
        settlement_date: "2024-02-02".to_owned(),
        movement_type: "DELI".to_owned(),
        payment_type: "APMT".to_owned(),
        fin_instr_id: "US0378331005".to_owned(),
        quantity: "500".to_owned(),
        cash_amount: "1050000".to_owned(),
        cash_currency: "USD".to_owned(),
        delivering_party_bic: "DEUTDEFF".to_owned(),
        delivering_account: "DLVRY-ACC".to_owned(),
        receiving_party_bic: "MARKDEFF".to_owned(),
        receiving_account: "RCVG-ACC".to_owned(),
        execution_order: "DELIVERY_THEN_PAYMENT".to_owned(),
        atomicity: "ALL_OR_NOTHING".to_owned(),
        settlement_condition: Some("NOMC".to_owned()),
        partial_settlement_indicator: Some("NPAR".to_owned()),
        hold_indicator: Some(true),
        venue_mic: Some("XNAS".to_owned()),
        linkages: vec![
            Linkage {
                relation: "WITH".to_owned(),
                reference: "SUBST-PAIR-B".to_owned(),
            },
            Linkage {
                relation: "BEFO".to_owned(),
                reference: "PACS009-CLS".to_owned(),
            },
        ],
        securities_metadata: Some(r#"{"note":"delivery"}"#.to_owned()),
        cash_metadata: Some(r#"{"note":"cash"}"#.to_owned()),
    }
}
fn expected_sese025_schema() -> Sese025 {
    Sese025 {
        tx_id: "PVP-FIXTURE-1".to_owned(),
        settlement_date: "2024-03-01".to_owned(),
        movement_type: "RECE".to_owned(),
        payment_type: "APMT".to_owned(),
        confirmation_status: "ACCP".to_owned(),
        settlement_quantity: "250000".to_owned(),
        settlement_amount: "100000".to_owned(),
        settlement_currency: "USD".to_owned(),
        security_id: Some("US0378331005".to_owned()),
        security_quantity: Some("500".to_owned()),
        delivering_party_bic: Some("DEUTDEFF".to_owned()),
        delivering_account: Some("DLVRY-ACC".to_owned()),
        receiving_party_bic: Some("MARKDEFF".to_owned()),
        receiving_account: Some("RCVG-ACC".to_owned()),
        execution_order: "PAYMENT_THEN_DELIVERY".to_owned(),
        atomicity: "ALL_OR_NOTHING".to_owned(),
        hold_indicator: Some(false),
        partial_settlement_indicator: Some("NPAR".to_owned()),
        settlement_condition: Some("NOMC".to_owned()),
        venue_mic: None,
        reason_code: Some("MATCHED".to_owned()),
        additional_info: Some(r#"{"counter_ccy":"EUR"}"#.to_owned()),
    }
}
fn expected_colr012_schema() -> Colr012 {
    Colr012 {
        tx_id: "COLR-FIXTURE-1".to_owned(),
        obligation_id: "REPO-123".to_owned(),
        original_amount: "1000000".to_owned(),
        original_currency: "USD".to_owned(),
        substitute_amount: "1002000".to_owned(),
        substitute_currency: "USD".to_owned(),
        haircut: Some("50".to_owned()),
        effective_date: "2024-04-05".to_owned(),
        substitution_type: "PARTIAL".to_owned(),
        original_fin_instr_id: Some("US0378331005".to_owned()),
        substitute_fin_instr_id: Some("US5949181045".to_owned()),
        reason_code: Some("MARGIN".to_owned()),
    }
}
const GENERATED_MD: &str = include_str!(r"../../../generatediso20022.md");
const SAMPLE_PACS008_XML: &str = include_str!("assets/text_v1/pacs008_sample.xml");
const SAMPLE_PACS004_XML: &str = include_str!("assets/text_v1/pacs004_sample.xml");
const SAMPLE_PACS009_XML: &str = include_str!("assets/text_v1/pacs009_sample.xml");
const SAMPLE_PACS009_ENVELOPE_XML: &str = include_str!("assets/text_v1/pacs009_envelope.xml");
const SAMPLE_PACS002_STATUS_XML: &str = include_str!("assets/text_v1/pacs002_status.xml");
const SAMPLE_PACS002_AUTH_XML: &str = include_str!("assets/text_v1/pacs002_auth.xml");
const SAMPLE_CAMT052_XML: &str = include_str!("assets/text_v1/camt052_sample.xml");
const SAMPLE_CAMT056_XML: &str = include_str!("assets/text_v1/camt056_sample.xml");
fn assert_validated(message_type: &str, xml: &str) {
    reset();
    msg_parse(message_type, xml.as_bytes())
        .unwrap_or_else(|err| panic!("parse {message_type} sample: {err:?}"));
    let valid = msg_validate();
    let failure = take_validation_failure();
    assert!(valid, "validation failed: {failure:?}");
}
fn generated_sample(message_marker: &str) -> String {
    let needle = format!("<!-- {message_marker} -->");
    let all = GENERATED_MD;
    let marker_pos = all
        .find(&needle)
        .unwrap_or_else(|| panic!("marker not found: {message_marker}"));
    let before = &all[..marker_pos];
    let start_fence = before
        .rfind("```xml")
        .unwrap_or_else(|| panic!("xml fence missing for {message_marker}"));
    let after_fence = &all[start_fence + "```xml".len()..];
    let end = after_fence
        .find("```")
        .unwrap_or_else(|| panic!("closing fence missing for {message_marker}"));
    after_fence[..end].trim().to_owned()
}
#[test]
fn msg_create_and_validate() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    assert!(msg_validate());
}
#[test]
fn pacs008_requires_creditor_agent() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    msg_remove("CdtrAgt");
    assert!(!msg_validate());
}
#[test]
fn pacs008_requires_debtor_account() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    msg_remove("DbtrAcct");
    assert!(!msg_validate());
}
#[test]
fn msg_validate_rejects_non_numeric_amount() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    msg_set("IntrBkSttlmAmt", b"not-a-number");
    assert!(!msg_validate());
}
#[test]
fn msg_validate_rejects_invalid_iban() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    msg_set("DbtrAcct", b"GB82WEST12345698765433");
    assert!(!msg_validate());
}
#[test]
fn take_validation_error_reports_identifier_failure() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    msg_set("IntrBkSttlmCcy", b"ZZZ");
    assert!(!msg_validate());
    let err = take_validation_error().expect("validation error captured");
    match err {
        MsgError::InvalidIdentifier { field, kind } => {
            assert_eq!(field, "IntrBkSttlmCcy");
            assert_eq!(kind, IdentifierKind::Currency);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(take_validation_error().is_none(), "error should be drained");
}
#[test]
fn msg_validate_accepts_valid_iban() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    assert!(msg_validate());
}
#[test]
fn pacs008_validates_proxy_identifiers() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    msg_set("DbtrAcct/Prxy/Id", b"1233214568521");
    msg_set("DbtrAcct/Prxy/Tp/Cd", b"2100");
    msg_set("CdtrAcct/Prxy/Id", b"4210118604441");
    assert!(
        msg_validate(),
        "proxy identifiers should validate when populated alongside IBANs"
    );
    assert_eq!(
        msg_get("DbtrAcct/Prxy/Id").as_deref(),
        Some(&b"1233214568521"[..])
    );
}
#[test]
fn pacs008_rejects_empty_proxy_identifier() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    msg_set("DbtrAcct/Prxy/Id", b"");
    assert!(!msg_validate(), "empty proxy ids must fail validation");
    let failure = take_validation_failure().expect("validation failure captured");
    match failure {
        ValidationFailure::InvalidField { field, reason } => {
            assert_eq!(field, "DbtrAcct/Prxy/Id");
            assert!(matches!(reason, InvalidReason::Empty));
        }
        other => panic!("unexpected validation failure: {other:?}"),
    }
}
#[test]
fn head001_requires_core_fields() {
    reset();
    msg_create("head.001.001.03");
    populate_head001_minimal();
    assert!(msg_validate(), "baseline header should validate");
    msg_remove("AppHdr/CreDt");
    assert!(!msg_validate(), "missing CreDt must fail validation");
    let err = take_validation_error().expect("validation error captured");
    match err {
        MsgError::MissingField(field) => assert_eq!(field, "AppHdr/CreDt"),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn msg_validate_rejects_invalid_bic() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    msg_set("DbtrAgt", b"deutdeff");
    assert!(!msg_validate());
}
#[test]
fn msg_validate_accepts_valid_bic() {
    reset();
    msg_create("pacs.008");
    populate_pacs008_minimal();
    assert!(msg_validate());
}
#[test]
fn msg_validate_rejects_invalid_isin() {
    reset();
    msg_create("sese.023");
    populate_sese023_minimal();
    msg_set("SctiesLeg/FinInstrmId", b"INVALID123456");
    assert!(!msg_validate());
}
#[test]
fn msg_validate_accepts_cusip_instrument() {
    reset();
    msg_create("sese.023");
    populate_sese023_minimal();
    msg_set("SctiesLeg/FinInstrmId", b"037833100");
    assert!(msg_validate());
}
#[test]
fn parse_message_reports_invalid_instrument() {
    reset();
    msg_create("sese.023");
    populate_sese023_minimal();
    msg_set("SctiesLeg/FinInstrmId", b"BADSIGN");
    let xml = msg_serialize("XML").expect("serialize");
    let err = parse_message("sese.023", &xml).expect_err("validation should fail");
    assert!(matches!(
        err,
        MsgError::InvalidInstrument { field } if field == "SctiesLeg/FinInstrmId"
    ));
}
#[test]
fn validate_identifier_helpers() {
    assert!(validate_identifier(IdentifierKind::Isin, "US0378331005"));
    assert!(!validate_identifier(IdentifierKind::Isin, "US0378331004"));
    assert!(validate_identifier(IdentifierKind::Cusip, "037833100"));
    assert!(!validate_identifier(IdentifierKind::Cusip, "03783310X"));
    assert!(validate_identifier(
        IdentifierKind::Lei,
        "5493001KJTIIGC8Y1R12"
    ));
    assert!(!validate_identifier(
        IdentifierKind::Lei,
        "5493001KJTIIGC8Y1R13"
    ));
    assert!(validate_identifier(IdentifierKind::Bic, "DEUTDEFF"));
    assert!(!validate_identifier(IdentifierKind::Bic, "deutDEFF"));
    assert!(validate_identifier(IdentifierKind::Mic, "XNAS"));
    assert!(!validate_identifier(IdentifierKind::Mic, "1NAS"));
    assert!(validate_identifier(
        IdentifierKind::Iban,
        "GB82WEST12345698765432"
    ));
    assert!(!validate_identifier(
        IdentifierKind::Iban,
        "GB82WEST12345698765433"
    ));
    assert!(validate_identifier(
        IdentifierKind::Iban,
        "de89370400440532013000"
    ));
    assert!(validate_identifier(IdentifierKind::Iban, "NO9386011117947"));
    assert!(!validate_identifier(
        IdentifierKind::Iban,
        "GB82WEST1234569876543"
    ));
    assert!(!validate_identifier(
        IdentifierKind::Iban,
        "ZZ82WEST12345698765432"
    ));
    assert!(validate_identifier(IdentifierKind::Currency, "USD"));
    assert!(!validate_identifier(IdentifierKind::Currency, "ZZZ"));
}
#[test]
fn validate_instrument_identifier_helper() {
    assert!(validate_instrument_identifier("US0378331005"));
    assert!(validate_instrument_identifier("037833100"));
    assert!(!validate_instrument_identifier("INVALID"));
}
#[test]
fn camt053_requires_account_id() {
    reset();
    msg_create("camt.053");
    populate_camt053_minimal();
    msg_remove("Stmt/Acct/Id");
    assert!(!msg_validate());
}
#[test]
fn camt053_rejects_invalid_iban() {
    reset();
    msg_create("camt.053");
    populate_camt053_minimal();
    msg_set("Stmt/Acct/Id", b"GB82WEST12345698765433");
    assert!(!msg_validate());
}
#[test]
fn camt053_rejects_non_numeric_balance() {
    reset();
    msg_create("camt.053");
    populate_camt053_minimal();
    msg_set("Stmt/Bal[0]/Amt", b"not-number");
    assert!(!msg_validate());
}
#[test]
fn camt053_accepts_valid_message() {
    reset();
    msg_create("camt.053");
    populate_camt053_minimal();
    assert!(msg_validate());
}
#[test]
fn camt052_accepts_valid_message() {
    reset();
    msg_create("camt.052");
    populate_camt052_minimal();
    assert!(msg_validate());
}
#[test]
fn pain001_accepts_valid_message() {
    reset();
    msg_create("pain.001");
    populate_pain001_minimal();
    assert!(msg_validate());
}
#[test]
fn pain001_rejects_missing_credit_transfer() {
    reset();
    msg_create("pain.001");
    populate_pain001_minimal();
    msg_remove("PmtInf[0]/CdtTrfTxInf[0]/Amt");
    assert!(!msg_validate());
}
#[test]
fn pacs009_accepts_valid_message() {
    reset();
    msg_create("pacs.009");
    populate_pacs009_minimal();
    assert!(msg_validate());
}
#[test]
fn pacs009_rejects_missing_agents() {
    reset();
    msg_create("pacs.009");
    populate_pacs009_minimal();
    msg_remove("InstgAgt");
    assert!(!msg_validate());
}
#[test]
fn pacs004_accepts_valid_message() {
    reset();
    msg_create("pacs.004");
    populate_pacs004_minimal();
    assert!(msg_validate());
}
#[test]
fn pacs028_accepts_valid_message() {
    reset();
    msg_create("pacs.028");
    populate_pacs028_minimal();
    assert!(msg_validate());
}
#[test]
fn pacs029_accepts_valid_message() {
    reset();
    msg_create("pacs.029");
    populate_pacs029_minimal();
    assert!(msg_validate());
}
#[test]
fn pain002_accepts_valid_message() {
    reset();
    msg_create("pain.002");
    populate_pain002_minimal();
    assert!(msg_validate());
}
#[test]
fn pacs007_accepts_valid_message() {
    reset();
    msg_create("pacs.007");
    populate_pacs007_minimal();
    assert!(msg_validate());
}
#[test]
fn camt056_accepts_valid_message() {
    reset();
    msg_create("camt.056");
    populate_camt056_minimal();
    assert!(msg_validate());
}
#[test]
fn pacs002_accepts_valid_message() {
    reset();
    msg_create("pacs.002");
    msg_set("OrgnlMsgId", b"1");
    msg_set("TxSts", b"ACTC");
    assert!(msg_validate());
}
#[test]
fn pacs002_accepts_missing_tx_status() {
    reset();
    msg_create("pacs.002");
    msg_set("OrgnlMsgId", b"1");
    assert!(msg_validate());
}
#[test]
fn pacs002_rejects_unknown_status() {
    reset();
    msg_create("pacs.002");
    msg_set("OrgnlMsgId", b"1");
    msg_set("TxSts", b"XXXX");
    assert!(!msg_validate());
}
#[test]
fn msg_set_and_get() {
    reset();
    msg_create("pacs.008");
    msg_set("field", b"value");
    assert_eq!(msg_get("field").as_deref(), Some(&b"value"[..]));
}
#[test]
fn msg_clear_removes_all() {
    reset();
    msg_create("pacs.008");
    msg_set("field", b"value");
    msg_clear();
    assert!(msg_get("field").is_none());
}
#[test]
fn msg_add_creates_incrementing_keys() {
    reset();
    msg_create("pacs.008");
    msg_add("Entry");
    msg_add("Entry");
    assert!(msg_get("Entry[0]").is_some());
    assert!(msg_get("Entry[1]").is_some());
    assert!(msg_get("Entry[2]").is_none());
}
#[test]
fn msg_remove_deletes_field() {
    reset();
    msg_create("pacs.008");
    msg_set("field", b"value");
    msg_remove("field");
    assert!(msg_get("field").is_none());
}
#[test]
fn msg_parse_and_serialize_roundtrip() {
    reset();
    msg_parse("pacs.008", b"field=value\nfoo=bar").unwrap();
    assert_eq!(msg_get("foo").as_deref(), Some(&b"bar"[..]));
    assert_eq!(
        msg_serialize("KV").unwrap(),
        b"field=value\nfoo=bar".to_vec()
    );
}
#[test]
fn parse_message_materialises_fields() {
    reset();
    let parsed = parse_message(
            "pacs.008",
            b"MsgId=abc\nIntrBkSttlmCcy=USD\nIntrBkSttlmAmt=10\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB33BUKB20201555555555\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF",
        )
        .expect("message parses");
    assert_eq!(parsed.message_type(), "pacs.008");
    assert_eq!(parsed.field_text("MsgId"), Some("abc"));
    assert_eq!(parsed.field_text("IntrBkSttlmCcy"), Some("USD"));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_xml_message_rejects_developer_formats() {
    reset();
    assert!(matches!(
        parse_xml_message("pacs.008", b"MsgId=abc"),
        Err(MsgError::InvalidFormat)
    ));
    assert!(matches!(
        parse_xml_message(
            "pacs.008",
            br#"<ISO20022 message="pacs.008"><Field path="MsgId">abc</Field></ISO20022>"#,
        ),
        Err(MsgError::InvalidFormat)
    ));
    let parsed = parse_xml_message("pacs.008", SAMPLE_PACS008_XML.as_bytes())
        .expect("real ISO XML remains accepted");
    assert_eq!(parsed.field_text("MsgId"), Some("ISO-008-GRP"));
}
#[test]
fn real_xml_provenance_covers_only_the_signed_range() {
    reset();
    let parsed =
        parse_xml_message("pacs.008", SAMPLE_PACS008_XML.as_bytes()).expect("sample XML parses");
    assert!(parsed.fields_are_covered_by_xml_range(
        SAMPLE_PACS008_XML.as_bytes(),
        0..SAMPLE_PACS008_XML.len()
    ));
    let document_start = SAMPLE_PACS008_XML
        .find("<Document")
        .expect("Document start");
    let document_end = SAMPLE_PACS008_XML
        .find("</Document>")
        .map(|offset| offset + "</Document>".len())
        .expect("Document end");
    assert!(!parsed.fields_are_covered_by_xml_range(
        SAMPLE_PACS008_XML.as_bytes(),
        document_start..document_end
    ));
    let changed = SAMPLE_PACS008_XML.replace("ISO-008-GRP", "ISO-008-ALT");
    assert!(!parsed.fields_are_covered_by_xml_range(changed.as_bytes(), 0..changed.len()));
}
#[test]
fn parse_message_validation_failure() {
    reset();
    let err = parse_message("pacs.008", b"MsgId=abc").unwrap_err();
    assert!(matches!(err, MsgError::MissingField("IntrBkSttlmCcy")));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_head001_envelope_preserves_apphdr_fields() {
    reset();
    let xml = include_str!("assets/text_v1/head001_envelope.xml");
    let parsed = parse_message("head.001.001.03", xml.as_bytes()).expect("header envelope parses");
    assert_eq!(parsed.message_type(), "head.001.001.03");
    assert_eq!(parsed.field_text("AppHdr/BizMsgIdr"), Some("HDR-123"));
    assert_eq!(
        parsed.field_text("AppHdr/MsgDefIdr"),
        Some("pacs.008.001.08")
    );
    assert_eq!(
        parsed.field_text("AppHdr/Fr/FIId/FinInstnId/BICFI"),
        Some("DEUTDEFF")
    );
    assert_eq!(
        parsed.field_text("AppHdr/To/FIId/FinInstnId/ClrSysMmbId/MmbId"),
        Some("654321")
    );
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn pacs008_accepts_proxy_accounts_without_iban() {
    reset();
    let xml = include_str!("assets/text_v1/pacs008_proxy.xml");
    let parsed =
        parse_message("pacs.008.001.08", xml.as_bytes()).expect("proxy-only pacs.008 parses");
    assert_eq!(parsed.field_text("DbtrAcct/Prxy/Id"), Some("proxy-debtor"));
    assert_eq!(
        parsed.field_text("CdtrAcct/Prxy/Id"),
        Some("proxy-creditor")
    );
    assert!(parsed.field_text("DbtrAcct").is_none());
    assert!(parsed.field_text("CdtrAcct").is_none());
}
#[test]
fn msg_validate_none() {
    reset();
    assert!(!msg_validate());
}
#[test]
fn versioned_pacs008_supported() {
    reset();
    msg_create("pacs.008.001.10");
    populate_pacs008_minimal();
    assert!(msg_validate());
}
#[test]
fn versioned_pacs002_supported() {
    reset();
    msg_create("pacs.002.001.12");
    msg_set("OrgnlMsgId", b"ABC");
    msg_set("TxSts", b"ACSP");
    assert!(msg_validate());
}
#[test]
fn versioned_camt053_supported() {
    reset();
    msg_create("camt.053.001.08");
    populate_camt053_minimal();
    assert!(msg_validate());
}
#[test]
fn versioned_camt054_supported() {
    reset();
    msg_create("camt.054.001.08");
    msg_set("Ntfctn/Id", b"NTF1");
    msg_set("Ntfctn/Acct/Id", b"GB82WEST12345698765432");
    msg_add("Ntfctn/Ntry");
    msg_set("Ntfctn/Ntry[0]/Amt", b"15.00");
    msg_set("Ntfctn/Ntry[0]/Ccy", b"USD");
    msg_set("Ntfctn/Ntry[0]/CdtDbtInd", b"CRDT");
    assert!(msg_validate());
}
#[test]
fn versioned_camt052_supported() {
    reset();
    msg_create("camt.052.001.09");
    populate_camt052_minimal();
    assert!(msg_validate());
}
#[test]
fn parse_sample_pacs008() {
    assert_validated("pacs.008.001.08", SAMPLE_PACS008_XML);
    let msg_id = msg_get("MsgId");
    assert_eq!(msg_id.as_deref(), Some(b"ISO-008-GRP".as_ref()));
    assert_eq!(msg_get("IntrBkSttlmCcy").as_deref(), Some(b"USD".as_ref()));
    assert_eq!(
        msg_get("IntrBkSttlmAmt").as_deref(),
        Some(b"1400.00".as_ref())
    );
}
#[test]
fn iso_xsd_document_roots_cover_supported_xml_families() {
    for (message_type, root) in [
        ("colr.012.001.05", "CollSbstitnConf"),
        ("pacs.002.001.10", "FIToFIPmtStsRpt"),
        ("pacs.004.001.09", "PmtRtr"),
        ("pacs.007.001.09", "FIToFIPmtRvsl"),
        ("pacs.008.001.08", "FIToFICstmrCdtTrf"),
        ("pacs.009.001.10", "FICdtTrf"),
        ("pacs.028.001.09", "FIToFIPmtStsReq"),
        ("pacs.029.001.09", "RsltnOfInvstgtn"),
        ("pain.001.001.11", "CstmrCdtTrfInitn"),
        ("pain.002.001.12", "CstmrPmtStsRpt"),
        ("camt.029.001.09", "RsltnOfInvstgtn"),
        ("camt.052.001.08", "BkToCstmrAcctRpt"),
        ("camt.053.001.08", "BkToCstmrStmt"),
        ("camt.054.001.08", "BkToCstmrDbtCdtNtfctn"),
        ("camt.056.001.08", "FIToFIPmtCxlReq"),
        ("sese.023.001.11", "SctiesSttlmTxInstr"),
        ("sese.024.001.10", "SctiesSttlmTxStsAdvc"),
        ("sese.025.001.10", "SctiesSttlmTxConf"),
    ] {
        assert_eq!(
            document_root_matches_message(message_type, root),
            Some(true)
        );
        assert_eq!(
            document_root_matches_message(message_type, "WrongDocumentRoot"),
            Some(false)
        );
    }
}
#[test]
fn parse_real_iso20022_rejects_mismatched_xsd_document_root() {
    reset();
    let xml = include_str!("assets/text_v1/pacs002_wrong_root.xml");
    let err = parse_message("pacs.002.001.10", xml.as_bytes())
        .expect_err("pacs.002 must not accept pacs.008 document root");
    assert!(matches!(err, MsgError::UnknownMessageType));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_missing_xsd_document_root() {
    reset();
    let xml = include_str!("assets/text_v1/pacs002_missing_root.xml");
    let err = parse_message("pacs.002.001.10", xml.as_bytes())
        .expect_err("real pacs.002 XML must carry its XSD document root");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_requested_version_drift() {
    reset();
    let err = parse_message("pacs.008.001.10", SAMPLE_PACS008_XML.as_bytes())
        .expect_err("exact requested MDR version must match payload declarations");
    assert!(matches!(err, MsgError::UnknownMessageType));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_header_document_definition_drift() {
    reset();
    let xml = SAMPLE_PACS008_XML.replace(
        "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08",
        "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.10",
    );
    let err = parse_message("pacs.008", xml.as_bytes())
        .expect_err("BAH MsgDefIdr must match Document XSD namespace exactly");
    assert!(matches!(err, MsgError::UnknownMessageType));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_spoofed_document_namespace_suffix() {
    reset();
    let xml = SAMPLE_PACS008_XML.replace(
        "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08",
        "https://attacker.invalid/schema:pacs.008.001.08",
    );
    let err = parse_message("pacs.008", xml.as_bytes())
        .expect_err("Document namespace must use the exact ISO 20022 XSD prefix");
    assert!(matches!(err, MsgError::UnknownMessageType));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_empty_document_namespace_definition() {
    reset();
    let xml = SAMPLE_PACS008_XML.replace(
        "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08",
        "urn:iso:std:iso:20022:tech:xsd:",
    );
    let err = parse_message("pacs.008", xml.as_bytes())
        .expect_err("Document namespace must include a concrete message definition");
    assert!(matches!(err, MsgError::UnknownMessageType));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_unqualified_document_namespace() {
    reset();
    let xml = SAMPLE_PACS008_XML.replace(
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">"#,
        "<Document>",
    );
    let err = parse_message("pacs.008", xml.as_bytes())
        .expect_err("Document must be bound to the ISO 20022 XSD namespace");
    assert!(matches!(err, MsgError::UnknownMessageType));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_accepts_prefixed_iso_document_namespace() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML
            .replace(
                r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
                r#"<pacs:Document xmlns:pacs="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10" xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
            )
            .replace("<FIToFIPmtStsRpt>", "<pacs:FIToFIPmtStsRpt>")
            .replace("</FIToFIPmtStsRpt>", "</pacs:FIToFIPmtStsRpt>")
            .replace("</Document>", "</pacs:Document>");
    let parsed = parse_message("pacs.002", xml.as_bytes())
        .expect("prefixed Document and payload root should resolve to ISO namespace");
    assert_eq!(parsed.message_type(), "pacs.002");
    assert_eq!(parsed.field_text("MsgId"), Some("ISO-PACS002-STATUS"));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_prefixed_document_namespace_spoofing() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML
            .replace(
                r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
                r#"<pacs:Document xmlns:pacs="https://attacker.invalid/schema:pacs.002.001.10" xmlns="https://attacker.invalid/schema:pacs.002.001.10">"#,
            )
            .replace("<FIToFIPmtStsRpt>", "<pacs:FIToFIPmtStsRpt>")
            .replace("</FIToFIPmtStsRpt>", "</pacs:FIToFIPmtStsRpt>")
            .replace("</Document>", "</pacs:Document>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("prefixed Document namespace must use the ISO XSD URI");
    assert!(matches!(err, MsgError::UnknownMessageType));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_payload_root_namespace_spoofing() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML
            .replace(
                "<FIToFIPmtStsRpt>",
                r#"<evil:FIToFIPmtStsRpt xmlns:evil="https://attacker.invalid/schema:pacs.002.001.10">"#,
            )
            .replace("</FIToFIPmtStsRpt>", "</evil:FIToFIPmtStsRpt>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("Document payload root must resolve to the ISO XSD namespace");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_conflicting_canonical_aliases() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace("<GrpSts>ACSP</GrpSts>", "<GrpSts>RJCT</GrpSts>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("canonical aliases may repeat only an identical value");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_descendant_namespace_spoofing() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML
        .replace(
            "<MsgId>",
            r#"<evil:MsgId xmlns:evil="https://attacker.invalid/iso">"#,
        )
        .replace("</MsgId>", "</evil:MsgId>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("every semantic descendant must retain the Document namespace");
    assert!(matches!(err, MsgError::InvalidFormat));
}
#[test]
fn parse_real_iso20022_ignores_fields_outside_semantic_namespaces() {
    reset();
    let xml = r#"<DataPDU xmlns:evil="https://attacker.invalid/iso">
  <evil:Body>
    <evil:MsgId>EVIL-MSG</evil:MsgId>
    <evil:IntrBkSttlmAmt>10.00</evil:IntrBkSttlmAmt>
    <evil:IntrBkSttlmCcy>USD</evil:IntrBkSttlmCcy>
    <evil:IntrBkSttlmDt>2024-01-01</evil:IntrBkSttlmDt>
    <evil:DbtrAcct>GB82WEST12345698765432</evil:DbtrAcct>
    <evil:CdtrAcct>GB33BUKB20201555555555</evil:CdtrAcct>
    <evil:DbtrAgt>DEUTDEFF</evil:DbtrAgt>
    <evil:CdtrAgt>MARKDEFF</evil:CdtrAgt>
  </evil:Body>
  <Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">
    <FIToFICstmrCdtTrf/>
  </Document>
</DataPDU>"#;
    let err = parse_xml_message("pacs.008", xml.as_bytes())
        .expect_err("transport-wrapper fields must not satisfy the ISO schema");
    assert!(matches!(err, MsgError::MissingField("MsgId")));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_transparent_wrappers_inside_document() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML
        .replace("<GrpHdr>", "<Body><GrpHdr>")
        .replace("</GrpHdr>", "</GrpHdr></Body>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("transport wrappers must not erase semantic path components");
    assert!(matches!(err, MsgError::InvalidFormat));
}
#[test]
fn parse_real_iso20022_enforces_depth_and_attribute_budgets() {
    reset();
    let nested = format!(
        "{}{}",
        "<X>".repeat(REAL_XML_MAX_DEPTH),
        "</X>".repeat(REAL_XML_MAX_DEPTH)
    );
    let deep = SAMPLE_PACS002_STATUS_XML.replace("<GrpHdr>", &format!("<GrpHdr>{nested}"));
    assert!(matches!(
        parse_message("pacs.002", deep.as_bytes()),
        Err(MsgError::InvalidFormat)
    ));

    let attributes = (0..=REAL_XML_MAX_ATTRIBUTES_PER_ELEMENT)
        .map(|index| format!(" a{index}=\"x\""))
        .collect::<String>();
    let wide = SAMPLE_PACS002_STATUS_XML.replace("<MsgId>", &format!("<MsgId{attributes}>"));
    assert!(matches!(
        parse_message("pacs.002", wide.as_bytes()),
        Err(MsgError::InvalidFormat)
    ));
}
#[test]
fn parse_real_iso20022_rejects_mismatched_closing_tag() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace("</GrpHdr>", "</WrongGrpHdr>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("mismatched closing tags must fail real ISO XML parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_extra_closing_tag() {
    reset();
    let xml = format!("{SAMPLE_PACS002_STATUS_XML}</Document>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("extra closing tags must fail real ISO XML parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_attributed_closing_tag() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace("</GrpHdr>", r#"</GrpHdr attr="x">"#);
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("closing tags with attributes must fail real ISO XML parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_unclosed_document_tag() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace("</Document>", "");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("unclosed Document tags must fail real ISO XML parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_accepts_single_quoted_namespace_attribute() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
        r#"<Document xmlns='urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10'>"#,
    );
    let parsed = parse_message("pacs.002", xml.as_bytes())
        .expect("single-quoted XML attributes are well-formed");
    assert_eq!(parsed.message_type(), "pacs.002");
    assert_eq!(parsed.field_text("MsgId"), Some("ISO-PACS002-STATUS"));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_unquoted_namespace_attribute() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
        r#"<Document xmlns=urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10>"#,
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("unquoted XML namespace attributes must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_unterminated_attribute_value() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10>"#,
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("unterminated XML attributes must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_duplicate_namespace_attribute() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
            r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
            r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10" xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
        );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("duplicate XML attributes must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_malformed_trailing_attribute() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10" malformed>"#,
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("malformed trailing XML attributes must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_decodes_xml_entities_in_text_and_attributes() {
    reset();
    let xml = SAMPLE_PACS008_XML
        .replace(
            "<BizMsgIdr>ISO-SAMPLE-008</BizMsgIdr>",
            "<BizMsgIdr>ISO&#45;SAMPLE&amp;008</BizMsgIdr>",
        )
        .replace(
            r#"<IntrBkSttlmAmt Ccy="USD">1400.00</IntrBkSttlmAmt>"#,
            r#"<IntrBkSttlmAmt Ccy="US&#68;">1400.00</IntrBkSttlmAmt>"#,
        );
    let parsed = parse_message("pacs.008", xml.as_bytes())
        .expect("valid XML character references should parse");
    assert_eq!(
        parsed.field_text("AppHdr/BizMsgIdr"),
        Some("ISO-SAMPLE&008")
    );
    assert_eq!(parsed.field_text("IntrBkSttlmCcy"), Some("USD"));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_unknown_xml_entity_reference() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        "<MsgId>ISO-PACS002-STATUS</MsgId>",
        "<MsgId>ISO-&xxe;-STATUS</MsgId>",
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("unknown XML entities must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_unterminated_xml_entity_reference() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        "<MsgId>ISO-PACS002-STATUS</MsgId>",
        "<MsgId>ISO&amp-PACS002-STATUS</MsgId>",
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("unterminated XML entities must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_invalid_numeric_xml_character_reference() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        r#"<IntrBkSttlmAmt Ccy="USD">1400</IntrBkSttlmAmt>"#,
        r#"<IntrBkSttlmAmt Ccy="US&#x0;">1400</IntrBkSttlmAmt>"#,
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("invalid XML numeric character references must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_raw_invalid_xml_character_in_text() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        "<MsgId>ISO-PACS002-STATUS</MsgId>",
        "<MsgId>ISO-\u{1}-STATUS</MsgId>",
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("raw invalid XML characters in text must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_raw_invalid_xml_character_in_attribute() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        r#"<IntrBkSttlmAmt Ccy="USD">1400</IntrBkSttlmAmt>"#,
        "<IntrBkSttlmAmt Ccy=\"US\u{1}\">1400</IntrBkSttlmAmt>",
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("raw invalid XML characters in attributes must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_raw_less_than_in_attribute_value() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        r#"<IntrBkSttlmAmt Ccy="USD">1400</IntrBkSttlmAmt>"#,
        r#"<IntrBkSttlmAmt Ccy="US<D">1400</IntrBkSttlmAmt>"#,
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("raw less-than characters in XML attributes must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_accepts_xml_declaration_and_well_formed_comment() {
    reset();
    let xml = format!("<?xml version=\"1.0\"?>\n<!--valid comment-->\n{SAMPLE_PACS002_STATUS_XML}");
    let parsed = parse_message("pacs.002", xml.as_bytes())
        .expect("well-formed XML declaration and comments should parse");
    assert_eq!(parsed.message_type(), "pacs.002");
    assert_eq!(parsed.field_text("MsgId"), Some("ISO-PACS002-STATUS"));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_concatenates_text_split_by_comment() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        "<MsgId>ISO-PACS002-STATUS</MsgId>",
        "<MsgId>ISO-<!--valid-->PACS002-STATUS</MsgId>",
    );
    let parsed = parse_message("pacs.002", xml.as_bytes())
        .expect("comments inside simple content should not overwrite text chunks");
    assert_eq!(parsed.field_text("MsgId"), Some("ISO-PACS002-STATUS"));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_text_before_child_element() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace("<GrpHdr>", "<GrpHdr>mixed");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("mixed content before child elements must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_text_after_child_element() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace("</MsgId>", "</MsgId>mixed");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("mixed content after child elements must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_content_outside_single_root() {
    for (label, xml) in [
        (
            "extra leading root",
            format!("<Ignored/>{SAMPLE_PACS002_STATUS_XML}"),
        ),
        (
            "trailing text",
            format!("{SAMPLE_PACS002_STATUS_XML}outside"),
        ),
    ] {
        reset();
        let err = match parse_message("pacs.002", xml.as_bytes()) {
            Ok(_) => panic!("{label} outside the ISO XML root must fail parsing"),
            Err(err) => err,
        };
        assert!(matches!(err, MsgError::InvalidFormat), "{label}: {err:?}");
        assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
    }
}
#[test]
fn parse_real_iso20022_rejects_unterminated_comment() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace("<GrpHdr>", "<!--unterminated><GrpHdr>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("unterminated comments must fail real ISO XML parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_malformed_comment_body() {
    reset();
    let xml = format!("<!--bad--comment-->\n{SAMPLE_PACS002_STATUS_XML}");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("comments containing double hyphen must fail real ISO XML parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_malformed_processing_instruction() {
    reset();
    let xml = format!("<?bad processing>\n{SAMPLE_PACS002_STATUS_XML}");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("unterminated processing instructions must fail real ISO XML parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_unsupported_doctype_declaration() {
    reset();
    let xml = format!("<!DOCTYPE Document [<!ENTITY x \"boom\">]>\n{SAMPLE_PACS002_STATUS_XML}");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("DOCTYPE declarations must fail real ISO XML parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_unsupported_cdata_section() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        "<MsgId>ISO-PACS002-STATUS</MsgId>",
        "<MsgId><![CDATA[ISO-PACS002-STATUS]]></MsgId>",
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("CDATA must fail real ISO XML parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_malformed_document_qname() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML
        .replace(
            r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
            r#"<pacs::Document xmlns:pacs="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
        )
        .replace("</Document>", "</pacs::Document>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("malformed Document QNames must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_malformed_payload_root_qname() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML
            .replace(
                "<FIToFIPmtStsRpt>",
                r#"<pacs::FIToFIPmtStsRpt xmlns:pacs="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
            )
            .replace("</FIToFIPmtStsRpt>", "</pacs::FIToFIPmtStsRpt>");
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("malformed payload root QNames must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_malformed_namespace_declaration_name() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
        r#"<pacs:Document xmlns::pacs="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("malformed namespace declaration names must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_rejects_invalid_element_name_start() {
    reset();
    let xml = SAMPLE_PACS002_STATUS_XML.replace(
        r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
        r#"<1Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">"#,
    );
    let err = parse_message("pacs.002", xml.as_bytes())
        .expect_err("unsupported XML element names must fail parsing");
    assert!(matches!(err, MsgError::InvalidFormat));
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_real_iso20022_allows_canonical_family_request_with_consistent_version() {
    reset();
    let parsed = parse_message("pacs.008", SAMPLE_PACS008_XML.as_bytes())
        .expect("canonical family requests defer exact MDR allowlists to profiles");
    assert_eq!(parsed.message_type(), "pacs.008");
    assert_eq!(
        parsed.field_text("AppHdr/MsgDefIdr"),
        Some("pacs.008.001.08")
    );
    assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
}
#[test]
fn parse_sample_pacs009() {
    assert_validated("pacs.009.001.10", SAMPLE_PACS009_XML);
    assert_eq!(
        msg_get("BizMsgIdr").as_deref(),
        Some(b"PACS009-BIZ".as_ref())
    );
    assert_eq!(msg_get("MsgId").as_deref(), Some(b"PACS009-GRP".as_ref()));
    assert_eq!(
        msg_get("MsgDefIdr").as_deref(),
        Some(b"pacs.009.001.10".as_ref())
    );
    assert_eq!(msg_get("IntrBkSttlmAmt").as_deref(), Some(b"2500".as_ref()));
    assert_eq!(msg_get("IntrBkSttlmCcy").as_deref(), Some(b"USD".as_ref()));
    assert_eq!(
        msg_get("DbtrAcct").as_deref(),
        Some(b"GB82WEST12345698765432".as_ref())
    );
    assert_eq!(
        msg_get("CdtrAcct").as_deref(),
        Some(b"GB33BUKB20201555555555".as_ref())
    );
    assert_eq!(msg_get("Purp").as_deref(), Some(b"SECU".as_ref()));
}
#[test]
fn parse_sample_pacs009_envelope() {
    assert_validated("pacs.009.001.10", SAMPLE_PACS009_ENVELOPE_XML);
    assert_eq!(
        msg_get("BizMsgIdr").as_deref(),
        Some(b"BAH-PACS009-1".as_ref())
    );
    assert_eq!(
        msg_get("MsgDefIdr").as_deref(),
        Some(b"pacs.009.001.10".as_ref())
    );
    assert_eq!(
        msg_get("AppHdr/CreDt").as_deref(),
        Some(b"2025-11-12T09:34:09Z".as_ref())
    );
    assert_eq!(msg_get("InstgAgt").as_deref(), Some(b"DEUTDEFF".as_ref()));
    assert_eq!(msg_get("InstdAgt").as_deref(), Some(b"MARKDEFF".as_ref()));
    assert_eq!(
        msg_get("DbtrAcct").as_deref(),
        Some(b"GB82WEST12345698765432".as_ref())
    );
    assert_eq!(
        msg_get("CdtrAcct").as_deref(),
        Some(b"GB33BUKB20201555555555".as_ref())
    );
}
#[test]
fn parsed_pacs009_distinct_identity_fields_remain_mutable() {
    assert_validated("pacs.009.001.10", SAMPLE_PACS009_ENVELOPE_XML);

    msg_set("AppHdr/CreDt", b"2025-11-12T09:35:00Z");
    assert_eq!(
        msg_get("AppHdr/CreDt").as_deref(),
        Some(b"2025-11-12T09:35:00Z".as_ref())
    );

    msg_set("Document/FICdtTrf/GrpHdr/MsgId", b"PACS009-GRP-NEW");
    assert_eq!(
        msg_get("MsgId").as_deref(),
        Some(b"PACS009-GRP-NEW".as_ref())
    );
    msg_remove("Document/FICdtTrf/GrpHdr/MsgId");
    assert!(msg_get("MsgId").is_none());
    assert_eq!(
        msg_get("BizMsgIdr").as_deref(),
        Some(b"BAH-PACS009-1".as_ref())
    );
}
#[test]
fn pacs009_aliases_keep_application_and_payment_identity_fields_distinct() {
    assert_eq!(
        canonical_field_name("pacs.009.001.10", "AppHdr/CreDt"),
        "AppHdr/CreDt"
    );
    assert_eq!(
        canonical_field_name("pacs.009.001.10", "Document/FICdtTrf/GrpHdr/CreDtTm"),
        "CreDtTm"
    );
    assert_eq!(
        canonical_field_name("pacs.009.001.10", "AppHdr/BizMsgIdr"),
        "BizMsgIdr"
    );
    assert_eq!(
        canonical_field_name("pacs.009.001.10", "Document/FICdtTrf/GrpHdr/MsgId"),
        "MsgId"
    );
}
#[test]
fn parse_sample_pacs002_auth_allows_missing_txsts() {
    assert_validated("pacs.002.001.10", SAMPLE_PACS002_AUTH_XML);
    assert_eq!(
        msg_get("MsgId").as_deref(),
        Some(b"ISO-PACS002-AUTH".as_ref())
    );
    assert_eq!(
        msg_get("OrgnlMsgId").as_deref(),
        Some(b"ISO-SAMPLE-008".as_ref())
    );
}
#[test]
fn parse_sese024_status_advice_lifecycle_fields() {
    let xml = include_str!("assets/text_v1/sese024_status.xml");
    assert_validated("sese.024.001.10", xml);
    assert_eq!(msg_get("TxId").as_deref(), Some(b"SETTLEMENT-123".as_ref()));
    assert_eq!(msg_get("SttlmSts").as_deref(), Some(b"SETT".as_ref()));
    assert_eq!(msg_get("RsnCd").as_deref(), Some(b"NARR".as_ref()));
}
#[test]
fn parse_sample_camt052_allows_other_account_id() {
    assert_validated("camt.052.001.08", SAMPLE_CAMT052_XML);
    assert_eq!(
        msg_get("Rpt/Acct/Id").as_deref(),
        Some(b"ALTACCOUNT".as_ref())
    );
}
#[test]
fn parse_sample_camt056_tracks_assignment() {
    assert_validated("camt.056.001.08", SAMPLE_CAMT056_XML);
    assert_eq!(
        msg_get("Assgnmt/Id").as_deref(),
        Some(b"ISO-CAMT056-ASSIGN".as_ref())
    );
    assert_eq!(
        msg_get("Undrlyg/TxInf/OrgnlGrpInf/OrgnlMsgId").as_deref(),
        Some(b"ISO-SAMPLE-008".as_ref())
    );
}
#[test]
fn camt056_fixture_parses_cancellation_fields() {
    assert_validated("camt.056.001.08", CAMT056_FIXTURE);
    assert_eq!(
        msg_get("Assgnmt/Id").as_deref(),
        Some(b"CANCEL-FIXTURE-1".as_ref())
    );
    assert_eq!(
        msg_get("Undrlyg/TxInf/OrgnlGrpInf/OrgnlMsgId").as_deref(),
        Some(b"CANCEL-ORIG-1".as_ref())
    );
    assert_eq!(
        msg_get("Undrlyg/TxInf/CxlRsnInf/Rsn/Cd").as_deref(),
        Some(b"CUST".as_ref())
    );
    assert_eq!(
        msg_get("Undrlyg/TxInf/CxlRsnInf/AddtlInf").as_deref(),
        Some(b"customer requested recall".as_ref())
    );
}
#[test]
fn camt056_001_09_fixture_parses_cancellation_fields() {
    assert_validated("camt.056.001.09", CAMT056_001_09_FIXTURE);
    assert_eq!(
        msg_get("Assgnmt/Id").as_deref(),
        Some(b"CANCEL-FIXTURE-9".as_ref())
    );
    assert_eq!(
        msg_get("Undrlyg/TxInf/OrgnlGrpInf/OrgnlMsgId").as_deref(),
        Some(b"CANCEL-ORIG-9".as_ref())
    );
    assert_eq!(
        msg_get("Undrlyg/TxInf/CxlRsnInf/Rsn/Cd").as_deref(),
        Some(b"CUST".as_ref())
    );
    assert_eq!(
        msg_get("Undrlyg/TxInf/CxlRsnInf/AddtlInf").as_deref(),
        Some(b"customer requested recall".as_ref())
    );
}
#[test]
fn parse_camt029_resolution_of_investigation() {
    let xml = include_str!("assets/text_v1/camt029_resolution.xml");
    assert_validated("camt.029.001.09", xml);
    assert_eq!(
        msg_get("Assgnmt/Id").as_deref(),
        Some(b"IROHA-CAMT029-ORIGINAL-1".as_ref())
    );
    assert_eq!(msg_get("Sts").as_deref(), Some(b"CNCL".as_ref()));
    assert_eq!(
        msg_get("CxlDtls/OrgnlGrpInf/OrgnlMsgId").as_deref(),
        Some(b"ORIGINAL-1".as_ref())
    );
}
#[test]
fn parse_sample_pacs004_return() {
    assert_validated("pacs.004.001.09", SAMPLE_PACS004_XML);
    assert_eq!(
        msg_get("MsgId").as_deref(),
        Some(b"ISO-PACS004-MSG".as_ref())
    );
    assert_eq!(
        msg_get("TxInf[0]/RtrdInstdAmt").as_deref(),
        Some(b"10.00".as_ref())
    );
    assert_eq!(
        msg_get("TxInf[0]/RtrdInstdAmtCcy").as_deref(),
        Some(b"USD".as_ref())
    );
    assert_eq!(
        msg_get("TxInf[0]/ChrgBr").as_deref(),
        Some(b"SLEV".as_ref())
    );
    assert_eq!(
        msg_get("TxInf[0]/RtrdRsn/Prtry").as_deref(),
        Some(b"TechnicalProblem".as_ref())
    );
}
#[test]
fn pacs004_fixture_parses_return_fields() {
    assert_validated("pacs.004.001.09", PACS004_FIXTURE);
    assert_eq!(
        msg_get("MsgId").as_deref(),
        Some(b"RETURN-FIXTURE-1".as_ref())
    );
    assert_eq!(
        msg_get("OrgnlGrpInf/OrgnlMsgId").as_deref(),
        Some(b"ORIGINAL-008".as_ref())
    );
    assert_eq!(
        msg_get("TxInf[0]/RtrdInstdAmt").as_deref(),
        Some(b"10.00".as_ref())
    );
    assert_eq!(
        msg_get("TxInf[0]/RtrdInstdAmtCcy").as_deref(),
        Some(b"USD".as_ref())
    );
    assert_eq!(
        msg_get("TxInf[0]/RtrdRsn/Cd").as_deref(),
        Some(b"AC01".as_ref())
    );
}
#[test]
fn parse_sample_pacs002_status() {
    assert_validated("pacs.002.001.10", SAMPLE_PACS002_STATUS_XML);
    assert_eq!(
        msg_get("OrgnlMsgId").as_deref(),
        Some(b"ISO-SAMPLE-008".as_ref())
    );
    assert_eq!(msg_get("TxSts").as_deref(), Some(b"ACSP".as_ref()));
}
#[test]
fn pacs002_fixture_parses_status_fields() {
    assert_validated("pacs.002.001.10", PACS002_FIXTURE);
    assert_eq!(
        msg_get("MsgId").as_deref(),
        Some(b"STATUS-FIXTURE-1".as_ref())
    );
    assert_eq!(msg_get("StsId").as_deref(), Some(b"STATUS-TX-1".as_ref()));
    assert_eq!(
        msg_get("OrgnlMsgId").as_deref(),
        Some(b"STATUS-ORIG-1".as_ref())
    );
    assert_eq!(msg_get("TxSts").as_deref(), Some(b"ACSC".as_ref()));
    assert_eq!(
        msg_get("AddtlInf[0]").as_deref(),
        Some(b"settled by fixture report".as_ref())
    );
}
#[test]
fn parse_generated_md_pacs008() {
    let xml = generated_sample("pacs.008.001.08");
    let parsed = parse_message("pacs.008", xml.as_bytes()).expect("parse pacs.008 sample");
    let keys: Vec<String> = parsed.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(
        parsed.field_text("MsgId"),
        Some("ISO-SAMPLE-001"),
        "keys={keys:?}"
    );
    assert_eq!(
        parsed.field_text("Document/FIToFICstmrCdtTrf/CdtTrfTxInf/PmtId/UETR"),
        Some("123e4567-e89b-12d3-a456-426614174000"),
        "keys={keys:?}"
    );
    assert_eq!(
        parsed.field_text("Document/FIToFICstmrCdtTrf/CdtTrfTxInf/ChrgBr"),
        Some("SHAR"),
        "keys={keys:?}"
    );
}
#[test]
fn parse_generated_md_pacs004() {
    let xml = generated_sample("pacs.004.001.09");
    let parsed = parse_message("pacs.004", xml.as_bytes()).expect("parse pacs.004 sample");
    let keys: Vec<String> = parsed.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(
        parsed.field_text("MsgId"),
        Some("ISO-SAMPLE-004"),
        "keys={keys:?}"
    );
    assert_eq!(
        parsed.field_text("OrgnlGrpInf/OrgnlMsgId"),
        Some("ISO-SAMPLE-001"),
        "keys={keys:?}"
    );
    assert_eq!(
        parsed.field_text("TxInf[0]/ChrgBr"),
        Some("SHAR"),
        "keys={keys:?}"
    );
    assert_eq!(
        parsed.field_text("TxInf[0]/RtrdRsn/Prtry"),
        Some("PR01"),
        "keys={keys:?}"
    );
}
#[test]
fn parse_generated_md_pacs002() {
    let xml = generated_sample("pacs.002.001.10");
    let parsed = parse_message("pacs.002", xml.as_bytes()).expect("parse pacs.002 sample");
    let keys: Vec<String> = parsed.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(parsed.field_text("TxSts"), Some("ACSP"), "keys={keys:?}");
    assert_eq!(
        parsed.field_text("Document/FIToFIPmtStsRpt/OrgnlGrpInfAndSts/OrgnlMsgNmId"),
        Some("pacs.008.001.08"),
        "keys={keys:?}"
    );
    assert_eq!(
        parsed.field_text("OrgnlMsgId"),
        Some("ISO-SAMPLE-001"),
        "keys={keys:?}"
    );
}
#[test]
fn parse_generated_md_camt052() {
    let xml = generated_sample("camt.052.001.08");
    reset();
    msg_parse("camt.052", xml.as_bytes()).expect("parse camt.052 sample");
    let valid = msg_validate();
    let failure = take_validation_failure();
    assert!(
        !valid,
        "camt.052 sample should miss Rpt/CreDtTm: {failure:?}"
    );
    assert_eq!(
        msg_get("Rpt/Acct/Id").as_deref(),
        Some(b"ALPHBANK-USD-ACCOUNT-001".as_ref())
    );
    assert_eq!(
        msg_get("Rpt/Ntry[0]/CdtDbtInd").as_deref(),
        Some(b"DBIT".as_ref())
    );
}
#[test]
fn parse_generated_md_camt056() {
    let xml = generated_sample("camt.056.001.08");
    let parsed = parse_message("camt.056", xml.as_bytes()).expect("parse camt.056 sample");
    let keys: Vec<String> = parsed.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(
        parsed.field_text("Document/FIToFIPmtCxlReq/Undrlyg/TxInf/OrgnlUETR"),
        Some("123e4567-e89b-12d3-a456-426614174000"),
        "keys={keys:?}"
    );
    assert_eq!(
        parsed.field_text("Assgnmt/Id"),
        Some("ISO-SAMPLE-056-ASGMT-001"),
        "keys={keys:?}"
    );
}
#[test]
fn versioned_pacs007_supported() {
    reset();
    msg_create("pacs.007.001.09");
    populate_pacs007_minimal();
    assert!(msg_validate());
}
#[test]
fn versioned_camt056_supported() {
    reset();
    msg_create("camt.056.001.09");
    populate_camt056_minimal();
    assert!(msg_validate());
}
#[test]
fn versioned_pacs004_supported() {
    reset();
    msg_create("pacs.004.001.10");
    populate_pacs004_minimal();
    assert!(msg_validate());
}
#[test]
fn versioned_pacs028_supported() {
    reset();
    msg_create("pacs.028.001.09");
    populate_pacs028_minimal();
    assert!(msg_validate());
}
#[test]
fn versioned_pacs029_supported() {
    reset();
    msg_create("pacs.029.001.09");
    populate_pacs029_minimal();
    assert!(msg_validate());
}
#[test]
fn bilateral_iso_rejects_retired_partial_atomicity() {
    for (message, populate) in [
        ("sese.023", populate_sese023_minimal as fn()),
        ("sese.025", populate_sese025_minimal as fn()),
    ] {
        reset();
        msg_create(message);
        populate();
        assert!(msg_validate());
        for retired in ["COMMIT_FIRST_LEG", "COMMIT_SECOND_LEG"] {
            msg_set("Plan/Atomicity", retired.as_bytes());
            assert!(!msg_validate(), "{message} must reject {retired}");
        }
        msg_set("Plan/Atomicity", b"ALL_OR_NOTHING");
        assert!(msg_validate());
    }
}
#[test]
fn sese023_roundtrip_and_norito_snapshot() {
    reset();
    let schema = expected_sese023_schema();
    schema.apply_to_stack();
    assert!(msg_validate());
    let xml = msg_serialize("XML").expect("serialize sese.023");
    let xml_str = String::from_utf8(xml.clone()).expect("utf8");
    assert!(xml_str.contains("ISO20022 message=\"sese.023\""));
    assert!(xml_str.contains("Field path=\"SttlmTpAndAddtlParams/SctiesMvmntTp\""));
    assert!(xml_str.contains("Field path=\"Plan/Atomicity\""));
    let parsed = parse_message("sese.023", &xml).expect("parse sese.023");
    assert_eq!(parsed.field_text("SttlmParams/PrtlSttlmInd"), Some("NPAR"));
    assert_eq!(parsed.field_text("SttlmParams/HldInd"), Some("true"));
    let materialized =
        Sese023::from_parsed(&parsed).expect("materialize sese.023 into Norito schema");
    assert_eq!(schema, materialized);
    let encoded = schema.encode();
    let mut cursor = encoded.as_slice();
    let decoded = Sese023::decode(&mut cursor).expect("decode");
    assert_eq!(schema, decoded);
}
#[test]
fn sese023_requires_movement_and_payment_qualifiers() {
    reset();
    msg_create("sese.023");
    populate_sese023_minimal();
    msg_remove("SttlmTpAndAddtlParams/SctiesMvmntTp");
    assert!(!msg_validate());
    msg_set("SttlmTpAndAddtlParams/SctiesMvmntTp", b"DELI");
    msg_set("SttlmTpAndAddtlParams/Pmt", b"INVALID");
    assert!(!msg_validate());
}
#[test]
fn sese023_missing_execution_order_fails() {
    reset();
    msg_create("sese.023");
    populate_sese023_minimal();
    msg_remove("Plan/ExecutionOrder");
    assert!(!msg_validate());
    msg_set("Plan/ExecutionOrder", b"INVALID");
    assert!(!msg_validate());
}
#[test]
fn sese023_fixture_parses_into_schema() {
    reset();
    let parsed =
        parse_message("sese.023", SESE023_FIXTURE.as_bytes()).expect("parse sese.023 fixture");
    let schema = Sese023::from_parsed(&parsed).expect("materialize sese.023 from fixture");
    assert_eq!(schema, expected_sese023_schema());
}
#[test]
fn sese024_fixture_parses_status_advice_fields() {
    reset();
    let parsed =
        parse_message("sese.024", SESE024_FIXTURE.as_bytes()).expect("parse sese.024 fixture");
    assert_eq!(parsed.field_text("TxId"), Some("DVP-FIXTURE-1"));
    assert_eq!(parsed.field_text("SttlmDt"), Some("2024-02-02"));
    assert_eq!(parsed.field_text("SttlmSts"), Some("PEND"));
    assert_eq!(parsed.field_text("RsnCd"), Some("NORE"));
    assert_eq!(
        parsed.field_text("AddtlInf"),
        Some("awaiting CSD matching confirmation")
    );
}
#[test]
fn sese025_validation_and_serialization() {
    reset();
    let schema = expected_sese025_schema();
    schema.apply_to_stack();
    assert!(msg_validate());
    let xml = msg_serialize("XML").expect("serialize sese.025");
    let parsed = parse_message("sese.025", &xml).expect("parse sese.025");
    let materialized = Sese025::from_parsed(&parsed).expect("materialize sese.025 into schema");
    assert_eq!(materialized, schema);
    assert_eq!(parsed.field_text("ConfSts"), Some("ACCP"));
    assert_eq!(parsed.field_text("Plan/Atomicity"), Some("ALL_OR_NOTHING"));
    assert_eq!(
        parsed.field_text("SttlmTpAndAddtlParams/SctiesMvmntTp"),
        Some("RECE")
    );
    assert_eq!(parsed.field_text("SttlmParams/HldInd"), Some("false"));
}
#[test]
fn sese025_requires_plan_fields() {
    reset();
    msg_create("sese.025");
    populate_sese025_minimal();
    msg_remove("Plan/ExecutionOrder");
    assert!(!msg_validate());
    msg_set("Plan/ExecutionOrder", b"PAYMENT_THEN_DELIVERY");
    msg_set("Plan/Atomicity", b"INVALID");
    assert!(!msg_validate());
}
#[test]
fn sese025_fixture_parses_into_schema() {
    reset();
    let parsed =
        parse_message("sese.025", SESE025_FIXTURE.as_bytes()).expect("parse sese.025 fixture");
    let schema = Sese025::from_parsed(&parsed).expect("materialize sese.025 from fixture");
    assert_eq!(schema, expected_sese025_schema());
}
#[test]
fn colr012_roundtrip_and_norito_snapshot() {
    reset();
    let schema = expected_colr012_schema();
    schema.apply_to_stack();
    assert!(msg_validate());
    let xml = msg_serialize("XML").expect("serialize colr.012");
    let parsed = parse_message("colr.012", &xml).expect("parse colr.012");
    assert_eq!(parsed.field_text("Substitution/Haircut"), Some("50"));
    let materialized = Colr012::from_parsed(&parsed).expect("materialize colr.012 into schema");
    assert_eq!(materialized, schema);
    let encoded = schema.encode();
    let mut cursor = encoded.as_slice();
    let decoded = Colr012::decode(&mut cursor).expect("decode");
    assert_eq!(schema, decoded);
}
#[test]
fn colr007_fixture_is_not_supported() {
    reset();
    assert!(parse_message("colr.007", COLR007_FIXTURE.as_bytes()).is_err());
}
#[test]
fn colr012_fixture_parses_into_schema() {
    reset();
    let parsed =
        parse_message("colr.012", COLR012_FIXTURE.as_bytes()).expect("parse colr.012 fixture");
    let schema = Colr012::from_parsed(&parsed).expect("materialize colr.012 from fixture");
    assert_eq!(schema, expected_colr012_schema());
}
#[test]
fn colr012_rejects_unknown_type() {
    reset();
    msg_create("colr.012");
    populate_colr012_minimal();
    msg_set("Substitution/Type", b"UNEXPECTED");
    assert!(!msg_validate());
}
#[test]
fn versioned_sese023_supported() {
    reset();
    msg_create("sese.023.001.09");
    populate_sese023_minimal();
    assert!(msg_validate());
}
#[test]
fn versioned_sese025_supported() {
    reset();
    msg_create("sese.025.001.08");
    populate_sese025_minimal();
    assert!(msg_validate());
}
#[test]
fn versioned_colr007_is_not_supported() {
    reset();
    msg_create("colr.007.001.08");
    populate_colr012_minimal();
    assert!(!msg_validate());
}
#[test]
fn versioned_colr012_supported() {
    reset();
    msg_create("colr.012.001.05");
    populate_colr012_minimal();
    assert!(msg_validate());
}
#[test]
fn versioned_pain002_supported() {
    reset();
    msg_create("pain.002.001.12");
    populate_pain002_minimal();
    assert!(msg_validate());
}
#[test]
fn msg_parse_xml_roundtrip() {
    reset();
    msg_parse(
            "pacs.008",
            b"<ISO20022 message=\"pacs.008\"><Field path=\"MsgId\">1</Field><Field path=\"IntrBkSttlmCcy\">USD</Field><Field path=\"IntrBkSttlmAmt\">10</Field><Field path=\"IntrBkSttlmDt\">2024-01-01</Field><Field path=\"DbtrAcct\">GB82WEST12345698765432</Field><Field path=\"CdtrAcct\">GB33BUKB20201555555555</Field><Field path=\"DbtrAgt\">DEUTDEFF</Field><Field path=\"CdtrAgt\">DEUTDEFF</Field></ISO20022>"
        ).unwrap();
    assert!(msg_validate());
    let xml = msg_serialize("XML").unwrap();
    let xml_str = String::from_utf8(xml).unwrap();
    assert!(xml_str.contains("<ISO20022"));
    assert!(xml_str.contains("CdtrAgt"));
}
#[test]
fn msg_parse_xml_wrapper_accepts_single_quoted_attributes() {
    reset();
    msg_parse(
        "pacs.008",
        b"<ISO20022 message='pacs.008'><Field path='MsgId'>1</Field></ISO20022>",
    )
    .expect("single-quoted internal XML wrapper attributes are well-formed");
    assert_eq!(msg_get("MsgId").as_deref(), Some(b"1".as_slice()));
}
#[test]
fn msg_parse_xml_wrapper_rejects_malformed_attribute_and_tag_shapes() {
    let cases: &[(&str, &[u8])] = &[
            (
                "message attribute substring",
                br#"<ISO20022 xmessage="pacs.008"><Field path="MsgId">1</Field></ISO20022>"#,
            ),
            (
                "path attribute substring",
                br#"<ISO20022 message="pacs.008"><Field xpath="MsgId">1</Field></ISO20022>"#,
            ),
            (
                "unknown root attribute",
                br#"<ISO20022 message="pacs.008" extra="x"><Field path="MsgId">1</Field></ISO20022>"#,
            ),
            (
                "unknown field attribute",
                br#"<ISO20022 message="pacs.008"><Field path="MsgId" extra="x">1</Field></ISO20022>"#,
            ),
            (
                "unsupported field encoding",
                br#"<ISO20022 message="pacs.008"><Field path="MsgId" encoding="hex">31</Field></ISO20022>"#,
            ),
            (
                "field element prefix match",
                br#"<ISO20022 message="pacs.008"><Fieldx path="MsgId">1</Field></ISO20022>"#,
            ),
            (
                "leading non-root markup",
                br#"<Ignored/><ISO20022 message="pacs.008"></ISO20022>"#,
            ),
            (
                "trailing non-root markup",
                br#"<ISO20022 message="pacs.008"></ISO20022><Ignored/>"#,
            ),
            (
                "entity-decoded invalid field path",
                br#"<ISO20022 message="pacs.008"><Field path="Msg&lt;Id">1</Field></ISO20022>"#,
            ),
            (
                "empty field index",
                br#"<ISO20022 message="pacs.008"><Field path="TxInf[]">1</Field></ISO20022>"#,
            ),
            (
                "self-closing field",
                br#"<ISO20022 message="pacs.008"><Field path="MsgId"/></ISO20022>"#,
            ),
            (
                "raw nested field markup",
                br#"<ISO20022 message="pacs.008"><Field path="MsgId"><b>1</b></Field></ISO20022>"#,
            ),
        ];
    for (label, xml) in cases {
        reset();
        let err = match msg_parse("pacs.008", xml) {
            Ok(()) => panic!("{label} must fail internal XML wrapper parsing"),
            Err(err) => err,
        };
        assert!(
            matches!(err, MsgError::InvalidFormat),
            "{label} returned {err:?}"
        );
        assert!(super::MESSAGE_STACK.with(|stack| stack.borrow().is_empty()));
    }
}
#[test]
fn msg_serialize_xml_base64_encodes_utf8_that_is_not_xml_text() {
    reset();
    let msg_id = "bad-\u{1}-xml";
    msg_create("pacs.008");
    msg_set("MsgId", msg_id.as_bytes());
    let xml = msg_serialize("XML").expect("XML serializes");
    let xml_str = String::from_utf8(xml.clone()).expect("internal XML is UTF-8");
    assert!(xml_str.contains(r#"<Field path="MsgId" encoding="base64">"#));
    assert!(!xml_str.contains(msg_id));
    reset();
    msg_parse("pacs.008", &xml).expect("base64 internal XML parses");
    assert_eq!(msg_get("MsgId").as_deref(), Some(msg_id.as_bytes()));
}
#[test]
fn signature_blocks_marked_as_ignored() {
    reset();
    let xml = include_str!("assets/text_v1/pacs008_signature.xml");
    msg_parse("pacs.008", xml.as_bytes()).expect("parse pacs.008 with signature");
    assert_eq!(
        msg_get("Document/FIToFICstmrCdtTrf/Sgntr/@ignored").as_deref(),
        Some(SIGNATURE_IGNORED_VALUE),
    );
    assert!(msg_get("Document/FIToFICstmrCdtTrf/Sgntr/SignatureValue").is_none());
    assert!(msg_validate());
}
#[test]
fn iban_bic_and_numeric_validators() {
    assert!(validate_iban(b"GB82WEST12345698765432"));
    assert!(!validate_iban(b"GB82WEST12345698765433"));
    assert!(!validate_iban(b"NO938601111794"));
    assert!(validate_bic_str("DEUTDEFF"));
    assert!(validate_numeric(b"12345"));
    assert!(!validate_numeric(b"12a"));
}
#[test]
fn base64_encode_decode_roundtrip() {
    let data = b"hello world";
    let enc = encode_base64(data);
    assert_eq!(enc, b"aGVsbG8gd29ybGQ=".to_vec());
    assert_eq!(decode_base64(&enc), Some(data.to_vec()));
}
#[test]
fn decode_base64_rejects_invalid() {
    assert!(decode_base64(b"@@@=").is_none());
}
#[test]
fn decode_base64_into_reuses_buffer() {
    let mut out = Vec::new();
    decode_base64_into(b"SGVsbG8=", &mut out).unwrap();
    assert_eq!(out, b"Hello");
}
#[test]
fn decode_base64_into_rejects_invalid() {
    let mut out = Vec::new();
    assert!(decode_base64_into(b"@@@=", &mut out).is_none());
}

fn native_settlement_extension() -> String {
    format!(
        "<SplmtryData><Envlp><nx:NexusSettlement xmlns:nx=\"{}\"><nx:NetworkId>selected-network</nx:NetworkId><nx:ExpiresAtHeight>100</nx:ExpiresAtHeight><nx:SourceAccountId>canonical-payer</nx:SourceAccountId><nx:TargetAccountId>canonical-recipient</nx:TargetAccountId><nx:AssetDefinitionId>canonical-asset</nx:AssetDefinitionId></nx:NexusSettlement></Envlp></SplmtryData>",
        super::NEXUS_SETTLEMENT_XML_NAMESPACE,
    )
}

#[test]
fn native_settlement_xml_extension_preserves_owned_fields_and_source_binding() {
    for (message, source, closing) in [
        ("pacs.008", SAMPLE_PACS008_XML, "</FIToFICstmrCdtTrf>"),
        ("pacs.009", SAMPLE_PACS009_XML, "</FICdtTrf>"),
    ] {
        reset();
        let xml = source.replace(
            closing,
            &format!("{}{closing}", native_settlement_extension()),
        );
        let parsed = parse_xml_message(message, xml.as_bytes()).unwrap();
        assert_eq!(
            parsed.field_text("NexusSettlement/NetworkId"),
            Some("selected-network")
        );
        assert_eq!(
            parsed.field_text("NexusSettlement/ExpiresAtHeight"),
            Some("100")
        );
        for (field, value) in [
            ("NexusSettlement/SourceAccountId", "canonical-payer"),
            ("NexusSettlement/TargetAccountId", "canonical-recipient"),
            ("NexusSettlement/AssetDefinitionId", "canonical-asset"),
        ] {
            assert_eq!(parsed.field_text(field), Some(value));
        }
        assert!(parsed.fields_are_covered_by_xml_range(xml.as_bytes(), 0..xml.len()));
    }
}

#[test]
fn native_settlement_xml_extension_refuses_namespace_shape_and_duplicate_ambiguity() {
    let extension = native_settlement_extension();
    let closing = "</FIToFICstmrCdtTrf>";
    let valid = SAMPLE_PACS008_XML.replace(closing, &format!("{extension}{closing}"));
    let cases = [
        valid.replace(
            super::NEXUS_SETTLEMENT_XML_NAMESPACE,
            "urn:attacker:nexus:v1",
        ),
        valid.replace("<nx:NetworkId>", "<nx:NetworkId unexpected=\"1\">"),
        valid.replace(
            "<nx:NetworkId>selected-network</nx:NetworkId>",
            "<nx:NetworkId><nx:NetworkId>selected-network</nx:NetworkId></nx:NetworkId>",
        ),
        valid.replace("<nx:ExpiresAtHeight>100</nx:ExpiresAtHeight>", ""),
        valid.replace(
            "</nx:NexusSettlement>",
            "<nx:Unknown>100</nx:Unknown></nx:NexusSettlement>",
        ),
        valid.replace(
            "</nx:NexusSettlement>",
            "<nx:NetworkId>selected-network</nx:NetworkId></nx:NexusSettlement>",
        ),
        SAMPLE_PACS008_XML.replace(closing, &format!("{extension}{extension}{closing}")),
        SAMPLE_PACS008_XML.replace("</CdtTrfTxInf>", &format!("{extension}</CdtTrfTxInf>")),
    ];
    for xml in cases {
        reset();
        assert!(matches!(
            parse_xml_message("pacs.008", xml.as_bytes()),
            Err(MsgError::InvalidFormat)
        ));
    }
    for (field, value) in [
        ("SourceAccountId", "canonical-payer"),
        ("TargetAccountId", "canonical-recipient"),
        ("AssetDefinitionId", "canonical-asset"),
    ] {
        let element = format!("<nx:{field}>{value}</nx:{field}>");
        for xml in [
            valid.replace(&element, ""),
            valid.replace(&element, &format!("{element}{element}")),
            valid.replace(&element, &format!("<{field}>{value}</{field}>")),
            valid.replace(
                &element,
                &format!("<nx:{field} extra=\"1\">{value}</nx:{field}>"),
            ),
        ] {
            reset();
            assert!(matches!(
                parse_xml_message("pacs.008", xml.as_bytes()),
                Err(MsgError::InvalidFormat)
            ));
        }
    }
    let start = SAMPLE_PACS008_XML.find("<CdtTrfTxInf>").unwrap();
    let end = SAMPLE_PACS008_XML.find("</CdtTrfTxInf>").unwrap() + "</CdtTrfTxInf>".len();
    let duplicated = valid.replace(
        closing,
        &format!("{}{closing}", &SAMPLE_PACS008_XML[start..end]),
    );
    reset();
    assert!(matches!(
        parse_xml_message("pacs.008", duplicated.as_bytes()),
        Err(MsgError::InvalidFormat)
    ));
}
