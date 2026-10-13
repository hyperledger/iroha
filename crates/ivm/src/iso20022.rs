//! ISO 20022 message handling opcodes and bridge parser support.
//!
//! The module keeps a compact in-memory message stack for IVM opcodes while providing deterministic
//! XML and key-value parsing for the ISO bridge. XML payloads are bound to their declared ISO
//! message definition through `MsgDefIdr` and `Document` XSD namespaces before schema-table
//! validation is applied. Network transport is deliberately outside this module and outside
//! consensus execution.
use core::fmt;
use sha2::{Digest as _, Sha256};
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    io::Write,
    ops::Range,
};
#[derive(Clone, Copy, Debug)]
struct XmlFieldSource {
    start: usize,
    end: usize,
}
/// Extremely small ISO 20022 message representation used for testing.
#[derive(Clone, Default)]
struct IsoMessage {
    /// Identifier such as `pacs.008`.
    message_type: String,
    /// Flat map of field name to encoded value.
    fields: HashMap<String, Vec<u8>>,
    /// Counters for `MSG_ADD` to emulate repeating fields.
    repeats: HashMap<String, usize>,
    /// Digest of the real XML source from which the fields were materialised.
    xml_source_sha256: Option<[u8; 32]>,
    /// Byte range in the original source which owns each materialised field.
    xml_field_sources: HashMap<String, XmlFieldSource>,
}
thread_local! {
    /// Thread-local stack of ISO 20022 messages.  The most recently created
    /// or parsed message lives at the top of the stack.
    static MESSAGE_STACK: RefCell<Vec<IsoMessage>> = const { RefCell::new(Vec::new()) };
    /// Last validation failure recorded by [`msg_validate`].
    static LAST_VALIDATION_FAILURE: RefCell<Option<ValidationFailure>> =
        const { RefCell::new(None) };
}
/// Return the list of fields that must be present for the given message type.
///
/// This is a tiny stand-in for schema driven validation. Only a handful of message types are
/// recognised and each lists a couple of representative mandatory fields. The map can be extended
/// over time as more messages are supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Requirement {
    Required,
    Optional,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierKind {
    /// International Securities Identification Number (ISO 6166)
    Isin,
    /// Committee on Uniform Securities Identification Procedures
    Cusip,
    /// Legal Entity Identifier (ISO 17442)
    Lei,
    /// Business Identifier Code (ISO 9362)
    Bic,
    /// Market Identifier Code (ISO 10383)
    Mic,
    /// International Bank Account Number (ISO 13616 / 7064 checksum)
    Iban,
    /// ISO 4217 currency code
    Currency,
}
impl IdentifierKind {
    fn label(self) -> &'static str {
        match self {
            IdentifierKind::Isin => "ISIN",
            IdentifierKind::Cusip => "CUSIP",
            IdentifierKind::Lei => "LEI",
            IdentifierKind::Bic => "BIC",
            IdentifierKind::Mic => "MIC",
            IdentifierKind::Iban => "IBAN",
            IdentifierKind::Currency => "ISO 4217 currency",
        }
    }
}
impl fmt::Display for IdentifierKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldKind {
    Text,
    Numeric,
    Amount,
    Identifier(IdentifierKind),
    Instrument,
    Date,
    DateTime,
    Enum(&'static [&'static str]),
}
#[derive(Clone, Debug)]
enum InvalidReason {
    Empty,
    Numeric,
    Amount,
    Identifier(IdentifierKind),
    Instrument,
    Date,
    DateTime,
    Enum,
    Utf8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidValueKind {
    Empty,
    Numeric,
    Amount,
    Date,
    DateTime,
    Enum,
    Utf8,
}
impl InvalidValueKind {
    fn label(self) -> &'static str {
        match self {
            InvalidValueKind::Empty => "empty",
            InvalidValueKind::Numeric => "numeric",
            InvalidValueKind::Amount => "amount",
            InvalidValueKind::Date => "date",
            InvalidValueKind::DateTime => "date-time",
            InvalidValueKind::Enum => "enumerated",
            InvalidValueKind::Utf8 => "UTF-8",
        }
    }
}
impl fmt::Display for InvalidValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
#[derive(Clone, Debug)]
enum ValidationFailure {
    MissingField(&'static str),
    TooManyOccurrences {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    InvalidField {
        field: String,
        reason: InvalidReason,
    },
}
#[derive(Clone, Copy, Debug)]
struct AliasSpec {
    alias: &'static str,
    canonical: &'static str,
}
#[derive(Clone, Copy, Debug)]
struct FieldSpec {
    pattern: &'static str,
    requirement: Requirement,
    max_occurs: Option<usize>,
    kind: FieldKind,
}
impl FieldSpec {
    const fn required(pattern: &'static str, kind: FieldKind) -> Self {
        Self {
            pattern,
            requirement: Requirement::Required,
            max_occurs: None,
            kind,
        }
    }
    const fn optional(pattern: &'static str, kind: FieldKind) -> Self {
        Self {
            pattern,
            requirement: Requirement::Optional,
            max_occurs: None,
            kind,
        }
    }
    const fn limited(
        pattern: &'static str,
        min_required: bool,
        max: usize,
        kind: FieldKind,
    ) -> Self {
        Self {
            pattern,
            requirement: if min_required {
                Requirement::Required
            } else {
                Requirement::Optional
            },
            max_occurs: Some(max),
            kind,
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct MessageSchema {
    fields: &'static [FieldSpec],
    aliases: &'static [AliasSpec],
}
impl MessageSchema {
    fn field_specs(&self) -> &'static [FieldSpec] {
        self.fields
    }
    fn aliases(&self) -> &'static [AliasSpec] {
        self.aliases
    }
}
fn canonical_message_type(message_type: &str) -> Cow<'_, str> {
    let parts: Vec<&str> = message_type.split('.').collect();
    if parts.len() >= 4
        && parts[1].chars().all(|c| c.is_ascii_digit())
        && parts[2].chars().all(|c| c.is_ascii_digit())
    {
        Cow::Owned(format!("{}.{}", parts[0], parts[1]))
    } else {
        Cow::Borrowed(message_type)
    }
}
fn record_validation_failure(failure: ValidationFailure) {
    LAST_VALIDATION_FAILURE.with(|cell| {
        *cell.borrow_mut() = Some(failure);
    });
}
fn take_validation_failure() -> Option<ValidationFailure> {
    LAST_VALIDATION_FAILURE.with(|cell| cell.borrow_mut().take())
}
fn clear_validation_failure() {
    LAST_VALIDATION_FAILURE.with(|cell| {
        cell.borrow_mut().take();
    });
}
include!(concat!(env!("OUT_DIR"), "/iso20022_schema_v1.rs"));
/// Errors that can occur when parsing, validating, or serializing ISO 20022 messages.
#[derive(Debug)]
pub enum MsgError {
    NoActiveMessage,
    UnknownMessageType,
    ValidationFailed,
    MissingField(&'static str),
    TooManyOccurrences {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    InvalidIdentifier {
        field: String,
        kind: IdentifierKind,
    },
    InvalidInstrument {
        field: String,
    },
    InvalidValue {
        field: String,
        kind: InvalidValueKind,
    },
    InvalidFormat,
}
impl fmt::Display for MsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsgError::NoActiveMessage => f.write_str("no active ISO 20022 message"),
            MsgError::UnknownMessageType => f.write_str("unsupported ISO 20022 message type"),
            MsgError::ValidationFailed => f.write_str("ISO 20022 validation failed"),
            MsgError::MissingField(field) => {
                write!(f, "missing ISO 20022 field `{field}`")
            }
            MsgError::TooManyOccurrences { field, max, actual } => write!(
                f,
                "field `{field}` exceeds max occurrences ({actual} > {max})"
            ),
            MsgError::InvalidIdentifier { field, kind } => {
                write!(f, "invalid {} value for field `{field}`", kind.label())
            }
            MsgError::InvalidInstrument { field } => write!(
                f,
                "field `{field}` must contain a valid ISIN or CUSIP identifier"
            ),
            MsgError::InvalidValue { field, kind } => {
                write!(f, "invalid {} value for field `{field}`", kind.label())
            }
            MsgError::InvalidFormat => f.write_str("ISO 20022 message format is invalid"),
        }
    }
}
impl From<ValidationFailure> for MsgError {
    fn from(failure: ValidationFailure) -> Self {
        match failure {
            ValidationFailure::MissingField(field) => MsgError::MissingField(field),
            ValidationFailure::TooManyOccurrences { field, max, actual } => {
                MsgError::TooManyOccurrences { field, max, actual }
            }
            ValidationFailure::InvalidField { field, reason } => match reason {
                InvalidReason::Identifier(kind) => MsgError::InvalidIdentifier { field, kind },
                InvalidReason::Instrument => MsgError::InvalidInstrument { field },
                InvalidReason::Empty => MsgError::InvalidValue {
                    field,
                    kind: InvalidValueKind::Empty,
                },
                InvalidReason::Numeric => MsgError::InvalidValue {
                    field,
                    kind: InvalidValueKind::Numeric,
                },
                InvalidReason::Amount => MsgError::InvalidValue {
                    field,
                    kind: InvalidValueKind::Amount,
                },
                InvalidReason::Date => MsgError::InvalidValue {
                    field,
                    kind: InvalidValueKind::Date,
                },
                InvalidReason::DateTime => MsgError::InvalidValue {
                    field,
                    kind: InvalidValueKind::DateTime,
                },
                InvalidReason::Enum => MsgError::InvalidValue {
                    field,
                    kind: InvalidValueKind::Enum,
                },
                InvalidReason::Utf8 => MsgError::InvalidValue {
                    field,
                    kind: InvalidValueKind::Utf8,
                },
            },
        }
    }
}
/// Consume and return the most recent validation error recorded by [`msg_validate`].
///
/// The helper yields [`MsgError`] variants mirroring the validation failure and clears the stored
/// state so subsequent calls return `None` until [`msg_validate`] runs again.
#[must_use]
pub fn take_validation_error() -> Option<MsgError> {
    take_validation_failure().map(MsgError::from)
}
/// Materialised ISO 20022 message extracted from the VM stack.
#[derive(Clone, Debug)]
pub struct ParsedMessage {
    message_type: String,
    fields: BTreeMap<String, Vec<u8>>,
    xml_source_sha256: Option<[u8; 32]>,
    xml_field_sources: BTreeMap<String, XmlFieldSource>,
}
impl ParsedMessage {
    /// Return the ISO 20022 message code (e.g. `"pacs.008"`).
    pub fn message_type(&self) -> &str {
        &self.message_type
    }
    /// Retrieve the raw bytes stored under the canonical field path.
    pub fn field_bytes(&self, field: &str) -> Option<&[u8]> {
        self.fields.get(field).map(|v| v.as_slice())
    }
    /// Retrieve the UTF-8 string stored under the canonical field path.
    pub fn field_text(&self, field: &str) -> Option<&str> {
        self.field_bytes(field)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
    }
    /// Iterate over canonical field paths and their values.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<u8>)> {
        self.fields.iter()
    }
    /// Return whether every materialised field came from `source` inside `range`.
    ///
    /// Messages parsed from the developer-only key/value or internal XML formats,
    /// messages mutated after XML parsing, and incomplete provenance fail closed.
    #[must_use]
    pub fn fields_are_covered_by_xml_range(&self, source: &[u8], range: Range<usize>) -> bool {
        if range.start > range.end || range.end > source.len() {
            return false;
        }
        let Some(expected_digest) = self.xml_source_sha256 else {
            return false;
        };
        let actual_digest: [u8; 32] = Sha256::digest(source).into();
        expected_digest == actual_digest
            && self.xml_field_sources.len() == self.fields.len()
            && self.fields.keys().all(|field| {
                self.xml_field_sources.get(field).is_some_and(|source| {
                    source.start >= range.start
                        && source.end <= range.end
                        && source.start <= source.end
                })
            })
    }
}
fn materialise_current_message(valid: bool) -> Result<ParsedMessage, MsgError> {
    MESSAGE_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let maybe_msg = stack.pop();
        drop(stack);
        match (valid, maybe_msg) {
            (true, Some(msg)) => Ok(ParsedMessage {
                message_type: msg.message_type,
                fields: msg.fields.into_iter().collect(),
                xml_source_sha256: msg.xml_source_sha256,
                xml_field_sources: msg.xml_field_sources.into_iter().collect(),
            }),
            (false, _) => {
                let err = take_validation_failure()
                    .map(MsgError::from)
                    .unwrap_or(MsgError::ValidationFailed);
                Err(err)
            }
            (true, None) => Err(MsgError::NoActiveMessage),
        }
    })
}
/// Parse, validate, and materialise an ISO 20022 message.
///
/// This helper wraps `msg_parse`/`msg_validate` and drains the temporary VM
/// stack entry, returning an owned [`ParsedMessage`] on success.
pub fn parse_message(message_type: &str, data: &[u8]) -> Result<ParsedMessage, MsgError> {
    msg_parse(message_type, data)?;
    materialise_current_message(msg_validate())
}

/// Parse, validate, and materialise a production ISO 20022 XML message.
///
/// Unlike [`parse_message`], this entry point rejects the developer-only
/// key/value and internal `<ISO20022>` representations.
pub fn parse_xml_message(message_type: &str, data: &[u8]) -> Result<ParsedMessage, MsgError> {
    if !looks_like_xml(data) {
        return Err(MsgError::InvalidFormat);
    }
    let text = core::str::from_utf8(data).map_err(|_| MsgError::InvalidFormat)?;
    if text.trim_start().starts_with("<ISO20022") {
        return Err(MsgError::InvalidFormat);
    }
    msg_create(message_type);
    if let Err(error) = parse_real_iso20022(message_type, text) {
        MESSAGE_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
        return Err(error);
    }
    materialise_current_message(msg_validate())
}
/// Norito-friendly projections of the ISO 20022 settlement messages covered by
/// this helper. These structs make it easy to encode/decode settlement payloads
/// alongside the VM message stack without reimplementing field mapping.
pub mod norito_schemas {
    use super::{InvalidValueKind, MsgError, ParsedMessage, msg_add, msg_create, msg_set};
    use norito::codec::{Decode, Encode};
    fn required_text(parsed: &ParsedMessage, field: &'static str) -> Result<String, MsgError> {
        parsed
            .field_text(field)
            .map(str::to_owned)
            .ok_or(MsgError::MissingField(field))
    }
    fn optional_text(parsed: &ParsedMessage, field: &str) -> Option<String> {
        parsed.field_text(field).map(str::to_owned)
    }
    fn optional_bool(
        parsed: &ParsedMessage,
        field: &'static str,
    ) -> Result<Option<bool>, MsgError> {
        let Some(text) = parsed.field_text(field) else {
            return Ok(None);
        };
        match text {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(MsgError::InvalidValue {
                field: field.to_owned(),
                kind: InvalidValueKind::Enum,
            }),
        }
    }
    fn bool_bytes(value: bool) -> &'static [u8] {
        if value { b"true" } else { b"false" }
    }
    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
    pub struct Linkage {
        pub relation: String,
        pub reference: String,
    }
    /// Norito schema for `sese.023` DvP instructions.
    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
    pub struct Sese023 {
        pub tx_id: String,
        pub settlement_date: String,
        pub movement_type: String,
        pub payment_type: String,
        pub fin_instr_id: String,
        pub quantity: String,
        pub cash_amount: String,
        pub cash_currency: String,
        pub delivering_party_bic: String,
        pub delivering_account: String,
        pub receiving_party_bic: String,
        pub receiving_account: String,
        pub execution_order: String,
        pub atomicity: String,
        pub settlement_condition: Option<String>,
        pub partial_settlement_indicator: Option<String>,
        pub hold_indicator: Option<bool>,
        pub venue_mic: Option<String>,
        pub linkages: Vec<Linkage>,
        pub securities_metadata: Option<String>,
        pub cash_metadata: Option<String>,
    }
    impl Sese023 {
        /// Populate the VM message stack with this instruction.
        pub fn apply_to_stack(&self) {
            msg_create("sese.023");
            msg_set("TxId", self.tx_id.as_bytes());
            msg_set("SttlmDt", self.settlement_date.as_bytes());
            msg_set(
                "SttlmTpAndAddtlParams/SctiesMvmntTp",
                self.movement_type.as_bytes(),
            );
            msg_set("SttlmTpAndAddtlParams/Pmt", self.payment_type.as_bytes());
            if let Some(condition) = &self.settlement_condition {
                msg_set("SttlmParams/SttlmTxCond/Cd", condition.as_bytes());
            }
            if let Some(indicator) = &self.partial_settlement_indicator {
                msg_set("SttlmParams/PrtlSttlmInd", indicator.as_bytes());
            }
            if let Some(hold) = self.hold_indicator {
                msg_set("SttlmParams/HldInd", bool_bytes(hold));
            }
            if let Some(mic) = &self.venue_mic {
                msg_set("PlcOfSttlm/MktId", mic.as_bytes());
            }
            msg_set("SctiesLeg/FinInstrmId", self.fin_instr_id.as_bytes());
            msg_set("SctiesLeg/Qty", self.quantity.as_bytes());
            msg_set("CashLeg/Amt", self.cash_amount.as_bytes());
            msg_set("CashLeg/Ccy", self.cash_currency.as_bytes());
            msg_set(
                "DlvrgSttlmPties/Pty/Bic",
                self.delivering_party_bic.as_bytes(),
            );
            msg_set("DlvrgSttlmPties/Acct", self.delivering_account.as_bytes());
            msg_set(
                "RcvgSttlmPties/Pty/Bic",
                self.receiving_party_bic.as_bytes(),
            );
            msg_set("RcvgSttlmPties/Acct", self.receiving_account.as_bytes());
            msg_set("Plan/ExecutionOrder", self.execution_order.as_bytes());
            msg_set("Plan/Atomicity", self.atomicity.as_bytes());
            for (idx, linkage) in self.linkages.iter().enumerate() {
                msg_add("Lnkgs/Lnkg");
                let prefix = format!("Lnkgs/Lnkg[{idx}]");
                msg_set(
                    format!("{prefix}/Tp/Cd").as_str(),
                    linkage.relation.as_bytes(),
                );
                msg_set(
                    format!("{prefix}/Ref/Prtry").as_str(),
                    linkage.reference.as_bytes(),
                );
            }
            if let Some(meta) = &self.securities_metadata {
                msg_set("SctiesLeg/Metadata", meta.as_bytes());
            }
            if let Some(meta) = &self.cash_metadata {
                msg_set("CashLeg/Metadata", meta.as_bytes());
            }
        }
        /// Build the Norito view from a parsed and validated message.
        pub fn from_parsed(parsed: &ParsedMessage) -> Result<Self, MsgError> {
            Ok(Self {
                tx_id: required_text(parsed, "TxId")?,
                settlement_date: required_text(parsed, "SttlmDt")?,
                movement_type: required_text(parsed, "SttlmTpAndAddtlParams/SctiesMvmntTp")?,
                payment_type: required_text(parsed, "SttlmTpAndAddtlParams/Pmt")?,
                fin_instr_id: required_text(parsed, "SctiesLeg/FinInstrmId")?,
                quantity: required_text(parsed, "SctiesLeg/Qty")?,
                cash_amount: required_text(parsed, "CashLeg/Amt")?,
                cash_currency: required_text(parsed, "CashLeg/Ccy")?,
                delivering_party_bic: required_text(parsed, "DlvrgSttlmPties/Pty/Bic")?,
                delivering_account: required_text(parsed, "DlvrgSttlmPties/Acct")?,
                receiving_party_bic: required_text(parsed, "RcvgSttlmPties/Pty/Bic")?,
                receiving_account: required_text(parsed, "RcvgSttlmPties/Acct")?,
                execution_order: required_text(parsed, "Plan/ExecutionOrder")?,
                atomicity: required_text(parsed, "Plan/Atomicity")?,
                settlement_condition: optional_text(parsed, "SttlmParams/SttlmTxCond/Cd"),
                partial_settlement_indicator: optional_text(parsed, "SttlmParams/PrtlSttlmInd"),
                hold_indicator: optional_bool(parsed, "SttlmParams/HldInd")?,
                venue_mic: optional_text(parsed, "PlcOfSttlm/MktId"),
                linkages: collect_linkages(parsed),
                securities_metadata: optional_text(parsed, "SctiesLeg/Metadata"),
                cash_metadata: optional_text(parsed, "CashLeg/Metadata"),
            })
        }
    }
    fn collect_linkages(parsed: &ParsedMessage) -> Vec<Linkage> {
        let mut linkages = Vec::new();
        let mut idx = 0usize;
        loop {
            let tp_field = format!("Lnkgs/Lnkg[{idx}]/Tp/Cd");
            let ref_field = format!("Lnkgs/Lnkg[{idx}]/Ref/Prtry");
            let Some(tp) = parsed.field_text(&tp_field) else {
                break;
            };
            let reference = parsed.field_text(&ref_field).unwrap_or_default().to_owned();
            linkages.push(Linkage {
                relation: tp.to_owned(),
                reference,
            });
            idx += 1;
        }
        linkages
    }
    /// Norito schema for `sese.025` PvP confirmations.
    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
    pub struct Sese025 {
        pub tx_id: String,
        pub settlement_date: String,
        pub movement_type: String,
        pub payment_type: String,
        pub confirmation_status: String,
        pub settlement_quantity: String,
        pub settlement_amount: String,
        pub settlement_currency: String,
        pub security_id: Option<String>,
        pub security_quantity: Option<String>,
        pub delivering_party_bic: Option<String>,
        pub delivering_account: Option<String>,
        pub receiving_party_bic: Option<String>,
        pub receiving_account: Option<String>,
        pub execution_order: String,
        pub atomicity: String,
        pub hold_indicator: Option<bool>,
        pub partial_settlement_indicator: Option<String>,
        pub settlement_condition: Option<String>,
        pub venue_mic: Option<String>,
        pub reason_code: Option<String>,
        pub additional_info: Option<String>,
    }
    impl Sese025 {
        /// Populate the VM stack with a confirmation message.
        pub fn apply_to_stack(&self) {
            msg_create("sese.025");
            msg_set("TxId", self.tx_id.as_bytes());
            msg_set("SttlmDt", self.settlement_date.as_bytes());
            msg_set(
                "SttlmTpAndAddtlParams/SctiesMvmntTp",
                self.movement_type.as_bytes(),
            );
            msg_set("SttlmTpAndAddtlParams/Pmt", self.payment_type.as_bytes());
            msg_set("ConfSts", self.confirmation_status.as_bytes());
            msg_set("SttlmQty", self.settlement_quantity.as_bytes());
            msg_set("SttlmAmt", self.settlement_amount.as_bytes());
            msg_set("SttlmCcy", self.settlement_currency.as_bytes());
            if let Some(id) = &self.security_id {
                msg_set("SctiesLeg/FinInstrmId", id.as_bytes());
            }
            if let Some(qty) = &self.security_quantity {
                msg_set("SctiesLeg/Qty", qty.as_bytes());
            }
            if let Some(bic) = &self.delivering_party_bic {
                msg_set("DlvrgSttlmPties/Pty/Bic", bic.as_bytes());
            }
            if let Some(acct) = &self.delivering_account {
                msg_set("DlvrgSttlmPties/Acct", acct.as_bytes());
            }
            if let Some(bic) = &self.receiving_party_bic {
                msg_set("RcvgSttlmPties/Pty/Bic", bic.as_bytes());
            }
            if let Some(acct) = &self.receiving_account {
                msg_set("RcvgSttlmPties/Acct", acct.as_bytes());
            }
            msg_set("Plan/ExecutionOrder", self.execution_order.as_bytes());
            msg_set("Plan/Atomicity", self.atomicity.as_bytes());
            if let Some(hold) = self.hold_indicator {
                msg_set("SttlmParams/HldInd", bool_bytes(hold));
            }
            if let Some(indicator) = &self.partial_settlement_indicator {
                msg_set("SttlmParams/PrtlSttlmInd", indicator.as_bytes());
            }
            if let Some(condition) = &self.settlement_condition {
                msg_set("SttlmParams/SttlmTxCond/Cd", condition.as_bytes());
            }
            if let Some(mic) = &self.venue_mic {
                msg_set("PlcOfSttlm/MktId", mic.as_bytes());
            }
            if let Some(reason) = &self.reason_code {
                msg_set("RsnCd", reason.as_bytes());
            }
            if let Some(info) = &self.additional_info {
                msg_set("AddtlInf", info.as_bytes());
            }
        }
        /// Convert a parsed message into the Norito struct.
        pub fn from_parsed(parsed: &ParsedMessage) -> Result<Self, MsgError> {
            Ok(Self {
                tx_id: required_text(parsed, "TxId")?,
                settlement_date: required_text(parsed, "SttlmDt")?,
                movement_type: required_text(parsed, "SttlmTpAndAddtlParams/SctiesMvmntTp")?,
                payment_type: required_text(parsed, "SttlmTpAndAddtlParams/Pmt")?,
                confirmation_status: required_text(parsed, "ConfSts")?,
                settlement_quantity: required_text(parsed, "SttlmQty")?,
                settlement_amount: required_text(parsed, "SttlmAmt")?,
                settlement_currency: required_text(parsed, "SttlmCcy")?,
                security_id: optional_text(parsed, "SctiesLeg/FinInstrmId"),
                security_quantity: optional_text(parsed, "SctiesLeg/Qty"),
                delivering_party_bic: optional_text(parsed, "DlvrgSttlmPties/Pty/Bic"),
                delivering_account: optional_text(parsed, "DlvrgSttlmPties/Acct"),
                receiving_party_bic: optional_text(parsed, "RcvgSttlmPties/Pty/Bic"),
                receiving_account: optional_text(parsed, "RcvgSttlmPties/Acct"),
                execution_order: required_text(parsed, "Plan/ExecutionOrder")?,
                atomicity: required_text(parsed, "Plan/Atomicity")?,
                hold_indicator: optional_bool(parsed, "SttlmParams/HldInd")?,
                partial_settlement_indicator: optional_text(parsed, "SttlmParams/PrtlSttlmInd"),
                settlement_condition: optional_text(parsed, "SttlmParams/SttlmTxCond/Cd"),
                venue_mic: optional_text(parsed, "PlcOfSttlm/MktId"),
                reason_code: optional_text(parsed, "RsnCd"),
                additional_info: optional_text(parsed, "AddtlInf"),
            })
        }
    }
    /// Norito schema for collateral substitution confirmations.
    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
    pub struct Colr012 {
        pub tx_id: String,
        pub obligation_id: String,
        pub original_amount: String,
        pub original_currency: String,
        pub substitute_amount: String,
        pub substitute_currency: String,
        pub haircut: Option<String>,
        pub effective_date: String,
        pub substitution_type: String,
        pub original_fin_instr_id: Option<String>,
        pub substitute_fin_instr_id: Option<String>,
        pub reason_code: Option<String>,
    }
    impl Colr012 {
        /// Populate the VM stack with a substitution confirmation.
        pub fn apply_to_stack(&self) {
            msg_create("colr.012");
            msg_set("TxId", self.tx_id.as_bytes());
            msg_set("OblgtnId", self.obligation_id.as_bytes());
            msg_set("Substitution/OriginalAmt", self.original_amount.as_bytes());
            msg_set(
                "Substitution/OriginalCcy",
                self.original_currency.as_bytes(),
            );
            msg_set(
                "Substitution/SubstituteAmt",
                self.substitute_amount.as_bytes(),
            );
            msg_set(
                "Substitution/SubstituteCcy",
                self.substitute_currency.as_bytes(),
            );
            if let Some(haircut) = &self.haircut {
                msg_set("Substitution/Haircut", haircut.as_bytes());
            }
            msg_set("Substitution/EffectiveDt", self.effective_date.as_bytes());
            msg_set("Substitution/Type", self.substitution_type.as_bytes());
            if let Some(id) = &self.original_fin_instr_id {
                msg_set("Substitution/OriginalFinInstrmId", id.as_bytes());
            }
            if let Some(id) = &self.substitute_fin_instr_id {
                msg_set("Substitution/SubstituteFinInstrmId", id.as_bytes());
            }
            if let Some(reason) = &self.reason_code {
                msg_set("Substitution/ReasonCd", reason.as_bytes());
            }
        }
        /// Convert a parsed message into the Norito struct.
        pub fn from_parsed(parsed: &ParsedMessage) -> Result<Self, MsgError> {
            Ok(Self {
                tx_id: required_text(parsed, "TxId")?,
                obligation_id: required_text(parsed, "OblgtnId")?,
                original_amount: required_text(parsed, "Substitution/OriginalAmt")?,
                original_currency: required_text(parsed, "Substitution/OriginalCcy")?,
                substitute_amount: required_text(parsed, "Substitution/SubstituteAmt")?,
                substitute_currency: required_text(parsed, "Substitution/SubstituteCcy")?,
                haircut: optional_text(parsed, "Substitution/Haircut"),
                effective_date: required_text(parsed, "Substitution/EffectiveDt")?,
                substitution_type: required_text(parsed, "Substitution/Type")?,
                original_fin_instr_id: optional_text(parsed, "Substitution/OriginalFinInstrmId"),
                substitute_fin_instr_id: optional_text(
                    parsed,
                    "Substitution/SubstituteFinInstrmId",
                ),
                reason_code: optional_text(parsed, "Substitution/ReasonCd"),
            })
        }
    }
}
fn parse_index(segment: &str) -> Option<(&str, usize)> {
    let (name, rest) = segment.split_once('[')?;
    let idx_str = rest.strip_suffix(']')?;
    if idx_str.is_empty() {
        return None;
    }
    Some((name, idx_str.parse().ok()?))
}
fn pattern_matches(pattern: &str, field: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let field_parts: Vec<&str> = field.split('/').collect();
    if pattern_parts.len() != field_parts.len() {
        return false;
    }
    pattern_parts
        .iter()
        .zip(field_parts.iter())
        .all(|(pat, actual)| {
            if let Some(base) = pat.strip_suffix("[*]") {
                parse_index(actual).is_some_and(|(name, _)| name == base)
            } else {
                pat == actual
            }
        })
}
fn repeating_base(pattern: &'static str) -> Option<&'static str> {
    let idx = pattern.find("[*]")?;
    let base = &pattern[..idx];
    Some(base.strip_suffix('/').unwrap_or(base))
}
fn resolve_alias(schema: &MessageSchema, field: &str) -> Option<String> {
    if schema
        .field_specs()
        .iter()
        .any(|spec| pattern_matches(spec.pattern, field))
    {
        return Some(field.to_owned());
    }
    for alias in schema.aliases() {
        if alias.alias == field {
            return Some(alias.canonical.to_owned());
        }
        if pattern_matches(alias.alias, field) {
            let field_parts: Vec<&str> = field.split('/').collect();
            let alias_parts: Vec<&str> = alias.alias.split('/').collect();
            let filtered_parts: Vec<&str> = field_parts
                .iter()
                .copied()
                .filter(|part| !part.starts_with('@'))
                .collect();
            let canonical_parts: Vec<&str> = alias.canonical.split('/').collect();
            if canonical_parts.len() <= filtered_parts.len() {
                let offset = filtered_parts.len().saturating_sub(canonical_parts.len());
                let mut out = Vec::with_capacity(canonical_parts.len());
                for (i, canon) in canonical_parts.iter().enumerate() {
                    if let Some(base_for_index) = canon.strip_suffix("[*]") {
                        let field_part = alias_parts
                            .iter()
                            .position(|part| part.trim_end_matches("[*]") == base_for_index)
                            .and_then(|idx| filtered_parts.get(idx))
                            .or_else(|| filtered_parts.get(offset + i));
                        if let Some(field_part) = field_part
                            && let Some((_, idx)) = parse_index(field_part)
                        {
                            out.push(format!("{base_for_index}[{idx}]"));
                        } else {
                            out.push(base_for_index.to_owned());
                        }
                    } else {
                        out.push((*canon).to_owned());
                    }
                }
                return Some(out.join("/"));
            }
        }
        if alias.alias.ends_with("[*]") {
            let base = alias.alias.trim_end_matches("[*]");
            if let Some(rest) = field.strip_prefix(base) {
                let canonical_base = alias.canonical.trim_end_matches("[*]");
                return Some(format!("{canonical_base}{rest}"));
            }
        }
    }
    None
}
fn canonical_field_name(message_type: &str, field: &str) -> String {
    schema_for(message_type)
        .and_then(|schema| resolve_alias(schema, field))
        .unwrap_or_else(|| field.to_owned())
}
fn canonical_repeating_base(message_type: &str, base: &str) -> String {
    if let Some(schema) = schema_for(message_type) {
        if let Some(resolved) = resolve_alias(schema, base) {
            return resolved;
        }
        if schema
            .field_specs()
            .iter()
            .filter_map(|spec| repeating_base(spec.pattern))
            .any(|candidate| candidate == base)
        {
            return base.to_owned();
        }
    }
    base.to_owned()
}
#[derive(Clone, Copy)]
struct IbanSpec {
    code: [u8; 2],
    length: u8,
}
/// Source: IBAN Registry (June 2024). Keep alphabetically sorted so
/// `iban_length_for_country` can binary-search deterministically.
const IBAN_SPEC_BYTES: &[u8; 234] = include_bytes!("assets/iso20022_iban_specs_v1.bin");
const fn decode_iban_specs(bytes: &[u8; 234]) -> [IbanSpec; 78] {
    let mut specs = [IbanSpec {
        code: [0_u8; 2],
        length: 0,
    }; 78];
    let mut index = 0;
    while index < 78 {
        let offset = index * 3;
        specs[index] = IbanSpec {
            code: [bytes[offset], bytes[offset + 1]],
            length: bytes[offset + 2],
        };
        index += 1;
    }
    specs
}
const IBAN_SPEC_VALUES: [IbanSpec; 78] = decode_iban_specs(IBAN_SPEC_BYTES);
const IBAN_SPECS: &[IbanSpec] = &IBAN_SPEC_VALUES;
fn iban_length_for_country(code: [u8; 2]) -> Option<usize> {
    IBAN_SPECS
        .binary_search_by(|spec| spec.code.cmp(&code))
        .ok()
        .map(|idx| IBAN_SPECS[idx].length as usize)
}
/// Validate an IBAN using the ISO 7064 mod 97-10 algorithm with
/// country-specific length checks and digit validation for the check byte pair.
fn validate_iban(value: &[u8]) -> bool {
    if value.len() < 4 {
        return false;
    }
    let mut normalized = Vec::with_capacity(value.len());
    for &byte in value {
        match byte {
            b'0'..=b'9' => normalized.push(byte),
            b'A'..=b'Z' => normalized.push(byte),
            b'a'..=b'z' => normalized.push(byte.to_ascii_uppercase()),
            _ => return false,
        }
    }
    if normalized.len() < 4 {
        return false;
    }
    let country = [normalized[0], normalized[1]];
    let expected_len = match iban_length_for_country(country) {
        Some(len) => len,
        None => return false,
    };
    if normalized.len() != expected_len {
        return false;
    }
    if !normalized[2].is_ascii_digit() || !normalized[3].is_ascii_digit() {
        return false;
    }
    // Rotate the country code and check digits to the end before running mod 97.
    normalized.rotate_left(4);
    let mut acc: u32 = 0;
    for byte in normalized {
        match byte {
            b'0'..=b'9' => acc = (acc * 10 + u32::from(byte - b'0')) % 97,
            b'A'..=b'Z' => acc = (acc * 100 + u32::from(byte - b'A' + 10)) % 97,
            _ => return false,
        }
    }
    acc == 1
}
/// Validate a BIC. The check is deliberately lightweight: it enforces
/// an uppercase alphanumeric string of length 8 or 11 as per ISO 9362 but
/// does not verify country codes or institution existence.
fn validate_bic_str(value: &str) -> bool {
    let bytes = value.as_bytes();
    let len = bytes.len();
    if !(len == 8 || len == 11) {
        return false;
    }
    for &b in bytes {
        if !b.is_ascii_alphanumeric() {
            return false;
        }
    }
    if !bytes[..4].iter().all(|&b| b.is_ascii_uppercase()) {
        return false;
    }
    if !bytes[4..6].iter().all(|&b| b.is_ascii_uppercase()) {
        return false;
    }
    if !bytes[6..8]
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return false;
    }
    if len == 11
        && !bytes[8..11]
            .iter()
            .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return false;
    }
    true
}
fn validate_amount(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut digits = 0;
    let mut dot = 0;
    for b in value {
        match b {
            b'0'..=b'9' => digits += 1,
            b'.' => {
                dot += 1;
                if dot > 1 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    if digits == 0 {
        return false;
    }
    if dot == 1 {
        let s = match core::str::from_utf8(value) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut parts = s.split('.');
        let whole = parts.next().unwrap_or("");
        let frac = parts.next().unwrap_or("");
        if parts.next().is_some() {
            return false;
        }
        if whole.is_empty() {
            return false;
        }
        frac.len() <= 5
    } else {
        true
    }
}
const VALID_CURRENCY_CODES: &[&str] = &[
    "AED", "AFN", "ALL", "AMD", "ANG", "AOA", "ARS", "AUD", "AWG", "AZN", "BAM", "BBD", "BDT",
    "BGN", "BHD", "BIF", "BMD", "BND", "BOB", "BOV", "BRL", "BSD", "BTN", "BWP", "BYN", "BZD",
    "CAD", "CDF", "CHE", "CHF", "CHW", "CLF", "CLP", "CNY", "COP", "COU", "CRC", "CUC", "CUP",
    "CVE", "CZK", "DJF", "DKK", "DOP", "DZD", "EGP", "ERN", "ETB", "EUR", "FJD", "FKP", "GBP",
    "GEL", "GHS", "GIP", "GMD", "GNF", "GTQ", "GYD", "HKD", "HNL", "HRK", "HTG", "HUF", "IDR",
    "ILS", "INR", "IQD", "IRR", "ISK", "JMD", "JOD", "JPY", "KES", "KGS", "KHR", "KMF", "KPW",
    "KRW", "KWD", "KYD", "KZT", "LAK", "LBP", "LKR", "LRD", "LSL", "LYD", "MAD", "MDL", "MGA",
    "MKD", "MMK", "MNT", "MOP", "MRU", "MUR", "MVR", "MWK", "MXN", "MXV", "MYR", "MZN", "NAD",
    "NGN", "NIO", "NOK", "NPR", "NZD", "OMR", "PAB", "PEN", "PGK", "PHP", "PKR", "PLN", "PYG",
    "QAR", "RON", "RSD", "RUB", "RWF", "SAR", "SBD", "SCR", "SDG", "SEK", "SGD", "SHP", "SLL",
    "SOS", "SRD", "SSP", "STN", "SVC", "SYP", "SZL", "THB", "TJS", "TMT", "TND", "TOP", "TRY",
    "TTD", "TWD", "TZS", "UAH", "UGX", "USD", "USN", "UYI", "UYU", "UYW", "UZS", "VED", "VES",
    "VND", "VUV", "WST", "XAF", "XAG", "XAU", "XBA", "XBB", "XBC", "XBD", "XCD", "XDR", "XOF",
    "XPD", "XPF", "XPT", "XSU", "XTS", "XUA", "XXX", "YER", "ZAR", "ZMW", "ZWL",
];
fn validate_currency_str(value: &str) -> bool {
    if value.len() != 3 {
        return false;
    }
    if !value.chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }
    VALID_CURRENCY_CODES.binary_search(&value).is_ok()
}
fn validate_mic_str(value: &str) -> bool {
    if value.len() != 4 {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_uppercase() || !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}
fn luhn_sum_from_digits(digits: impl DoubleEndedIterator<Item = u32>) -> u32 {
    let mut sum = 0;
    let mut double = true;
    for mut value in digits {
        if double {
            value *= 2;
            if value >= 10 {
                sum += value / 10 + value % 10;
            } else {
                sum += value;
            }
        } else {
            sum += value;
        }
        double = !double;
    }
    sum
}
fn validate_isin_str(value: &str) -> bool {
    if value.len() != 12 {
        return false;
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if value.chars().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    let mut digits = Vec::with_capacity(24);
    for ch in value.chars() {
        if let Some(d) = ch.to_digit(10) {
            digits.push(d);
        } else if ch.is_ascii_uppercase() {
            let mapped = 10 + (ch as u32 - 'A' as u32);
            if (10..36).contains(&mapped) {
                if mapped >= 20 {
                    digits.push(mapped / 10);
                } else {
                    digits.push(1);
                }
                digits.push(mapped % 10);
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    let check = digits.pop().unwrap_or(0);
    let sum = luhn_sum_from_digits(digits.into_iter().rev());
    (sum + check) % 10 == 0
}
fn cusip_char_value(ch: char) -> Option<u32> {
    match ch {
        '0'..='9' => Some(ch as u32 - '0' as u32),
        'A'..='Z' => Some(ch as u32 - 'A' as u32 + 10),
        '*' => Some(36),
        '@' => Some(37),
        '#' => Some(38),
        _ => None,
    }
}
fn validate_cusip_str(value: &str) -> bool {
    if value.len() != 9 {
        return false;
    }
    if value.chars().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    let value = value.to_ascii_uppercase();
    let mut sum = 0u32;
    for (idx, ch) in value.chars().take(8).enumerate() {
        let mut val = match cusip_char_value(ch) {
            Some(v) => v,
            None => return false,
        };
        if idx % 2 == 1 {
            val *= 2;
        }
        sum += val / 10 + val % 10;
    }
    let check_char = value.chars().nth(8).unwrap_or('0');
    let check_digit = match check_char.to_digit(10) {
        Some(d) => d,
        None => return false,
    };
    (sum + check_digit).is_multiple_of(10)
}
fn validate_lei_str(value: &str) -> bool {
    if value.len() != 20 {
        return false;
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if value.chars().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    let upper = value.to_ascii_uppercase();
    let mut remainder: u32 = 0;
    for ch in upper.chars() {
        if let Some(d) = ch.to_digit(10) {
            remainder = (remainder * 10 + d) % 97;
        } else if ch.is_ascii_uppercase() {
            let mapped = 10 + (ch as u32 - 'A' as u32);
            remainder = (remainder * 100 + mapped) % 97;
        } else {
            return false;
        }
    }
    remainder == 1
}
pub fn validate_identifier(kind: IdentifierKind, value: &str) -> bool {
    match kind {
        IdentifierKind::Isin => validate_isin_str(value),
        IdentifierKind::Cusip => validate_cusip_str(value),
        IdentifierKind::Lei => validate_lei_str(value),
        IdentifierKind::Bic => validate_bic_str(value),
        IdentifierKind::Mic => validate_mic_str(value),
        IdentifierKind::Iban => validate_iban(value.as_bytes()),
        IdentifierKind::Currency => validate_currency_str(value),
    }
}
pub fn validate_instrument_identifier(value: &str) -> bool {
    validate_identifier(IdentifierKind::Isin, value)
        || validate_identifier(IdentifierKind::Cusip, value)
}
fn validate_numeric(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(|b| b.is_ascii_digit())
}
fn parse_ascii_u32(slice: &[u8]) -> Option<u32> {
    if slice.is_empty() {
        return None;
    }
    let mut acc = 0u32;
    for &b in slice {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc * 10 + u32::from(b - b'0');
    }
    Some(acc)
}
fn validate_date(value: &[u8]) -> bool {
    if value.len() != 10 {
        return false;
    }
    if value[4] != b'-' || value[7] != b'-' {
        return false;
    }
    let year = match parse_ascii_u32(&value[0..4]) {
        Some(v) => v,
        None => return false,
    };
    let month = match parse_ascii_u32(&value[5..7]) {
        Some(v) => v,
        None => return false,
    };
    let day = match parse_ascii_u32(&value[8..10]) {
        Some(v) => v,
        None => return false,
    };
    if !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
        _ => return false,
    };
    day <= max_day
}
fn validate_offset(offset: &str) -> bool {
    if offset.len() != 6 {
        return false;
    }
    let mut chars = offset.chars();
    let sign = chars.next().unwrap_or('+');
    if sign != '+' && sign != '-' {
        return false;
    }
    let hour_tens = chars.next().and_then(|c| c.to_digit(10));
    let hour_ones = chars.next().and_then(|c| c.to_digit(10));
    if chars.next() != Some(':') {
        return false;
    }
    let min_tens = chars.next().and_then(|c| c.to_digit(10));
    let min_ones = chars.next().and_then(|c| c.to_digit(10));
    if chars.next().is_some() {
        return false;
    }
    let hour = match (hour_tens, hour_ones) {
        (Some(t), Some(o)) => t * 10 + o,
        _ => return false,
    };
    let minute = match (min_tens, min_ones) {
        (Some(t), Some(o)) => t * 10 + o,
        _ => return false,
    };
    hour <= 23 && minute <= 59
}
fn validate_datetime(value: &[u8]) -> bool {
    let s = match core::str::from_utf8(value) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (date_part, rest) = match s.split_once('T') {
        Some(parts) => parts,
        None => return false,
    };
    if !validate_date(date_part.as_bytes()) {
        return false;
    }
    let (time_part, tz_part) = if let Some(v) = rest.strip_suffix('Z') {
        (v, None)
    } else if let Some(pos) = rest.rfind(['+', '-']) {
        (rest[..pos].trim_end_matches('Z'), Some(&rest[pos..]))
    } else {
        (rest, None)
    };
    let mut pieces = time_part.split(':');
    let hour = match pieces.next() {
        Some(v) if v.len() == 2 => match v.parse::<u32>() {
            Ok(v) => v,
            Err(_) => return false,
        },
        _ => return false,
    };
    let minute = match pieces.next() {
        Some(v) if v.len() == 2 => match v.parse::<u32>() {
            Ok(v) => v,
            Err(_) => return false,
        },
        _ => return false,
    };
    let sec_fragment = match pieces.next() {
        Some(v) => v,
        None => return false,
    };
    if pieces.next().is_some() {
        return false;
    }
    let (second_str, fraction_ok) = if let Some((sec, frac)) = sec_fragment.split_once('.') {
        (
            sec,
            !frac.is_empty() && frac.len() <= 6 && frac.chars().all(|c| c.is_ascii_digit()),
        )
    } else {
        (sec_fragment, true)
    };
    if !fraction_ok || second_str.len() != 2 {
        return false;
    }
    let second = match second_str.parse::<u32>() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let tz_ok = if let Some(offset) = tz_part {
        validate_offset(offset)
    } else {
        true
    };
    tz_ok && hour <= 23 && minute <= 59 && second <= 60
}
fn validate_identifier_bytes(kind: IdentifierKind, value: &[u8]) -> Result<(), InvalidReason> {
    let text = core::str::from_utf8(value).map_err(|_| InvalidReason::Utf8)?;
    if validate_identifier(kind, text) {
        Ok(())
    } else {
        Err(InvalidReason::Identifier(kind))
    }
}
fn validate_instrument_bytes(value: &[u8]) -> Result<(), InvalidReason> {
    let text = core::str::from_utf8(value).map_err(|_| InvalidReason::Utf8)?;
    if validate_identifier(IdentifierKind::Isin, text)
        || validate_identifier(IdentifierKind::Cusip, text)
    {
        Ok(())
    } else {
        Err(InvalidReason::Instrument)
    }
}
fn validate_field(kind: FieldKind, value: &[u8]) -> Result<(), InvalidReason> {
    match kind {
        FieldKind::Text => {
            if value.is_empty() {
                Err(InvalidReason::Empty)
            } else {
                Ok(())
            }
        }
        FieldKind::Numeric => {
            if validate_numeric(value) {
                Ok(())
            } else {
                Err(InvalidReason::Numeric)
            }
        }
        FieldKind::Amount => {
            if validate_amount(value) {
                Ok(())
            } else {
                Err(InvalidReason::Amount)
            }
        }
        FieldKind::Identifier(kind) => validate_identifier_bytes(kind, value),
        FieldKind::Instrument => validate_instrument_bytes(value),
        FieldKind::Date => {
            if validate_date(value) {
                Ok(())
            } else {
                Err(InvalidReason::Date)
            }
        }
        FieldKind::DateTime => {
            if validate_datetime(value) {
                Ok(())
            } else {
                Err(InvalidReason::DateTime)
            }
        }
        FieldKind::Enum(options) => {
            if options.iter().any(|opt| opt.as_bytes() == value) {
                Ok(())
            } else {
                Err(InvalidReason::Enum)
            }
        }
    }
}
fn proxy_fallback_match<'a>(
    pattern: &str,
    message: &'a IsoMessage,
) -> Option<(&'a String, &'a Vec<u8>, FieldKind)> {
    match pattern {
        "DbtrAcct" => message
            .fields
            .get_key_value("DbtrAcct/Prxy/Id")
            .map(|(field, value)| (field, value, FieldKind::Text)),
        "CdtrAcct" => message
            .fields
            .get_key_value("CdtrAcct/Prxy/Id")
            .map(|(field, value)| (field, value, FieldKind::Text)),
        "CreDtTm" if canonical_message_type(&message.message_type).as_ref() == "pacs.009" => {
            message
                .fields
                .get_key_value("AppHdr/CreDt")
                .map(|(field, value)| (field, value, FieldKind::DateTime))
        }
        _ => None,
    }
}
fn validate_message_against_schema(
    message: &IsoMessage,
    schema: &MessageSchema,
) -> Result<(), ValidationFailure> {
    for spec in schema.field_specs() {
        let mut matches: Vec<(&String, &Vec<u8>, FieldKind)> = message
            .fields
            .iter()
            .filter(|(field, _)| pattern_matches(spec.pattern, field))
            .map(|(field, value)| (field, value, spec.kind))
            .collect();
        if matches.is_empty()
            && let Some(fallback) = proxy_fallback_match(spec.pattern, message)
        {
            matches.push(fallback);
        }
        if matches.is_empty() && matches!(spec.requirement, Requirement::Required) {
            return Err(ValidationFailure::MissingField(spec.pattern));
        }
        if let Some(max) = spec.max_occurs
            && matches.len() > max
        {
            return Err(ValidationFailure::TooManyOccurrences {
                field: spec.pattern,
                max,
                actual: matches.len(),
            });
        }
        for (field, value, kind) in matches {
            if let Err(reason) = validate_field(kind, value) {
                return Err(ValidationFailure::InvalidField {
                    field: field.clone(),
                    reason,
                });
            }
        }
    }
    Ok(())
}
fn collect_fields_in_order<'a>(
    message: &'a IsoMessage,
    schema: Option<&'static MessageSchema>,
) -> Vec<(&'a String, &'a Vec<u8>, usize)> {
    let mut pairs: Vec<(&String, &Vec<u8>, usize)> = message
        .fields
        .iter()
        .map(|(key, value)| {
            let order = schema
                .and_then(|s| {
                    s.field_specs()
                        .iter()
                        .position(|spec| pattern_matches(spec.pattern, key))
                })
                .unwrap_or(usize::MAX);
            (key, value, order)
        })
        .collect();
    pairs.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(b.0)));
    pairs
}
fn escape_xml_text(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}
fn escape_xml_attr(input: &str) -> String {
    escape_xml_text(input)
}
fn serialize_key_value(message: &IsoMessage, schema: Option<&'static MessageSchema>) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, (key, value, _)) in collect_fields_in_order(message, schema)
        .into_iter()
        .enumerate()
    {
        if i != 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value);
    }
    out
}
fn serialize_xml(message: &IsoMessage, schema: Option<&'static MessageSchema>) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = write!(out, "<ISO20022 message=\"{}\">", message.message_type);
    for (key, value, _) in collect_fields_in_order(message, schema) {
        let path = escape_xml_attr(key);
        if let Ok(text) = core::str::from_utf8(value)
            && contains_only_xml_characters(text)
        {
            let escaped = escape_xml_text(text);
            let _ = write!(out, "<Field path=\"{path}\">{escaped}</Field>");
            continue;
        }
        let encoded = encode_base64(value);
        let encoded_str = String::from_utf8(encoded).unwrap_or_default();
        let _ = write!(
            out,
            "<Field path=\"{path}\" encoding=\"base64\">{encoded_str}</Field>"
        );
    }
    out.extend_from_slice(b"</ISO20022>");
    out
}
fn looks_like_xml(data: &[u8]) -> bool {
    data.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'<')
}
fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}
const ISO_20022_XSD_NAMESPACE_PREFIX: &str = "urn:iso:std:iso:20022:tech:xsd:";
fn message_type_from_namespace(ns: &str) -> Option<String> {
    ns.strip_prefix(ISO_20022_XSD_NAMESPACE_PREFIX)
        .filter(|message_type| !message_type.is_empty())
        .map(str::to_owned)
}
fn namespace_bindings(attrs: &[(String, String)]) -> Vec<(String, String)> {
    attrs
        .iter()
        .filter_map(|(name, value)| {
            if name == "xmlns" {
                Some(("".to_owned(), value.to_owned()))
            } else {
                name.strip_prefix("xmlns:")
                    .map(|prefix| (prefix.to_owned(), value.to_owned()))
            }
        })
        .collect()
}
fn namespace_uri_for_prefix<'a>(
    prefix: &str,
    attrs: &'a [(String, String)],
    namespace_scopes: &'a [Vec<(String, String)>],
) -> Option<&'a str> {
    if prefix == "xml" {
        return Some("http://www.w3.org/XML/1998/namespace");
    }
    attrs
        .iter()
        .rev()
        .find_map(|(name, value)| {
            if prefix.is_empty() && name == "xmlns" {
                Some(value.as_str())
            } else if let Some(bound_prefix) = name.strip_prefix("xmlns:") {
                (bound_prefix == prefix).then_some(value.as_str())
            } else {
                None
            }
        })
        .or_else(|| {
            namespace_scopes.iter().rev().find_map(|scope| {
                scope.iter().rev().find_map(|(bound_prefix, value)| {
                    (bound_prefix == prefix).then_some(value.as_str())
                })
            })
        })
}
fn element_namespace_uri<'a>(
    name: &str,
    attrs: &'a [(String, String)],
    namespace_scopes: &'a [Vec<(String, String)>],
) -> Result<Option<&'a str>, MsgError> {
    if let Some((prefix, local)) = name.split_once(':') {
        if prefix.is_empty() || local.is_empty() {
            return Err(MsgError::InvalidFormat);
        }
        return namespace_uri_for_prefix(prefix, attrs, namespace_scopes)
            .map(Some)
            .ok_or(MsgError::InvalidFormat);
    }
    Ok(namespace_uri_for_prefix("", attrs, namespace_scopes))
}
fn is_versioned_message_definition_id(message_type: &str) -> bool {
    let mut parts = message_type.split('.');
    let (Some(_business_area), Some(number), Some(variant), Some(version)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    parts.next().is_none()
        && number.len() == 3
        && variant.len() == 3
        && version.len() == 2
        && number.chars().all(|c| c.is_ascii_digit())
        && variant.chars().all(|c| c.is_ascii_digit())
        && version.chars().all(|c| c.is_ascii_digit())
}
fn declared_message_definitions_match(first: &str, second: &str) -> bool {
    if is_versioned_message_definition_id(first) || is_versioned_message_definition_id(second) {
        first.eq_ignore_ascii_case(second)
    } else {
        canonical_message_type(first)
            .as_ref()
            .eq_ignore_ascii_case(canonical_message_type(second).as_ref())
    }
}
fn requested_message_matches_declaration(requested: &str, declared: &str) -> bool {
    if is_versioned_message_definition_id(requested) {
        requested.eq_ignore_ascii_case(declared)
    } else {
        canonical_message_type(requested)
            .as_ref()
            .eq_ignore_ascii_case(canonical_message_type(declared).as_ref())
    }
}
fn observe_declared_message_type(
    declared_message_type: &mut Option<String>,
    candidate: &str,
) -> Result<(), MsgError> {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return Err(MsgError::InvalidFormat);
    }
    if let Some(declared) = declared_message_type.as_deref() {
        if !declared_message_definitions_match(declared, candidate) {
            return Err(MsgError::UnknownMessageType);
        }
    } else {
        *declared_message_type = Some(candidate.to_owned());
    }
    Ok(())
}
fn document_root_matches_message(message_type: &str, root: &str) -> Option<bool> {
    Some(match canonical_message_type(message_type).as_ref() {
        "colr.012" => root == "CollSbstitnConf",
        "pacs.002" => root == "FIToFIPmtStsRpt",
        "pacs.004" => root == "PmtRtr",
        "pacs.007" => root == "FIToFIPmtRvsl",
        "pacs.008" => root == "FIToFICstmrCdtTrf",
        "pacs.009" => root == "FICdtTrf",
        "pacs.028" => root == "FIToFIPmtStsReq",
        "pacs.029" => root == "RsltnOfInvstgtn",
        "pain.001" => root == "CstmrCdtTrfInitn",
        "pain.002" => root == "CstmrPmtStsRpt",
        "camt.029" => root == "RsltnOfInvstgtn",
        "camt.052" => root == "BkToCstmrAcctRpt",
        "camt.053" => root == "BkToCstmrStmt",
        "camt.054" => root == "BkToCstmrDbtCdtNtfctn",
        "camt.056" => root == "FIToFIPmtCxlReq",
        "sese.023" => root == "SctiesSttlmTxInstr",
        "sese.024" => root == "SctiesSttlmTxStsAdvc",
        "sese.025" => root == "SctiesSttlmTxConf",
        _ => return None,
    })
}
fn message_type_requires_document_root(message_type: &str) -> bool {
    document_root_matches_message(message_type, "").is_some()
}
fn repeating_bases_for(message_type: &str) -> Vec<String> {
    schema_for(message_type)
        .map(|schema| {
            schema
                .field_specs()
                .iter()
                .filter_map(|spec| repeating_base(spec.pattern))
                .map(|base| base.to_owned())
                .collect()
        })
        .unwrap_or_default()
}
fn should_index(path: &str, repeating_bases: &[String]) -> bool {
    repeating_bases.iter().any(|base| path.ends_with(base))
}
const SIGNATURE_IGNORED_VALUE: &[u8] = b"signature-block-ignored";
const XMLDSIG_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";
const REAL_XML_MAX_DEPTH: usize = 64;
const REAL_XML_MAX_ELEMENTS: usize = 16_384;
const REAL_XML_MAX_ATTRIBUTES_PER_ELEMENT: usize = 64;
const REAL_XML_MAX_ATTRIBUTES: usize = 65_536;
const REAL_XML_MAX_PATH_BYTES: usize = 4_096;
const REAL_XML_MAX_FIELDS: usize = 16_384;
fn normalised_parts(stack: &[String]) -> Vec<String> {
    stack
        .iter()
        .map(|s| s.as_str())
        .filter(|s| {
            let name = local_name(s);
            !matches!(name, "DataPDU" | "DataEnvelope" | "Body")
        })
        .map(|s| local_name(s).to_owned())
        .collect()
}
fn current_path(stack: &[String]) -> Option<String> {
    let parts = normalised_parts(stack);
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}
fn find_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut in_quote = None;
    while i < bytes.len() {
        let b = bytes[i];
        match in_quote {
            Some(q) if b == q => in_quote = None,
            None if b == b'"' || b == b'\'' => in_quote = Some(b),
            None if b == b'>' => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}
fn supported_xml_comment_end(text: &str, start: usize) -> Result<usize, MsgError> {
    let Some(body_start) = text[start..].strip_prefix("<!--").map(|_| start + 4) else {
        return Err(MsgError::InvalidFormat);
    };
    let Some(comment_end) = text[body_start..]
        .find("-->")
        .map(|offset| body_start + offset)
    else {
        return Err(MsgError::InvalidFormat);
    };
    let body = &text[body_start..comment_end];
    if body.contains("--") || body.ends_with('-') {
        return Err(MsgError::InvalidFormat);
    }
    Ok(comment_end + 3)
}
fn supported_processing_instruction_end(text: &str, start: usize) -> Result<usize, MsgError> {
    let Some(body_start) = text[start..].strip_prefix("<?").map(|_| start + 2) else {
        return Err(MsgError::InvalidFormat);
    };
    let Some(pi_end) = text[body_start..]
        .find("?>")
        .map(|offset| body_start + offset)
    else {
        return Err(MsgError::InvalidFormat);
    };
    let body = &text[body_start..pi_end];
    if body.is_empty() || body.chars().next().is_some_and(char::is_whitespace) {
        return Err(MsgError::InvalidFormat);
    }
    let target = body
        .split(char::is_whitespace)
        .next()
        .ok_or(MsgError::InvalidFormat)?;
    if !is_supported_xml_name(target) {
        return Err(MsgError::InvalidFormat);
    }
    Ok(pi_end + 2)
}
fn supported_special_xml_markup_end(text: &str, start: usize) -> Result<Option<usize>, MsgError> {
    if text[start..].starts_with("<!--") {
        return supported_xml_comment_end(text, start).map(Some);
    }
    if text[start..].starts_with("<?") {
        return supported_processing_instruction_end(text, start).map(Some);
    }
    if text[start..].starts_with("<!") {
        return Err(MsgError::InvalidFormat);
    }
    Ok(None)
}
fn parse_attributes_limited(
    tag_body: &str,
    max_attributes: usize,
) -> Result<Vec<(String, String)>, MsgError> {
    let mut attrs = Vec::new();
    let mut cursor = tag_body.trim();
    if let Some((_, rest)) = cursor.split_once(char::is_whitespace) {
        cursor = rest.trim();
    } else {
        return Ok(attrs);
    }
    if cursor.ends_with('/') {
        cursor = cursor.trim_end_matches('/').trim_end();
    }
    while !cursor.is_empty() {
        if attrs.len() >= max_attributes {
            return Err(MsgError::InvalidFormat);
        }
        let name_end = cursor
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(cursor.len());
        if name_end == 0 {
            return Err(MsgError::InvalidFormat);
        }
        let name = &cursor[..name_end];
        if !is_supported_xml_attribute_name(name)
            || attrs.iter().any(|(attr_name, _)| attr_name == name)
        {
            return Err(MsgError::InvalidFormat);
        }
        let mut remainder = cursor[name_end..].trim_start();
        if !remainder.starts_with('=') {
            return Err(MsgError::InvalidFormat);
        }
        remainder = remainder[1..].trim_start();
        let Some(quote) = remainder.chars().next() else {
            return Err(MsgError::InvalidFormat);
        };
        if quote != '"' && quote != '\'' {
            return Err(MsgError::InvalidFormat);
        }
        let value_start = quote.len_utf8();
        let value_remainder = &remainder[value_start..];
        let Some(value_end) = value_remainder.find(quote) else {
            return Err(MsgError::InvalidFormat);
        };
        let value = &value_remainder[..value_end];
        if value.contains('<') {
            return Err(MsgError::InvalidFormat);
        }
        attrs.push((name.to_owned(), unescape_xml_text(value)?));
        let consumed = value_start + value_end + quote.len_utf8();
        cursor = remainder[consumed..].trim_start();
    }
    Ok(attrs)
}
fn parse_attributes(tag_body: &str) -> Result<Vec<(String, String)>, MsgError> {
    parse_attributes_limited(tag_body, usize::MAX)
}
fn is_supported_xml_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn is_supported_xml_qname(name: &str) -> bool {
    if name.matches(':').count() > 1 {
        return false;
    }
    if let Some((prefix, local)) = name.split_once(':') {
        is_supported_xml_name(prefix) && is_supported_xml_name(local) && prefix != "xmlns"
    } else {
        is_supported_xml_name(name)
    }
}
fn is_supported_xml_attribute_name(name: &str) -> bool {
    if name == "xmlns" {
        return true;
    }
    if let Some(prefix) = name.strip_prefix("xmlns:") {
        return is_supported_xml_name(prefix) && !matches!(prefix, "xml" | "xmlns");
    }
    is_supported_xml_qname(name)
}
fn unescape_xml_text(input: &str) -> Result<String, MsgError> {
    if !input.contains('&') {
        ensure_xml_characters(input)?;
        return Ok(input.to_owned());
    }
    let mut out = String::with_capacity(input.len());
    let mut remainder = input;
    while let Some(idx) = remainder.find('&') {
        out.push_str(&remainder[..idx]);
        remainder = &remainder[idx + 1..];
        let Some(end) = remainder.find(';') else {
            return Err(MsgError::InvalidFormat);
        };
        let entity = &remainder[..end];
        remainder = &remainder[end + 1..];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => out.push(decode_xml_character_reference(entity)?),
        }
    }
    out.push_str(remainder);
    ensure_xml_characters(&out)?;
    Ok(out)
}
fn decode_xml_character_reference(entity: &str) -> Result<char, MsgError> {
    let (digits, radix) = if let Some(digits) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        (digits, 16_u32)
    } else if let Some(digits) = entity.strip_prefix('#') {
        (digits, 10_u32)
    } else {
        return Err(MsgError::InvalidFormat);
    };
    if digits.is_empty() {
        return Err(MsgError::InvalidFormat);
    }
    let mut value = 0_u32;
    for byte in digits.bytes() {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' if radix == 16 => u32::from(byte - b'a' + 10),
            b'A'..=b'F' if radix == 16 => u32::from(byte - b'A' + 10),
            _ => return Err(MsgError::InvalidFormat),
        };
        if digit >= radix {
            return Err(MsgError::InvalidFormat);
        }
        value = value
            .checked_mul(radix)
            .and_then(|acc| acc.checked_add(digit))
            .ok_or(MsgError::InvalidFormat)?;
    }
    let ch = char::from_u32(value).ok_or(MsgError::InvalidFormat)?;
    if is_xml_character(ch) {
        Ok(ch)
    } else {
        Err(MsgError::InvalidFormat)
    }
}
fn is_xml_character(ch: char) -> bool {
    matches!(
        ch as u32,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}
fn contains_only_xml_characters(input: &str) -> bool {
    input.chars().all(is_xml_character)
}
fn ensure_xml_characters(input: &str) -> Result<(), MsgError> {
    if contains_only_xml_characters(input) {
        Ok(())
    } else {
        Err(MsgError::InvalidFormat)
    }
}
fn buffer_real_iso20022_text(
    stack: &[String],
    path: &str,
    raw_text: &str,
    element_child_counts: &[usize],
    text_buffers: &mut HashMap<String, String>,
) -> Result<(), MsgError> {
    if raw_text.trim().is_empty() {
        return Ok(());
    }
    if element_child_counts.last().copied().unwrap_or_default() != 0 {
        return Err(MsgError::InvalidFormat);
    }
    let value = unescape_xml_text(raw_text)?;
    text_buffers
        .entry(path.to_owned())
        .or_default()
        .push_str(&value);
    let _ = stack;
    Ok(())
}
fn begin_real_xml_provenance(source: &[u8]) {
    MESSAGE_STACK.with(|stack| {
        if let Some(message) = stack.borrow_mut().last_mut() {
            message.xml_source_sha256 = Some(Sha256::digest(source).into());
            message.xml_field_sources.clear();
        }
    });
}
fn msg_set_xml(
    field: &str,
    value: &[u8],
    source: Range<usize>,
    fields_materialised: &mut usize,
) -> Result<(), MsgError> {
    MESSAGE_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let message = stack.last_mut().ok_or(MsgError::NoActiveMessage)?;
        let key = canonical_field_name(&message.message_type, field);
        if let Some(existing) = message.fields.get(&key) {
            if existing.as_slice() != value {
                return Err(MsgError::InvalidFormat);
            }
            let existing_source = message
                .xml_field_sources
                .get_mut(&key)
                .ok_or(MsgError::InvalidFormat)?;
            existing_source.start = existing_source.start.min(source.start);
            existing_source.end = existing_source.end.max(source.end);
            return Ok(());
        }
        if *fields_materialised >= REAL_XML_MAX_FIELDS {
            return Err(MsgError::InvalidFormat);
        }
        *fields_materialised += 1;
        message.fields.insert(key.clone(), value.to_vec());
        message.xml_field_sources.insert(
            key,
            XmlFieldSource {
                start: source.start,
                end: source.end,
            },
        );
        Ok(())
    })
}
fn flush_real_iso20022_text(
    stack: &[String],
    declared_message_type: &mut Option<String>,
    path: &str,
    text_buffers: &mut HashMap<String, String>,
    source: Range<usize>,
    fields_materialised: &mut usize,
) -> Result<(), MsgError> {
    let Some(value) = text_buffers.remove(path) else {
        return Ok(());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if stack
        .last()
        .is_some_and(|last| local_name(last) == "MsgDefIdr")
    {
        observe_declared_message_type(declared_message_type, trimmed)?;
    }
    msg_set_xml(path, trimmed.as_bytes(), source, fields_materialised)
}
fn parsed_attr_value<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find_map(|(attr_name, value)| (attr_name == name).then_some(value.as_str()))
}
fn parse_named_opening_attributes(
    raw_tag: &str,
    expected_name: &str,
) -> Result<Vec<(String, String)>, MsgError> {
    let tag_body = raw_tag.trim();
    if tag_body.ends_with('/') {
        return Err(MsgError::InvalidFormat);
    }
    let (name_part, _) = tag_body
        .split_once(char::is_whitespace)
        .unwrap_or((tag_body, ""));
    if name_part != expected_name || !is_supported_xml_qname(name_part) {
        return Err(MsgError::InvalidFormat);
    }
    parse_attributes(tag_body)
}
fn reject_unexpected_attrs(
    attrs: &[(String, String)],
    allowed: &[&str],
    label: &'static str,
) -> Result<(), MsgError> {
    if attrs
        .iter()
        .any(|(name, _)| !allowed.iter().any(|allowed_name| allowed_name == name))
    {
        return Err(MsgError::InvalidFormat);
    }
    if allowed.iter().any(|name| {
        attrs
            .iter()
            .filter(|(attr_name, _)| attr_name == name)
            .count()
            > 1
    }) {
        return Err(MsgError::InvalidFormat);
    }
    let _ = label;
    Ok(())
}
fn is_supported_internal_field_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|segment| {
            if segment.is_empty() {
                return false;
            }
            if let Some(attribute_name) = segment.strip_prefix('@') {
                return is_supported_xml_name(attribute_name);
            }
            let (name, index) = if let Some(index_start) = segment.find('[') {
                if !segment.ends_with(']') {
                    return false;
                }
                (
                    &segment[..index_start],
                    Some(&segment[index_start + 1..segment.len() - 1]),
                )
            } else {
                (segment, None)
            };
            is_supported_xml_name(name)
                && index.is_none_or(|idx| {
                    idx == "*" || !idx.is_empty() && idx.bytes().all(|b| b.is_ascii_digit())
                })
        })
}
fn parse_key_values(message_type: &str, text: &str) {
    for (key, value) in text.lines().filter_map(|line| line.split_once('=')) {
        msg_set(key.trim(), value.trim().as_bytes());
    }
    MESSAGE_STACK.with(|stack| {
        if let Some(m) = stack.borrow_mut().last_mut() {
            // Ensure the message type was set correctly for empty inputs.
            if m.message_type != message_type {
                m.message_type = message_type.to_owned();
            }
        }
    });
}
/// Owned ISO supplementary namespace for exact native payment network and absolute expiry.
pub const NEXUS_SETTLEMENT_XML_NAMESPACE: &str = "urn:iroha:iso20022:nexus:v1";

fn nexus_settlement_xml_parent(message_type: &str) -> Option<&'static str> {
    match canonical_message_type(message_type).as_ref() {
        "pacs.008" => Some("Document/FIToFICstmrCdtTrf/SplmtryData/Envlp"),
        "pacs.009" => Some("Document/FICdtTrf/SplmtryData/Envlp"),
        _ => None,
    }
}

// Only a fixed, owned native intent subtree is a semantic namespace extension.
// The caller rejects a second NexusSettlement root and every non-xmlns attribute.
fn is_nexus_settlement_xml_element(
    message_type: &str,
    parent_path: &str,
    parent_namespace: &str,
    name: &str,
    namespace: Option<&str>,
) -> Result<bool, MsgError> {
    if parent_namespace != NEXUS_SETTLEMENT_XML_NAMESPACE
        && namespace != Some(NEXUS_SETTLEMENT_XML_NAMESPACE)
    {
        return Ok(false);
    }
    let expected_parent =
        nexus_settlement_xml_parent(message_type).ok_or(MsgError::InvalidFormat)?;
    if namespace != Some(NEXUS_SETTLEMENT_XML_NAMESPACE) {
        return Err(MsgError::InvalidFormat);
    }
    if parent_namespace == NEXUS_SETTLEMENT_XML_NAMESPACE {
        let Some(extension_parent) = parent_path.strip_suffix("/NexusSettlement") else {
            return Err(MsgError::InvalidFormat);
        };
        if extension_parent != expected_parent
            || !matches!(
                name,
                "NetworkId"
                    | "ExpiresAtHeight"
                    | "SourceAccountId"
                    | "TargetAccountId"
                    | "AssetDefinitionId"
            )
        {
            return Err(MsgError::InvalidFormat);
        }
    } else if parent_path != expected_parent || name != "NexusSettlement" {
        return Err(MsgError::InvalidFormat);
    }
    Ok(true)
}

fn parse_real_iso20022(message_type: &str, text: &str) -> Result<(), MsgError> {
    begin_real_xml_provenance(text.as_bytes());
    let mut stack: Vec<String> = Vec::new();
    let mut qname_stack: Vec<String> = Vec::new();
    let mut skip_stack: Vec<bool> = Vec::new();
    let mut element_child_counts: Vec<usize> = Vec::new();
    let mut element_starts: Vec<usize> = Vec::new();
    let mut semantic_namespace_stack: Vec<Option<String>> = Vec::new();
    let mut skip_depth = 0usize;
    let repeating_bases = repeating_bases_for(message_type);
    let mut repeat_counters: HashMap<String, usize> = HashMap::new();
    let mut declared_message_type: Option<String> = None;
    let mut document_root_seen = false;
    let mut nexus_settlement_fields = 0_u8;
    let mut payment_transaction_count = 0_usize;
    let mut top_level_root_seen = false;
    let mut namespace_scopes: Vec<Vec<(String, String)>> = Vec::new();
    let mut text_buffers: HashMap<String, String> = HashMap::new();
    let mut element_count = 0usize;
    let mut attribute_count = 0usize;
    let mut fields_materialised = 0usize;
    let mut idx = 0usize;
    let bytes = text.as_bytes();
    let len = bytes.len();
    while idx < len {
        let next_lt = match text[idx..].find('<') {
            Some(offset) => idx + offset,
            None => {
                let tail = &text[idx..];
                if skip_depth == 0
                    && semantic_namespace_stack.last().is_some_and(Option::is_some)
                    && let Some(path) = current_path(&stack)
                {
                    buffer_real_iso20022_text(
                        &stack,
                        &path,
                        tail,
                        &element_child_counts,
                        &mut text_buffers,
                    )?;
                } else if skip_depth == 0 && stack.is_empty() && !tail.trim().is_empty() {
                    return Err(MsgError::InvalidFormat);
                }
                break;
            }
        };
        if next_lt > idx && skip_depth == 0 {
            let body = &text[idx..next_lt];
            if semantic_namespace_stack.last().is_some_and(Option::is_some)
                && let Some(path) = current_path(&stack)
            {
                buffer_real_iso20022_text(
                    &stack,
                    &path,
                    body,
                    &element_child_counts,
                    &mut text_buffers,
                )?;
            } else if stack.is_empty() && !body.trim().is_empty() {
                return Err(MsgError::InvalidFormat);
            }
        }
        if let Some(special_end) = supported_special_xml_markup_end(text, next_lt)? {
            idx = special_end;
            continue;
        }
        let Some(tag_end) = find_tag_end(bytes, next_lt + 1) else {
            return Err(MsgError::InvalidFormat);
        };
        let raw_tag = &text[next_lt + 1..tag_end];
        idx = tag_end + 1;
        let tag = raw_tag.trim();
        if tag.starts_with('?') || tag.starts_with('!') {
            return Err(MsgError::InvalidFormat);
        }
        let closing = tag.starts_with('/');
        let tag_body = if closing {
            let closing_body = tag.strip_prefix('/').ok_or(MsgError::InvalidFormat)?;
            if closing_body.chars().next().is_some_and(char::is_whitespace) {
                return Err(MsgError::InvalidFormat);
            }
            let closing_body = closing_body.trim();
            if closing_body.is_empty() || closing_body.chars().any(char::is_whitespace) {
                return Err(MsgError::InvalidFormat);
            }
            closing_body
        } else {
            tag
        };
        let self_closing = !closing && tag_body.ends_with('/');
        let tag_body = if self_closing {
            tag_body.trim_end_matches('/').trim_end()
        } else {
            tag_body
        };
        let (name_part, _) = tag_body
            .split_once(char::is_whitespace)
            .unwrap_or((tag_body, ""));
        if !is_supported_xml_qname(name_part) {
            return Err(MsgError::InvalidFormat);
        }
        let lname = local_name(name_part);
        if closing {
            let Some(opened) = qname_stack.pop() else {
                return Err(MsgError::InvalidFormat);
            };
            if opened != name_part {
                return Err(MsgError::InvalidFormat);
            }
            let source_start = element_starts
                .last()
                .copied()
                .ok_or(MsgError::InvalidFormat)?;
            if let Some(skipped) = skip_stack.pop()
                && skipped
                && skip_depth > 0
            {
                skip_depth -= 1;
            }
            if skip_depth == 0
                && semantic_namespace_stack.last().is_some_and(Option::is_some)
                && let Some(path) = current_path(&stack)
            {
                flush_real_iso20022_text(
                    &stack,
                    &mut declared_message_type,
                    &path,
                    &mut text_buffers,
                    source_start..idx,
                    &mut fields_materialised,
                )?;
            }
            stack.pop();
            element_child_counts.pop();
            element_starts.pop();
            semantic_namespace_stack.pop();
            namespace_scopes.pop();
            continue;
        }
        element_count = element_count
            .checked_add(1)
            .ok_or(MsgError::InvalidFormat)?;
        if element_count > REAL_XML_MAX_ELEMENTS || qname_stack.len() >= REAL_XML_MAX_DEPTH {
            return Err(MsgError::InvalidFormat);
        }
        let remaining_attributes = REAL_XML_MAX_ATTRIBUTES
            .checked_sub(attribute_count)
            .ok_or(MsgError::InvalidFormat)?;
        let attrs = parse_attributes_limited(
            tag_body,
            remaining_attributes.min(REAL_XML_MAX_ATTRIBUTES_PER_ELEMENT),
        )?;
        attribute_count = attribute_count
            .checked_add(attrs.len())
            .ok_or(MsgError::InvalidFormat)?;
        if skip_depth == 0 && stack.is_empty() {
            if top_level_root_seen {
                return Err(MsgError::InvalidFormat);
            }
            top_level_root_seen = true;
        }
        let current_namespace_bindings = namespace_bindings(&attrs);
        let parent_namespace = semantic_namespace_stack.last().cloned().flatten();
        let parent_is_document = skip_depth == 0
            && stack
                .last()
                .is_some_and(|parent| local_name(parent) == "Document");
        let element_namespace = if skip_depth == 0 {
            element_namespace_uri(name_part, &attrs, &namespace_scopes)?.map(ToOwned::to_owned)
        } else {
            None
        };
        let is_dsig_signature = skip_depth == 0
            && lname == "Signature"
            && element_namespace.as_deref() == Some(XMLDSIG_NAMESPACE);
        if skip_depth == 0 && lname == "Signature" && !is_dsig_signature {
            return Err(MsgError::InvalidFormat);
        }
        if skip_depth == 0
            && parent_namespace.is_some()
            && matches!(lname, "DataPDU" | "DataEnvelope" | "Body")
        {
            return Err(MsgError::InvalidFormat);
        }
        let semantic_namespace = if skip_depth > 0 {
            parent_namespace.clone()
        } else if lname == "AppHdr" {
            if parent_namespace.is_some() {
                return Err(MsgError::InvalidFormat);
            }
            let namespace = element_namespace
                .as_deref()
                .ok_or(MsgError::UnknownMessageType)?;
            let definition =
                message_type_from_namespace(namespace).ok_or(MsgError::UnknownMessageType)?;
            if canonical_message_type(&definition).as_ref() != "head.001"
                || !is_versioned_message_definition_id(&definition)
            {
                return Err(MsgError::UnknownMessageType);
            }
            Some(namespace.to_owned())
        } else if lname == "Document" {
            if parent_namespace.is_some() {
                return Err(MsgError::InvalidFormat);
            }
            let namespace = element_namespace
                .as_deref()
                .ok_or(MsgError::UnknownMessageType)?;
            let definition =
                message_type_from_namespace(namespace).ok_or(MsgError::UnknownMessageType)?;
            observe_declared_message_type(&mut declared_message_type, &definition)?;
            Some(namespace.to_owned())
        } else if let Some(owner) = parent_namespace.as_deref() {
            let parent_path = current_path(&stack).ok_or(MsgError::InvalidFormat)?;
            if is_nexus_settlement_xml_element(
                message_type,
                &parent_path,
                owner,
                lname,
                element_namespace.as_deref(),
            )? {
                if attrs
                    .iter()
                    .any(|(name, _)| name != "xmlns" && !name.starts_with("xmlns:"))
                {
                    return Err(MsgError::InvalidFormat);
                }
                let field = match lname {
                    "NexusSettlement" => 1,
                    "NetworkId" => 2,
                    "ExpiresAtHeight" => 4,
                    "SourceAccountId" => 8,
                    "TargetAccountId" => 16,
                    "AssetDefinitionId" => 32,
                    _ => return Err(MsgError::InvalidFormat),
                };
                if nexus_settlement_fields & field != 0 {
                    return Err(MsgError::InvalidFormat);
                }
                nexus_settlement_fields |= field;
                Some(NEXUS_SETTLEMENT_XML_NAMESPACE.to_owned())
            } else {
                if !is_dsig_signature && element_namespace.as_deref() != Some(owner) {
                    return Err(MsgError::InvalidFormat);
                }
                if lname == "CdtTrfTxInf"
                    && matches!(
                        parent_path.as_str(),
                        "Document/FIToFICstmrCdtTrf" | "Document/FICdtTrf"
                    )
                {
                    payment_transaction_count = payment_transaction_count
                        .checked_add(1)
                        .ok_or(MsgError::InvalidFormat)?;
                }
                Some(owner.to_owned())
            }
        } else {
            None
        };
        let materialise_semantic = semantic_namespace.is_some();
        let is_skipped = skip_depth == 0
            && (is_dsig_signature
                || (lname == "Sgntr"
                    && parent_namespace.is_some()
                    && element_namespace == parent_namespace));
        if parent_is_document
            && !is_skipped
            && let Some(matches) = document_root_matches_message(message_type, lname)
        {
            let namespace = element_namespace
                .as_deref()
                .ok_or(MsgError::UnknownMessageType)?;
            let definition =
                message_type_from_namespace(namespace).ok_or(MsgError::UnknownMessageType)?;
            observe_declared_message_type(&mut declared_message_type, &definition)?;
            if !matches || document_root_seen {
                return Err(if matches {
                    MsgError::InvalidFormat
                } else {
                    MsgError::UnknownMessageType
                });
            }
            document_root_seen = true;
        }
        if lname.len() > REAL_XML_MAX_PATH_BYTES {
            return Err(MsgError::InvalidFormat);
        }
        let mut parts = normalised_parts(&stack);
        parts.push(lname.to_owned());
        let base_path = parts.join("/");
        if base_path.len() > REAL_XML_MAX_PATH_BYTES {
            return Err(MsgError::InvalidFormat);
        }
        let mut element_name = lname.to_owned();
        if should_index(&base_path, &repeating_bases) {
            let counter = repeat_counters.entry(base_path.clone()).or_insert(0);
            element_name = format!("{lname}[{counter}]");
            *counter = counter.checked_add(1).ok_or(MsgError::InvalidFormat)?;
        }
        if skip_depth == 0
            && let Some(parent_path) = current_path(&stack)
        {
            if text_buffers
                .get(&parent_path)
                .is_some_and(|text| !text.trim().is_empty())
            {
                return Err(MsgError::InvalidFormat);
            }
            if let Some(child_count) = element_child_counts.last_mut() {
                *child_count = child_count.checked_add(1).ok_or(MsgError::InvalidFormat)?;
            }
        }
        stack.push(element_name);
        let path = current_path(&stack);
        if path
            .as_ref()
            .is_some_and(|path| path.len() > REAL_XML_MAX_PATH_BYTES)
        {
            return Err(MsgError::InvalidFormat);
        }
        qname_stack.push(name_part.to_owned());
        element_child_counts.push(0);
        element_starts.push(next_lt);
        semantic_namespace_stack.push(semantic_namespace);
        namespace_scopes.push(current_namespace_bindings);
        if is_skipped && skip_depth == 0 && materialise_semantic {
            let path = path.as_deref().ok_or(MsgError::InvalidFormat)?;
            let marker_path = format!("{path}/@ignored");
            if marker_path.len() > REAL_XML_MAX_PATH_BYTES {
                return Err(MsgError::InvalidFormat);
            }
            msg_set_xml(
                &marker_path,
                SIGNATURE_IGNORED_VALUE,
                next_lt..idx,
                &mut fields_materialised,
            )?;
        }
        skip_stack.push(is_skipped);
        if is_skipped {
            skip_depth += 1;
        }
        if skip_depth == 0
            && materialise_semantic
            && let Some(path) = path.as_deref()
        {
            for (attr_name, value) in &attrs {
                if attr_name == "xmlns" || attr_name.starts_with("xmlns:") {
                    continue;
                }
                if let Some((prefix, _)) = attr_name.split_once(':') {
                    namespace_uri_for_prefix(prefix, &[], &namespace_scopes)
                        .ok_or(MsgError::InvalidFormat)?;
                    continue;
                }
                let attr_path = format!("{path}/@{attr_name}");
                if attr_path.len() > REAL_XML_MAX_PATH_BYTES {
                    return Err(MsgError::InvalidFormat);
                }
                msg_set_xml(
                    &attr_path,
                    value.as_bytes(),
                    next_lt..idx,
                    &mut fields_materialised,
                )?;
            }
        }
        if self_closing {
            if let Some(skipped) = skip_stack.pop()
                && skipped
                && skip_depth > 0
            {
                skip_depth -= 1;
            }
            stack.pop();
            qname_stack.pop();
            element_child_counts.pop();
            element_starts.pop();
            semantic_namespace_stack.pop();
            namespace_scopes.pop();
        }
    }
    if !qname_stack.is_empty() || !text_buffers.is_empty() || !top_level_root_seen {
        return Err(MsgError::InvalidFormat);
    }
    if nexus_settlement_fields != 0
        && (nexus_settlement_fields != 63 || payment_transaction_count != 1)
    {
        return Err(MsgError::InvalidFormat);
    }
    if let Some(declared) = declared_message_type {
        let requested_head = canonical_message_type(message_type) == "head.001";
        if !requested_head && !requested_message_matches_declaration(message_type, &declared) {
            return Err(MsgError::UnknownMessageType);
        }
    }
    if message_type_requires_document_root(message_type) && !document_root_seen {
        return Err(MsgError::InvalidFormat);
    }
    Ok(())
}
fn parse_xml_into_current(message_type: &str, text: &str) -> Result<(), MsgError> {
    let trimmed = text.trim();
    if !trimmed.starts_with("<ISO20022") {
        return Err(MsgError::InvalidFormat);
    }
    let tag_end = find_tag_end(trimmed.as_bytes(), 1).ok_or(MsgError::InvalidFormat)?;
    let root_attrs = parse_named_opening_attributes(&trimmed[1..tag_end], "ISO20022")?;
    reject_unexpected_attrs(&root_attrs, &["message"], "ISO20022")?;
    let declared = parsed_attr_value(&root_attrs, "message").ok_or(MsgError::InvalidFormat)?;
    if declared != message_type {
        return Err(MsgError::UnknownMessageType);
    }
    let cursor = &trimmed[tag_end + 1..];
    let close_idx = cursor.find("</ISO20022>").ok_or(MsgError::InvalidFormat)?;
    if !cursor[close_idx + "</ISO20022>".len()..].trim().is_empty() {
        return Err(MsgError::InvalidFormat);
    }
    let mut fields = &cursor[..close_idx];
    loop {
        fields = fields.trim_start();
        if fields.is_empty() {
            break;
        }
        if !fields.starts_with("<Field") {
            return Err(MsgError::InvalidFormat);
        }
        let field_tag_end = find_tag_end(fields.as_bytes(), 1).ok_or(MsgError::InvalidFormat)?;
        let field_attrs = parse_named_opening_attributes(&fields[1..field_tag_end], "Field")?;
        reject_unexpected_attrs(&field_attrs, &["path", "encoding"], "Field")?;
        let path = parsed_attr_value(&field_attrs, "path").ok_or(MsgError::InvalidFormat)?;
        if !is_supported_internal_field_path(path) {
            return Err(MsgError::InvalidFormat);
        }
        let encoding = parsed_attr_value(&field_attrs, "encoding");
        if let Some(encoding) = encoding
            && encoding != "base64"
        {
            return Err(MsgError::InvalidFormat);
        }
        fields = &fields[field_tag_end + 1..];
        let end_idx = fields.find("</Field>").ok_or(MsgError::InvalidFormat)?;
        let value_text = fields[..end_idx].trim();
        fields = &fields[end_idx + "</Field>".len()..];
        let value = if encoding == Some("base64") {
            decode_base64(value_text.as_bytes()).ok_or(MsgError::InvalidFormat)?
        } else {
            if value_text.contains('<') || value_text.contains("]]>") {
                return Err(MsgError::InvalidFormat);
            }
            unescape_xml_text(value_text)?.into_bytes()
        };
        msg_set(path, &value);
    }
    Ok(())
}
/// Base64 alphabet used by [`encode_base64`] and [`decode_base64`].
const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Precomputed table mapping ASCII bytes to their 6-bit Base64 value. Invalid bytes map to `0xFF`.
const fn build_b64_decode_table() -> [u8; 256] {
    let mut table = [0xFFu8; 256];
    let mut i = 0;
    while i < 64 {
        table[BASE64_TABLE[i] as usize] = i as u8;
        i += 1;
    }
    // Padding character is treated as zero during decoding.
    table[b'=' as usize] = 0;
    table
}
const BASE64_DECODE_TABLE: [u8; 256] = build_b64_decode_table();
/// Encode binary data as a Base64 ASCII string.
///
/// This lightweight helper is sufficient for tests and prototypes and uses
/// constant-time table lookups.
pub fn encode_base64(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(BASE64_TABLE[(b0 >> 2) as usize]);
        out.push(BASE64_TABLE[((b0 & 0x03) << 4 | (b1 >> 4)) as usize]);
        if chunk.len() > 1 {
            out.push(BASE64_TABLE[((b1 & 0x0F) << 2 | (b2 >> 6)) as usize]);
        } else {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_TABLE[(b2 & 0x3F) as usize]);
        } else {
            out.push(b'=');
        }
    }
    out
}
/// Decode a Base64 ASCII string into the provided output buffer.
///
/// The caller supplies the destination [`Vec`] which is extended with the decoded bytes. This
/// allows large payloads to be processed without allocating a fresh buffer for every call.
///
/// Returns `None` if the input contains invalid characters or has the wrong padding.
pub fn decode_base64_into(data: &[u8], out: &mut Vec<u8>) -> Option<()> {
    if !data.len().is_multiple_of(4) {
        return None;
    }
    out.reserve(data.len().div_ceil(4) * 3);
    let mut i = 0;
    while i < data.len() {
        let n0 = BASE64_DECODE_TABLE[data[i] as usize];
        let n1 = BASE64_DECODE_TABLE[data[i + 1] as usize];
        let n2 = BASE64_DECODE_TABLE[data[i + 2] as usize];
        let n3 = BASE64_DECODE_TABLE[data[i + 3] as usize];
        if (n0 | n1 | n2 | n3) == 0xFF {
            return None;
        }
        out.push((n0 << 2) | (n1 >> 4));
        if data[i + 2] != b'=' {
            out.push((n1 << 4) | (n2 >> 2));
            if data[i + 3] != b'=' {
                out.push((n2 << 6) | n3);
            } else if n3 != 0 {
                return None;
            }
        } else if n2 != 0 || n3 != 0 {
            return None;
        }
        i += 4;
    }
    Some(())
}
/// Decode a Base64 ASCII string back into binary data.
///
/// Returns `None` if the input contains invalid characters or has the wrong padding.
pub fn decode_base64(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len().div_ceil(4) * 3);
    decode_base64_into(data, &mut out)?;
    Some(out)
}
/// Create a new ISO 20022 message of the given type.
///
/// The message is represented as a deterministic in-memory [`IsoMessage`] slot. Schema helpers and
/// validators can inspect or update the fields before the encoded XML is emitted.
pub fn msg_create(message_type: &str) {
    MESSAGE_STACK.with(|stack| {
        stack.borrow_mut().push(IsoMessage {
            message_type: message_type.to_owned(),
            ..IsoMessage::default()
        });
    });
}
/// Set the value of an ISO 20022 field.
///
/// Values are stored verbatim; type checking is intentionally omitted but the
/// call site can at least observe storage behaviour.
pub fn msg_set(field: &str, value: &[u8]) {
    MESSAGE_STACK.with(|stack| {
        if let Some(m) = stack.borrow_mut().last_mut() {
            let key = stored_field_key(m, field);
            m.fields.insert(key, value.to_vec());
            m.xml_source_sha256 = None;
            m.xml_field_sources.clear();
        }
    });
}
fn stored_field_key(message: &IsoMessage, field: &str) -> String {
    if message.fields.contains_key(field) {
        return field.to_owned();
    }
    canonical_field_name(&message.message_type, field)
}
/// Retrieve the value of an ISO 20022 field.
pub fn msg_get(field: &str) -> Option<Vec<u8>> {
    MESSAGE_STACK.with(|stack| {
        let borrow = stack.borrow();
        let message = borrow.last()?;
        let key = stored_field_key(message, field);
        message.fields.get(&key).cloned()
    })
}
/// Append a repeating ISO 20022 sub-structure.
///
/// Each call creates an empty entry with an incremented index.  The entry can
/// later be populated using [`msg_set`] with the generated key.
pub fn msg_add(field: &str) {
    MESSAGE_STACK.with(|stack| {
        if let Some(m) = stack.borrow_mut().last_mut() {
            let base = canonical_repeating_base(&m.message_type, field);
            let count = m.repeats.entry(base.clone()).or_insert(0);
            let key = format!("{}[{}]", base, *count);
            m.fields.entry(key).or_default();
            *count += 1;
            m.xml_source_sha256 = None;
            m.xml_field_sources.clear();
        }
    });
}
/// Remove a field or sub-structure from the current message.
pub fn msg_remove(field: &str) {
    MESSAGE_STACK.with(|stack| {
        if let Some(m) = stack.borrow_mut().last_mut() {
            let key = stored_field_key(m, field);
            m.fields.remove(&key);
            m.xml_source_sha256 = None;
            m.xml_field_sources.clear();
        }
    });
}
/// Clear all fields of the current ISO 20022 message.
pub fn msg_clear() {
    MESSAGE_STACK.with(|stack| {
        if let Some(m) = stack.borrow_mut().last_mut() {
            m.fields.clear();
            m.repeats.clear();
            m.xml_source_sha256 = None;
            m.xml_field_sources.clear();
        }
    });
}
/// Parse raw data into an ISO 20022 message.
///
/// The parser accepts deterministic internal `<ISO20022>` XML wrappers, real
/// ISO 20022 XML payloads, and a compact `key=value` line-oriented format for
/// tests. XML inputs fail closed on malformed structure before fields are stored.
pub fn msg_parse(message_type: &str, data: &[u8]) -> Result<(), MsgError> {
    msg_create(message_type);
    let result = if looks_like_xml(data) {
        let text = core::str::from_utf8(data).map_err(|_| MsgError::InvalidFormat)?;
        if text.contains("<ISO20022") {
            parse_xml_into_current(message_type, text)
        } else {
            parse_real_iso20022(message_type, text)
        }
    } else {
        let text = core::str::from_utf8(data).map_err(|_| MsgError::InvalidFormat)?;
        parse_key_values(message_type, text);
        Ok(())
    };
    if result.is_err() {
        MESSAGE_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
    result
}
/// Serialize the current ISO 20022 message into a simple key=value format.
///
/// Fields are written one per line in lexicographic order of their keys.
pub fn msg_serialize(format: &str) -> Result<Vec<u8>, MsgError> {
    MESSAGE_STACK.with(|stack| {
        let borrow = stack.borrow();
        let message = borrow.last().ok_or(MsgError::NoActiveMessage)?;
        let schema = schema_for(&message.message_type);
        let normalized = if format.is_empty() {
            "KV".to_owned()
        } else {
            format.to_ascii_uppercase()
        };
        match normalized.as_str() {
            "XML" => Ok(serialize_xml(message, schema)),
            "KV" | "KEYVALUE" => Ok(serialize_key_value(message, schema)),
            _ => Err(MsgError::InvalidFormat),
        }
    })
}
/// Validate the current ISO 20022 message against schema rules.
///
/// Rather than a full schema engine we keep a tiny table of mandatory fields
/// for a handful of message types. Validation succeeds when the current message
/// exists **and** all required fields for its type are present.
pub fn msg_validate() -> bool {
    clear_validation_failure();
    MESSAGE_STACK.with(|stack| {
        stack.borrow().last().is_some_and(|m| {
            if let Some(schema) = schema_for(&m.message_type) {
                match validate_message_against_schema(m, schema) {
                    Ok(()) => true,
                    Err(err) => {
                        record_validation_failure(err);
                        false
                    }
                }
            } else {
                false
            }
        })
    })
}
#[cfg(test)]
#[path = "iso20022_tests.rs"]
mod tests;
