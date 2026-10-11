use crate::{
    routing::{self, MaybeTelemetry},
    secure_file_metadata::{self, SecureMetadata},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use dashmap::DashMap;
use eyre::WrapErr as _;
use iroha_config::parameters::actual;
use iroha_core::iso_bridge::{
    profiles::{
        self, EmbeddedSignaturePolicy, MessageDirection, MessageProfile,
        ReferenceDatasetRequirement, StructuredAddressMode, TradfiRail, TradfiRailProfile,
    },
    reference_data::{ReferenceDataError, ReferenceDataSnapshots},
};
use iroha_core::state::WorldReadOnly;
use iroha_crypto::{KeyPair, PrivateKey, PublicKey, Signature};
#[cfg(test)]
use iroha_data_model::alias::AliasIndex;
use iroha_data_model::{
    ValidationFail,
    account::address::AccountAddress,
    asset::AssetDefinitionAlias,
    prelude::{
        AccountId, AssetDefinitionId, AssetId, InstructionBox, TransactionBuilder, Transfer,
    },
    transaction::{SignedTransaction, TransactionPayload, error::TransactionRejectionReason},
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric::Quantity};
use ivm::iso20022::{IdentifierKind, InvalidValueKind, MsgError, ParsedMessage};
#[cfg(test)]
use ivm::iso20022::{parse_message, parse_xml_message};
use norito::json::Value as JsonValue;
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::Verifier as _,
};
use parking_lot::{Mutex, ReentrantMutex};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as FmtWrite,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use time::{Date, Month, PrimitiveDateTime, Time, UtcOffset};
use x509_parser::{
    extensions::{GeneralName, NameConstraints, ParsedExtension},
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256},
    prelude::{FromDer as _, X509Certificate},
    revocation_list::CertificateRevocationList,
    time::ASN1Time,
};
#[derive(Clone)]
struct IsoCurrencyBinding {
    asset_definition: String,
    max_amount: Quantity,
}
/// Runtime bridge configuration derived from Torii settings.
#[derive(Clone)]
pub struct Iso20022BridgeRuntime {
    signer_account: AccountId,
    signer_private_key: PrivateKey,
    signer_public_key: PublicKey,
    participants_by_key: Arc<BTreeMap<PublicKey, IsoBridgeParticipant>>,
    participants_by_financial_id: Arc<HashMap<String, String>>,
    audit_admin_keys: Arc<BTreeSet<PublicKey>>,
    account_aliases: Arc<HashMap<String, AccountId>>,
    #[cfg(test)]
    alias_indices: Arc<HashMap<String, AliasIndex>>,
    #[cfg(test)]
    index_aliases: Arc<BTreeMap<AliasIndex, (String, AccountId)>>,
    currency_assets: Arc<HashMap<String, IsoCurrencyBinding>>,
    reference_data: Arc<ReferenceDataSnapshots>,
    default_profile_id: String,
    profiles: Arc<HashMap<String, TradfiRailProfile>>,
    store_dir: Option<PathBuf>,
    store_retention: Duration,
    store_max_records: usize,
    audit_export_dir: Option<PathBuf>,
    dedupe_ttl: Duration,
    state_lock: Arc<ReentrantMutex<()>>,
    records: DashMap<String, IsoMessageRecordV2>,
    tx_hash_index: DashMap<String, String>,
    payload_hash_index: DashMap<String, String>,
    business_message_id_index: DashMap<String, String>,
    uetr_index: DashMap<String, String>,
    replay_tombstones: DashMap<String, IsoReplayTombstone>,
    durable_store_usage: Arc<Mutex<IsoDurableStoreUsage>>,
    lifecycle_persistence_healthy: Arc<AtomicBool>,
    audit_persistence_healthy: Arc<AtomicBool>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum IsoParticipantRole {
    Originator,
    Counterparty,
}
#[derive(Clone, Debug)]
struct IsoBridgeParticipant {
    id: String,
    financial_identifiers: BTreeSet<String>,
    allowed_profiles: BTreeSet<String>,
    roles: BTreeSet<IsoParticipantRole>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IsoRecordParties {
    originator_participant_id: String,
    counterparty_participant_id: String,
    admitting_participant_id: String,
    admitting_operator_key: String,
    originator_financial_id: String,
    counterparty_financial_id: String,
    pinned_profile_id: String,
    pinned_signature_policy: String,
    pinned_profile_policy_sha256: String,
}
// Runtime-only allocation identity: record clones retain it, while every admission or reload
// receives a fresh token. It is deliberately absent from the persisted wire schema.
#[derive(Clone, Debug)]
struct IsoRecordIncarnation(Arc<()>);
impl PartialEq for IsoRecordIncarnation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for IsoRecordIncarnation {}
#[derive(Clone, Debug, PartialEq, Eq)]
struct IsoLifecycleOriginalBinding {
    message_id: String,
    incarnation: IsoRecordIncarnation,
    transaction_hash: Option<String>,
}
/// Opaque authorization tying one lifecycle admission to the exact original record observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IsoLifecycleAuthorization {
    parties: IsoRecordParties,
    original: Option<IsoLifecycleOriginalBinding>,
}
impl IsoLifecycleAuthorization {
    fn initial(parties: IsoRecordParties) -> Self {
        Self {
            parties,
            original: None,
        }
    }

    /// Return the participant snapshot to persist with the lifecycle admission.
    pub(crate) fn parties(&self) -> &IsoRecordParties {
        &self.parties
    }

    /// Return the exact original transaction hash whose commitment may authorize settlement.
    pub(crate) fn settlement_transaction_hash(
        &self,
        message_type: &str,
        parsed: &ParsedMessage,
    ) -> Result<Option<&str>, MsgError> {
        if message_type != "pacs.002"
            || !lifecycle_status_code(message_type, parsed).is_some_and(is_settlement_status_code)
        {
            return Ok(None);
        }
        let referenced_id = canonical_lifecycle_referenced_message_id(message_type, parsed)?
            .ok_or(MsgError::MissingField("OrgnlMsgId"))?;
        let original = self
            .original
            .as_ref()
            .filter(|binding| binding.message_id == referenced_id)
            .ok_or(MsgError::ValidationFailed)?;
        Ok(original.transaction_hash.as_deref())
    }
}
#[derive(Clone, Debug)]
struct IsoReplayTombstone {
    expires_at: SystemTime,
    payload_hash: Option<String>,
    business_message_id: Option<String>,
    uetr: Option<String>,
}
/// Reason an inbound ISO message could not be durably admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IsoAdmissionError {
    /// The message or one of its immutable replay identities already exists.
    Duplicate,
    /// Every bounded replay slot is still protected by the configured TTL.
    ProtectedCapacity,
    /// Admission could not be persisted before further processing.
    PersistenceUnavailable,
    /// The authenticated operator is not authorized for this participant operation.
    NotAuthorized,
}
/// Detached signature covering one exact outbound ISO XML document.
pub(crate) struct SignedIsoDocument {
    /// XML bytes that were signed.
    pub(crate) xml: String,
    /// Canonical public key identifying the bridge signer.
    pub(crate) public_key: String,
    /// Base64-encoded signature over the domain-separated XML bytes.
    pub(crate) signature: String,
}
#[derive(Clone, Debug, Default)]
/// Metadata captured while parsing an ISO 20022 payment message.
pub struct IsoMessageContext {
    ledger_id: Option<String>,
    source_account_id: Option<String>,
    source_account_address: Option<String>,
    target_account_id: Option<String>,
    target_account_address: Option<String>,
    asset_definition_id: Option<String>,
    asset_id: Option<String>,
    settlement_amount: Option<String>,
    settlement_currency: Option<String>,
    settlement_date: Option<String>,
    settlement_quantity: Option<String>,
    settlement_movement_type: Option<String>,
    settlement_payment_type: Option<String>,
    security_instrument_id: Option<String>,
    collateral_obligation_id: Option<String>,
    collateral_original_amount: Option<String>,
    collateral_original_currency: Option<String>,
    collateral_original_instrument_id: Option<String>,
    collateral_substitute_amount: Option<String>,
    collateral_substitute_currency: Option<String>,
    collateral_substitute_instrument_id: Option<String>,
    collateral_effective_date: Option<String>,
    collateral_substitution_type: Option<String>,
    collateral_haircut: Option<String>,
    collateral_reason_code: Option<String>,
    plan_execution_order: Option<String>,
    plan_atomicity: Option<String>,
}
impl IsoMessageContext {
    /// Ledger identifier supplied in the message, if any.
    pub fn ledger_id(&self) -> Option<&str> {
        self.ledger_id.as_deref()
    }
    /// Account ID of the sender once resolved from hints or aliases.
    pub fn source_account_id(&self) -> Option<&str> {
        self.source_account_id.as_deref()
    }
    /// Optional textual address associated with the sender.
    pub fn source_account_address(&self) -> Option<&str> {
        self.source_account_address.as_deref()
    }
    /// Account ID of the recipient once resolved from hints or aliases.
    pub fn target_account_id(&self) -> Option<&str> {
        self.target_account_id.as_deref()
    }
    /// Optional textual address associated with the recipient.
    pub fn target_account_address(&self) -> Option<&str> {
        self.target_account_address.as_deref()
    }
    /// Asset definition inferred for the transfer.
    pub fn asset_definition_id(&self) -> Option<&str> {
        self.asset_definition_id.as_deref()
    }
    /// Specific asset instance referenced by the message.
    pub fn asset_id(&self) -> Option<&str> {
        self.asset_id.as_deref()
    }
    /// Settlement amount carried by the ISO payment or securities instruction.
    pub fn settlement_amount(&self) -> Option<&str> {
        self.settlement_amount.as_deref()
    }
    /// Settlement currency carried by the ISO payment or securities instruction.
    pub fn settlement_currency(&self) -> Option<&str> {
        self.settlement_currency.as_deref()
    }
}
/// Profile and idempotency metadata captured for an inbound ISO message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IsoMessageMetadata {
    profile_id: Option<String>,
    message_type: Option<String>,
    business_service: Option<String>,
    business_message_id: Option<String>,
    uetr: Option<String>,
    payload_hash: Option<String>,
    reference_snapshot_id: Option<String>,
    embedded_signature_detected: bool,
}
impl IsoMessageMetadata {
    fn inbound(
        profile_id: &str,
        message_type: &str,
        business_service: Option<String>,
        business_message_id: Option<String>,
        uetr: Option<String>,
        payload_hash: String,
        reference_snapshot_id: String,
        embedded_signature_detected: bool,
    ) -> Self {
        Self {
            profile_id: Some(profile_id.to_owned()),
            message_type: Some(message_type.to_owned()),
            business_service,
            business_message_id,
            uetr,
            payload_hash: Some(payload_hash),
            reference_snapshot_id: Some(reference_snapshot_id),
            embedded_signature_detected,
        }
    }
    /// Selected rail profile identifier.
    pub fn profile_id(&self) -> Option<&str> {
        self.profile_id.as_deref()
    }
    /// ISO message family.
    pub fn message_type(&self) -> Option<&str> {
        self.message_type.as_deref()
    }
    /// Business service identifier from the Business Application Header.
    pub fn business_service(&self) -> Option<&str> {
        self.business_service.as_deref()
    }
    /// Business message identifier used for rail idempotency.
    pub fn business_message_id(&self) -> Option<&str> {
        self.business_message_id.as_deref()
    }
    /// UETR when present.
    pub fn uetr(&self) -> Option<&str> {
        self.uetr.as_deref()
    }
    /// SHA-256 hash of the submitted payload.
    pub fn payload_hash(&self) -> Option<&str> {
        self.payload_hash.as_deref()
    }
    /// Deterministic checksum of the reference-data snapshot used for validation.
    pub fn reference_snapshot_id(&self) -> Option<&str> {
        self.reference_snapshot_id.as_deref()
    }
    /// Whether an embedded XML signature subtree was observed.
    pub fn embedded_signature_detected(&self) -> bool {
        self.embedded_signature_detected
    }
}
/// Historical ISO bridge status transition.
#[derive(Clone, Debug)]
pub struct IsoStatusHistoryEntry {
    status: IsoMessageState,
    pacs002_code: Pacs002Status,
    updated_at: SystemTime,
    detail: Option<String>,
    reason_code: Option<String>,
}
impl IsoStatusHistoryEntry {
    fn new(record: &IsoMessageRecordV2) -> Self {
        Self {
            status: record.state,
            pacs002_code: record.derived_status(),
            updated_at: record.updated_at,
            detail: record.detail.clone(),
            reason_code: record.rejection_reason_code.clone(),
        }
    }
    /// Human-readable bridge state label.
    pub fn status_label(&self) -> &'static str {
        self.status.label()
    }
    /// ISO pacs.002 status code derived for this transition.
    pub fn pacs002_code(&self) -> &'static str {
        self.pacs002_code.code()
    }
    /// Transition timestamp.
    pub fn updated_at(&self) -> SystemTime {
        self.updated_at
    }
    /// Optional transition detail.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
    /// Optional ISO or proprietary reason code.
    pub fn reason_code(&self) -> Option<&str> {
        self.reason_code.as_deref()
    }
}
fn parse_account_address_literal(input: &str) -> Result<String, MsgError> {
    let address =
        AccountAddress::parse_encoded(input, None).map_err(|_| MsgError::ValidationFailed)?;
    address
        .canonical_hex()
        .map_err(|_| MsgError::ValidationFailed)
}
fn parse_iso_account_hint(
    literal: &str,
    telemetry: &MaybeTelemetry,
    context: &'static str,
) -> Result<(AccountId, String), MsgError> {
    let parsed = routing::parse_account_literal(literal, telemetry, context)
        .map_err(|_| MsgError::ValidationFailed)?;
    let canonical = parsed.to_string();
    Ok((parsed, canonical))
}
#[derive(Clone, Debug)]
pub struct IsoMessageStatus {
    message_id: String,
    state: IsoMessageState,
    transaction_hash: Option<String>,
    detail: Option<String>,
    updated_at: SystemTime,
    settled_at: Option<SystemTime>,
    context: IsoMessageContext,
    metadata: IsoMessageMetadata,
    derived_status: Pacs002Status,
    hold_reason_code: Option<String>,
    change_reason_codes: Vec<String>,
    rejection_reason_code: Option<String>,
    status_history: Vec<IsoStatusHistoryEntry>,
    parties: IsoRecordParties,
}
impl IsoMessageStatus {
    pub fn message_id(&self) -> &str {
        &self.message_id
    }
    pub fn status_label(&self) -> &'static str {
        self.state.label()
    }
    pub fn pacs002_code(&self) -> &'static str {
        self.derived_status.code()
    }
    pub fn transaction_hash(&self) -> Option<&str> {
        self.transaction_hash.as_deref()
    }
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
    pub fn updated_at(&self) -> SystemTime {
        self.updated_at
    }
    pub fn settled_at(&self) -> Option<SystemTime> {
        self.settled_at
    }
    pub fn ledger_id(&self) -> Option<&str> {
        self.context.ledger_id.as_deref()
    }
    pub fn source_account_id(&self) -> Option<&str> {
        self.context.source_account_id.as_deref()
    }
    pub fn source_account_address(&self) -> Option<&str> {
        self.context.source_account_address.as_deref()
    }
    pub fn target_account_id(&self) -> Option<&str> {
        self.context.target_account_id.as_deref()
    }
    pub fn target_account_address(&self) -> Option<&str> {
        self.context.target_account_address.as_deref()
    }
    pub fn asset_definition_id(&self) -> Option<&str> {
        self.context.asset_definition_id.as_deref()
    }
    pub fn asset_id(&self) -> Option<&str> {
        self.context.asset_id.as_deref()
    }
    pub fn settlement_amount(&self) -> Option<&str> {
        self.context.settlement_amount.as_deref()
    }
    pub fn settlement_currency(&self) -> Option<&str> {
        self.context.settlement_currency.as_deref()
    }
    pub fn settlement_date(&self) -> Option<&str> {
        self.context.settlement_date.as_deref()
    }
    pub fn settlement_quantity(&self) -> Option<&str> {
        self.context.settlement_quantity.as_deref()
    }
    pub fn settlement_movement_type(&self) -> Option<&str> {
        self.context.settlement_movement_type.as_deref()
    }
    pub fn settlement_payment_type(&self) -> Option<&str> {
        self.context.settlement_payment_type.as_deref()
    }
    pub fn security_instrument_id(&self) -> Option<&str> {
        self.context.security_instrument_id.as_deref()
    }
    pub fn collateral_obligation_id(&self) -> Option<&str> {
        self.context.collateral_obligation_id.as_deref()
    }
    pub fn collateral_original_amount(&self) -> Option<&str> {
        self.context.collateral_original_amount.as_deref()
    }
    pub fn collateral_original_currency(&self) -> Option<&str> {
        self.context.collateral_original_currency.as_deref()
    }
    pub fn collateral_original_instrument_id(&self) -> Option<&str> {
        self.context.collateral_original_instrument_id.as_deref()
    }
    pub fn collateral_substitute_amount(&self) -> Option<&str> {
        self.context.collateral_substitute_amount.as_deref()
    }
    pub fn collateral_substitute_currency(&self) -> Option<&str> {
        self.context.collateral_substitute_currency.as_deref()
    }
    pub fn collateral_substitute_instrument_id(&self) -> Option<&str> {
        self.context.collateral_substitute_instrument_id.as_deref()
    }
    pub fn collateral_effective_date(&self) -> Option<&str> {
        self.context.collateral_effective_date.as_deref()
    }
    pub fn collateral_substitution_type(&self) -> Option<&str> {
        self.context.collateral_substitution_type.as_deref()
    }
    pub fn collateral_haircut(&self) -> Option<&str> {
        self.context.collateral_haircut.as_deref()
    }
    pub fn collateral_reason_code(&self) -> Option<&str> {
        self.context.collateral_reason_code.as_deref()
    }
    pub fn plan_execution_order(&self) -> Option<&str> {
        self.context.plan_execution_order.as_deref()
    }
    pub fn plan_atomicity(&self) -> Option<&str> {
        self.context.plan_atomicity.as_deref()
    }
    pub fn derived_status(&self) -> Pacs002Status {
        self.derived_status
    }
    /// Profile/idempotency metadata captured for the message.
    pub fn metadata(&self) -> &IsoMessageMetadata {
        &self.metadata
    }
    pub fn hold_reason_code(&self) -> Option<&str> {
        self.hold_reason_code.as_deref()
    }
    pub fn change_reason_codes(&self) -> &[String] {
        &self.change_reason_codes
    }
    pub fn rejection_reason_code(&self) -> Option<&str> {
        self.rejection_reason_code.as_deref()
    }
    /// Status transition history for the message.
    pub fn status_history(&self) -> &[IsoStatusHistoryEntry] {
        &self.status_history
    }
    /// Stable participant that originated the initial ISO message.
    pub fn originator_participant_id(&self) -> &str {
        &self.parties.originator_participant_id
    }
    /// Stable participant expected to submit counterparty lifecycle messages.
    pub fn counterparty_participant_id(&self) -> &str {
        &self.parties.counterparty_participant_id
    }
    /// Participant whose authenticated operator admitted this exact message.
    pub fn admitting_participant_id(&self) -> &str {
        &self.parties.admitting_participant_id
    }
    /// Canonical public key of the authenticated admitting operator.
    pub fn admitting_operator_key(&self) -> &str {
        &self.parties.admitting_operator_key
    }
    /// Immutable rail/profile selected by the initial message.
    pub fn pinned_profile_id(&self) -> &str {
        &self.parties.pinned_profile_id
    }
    /// Immutable signature policy selected by the initial message.
    pub fn pinned_signature_policy(&self) -> &str {
        &self.parties.pinned_signature_policy
    }
    /// SHA-256 digest of the complete immutable rail-profile policy snapshot.
    #[cfg(test)]
    pub fn pinned_profile_policy_sha256(&self) -> &str {
        &self.parties.pinned_profile_policy_sha256
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IsoLifecycleOutcome {
    referenced_message_id: Option<String>,
    referenced_message_known: bool,
    lifecycle_status_code: Option<String>,
    lifecycle_reason_code: Option<String>,
    action: &'static str,
}
impl IsoLifecycleOutcome {
    pub(crate) fn referenced_message_id(&self) -> Option<&str> {
        self.referenced_message_id.as_deref()
    }
    pub(crate) fn referenced_message_known(&self) -> bool {
        self.referenced_message_known
    }
    pub(crate) fn lifecycle_status_code(&self) -> Option<&str> {
        self.lifecycle_status_code.as_deref()
    }
    pub(crate) fn lifecycle_reason_code(&self) -> Option<&str> {
        self.lifecycle_reason_code.as_deref()
    }
    pub(crate) fn action(&self) -> &'static str {
        self.action
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsoMessageState {
    Pending,
    Accepted,
    Rejected,
}
impl IsoMessageState {
    pub fn label(self) -> &'static str {
        match self {
            IsoMessageState::Pending => "Pending",
            IsoMessageState::Accepted => "Accepted",
            IsoMessageState::Rejected => "Rejected",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pacs002Status {
    Actc,
    Acsp,
    Acsc,
    Acwc,
    Pdng,
    Rjct,
}
impl Pacs002Status {
    pub fn code(self) -> &'static str {
        match self {
            Pacs002Status::Actc => "ACTC",
            Pacs002Status::Acsp => "ACSP",
            Pacs002Status::Acsc => "ACSC",
            Pacs002Status::Acwc => "ACWC",
            Pacs002Status::Pdng => "PDNG",
            Pacs002Status::Rjct => "RJCT",
        }
    }
}
#[derive(Clone, Debug)]
struct IsoMessageRecordV2 {
    incarnation: IsoRecordIncarnation,
    last_seen: Instant,
    updated_at: SystemTime,
    state: IsoMessageState,
    transaction_hash: Option<String>,
    detail: Option<String>,
    context: IsoMessageContext,
    metadata: IsoMessageMetadata,
    ledger_tx_queued: bool,
    settled_at: Option<SystemTime>,
    hold_reason_code: Option<String>,
    change_reason_codes: Vec<String>,
    rejection_reason_code: Option<String>,
    status_history: Vec<IsoStatusHistoryEntry>,
    parties: IsoRecordParties,
    replay_expires_at: SystemTime,
}
impl IsoMessageRecordV2 {
    fn pending(now: Instant) -> Self {
        let mut record = Self {
            incarnation: new_iso_record_incarnation(),
            last_seen: now,
            updated_at: SystemTime::now(),
            state: IsoMessageState::Pending,
            transaction_hash: None,
            detail: None,
            context: IsoMessageContext::default(),
            metadata: IsoMessageMetadata::default(),
            ledger_tx_queued: false,
            settled_at: None,
            hold_reason_code: None,
            change_reason_codes: Vec::new(),
            rejection_reason_code: None,
            status_history: Vec::new(),
            parties: IsoRecordParties::default(),
            replay_expires_at: SystemTime::now(),
        };
        record
            .try_push_history()
            .expect("the fixed pending history entry fits the V1 bounds");
        record
    }
    fn accepted(now: Instant, tx_hash: String) -> Self {
        let mut record = Self {
            incarnation: new_iso_record_incarnation(),
            last_seen: now,
            updated_at: SystemTime::now(),
            state: IsoMessageState::Accepted,
            transaction_hash: Some(tx_hash),
            detail: None,
            context: IsoMessageContext::default(),
            metadata: IsoMessageMetadata::default(),
            ledger_tx_queued: true,
            settled_at: None,
            hold_reason_code: None,
            change_reason_codes: Vec::new(),
            rejection_reason_code: None,
            status_history: Vec::new(),
            parties: IsoRecordParties::default(),
            replay_expires_at: SystemTime::now(),
        };
        record
            .try_push_history()
            .expect("the fixed accepted history entry fits the V1 bounds");
        record
    }
    fn rejected(
        now: Instant,
        detail: Option<String>,
        reason_code: Option<String>,
    ) -> Result<Self, IsoStatusHistoryLimitError> {
        let mut record = Self {
            incarnation: new_iso_record_incarnation(),
            last_seen: now,
            updated_at: SystemTime::now(),
            state: IsoMessageState::Rejected,
            transaction_hash: None,
            detail,
            context: IsoMessageContext::default(),
            metadata: IsoMessageMetadata::default(),
            ledger_tx_queued: false,
            settled_at: None,
            hold_reason_code: None,
            change_reason_codes: Vec::new(),
            rejection_reason_code: reason_code,
            status_history: Vec::new(),
            parties: IsoRecordParties::default(),
            replay_expires_at: SystemTime::now(),
        };
        record.try_push_history()?;
        Ok(record)
    }
    fn derived_status(&self) -> Pacs002Status {
        match self.state {
            IsoMessageState::Rejected => Pacs002Status::Rjct,
            IsoMessageState::Accepted => {
                if self.settled_at.is_some() {
                    Pacs002Status::Acsc
                } else {
                    Pacs002Status::Acsp
                }
            }
            IsoMessageState::Pending => {
                if self.hold_reason_code.is_some() {
                    Pacs002Status::Pdng
                } else if !self.change_reason_codes.is_empty() {
                    Pacs002Status::Acwc
                } else if self.ledger_tx_queued {
                    Pacs002Status::Acsp
                } else {
                    Pacs002Status::Actc
                }
            }
        }
    }
    fn set_hold_reason(&mut self, reason: Option<String>) {
        self.hold_reason_code = reason;
    }
    fn clear_hold(&mut self) {
        self.hold_reason_code = None;
    }
    fn add_change_reason_code(&mut self, code: String) {
        if !self
            .change_reason_codes
            .iter()
            .any(|existing| existing == &code)
        {
            self.change_reason_codes.push(code);
        }
    }
    fn set_queued(&mut self) {
        self.ledger_tx_queued = true;
    }
    fn mark_settled(&mut self, when: SystemTime) {
        self.settled_at = Some(when);
    }
    fn is_rejected(&self) -> bool {
        self.state == IsoMessageState::Rejected
    }
    fn is_settled(&self) -> bool {
        self.settled_at.is_some()
    }
    fn is_terminal(&self) -> bool {
        self.is_rejected() || self.is_settled()
    }
    fn retention_protected(&self) -> bool {
        self.state == IsoMessageState::Pending
            || (self.ledger_tx_queued && self.settled_at.is_none())
    }
    fn try_transition(
        &mut self,
        update: impl FnOnce(&mut Self),
    ) -> Result<bool, IsoStatusHistoryLimitError> {
        // Apply to a bounded candidate so an exhausted history never leaves the
        // authoritative record partially advanced without its audit entry.
        let mut candidate = self.clone();
        update(&mut candidate);
        candidate.validate_change_reason_codes()?;
        let appended = candidate.try_push_history()?;
        *self = candidate;
        Ok(appended)
    }
    fn try_push_history(&mut self) -> Result<bool, IsoStatusHistoryLimitError> {
        let derived_status = self.derived_status();
        let should_push = self.status_history.last().is_none_or(|last| {
            last.status != self.state
                || last.pacs002_code != derived_status
                || last.detail != self.detail
                || last.reason_code != self.rejection_reason_code
        });
        if !should_push {
            return Ok(false);
        }
        if self.status_history.len() >= ISO_STATUS_HISTORY_MAX_ENTRIES_V1 {
            return Err(IsoStatusHistoryLimitError::EntryCount);
        }
        let current_encoded_bytes = status_history_encoded_len(&self.status_history)
            .ok_or(IsoStatusHistoryLimitError::EncodedBytes)?;
        let entry_encoded_bytes = status_history_entry_encoded_len(
            self.state,
            derived_status,
            self.updated_at,
            self.detail.as_deref(),
            self.rejection_reason_code.as_deref(),
        )
        .ok_or(IsoStatusHistoryLimitError::EncodedBytes)?;
        let separator_bytes = usize::from(!self.status_history.is_empty());
        let prospective_encoded_bytes = current_encoded_bytes
            .checked_add(separator_bytes)
            .and_then(|bytes| bytes.checked_add(entry_encoded_bytes))
            .ok_or(IsoStatusHistoryLimitError::EncodedBytes)?;
        if prospective_encoded_bytes > ISO_STATUS_HISTORY_MAX_ENCODED_BYTES_V1 {
            return Err(IsoStatusHistoryLimitError::EncodedBytes);
        }
        self.status_history
            .try_reserve(1)
            .map_err(|_| IsoStatusHistoryLimitError::Allocation)?;
        let entry = IsoStatusHistoryEntry::new(self);
        self.status_history.push(entry);
        Ok(true)
    }
    fn validate_change_reason_codes(&self) -> Result<(), IsoStatusHistoryLimitError> {
        if self.change_reason_codes.len() > ISO_CHANGE_REASON_MAX_ENTRIES_V1 {
            return Err(IsoStatusHistoryLimitError::ChangeReasonCount);
        }
        let encoded_bytes = change_reason_codes_encoded_len(&self.change_reason_codes)
            .ok_or(IsoStatusHistoryLimitError::ChangeReasonEncodedBytes)?;
        if encoded_bytes > ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1 {
            return Err(IsoStatusHistoryLimitError::ChangeReasonEncodedBytes);
        }
        Ok(())
    }
}
const ISO_PACS008_CONTEXT: &str = "/v1/iso20022/pacs008";
const ISO_PACS009_CONTEXT: &str = "/v1/iso20022/pacs009";
const ISO_PERSISTED_RECORD_VERSION: u64 = 3;
const ISO_PERSISTED_RECORD_DIGEST_FIELD: &str = "record_sha256";
const ISO_PERSISTED_RECORD_MAX_BYTES: u64 = 1024 * 1024;
// The independent runtime ceiling keeps hand-built `actual` configs fail-closed too.
const ISO_PERSISTED_RECORD_MAX_COUNT_V1: u64 = 1_024;
// Recovery is a single bounded operation across both durable identity directories.
// The aggregate byte ceiling is intentionally independent of the per-record cap:
// a directory full of individually valid maximum-size records must not starve node startup.
const ISO_PERSISTED_STARTUP_MAX_ENTRIES_V1: u64 = ISO_PERSISTED_RECORD_MAX_COUNT_V1 * 2;
const ISO_PERSISTED_STARTUP_MAX_BYTES_V1: u64 = 256 * 1024 * 1024;
// V1 retains exact lifecycle evidence; it never rolls this append-only history forward.
const ISO_STATUS_HISTORY_MAX_ENTRIES_V1: usize = 256;
const ISO_STATUS_HISTORY_MAX_ENCODED_BYTES_V1: usize = 256 * 1024;
static ISO_RECORD_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const ISO_CHANGE_REASON_MAX_ENTRIES_V1: usize = 64;
const ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1: usize = 16 * 1024;
const ISO_PERSISTED_AUDIT_INDEX_VERSION: u64 = 3;
const ISO_PERSISTED_AUDIT_INDEX_MAX_BYTES: u64 = 32 * 1024 * 1024;
const ISO_PERSISTED_AUDIT_DIR: &str = "audit";
const ISO_PERSISTED_REPLAY_TOMBSTONE_DIR: &str = "replay_tombstones";
const ISO_PERSISTED_REPLAY_TOMBSTONE_VERSION: u64 = 2;
const ISO_PERSISTED_REPLAY_TOMBSTONE_DIGEST_FIELD: &str = "tombstone_sha256";
const ISO_PERSISTED_LIFECYCLE_OPERATION_DIR: &str = "lifecycle_operations";
const ISO_PERSISTED_LIFECYCLE_OPERATION_ID: &str = "pending-lifecycle-operation-v1";
const ISO_PERSISTED_LIFECYCLE_OPERATION_VERSION: u64 = 1;
const ISO_PERSISTED_LIFECYCLE_OPERATION_DIGEST_FIELD: &str = "operation_sha256";
const ISO_PERSISTED_LIFECYCLE_OPERATION_MAX_BYTES: u64 =
    ISO_PERSISTED_RECORD_MAX_BYTES * 2 + 256 * 1024;
const ISO_PERSISTED_LIFECYCLE_OPERATION_MAX_ENTRIES: u64 = 4;
const ISO_PERSISTED_AUDIT_INDEX_FILE: &str = "messages.index.json";
const ISO_PERSISTED_AUDIT_INDEX_DIGEST_FIELD: &str = "index_sha256";
const ISO_AUDIT_EXPORT_ANCHOR_VERSION: u64 = 1;
const ISO_AUDIT_EXPORT_ANCHOR_DIR: &str = "anchors";
const ISO_AUDIT_EXPORT_LATEST_ANCHOR_FILE: &str = "latest.notary.json";
const ISO_AUDIT_EXPORT_ANCHOR_DIGEST_FIELD: &str = "anchor_sha256";
#[cfg(not(test))]
const ISO_AUDIT_PERSISTENCE_RETRY_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(test)]
const ISO_AUDIT_PERSISTENCE_RETRY_INTERVAL: Duration = Duration::from_millis(25);

fn new_iso_record_incarnation() -> IsoRecordIncarnation {
    IsoRecordIncarnation(Arc::new(()))
}
const ISO4217_MAX_MINOR_UNITS: u8 = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IsoStatusHistoryLimitError {
    EntryCount,
    EncodedBytes,
    ChangeReasonCount,
    ChangeReasonEncodedBytes,
    Allocation,
    MissingReservation,
    Persistence,
}
/// Failure while applying an admitted ISO lifecycle message.
#[derive(Debug)]
pub(crate) enum IsoLifecycleApplyError {
    /// The message cannot be applied to the currently authorized record.
    Validation(MsgError),
    /// Durable commit state is unavailable or indeterminate and may be retried.
    PersistenceUnavailable,
}
impl From<MsgError> for IsoLifecycleApplyError {
    fn from(error: MsgError) -> Self {
        Self::Validation(error)
    }
}
impl core::fmt::Display for IsoLifecycleApplyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Validation(error) => core::fmt::Display::fmt(error, formatter),
            Self::PersistenceUnavailable => {
                formatter.write_str("ISO lifecycle persistence is temporarily unavailable")
            }
        }
    }
}
#[derive(Clone, Debug)]
struct IsoPreparedRecordMutation {
    message_id: String,
    previous: IsoMessageRecordV2,
    candidate: IsoMessageRecordV2,
}
#[derive(Clone, Debug)]
struct IsoLifecycleJournalMutation {
    message_id: String,
    previous_record_sha256: String,
    after_record: JsonValue,
}
#[derive(Clone, Debug)]
struct IsoLifecycleJournal {
    original: Option<IsoLifecycleJournalMutation>,
    lifecycle: IsoLifecycleJournalMutation,
}
#[derive(Clone, Copy, Debug)]
struct IsoStartupScanBudget {
    entries: u64,
    bytes: u64,
    max_entries: u64,
    max_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IsoDurableRecordKind {
    Message,
    ReplayTombstone,
}
impl IsoDurableRecordKind {
    fn label(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::ReplayTombstone => "replay tombstone",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IsoDurableStoreUsageError {
    DuplicateEntry,
    EntryBytes,
    DirectoryEntries,
    AggregateEntries,
    AggregateBytes,
    Accounting,
}
#[derive(Clone, Debug)]
struct IsoDurableStoreUsage {
    message_bytes: HashMap<String, u64>,
    tombstone_bytes: HashMap<String, u64>,
    bytes: u64,
    max_directory_entries: u64,
    max_entries: u64,
    max_bytes: u64,
}
impl IsoDurableStoreUsage {
    fn v1() -> Self {
        Self {
            message_bytes: HashMap::new(),
            tombstone_bytes: HashMap::new(),
            bytes: 0,
            max_directory_entries: ISO_PERSISTED_RECORD_MAX_COUNT_V1,
            max_entries: ISO_PERSISTED_STARTUP_MAX_ENTRIES_V1,
            max_bytes: ISO_PERSISTED_STARTUP_MAX_BYTES_V1,
        }
    }
    fn entries(&self, kind: IsoDurableRecordKind) -> &HashMap<String, u64> {
        match kind {
            IsoDurableRecordKind::Message => &self.message_bytes,
            IsoDurableRecordKind::ReplayTombstone => &self.tombstone_bytes,
        }
    }
    fn entries_mut(&mut self, kind: IsoDurableRecordKind) -> &mut HashMap<String, u64> {
        match kind {
            IsoDurableRecordKind::Message => &mut self.message_bytes,
            IsoDurableRecordKind::ReplayTombstone => &mut self.tombstone_bytes,
        }
    }
    fn replacement_total_bytes(
        &self,
        kind: IsoDurableRecordKind,
        message_id: &str,
        bytes: u64,
    ) -> Result<u64, IsoDurableStoreUsageError> {
        if bytes > ISO_PERSISTED_RECORD_MAX_BYTES {
            return Err(IsoDurableStoreUsageError::EntryBytes);
        }
        let entries = self.entries(kind);
        let previous_bytes = entries.get(message_id).copied().unwrap_or(0);
        let is_new = !entries.contains_key(message_id);
        let new_entries = if is_new { 1 } else { 0 };
        let directory_entries = u64::try_from(entries.len())
            .map_err(|_| IsoDurableStoreUsageError::Accounting)?
            .checked_add(new_entries)
            .ok_or(IsoDurableStoreUsageError::Accounting)?;
        if directory_entries > self.max_directory_entries {
            return Err(IsoDurableStoreUsageError::DirectoryEntries);
        }
        let aggregate_entries = u64::try_from(self.message_bytes.len())
            .ok()
            .and_then(|messages| {
                u64::try_from(self.tombstone_bytes.len())
                    .ok()
                    .and_then(|tombstones| messages.checked_add(tombstones))
            })
            .and_then(|entries| entries.checked_add(new_entries))
            .ok_or(IsoDurableStoreUsageError::Accounting)?;
        if aggregate_entries > self.max_entries {
            return Err(IsoDurableStoreUsageError::AggregateEntries);
        }
        let next_bytes = self
            .bytes
            .checked_sub(previous_bytes)
            .and_then(|retained| retained.checked_add(bytes))
            .ok_or(IsoDurableStoreUsageError::Accounting)?;
        if next_bytes > self.max_bytes {
            return Err(IsoDurableStoreUsageError::AggregateBytes);
        }
        Ok(next_bytes)
    }
    fn record_replacement(
        &mut self,
        kind: IsoDurableRecordKind,
        message_id: &str,
        bytes: u64,
    ) -> Result<(), IsoDurableStoreUsageError> {
        let next_bytes = self.replacement_total_bytes(kind, message_id, bytes)?;
        self.commit_replacement(kind, message_id, bytes, next_bytes);
        Ok(())
    }
    fn replacements_fit(
        &self,
        replacements: &[(IsoDurableRecordKind, &str, u64)],
    ) -> Result<(), IsoDurableStoreUsageError> {
        let mut planned = self.clone();
        for (kind, message_id, bytes) in replacements {
            planned.record_replacement(*kind, message_id, *bytes)?;
        }
        Ok(())
    }
    fn commit_replacement(
        &mut self,
        kind: IsoDurableRecordKind,
        message_id: &str,
        bytes: u64,
        next_bytes: u64,
    ) {
        self.entries_mut(kind).insert(message_id.to_owned(), bytes);
        self.bytes = next_bytes;
    }
    fn record_existing(
        &mut self,
        kind: IsoDurableRecordKind,
        message_id: &str,
        bytes: u64,
    ) -> Result<(), IsoDurableStoreUsageError> {
        if self.entries(kind).contains_key(message_id) {
            return Err(IsoDurableStoreUsageError::DuplicateEntry);
        }
        self.record_replacement(kind, message_id, bytes)
    }
    fn remove(
        &mut self,
        kind: IsoDurableRecordKind,
        message_id: &str,
    ) -> Result<(), IsoDurableStoreUsageError> {
        let Some(bytes) = self.entries(kind).get(message_id).copied() else {
            return Ok(());
        };
        let next_bytes = self
            .bytes
            .checked_sub(bytes)
            .ok_or(IsoDurableStoreUsageError::Accounting)?;
        self.entries_mut(kind).remove(message_id);
        self.bytes = next_bytes;
        Ok(())
    }
}
impl IsoStartupScanBudget {
    fn v1() -> Self {
        Self {
            entries: 0,
            bytes: 0,
            max_entries: ISO_PERSISTED_STARTUP_MAX_ENTRIES_V1,
            max_bytes: ISO_PERSISTED_STARTUP_MAX_BYTES_V1,
        }
    }
    fn charge_entry(&mut self, path: &Path, bytes: u64) -> eyre::Result<()> {
        self.entries = self.entries.checked_add(1).ok_or_else(|| {
            eyre::eyre!(
                "ISO bridge startup entry counter overflowed at `{}`",
                path.display()
            )
        })?;
        if self.entries > self.max_entries {
            eyre::bail!(
                "ISO bridge durable store exceeds the V1 startup work limit of {} entries; regenerate the first-release ISO store",
                self.max_entries
            );
        }
        if bytes > ISO_PERSISTED_RECORD_MAX_BYTES {
            eyre::bail!(
                "ISO bridge durable record `{}` exceeds the V1 per-entry byte limit of {ISO_PERSISTED_RECORD_MAX_BYTES}; regenerate the first-release ISO store",
                path.display()
            );
        }
        self.charge_bytes(path, bytes)
    }
    fn charge_bytes(&mut self, path: &Path, bytes: u64) -> eyre::Result<()> {
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(|| {
            eyre::eyre!(
                "ISO bridge startup byte counter overflowed at `{}`",
                path.display()
            )
        })?;
        if self.bytes > self.max_bytes {
            eyre::bail!(
                "ISO bridge durable store exceeds the V1 aggregate startup byte limit of {}; regenerate the first-release ISO store",
                self.max_bytes
            );
        }
        Ok(())
    }
}
fn parse_config_account_id(literal: &str, field: &str) -> eyre::Result<AccountId> {
    AccountId::parse_encoded(literal)
        .wrap_err_with(|| format!("{field} must parse as an account identifier"))
}
fn parse_participant_role(value: &str) -> eyre::Result<IsoParticipantRole> {
    match value.trim().to_ascii_lowercase().as_str() {
        "originator" => Ok(IsoParticipantRole::Originator),
        "counterparty" => Ok(IsoParticipantRole::Counterparty),
        other => eyre::bail!(
            "iso_bridge participant role `{other}` is invalid; expected `originator` or `counterparty`"
        ),
    }
}
fn normalise_financial_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return None;
    }
    Some(value.to_ascii_uppercase())
}
fn validate_participant_id(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed != value
        || value.is_empty()
        || value.len() > 128
        || value
            .chars()
            .any(|ch| !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_')))
        || !value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
    {
        return None;
    }
    Some(value)
}
fn load_participant_catalog(
    config: &actual::IsoBridge,
    profiles: &HashMap<String, TradfiRailProfile>,
) -> eyre::Result<(
    BTreeMap<PublicKey, IsoBridgeParticipant>,
    HashMap<String, String>,
    BTreeSet<PublicKey>,
)> {
    if config.participants.is_empty() {
        eyre::bail!(
            "iso_bridge participants must be configured when enabled; legacy unscoped bridge configuration is incompatible with ISO record schema V3"
        );
    }
    let mut participant_ids = BTreeSet::new();
    let mut participants_by_key = BTreeMap::new();
    let mut participants_by_financial_id = HashMap::new();
    for configured in &config.participants {
        let id = validate_participant_id(&configured.id).ok_or_else(|| {
            eyre::eyre!(
                "iso_bridge participant id `{}` must be a canonical lowercase ASCII identifier of at most 128 bytes",
                configured.id
            )
        })?;
        if !participant_ids.insert(id.to_owned()) {
            eyre::bail!("iso_bridge participant id `{id}` is duplicated");
        }
        if configured.operator_keys.is_empty() {
            eyre::bail!("iso_bridge participant `{id}` must define at least one operator key");
        }
        if configured.financial_identifiers.is_empty() {
            eyre::bail!(
                "iso_bridge participant `{id}` must define at least one financial identifier"
            );
        }
        if configured.allowed_profiles.is_empty() {
            eyre::bail!("iso_bridge participant `{id}` must allow at least one profile");
        }
        if configured.roles.is_empty() {
            eyre::bail!("iso_bridge participant `{id}` must define at least one role");
        }
        let financial_identifiers = configured
            .financial_identifiers
            .iter()
            .map(|value| {
                normalise_financial_identifier(value).ok_or_else(|| {
                    eyre::eyre!(
                        "iso_bridge participant `{id}` has invalid financial identifier `{value}`"
                    )
                })
            })
            .collect::<eyre::Result<BTreeSet<_>>>()?;
        if financial_identifiers.len() != configured.financial_identifiers.len() {
            eyre::bail!(
                "iso_bridge participant `{id}` financial identifiers must be duplicate-free"
            );
        }
        let allowed_profiles = configured
            .allowed_profiles
            .iter()
            .map(|profile| {
                let profile = require_trimmed_non_empty(
                    &format!("iso_bridge participant `{id}` allowed profile"),
                    profile,
                )?;
                if !profiles.contains_key(profile) {
                    eyre::bail!(
                        "iso_bridge participant `{id}` references unknown profile `{profile}`"
                    );
                }
                Ok(profile.to_owned())
            })
            .collect::<eyre::Result<BTreeSet<_>>>()?;
        if allowed_profiles.len() != configured.allowed_profiles.len() {
            eyre::bail!("iso_bridge participant `{id}` allowed profiles must be duplicate-free");
        }
        let roles = configured
            .roles
            .iter()
            .map(|role| parse_participant_role(role))
            .collect::<eyre::Result<BTreeSet<_>>>()?;
        if roles.len() != configured.roles.len() {
            eyre::bail!("iso_bridge participant `{id}` roles must be duplicate-free");
        }
        let participant = IsoBridgeParticipant {
            id: id.to_owned(),
            financial_identifiers: financial_identifiers.clone(),
            allowed_profiles,
            roles,
        };
        for key in &configured.operator_keys {
            if participants_by_key
                .insert(key.clone(), participant.clone())
                .is_some()
            {
                eyre::bail!("iso_bridge operator keys must be unique across participants");
            }
        }
        for identifier in financial_identifiers {
            if participants_by_financial_id
                .insert(identifier.clone(), id.to_owned())
                .is_some()
            {
                eyre::bail!(
                    "iso_bridge financial identifier `{identifier}` is owned by more than one participant"
                );
            }
        }
    }
    if !participants_by_key
        .values()
        .any(|participant| participant.roles.contains(&IsoParticipantRole::Originator))
    {
        eyre::bail!("iso_bridge must configure at least one originator participant");
    }
    if !participants_by_key.values().any(|participant| {
        participant
            .roles
            .contains(&IsoParticipantRole::Counterparty)
    }) {
        eyre::bail!("iso_bridge must configure at least one counterparty participant");
    }
    let audit_admin_keys = config
        .audit_admin_keys
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if audit_admin_keys.len() != config.audit_admin_keys.len() {
        eyre::bail!("iso_bridge audit_admin_keys must be duplicate-free");
    }
    if let Some(key) = audit_admin_keys
        .iter()
        .find(|key| participants_by_key.contains_key(*key))
    {
        eyre::bail!(
            "iso_bridge audit-admin key `{key}` must not also be a participant mutation key"
        );
    }
    Ok((
        participants_by_key,
        participants_by_financial_id,
        audit_admin_keys,
    ))
}
fn load_profile_catalog(
    config: &actual::IsoBridge,
) -> eyre::Result<HashMap<String, TradfiRailProfile>> {
    let mut catalog = profiles::default_profile_catalog();
    let global_policy = config
        .embedded_signature_policy
        .as_deref()
        .map(parse_signature_policy)
        .transpose()?;
    if let Some(policy) = global_policy {
        for profile in catalog.values_mut() {
            profile.embedded_signature_policy = policy;
        }
    }
    let mut override_profile_ids = HashSet::new();
    for override_profile in &config.profiles {
        let profile = convert_config_profile(override_profile, global_policy)?;
        if !override_profile_ids.insert(profile.id.to_ascii_lowercase()) {
            eyre::bail!(
                "iso_bridge profile overrides must not contain duplicate profile id `{}`",
                profile.id
            );
        }
        catalog.insert(profile.id.clone(), profile);
    }
    let default_id =
        require_trimmed_non_empty("iso_bridge default_profile", &config.default_profile)?;
    if !catalog.contains_key(default_id) {
        eyre::bail!("iso_bridge default_profile `{default_id}` is not configured");
    }
    Ok(catalog.into_iter().collect())
}
fn convert_config_profile(
    config: &actual::IsoBridgeProfile,
    global_policy: Option<EmbeddedSignaturePolicy>,
) -> eyre::Result<TradfiRailProfile> {
    let id = require_trimmed_non_empty("iso_bridge profile id", &config.id)?;
    require_trimmed_non_empty(&format!("iso_bridge profile `{id}` rail"), &config.rail)?;
    let rail = TradfiRail::parse(&config.rail).ok_or_else(|| {
        eyre::eyre!(
            "iso_bridge profile `{id}` has unknown rail `{}`",
            config.rail
        )
    })?;
    let embedded_signature_policy = config
        .embedded_signature_policy
        .as_deref()
        .map(parse_signature_policy)
        .transpose()?
        .or(global_policy)
        .unwrap_or(EmbeddedSignaturePolicy::RecordOnly);
    let revoked_certificate_sha256 = normalise_profile_sha256_pins(
        id,
        "revoked_certificate_sha256",
        &config.revoked_certificate_sha256,
    )?;
    let required_reference_datasets =
        normalise_required_reference_datasets(id, &config.required_reference_datasets)?;
    let message_profiles = config
        .message_profiles
        .iter()
        .map(|message| convert_config_message_profile(id, message))
        .collect::<eyre::Result<Vec<_>>>()?;
    validate_profile_message_entries(id, &message_profiles)?;
    let signature_public_key_sha256_pins = normalise_profile_sha256_pins(
        id,
        "signature_public_key_sha256_pins",
        &config.signature_public_key_sha256_pins,
    )?;
    let x509_trust_anchor_sha256_pins = normalise_profile_sha256_pins(
        id,
        "x509_trust_anchor_sha256_pins",
        &config.x509_trust_anchor_sha256_pins,
    )?;
    reject_profile_sha256_overlap(
        id,
        "signature_public_key_sha256_pins",
        &signature_public_key_sha256_pins,
        "x509_trust_anchor_sha256_pins",
        &x509_trust_anchor_sha256_pins,
    )?;
    reject_profile_sha256_overlap(
        id,
        "x509_trust_anchor_sha256_pins",
        &x509_trust_anchor_sha256_pins,
        "revoked_certificate_sha256",
        &revoked_certificate_sha256,
    )?;
    reject_profile_sha256_overlap(
        id,
        "signature_public_key_sha256_pins",
        &signature_public_key_sha256_pins,
        "revoked_certificate_sha256",
        &revoked_certificate_sha256,
    )?;
    let x509_required_certificate_policy_oids = normalise_profile_oid_literals(
        id,
        "x509_required_certificate_policy_oids",
        &config.x509_required_certificate_policy_oids,
    )?;
    let x509_crl_der_base64 =
        normalise_profile_crl_der_base64(id, "x509_crl_der_base64", &config.x509_crl_der_base64)?;
    let x509_ocsp_response_der_base64 = normalise_profile_ocsp_response_der_base64(
        id,
        "x509_ocsp_response_der_base64",
        &config.x509_ocsp_response_der_base64,
    )?;
    if message_profiles.is_empty() {
        eyre::bail!("iso_bridge profile `{id}` must define at least one message profile");
    }
    Ok(TradfiRailProfile {
        id: id.to_owned(),
        rail,
        embedded_signature_policy,
        signature_public_key_sha256_pins,
        x509_trust_anchor_sha256_pins,
        x509_required_certificate_policy_oids,
        x509_require_crl_revocation_check: config.x509_require_crl_revocation_check,
        x509_crl_der_base64,
        x509_require_ocsp_revocation_check: config.x509_require_ocsp_revocation_check,
        x509_ocsp_response_der_base64,
        revoked_certificate_sha256,
        required_reference_datasets,
        message_profiles,
    })
}
fn normalise_required_reference_datasets(
    profile_id: &str,
    values: &[String],
) -> eyre::Result<Vec<ReferenceDatasetRequirement>> {
    let mut datasets = Vec::new();
    for dataset in values {
        require_trimmed_non_empty(
            &format!("iso_bridge profile `{profile_id}` required_reference_datasets entry"),
            dataset,
        )?;
        let requirement = ReferenceDatasetRequirement::parse(dataset).ok_or_else(|| {
            eyre::eyre!(
                "iso_bridge profile `{profile_id}` has unknown reference dataset `{dataset}`"
            )
        })?;
        if datasets.contains(&requirement) {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` required_reference_datasets entries must be duplicate-free"
            );
        }
        datasets.push(requirement);
    }
    Ok(datasets)
}
fn validate_profile_message_entries(
    profile_id: &str,
    message_profiles: &[MessageProfile],
) -> eyre::Result<()> {
    let mut seen = BTreeSet::new();
    for profile in message_profiles {
        let key = (profile.message_type.to_ascii_lowercase(), profile.direction);
        if !seen.insert(key) {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` message_profiles entries must be unique by message_type and direction"
            );
        }
    }
    Ok(())
}
fn convert_config_message_profile(
    profile_id: &str,
    config: &actual::IsoMessageProfile,
) -> eyre::Result<MessageProfile> {
    let message_type = require_trimmed_non_empty(
        &format!("iso_bridge profile `{profile_id}` message_type"),
        &config.message_type,
    )?;
    require_trimmed_non_empty(
        &format!("iso_bridge profile `{profile_id}` message `{message_type}` direction"),
        &config.direction,
    )?;
    let direction = MessageDirection::parse(&config.direction).ok_or_else(|| {
        eyre::eyre!(
            "iso_bridge profile `{profile_id}` message `{message_type}` has unknown direction `{}`",
            config.direction
        )
    })?;
    require_trimmed_non_empty(
        &format!(
            "iso_bridge profile `{profile_id}` message `{message_type}` structured_address_mode"
        ),
        &config.structured_address_mode,
    )?;
    let structured_address_mode =
        StructuredAddressMode::parse(&config.structured_address_mode).ok_or_else(|| {
            eyre::eyre!(
                "iso_bridge profile `{profile_id}` message `{message_type}` has unknown structured_address_mode `{}`",
                config.structured_address_mode
            )
        })?;
    let amount_minor_units =
        normalise_amount_minor_units(profile_id, message_type, &config.amount_minor_units)?;
    let versions = normalise_message_versions(profile_id, message_type, &config.versions)?;
    let business_services = normalise_business_services(
        profile_id,
        message_type,
        &config.business_services,
        config.require_business_service,
    )?;
    Ok(MessageProfile {
        message_type: message_type.to_owned(),
        direction,
        versions,
        business_services,
        require_app_header: config.require_app_header,
        require_business_service: config.require_business_service,
        require_uetr: config.require_uetr,
        structured_address_mode,
        supplementary_data_max_bytes: config.supplementary_data_max_bytes,
        amount_minor_units,
    })
}
fn normalise_message_versions(
    profile_id: &str,
    message_type: &str,
    values: &[String],
) -> eyre::Result<Vec<String>> {
    if values.is_empty() {
        eyre::bail!(
            "iso_bridge profile `{profile_id}` message `{message_type}` requires at least one versions entry"
        );
    }
    values
        .iter()
        .map(|version| {
            if version.trim().is_empty() || version.trim() != version {
                eyre::bail!(
                    "iso_bridge profile `{profile_id}` message `{message_type}` versions entries must be non-empty trimmed strings"
                );
            }
            Ok(version.clone())
        })
        .collect::<eyre::Result<Vec<_>>>()
        .and_then(|versions| {
            let mut seen = HashSet::new();
            for version in &versions {
                if !seen.insert(version.to_ascii_lowercase()) {
                    eyre::bail!(
                        "iso_bridge profile `{profile_id}` message `{message_type}` versions entries must be duplicate-free"
                    );
                }
            }
            Ok(versions)
        })
}
fn normalise_business_services(
    profile_id: &str,
    message_type: &str,
    values: &[String],
    require_business_service: bool,
) -> eyre::Result<Vec<String>> {
    if require_business_service && values.is_empty() {
        eyre::bail!(
            "iso_bridge profile `{profile_id}` message `{message_type}` requires at least one business_services entry"
        );
    }
    values
        .iter()
        .map(|service| {
            if service.trim().is_empty() || service.trim() != service {
                eyre::bail!(
                    "iso_bridge profile `{profile_id}` message `{message_type}` business_services entries must be non-empty trimmed strings"
                );
            }
            Ok(service.clone())
        })
        .collect::<eyre::Result<Vec<_>>>()
        .and_then(|services| {
            let mut seen = HashSet::new();
            for service in &services {
                if !seen.insert(service.to_ascii_lowercase()) {
                    eyre::bail!(
                        "iso_bridge profile `{profile_id}` message `{message_type}` business_services entries must be duplicate-free"
                    );
                }
            }
            Ok(services)
        })
}
fn normalise_amount_minor_units(
    profile_id: &str,
    message_type: &str,
    values: &[actual::IsoCurrencyMinorUnit],
) -> eyre::Result<BTreeMap<String, u8>> {
    let mut amount_minor_units = BTreeMap::new();
    for entry in values {
        require_trimmed_non_empty(
            &format!(
                "iso_bridge profile `{profile_id}` message `{message_type}` amount_minor_units currency"
            ),
            &entry.currency,
        )?;
        let currency = normalise_currency(&entry.currency);
        if !ivm::iso20022::validate_identifier(IdentifierKind::Currency, &currency) {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` message `{message_type}` has invalid currency `{}`",
                entry.currency
            );
        }
        if entry.minor_units > ISO4217_MAX_MINOR_UNITS {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` message `{message_type}` currency `{currency}` minor_units must be at most {ISO4217_MAX_MINOR_UNITS}"
            );
        }
        if amount_minor_units
            .insert(currency.clone(), entry.minor_units)
            .is_some()
        {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` message `{message_type}` amount_minor_units contains duplicate currency `{currency}`"
            );
        }
    }
    Ok(amount_minor_units)
}
fn require_trimmed_non_empty<'a>(label: &str, value: &'a str) -> eyre::Result<&'a str> {
    if value.is_empty() || value.trim() != value {
        eyre::bail!("{label} must be a non-empty trimmed string");
    }
    Ok(value)
}
fn parse_signature_policy(value: &str) -> eyre::Result<EmbeddedSignaturePolicy> {
    require_trimmed_non_empty("ISO embedded signature policy", value)?;
    EmbeddedSignaturePolicy::parse(value)
        .ok_or_else(|| eyre::eyre!("unknown ISO embedded signature policy `{value}`"))
}
fn normalise_profile_sha256_pins(
    profile_id: &str,
    field: &str,
    pins: &[String],
) -> eyre::Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for pin in pins {
        let candidate = pin.as_str();
        if candidate.len() != 64
            || !candidate
                .chars()
                .all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
        {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` {field} entries must be canonical lowercase 64-character SHA-256 hex strings"
            );
        }
        if candidate.chars().all(|ch| ch == '0') {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` {field} must not contain the all-zero placeholder"
            );
        }
        if seen.insert(candidate.to_owned()) {
            normalized.push(candidate.to_owned());
        }
    }
    Ok(normalized)
}
fn reject_profile_sha256_overlap(
    profile_id: &str,
    left_field: &str,
    left: &[String],
    right_field: &str,
    right: &[String],
) -> eyre::Result<()> {
    let left_values = left.iter().collect::<HashSet<_>>();
    for value in right {
        if left_values.contains(value) {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` fields `{left_field}` and `{right_field}` must not overlap"
            );
        }
    }
    Ok(())
}
fn normalise_profile_oid_literals(
    profile_id: &str,
    field: &str,
    values: &[String],
) -> eyre::Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let candidate = require_trimmed_non_empty(
            &format!("iso_bridge profile `{profile_id}` {field} entry"),
            value,
        )?;
        if !is_valid_oid_literal(&candidate) {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` {field} entries must be dotted numeric OIDs"
            );
        }
        if !seen.insert(candidate.to_owned()) {
            eyre::bail!("iso_bridge profile `{profile_id}` {field} entries must be duplicate-free");
        }
        normalized.push(candidate.to_owned());
    }
    Ok(normalized)
}
fn normalise_profile_crl_der_base64(
    profile_id: &str,
    field: &str,
    values: &[String],
) -> eyre::Result<Vec<String>> {
    if values.len() > XMLDSIG_MAX_X509_CRLS {
        eyre::bail!(
            "iso_bridge profile `{profile_id}` {field} must not contain more than {XMLDSIG_MAX_X509_CRLS} CRLs"
        );
    }
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let candidate = require_trimmed_non_empty(
            &format!("iso_bridge profile `{profile_id}` {field} entry"),
            value,
        )?;
        let der = BASE64_STANDARD.decode(candidate).map_err(|_| {
            eyre::eyre!("iso_bridge profile `{profile_id}` {field} entries must be base64 DER CRLs")
        })?;
        if der.is_empty() || der.len() > XMLDSIG_MAX_X509_CRL_BYTES {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` {field} entries must be non-empty CRLs no larger than {XMLDSIG_MAX_X509_CRL_BYTES} bytes"
            );
        }
        parse_x509_crl_der(&der).map_err(|_| {
            eyre::eyre!("iso_bridge profile `{profile_id}` {field} entries must parse as DER CRLs")
        })?;
        if !seen.insert(sha256_hex(&der)) {
            eyre::bail!("iso_bridge profile `{profile_id}` {field} entries must be duplicate-free");
        }
        normalized.push(BASE64_STANDARD.encode(&der));
    }
    Ok(normalized)
}
fn normalise_profile_ocsp_response_der_base64(
    profile_id: &str,
    field: &str,
    values: &[String],
) -> eyre::Result<Vec<String>> {
    if values.len() > XMLDSIG_MAX_X509_OCSP_RESPONSES {
        eyre::bail!(
            "iso_bridge profile `{profile_id}` {field} must not contain more than {XMLDSIG_MAX_X509_OCSP_RESPONSES} OCSP responses"
        );
    }
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let candidate = require_trimmed_non_empty(
            &format!("iso_bridge profile `{profile_id}` {field} entry"),
            value,
        )?;
        let der = BASE64_STANDARD.decode(candidate).map_err(|_| {
            eyre::eyre!(
                "iso_bridge profile `{profile_id}` {field} entries must be base64 DER OCSP responses"
            )
        })?;
        if der.is_empty() || der.len() > XMLDSIG_MAX_X509_OCSP_RESPONSE_BYTES {
            eyre::bail!(
                "iso_bridge profile `{profile_id}` {field} entries must be non-empty OCSP responses no larger than {XMLDSIG_MAX_X509_OCSP_RESPONSE_BYTES} bytes"
            );
        }
        parse_ocsp_response_der(&der).map_err(|_| {
            eyre::eyre!(
                "iso_bridge profile `{profile_id}` {field} entries must parse as DER OCSP responses"
            )
        })?;
        if !seen.insert(sha256_hex(&der)) {
            eyre::bail!("iso_bridge profile `{profile_id}` {field} entries must be duplicate-free");
        }
        normalized.push(BASE64_STANDARD.encode(&der));
    }
    Ok(normalized)
}
fn is_valid_oid_literal(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    if first.is_empty()
        || second.is_empty()
        || !first.chars().all(|ch| ch.is_ascii_digit())
        || !second.chars().all(|ch| ch.is_ascii_digit())
    {
        return false;
    }
    if !parts.all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit())) {
        return false;
    }
    let Ok(first_arc) = first.parse::<u32>() else {
        return false;
    };
    let Ok(second_arc) = second.parse::<u32>() else {
        return false;
    };
    first_arc <= 2 && (first_arc == 2 || second_arc <= 39)
}
impl Iso20022BridgeRuntime {
    /// Construct runtime helper from user configuration.
    pub fn from_config(config: &actual::IsoBridge) -> eyre::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        if config.max_body_bytes.get() == 0 {
            eyre::bail!("iso_bridge max_body_bytes must be greater than zero");
        }
        if config.store_max_records == 0 {
            eyre::bail!("iso_bridge store_max_records must be greater than zero");
        }
        if config.store_max_records > ISO_PERSISTED_RECORD_MAX_COUNT_V1 {
            eyre::bail!(
                "iso_bridge store_max_records must not exceed the first-release hard maximum of {ISO_PERSISTED_RECORD_MAX_COUNT_V1}"
            );
        }
        let store_max_records = usize::try_from(config.store_max_records)
            .wrap_err("iso_bridge store_max_records must fit the platform address space")?;
        let signer = config
            .signer
            .as_ref()
            .ok_or_else(|| eyre::eyre!("iso_bridge signer must be configured when enabled"))?;
        let signer_account =
            parse_config_account_id(&signer.account_id, "iso_bridge signer account_id")?;
        let signer_private_key = signer.private_key.clone();
        let signer_public_key = KeyPair::from_private_key(signer_private_key.clone())
            .wrap_err("iso_bridge signer private_key is invalid")?
            .public_key()
            .clone();
        let mut aliases = HashMap::new();
        for alias in &config.account_aliases {
            let iban = normalise_iban(&alias.iban);
            if !ivm::iso20022::validate_identifier(IdentifierKind::Iban, &iban) {
                eyre::bail!(
                    "iso_bridge account alias `{}` is not a valid IBAN",
                    alias.iban
                );
            }
            let account_id = parse_config_account_id(
                &alias.account_id,
                &format!("iso_bridge account alias `{iban}` account_id"),
            )?;
            aliases.insert(iban, account_id);
        }
        #[cfg(test)]
        let (alias_indices, index_aliases) = {
            let mut alias_indices = HashMap::new();
            let mut index_aliases = BTreeMap::new();
            for (position, alias) in config.account_aliases.iter().enumerate() {
                let iban = normalise_iban(&alias.iban);
                let index = AliasIndex(position as u64);
                alias_indices.insert(iban.clone(), index);
                index_aliases.insert(index, (iban.clone(), aliases[&iban].clone()));
            }
            (alias_indices, index_aliases)
        };
        let mut currencies = HashMap::new();
        for binding in &config.currency_assets {
            let currency = normalise_currency(&binding.currency);
            if !ivm::iso20022::validate_identifier(IdentifierKind::Currency, &currency) {
                eyre::bail!(
                    "iso_bridge currency binding `{}` is not a valid ISO 4217 code",
                    binding.currency
                );
            }
            let asset_selector = validate_asset_definition_selector(&binding.asset_definition)
                .wrap_err_with(|| format!("invalid asset definition for currency {currency}"))?;
            if binding.max_amount.is_zero() {
                eyre::bail!(
                    "iso_bridge currency binding `{currency}` max_amount must be greater than zero"
                );
            }
            if currencies
                .insert(
                    currency.clone(),
                    IsoCurrencyBinding {
                        asset_definition: asset_selector,
                        max_amount: binding.max_amount.clone(),
                    },
                )
                .is_some()
            {
                eyre::bail!("iso_bridge contains duplicate currency binding `{currency}`");
            }
        }
        let reference_data = Arc::new(ReferenceDataSnapshots::from_config(&config.reference_data));
        let profiles = load_profile_catalog(config)?;
        let (participants_by_key, participants_by_financial_id, audit_admin_keys) =
            load_participant_catalog(config, &profiles)?;
        let (store_dir, audit_export_dir) = prepare_iso_persistence_layout(
            config.store_dir.as_deref(),
            config.audit_export_dir.as_deref(),
        )
        .map_err(|error| {
            eyre::eyre!(
                "failed to initialize the configured ISO bridge audit persistence targets: {error}"
            )
        })?;
        let runtime = Iso20022BridgeRuntime {
            signer_account,
            signer_private_key,
            signer_public_key,
            participants_by_key: Arc::new(participants_by_key),
            participants_by_financial_id: Arc::new(participants_by_financial_id),
            audit_admin_keys: Arc::new(audit_admin_keys),
            account_aliases: Arc::new(aliases),
            #[cfg(test)]
            alias_indices: Arc::new(alias_indices),
            #[cfg(test)]
            index_aliases: Arc::new(index_aliases),
            currency_assets: Arc::new(currencies),
            reference_data,
            default_profile_id: config.default_profile.trim().to_owned(),
            profiles: Arc::new(profiles),
            store_dir,
            store_retention: Duration::from_secs(config.store_retention_secs),
            store_max_records,
            audit_export_dir,
            dedupe_ttl: Duration::from_secs(config.dedupe_ttl_secs),
            state_lock: Arc::new(ReentrantMutex::new(())),
            records: DashMap::new(),
            tx_hash_index: DashMap::new(),
            payload_hash_index: DashMap::new(),
            business_message_id_index: DashMap::new(),
            uetr_index: DashMap::new(),
            replay_tombstones: DashMap::new(),
            durable_store_usage: Arc::new(Mutex::new(IsoDurableStoreUsage::v1())),
            lifecycle_persistence_healthy: Arc::new(AtomicBool::new(true)),
            audit_persistence_healthy: Arc::new(AtomicBool::new(true)),
        };
        runtime.load_persisted_records()?;
        if !runtime.persist_audit_index() {
            eyre::bail!("failed to initialize the configured ISO bridge audit persistence targets");
        }
        Ok(Some(runtime))
    }
    /// Resolve an IBAN into an on-ledger account identifier.
    pub fn resolve_account(&self, iban: &str) -> Option<AccountId> {
        let iban = normalise_iban(iban);
        self.account_aliases.get(&iban).cloned()
    }
    /// Look up the canonical index assigned to an alias (IBAN) if present.
    #[cfg(test)]
    pub fn resolve_alias_index(&self, alias: &str) -> Option<AliasIndex> {
        let alias = normalise_iban(alias);
        self.alias_indices.get(&alias).copied()
    }
    /// Resolve an alias index back into the normalized alias and account identifier.
    #[cfg(test)]
    pub fn resolve_account_by_index(&self, index: AliasIndex) -> Option<(String, AccountId)> {
        self.index_aliases.get(&index).cloned()
    }
    /// Resolve an ISO 4217 currency code into an asset definition identifier.
    pub fn resolve_asset(
        &self,
        world: &impl WorldReadOnly,
        now_ms: u64,
        currency: &str,
    ) -> Option<AssetDefinitionId> {
        let currency = normalise_currency(currency);
        let binding = self.currency_assets.get(&currency)?;
        resolve_asset_definition_selector(world, &binding.asset_definition, now_ms)
    }
    fn resolve_bound_account(
        &self,
        iban: &str,
        iban_field: &'static str,
        hint: Option<&str>,
        hint_field: &'static str,
        telemetry: &MaybeTelemetry,
        context: &'static str,
    ) -> Result<AccountId, MsgError> {
        let configured = self
            .resolve_account(iban)
            .ok_or_else(|| MsgError::InvalidIdentifier {
                field: iban_field.to_owned(),
                kind: IdentifierKind::Iban,
            })?;
        if let Some(hint) = hint {
            let (hinted, _) = parse_iso_account_hint(hint, telemetry, context)?;
            if hinted != configured {
                return Err(MsgError::InvalidValue {
                    field: hint_field.to_owned(),
                    kind: InvalidValueKind::Enum,
                });
            }
        }
        Ok(configured)
    }
    fn resolve_bound_asset(
        &self,
        world: &impl WorldReadOnly,
        now_ms: u64,
        currency: &str,
        hint: Option<&str>,
    ) -> Result<AssetDefinitionId, MsgError> {
        let configured = self.resolve_asset(world, now_ms, currency).ok_or_else(|| {
            MsgError::InvalidIdentifier {
                field: "IntrBkSttlmCcy".to_owned(),
                kind: IdentifierKind::Currency,
            }
        })?;
        if let Some(hint) = hint {
            let hinted = resolve_asset_definition_selector(world, hint, now_ms)
                .ok_or(MsgError::ValidationFailed)?;
            if hinted != configured {
                return Err(MsgError::InvalidValue {
                    field: "SplmtryData/AssetDefinitionId".to_owned(),
                    kind: InvalidValueKind::Enum,
                });
            }
        }
        Ok(configured)
    }
    fn settlement_amount(&self, currency: &str, amount: &str) -> Result<Quantity, MsgError> {
        let currency = normalise_currency(currency);
        let binding =
            self.currency_assets
                .get(&currency)
                .ok_or_else(|| MsgError::InvalidIdentifier {
                    field: "IntrBkSttlmCcy".to_owned(),
                    kind: IdentifierKind::Currency,
                })?;
        let amount = Quantity::from_str(amount).map_err(|_| MsgError::InvalidValue {
            field: "IntrBkSttlmAmt".to_owned(),
            kind: InvalidValueKind::Amount,
        })?;
        if amount.is_zero() || amount > binding.max_amount {
            return Err(MsgError::InvalidValue {
                field: "IntrBkSttlmAmt".to_owned(),
                kind: InvalidValueKind::Amount,
            });
        }
        Ok(amount)
    }
    /// Access the cached ISO reference datasets.
    #[cfg(test)]
    pub fn reference_data(&self) -> &ReferenceDataSnapshots {
        &self.reference_data
    }
    /// Return the deterministic audit manifest for durable ISO message records.
    pub fn audit_index(&self) -> JsonValue {
        let mut records = BTreeMap::new();
        for entry in &self.records {
            if let Some(value) = persisted_audit_index_entry_value(entry.key(), entry.value()) {
                records.insert(entry.key().clone(), value);
            }
        }
        persisted_audit_index_value(records.into_values().collect())
    }
    /// Return whether the latest audit persistence attempt reached every configured target.
    pub(crate) fn audit_persistence_is_healthy(&self) -> bool {
        self.audit_persistence_healthy.load(Ordering::Acquire)
    }
    /// Return whether lifecycle commits may safely accept another mutation.
    ///
    /// A false value means a committed or indeterminate journal must be recovered before
    /// ordinary message transitions can resume.
    #[cfg(test)]
    pub(crate) fn lifecycle_persistence_is_healthy(&self) -> bool {
        self.lifecycle_mutations_available()
    }
    /// Start a supervised retry loop for an unavailable audit persistence target.
    pub(crate) fn start_audit_persistence_worker(
        self: &Arc<Self>,
        shutdown_signal: iroha_futures::supervisor::ShutdownSignal,
    ) -> tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit> {
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(ISO_AUDIT_PERSISTENCE_RETRY_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Construction already performed the synchronous initial preflight.
            ticker.tick().await;
            loop {
                tokio::select! {
                    () = shutdown_signal.receive() => {
                        return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                    }
                    _ = ticker.tick() => {
                        if runtime.audit_persistence_is_healthy() {
                            continue;
                        }
                        let retry_runtime = Arc::clone(&runtime);
                        let result = tokio::task::spawn_blocking(move || {
                            let _state_guard = retry_runtime.state_lock.lock();
                            retry_runtime.persist_audit_index()
                        })
                        .await;
                        match result {
                            Ok(true) => {
                                iroha_logger::info!("ISO bridge audit persistence recovered");
                            }
                            Ok(false) => {
                                iroha_logger::warn!(
                                    "ISO bridge audit persistence remains unavailable"
                                );
                            }
                            Err(error) => {
                                iroha_logger::error!(
                                    ?error,
                                    "ISO bridge audit persistence retry task failed"
                                );
                                return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                            }
                        }
                    }
                }
            }
        })
    }
    /// Return the configured default rail profile.
    #[cfg(test)]
    pub fn default_profile(&self) -> &TradfiRailProfile {
        self.profiles
            .get(&self.default_profile_id)
            .expect("default ISO profile validated during runtime construction")
    }
    /// Resolve a profile identifier, falling back to the configured default.
    pub fn resolve_profile(&self, profile_id: Option<&str>) -> Option<&TradfiRailProfile> {
        let selected = profile_id
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .unwrap_or(&self.default_profile_id);
        self.profiles.get(selected)
    }
    /// Bind an initial ISO message to the authenticated participant and its exact `AppHdr/Fr`.
    pub(crate) fn authorize_initial_submission(
        &self,
        operator_key: &PublicKey,
        profile: &TradfiRailProfile,
        parsed: &ParsedMessage,
    ) -> Result<IsoRecordParties, IsoAdmissionError> {
        if self.audit_admin_keys.contains(operator_key) {
            return Err(IsoAdmissionError::NotAuthorized);
        }
        let participant = self
            .participants_by_key
            .get(operator_key)
            .ok_or(IsoAdmissionError::NotAuthorized)?;
        if !participant.roles.contains(&IsoParticipantRole::Originator)
            || !participant.allowed_profiles.contains(&profile.id)
        {
            return Err(IsoAdmissionError::NotAuthorized);
        }
        let originator_financial_id =
            app_header_financial_identifier(parsed, AppHeaderParty::From)?
                .ok_or(IsoAdmissionError::NotAuthorized)?;
        if !participant
            .financial_identifiers
            .contains(&originator_financial_id)
        {
            return Err(IsoAdmissionError::NotAuthorized);
        }
        let counterparty_financial_id =
            app_header_financial_identifier(parsed, AppHeaderParty::To)?
                .ok_or(IsoAdmissionError::NotAuthorized)?;
        let counterparty_id = self
            .participants_by_financial_id
            .get(&counterparty_financial_id)
            .ok_or(IsoAdmissionError::NotAuthorized)?;
        let counterparty = self
            .participants_by_key
            .values()
            .find(|candidate| &candidate.id == counterparty_id)
            .ok_or(IsoAdmissionError::NotAuthorized)?;
        if !counterparty
            .roles
            .contains(&IsoParticipantRole::Counterparty)
            || !counterparty.allowed_profiles.contains(&profile.id)
        {
            return Err(IsoAdmissionError::NotAuthorized);
        }
        Ok(IsoRecordParties {
            originator_participant_id: participant.id.clone(),
            counterparty_participant_id: counterparty_id.clone(),
            admitting_participant_id: participant.id.clone(),
            admitting_operator_key: operator_key.to_string(),
            originator_financial_id,
            counterparty_financial_id,
            pinned_profile_id: profile.id.clone(),
            pinned_signature_policy: signature_policy_label(profile.embedded_signature_policy)
                .to_owned(),
            pinned_profile_policy_sha256: profile_policy_sha256(profile),
        })
    }
    /// Authorize a lifecycle message against the immutable parties and policy of its original.
    pub(crate) fn authorize_lifecycle_submission(
        &self,
        operator_key: &PublicKey,
        profile: &TradfiRailProfile,
        message_type: &str,
        parsed: &ParsedMessage,
    ) -> Result<IsoLifecycleAuthorization, IsoAdmissionError> {
        if matches!(message_type, "sese.023" | "colr.012") {
            return self
                .authorize_initial_submission(operator_key, profile, parsed)
                .map(IsoLifecycleAuthorization::initial);
        }
        if self.audit_admin_keys.contains(operator_key) {
            return Err(IsoAdmissionError::NotAuthorized);
        }
        let actor = self
            .participants_by_key
            .get(operator_key)
            .ok_or(IsoAdmissionError::NotAuthorized)?;
        let referenced_id = canonical_lifecycle_referenced_message_id(message_type, parsed)
            .map_err(|_| IsoAdmissionError::NotAuthorized)?
            .ok_or(IsoAdmissionError::NotAuthorized)?;
        let _state_guard = self.state_lock.lock();
        let original = self
            .records
            .get(&referenced_id)
            .ok_or(IsoAdmissionError::NotAuthorized)?;
        if !self.record_is_live_at(&original, SystemTime::now()) {
            return Err(IsoAdmissionError::NotAuthorized);
        }
        if original.parties.pinned_profile_id != profile.id
            || original.parties.pinned_signature_policy
                != signature_policy_label(profile.embedded_signature_policy)
            || original.parties.pinned_profile_policy_sha256 != profile_policy_sha256(profile)
        {
            return Err(IsoAdmissionError::NotAuthorized);
        }
        let (expected_participant, required_role, expected_from, expected_to) = match message_type {
            "pacs.002" | "pacs.004" | "sese.024" | "sese.025" => (
                original.parties.counterparty_participant_id.as_str(),
                IsoParticipantRole::Counterparty,
                original.parties.counterparty_financial_id.as_str(),
                original.parties.originator_financial_id.as_str(),
            ),
            "camt.056" => (
                original.parties.originator_participant_id.as_str(),
                IsoParticipantRole::Originator,
                original.parties.originator_financial_id.as_str(),
                original.parties.counterparty_financial_id.as_str(),
            ),
            _ => return Err(IsoAdmissionError::NotAuthorized),
        };
        if actor.id != expected_participant
            || !actor.roles.contains(&required_role)
            || !actor.allowed_profiles.contains(&profile.id)
        {
            return Err(IsoAdmissionError::NotAuthorized);
        }
        let from = app_header_financial_identifier(parsed, AppHeaderParty::From)?
            .ok_or(IsoAdmissionError::NotAuthorized)?;
        let to = app_header_financial_identifier(parsed, AppHeaderParty::To)?
            .ok_or(IsoAdmissionError::NotAuthorized)?;
        if from != expected_from || to != expected_to {
            return Err(IsoAdmissionError::NotAuthorized);
        }
        let mut parties = original.parties.clone();
        let original_binding = IsoLifecycleOriginalBinding {
            message_id: referenced_id,
            incarnation: original.incarnation.clone(),
            transaction_hash: original.transaction_hash.clone(),
        };
        drop(original);
        parties.admitting_participant_id = actor.id.clone();
        parties.admitting_operator_key = operator_key.to_string();
        Ok(IsoLifecycleAuthorization {
            parties,
            original: Some(original_binding),
        })
    }
    /// Authorize and snapshot one rich ISO record while holding the runtime state lock.
    pub(crate) fn authorized_message_status(
        &self,
        operator_key: &PublicKey,
        message_id: &str,
    ) -> Option<IsoMessageStatus> {
        let _state_guard = self.state_lock.lock();
        let record = self.records.get(message_id)?;
        let authorized = self.audit_admin_keys.contains(operator_key)
            || self
                .participants_by_key
                .get(operator_key)
                .is_some_and(|participant| {
                    record.parties.originator_participant_id == participant.id
                        || record.parties.counterparty_participant_id == participant.id
                });
        authorized.then(|| Self::status_snapshot(message_id, &record))
    }
    /// Return a party-scoped audit manifest, or the complete manifest for an audit admin.
    pub(crate) fn audit_index_for(&self, operator_key: &PublicKey) -> Option<JsonValue> {
        let audit_admin = self.audit_admin_keys.contains(operator_key);
        let participant_id = self
            .participants_by_key
            .get(operator_key)
            .map(|participant| participant.id.clone());
        if !audit_admin && participant_id.is_none() {
            return None;
        }
        let mut records = BTreeMap::new();
        for entry in &self.records {
            let visible = audit_admin
                || participant_id.as_ref().is_some_and(|participant_id| {
                    &entry.parties.originator_participant_id == participant_id
                        || &entry.parties.counterparty_participant_id == participant_id
                });
            if visible
                && let Some(value) = persisted_audit_index_entry_value(entry.key(), entry.value())
            {
                records.insert(entry.key().clone(), value);
            }
        }
        Some(persisted_audit_index_value(records.into_values().collect()))
    }
    /// Sign a domain-separated outbound ISO XML document with the bridge key.
    pub(crate) fn sign_outbound_document(
        &self,
        xml: String,
    ) -> Result<SignedIsoDocument, MsgError> {
        const DOMAIN: &[u8] = b"iroha.iso20022.outbound.v2\0";
        let mut signing_bytes = Vec::with_capacity(DOMAIN.len() + xml.len());
        signing_bytes.extend_from_slice(DOMAIN);
        signing_bytes.extend_from_slice(xml.as_bytes());
        let signature = Signature::try_new(&self.signer_private_key, &signing_bytes)
            .map_err(|_| MsgError::ValidationFailed)?;
        Ok(SignedIsoDocument {
            xml,
            public_key: self.signer_public_key.to_string(),
            signature: BASE64_STANDARD.encode(signature.payload()),
        })
    }
    /// Validate profile policy for a parsed inbound message and produce audit metadata.
    pub fn validate_profile_submission(
        &self,
        profile: &TradfiRailProfile,
        message_type: &str,
        parsed: &ParsedMessage,
        payload: &[u8],
    ) -> Result<IsoMessageMetadata, MsgError> {
        let message_profile = profile
            .message_profile(message_type, MessageDirection::Inbound)
            .ok_or(MsgError::UnknownMessageType)?;
        self.require_profile_reference_data(profile)?;
        if message_profile.require_app_header
            && (app_header_business_message_id(parsed).is_none()
                || app_header_message_definition_id(parsed).is_none()
                || app_header_creation_date(parsed).is_none())
        {
            return Err(MsgError::MissingField("AppHdr"));
        }
        let definition_id =
            message_definition_id(parsed, message_type).ok_or(MsgError::ValidationFailed)?;
        if !message_profile.allows_version(definition_id) {
            return Err(MsgError::UnknownMessageType);
        }
        let business_message_id = business_message_id(parsed).map(ToOwned::to_owned);
        let business_service = business_service(parsed).map(ToOwned::to_owned);
        if message_profile.require_business_service {
            let service = business_service
                .as_deref()
                .filter(|service| !service.trim().is_empty())
                .ok_or_else(|| MsgError::MissingField("AppHdr/BizSvc"))?;
            if !message_profile.allows_business_service(service) {
                return Err(MsgError::InvalidValue {
                    field: "AppHdr/BizSvc".to_owned(),
                    kind: InvalidValueKind::Enum,
                });
            }
        } else if let Some(service) = business_service.as_deref() {
            if service.trim().is_empty() || !message_profile.allows_business_service(service) {
                return Err(MsgError::InvalidValue {
                    field: "AppHdr/BizSvc".to_owned(),
                    kind: InvalidValueKind::Enum,
                });
            }
        }
        let uetr = uetr(parsed).map(ToOwned::to_owned);
        if message_profile.require_uetr && uetr.is_none() {
            return Err(MsgError::MissingField("UETR"));
        }
        if let Some(value) = uetr.as_deref()
            && !is_valid_uetr(value)
        {
            return Err(MsgError::InvalidValue {
                field: "UETR".to_owned(),
                kind: InvalidValueKind::Enum,
            });
        }
        self.validate_amount_minor_units(message_profile, parsed)?;
        if let (Some(currency), Some(amount)) = (
            parsed.field_text("IntrBkSttlmCcy"),
            parsed.field_text("IntrBkSttlmAmt"),
        ) {
            self.settlement_amount(currency, amount)?;
        }
        self.validate_supplementary_data_limit(message_profile, parsed)?;
        self.validate_structured_address_mode(message_profile, parsed)?;
        self.validate_message_reference_data(message_type, parsed)?;
        self.validate_securities_ledger_mapping(profile, message_type, parsed)?;
        let embedded_signature_detected =
            has_embedded_signature_marker(parsed) || payload_has_embedded_signature(payload);
        match profile.embedded_signature_policy {
            EmbeddedSignaturePolicy::RecordOnly => {}
            EmbeddedSignaturePolicy::RejectUnsupported if embedded_signature_detected => {
                return Err(MsgError::ValidationFailed);
            }
            EmbeddedSignaturePolicy::RejectUnsupported => {}
            EmbeddedSignaturePolicy::RequireVerified => {
                if !embedded_signature_detected
                    || !verify_embedded_xml_signature(payload, profile, parsed)?
                {
                    return Err(MsgError::ValidationFailed);
                }
            }
        }
        Ok(IsoMessageMetadata::inbound(
            &profile.id,
            message_type,
            business_service,
            business_message_id,
            uetr,
            sha256_hex(payload),
            self.reference_data.snapshot_id(),
            embedded_signature_detected,
        ))
    }
    /// Perform a deduplication check for the provided message identifier. Returns `true` when the
    /// identifier is new (and records it), or `false` when a still-active entry already exists.
    #[cfg(test)]
    pub(crate) fn check_and_record_message(&self, message_id: &str) -> bool {
        self.check_and_record_inbound(message_id, IsoMessageMetadata::default())
    }
    /// Perform idempotency checks and record a new inbound message.
    #[cfg(test)]
    pub(crate) fn check_and_record_inbound(
        &self,
        message_id: &str,
        metadata: IsoMessageMetadata,
    ) -> bool {
        let parties = self.compatibility_test_parties(&metadata);
        self.admit_inbound(message_id, metadata, parties, false)
            .is_ok()
    }
    /// Durably admit an authenticated inbound message before signing or lifecycle processing.
    pub(crate) fn admit_authenticated_inbound(
        &self,
        message_id: &str,
        metadata: IsoMessageMetadata,
        parties: IsoRecordParties,
    ) -> Result<(), IsoAdmissionError> {
        self.admit_inbound(message_id, metadata, parties, true)
    }
    fn admit_inbound(
        &self,
        message_id: &str,
        metadata: IsoMessageMetadata,
        parties: IsoRecordParties,
        require_persistence: bool,
    ) -> Result<(), IsoAdmissionError> {
        let _state_guard = self.state_lock.lock();
        if !self.lifecycle_mutations_available() {
            return Err(IsoAdmissionError::PersistenceUnavailable);
        }
        let now = Instant::now();
        self.prune_expired();
        if self.records.contains_key(message_id)
            || self.replay_tombstones.contains_key(message_id)
            || self.metadata_conflicts(message_id, &metadata)
        {
            return Err(IsoAdmissionError::Duplicate);
        }
        if require_persistence && self.store_dir.is_none() {
            return Err(IsoAdmissionError::PersistenceUnavailable);
        }
        let wall_now = SystemTime::now();
        let protected_record_ids = self
            .records
            .iter()
            .filter(|record| {
                record.retention_protected()
                    || wall_now.duration_since(record.replay_expires_at).is_err()
            })
            .map(|record| record.key().clone())
            .collect::<BTreeSet<_>>();
        let protected_identity_count = protected_record_ids.len().saturating_add(
            self.replay_tombstones
                .iter()
                .filter(|tombstone| !protected_record_ids.contains(tombstone.key()))
                .count(),
        );
        if protected_identity_count >= self.store_max_records {
            return Err(IsoAdmissionError::ProtectedCapacity);
        }
        let mut record = IsoMessageRecordV2::pending(now);
        record.metadata = metadata.clone();
        record.parties = parties;
        // Persist the configured TTL exactly in the canonical millisecond domain.
        // Neither host time overflow nor wire overflow may shorten replay protection.
        let replay_expires_at_ms = wall_now
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|age| age.as_millis().checked_add(self.dedupe_ttl.as_millis()))
            .and_then(|millis| u64::try_from(millis).ok())
            .ok_or(IsoAdmissionError::PersistenceUnavailable)?;
        record.replay_expires_at = system_time_from_ms(replay_expires_at_ms)
            .ok_or(IsoAdmissionError::PersistenceUnavailable)?;
        let tombstone = IsoReplayTombstone {
            expires_at: record.replay_expires_at,
            payload_hash: metadata.payload_hash.clone(),
            business_message_id: metadata.business_message_id.clone(),
            uetr: metadata.uetr.clone(),
        };
        if self.store_dir.is_some() && !self.persist_replay_tombstone(message_id, &tombstone) {
            return Err(IsoAdmissionError::PersistenceUnavailable);
        }
        self.insert_tombstone_indexes(message_id, &tombstone);
        self.replay_tombstones
            .insert(message_id.to_owned(), tombstone);
        self.records.insert(message_id.to_owned(), record);
        if !self.persist_message(message_id) {
            // The durable replay tombstone intentionally remains. Once an external
            // identity has reached admission, a detail-write failure must not reopen it.
            self.records.remove(message_id);
            return Err(IsoAdmissionError::PersistenceUnavailable);
        }
        Ok(())
    }
    #[cfg(test)]
    fn compatibility_test_parties(&self, metadata: &IsoMessageMetadata) -> IsoRecordParties {
        let mut configured = self
            .participants_by_key
            .iter()
            .map(|(key, participant)| (participant.id.as_str(), key, participant))
            .collect::<Vec<_>>();
        configured.sort_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));
        let (_, operator_key, participant) = configured
            .iter()
            .copied()
            .find(|(_, _, participant)| participant.roles.contains(&IsoParticipantRole::Originator))
            .expect("enabled ISO runtime validates an originator participant");
        let counterparty = configured
            .iter()
            .map(|(_, _, candidate)| *candidate)
            .find(|candidate| {
                candidate.id != participant.id
                    && candidate.roles.contains(&IsoParticipantRole::Counterparty)
            })
            .or_else(|| {
                configured
                    .iter()
                    .map(|(_, _, candidate)| *candidate)
                    .find(|candidate| candidate.roles.contains(&IsoParticipantRole::Counterparty))
            })
            .unwrap_or(participant);
        let originator_financial_id = participant
            .financial_identifiers
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "TEST-ORIGINATOR".to_owned());
        let counterparty_financial_id = counterparty
            .financial_identifiers
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "TEST-COUNTERPARTY".to_owned());
        let pinned_profile_id = metadata
            .profile_id()
            .unwrap_or(&self.default_profile_id)
            .to_owned();
        let pinned_signature_policy = self
            .profiles
            .get(&pinned_profile_id)
            .map(|profile| signature_policy_label(profile.embedded_signature_policy))
            .unwrap_or("record_only")
            .to_owned();
        let pinned_profile_policy_sha256 = self
            .profiles
            .get(&pinned_profile_id)
            .map(profile_policy_sha256)
            .unwrap_or_default();
        IsoRecordParties {
            originator_participant_id: participant.id.clone(),
            counterparty_participant_id: counterparty.id.clone(),
            admitting_participant_id: participant.id.clone(),
            admitting_operator_key: operator_key.to_string(),
            originator_financial_id,
            counterparty_financial_id,
            pinned_profile_id,
            pinned_signature_policy,
            pinned_profile_policy_sha256,
        }
    }
    /// Remove an identity only after its replay TTL elapsed.
    fn remove_expired_message_locked(&self, message_id: &str, now: SystemTime) {
        if let Some(record) = self.records.get(message_id)
            && (record.retention_protected()
                || now.duration_since(record.replay_expires_at).is_err())
        {
            return;
        }
        if let Some((_, record)) = self.records.remove(message_id) {
            self.remove_record_indexes(message_id, &record);
        }
        self.remove_persisted_message(message_id);
    }
    /// Record supplementary ledger/account context attached to an admitted message.
    ///
    /// Returns `false` if the reservation no longer exists or the updated record
    /// cannot be persisted. Missing reservations are never recreated because
    /// doing so would detach the message from its semantic idempotency indexes.
    pub fn update_message_context(&self, message_id: &str, context: IsoMessageContext) -> bool {
        let _state_guard = self.state_lock.lock();
        self.update_message_context_locked(message_id, context)
    }
    fn update_message_context_locked(&self, message_id: &str, context: IsoMessageContext) -> bool {
        let Some(previous) = self.records.get(message_id).map(|record| record.clone()) else {
            return false;
        };
        let mut candidate = previous.clone();
        candidate.last_seen = Instant::now();
        candidate.updated_at = SystemTime::now();
        candidate.context = context;
        self.commit_record_candidate(message_id, Some(&previous), candidate)
    }
    /// Mark the provided message as queued for ledger execution.
    ///
    /// Returns `false` when the exact history is exhausted; the record and its
    /// persisted form then remain unchanged.
    pub fn mark_queued(&self, message_id: &str) -> bool {
        let _state_guard = self.state_lock.lock();
        let now = Instant::now();
        let previous = self.records.get(message_id).map(|record| record.clone());
        let mut candidate = previous
            .clone()
            .unwrap_or_else(|| IsoMessageRecordV2::pending(now));
        if candidate.is_terminal() {
            return false;
        }
        let transition = candidate
            .try_transition(|record| {
                record.last_seen = now;
                record.updated_at = SystemTime::now();
                record.set_queued();
            })
            .map(|_| candidate);
        self.finish_status_transition(message_id, previous, transition)
    }
    /// Bind the exact signed transaction identity before queue admission begins.
    ///
    /// This reservation lets an indeterminate queue result remain reconcilable
    /// without reopening the ISO message identifier for a replacement transfer.
    pub fn bind_transaction_hash(&self, message_id: &str, transaction_hash: &str) -> bool {
        let _state_guard = self.state_lock.lock();
        if self.store_dir.is_none() {
            return false;
        }
        if self
            .tx_hash_index
            .get(transaction_hash)
            .is_some_and(|owner| owner.as_str() != message_id)
        {
            return false;
        }
        let Some(previous) = self.records.get(message_id).map(|record| record.clone()) else {
            return false;
        };
        if previous.state != IsoMessageState::Pending || previous.ledger_tx_queued {
            return false;
        }
        if previous
            .transaction_hash
            .as_deref()
            .is_some_and(|existing_hash| existing_hash != transaction_hash)
        {
            return false;
        }
        let mut candidate = previous.clone();
        let tx_hash = transaction_hash.to_owned();
        let transition = candidate
            .try_transition(|record| {
                record.transaction_hash = Some(tx_hash);
                record.last_seen = Instant::now();
                record.updated_at = SystemTime::now();
                record.detail = Some("signed transaction prepared for queue admission".to_owned());
                record.hold_reason_code = None;
                record.rejection_reason_code = None;
            })
            .map(|_| candidate);
        self.finish_status_transition(message_id, Some(previous), transition)
    }
    /// Flag a message as pending due to screening/manual hold with an optional ISO reason code.
    ///
    /// Returns `false` without changing or persisting the record when the exact
    /// append-only status history has reached a V1 capacity bound.
    #[cfg(test)]
    pub fn mark_hold(&self, message_id: &str, reason_code: Option<&str>) -> bool {
        let _state_guard = self.state_lock.lock();
        let now = Instant::now();
        let previous = self.records.get(message_id).map(|record| record.clone());
        let mut candidate = previous
            .clone()
            .unwrap_or_else(|| IsoMessageRecordV2::pending(now));
        if candidate.is_terminal() {
            return false;
        }
        let reason_code = reason_code.map(std::borrow::ToOwned::to_owned);
        let transition = candidate
            .try_transition(|record| {
                record.last_seen = now;
                record.updated_at = SystemTime::now();
                record.state = IsoMessageState::Pending;
                record.settled_at = None;
                record.rejection_reason_code = None;
                record.set_hold_reason(reason_code);
            })
            .map(|_| candidate);
        self.finish_status_transition(message_id, previous, transition)
    }
    /// Append a change-reason code for the message (deduplicated).
    ///
    /// Returns `false` when the exact history is exhausted.
    #[cfg(test)]
    pub fn add_change_reason_code(&self, message_id: &str, code: &str) -> bool {
        let _state_guard = self.state_lock.lock();
        let now = Instant::now();
        let code_encoded_bytes = json_string_encoded_len(code).unwrap_or(usize::MAX);
        if code_encoded_bytes
            .checked_add(2)
            .is_none_or(|bytes| bytes > ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1)
        {
            self.report_status_history_limit(
                message_id,
                IsoStatusHistoryLimitError::ChangeReasonEncodedBytes,
            );
            return false;
        }
        let code = code.to_owned();
        let previous = self.records.get(message_id).map(|record| record.clone());
        let mut candidate = previous
            .clone()
            .unwrap_or_else(|| IsoMessageRecordV2::pending(now));
        let transition = candidate
            .try_transition(|record| {
                record.last_seen = now;
                record.updated_at = SystemTime::now();
                record.add_change_reason_code(code);
            })
            .map(|_| candidate);
        self.finish_status_transition(message_id, previous, transition)
    }
    /// Mark the message as fully settled on-ledger.
    ///
    /// Returns `false` when the exact history is exhausted.
    pub fn mark_settled(&self, message_id: &str, settled_at: SystemTime) -> bool {
        let _state_guard = self.state_lock.lock();
        let now = Instant::now();
        let previous = self.records.get(message_id).map(|record| record.clone());
        if previous.as_ref().is_some_and(|record| {
            record.is_rejected() && (!record.ledger_tx_queued || record.transaction_hash.is_none())
        }) {
            return false;
        }
        if previous
            .as_ref()
            .is_some_and(IsoMessageRecordV2::is_settled)
        {
            return true;
        }
        let mut candidate = previous
            .clone()
            .unwrap_or_else(|| IsoMessageRecordV2::pending(now));
        let transition = candidate
            .try_transition(|record| {
                record.last_seen = now;
                record.updated_at = SystemTime::now();
                record.state = IsoMessageState::Accepted;
                record.set_queued();
                record.mark_settled(settled_at);
                record.clear_hold();
                record.rejection_reason_code = None;
            })
            .map(|_| candidate);
        self.finish_status_transition(message_id, previous, transition)
    }
    /// Mark the transaction identified by `tx_hash` as applied and fully settled.
    ///
    /// Returns `false` when no message is indexed or its exact history is exhausted.
    pub fn mark_transaction_applied(&self, tx_hash: &str, settled_at: SystemTime) -> bool {
        let _state_guard = self.state_lock.lock();
        if let Some(message_id) = self.tx_hash_index.get(tx_hash).map(|entry| entry.clone()) {
            let applied = self.mark_settled(&message_id, settled_at);
            if applied {
                self.tx_hash_index
                    .remove_if(tx_hash, |_, owner| owner == &message_id);
            }
            return applied;
        }
        false
    }
    /// Mark the transaction identified by `tx_hash` as rejected.
    ///
    /// Returns `false` when no message is indexed or its exact history is exhausted.
    pub fn mark_transaction_rejected(
        &self,
        tx_hash: &str,
        reason: Option<&TransactionRejectionReason>,
    ) -> bool {
        let _state_guard = self.state_lock.lock();
        if let Some(message_id) = self.tx_hash_index.get(tx_hash).map(|entry| entry.clone()) {
            let (detail, reason_code) = reason
                .map(Self::rejection_reason_metadata)
                .map(|(code, detail)| (Some(detail), Some(code)))
                .unwrap_or_else(|| {
                    (
                        Some("transaction rejected".to_owned()),
                        Some("PRTRY:TX_REJECTED".to_owned()),
                    )
                });
            let rejected = self.mark_rejected(&message_id, detail, reason_code.as_deref());
            if rejected {
                self.tx_hash_index
                    .remove_if(tx_hash, |_, owner| owner == &message_id);
            }
            return rejected;
        }
        false
    }
    /// Mark the transaction identified by `tx_hash` as expired in the queue.
    ///
    /// Returns `false` when no message is indexed or its exact history is exhausted.
    pub fn mark_transaction_expired(&self, tx_hash: &str) -> bool {
        let _state_guard = self.state_lock.lock();
        if let Some(message_id) = self.tx_hash_index.get(tx_hash).map(|entry| entry.clone()) {
            let expired = self.mark_rejected(
                &message_id,
                Some("transaction expired before admission".to_owned()),
                Some("ED07"),
            );
            if expired {
                self.tx_hash_index
                    .remove_if(tx_hash, |_, owner| owner == &message_id);
            }
            return expired;
        }
        false
    }
    /// Return canonical transaction hashes for durable, nonterminal records
    /// that have completed queue admission.
    pub(crate) fn queued_transaction_hashes(&self) -> Vec<String> {
        let mut hashes = self
            .records
            .iter()
            .filter_map(|entry| {
                let record = entry.value();
                if record.ledger_tx_queued && !record.is_terminal() {
                    record.transaction_hash.clone()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        hashes.sort_unstable();
        hashes.dedup();
        hashes
    }
    /// Return whether `tx_hash` still names a durable, nonterminal queued record.
    pub(crate) fn has_queued_transaction_hash(&self, tx_hash: &str) -> bool {
        let Some(message_id) = self.tx_hash_index.get(tx_hash).map(|entry| entry.clone()) else {
            return false;
        };
        self.records.get(&message_id).is_some_and(|record| {
            record.ledger_tx_queued
                && !record.is_terminal()
                && record.transaction_hash.as_deref() == Some(tx_hash)
        })
    }
    fn rejection_reason_metadata(reason: &TransactionRejectionReason) -> (String, String) {
        match reason {
            TransactionRejectionReason::AccountDoesNotExist(_) => {
                ("AC01".to_owned(), "Account does not exist".to_owned())
            }
            TransactionRejectionReason::LimitCheck(err) => (
                "BE01".to_owned(),
                format!("Transaction limit check failed: {}", err.reason),
            ),
            TransactionRejectionReason::Validation(fail) => match fail {
                ValidationFail::AxtReject(ctx) => {
                    let mut detail =
                        format!("AXT rejection ({}): {}", ctx.reason.label(), ctx.detail);
                    if let Some(snapshot_version) = ctx.snapshot_version {
                        let _ = FmtWrite::write_fmt(
                            &mut detail,
                            format_args!(" snapshot_version={snapshot_version}"),
                        );
                    }
                    if let Some(dsid) = ctx.dataspace {
                        let _ = FmtWrite::write_fmt(
                            &mut detail,
                            format_args!(" dsid={}", dsid.as_u64()),
                        );
                    }
                    if let Some(lane) = ctx.lane {
                        let _ = FmtWrite::write_fmt(
                            &mut detail,
                            format_args!(" lane={}", lane.as_u32()),
                        );
                    }
                    if let Some(era) = ctx.active_handle_era {
                        let _ = FmtWrite::write_fmt(
                            &mut detail,
                            format_args!(" active_handle_era={era}"),
                        );
                    }
                    if let Some(sub) = ctx.next_handle_counter {
                        let _ = FmtWrite::write_fmt(
                            &mut detail,
                            format_args!(" next_handle_counter={sub}"),
                        );
                    }
                    (format!("PRTRY:{}", ctx.reason.code()), detail)
                }
                ValidationFail::IvmFault(fault) => ("PRTRY:IVM_EXEC".to_owned(), fault.to_string()),
                other => ("BE01".to_owned(), format!("Validation failed: {other}")),
            },
            TransactionRejectionReason::InstructionExecution(fail) => (
                "PRTRY:INSTRUCTION_EXEC".to_owned(),
                format!("Instruction execution failed: {}", fail.reason),
            ),
            TransactionRejectionReason::TriggerExecution(fail) => (
                "PRTRY:TRIGGER_EXEC".to_owned(),
                format!("Trigger execution failed: {fail}"),
            ),
        }
    }
    /// Mark the provided message as successfully submitted on-chain and return
    /// the exact status snapshot produced by that atomic update.
    ///
    /// Capacity exhaustion is logged and returns the unchanged exact snapshot;
    /// the record, transaction index, and persisted form are not advanced.
    pub fn mark_accepted(&self, message_id: &str, transaction_hash: &str) -> IsoMessageStatus {
        let _state_guard = self.state_lock.lock();
        match self.try_mark_accepted(message_id, transaction_hash) {
            Ok(status) => status,
            Err(error) => {
                self.report_status_history_limit(message_id, error);
                self.message_status(message_id).unwrap_or_else(|| {
                    let pending = IsoMessageRecordV2::pending(Instant::now());
                    Self::status_snapshot(message_id, &pending)
                })
            }
        }
    }
    fn try_mark_accepted(
        &self,
        message_id: &str,
        transaction_hash: &str,
    ) -> Result<IsoMessageStatus, IsoStatusHistoryLimitError> {
        let now = Instant::now();
        let previous = self.records.get(message_id).map(|record| record.clone());
        if let Some(existing) = previous.as_ref()
            && (existing.state != IsoMessageState::Pending
                || existing
                    .transaction_hash
                    .as_deref()
                    .is_some_and(|hash| hash != transaction_hash)
                || self
                    .tx_hash_index
                    .get(transaction_hash)
                    .is_some_and(|owner| owner.as_str() != message_id))
        {
            return Ok(Self::status_snapshot(message_id, existing));
        }
        let tx_hash = transaction_hash.to_owned();
        let mut candidate = previous
            .clone()
            .unwrap_or_else(|| IsoMessageRecordV2::accepted(now, tx_hash.clone()));
        if previous.is_some() {
            candidate.try_transition(|record| {
                record.transaction_hash = Some(tx_hash);
                record.last_seen = now;
                record.updated_at = SystemTime::now();
                record.state = IsoMessageState::Accepted;
                record.detail = None;
                record.set_queued();
                record.settled_at = None;
                record.hold_reason_code = None;
                record.change_reason_codes.clear();
                record.rejection_reason_code = None;
            })?;
        }
        let status = Self::status_snapshot(message_id, &candidate);
        if !self.commit_record_candidate(message_id, previous.as_ref(), candidate) {
            return Err(IsoStatusHistoryLimitError::Persistence);
        }
        Ok(status)
    }
    /// Prepare an accepted lifecycle after-image without publishing either side of the update.
    fn prepare_lifecycle_accepted(
        &self,
        message_id: &str,
        context: Option<IsoMessageContext>,
        detail: Option<String>,
    ) -> Result<IsoPreparedRecordMutation, IsoStatusHistoryLimitError> {
        let now = Instant::now();
        let previous = self
            .records
            .get(message_id)
            .map(|record| record.clone())
            .ok_or(IsoStatusHistoryLimitError::MissingReservation)?;
        let mut candidate = previous.clone();
        if let Some(context) = context {
            candidate.context = context;
        }
        candidate.try_transition(|record| {
            record.transaction_hash = None;
            record.last_seen = now;
            record.updated_at = SystemTime::now();
            record.state = IsoMessageState::Accepted;
            record.detail = detail;
            record.ledger_tx_queued = false;
            record.settled_at = None;
            record.hold_reason_code = None;
            record.change_reason_codes.clear();
            record.rejection_reason_code = None;
        })?;
        Ok(IsoPreparedRecordMutation {
            message_id: message_id.to_owned(),
            previous,
            candidate,
        })
    }
    /// Mark the provided message as rejected and record the reason.
    ///
    /// Returns `false` when the exact history is exhausted; no part of the
    /// rejection is then applied or persisted.
    pub fn mark_rejected(
        &self,
        message_id: &str,
        reason: Option<String>,
        reason_code: Option<&str>,
    ) -> bool {
        let _state_guard = self.state_lock.lock();
        let now = Instant::now();
        let reason_code = reason_code.map(std::borrow::ToOwned::to_owned);
        let previous = self.records.get(message_id).map(|record| record.clone());
        if previous
            .as_ref()
            .is_some_and(IsoMessageRecordV2::is_settled)
        {
            return false;
        }
        if previous.as_ref().is_some_and(|record| {
            record.is_rejected() && !record.ledger_tx_queued && record.transaction_hash.is_none()
        }) {
            return true;
        }
        let mut candidate = match previous.clone() {
            Some(record) => record,
            None => match IsoMessageRecordV2::rejected(now, reason, reason_code) {
                Ok(record) => {
                    return self.commit_record_candidate(message_id, None, record);
                }
                Err(error) => {
                    self.report_status_history_limit(message_id, error);
                    return false;
                }
            },
        };
        let transition = candidate
            .try_transition(|record| {
                record.transaction_hash = None;
                record.last_seen = now;
                record.updated_at = SystemTime::now();
                record.state = IsoMessageState::Rejected;
                record.detail = reason;
                record.ledger_tx_queued = false;
                record.settled_at = None;
                record.hold_reason_code = None;
                record.change_reason_codes.clear();
                record.rejection_reason_code = reason_code;
            })
            .map(|_| candidate);
        self.finish_status_transition(message_id, previous, transition)
    }
    /// Retrieve the current status of a processed ISO 20022 message.
    pub fn message_status(&self, message_id: &str) -> Option<IsoMessageStatus> {
        self.records
            .get(message_id)
            .map(|record| Self::status_snapshot(message_id, &record))
    }
    fn finish_status_transition(
        &self,
        message_id: &str,
        previous: Option<IsoMessageRecordV2>,
        transition: Result<IsoMessageRecordV2, IsoStatusHistoryLimitError>,
    ) -> bool {
        match transition {
            Ok(candidate) => self.commit_record_candidate(message_id, previous.as_ref(), candidate),
            Err(error) => {
                self.report_status_history_limit(message_id, error);
                false
            }
        }
    }
    fn report_status_history_limit(&self, message_id: &str, error: IsoStatusHistoryLimitError) {
        if error == IsoStatusHistoryLimitError::Persistence {
            iroha_logger::error!(
                message_id_sha256 = %sha256_hex(message_id.as_bytes()),
                "ISO status transition rejected because its candidate record was not durable"
            );
            return;
        }
        iroha_logger::error!(
            ?error,
            message_id_sha256 = %sha256_hex(message_id.as_bytes()),
            max_entries = ISO_STATUS_HISTORY_MAX_ENTRIES_V1,
            max_encoded_bytes = ISO_STATUS_HISTORY_MAX_ENCODED_BYTES_V1,
            max_change_reason_entries = ISO_CHANGE_REASON_MAX_ENTRIES_V1,
            max_change_reason_encoded_bytes = ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1,
            "ISO status transition rejected before record or persistence mutation"
        );
    }
    fn status_snapshot(message_id: &str, record: &IsoMessageRecordV2) -> IsoMessageStatus {
        IsoMessageStatus {
            message_id: message_id.to_owned(),
            state: record.state,
            transaction_hash: record.transaction_hash.clone(),
            detail: record.detail.clone(),
            updated_at: record.updated_at,
            settled_at: record.settled_at,
            context: record.context.clone(),
            metadata: record.metadata.clone(),
            derived_status: record.derived_status(),
            hold_reason_code: record.hold_reason_code.clone(),
            change_reason_codes: record.change_reason_codes.clone(),
            rejection_reason_code: record.rejection_reason_code.clone(),
            status_history: record.status_history.clone(),
            parties: record.parties.clone(),
        }
    }
    /// Return the stable group-header identity for an inbound payment message.
    ///
    /// Both pacs.008 and pacs.009 lifecycle reports correlate through
    /// `GrpHdr/MsgId`; the application-header `BizMsgIdr` remains a separate
    /// replay identity in [`IsoMessageMetadata`].
    pub(crate) fn payment_message_id(
        message_type: &str,
        parsed: &ParsedMessage,
    ) -> Result<String, MsgError> {
        if !matches!(message_type, "pacs.008" | "pacs.009") {
            return Err(MsgError::UnknownMessageType);
        }
        let message_id = parsed
            .field_text("MsgId")
            .ok_or(MsgError::MissingField("MsgId"))?
            .trim();
        if message_id.is_empty() {
            return Err(MsgError::MissingField("MsgId"));
        }
        Ok(message_id.to_owned())
    }
    /// Determine the durable identifier for an inbound lifecycle message.
    pub(crate) fn lifecycle_message_id(
        message_type: &str,
        parsed: &ParsedMessage,
    ) -> Result<String, MsgError> {
        let referenced_message_id = lifecycle_referenced_message_id(message_type, parsed)?;
        let securities_tx_id = if matches!(
            message_type,
            "sese.023" | "sese.024" | "sese.025" | "colr.012"
        ) {
            unique_field_text_by_suffix(parsed, &["TxId"], "TxId")?
        } else {
            None
        };
        let id = if matches!(
            message_type,
            "sese.023" | "sese.024" | "sese.025" | "colr.012"
        ) {
            securities_tx_id
                .or_else(|| business_message_id(parsed))
                .or(referenced_message_id)
        } else {
            business_message_id(parsed)
                .or_else(|| parsed.field_text("Assgnmt/Id"))
                .or(referenced_message_id)
        }
        .ok_or(MsgError::MissingField("MsgId"))?;
        let id = id.trim();
        if id.is_empty() {
            return Err(MsgError::MissingField("MsgId"));
        }
        if matches!(
            message_type,
            "sese.023" | "sese.024" | "sese.025" | "colr.012"
        ) {
            Ok(format!("{message_type}:{id}"))
        } else {
            Ok(id.to_owned())
        }
    }
    /// Apply an inbound lifecycle message to its referenced durable record.
    ///
    /// Reference-bearing lifecycle messages fail closed if their original was
    /// removed, replaced, or crossed its retention boundary after participant authorization.
    /// Incarnation, liveness, exact settlement evidence, and update checks share the runtime
    /// state lock, so compaction cannot retarget an authorized update to a replacement record.
    #[cfg(test)]
    pub(crate) fn apply_inbound_lifecycle_message(
        &self,
        message_id: &str,
        message_type: &str,
        parsed: &ParsedMessage,
    ) -> Result<IsoLifecycleOutcome, MsgError> {
        self.apply_inbound_lifecycle_message_with_status(message_id, message_type, parsed)
            .map(|(outcome, _)| outcome)
    }
    /// Apply a lifecycle message and return its response snapshot atomically.
    ///
    /// The returned snapshot remains valid even if bounded durable compaction
    /// evicts the rich lifecycle record immediately after this critical section.
    #[cfg(test)]
    pub(crate) fn apply_inbound_lifecycle_message_with_status(
        &self,
        message_id: &str,
        message_type: &str,
        parsed: &ParsedMessage,
    ) -> Result<(IsoLifecycleOutcome, IsoMessageStatus), MsgError> {
        let authorization = self.compatibility_lifecycle_authorization(message_type, parsed)?;
        let settlement_evidence = authorization
            .settlement_transaction_hash(message_type, parsed)?
            .map(ToOwned::to_owned);
        self.apply_inbound_lifecycle_message_with_evidence(
            message_id,
            message_type,
            parsed,
            &authorization,
            settlement_evidence.as_deref(),
        )
        .map_err(|error| match error {
            IsoLifecycleApplyError::Validation(error) => error,
            IsoLifecycleApplyError::PersistenceUnavailable => MsgError::ValidationFailed,
        })
    }
    /// Apply a lifecycle message while requiring exact committed-transaction evidence.
    pub(crate) fn apply_inbound_lifecycle_message_with_evidence(
        &self,
        message_id: &str,
        message_type: &str,
        parsed: &ParsedMessage,
        authorization: &IsoLifecycleAuthorization,
        committed_transaction_hash: Option<&str>,
    ) -> Result<(IsoLifecycleOutcome, IsoMessageStatus), IsoLifecycleApplyError> {
        let _state_guard = self.state_lock.lock();
        let referenced_message_id =
            canonical_lifecycle_referenced_message_id(message_type, parsed)?;
        let status_code = lifecycle_status_code(message_type, parsed).map(ToOwned::to_owned);
        let reason_code = lifecycle_reason_code(parsed).map(ToOwned::to_owned);
        let detail = lifecycle_detail(message_type, parsed, status_code.as_deref());
        let reference_time = SystemTime::now();
        let referenced_message_known = if let Some(original_id) = referenced_message_id.as_deref() {
            let binding = authorization
                .original
                .as_ref()
                .filter(|binding| binding.message_id == original_id)
                .ok_or(MsgError::ValidationFailed)?;
            let original = self
                .records
                .get(original_id)
                .ok_or(MsgError::ValidationFailed)?;
            if original.incarnation != binding.incarnation
                || !self.record_is_live_at(&original, reference_time)
            {
                return Err(MsgError::ValidationFailed.into());
            }
            if message_type == "pacs.002"
                && status_code
                    .as_deref()
                    .is_some_and(is_settlement_status_code)
            {
                let expected_hash = binding
                    .transaction_hash
                    .as_deref()
                    .ok_or(MsgError::ValidationFailed)?;
                if committed_transaction_hash != Some(expected_hash)
                    || original.transaction_hash.as_deref() != Some(expected_hash)
                {
                    return Err(MsgError::ValidationFailed.into());
                }
            }
            true
        } else {
            if authorization.original.is_some() {
                return Err(MsgError::ValidationFailed.into());
            }
            false
        };
        let (action, original_mutation) = if let Some(original_id) = referenced_message_id
            .as_deref()
            .filter(|_| referenced_message_known)
        {
            self.prepare_lifecycle_update(
                message_id,
                original_id,
                message_type,
                status_code.as_deref(),
                reason_code.as_deref(),
                detail,
            )
            .map_err(|error| self.lifecycle_apply_error(original_id, error))?
        } else {
            ("recorded", None)
        };
        let lifecycle_mutation = self
            .prepare_lifecycle_accepted(
                message_id,
                lifecycle_context(message_type, parsed),
                Some(format!(
                    "recorded inbound ISO 20022 {message_type} lifecycle message"
                )),
            )
            .map_err(|error| self.lifecycle_apply_error(message_id, error))?;
        let status = Self::status_snapshot(message_id, &lifecycle_mutation.candidate);
        self.commit_lifecycle_operation(original_mutation, lifecycle_mutation)
            .map_err(|error| self.lifecycle_apply_error(message_id, error))?;
        Ok((
            IsoLifecycleOutcome {
                referenced_message_id,
                referenced_message_known,
                lifecycle_status_code: status_code,
                lifecycle_reason_code: reason_code,
                action,
            },
            status,
        ))
    }
    fn lifecycle_apply_error(
        &self,
        message_id: &str,
        error: IsoStatusHistoryLimitError,
    ) -> IsoLifecycleApplyError {
        self.report_status_history_limit(message_id, error);
        if error == IsoStatusHistoryLimitError::Persistence {
            IsoLifecycleApplyError::PersistenceUnavailable
        } else {
            IsoLifecycleApplyError::Validation(MsgError::ValidationFailed)
        }
    }
    #[cfg(test)]
    fn compatibility_lifecycle_authorization(
        &self,
        message_type: &str,
        parsed: &ParsedMessage,
    ) -> Result<IsoLifecycleAuthorization, MsgError> {
        let _state_guard = self.state_lock.lock();
        let Some(message_id) = canonical_lifecycle_referenced_message_id(message_type, parsed)?
        else {
            return Ok(IsoLifecycleAuthorization::initial(
                IsoRecordParties::default(),
            ));
        };
        let original = self
            .records
            .get(&message_id)
            .ok_or(MsgError::ValidationFailed)?;
        if !self.record_is_live_at(&original, SystemTime::now()) {
            return Err(MsgError::ValidationFailed);
        }
        Ok(IsoLifecycleAuthorization {
            parties: original.parties.clone(),
            original: Some(IsoLifecycleOriginalBinding {
                message_id,
                incarnation: original.incarnation.clone(),
                transaction_hash: original.transaction_hash.clone(),
            }),
        })
    }
    #[cfg(test)]
    fn lifecycle_reference_is_live_at(&self, message_id: &str, now: SystemTime) -> bool {
        self.records
            .get(message_id)
            .is_some_and(|record| self.record_is_live_at(&record, now))
    }
    fn record_is_live_at(&self, record: &IsoMessageRecordV2, now: SystemTime) -> bool {
        if record.retention_protected() {
            return true;
        }
        if self.store_dir.is_some() {
            self.store_retention.is_zero()
                || match now.duration_since(record.updated_at) {
                    Ok(age) => age <= self.store_retention,
                    Err(_) => true,
                }
        } else {
            now.duration_since(record.replay_expires_at).is_err()
        }
    }
    /// Create the exact unsigned transfer payload for a validated pacs.008 message.
    pub fn build_pacs008_payload(
        &self,
        parsed: &ParsedMessage,
        world: &impl WorldReadOnly,
        now_ms: u64,
        chain_id: &ChainId,
        network_id: &iroha_data_model::NetworkId,
        telemetry: &MaybeTelemetry,
    ) -> Result<(TransactionPayload, IsoMessageContext), MsgError> {
        let debtor_iban = require_identifier(
            "DbtrAcct",
            IdentifierKind::Iban,
            parsed
                .field_text("DbtrAcct")
                .ok_or(MsgError::ValidationFailed)?,
        )?;
        let creditor_iban = require_identifier(
            "CdtrAcct",
            IdentifierKind::Iban,
            parsed
                .field_text("CdtrAcct")
                .ok_or(MsgError::ValidationFailed)?,
        )?;
        let currency = require_identifier(
            "IntrBkSttlmCcy",
            IdentifierKind::Currency,
            parsed
                .field_text("IntrBkSttlmCcy")
                .ok_or(MsgError::ValidationFailed)?,
        )?;
        let amount_raw = parsed
            .field_text("IntrBkSttlmAmt")
            .ok_or(MsgError::ValidationFailed)?;
        let debtor_agent = parsed
            .field_text("DbtrAgt")
            .ok_or(MsgError::ValidationFailed)?;
        self.require_bic("DbtrAgt", debtor_agent)?;
        let creditor_agent = parsed
            .field_text("CdtrAgt")
            .ok_or(MsgError::ValidationFailed)?;
        self.require_bic("CdtrAgt", creditor_agent)?;
        let mut context = IsoMessageContext {
            ledger_id: Some(chain_id.as_str().to_owned()),
            settlement_amount: Some(amount_raw.trim().to_owned()),
            settlement_currency: Some(currency.clone()),
            ..IsoMessageContext::default()
        };
        if let Some(ledger_hint) = parsed.field_text("SplmtryData/LedgerId") {
            if ledger_hint != chain_id.as_str() {
                return Err(MsgError::ValidationFailed);
            }
            context.ledger_id = Some(ledger_hint.to_owned());
        }
        let debtor = self.resolve_bound_account(
            &debtor_iban,
            "DbtrAcct",
            parsed.field_text("SplmtryData/SourceAccountId"),
            "SplmtryData/SourceAccountId",
            telemetry,
            ISO_PACS008_CONTEXT,
        )?;
        context.source_account_id = Some(debtor.to_string());
        if let Some(address) = parsed.field_text("SplmtryData/SourceAccountAddress") {
            let trimmed = address.trim();
            if !trimmed.is_empty() {
                context.source_account_address = Some(parse_account_address_literal(trimmed)?);
            }
        }
        let creditor = self.resolve_bound_account(
            &creditor_iban,
            "CdtrAcct",
            parsed.field_text("SplmtryData/TargetAccountId"),
            "SplmtryData/TargetAccountId",
            telemetry,
            ISO_PACS008_CONTEXT,
        )?;
        context.target_account_id = Some(creditor.to_string());
        if let Some(address) = parsed.field_text("SplmtryData/TargetAccountAddress") {
            let trimmed = address.trim();
            if !trimmed.is_empty() {
                context.target_account_address = Some(parse_account_address_literal(trimmed)?);
            }
        }
        let asset_definition = self.resolve_bound_asset(
            world,
            now_ms,
            &currency,
            parsed.field_text("SplmtryData/AssetDefinitionId"),
        )?;
        context.asset_definition_id = Some(asset_definition.to_string());
        let amount = self.settlement_amount(&currency, amount_raw)?;
        let asset = AssetId::new(asset_definition.clone(), debtor.clone());
        let asset_id_str = asset.to_string();
        context.asset_id = Some(asset_id_str);
        let transfer = Transfer::asset_quantity(asset, amount, creditor);
        let mut metadata = Metadata::default();
        for (key, value) in [
            ("iso20022_ledger_id", context.ledger_id.as_deref()),
            (
                "iso20022_source_account_id",
                context.source_account_id.as_deref(),
            ),
            (
                "iso20022_source_account_address",
                context.source_account_address.as_deref(),
            ),
            (
                "iso20022_target_account_id",
                context.target_account_id.as_deref(),
            ),
            (
                "iso20022_target_account_address",
                context.target_account_address.as_deref(),
            ),
            (
                "iso20022_asset_definition_id",
                context.asset_definition_id.as_deref(),
            ),
            ("iso20022_asset_id", context.asset_id.as_deref()),
            (
                "iso20022_settlement_amount",
                context.settlement_amount.as_deref(),
            ),
            (
                "iso20022_settlement_currency",
                context.settlement_currency.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                insert_metadata_value(&mut metadata, key, value)?;
            }
        }
        let mut builder = TransactionBuilder::new(
            *network_id,
            self.signer_account.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(core::iter::once(InstructionBox::from(transfer)));
        if metadata.iter().len() > 0 {
            builder = builder.with_metadata(metadata);
        }
        let payload = builder
            .into_payload()
            .map_err(|_| MsgError::ValidationFailed)?;
        Ok((payload, context))
    }
    /// Create the exact unsigned transfer payload for a validated pacs.009 message.
    pub fn build_pacs009_payload(
        &self,
        parsed: &ParsedMessage,
        world: &impl WorldReadOnly,
        now_ms: u64,
        chain_id: &ChainId,
        network_id: &iroha_data_model::NetworkId,
        telemetry: &MaybeTelemetry,
    ) -> Result<(TransactionPayload, IsoMessageContext), MsgError> {
        let debtor_iban = require_identifier(
            "DbtrAcct",
            IdentifierKind::Iban,
            parsed
                .field_text("DbtrAcct")
                .ok_or(MsgError::ValidationFailed)?,
        )?;
        let creditor_iban = require_identifier(
            "CdtrAcct",
            IdentifierKind::Iban,
            parsed
                .field_text("CdtrAcct")
                .ok_or(MsgError::ValidationFailed)?,
        )?;
        let currency = require_identifier(
            "IntrBkSttlmCcy",
            IdentifierKind::Currency,
            parsed
                .field_text("IntrBkSttlmCcy")
                .ok_or(MsgError::ValidationFailed)?,
        )?;
        let amount_raw = parsed
            .field_text("IntrBkSttlmAmt")
            .ok_or(MsgError::ValidationFailed)?;
        let instructing_agent_bic = parsed
            .field_text("InstgAgt")
            .ok_or(MsgError::ValidationFailed)?;
        self.require_bic("InstgAgt", instructing_agent_bic)?;
        let instructed_agent_bic = parsed
            .field_text("InstdAgt")
            .ok_or(MsgError::ValidationFailed)?;
        self.require_bic("InstdAgt", instructed_agent_bic)?;
        if let Some(purpose) = parsed.field_text("Purp") {
            if !purpose.trim().eq_ignore_ascii_case("SECU") {
                return Err(MsgError::InvalidValue {
                    field: "Purp".to_owned(),
                    kind: InvalidValueKind::Enum,
                });
            }
        }
        let mut context = IsoMessageContext {
            ledger_id: Some(chain_id.as_str().to_owned()),
            settlement_amount: Some(amount_raw.trim().to_owned()),
            settlement_currency: Some(currency.clone()),
            ..IsoMessageContext::default()
        };
        if let Some(ledger_hint) = parsed.field_text("SplmtryData/LedgerId") {
            if ledger_hint != chain_id.as_str() {
                return Err(MsgError::ValidationFailed);
            }
            context.ledger_id = Some(ledger_hint.to_owned());
        }
        let debtor = self.resolve_bound_account(
            &debtor_iban,
            "DbtrAcct",
            parsed.field_text("SplmtryData/SourceAccountId"),
            "SplmtryData/SourceAccountId",
            telemetry,
            ISO_PACS009_CONTEXT,
        )?;
        context.source_account_id = Some(debtor.to_string());
        if let Some(address) = parsed.field_text("SplmtryData/SourceAccountAddress") {
            let trimmed = address.trim();
            if !trimmed.is_empty() {
                context.source_account_address = Some(parse_account_address_literal(trimmed)?);
            }
        }
        let creditor = self.resolve_bound_account(
            &creditor_iban,
            "CdtrAcct",
            parsed.field_text("SplmtryData/TargetAccountId"),
            "SplmtryData/TargetAccountId",
            telemetry,
            ISO_PACS009_CONTEXT,
        )?;
        context.target_account_id = Some(creditor.to_string());
        if let Some(address) = parsed.field_text("SplmtryData/TargetAccountAddress") {
            let trimmed = address.trim();
            if !trimmed.is_empty() {
                context.target_account_address = Some(parse_account_address_literal(trimmed)?);
            }
        }
        let asset_definition = self.resolve_bound_asset(
            world,
            now_ms,
            &currency,
            parsed.field_text("SplmtryData/AssetDefinitionId"),
        )?;
        context.asset_definition_id = Some(asset_definition.to_string());
        let amount = self.settlement_amount(&currency, amount_raw)?;
        let asset = AssetId::new(asset_definition.clone(), debtor.clone());
        let asset_id_str = asset.to_string();
        context.asset_id = Some(asset_id_str);
        let transfer = Transfer::asset_quantity(asset, amount, creditor);
        let mut metadata = Metadata::default();
        for (key, value) in [
            ("iso20022_ledger_id", context.ledger_id.as_deref()),
            (
                "iso20022_source_account_id",
                context.source_account_id.as_deref(),
            ),
            (
                "iso20022_source_account_address",
                context.source_account_address.as_deref(),
            ),
            (
                "iso20022_target_account_id",
                context.target_account_id.as_deref(),
            ),
            (
                "iso20022_target_account_address",
                context.target_account_address.as_deref(),
            ),
            (
                "iso20022_asset_definition_id",
                context.asset_definition_id.as_deref(),
            ),
            ("iso20022_asset_id", context.asset_id.as_deref()),
            (
                "iso20022_settlement_amount",
                context.settlement_amount.as_deref(),
            ),
            (
                "iso20022_settlement_currency",
                context.settlement_currency.as_deref(),
            ),
            (
                "iso20022_business_message_id",
                parsed.field_text("BizMsgIdr"),
            ),
            ("iso20022_definition_id", parsed.field_text("MsgDefIdr")),
            ("iso20022_category_purpose", parsed.field_text("Purp")),
        ] {
            if let Some(value) = value {
                insert_metadata_value(&mut metadata, key, value)?;
            }
        }
        let mut builder = TransactionBuilder::new(
            *network_id,
            self.signer_account.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(core::iter::once(InstructionBox::from(transfer)));
        if metadata.iter().len() > 0 {
            builder = builder.with_metadata(metadata);
        }
        let payload = builder
            .into_payload()
            .map_err(|_| MsgError::ValidationFailed)?;
        Ok((payload, context))
    }
    /// Sign the exact payload after Torii has inserted its fixed-point fee quote.
    pub(crate) fn sign_transaction_payload(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, MsgError> {
        TransactionBuilder::from_payload(payload)
            .map_err(|_| MsgError::ValidationFailed)?
            .try_sign(&self.signer_private_key)
            .map_err(|_| MsgError::ValidationFailed)
    }
}
impl Iso20022BridgeRuntime {
    fn prepare_lifecycle_update(
        &self,
        lifecycle_message_id: &str,
        original_id: &str,
        message_type: &str,
        status_code: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) -> Result<(&'static str, Option<IsoPreparedRecordMutation>), IsoStatusHistoryLimitError> {
        let Some(lifecycle_metadata) = self
            .records
            .get(lifecycle_message_id)
            .map(|record| record.metadata.clone())
        else {
            return Ok(("ignored_profile_mismatch", None));
        };
        let Some((
            original_message_type,
            original_metadata,
            original_state,
            original_queued,
            settled,
        )) = self.records.get(original_id).map(|record| {
            (
                record.metadata.message_type().map(ToOwned::to_owned),
                record.metadata.clone(),
                record.state,
                record.ledger_tx_queued,
                record.settled_at.is_some(),
            )
        })
        else {
            return Ok(("recorded", None));
        };
        if lifecycle_metadata.profile_id().is_none()
            || lifecycle_metadata.profile_id() != original_metadata.profile_id()
        {
            return Ok(("ignored_profile_mismatch", None));
        }
        if lifecycle_metadata.business_service() != original_metadata.business_service() {
            return Ok(("ignored_business_service_mismatch", None));
        }
        if !lifecycle_update_matches_original(message_type, original_message_type.as_deref()) {
            return Ok(("ignored_message_family_mismatch", None));
        }
        if original_state == IsoMessageState::Rejected || (settled && message_type != "pacs.004") {
            return Ok(("ignored_stale_transition", None));
        }
        if original_state == IsoMessageState::Pending && !original_queued {
            return Ok(("ignored_in_flight", None));
        }
        if message_type == "pacs.004" {
            if !settled {
                return Ok(("ignored_unsettled_return", None));
            }
            let detail =
                Some(detail.unwrap_or_else(|| "payment returned by inbound pacs.004".to_owned()));
            let reason_code = reason_code
                .or(Some("PRTRY:PAYMENT_RETURN"))
                .map(ToOwned::to_owned);
            let mutation = self.prepare_transition_existing(original_id, |record| {
                record.last_seen = Instant::now();
                record.updated_at = SystemTime::now();
                record.state = IsoMessageState::Rejected;
                record.detail = detail;
                record.hold_reason_code = None;
                record.change_reason_codes.clear();
                record.rejection_reason_code = reason_code;
            })?;
            return Ok(("marked_returned", Some(mutation)));
        }
        if message_type == "camt.056" {
            let reason_code = reason_code.or(Some("CANC")).map(ToOwned::to_owned);
            let mutation = self.prepare_transition_existing(original_id, |record| {
                record.last_seen = Instant::now();
                record.updated_at = SystemTime::now();
                record.rejection_reason_code = None;
                record.set_hold_reason(reason_code);
                record.add_change_reason_code("CANCELLATION_REQUESTED".to_owned());
            })?;
            return Ok(("marked_cancellation_requested", Some(mutation)));
        }
        if status_code.is_some_and(|code| {
            json_string_encoded_len(code)
                .and_then(|bytes| bytes.checked_add(2))
                .is_none_or(|bytes| bytes > ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1)
        }) {
            return Err(IsoStatusHistoryLimitError::ChangeReasonEncodedBytes);
        }
        match status_code
            .map(str::trim)
            .filter(|code| !code.is_empty())
            .map(|code| code.to_ascii_uppercase())
            .as_deref()
        {
            Some("ACSC" | "ACCP" | "SETT" | "SETTLED") => {
                let mutation = self.prepare_transition_existing(original_id, |record| {
                    let now = SystemTime::now();
                    record.last_seen = Instant::now();
                    record.updated_at = now;
                    record.state = IsoMessageState::Accepted;
                    record.set_queued();
                    record.mark_settled(now);
                    record.clear_hold();
                    record.rejection_reason_code = None;
                })?;
                Ok(("marked_settled", Some(mutation)))
            }
            Some("RJCT" | "REJT" | "CANC" | "CAND") => {
                let detail =
                    Some(detail.unwrap_or_else(|| "ISO 20022 lifecycle rejection".to_owned()));
                let reason_code = reason_code.or(Some("RJCT")).map(ToOwned::to_owned);
                let mutation = self.prepare_transition_existing(original_id, |record| {
                    record.last_seen = Instant::now();
                    record.updated_at = SystemTime::now();
                    record.state = IsoMessageState::Rejected;
                    record.detail = detail;
                    record.settled_at = None;
                    record.hold_reason_code = None;
                    record.change_reason_codes.clear();
                    record.rejection_reason_code = reason_code;
                })?;
                Ok(("marked_rejected", Some(mutation)))
            }
            Some("PDNG" | "PEND" | "PENF") => {
                let reason_code = reason_code.or(status_code).map(ToOwned::to_owned);
                let mutation = self.prepare_transition_existing(original_id, |record| {
                    record.last_seen = Instant::now();
                    record.updated_at = SystemTime::now();
                    record.state = IsoMessageState::Pending;
                    record.settled_at = None;
                    record.rejection_reason_code = None;
                    record.set_hold_reason(reason_code);
                })?;
                Ok(("marked_pending", Some(mutation)))
            }
            Some("PART") => {
                let mutation = self.prepare_transition_existing(original_id, |record| {
                    record.last_seen = Instant::now();
                    record.updated_at = SystemTime::now();
                    record.add_change_reason_code("PARTIAL_SETTLEMENT".to_owned());
                })?;
                Ok(("marked_partial", Some(mutation)))
            }
            Some("ACSP" | "ACTC") => {
                let mutation = self.prepare_transition_existing(original_id, |record| {
                    record.last_seen = Instant::now();
                    record.updated_at = SystemTime::now();
                    record.set_queued();
                })?;
                Ok(("marked_processing", Some(mutation)))
            }
            Some(other) => {
                let other = other.to_owned();
                let mutation = self.prepare_transition_existing(original_id, |record| {
                    record.last_seen = Instant::now();
                    record.updated_at = SystemTime::now();
                    record.add_change_reason_code(other);
                })?;
                Ok(("recorded_status_code", Some(mutation)))
            }
            None => {
                let message_type = message_type.to_owned();
                let mutation = self.prepare_transition_existing(original_id, |record| {
                    record.last_seen = Instant::now();
                    record.updated_at = SystemTime::now();
                    record.add_change_reason_code(message_type);
                })?;
                Ok(("recorded_lifecycle_reference", Some(mutation)))
            }
        }
    }
    #[cfg(test)]
    fn apply_lifecycle_update(
        &self,
        lifecycle_message_id: &str,
        original_id: &str,
        message_type: &str,
        status_code: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) -> Result<&'static str, IsoStatusHistoryLimitError> {
        let (action, mutation) = self.prepare_lifecycle_update(
            lifecycle_message_id,
            original_id,
            message_type,
            status_code,
            reason_code,
            detail,
        )?;
        if let Some(mutation) = mutation
            && !self.commit_record_candidate(
                &mutation.message_id,
                Some(&mutation.previous),
                mutation.candidate,
            )
        {
            return Err(IsoStatusHistoryLimitError::Persistence);
        }
        Ok(action)
    }
    fn prepare_transition_existing(
        &self,
        message_id: &str,
        update: impl FnOnce(&mut IsoMessageRecordV2),
    ) -> Result<IsoPreparedRecordMutation, IsoStatusHistoryLimitError> {
        let previous = self
            .records
            .get(message_id)
            .map(|record| record.clone())
            .ok_or(IsoStatusHistoryLimitError::MissingReservation)?;
        let mut candidate = previous.clone();
        candidate.try_transition(update)?;
        Ok(IsoPreparedRecordMutation {
            message_id: message_id.to_owned(),
            previous,
            candidate,
        })
    }
    #[cfg(test)]
    fn try_transition_existing(
        &self,
        message_id: &str,
        update: impl FnOnce(&mut IsoMessageRecordV2),
    ) -> Result<bool, IsoStatusHistoryLimitError> {
        let mutation = match self.prepare_transition_existing(message_id, update) {
            Ok(mutation) => mutation,
            Err(IsoStatusHistoryLimitError::MissingReservation) => return Ok(false),
            Err(error) => return Err(error),
        };
        if !self.commit_record_candidate(message_id, Some(&mutation.previous), mutation.candidate) {
            return Err(IsoStatusHistoryLimitError::Persistence);
        }
        Ok(true)
    }
    fn prune_expired(&self) {
        let wall_now = SystemTime::now();
        self.prune_expired_tombstones(wall_now);
        if self.store_dir.is_some() {
            self.compact_persisted_records();
            return;
        }
        let expired = self
            .records
            .iter()
            .filter_map(|entry| {
                (!entry.retention_protected()
                    && wall_now.duration_since(entry.replay_expires_at).is_ok())
                .then(|| entry.key().clone())
            })
            .collect::<Vec<_>>();
        for message_id in expired {
            self.remove_expired_message_locked(&message_id, wall_now);
        }
    }
    fn metadata_conflicts(&self, message_id: &str, metadata: &IsoMessageMetadata) -> bool {
        metadata
            .payload_hash()
            .and_then(|hash| self.payload_hash_index.get(hash))
            .is_some_and(|existing| existing.as_str() != message_id)
            || metadata
                .business_message_id()
                .and_then(normalise_business_message_id)
                .and_then(|id| {
                    self.business_message_id_index
                        .get(&id)
                        .map(|existing| existing.value().clone())
                })
                .is_some_and(|existing| existing.as_str() != message_id)
            || metadata
                .uetr()
                .and_then(|uetr| self.uetr_index.get(&normalise_uetr(uetr)))
                .is_some_and(|existing| existing.as_str() != message_id)
    }
    fn insert_metadata_indexes(&self, message_id: &str, metadata: &IsoMessageMetadata) {
        if let Some(payload_hash) = metadata.payload_hash() {
            self.payload_hash_index
                .insert(payload_hash.to_owned(), message_id.to_owned());
        }
        if let Some(business_message_id) = metadata
            .business_message_id()
            .and_then(normalise_business_message_id)
        {
            self.business_message_id_index
                .insert(business_message_id, message_id.to_owned());
        }
        if let Some(uetr) = metadata.uetr() {
            self.uetr_index
                .insert(normalise_uetr(uetr), message_id.to_owned());
        }
    }
    fn insert_tombstone_indexes(&self, message_id: &str, tombstone: &IsoReplayTombstone) {
        if let Some(payload_hash) = tombstone.payload_hash.as_deref() {
            self.payload_hash_index
                .insert(payload_hash.to_owned(), message_id.to_owned());
        }
        if let Some(business_message_id) = tombstone
            .business_message_id
            .as_deref()
            .and_then(normalise_business_message_id)
        {
            self.business_message_id_index
                .insert(business_message_id, message_id.to_owned());
        }
        if let Some(uetr) = tombstone.uetr.as_deref() {
            self.uetr_index
                .insert(normalise_uetr(uetr), message_id.to_owned());
        }
    }
    fn remove_tombstone_indexes(&self, message_id: &str, tombstone: &IsoReplayTombstone) {
        if let Some(payload_hash) = tombstone.payload_hash.as_deref() {
            self.payload_hash_index
                .remove_if(payload_hash, |_, owner| owner == message_id);
        }
        if let Some(business_message_id) = tombstone
            .business_message_id
            .as_deref()
            .and_then(normalise_business_message_id)
        {
            self.business_message_id_index
                .remove_if(&business_message_id, |_, owner| owner == message_id);
        }
        if let Some(uetr) = tombstone.uetr.as_deref() {
            self.uetr_index
                .remove_if(&normalise_uetr(uetr), |_, owner| owner == message_id);
        }
    }
    fn remove_record_indexes(&self, message_id: &str, record: &IsoMessageRecordV2) {
        if let Some(hash) = record.transaction_hash.as_deref() {
            self.tx_hash_index
                .remove_if(hash, |_, owner| owner == message_id);
        }
        if let Some(payload_hash) = record.metadata.payload_hash() {
            self.payload_hash_index
                .remove_if(payload_hash, |_, owner| owner == message_id);
        }
        if let Some(business_message_id) = record
            .metadata
            .business_message_id()
            .and_then(normalise_business_message_id)
        {
            self.business_message_id_index
                .remove_if(&business_message_id, |_, owner| owner == message_id);
        }
        if let Some(uetr) = record.metadata.uetr() {
            self.uetr_index
                .remove_if(&normalise_uetr(uetr), |_, owner| owner == message_id);
        }
        self.payload_hash_index
            .retain(|_, existing_message| existing_message != message_id);
        self.business_message_id_index
            .retain(|_, existing_message| existing_message != message_id);
        self.uetr_index
            .retain(|_, existing_message| existing_message != message_id);
    }
    fn recover_pending_lifecycle_operation(&self, store_dir: &Path) -> eyre::Result<()> {
        let operations_dir = store_dir.join(ISO_PERSISTED_LIFECYCLE_OPERATION_DIR);
        if !is_real_directory(&operations_dir) {
            eyre::bail!(
                "ISO lifecycle operation store `{}` is not a real directory; regenerate the first-release ISO store",
                operations_dir.display()
            );
        }
        let expected_filename = lifecycle_journal_filename();
        let mut pending = None;
        let mut entry_count = 0_u64;
        for entry in fs::read_dir(&operations_dir)
            .wrap_err("failed to enumerate ISO lifecycle operation records")?
        {
            let entry = entry.wrap_err("failed to read an ISO lifecycle operation entry")?;
            entry_count = entry_count
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("ISO lifecycle operation entry counter overflowed"))?;
            if entry_count > ISO_PERSISTED_LIFECYCLE_OPERATION_MAX_ENTRIES {
                eyre::bail!(
                    "ISO lifecycle operation store exceeds its bounded recovery limit of {ISO_PERSISTED_LIFECYCLE_OPERATION_MAX_ENTRIES} entries; regenerate the first-release ISO store"
                );
            }
            let path = entry.path();
            let file_name = path.file_name().and_then(|name| name.to_str());
            let is_expected_temp = file_name
                .and_then(iso_record_temp_target_filename)
                .is_some_and(|target| target == expected_filename.as_str());
            let metadata = secure_file_metadata::from_path(&path).wrap_err_with(|| {
                format!(
                    "failed to inspect ISO lifecycle operation entry `{}`",
                    path.display()
                )
            })?;
            if !persisted_metadata_is_direct_regular(&metadata)
                || metadata.len() > ISO_PERSISTED_LIFECYCLE_OPERATION_MAX_BYTES
            {
                eyre::bail!(
                    "ISO lifecycle operation entry `{}` is unsafe or exceeds its bounded recovery byte limit; regenerate the first-release ISO store",
                    path.display()
                );
            }
            if is_expected_temp {
                remove_stable_startup_writer_temp(&path, &metadata, "lifecycle operation")?;
                continue;
            }
            if file_name != Some(expected_filename.as_str()) || pending.is_some() {
                eyre::bail!(
                    "ISO lifecycle operation store contains unexpected entry `{}`; regenerate the first-release ISO store",
                    path.display()
                );
            }
            let (text, _) = read_persisted_json_bounded_with_metadata(
                &path,
                &metadata,
                ISO_PERSISTED_LIFECYCLE_OPERATION_MAX_BYTES,
            )
            .ok_or_else(|| {
                eyre::eyre!(
                    "ISO lifecycle operation record `{}` is unstable or unreadable; regenerate the first-release ISO store",
                    path.display()
                )
            })?;
            let value = norito::json::from_json::<JsonValue>(&text).wrap_err_with(|| {
                format!(
                    "ISO lifecycle operation record `{}` is not valid JSON; regenerate the first-release ISO store",
                    path.display()
                )
            })?;
            let journal = lifecycle_journal_from_value(&value).ok_or_else(|| {
                eyre::eyre!(
                    "ISO lifecycle operation record `{}` is invalid or corrupt; regenerate the first-release ISO store",
                    path.display()
                )
            })?;
            pending = Some((path, journal));
        }
        let Some((path, journal)) = pending else {
            return Ok(());
        };
        if let Some(original) = journal.original.as_ref() {
            self.materialize_lifecycle_journal_mutation(original, false)
                .map_err(|error| eyre::eyre!(error))?;
        }
        self.materialize_lifecycle_journal_mutation(&journal.lifecycle, false)
            .map_err(|error| eyre::eyre!(error))?;
        remove_lifecycle_journal_file(&path).wrap_err_with(|| {
            format!(
                "failed to durably retire recovered ISO lifecycle operation `{}`",
                path.display()
            )
        })?;
        Ok(())
    }
    fn load_persisted_tombstones(
        &self,
        store_dir: &Path,
        scan_budget: &mut IsoStartupScanBudget,
    ) -> eyre::Result<Vec<(PathBuf, String)>> {
        let tombstones_dir = store_dir.join(ISO_PERSISTED_REPLAY_TOMBSTONE_DIR);
        match fs::symlink_metadata(&tombstones_dir) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                eyre::bail!(
                    "ISO replay tombstone store `{}` is not a real directory; regenerate the first-release ISO store",
                    tombstones_dir.display()
                );
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(Vec::new());
            }
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!(
                        "failed to inspect ISO replay tombstone store `{}`",
                        tombstones_dir.display()
                    )
                });
            }
        }
        let now = SystemTime::now();
        let mut expired_paths = Vec::new();
        let entries =
            fs::read_dir(&tombstones_dir).wrap_err("failed to enumerate ISO replay tombstones")?;
        let mut directory_entries = 0;
        for entry in entries {
            let entry = entry.wrap_err("failed to read an ISO replay tombstone directory entry")?;
            let Some((path, text, bytes)) = read_startup_record_entry(
                entry,
                &mut directory_entries,
                scan_budget,
                "replay tombstone",
            )?
            else {
                continue;
            };
            let value = norito::json::from_json::<JsonValue>(&text).wrap_err_with(|| {
                format!(
                    "ISO replay tombstone `{}` is not valid JSON; regenerate the first-release ISO store",
                    path.display()
                )
            })?;
            if let Some(version) = value
                .as_object()
                .and_then(|object| object.get("version"))
                .and_then(JsonValue::as_u64)
                && version != ISO_PERSISTED_REPLAY_TOMBSTONE_VERSION
            {
                eyre::bail!(
                    "incompatible ISO bridge replay tombstone schema version {version}; expected V{ISO_PERSISTED_REPLAY_TOMBSTONE_VERSION}; regenerate the first-release ISO store"
                );
            }
            let (message_id, tombstone) = replay_tombstone_from_value(&value).ok_or_else(|| {
                eyre::eyre!(
                    "ISO replay tombstone `{}` is invalid or corrupt for schema V{}; regenerate the first-release ISO store",
                    path.display(),
                    ISO_PERSISTED_REPLAY_TOMBSTONE_VERSION
                )
            })?;
            if path.file_name().and_then(|name| name.to_str())
                != Some(message_filename(&message_id).as_str())
            {
                eyre::bail!(
                    "ISO replay tombstone `{}` does not match its embedded message identity; regenerate the first-release ISO store",
                    path.display()
                );
            }
            self.record_existing_durable_entry(
                IsoDurableRecordKind::ReplayTombstone,
                &message_id,
                bytes,
                &path,
            )?;
            if now.duration_since(tombstone.expires_at).is_ok() {
                expired_paths.push((path, message_id));
                continue;
            }
            let metadata = replay_tombstone_metadata(&tombstone);
            if self.metadata_conflicts(&message_id, &metadata)
                || self.replay_tombstones.contains_key(&message_id)
            {
                eyre::bail!(
                    "ISO bridge replay tombstone store contains conflicting immutable identities; regenerate the first-release ISO store"
                );
            }
            self.insert_tombstone_indexes(&message_id, &tombstone);
            self.replay_tombstones.insert(message_id, tombstone);
        }
        Ok(expired_paths)
    }
    fn load_persisted_records(&self) -> eyre::Result<()> {
        let Some(store_dir) = self.store_dir.as_deref() else {
            return Ok(());
        };
        self.recover_pending_lifecycle_operation(store_dir)?;
        let mut scan_budget = IsoStartupScanBudget::v1();
        let expired_tombstone_paths =
            self.load_persisted_tombstones(store_dir, &mut scan_budget)?;
        let audit_dir = store_dir.join(ISO_PERSISTED_AUDIT_DIR);
        match fs::symlink_metadata(&audit_dir) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                eyre::bail!(
                    "ISO bridge audit store `{}` is not a real directory; regenerate the first-release ISO store",
                    audit_dir.display()
                );
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!(
                        "failed to inspect ISO bridge audit store `{}`",
                        audit_dir.display()
                    )
                });
            }
        }
        let audit_index_path = audit_dir.join(ISO_PERSISTED_AUDIT_INDEX_FILE);
        load_persisted_audit_index(&audit_index_path)?;
        let messages_dir = store_dir.join("messages");
        let load_messages_dir = match fs::symlink_metadata(&messages_dir) {
            Ok(metadata) if metadata.file_type().is_dir() => true,
            Ok(_) => {
                eyre::bail!(
                    "ISO bridge message store `{}` is not a real directory; regenerate the first-release ISO store",
                    messages_dir.display()
                );
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                false
            }
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!(
                        "failed to inspect ISO bridge message store `{}`",
                        messages_dir.display()
                    )
                });
            }
        };
        let now = SystemTime::now();
        let mut persisted_records = BTreeMap::new();
        if load_messages_dir {
            let entries = fs::read_dir(&messages_dir)
                .wrap_err("failed to enumerate ISO bridge V3 message records")?;
            let mut directory_entries = 0;
            for entry in entries {
                let entry =
                    entry.wrap_err("failed to read an ISO bridge message directory entry")?;
                let Some((path, text, bytes)) = read_startup_record_entry(
                    entry,
                    &mut directory_entries,
                    &mut scan_budget,
                    "message",
                )?
                else {
                    continue;
                };
                let value = norito::json::from_json::<JsonValue>(&text).wrap_err_with(|| {
                    format!(
                        "ISO bridge message record `{}` is not valid JSON; regenerate the first-release ISO store",
                        path.display()
                    )
                })?;
                let version = value
                    .as_object()
                    .and_then(|object| object.get("version"))
                    .and_then(JsonValue::as_u64)
                    .ok_or_else(|| {
                        eyre::eyre!(
                            "ISO bridge message record `{}` does not advertise numeric schema version V{}; regenerate the first-release ISO store",
                            path.display(),
                            ISO_PERSISTED_RECORD_VERSION
                        )
                    })?;
                if version != ISO_PERSISTED_RECORD_VERSION {
                    eyre::bail!(
                        "incompatible ISO bridge store record schema version {version}; expected V{ISO_PERSISTED_RECORD_VERSION}; regenerate the first-release ISO store"
                    );
                }
                let (message_id, record) = persisted_record_from_value(&value).ok_or_else(|| {
                    eyre::eyre!(
                        "ISO bridge message record `{}` is invalid or corrupt for schema V{}; regenerate the first-release ISO store",
                        path.display(),
                        ISO_PERSISTED_RECORD_VERSION
                    )
                })?;
                let expected_filename = message_filename(&message_id);
                if path.file_name().and_then(|name| name.to_str())
                    != Some(expected_filename.as_str())
                {
                    eyre::bail!(
                        "ISO bridge message record `{}` does not match its embedded message identity; regenerate the first-release ISO store",
                        path.display()
                    );
                }
                self.record_existing_durable_entry(
                    IsoDurableRecordKind::Message,
                    &message_id,
                    bytes,
                    &path,
                )?;
                if persisted_records
                    .insert(message_id.clone(), (path, record))
                    .is_some()
                {
                    eyre::bail!(
                        "ISO bridge V3 store contains duplicate embedded message identity `{message_id}`; regenerate the first-release ISO store"
                    );
                }
            }
        }
        let mut payload_hash_owners = BTreeMap::new();
        let mut business_message_id_owners = BTreeMap::new();
        let mut uetr_owners = BTreeMap::new();
        let mut transaction_hash_owners = BTreeMap::new();
        for (message_id, (_, record)) in &persisted_records {
            if !self.record_parties_are_configured(record) {
                eyre::bail!(
                    "ISO bridge V3 store record references participants or a full profile policy absent from the current configuration"
                );
            }
            let replay_live = now.duration_since(record.replay_expires_at).is_err();
            if replay_live {
                let Some(tombstone) = self.replay_tombstones.get(message_id) else {
                    eyre::bail!(
                        "ISO bridge V3 store record `{message_id}` is missing its durable replay tombstone"
                    );
                };
                if !record_matches_replay_tombstone(record, tombstone.value()) {
                    eyre::bail!(
                        "ISO bridge V3 store record `{message_id}` conflicts with its durable replay tombstone"
                    );
                }
                if self.metadata_conflicts(message_id, &record.metadata)
                    || insert_unique_persisted_identity(
                        &mut payload_hash_owners,
                        record.metadata.payload_hash().map(str::to_owned),
                        message_id,
                    )
                    || insert_unique_persisted_identity(
                        &mut business_message_id_owners,
                        record
                            .metadata
                            .business_message_id()
                            .and_then(normalise_business_message_id),
                        message_id,
                    )
                    || insert_unique_persisted_identity(
                        &mut uetr_owners,
                        record.metadata.uetr().map(normalise_uetr),
                        message_id,
                    )
                {
                    eyre::bail!(
                        "ISO bridge V3 store contains conflicting immutable replay identities for record `{message_id}`; regenerate the first-release ISO store"
                    );
                }
            }
            if insert_unique_persisted_identity(
                &mut transaction_hash_owners,
                record.transaction_hash.clone(),
                message_id,
            ) {
                eyre::bail!(
                    "ISO bridge V3 store contains conflicting transaction identities for record `{message_id}`; regenerate the first-release ISO store"
                );
            }
        }
        let mut retained = BTreeMap::new();
        for (message_id, (path, record)) in persisted_records {
            if !record.retention_protected()
                && !self.store_retention.is_zero()
                && now
                    .duration_since(record.updated_at)
                    .is_ok_and(|age| age > self.store_retention)
            {
                if now.duration_since(record.replay_expires_at).is_err() {
                    let tombstone = IsoReplayTombstone {
                        expires_at: record.replay_expires_at,
                        payload_hash: record.metadata.payload_hash.clone(),
                        business_message_id: record.metadata.business_message_id.clone(),
                        uetr: record.metadata.uetr.clone(),
                    };
                    if let Some(existing) = self.replay_tombstones.get(&message_id) {
                        if !record_matches_replay_tombstone(&record, existing.value()) {
                            eyre::bail!(
                                "ISO bridge V3 store record `{message_id}` conflicts with its durable replay tombstone"
                            );
                        }
                    } else {
                        if !self.persist_replay_tombstone(&message_id, &tombstone) {
                            retained.insert(
                                (system_time_to_ms(record.updated_at), message_id),
                                (path, record),
                            );
                            continue;
                        }
                        self.insert_tombstone_indexes(&message_id, &tombstone);
                        self.replay_tombstones.insert(message_id.clone(), tombstone);
                    }
                }
                if !self.remove_durable_identity_file(
                    IsoDurableRecordKind::Message,
                    &message_id,
                    &path,
                ) {
                    eyre::bail!(
                        "failed to durably remove expired ISO bridge V3 message record `{}`",
                        path.display()
                    );
                }
                continue;
            }
            retained.insert(
                (system_time_to_ms(record.updated_at), message_id),
                (path, record),
            );
        }
        // Rich details and replay tombstones are independent. The configured identity
        // capacity may be temporarily exceeded after an operator lowers the limit; in
        // that case all existing unexpired identities remain protected and new ingress
        // receives a retryable capacity rejection.
        for ((_, message_id), (_, record)) in retained {
            let replay_live = now.duration_since(record.replay_expires_at).is_err();
            if replay_live {
                self.insert_metadata_indexes(&message_id, &record.metadata);
            }
            if let Some(tx_hash) = record.transaction_hash.as_deref() {
                self.tx_hash_index
                    .insert(tx_hash.to_owned(), message_id.clone());
            }
            self.records.insert(message_id, record);
        }
        for (path, message_id) in expired_tombstone_paths {
            if !self.remove_durable_identity_file(
                IsoDurableRecordKind::ReplayTombstone,
                &message_id,
                &path,
            ) {
                eyre::bail!(
                    "failed to durably remove expired ISO replay tombstone `{}`",
                    path.display()
                );
            }
        }
        self.persist_audit_index();
        Ok(())
    }
    fn record_parties_are_configured(&self, record: &IsoMessageRecordV2) -> bool {
        let originator_exists = self
            .participants_by_key
            .values()
            .any(|participant| participant.id == record.parties.originator_participant_id);
        let counterparty_exists = self
            .participants_by_key
            .values()
            .any(|participant| participant.id == record.parties.counterparty_participant_id);
        let profile_matches = self
            .profiles
            .get(&record.parties.pinned_profile_id)
            .is_some_and(|profile| {
                record
                    .metadata
                    .profile_id()
                    .is_none_or(|profile_id| profile_id == profile.id.as_str())
                    && record.parties.pinned_signature_policy
                        == signature_policy_label(profile.embedded_signature_policy)
                    && record.parties.pinned_profile_policy_sha256 == profile_policy_sha256(profile)
            });
        let admitting_operator_matches =
            PublicKey::from_str(&record.parties.admitting_operator_key)
                .ok()
                .and_then(|key| self.participants_by_key.get(&key))
                .is_some_and(|participant| {
                    participant.id == record.parties.admitting_participant_id
                });
        let originator_identity_matches = self
            .participants_by_financial_id
            .get(&record.parties.originator_financial_id)
            .is_some_and(|participant| participant == &record.parties.originator_participant_id);
        let counterparty_identity_matches = self
            .participants_by_financial_id
            .get(&record.parties.counterparty_financial_id)
            .is_some_and(|participant| participant == &record.parties.counterparty_participant_id);
        originator_exists
            && counterparty_exists
            && profile_matches
            && admitting_operator_matches
            && originator_identity_matches
            && counterparty_identity_matches
    }
    fn lifecycle_mutations_available(&self) -> bool {
        if !self.lifecycle_persistence_healthy.load(Ordering::Acquire) {
            return false;
        }
        let Some(store_dir) = self.store_dir.as_deref() else {
            return true;
        };
        match secure_file_metadata::from_path(&lifecycle_journal_path(store_dir)) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        }
    }
    fn preflight_lifecycle_journal(&self, journal: &IsoLifecycleJournal) -> bool {
        let mut replacements = Vec::with_capacity(2);
        for mutation in journal
            .original
            .iter()
            .chain(core::iter::once(&journal.lifecycle))
        {
            let Ok(json) = norito::json::to_string_pretty(&mutation.after_record) else {
                return false;
            };
            let Ok(bytes) = u64::try_from(json.len()) else {
                return false;
            };
            if bytes > ISO_PERSISTED_RECORD_MAX_BYTES {
                return false;
            }
            replacements.push((
                IsoDurableRecordKind::Message,
                mutation.message_id.as_str(),
                bytes,
            ));
        }
        self.durable_store_usage
            .lock()
            .replacements_fit(&replacements)
            .is_ok()
    }
    fn persist_lifecycle_journal(&self, journal: &IsoLifecycleJournal) -> bool {
        let Some(store_dir) = self.store_dir.as_deref() else {
            return false;
        };
        let operations_dir = store_dir.join(ISO_PERSISTED_LIFECYCLE_OPERATION_DIR);
        if !is_real_directory(&operations_dir) {
            self.lifecycle_persistence_healthy
                .store(false, Ordering::Release);
            return false;
        }
        let Some(json) = lifecycle_journal_json(journal) else {
            self.lifecycle_persistence_healthy
                .store(false, Ordering::Release);
            return false;
        };
        if !persisted_json_fits_cap(&json, ISO_PERSISTED_LIFECYCLE_OPERATION_MAX_BYTES) {
            self.lifecycle_persistence_healthy
                .store(false, Ordering::Release);
            return false;
        }
        let path = lifecycle_journal_path(store_dir);
        match secure_file_metadata::from_path(&path) {
            Ok(_) => {
                self.lifecycle_persistence_healthy
                    .store(false, Ordering::Release);
                return false;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                self.lifecycle_persistence_healthy
                    .store(false, Ordering::Release);
                return false;
            }
        }
        self.lifecycle_persistence_healthy
            .store(false, Ordering::Release);
        if let Err(error) = write_iso_record_atomically(&path, json.as_bytes()) {
            let candidate_is_visible =
                read_persisted_json_bounded(&path, ISO_PERSISTED_LIFECYCLE_OPERATION_MAX_BYTES)
                    .is_some_and(|visible| visible.as_bytes() == json.as_bytes());
            iroha_logger::error!(
                ?error,
                candidate_is_visible,
                "failed to durably commit the ISO lifecycle operation journal"
            );
            return false;
        }
        true
    }
    fn materialize_lifecycle_journal_mutation(
        &self,
        mutation: &IsoLifecycleJournalMutation,
        track_usage: bool,
    ) -> Result<(), String> {
        let store_dir = self
            .store_dir
            .as_deref()
            .ok_or_else(|| "ISO lifecycle recovery requires a configured store".to_owned())?;
        let messages_dir = store_dir.join("messages");
        if !is_real_directory(&messages_dir) {
            return Err(format!(
                "ISO lifecycle recovery message store `{}` is not a real directory",
                messages_dir.display()
            ));
        }
        let path = messages_dir.join(message_filename(&mutation.message_id));
        let current_text = read_persisted_record_bounded(&path).ok_or_else(|| {
            format!(
                "ISO lifecycle recovery preimage `{}` is absent, unsafe, or unreadable",
                path.display()
            )
        })?;
        let current_value =
            norito::json::from_json::<JsonValue>(&current_text).map_err(|error| {
                format!(
                    "ISO lifecycle recovery preimage `{}` is invalid JSON: {error}",
                    path.display()
                )
            })?;
        let (current_message_id, _) =
            persisted_record_from_value(&current_value).ok_or_else(|| {
                format!(
                    "ISO lifecycle recovery preimage `{}` is invalid for record schema V{}",
                    path.display(),
                    ISO_PERSISTED_RECORD_VERSION
                )
            })?;
        if current_message_id != mutation.message_id {
            return Err(format!(
                "ISO lifecycle recovery preimage `{}` has a conflicting embedded identity",
                path.display()
            ));
        }
        let current_digest = persisted_record_sha256(&current_value)
            .ok_or_else(|| "ISO lifecycle recovery preimage has no canonical digest".to_owned())?;
        let after_digest = persisted_record_sha256(&mutation.after_record).ok_or_else(|| {
            "ISO lifecycle recovery after-image has no canonical digest".to_owned()
        })?;
        let after_json = norito::json::to_string_pretty(&mutation.after_record)
            .map_err(|error| format!("failed to encode ISO lifecycle after-image: {error}"))?;
        if !persisted_json_fits_record_cap(&after_json) {
            return Err("ISO lifecycle recovery after-image exceeds the record cap".to_owned());
        }
        if current_digest == after_digest {
            if track_usage {
                let bytes = u64::try_from(after_json.len())
                    .map_err(|_| "ISO lifecycle after-image length overflowed".to_owned())?;
                self.durable_store_usage
                    .lock()
                    .record_replacement(
                        IsoDurableRecordKind::Message,
                        &mutation.message_id,
                        bytes,
                    )
                    .map_err(|error| {
                        format!(
                            "ISO lifecycle recovery accounting rejected an already materialized after-image: {error:?}"
                        )
                    })?;
            }
            return Ok(());
        }
        if current_digest != mutation.previous_record_sha256 {
            return Err(format!(
                "ISO lifecycle recovery preimage for `{}` conflicts with both the journal preimage and after-image",
                sha256_hex(mutation.message_id.as_bytes())
            ));
        }
        let persisted = if track_usage {
            self.persist_durable_identity_json(
                IsoDurableRecordKind::Message,
                &mutation.message_id,
                &path,
                after_json.as_bytes(),
            )
        } else {
            write_iso_record_atomically(&path, after_json.as_bytes()).is_ok()
        };
        if !persisted {
            return Err(format!(
                "failed to materialize committed ISO lifecycle after-image for `{}`",
                sha256_hex(mutation.message_id.as_bytes())
            ));
        }
        Ok(())
    }
    fn publish_record_candidate(
        &self,
        message_id: &str,
        previous: Option<&IsoMessageRecordV2>,
        candidate: IsoMessageRecordV2,
    ) {
        let previous_hash = previous.and_then(|record| record.transaction_hash.as_deref());
        let candidate_hash = candidate.transaction_hash.as_deref();
        if previous_hash != candidate_hash
            && let Some(previous_hash) = previous_hash
        {
            self.tx_hash_index
                .remove_if(previous_hash, |_, owner| owner == message_id);
        }
        if let Some(candidate_hash) = candidate_hash {
            self.tx_hash_index
                .insert(candidate_hash.to_owned(), message_id.to_owned());
        }
        self.records.insert(message_id.to_owned(), candidate);
    }
    fn commit_lifecycle_operation(
        &self,
        original: Option<IsoPreparedRecordMutation>,
        lifecycle: IsoPreparedRecordMutation,
    ) -> Result<(), IsoStatusHistoryLimitError> {
        if self.store_dir.is_none() {
            if let Some(original) = original {
                self.publish_record_candidate(
                    &original.message_id,
                    Some(&original.previous),
                    original.candidate,
                );
            }
            self.publish_record_candidate(
                &lifecycle.message_id,
                Some(&lifecycle.previous),
                lifecycle.candidate,
            );
            self.compact_persisted_records();
            return Ok(());
        }
        if !self.lifecycle_mutations_available() {
            return Err(IsoStatusHistoryLimitError::Persistence);
        }
        let journal = IsoLifecycleJournal {
            original: original.as_ref().map(lifecycle_journal_mutation),
            lifecycle: lifecycle_journal_mutation(&lifecycle),
        };
        if !self.preflight_lifecycle_journal(&journal) || !self.persist_lifecycle_journal(&journal)
        {
            return Err(IsoStatusHistoryLimitError::Persistence);
        }

        // The fsynced journal is the commit point. Publish both after-images together under
        // `state_lock`; bounded recovery can now roll them forward after any crash.
        if let Some(original) = original {
            self.publish_record_candidate(
                &original.message_id,
                Some(&original.previous),
                original.candidate,
            );
        }
        self.publish_record_candidate(
            &lifecycle.message_id,
            Some(&lifecycle.previous),
            lifecycle.candidate,
        );

        let materialized = journal
            .original
            .as_ref()
            .map_or(Ok(()), |mutation| {
                self.materialize_lifecycle_journal_mutation(mutation, true)
            })
            .and_then(|()| self.materialize_lifecycle_journal_mutation(&journal.lifecycle, true));
        if let Err(error) = materialized {
            iroha_logger::error!(
                %error,
                lifecycle_message_id_sha256 = %sha256_hex(journal.lifecycle.message_id.as_bytes()),
                "committed ISO lifecycle operation remains journal-backed pending recovery"
            );
            self.persist_audit_index();
            return Ok(());
        }
        let journal_path = lifecycle_journal_path(
            self.store_dir
                .as_deref()
                .expect("configured store checked above"),
        );
        if let Err(error) = remove_lifecycle_journal_file(&journal_path) {
            iroha_logger::error!(
                ?error,
                lifecycle_message_id_sha256 = %sha256_hex(journal.lifecycle.message_id.as_bytes()),
                "materialized ISO lifecycle operation remains journaled until restart"
            );
            self.persist_audit_index();
            return Ok(());
        }
        self.lifecycle_persistence_healthy
            .store(true, Ordering::Release);
        self.compact_persisted_records();
        Ok(())
    }
    fn record_existing_durable_entry(
        &self,
        kind: IsoDurableRecordKind,
        message_id: &str,
        bytes: u64,
        path: &Path,
    ) -> eyre::Result<()> {
        self.durable_store_usage
            .lock()
            .record_existing(kind, message_id, bytes)
            .map_err(|error| {
                eyre::eyre!(
                    "ISO bridge {} record `{}` violates the V1 durable-store count or aggregate-byte invariant ({error:?}); regenerate the first-release ISO store",
                    kind.label(),
                    path.display()
                )
            })
    }
    fn persist_durable_identity_json(
        &self,
        kind: IsoDurableRecordKind,
        message_id: &str,
        path: &Path,
        bytes: &[u8],
    ) -> bool {
        let Ok(byte_count) = u64::try_from(bytes.len()) else {
            return false;
        };
        let mut usage = self.durable_store_usage.lock();
        let next_bytes = match usage.replacement_total_bytes(kind, message_id, byte_count) {
            Ok(next_bytes) => next_bytes,
            Err(error) => {
                iroha_logger::error!(
                    ?error,
                    record_kind = kind.label(),
                    message_id_sha256 = %sha256_hex(message_id.as_bytes()),
                    max_entries = ISO_PERSISTED_STARTUP_MAX_ENTRIES_V1,
                    max_bytes = ISO_PERSISTED_STARTUP_MAX_BYTES_V1,
                    "refused an ISO durable write that would exceed the V1 restart budget"
                );
                return false;
            }
        };
        if let Err(error) = write_iso_record_atomically(path, bytes) {
            let candidate_is_visible =
                read_persisted_json_bounded(path, ISO_PERSISTED_RECORD_MAX_BYTES)
                    .is_some_and(|visible| visible.as_bytes() == bytes);
            if candidate_is_visible {
                // `rename` may have succeeded before a directory-sync error was reported.
                // Keep the in-process budget conservative and coherent with the visible file
                // even though the caller must still treat durability as unconfirmed.
                usage.commit_replacement(kind, message_id, byte_count, next_bytes);
            }
            iroha_logger::error!(
                ?error,
                candidate_is_visible,
                record_kind = kind.label(),
                message_id_sha256 = %sha256_hex(message_id.as_bytes()),
                "failed to persist ISO record atomically"
            );
            return false;
        }
        usage.commit_replacement(kind, message_id, byte_count, next_bytes);
        true
    }
    fn remove_durable_identity_file(
        &self,
        kind: IsoDurableRecordKind,
        message_id: &str,
        path: &Path,
    ) -> bool {
        self.remove_durable_identity_file_with_directory_sync(
            kind,
            message_id,
            path,
            sync_iso_directory,
        )
    }
    fn remove_durable_identity_file_with_directory_sync(
        &self,
        kind: IsoDurableRecordKind,
        message_id: &str,
        path: &Path,
        sync_directory: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> bool {
        let mut usage = self.durable_store_usage.lock();
        let unlink_succeeded = match fs::remove_file(path) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                iroha_logger::error!(
                    ?error,
                    record_kind = kind.label(),
                    message_id_sha256 = %sha256_hex(message_id.as_bytes()),
                    "failed to remove an ISO durable identity record"
                );
                return false;
            }
        };
        let Some(parent) = path.parent() else {
            iroha_logger::error!(
                record_kind = kind.label(),
                message_id_sha256 = %sha256_hex(message_id.as_bytes()),
                "refused to release ISO durable-store accounting for a path without a containing directory"
            );
            return false;
        };
        if let Err(error) = sync_directory(parent) {
            // The name may already be absent, but a crash can still resurrect it until
            // the containing directory is durable. Keep both the in-memory identity and
            // its capacity reservation so callers fail closed and can retry the sync.
            iroha_logger::error!(
                ?error,
                unlink_succeeded,
                record_kind = kind.label(),
                message_id_sha256 = %sha256_hex(message_id.as_bytes()),
                "ISO durable identity unlink is visible but not durable; retained in-memory state and accounting"
            );
            return false;
        }
        Self::finish_durable_usage_removal(&mut usage, kind, message_id)
    }
    fn finish_durable_usage_removal(
        usage: &mut IsoDurableStoreUsage,
        kind: IsoDurableRecordKind,
        message_id: &str,
    ) -> bool {
        if let Err(error) = usage.remove(kind, message_id) {
            iroha_logger::error!(
                ?error,
                record_kind = kind.label(),
                message_id_sha256 = %sha256_hex(message_id.as_bytes()),
                "ISO durable-store accounting failed after file removal"
            );
            return false;
        }
        true
    }
    fn commit_record_candidate(
        &self,
        message_id: &str,
        previous: Option<&IsoMessageRecordV2>,
        candidate: IsoMessageRecordV2,
    ) -> bool {
        if !self.lifecycle_mutations_available() {
            return false;
        }
        if !self.persist_record_candidate(message_id, &candidate) {
            return false;
        }
        self.publish_record_candidate(message_id, previous, candidate);
        self.compact_persisted_records();
        true
    }
    fn persist_record_candidate(&self, message_id: &str, record: &IsoMessageRecordV2) -> bool {
        let Some(store_dir) = self.store_dir.as_deref() else {
            return true;
        };
        let messages_dir = store_dir.join("messages");
        if !is_real_directory(&messages_dir) {
            return false;
        }
        let Some(json) = persisted_record_json(message_id, &record) else {
            return false;
        };
        let path = messages_dir.join(message_filename(message_id));
        if !persisted_json_fits_record_cap(&json) {
            iroha_logger::error!(
                message_id_sha256 = %sha256_hex(message_id.as_bytes()),
                max_bytes = ISO_PERSISTED_RECORD_MAX_BYTES,
                "refused to replace an ISO record with an oversized candidate"
            );
            return false;
        }
        self.persist_durable_identity_json(
            IsoDurableRecordKind::Message,
            message_id,
            &path,
            json.as_bytes(),
        )
    }
    fn persist_message(&self, message_id: &str) -> bool {
        let Some(record) = self.records.get(message_id).map(|entry| entry.clone()) else {
            return false;
        };
        if !self.persist_record_candidate(message_id, &record) {
            return false;
        }
        self.compact_persisted_records();
        true
    }
    fn remove_persisted_message(&self, message_id: &str) {
        let Some(store_dir) = self.store_dir.as_deref() else {
            return;
        };
        let messages_dir = store_dir.join("messages");
        if !is_real_directory(&messages_dir) {
            self.persist_audit_index();
            return;
        }
        let path = messages_dir.join(message_filename(message_id));
        self.remove_durable_identity_file(IsoDurableRecordKind::Message, message_id, &path);
        self.persist_audit_index();
    }
    fn persist_replay_tombstone(&self, message_id: &str, tombstone: &IsoReplayTombstone) -> bool {
        let Some(store_dir) = self.store_dir.as_deref() else {
            return false;
        };
        let tombstones_dir = store_dir.join(ISO_PERSISTED_REPLAY_TOMBSTONE_DIR);
        if !is_real_directory(&tombstones_dir) {
            return false;
        }
        let Ok(json) =
            norito::json::to_string_pretty(&replay_tombstone_value(message_id, tombstone))
        else {
            return false;
        };
        if !persisted_json_fits_record_cap(&json) {
            return false;
        }
        let path = tombstones_dir.join(message_filename(message_id));
        self.persist_durable_identity_json(
            IsoDurableRecordKind::ReplayTombstone,
            message_id,
            &path,
            json.as_bytes(),
        )
    }
    fn remove_persisted_replay_tombstone(&self, message_id: &str) -> bool {
        let Some(store_dir) = self.store_dir.as_deref() else {
            return true;
        };
        let tombstones_dir = store_dir.join(ISO_PERSISTED_REPLAY_TOMBSTONE_DIR);
        if !is_real_directory(&tombstones_dir) {
            return false;
        }
        self.remove_durable_identity_file(
            IsoDurableRecordKind::ReplayTombstone,
            message_id,
            &tombstones_dir.join(message_filename(message_id)),
        )
    }
    fn persist_audit_index(&self) -> bool {
        let result = self.try_persist_audit_index();
        let healthy = result.is_ok();
        self.audit_persistence_healthy
            .store(healthy, Ordering::Release);
        if let Err(error) = result {
            iroha_logger::error!(
                %error,
                "failed to persist the ISO V3 audit index to every configured target"
            );
        }
        healthy
    }
    fn try_persist_audit_index(&self) -> Result<(), String> {
        let payload = self.audit_index();
        let json = norito::json::to_string_pretty(&payload)
            .map_err(|error| format!("failed to encode the ISO V3 audit index: {error}"))?;
        if !persisted_json_fits_cap(&json, ISO_PERSISTED_AUDIT_INDEX_MAX_BYTES) {
            return Err(format!(
                "ISO V3 audit index exceeds the {ISO_PERSISTED_AUDIT_INDEX_MAX_BYTES}-byte limit"
            ));
        }
        if let Some(store_dir) = self.store_dir.as_deref() {
            let audit_dir = store_dir.join(ISO_PERSISTED_AUDIT_DIR);
            if !is_real_directory(&audit_dir) {
                return Err(format!(
                    "ISO bridge audit directory is unavailable or unsafe: {}",
                    audit_dir.display()
                ));
            }
            let path = audit_dir.join(ISO_PERSISTED_AUDIT_INDEX_FILE);
            write_iso_record_atomically(&path, json.as_bytes()).map_err(|error| {
                format!(
                    "failed to persist ISO V3 audit index `{}`: {error}",
                    path.display()
                )
            })?;
        }
        self.persist_external_audit_export(&payload, &json)
    }
    fn persist_external_audit_export(&self, payload: &JsonValue, json: &str) -> Result<(), String> {
        let Some(export_dir) = self.audit_export_dir.as_deref() else {
            return Ok(());
        };
        if !is_real_directory(export_dir) {
            return Err(format!(
                "ISO audit export directory is unavailable or unsafe: {}",
                export_dir.display()
            ));
        }
        let index_sha256 = audit_index_digest(payload)
            .ok_or_else(|| "failed to calculate the ISO audit index digest".to_owned())?;
        let anchor = audit_export_anchor_value(payload, self.store_dir.as_deref());
        let anchor_json = norito::json::to_string_pretty(&anchor)
            .map_err(|error| format!("failed to encode the ISO audit anchor: {error}"))?;
        let anchor_dir = export_dir.join(ISO_AUDIT_EXPORT_ANCHOR_DIR);
        if !is_real_directory(&anchor_dir) {
            return Err(format!(
                "ISO audit anchor directory is unavailable or unsafe: {}",
                anchor_dir.display()
            ));
        }
        let immutable_anchor_path = anchor_dir.join(format!("{index_sha256}.notary.json"));
        write_iso_record_atomically(&immutable_anchor_path, anchor_json.as_bytes()).map_err(
            |error| {
                format!(
                    "failed to persist digest-addressed ISO audit anchor `{}`: {error}",
                    immutable_anchor_path.display()
                )
            },
        )?;
        let index_path = export_dir.join(ISO_PERSISTED_AUDIT_INDEX_FILE);
        write_iso_record_atomically(&index_path, json.as_bytes()).map_err(|error| {
            format!(
                "failed to persist external ISO audit index `{}`: {error}",
                index_path.display()
            )
        })?;
        let latest_anchor_path = export_dir.join(ISO_AUDIT_EXPORT_LATEST_ANCHOR_FILE);
        write_iso_record_atomically(&latest_anchor_path, anchor_json.as_bytes()).map_err(
            |error| {
                format!(
                    "failed to advance latest ISO audit anchor `{}`: {error}",
                    latest_anchor_path.display()
                )
            },
        )?;
        Ok(())
    }
    fn compact_persisted_records(&self) -> bool {
        let Some(store_dir) = self.store_dir.as_deref() else {
            return self.persist_audit_index();
        };
        let now = SystemTime::now();
        self.prune_expired_tombstones(now);
        if !self.store_retention.is_zero() {
            while let Some(message_id) = self.oldest_expired_record_message_id(now) {
                if !self.remove_record_for_retention(&message_id, store_dir, now) {
                    break;
                }
            }
        }
        while self.records.len() > self.store_max_records {
            let Some(message_id) = self.oldest_replay_expired_record_message_id(now) else {
                break;
            };
            if !self.remove_record_for_retention(&message_id, store_dir, now) {
                break;
            }
        }
        self.persist_audit_index()
    }
    fn oldest_expired_record_message_id(&self, now: SystemTime) -> Option<String> {
        self.records
            .iter()
            .filter(|entry| {
                !entry.value().retention_protected()
                    && now
                        .duration_since(entry.value().updated_at)
                        .is_ok_and(|age| age > self.store_retention)
            })
            .min_by(|left, right| {
                system_time_to_ms(left.value().updated_at)
                    .cmp(&system_time_to_ms(right.value().updated_at))
                    .then_with(|| left.key().cmp(right.key()))
            })
            .map(|entry| entry.key().clone())
    }
    fn oldest_replay_expired_record_message_id(&self, now: SystemTime) -> Option<String> {
        self.records
            .iter()
            .filter(|entry| {
                !entry.value().retention_protected()
                    && now.duration_since(entry.value().replay_expires_at).is_ok()
            })
            .min_by(|left, right| {
                system_time_to_ms(left.value().updated_at)
                    .cmp(&system_time_to_ms(right.value().updated_at))
                    .then_with(|| left.key().cmp(right.key()))
            })
            .map(|entry| entry.key().clone())
    }
    fn remove_record_for_retention(
        &self,
        message_id: &str,
        store_dir: &Path,
        now: SystemTime,
    ) -> bool {
        let Some(record) = self.records.get(message_id).map(|record| record.clone()) else {
            return true;
        };
        let replay_live = now.duration_since(record.replay_expires_at).is_err();
        if replay_live {
            let tombstone = IsoReplayTombstone {
                expires_at: record.replay_expires_at,
                payload_hash: record.metadata.payload_hash.clone(),
                business_message_id: record.metadata.business_message_id.clone(),
                uetr: record.metadata.uetr.clone(),
            };
            if let Some(existing) = self.replay_tombstones.get(message_id) {
                if !record_matches_replay_tombstone(&record, existing.value()) {
                    return false;
                }
            } else {
                if !self.persist_replay_tombstone(message_id, &tombstone) {
                    return false;
                }
                self.insert_tombstone_indexes(message_id, &tombstone);
                self.replay_tombstones
                    .insert(message_id.to_owned(), tombstone);
            }
        }
        let messages_dir = store_dir.join("messages");
        if is_real_directory(&messages_dir) {
            let path = messages_dir.join(message_filename(message_id));
            if !self.remove_durable_identity_file(IsoDurableRecordKind::Message, message_id, &path)
            {
                return false;
            }
        }
        if replay_live {
            if let Some(hash) = record.transaction_hash.as_deref() {
                self.tx_hash_index
                    .remove_if(hash, |_, owner| owner == message_id);
            }
        } else {
            self.remove_record_indexes(message_id, &record);
        }
        self.records.remove(message_id);
        true
    }
    fn prune_expired_tombstones(&self, now: SystemTime) {
        let expired = self
            .replay_tombstones
            .iter()
            .filter_map(|entry| {
                now.duration_since(entry.expires_at)
                    .is_ok()
                    .then(|| entry.key().clone())
            })
            .collect::<Vec<_>>();
        for message_id in expired {
            if !self.remove_persisted_replay_tombstone(&message_id) {
                continue;
            }
            if let Some((_, tombstone)) = self.replay_tombstones.remove(&message_id) {
                self.remove_tombstone_indexes(&message_id, &tombstone);
            }
        }
    }
    fn require_profile_reference_data(&self, profile: &TradfiRailProfile) -> Result<(), MsgError> {
        for requirement in &profile.required_reference_datasets {
            if !self.reference_data.has_required_dataset(*requirement) {
                return Err(MsgError::ValidationFailed);
            }
        }
        Ok(())
    }
    fn validate_amount_minor_units(
        &self,
        profile: &MessageProfile,
        parsed: &ParsedMessage,
    ) -> Result<(), MsgError> {
        let Some(currency) = parsed.field_text("IntrBkSttlmCcy") else {
            return Ok(());
        };
        let Some(amount) = parsed.field_text("IntrBkSttlmAmt") else {
            return Ok(());
        };
        let currency = normalise_currency(currency);
        let minor_units = profile.minor_units_for(&currency);
        if amount_fraction_digits(amount) > usize::from(minor_units) {
            return Err(MsgError::InvalidValue {
                field: "IntrBkSttlmAmt".to_owned(),
                kind: InvalidValueKind::Amount,
            });
        }
        Ok(())
    }
    fn validate_supplementary_data_limit(
        &self,
        profile: &MessageProfile,
        parsed: &ParsedMessage,
    ) -> Result<(), MsgError> {
        let total = parsed
            .iter()
            .filter(|(field, _)| field.contains("SplmtryData"))
            .map(|(field, value)| field.len() + value.len())
            .sum::<usize>();
        if total > profile.supplementary_data_max_bytes {
            return Err(MsgError::TooManyOccurrences {
                field: "SplmtryData",
                max: profile.supplementary_data_max_bytes,
                actual: total,
            });
        }
        Ok(())
    }
    fn validate_structured_address_mode(
        &self,
        profile: &MessageProfile,
        parsed: &ParsedMessage,
    ) -> Result<(), MsgError> {
        if profile.structured_address_mode == StructuredAddressMode::Permissive {
            return Ok(());
        }
        let has_unstructured_address = parsed
            .iter()
            .any(|(field, _)| is_unstructured_postal_address_field(field));
        if has_unstructured_address {
            return Err(MsgError::InvalidValue {
                field: "PstlAdr/AdrLine".to_owned(),
                kind: InvalidValueKind::Enum,
            });
        }
        Ok(())
    }
    fn validate_message_reference_data(
        &self,
        message_type: &str,
        parsed: &ParsedMessage,
    ) -> Result<(), MsgError> {
        if !matches!(
            message_type,
            "sese.023" | "sese.024" | "sese.025" | "colr.012"
        ) {
            return Ok(());
        }
        for (field, value) in parsed.iter() {
            let value = core::str::from_utf8(value).map_err(|_| MsgError::InvalidValue {
                field: field.to_owned(),
                kind: InvalidValueKind::Utf8,
            })?;
            if is_instrument_reference_field(field) {
                self.require_instrument_crosswalk(field, value)?;
            }
            if is_settlement_venue_field(field) {
                self.require_mic(field, value)?;
            }
            if is_settlement_party_bic_field(field) {
                self.require_bic(field, value)?;
            }
        }
        Ok(())
    }
    fn validate_securities_ledger_mapping(
        &self,
        profile: &TradfiRailProfile,
        message_type: &str,
        parsed: &ParsedMessage,
    ) -> Result<(), MsgError> {
        if profile.rail != TradfiRail::SecuritiesCsd || message_type != "sese.023" {
            return Ok(());
        }
        let instrument = parsed
            .field_text("SctiesLeg/FinInstrmId")
            .ok_or(MsgError::MissingField("SctiesLeg/FinInstrmId"))?;
        self.require_instrument_ledger_mapping("SctiesLeg/FinInstrmId", instrument)?;
        let venue_mic = parsed
            .field_text("PlcOfSttlm/MktId")
            .ok_or(MsgError::MissingField("PlcOfSttlm/MktId"))?;
        self.require_csd_venue_mapping("PlcOfSttlm/MktId", venue_mic)?;
        let delivering_bic = parsed
            .field_text("DlvrgSttlmPties/Pty/Bic")
            .ok_or(MsgError::MissingField("DlvrgSttlmPties/Pty/Bic"))?;
        let delivering_account = parsed
            .field_text("DlvrgSttlmPties/Acct")
            .ok_or(MsgError::MissingField("DlvrgSttlmPties/Acct"))?;
        self.require_securities_account_mapping(
            "DlvrgSttlmPties/Acct",
            delivering_account,
            Some(delivering_bic),
        )?;
        let receiving_bic = parsed
            .field_text("RcvgSttlmPties/Pty/Bic")
            .ok_or(MsgError::MissingField("RcvgSttlmPties/Pty/Bic"))?;
        let receiving_account = parsed
            .field_text("RcvgSttlmPties/Acct")
            .ok_or(MsgError::MissingField("RcvgSttlmPties/Acct"))?;
        self.require_securities_account_mapping(
            "RcvgSttlmPties/Acct",
            receiving_account,
            Some(receiving_bic),
        )?;
        let currency = parsed
            .field_text("CashLeg/Ccy")
            .ok_or(MsgError::MissingField("CashLeg/Ccy"))?;
        let payment_type = parsed.field_text("SttlmTpAndAddtlParams/Pmt");
        self.require_cash_leg_mapping("CashLeg/Ccy", currency, payment_type)?;
        Ok(())
    }
    fn require_instrument_crosswalk(&self, field: &str, value: &str) -> Result<(), MsgError> {
        let isin = normalise_identifier(IdentifierKind::Isin, value);
        if ivm::iso20022::validate_identifier(IdentifierKind::Isin, &isin) {
            return match self.reference_data.validate_isin(&isin) {
                Ok(()) => Ok(()),
                Err(err) => Err(Self::map_reference_error(field, IdentifierKind::Isin, err)),
            };
        }
        let cusip = normalise_identifier(IdentifierKind::Cusip, value);
        if ivm::iso20022::validate_identifier(IdentifierKind::Cusip, &cusip) {
            return match self.reference_data.validate_cusip(&cusip) {
                Ok(()) => Ok(()),
                Err(err) => Err(Self::map_reference_error(field, IdentifierKind::Cusip, err)),
            };
        }
        Err(MsgError::InvalidIdentifier {
            field: field.to_owned(),
            kind: IdentifierKind::Isin,
        })
    }
    fn require_instrument_ledger_mapping(&self, field: &str, value: &str) -> Result<(), MsgError> {
        match self
            .reference_data
            .validate_instrument_ledger_mapping(value)
        {
            Ok(()) => Ok(()),
            Err(err) => Err(Self::map_reference_error(field, IdentifierKind::Isin, err)),
        }
    }
    fn require_mic(&self, field: &str, value: &str) -> Result<(), MsgError> {
        let mic = require_identifier(field, IdentifierKind::Mic, value)?;
        match self.reference_data.validate_mic(&mic) {
            Ok(()) => Ok(()),
            Err(err) => Err(Self::map_reference_error(field, IdentifierKind::Mic, err)),
        }
    }
    fn require_csd_venue_mapping(&self, field: &str, value: &str) -> Result<(), MsgError> {
        let mic = require_identifier(field, IdentifierKind::Mic, value)?;
        match self.reference_data.validate_csd_venue(&mic) {
            Ok(()) => Ok(()),
            Err(err) => Err(Self::map_reference_error(field, IdentifierKind::Mic, err)),
        }
    }
    fn require_securities_account_mapping(
        &self,
        field: &str,
        account: &str,
        bic: Option<&str>,
    ) -> Result<(), MsgError> {
        let account = account.trim();
        if account.is_empty() {
            return Err(MsgError::MissingField("SecuritiesAccount"));
        }
        match self
            .reference_data
            .validate_securities_account(account, bic)
        {
            Ok(()) => Ok(()),
            Err(ReferenceDataError::MissingLedgerMapping { .. }) => Err(MsgError::ValidationFailed),
            Err(
                ReferenceDataError::DatasetUnavailable { .. }
                | ReferenceDataError::DatasetFailed { .. },
            ) => Err(MsgError::ValidationFailed),
            Err(ReferenceDataError::NotFound { .. } | ReferenceDataError::MicInactive { .. }) => {
                Err(MsgError::InvalidValue {
                    field: field.to_owned(),
                    kind: InvalidValueKind::Enum,
                })
            }
        }
    }
    fn require_bic(&self, field: &str, value: &str) -> Result<(), MsgError> {
        let bic = require_identifier(field, IdentifierKind::Bic, value)?;
        match self.reference_data.validate_bic(&bic) {
            Ok(()) => Ok(()),
            Err(err) => Err(Self::map_reference_error(field, IdentifierKind::Bic, err)),
        }
    }
    fn require_cash_leg_mapping(
        &self,
        field: &str,
        currency: &str,
        payment_type: Option<&str>,
    ) -> Result<(), MsgError> {
        let currency = require_identifier(field, IdentifierKind::Currency, currency)?;
        match self
            .reference_data
            .validate_cash_leg(&currency, payment_type)
        {
            Ok(()) => Ok(()),
            Err(err) => Err(Self::map_reference_error(
                field,
                IdentifierKind::Currency,
                err,
            )),
        }
    }
    fn map_reference_error(field: &str, kind: IdentifierKind, err: ReferenceDataError) -> MsgError {
        match err {
            ReferenceDataError::DatasetUnavailable { .. }
            | ReferenceDataError::DatasetFailed { .. } => MsgError::ValidationFailed,
            ReferenceDataError::NotFound { .. } => MsgError::InvalidIdentifier {
                field: field.to_owned(),
                kind,
            },
            ReferenceDataError::MicInactive { .. } => MsgError::InvalidIdentifier {
                field: field.to_owned(),
                kind: IdentifierKind::Mic,
            },
            ReferenceDataError::MissingLedgerMapping { .. } => MsgError::ValidationFailed,
        }
    }
}
fn persisted_record_value(message_id: &str, record: &IsoMessageRecordV2) -> JsonValue {
    let mut root = persisted_record_body_value(message_id, record);
    let digest = persisted_record_digest(&JsonValue::Object(root.clone()));
    root.insert(
        ISO_PERSISTED_RECORD_DIGEST_FIELD.to_owned(),
        JsonValue::from(digest.as_str()),
    );
    JsonValue::Object(root)
}
fn persisted_record_json(message_id: &str, record: &IsoMessageRecordV2) -> Option<String> {
    norito::json::to_string_pretty(&persisted_record_value(message_id, record)).ok()
}
fn persisted_record_sha256(value: &JsonValue) -> Option<&str> {
    value
        .as_object()
        .and_then(|object| object.get(ISO_PERSISTED_RECORD_DIGEST_FIELD))
        .and_then(JsonValue::as_str)
        .filter(|digest| is_canonical_sha256_hex(digest))
}
fn lifecycle_journal_mutation(mutation: &IsoPreparedRecordMutation) -> IsoLifecycleJournalMutation {
    let previous = persisted_record_value(&mutation.message_id, &mutation.previous);
    IsoLifecycleJournalMutation {
        message_id: mutation.message_id.clone(),
        previous_record_sha256: persisted_record_sha256(&previous)
            .expect("persisted ISO record values always carry a canonical digest")
            .to_owned(),
        after_record: persisted_record_value(&mutation.message_id, &mutation.candidate),
    }
}
fn lifecycle_journal_mutation_value(mutation: &IsoLifecycleJournalMutation) -> JsonValue {
    let mut value = norito::json::Map::new();
    value.insert(
        "message_id".to_owned(),
        JsonValue::from(mutation.message_id.as_str()),
    );
    value.insert(
        "previous_record_sha256".to_owned(),
        JsonValue::from(mutation.previous_record_sha256.as_str()),
    );
    value.insert("after_record".to_owned(), mutation.after_record.clone());
    JsonValue::Object(value)
}
fn lifecycle_journal_value(journal: &IsoLifecycleJournal) -> JsonValue {
    let mut root = norito::json::Map::new();
    root.insert(
        "version".to_owned(),
        JsonValue::from(ISO_PERSISTED_LIFECYCLE_OPERATION_VERSION),
    );
    root.insert(
        "record_version".to_owned(),
        JsonValue::from(ISO_PERSISTED_RECORD_VERSION),
    );
    root.insert(
        "original".to_owned(),
        journal
            .original
            .as_ref()
            .map_or(JsonValue::Null, |mutation| {
                lifecycle_journal_mutation_value(mutation)
            }),
    );
    root.insert(
        "lifecycle".to_owned(),
        lifecycle_journal_mutation_value(&journal.lifecycle),
    );
    let digest = persisted_record_digest(&JsonValue::Object(root.clone()));
    root.insert(
        ISO_PERSISTED_LIFECYCLE_OPERATION_DIGEST_FIELD.to_owned(),
        JsonValue::from(digest),
    );
    JsonValue::Object(root)
}
fn lifecycle_journal_json(journal: &IsoLifecycleJournal) -> Option<String> {
    norito::json::to_string_pretty(&lifecycle_journal_value(journal)).ok()
}
const PERSISTED_LIFECYCLE_JOURNAL_REQUIRED_KEYS: &[&str] = &[
    "version",
    "record_version",
    "original",
    "lifecycle",
    ISO_PERSISTED_LIFECYCLE_OPERATION_DIGEST_FIELD,
];
const PERSISTED_LIFECYCLE_JOURNAL_MUTATION_REQUIRED_KEYS: &[&str] =
    &["message_id", "previous_record_sha256", "after_record"];
fn lifecycle_journal_mutation_from_value(value: &JsonValue) -> Option<IsoLifecycleJournalMutation> {
    let object = value.as_object()?;
    if !json_object_has_exact_keys(object, PERSISTED_LIFECYCLE_JOURNAL_MUTATION_REQUIRED_KEYS) {
        return None;
    }
    let message_id = required_clean_string(object, "message_id")?;
    let previous_record_sha256 = required_clean_string(object, "previous_record_sha256")?;
    if !is_canonical_sha256_hex(&previous_record_sha256) {
        return None;
    }
    let after_record = object.get("after_record")?.clone();
    let (after_message_id, _) = persisted_record_from_value(&after_record)?;
    if after_message_id != message_id {
        return None;
    }
    Some(IsoLifecycleJournalMutation {
        message_id,
        previous_record_sha256,
        after_record,
    })
}
fn lifecycle_journal_from_value(value: &JsonValue) -> Option<IsoLifecycleJournal> {
    let object = value.as_object()?;
    if !json_object_has_exact_keys(object, PERSISTED_LIFECYCLE_JOURNAL_REQUIRED_KEYS)
        || object.get("version")?.as_u64()? != ISO_PERSISTED_LIFECYCLE_OPERATION_VERSION
        || object.get("record_version")?.as_u64()? != ISO_PERSISTED_RECORD_VERSION
        || !persisted_json_digest_matches(object, ISO_PERSISTED_LIFECYCLE_OPERATION_DIGEST_FIELD)
    {
        return None;
    }
    let original = match object.get("original")? {
        JsonValue::Null => None,
        value => Some(lifecycle_journal_mutation_from_value(value)?),
    };
    let lifecycle = lifecycle_journal_mutation_from_value(object.get("lifecycle")?)?;
    if original
        .as_ref()
        .is_some_and(|mutation| mutation.message_id == lifecycle.message_id)
    {
        return None;
    }
    Some(IsoLifecycleJournal {
        original,
        lifecycle,
    })
}
fn replay_tombstone_metadata(tombstone: &IsoReplayTombstone) -> IsoMessageMetadata {
    IsoMessageMetadata {
        payload_hash: tombstone.payload_hash.clone(),
        business_message_id: tombstone.business_message_id.clone(),
        uetr: tombstone.uetr.clone(),
        ..IsoMessageMetadata::default()
    }
}
fn replay_tombstone_value(message_id: &str, tombstone: &IsoReplayTombstone) -> JsonValue {
    let mut map = norito::json::Map::new();
    map.insert(
        "version".to_owned(),
        JsonValue::from(ISO_PERSISTED_REPLAY_TOMBSTONE_VERSION),
    );
    map.insert("message_id".to_owned(), JsonValue::from(message_id));
    map.insert(
        "expires_at_ms".to_owned(),
        JsonValue::from(system_time_to_ms(tombstone.expires_at)),
    );
    map.insert(
        "payload_hash".to_owned(),
        string_or_null(tombstone.payload_hash.as_deref()),
    );
    map.insert(
        "business_message_id".to_owned(),
        string_or_null(tombstone.business_message_id.as_deref()),
    );
    map.insert("uetr".to_owned(), string_or_null(tombstone.uetr.as_deref()));
    let digest = persisted_record_digest(&JsonValue::Object(map.clone()));
    map.insert(
        ISO_PERSISTED_REPLAY_TOMBSTONE_DIGEST_FIELD.to_owned(),
        JsonValue::from(digest),
    );
    JsonValue::Object(map)
}
const REPLAY_TOMBSTONE_REQUIRED_KEYS: &[&str] = &[
    "version",
    "message_id",
    "expires_at_ms",
    "payload_hash",
    "business_message_id",
    "uetr",
    ISO_PERSISTED_REPLAY_TOMBSTONE_DIGEST_FIELD,
];
fn replay_tombstone_from_value(value: &JsonValue) -> Option<(String, IsoReplayTombstone)> {
    let object = value.as_object()?;
    if !json_object_has_exact_keys(object, REPLAY_TOMBSTONE_REQUIRED_KEYS)
        || object.get("version")?.as_u64()? != ISO_PERSISTED_REPLAY_TOMBSTONE_VERSION
        || !persisted_json_digest_matches(object, ISO_PERSISTED_REPLAY_TOMBSTONE_DIGEST_FIELD)
    {
        return None;
    }
    Some((
        required_clean_string(object, "message_id")?,
        IsoReplayTombstone {
            expires_at: system_time_from_ms(object.get("expires_at_ms")?.as_u64()?)?,
            payload_hash: required_nullable_string(object, "payload_hash")?,
            business_message_id: required_nullable_string(object, "business_message_id")?,
            uetr: required_nullable_string(object, "uetr")?,
        },
    ))
}
fn record_matches_replay_tombstone(
    record: &IsoMessageRecordV2,
    tombstone: &IsoReplayTombstone,
) -> bool {
    record.replay_expires_at == tombstone.expires_at
        && record.metadata.payload_hash == tombstone.payload_hash
        && record.metadata.business_message_id == tombstone.business_message_id
        && record.metadata.uetr == tombstone.uetr
}
fn insert_unique_persisted_identity(
    owners: &mut BTreeMap<String, String>,
    identity: Option<String>,
    message_id: &str,
) -> bool {
    let Some(identity) = identity else {
        return false;
    };
    owners
        .insert(identity, message_id.to_owned())
        .is_some_and(|owner| owner != message_id)
}
fn persisted_json_fits_record_cap(json: &str) -> bool {
    persisted_json_fits_cap(json, ISO_PERSISTED_RECORD_MAX_BYTES)
}
fn persisted_json_fits_cap(json: &str, max_bytes: u64) -> bool {
    u64::try_from(json.len()).is_ok_and(|len| len <= max_bytes)
}
fn persisted_record_body_value(message_id: &str, record: &IsoMessageRecordV2) -> norito::json::Map {
    let mut root = norito::json::Map::new();
    root.insert(
        "version".to_owned(),
        JsonValue::from(ISO_PERSISTED_RECORD_VERSION),
    );
    root.insert("message_id".to_owned(), JsonValue::from(message_id));
    root.insert("state".to_owned(), JsonValue::from(record.state.label()));
    root.insert(
        "updated_at_ms".to_owned(),
        JsonValue::from(system_time_to_ms(record.updated_at)),
    );
    root.insert(
        "transaction_hash".to_owned(),
        string_or_null(record.transaction_hash.as_deref()),
    );
    root.insert(
        "detail".to_owned(),
        string_or_null(record.detail.as_deref()),
    );
    root.insert(
        "ledger_tx_queued".to_owned(),
        JsonValue::from(record.ledger_tx_queued),
    );
    root.insert(
        "settled_at_ms".to_owned(),
        record
            .settled_at
            .map(system_time_to_ms)
            .map_or(JsonValue::Null, JsonValue::from),
    );
    root.insert(
        "hold_reason_code".to_owned(),
        string_or_null(record.hold_reason_code.as_deref()),
    );
    root.insert(
        "change_reason_codes".to_owned(),
        JsonValue::Array(
            record
                .change_reason_codes
                .iter()
                .map(|code| JsonValue::from(code.as_str()))
                .collect(),
        ),
    );
    root.insert(
        "rejection_reason_code".to_owned(),
        string_or_null(record.rejection_reason_code.as_deref()),
    );
    root.insert("context".to_owned(), context_value(&record.context));
    root.insert("metadata".to_owned(), metadata_value(&record.metadata));
    root.insert("parties".to_owned(), parties_value(&record.parties));
    root.insert(
        "replay_expires_at_ms".to_owned(),
        JsonValue::from(system_time_to_ms(record.replay_expires_at)),
    );
    root.insert(
        "status_history".to_owned(),
        JsonValue::Array(
            record
                .status_history
                .iter()
                .map(history_value)
                .collect::<Vec<_>>(),
        ),
    );
    root
}
fn persisted_record_digest(value: &JsonValue) -> String {
    let json = norito::json::to_string(value).expect("ISO persisted record JSON must serialize");
    sha256_hex(json.as_bytes())
}
fn persisted_json_digest_matches(obj: &norito::json::Map, digest_field: &str) -> bool {
    let Some(expected) = obj.get(digest_field).and_then(JsonValue::as_str) else {
        return false;
    };
    if expected.len() != 64
        || !expected
            .chars()
            .all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    {
        return false;
    }
    let mut body = obj.clone();
    body.remove(digest_field);
    persisted_record_digest(&JsonValue::Object(body)) == expected
}
fn persisted_record_digest_matches(obj: &norito::json::Map) -> bool {
    persisted_json_digest_matches(obj, ISO_PERSISTED_RECORD_DIGEST_FIELD)
}
const PERSISTED_RECORD_REQUIRED_KEYS: &[&str] = &[
    "version",
    "message_id",
    "state",
    "updated_at_ms",
    "transaction_hash",
    "detail",
    "ledger_tx_queued",
    "settled_at_ms",
    "hold_reason_code",
    "change_reason_codes",
    "rejection_reason_code",
    "context",
    "metadata",
    "parties",
    "replay_expires_at_ms",
    "status_history",
    ISO_PERSISTED_RECORD_DIGEST_FIELD,
];
const PERSISTED_CONTEXT_REQUIRED_KEYS: &[&str] = &[
    "ledger_id",
    "source_account_id",
    "source_account_address",
    "target_account_id",
    "target_account_address",
    "asset_definition_id",
    "asset_id",
    "settlement_amount",
    "settlement_currency",
    "settlement_date",
    "settlement_quantity",
    "settlement_movement_type",
    "settlement_payment_type",
    "security_instrument_id",
    "collateral_obligation_id",
    "collateral_original_amount",
    "collateral_original_currency",
    "collateral_original_instrument_id",
    "collateral_substitute_amount",
    "collateral_substitute_currency",
    "collateral_substitute_instrument_id",
    "collateral_effective_date",
    "collateral_substitution_type",
    "collateral_haircut",
    "collateral_reason_code",
    "plan_execution_order",
    "plan_atomicity",
];
const PERSISTED_METADATA_REQUIRED_KEYS: &[&str] = &[
    "profile_id",
    "message_type",
    "business_service",
    "business_message_id",
    "uetr",
    "payload_hash",
    "reference_snapshot_id",
    "embedded_signature_detected",
];
const PERSISTED_PARTIES_REQUIRED_KEYS: &[&str] = &[
    "originator_participant_id",
    "counterparty_participant_id",
    "admitting_participant_id",
    "admitting_operator_key",
    "originator_financial_id",
    "counterparty_financial_id",
    "pinned_profile_id",
    "pinned_signature_policy",
    "pinned_profile_policy_sha256",
];
const PERSISTED_HISTORY_REQUIRED_KEYS: &[&str] = &[
    "status",
    "pacs002_code",
    "updated_at_ms",
    "detail",
    "reason_code",
];
const PERSISTED_AUDIT_INDEX_REQUIRED_KEYS: &[&str] = &[
    "version",
    "record_count",
    "records",
    ISO_PERSISTED_AUDIT_INDEX_DIGEST_FIELD,
];
const PERSISTED_AUDIT_INDEX_ENTRY_REQUIRED_KEYS: &[&str] = &[
    "message_id",
    "filename",
    ISO_PERSISTED_RECORD_DIGEST_FIELD,
    "state",
    "pacs002_code",
    "updated_at_ms",
    "settled_at_ms",
    "transaction_hash",
    "profile_id",
    "message_type",
    "business_message_id",
    "uetr",
    "payload_hash",
    "reference_snapshot_id",
];
fn json_object_has_exact_keys(obj: &norito::json::Map, required: &[&str]) -> bool {
    obj.len() == required.len() && required.iter().all(|key| obj.contains_key(*key))
}
fn clean_persisted_string(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.trim() != raw || raw.chars().any(char::is_control) {
        return None;
    }
    Some(raw.to_owned())
}
fn required_clean_string(obj: &norito::json::Map, key: &str) -> Option<String> {
    obj.get(key)?.as_str().and_then(clean_persisted_string)
}
fn required_nullable_string(obj: &norito::json::Map, key: &str) -> Option<Option<String>> {
    match obj.get(key)? {
        JsonValue::Null => Some(None),
        value => value.as_str().and_then(clean_persisted_string).map(Some),
    }
}
fn required_nullable_time_ms(obj: &norito::json::Map, key: &str) -> Option<Option<SystemTime>> {
    match obj.get(key)? {
        JsonValue::Null => Some(None),
        value => value.as_u64().and_then(system_time_from_ms).map(Some),
    }
}
fn persisted_record_from_value(value: &JsonValue) -> Option<(String, IsoMessageRecordV2)> {
    let obj = value.as_object()?;
    if !json_object_has_exact_keys(obj, PERSISTED_RECORD_REQUIRED_KEYS) {
        return None;
    }
    if obj.get("version").and_then(JsonValue::as_u64)? != ISO_PERSISTED_RECORD_VERSION {
        return None;
    }
    if !persisted_record_digest_matches(obj) {
        return None;
    }
    let message_id = required_clean_string(obj, "message_id")?;
    let state = state_from_label(obj.get("state")?.as_str()?)?;
    let updated_at = obj
        .get("updated_at_ms")
        .and_then(JsonValue::as_u64)
        .and_then(system_time_from_ms)?;
    let transaction_hash = required_nullable_string(obj, "transaction_hash")?;
    let detail = required_nullable_string(obj, "detail")?;
    let ledger_tx_queued = obj.get("ledger_tx_queued")?.as_bool()?;
    let settled_at = required_nullable_time_ms(obj, "settled_at_ms")?;
    let hold_reason_code = required_nullable_string(obj, "hold_reason_code")?;
    let change_reason_values = obj.get("change_reason_codes")?.as_array()?;
    if change_reason_values.len() > ISO_CHANGE_REASON_MAX_ENTRIES_V1 {
        return None;
    }
    let change_reason_codes = change_reason_values
        .iter()
        .map(|item| item.as_str().and_then(clean_persisted_string))
        .collect::<Option<Vec<_>>>()?;
    if change_reason_codes_encoded_len(&change_reason_codes)?
        > ISO_CHANGE_REASON_MAX_ENCODED_BYTES_V1
    {
        return None;
    }
    let rejection_reason_code = required_nullable_string(obj, "rejection_reason_code")?;
    let context = context_from_value(obj.get("context")?)?;
    let metadata = metadata_from_value(obj.get("metadata")?)?;
    let parties = parties_from_value(obj.get("parties")?)?;
    let replay_expires_at = obj
        .get("replay_expires_at_ms")
        .and_then(JsonValue::as_u64)
        .and_then(system_time_from_ms)?;
    let status_history_values = obj.get("status_history")?.as_array()?;
    if status_history_values.is_empty()
        || status_history_values.len() > ISO_STATUS_HISTORY_MAX_ENTRIES_V1
    {
        return None;
    }
    let status_history = status_history_values
        .iter()
        .map(history_from_value)
        .collect::<Option<Vec<_>>>()?;
    if status_history_encoded_len(&status_history)? > ISO_STATUS_HISTORY_MAX_ENCODED_BYTES_V1 {
        return None;
    }
    let record = IsoMessageRecordV2 {
        incarnation: new_iso_record_incarnation(),
        last_seen: Instant::now(),
        updated_at,
        state,
        transaction_hash,
        detail,
        context,
        metadata,
        ledger_tx_queued,
        settled_at,
        hold_reason_code,
        change_reason_codes,
        rejection_reason_code,
        status_history,
        parties,
        replay_expires_at,
    };
    Some((message_id, record))
}
fn persisted_audit_index_value(records: Vec<JsonValue>) -> JsonValue {
    let mut root = norito::json::Map::new();
    root.insert(
        "version".to_owned(),
        JsonValue::from(ISO_PERSISTED_AUDIT_INDEX_VERSION),
    );
    root.insert(
        "record_count".to_owned(),
        JsonValue::from(u64::try_from(records.len()).unwrap_or(u64::MAX)),
    );
    root.insert("records".to_owned(), JsonValue::Array(records));
    let digest = persisted_record_digest(&JsonValue::Object(root.clone()));
    root.insert(
        ISO_PERSISTED_AUDIT_INDEX_DIGEST_FIELD.to_owned(),
        JsonValue::from(digest.as_str()),
    );
    JsonValue::Object(root)
}
fn persisted_audit_index_entry_value(
    message_id: &str,
    record: &IsoMessageRecordV2,
) -> Option<JsonValue> {
    let persisted_record = persisted_record_value(message_id, record);
    let persisted_json = norito::json::to_string_pretty(&persisted_record).ok()?;
    if !persisted_json_fits_record_cap(&persisted_json) {
        return None;
    }
    let record_sha256 = persisted_record
        .as_object()
        .and_then(|obj| obj.get(ISO_PERSISTED_RECORD_DIGEST_FIELD))
        .and_then(JsonValue::as_str)
        .expect("persisted ISO record digest is always present");
    let mut entry = norito::json::Map::new();
    entry.insert("message_id".to_owned(), JsonValue::from(message_id));
    entry.insert(
        "filename".to_owned(),
        JsonValue::from(message_filename(message_id).as_str()),
    );
    entry.insert(
        ISO_PERSISTED_RECORD_DIGEST_FIELD.to_owned(),
        JsonValue::from(record_sha256),
    );
    entry.insert("state".to_owned(), JsonValue::from(record.state.label()));
    entry.insert(
        "pacs002_code".to_owned(),
        JsonValue::from(record.derived_status().code()),
    );
    entry.insert(
        "updated_at_ms".to_owned(),
        JsonValue::from(system_time_to_ms(record.updated_at)),
    );
    entry.insert(
        "settled_at_ms".to_owned(),
        record
            .settled_at
            .map(system_time_to_ms)
            .map_or(JsonValue::Null, JsonValue::from),
    );
    entry.insert(
        "transaction_hash".to_owned(),
        string_or_null(record.transaction_hash.as_deref()),
    );
    entry.insert(
        "profile_id".to_owned(),
        string_or_null(record.metadata.profile_id()),
    );
    entry.insert(
        "message_type".to_owned(),
        string_or_null(record.metadata.message_type()),
    );
    entry.insert(
        "business_message_id".to_owned(),
        string_or_null(record.metadata.business_message_id()),
    );
    entry.insert("uetr".to_owned(), string_or_null(record.metadata.uetr()));
    entry.insert(
        "payload_hash".to_owned(),
        string_or_null(record.metadata.payload_hash()),
    );
    entry.insert(
        "reference_snapshot_id".to_owned(),
        string_or_null(record.metadata.reference_snapshot_id()),
    );
    Some(JsonValue::Object(entry))
}
fn persisted_audit_index_digest_matches(obj: &norito::json::Map) -> bool {
    persisted_json_digest_matches(obj, ISO_PERSISTED_AUDIT_INDEX_DIGEST_FIELD)
}
fn persisted_audit_index_entry_is_valid(value: &JsonValue) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if !json_object_has_exact_keys(object, PERSISTED_AUDIT_INDEX_ENTRY_REQUIRED_KEYS) {
        return false;
    }
    let Some(message_id) = required_clean_string(object, "message_id") else {
        return false;
    };
    let expected_filename = message_filename(&message_id);
    if required_clean_string(object, "filename").as_deref() != Some(expected_filename.as_str())
        || object
            .get(ISO_PERSISTED_RECORD_DIGEST_FIELD)
            .and_then(JsonValue::as_str)
            .is_none_or(|digest| {
                digest.len() != 64 || !digest.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
            })
        || object
            .get("state")
            .and_then(JsonValue::as_str)
            .and_then(state_from_label)
            .is_none()
        || object
            .get("pacs002_code")
            .and_then(JsonValue::as_str)
            .and_then(pacs002_from_code)
            .is_none()
        || object
            .get("updated_at_ms")
            .and_then(JsonValue::as_u64)
            .is_none()
        || required_nullable_time_ms(object, "settled_at_ms").is_none()
    {
        return false;
    }
    [
        "transaction_hash",
        "profile_id",
        "message_type",
        "business_message_id",
        "uetr",
        "payload_hash",
        "reference_snapshot_id",
    ]
    .into_iter()
    .all(|key| required_nullable_string(object, key).is_some())
}
fn load_persisted_audit_index(path: &Path) -> eyre::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(());
        }
        Err(error) => {
            return Err(error).wrap_err_with(|| {
                format!(
                    "failed to inspect ISO bridge audit index `{}`",
                    path.display()
                )
            });
        }
    };
    if !metadata.file_type().is_file() {
        eyre::bail!(
            "ISO bridge audit index `{}` is not a regular file; regenerate the first-release ISO store",
            path.display()
        );
    }
    let Some(text) = read_persisted_json_bounded(path, ISO_PERSISTED_AUDIT_INDEX_MAX_BYTES) else {
        eyre::bail!(
            "ISO bridge audit index `{}` is unreadable or exceeds the V3 byte limit; regenerate the first-release ISO store",
            path.display()
        );
    };
    let value = norito::json::from_json::<JsonValue>(&text).wrap_err_with(|| {
        format!(
            "ISO bridge audit index `{}` is not valid JSON; regenerate the first-release ISO store",
            path.display()
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        eyre::eyre!(
            "ISO bridge audit index `{}` is invalid or corrupt for schema V{}; regenerate the first-release ISO store",
            path.display(),
            ISO_PERSISTED_AUDIT_INDEX_VERSION
        )
    })?;
    let version = object
        .get("version")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| {
            eyre::eyre!(
                "ISO bridge audit index `{}` does not advertise numeric schema version V{}; regenerate the first-release ISO store",
                path.display(),
                ISO_PERSISTED_AUDIT_INDEX_VERSION
            )
        })?;
    if version != ISO_PERSISTED_AUDIT_INDEX_VERSION {
        eyre::bail!(
            "incompatible ISO bridge audit index schema version {version}; expected V{ISO_PERSISTED_AUDIT_INDEX_VERSION}; regenerate the first-release ISO store"
        );
    }
    let records = object.get("records").and_then(JsonValue::as_array);
    let record_count = object.get("record_count").and_then(JsonValue::as_u64);
    let records_are_current = records.is_some_and(|records| {
        let mut previous_message_id = None;
        records.iter().all(|record| {
            if !persisted_audit_index_entry_is_valid(record) {
                return false;
            }
            let message_id = record
                .as_object()
                .and_then(|object| object.get("message_id"))
                .and_then(JsonValue::as_str)
                .expect("validated audit entries carry a message id");
            if previous_message_id.is_some_and(|previous| previous >= message_id) {
                return false;
            }
            previous_message_id = Some(message_id);
            true
        })
    });
    if !json_object_has_exact_keys(object, PERSISTED_AUDIT_INDEX_REQUIRED_KEYS)
        || !persisted_audit_index_digest_matches(object)
        || records.is_none()
        || record_count != records.and_then(|records| u64::try_from(records.len()).ok())
        || !records_are_current
    {
        eyre::bail!(
            "ISO bridge audit index `{}` is invalid or corrupt for schema V{}; regenerate the first-release ISO store",
            path.display(),
            ISO_PERSISTED_AUDIT_INDEX_VERSION
        );
    }
    Ok(())
}
fn audit_index_digest(index: &JsonValue) -> Option<&str> {
    index
        .as_object()
        .and_then(|obj| obj.get(ISO_PERSISTED_AUDIT_INDEX_DIGEST_FIELD))
        .and_then(JsonValue::as_str)
}
fn audit_export_anchor_value(index: &JsonValue, store_dir: Option<&Path>) -> JsonValue {
    let mut root = norito::json::Map::new();
    root.insert(
        "version".to_owned(),
        JsonValue::from(ISO_AUDIT_EXPORT_ANCHOR_VERSION),
    );
    root.insert(
        "index_sha256".to_owned(),
        audit_index_digest(index).map_or(JsonValue::Null, JsonValue::from),
    );
    root.insert(
        "record_count".to_owned(),
        index
            .as_object()
            .and_then(|obj| obj.get("record_count"))
            .and_then(JsonValue::as_u64)
            .map_or(JsonValue::Null, JsonValue::from),
    );
    root.insert(
        "store_dir".to_owned(),
        store_dir.map_or(JsonValue::Null, |path| {
            JsonValue::from(path.display().to_string().as_str())
        }),
    );
    root.insert("audit_index".to_owned(), index.clone());
    let digest = persisted_record_digest(&JsonValue::Object(root.clone()));
    root.insert(
        ISO_AUDIT_EXPORT_ANCHOR_DIGEST_FIELD.to_owned(),
        JsonValue::from(digest.as_str()),
    );
    JsonValue::Object(root)
}
#[cfg(test)]
fn audit_export_anchor_digest_matches(obj: &norito::json::Map) -> bool {
    persisted_json_digest_matches(obj, ISO_AUDIT_EXPORT_ANCHOR_DIGEST_FIELD)
}
fn read_persisted_record_bounded(path: &Path) -> Option<String> {
    read_persisted_json_bounded(path, ISO_PERSISTED_RECORD_MAX_BYTES)
}
fn read_startup_record_entry(
    entry: fs::DirEntry,
    directory_entries: &mut u64,
    budget: &mut IsoStartupScanBudget,
    record_kind: &str,
) -> eyre::Result<Option<(PathBuf, String, u64)>> {
    *directory_entries = directory_entries.checked_add(1).ok_or_else(|| {
        eyre::eyre!("ISO bridge {record_kind} directory entry counter overflowed")
    })?;
    if *directory_entries > ISO_PERSISTED_RECORD_MAX_COUNT_V1 {
        eyre::bail!(
            "ISO bridge {record_kind} store exceeds the V1 directory entry limit of {ISO_PERSISTED_RECORD_MAX_COUNT_V1}; regenerate the first-release ISO store"
        );
    }
    let path = entry.path();
    let is_known_writer_temp = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(iso_record_temp_target_filename)
        .is_some_and(is_canonical_durable_identity_filename);
    if is_known_writer_temp {
        let file_type = entry.file_type().wrap_err_with(|| {
            format!(
                "failed to inspect ISO bridge {record_kind} writer temp `{}`",
                path.display()
            )
        })?;
        if !file_type.is_file() {
            eyre::bail!(
                "ISO bridge {record_kind} writer temp `{}` is not a direct regular file; regenerate the first-release ISO store",
                path.display()
            );
        }
        let metadata = secure_file_metadata::from_path(&path).wrap_err_with(|| {
            format!(
                "failed to inspect ISO bridge {record_kind} writer temp `{}`",
                path.display()
            )
        })?;
        if !persisted_metadata_is_direct_regular(&metadata) {
            eyre::bail!(
                "ISO bridge {record_kind} writer temp `{}` is not a direct regular file; regenerate the first-release ISO store",
                path.display()
            );
        }
        // Crash debris is still attacker-controlled startup work. Charge it before
        // opening or unlinking so repeated temps cannot bypass either V1 bound.
        budget.charge_entry(&path, metadata.len())?;
        remove_stable_startup_writer_temp(&path, &metadata, record_kind)?;
        return Ok(None);
    }
    if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
        eyre::bail!(
            "ISO bridge {record_kind} store contains unexpected entry `{}`; regenerate the first-release ISO store",
            path.display()
        );
    }
    let file_type = entry.file_type().wrap_err_with(|| {
        format!(
            "failed to inspect ISO bridge {record_kind} record `{}`",
            path.display()
        )
    })?;
    if !file_type.is_file() {
        eyre::bail!(
            "ISO bridge {record_kind} record `{}` is not a regular file; regenerate the first-release ISO store",
            path.display()
        );
    }
    let metadata = secure_file_metadata::from_path(&path).wrap_err_with(|| {
        format!(
            "failed to inspect ISO bridge {record_kind} record `{}`",
            path.display()
        )
    })?;
    let (text, actual_bytes) = read_persisted_json_bounded_with_metadata(
        &path,
        &metadata,
        ISO_PERSISTED_RECORD_MAX_BYTES,
    )
    .ok_or_else(|| {
        eyre::eyre!(
            "ISO bridge {record_kind} record `{}` is unsafe, unstable, unreadable, or exceeds the V3 byte limit; regenerate the first-release ISO store",
            path.display()
        )
    })?;
    budget.charge_entry(&path, actual_bytes)?;
    Ok(Some((path, text, actual_bytes)))
}
fn is_canonical_durable_identity_filename(file_name: &str) -> bool {
    let Some(digest) = file_name.strip_suffix(".json") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn iso_record_temp_filename(file_name: &str, process_id: u32, sequence: u64) -> String {
    format!(".{file_name}.{process_id}.{sequence}.tmp")
}
fn iso_record_temp_target_filename(file_name: &str) -> Option<&str> {
    let body = file_name.strip_prefix('.')?.strip_suffix(".tmp")?;
    let (target_and_process, sequence) = body.rsplit_once('.')?;
    let (target, process_id) = target_and_process.rsplit_once('.')?;
    let parsed_process_id = process_id.parse::<u32>().ok()?;
    let parsed_sequence = sequence.parse::<u64>().ok()?;
    if parsed_process_id.to_string() != process_id || parsed_sequence.to_string() != sequence {
        return None;
    }
    Some(target)
}
fn remove_stable_startup_writer_temp(
    path: &Path,
    expected_metadata: &SecureMetadata,
    record_kind: &str,
) -> eyre::Result<()> {
    let file = open_persisted_file_no_follow(path).wrap_err_with(|| {
        format!(
            "failed to open ISO bridge {record_kind} writer temp `{}` without following links",
            path.display()
        )
    })?;
    let opened_metadata = secure_file_metadata::from_file(&file).wrap_err_with(|| {
        format!(
            "failed to inspect opened ISO bridge {record_kind} writer temp `{}`",
            path.display()
        )
    })?;
    let named_metadata = secure_file_metadata::from_path(path).wrap_err_with(|| {
        format!(
            "failed to re-inspect ISO bridge {record_kind} writer temp `{}`",
            path.display()
        )
    })?;
    if !persisted_metadata_is_direct_regular(&opened_metadata)
        || !persisted_metadata_unchanged(expected_metadata, &opened_metadata)
        || !persisted_metadata_unchanged(&opened_metadata, &named_metadata)
    {
        eyre::bail!(
            "ISO bridge {record_kind} writer temp `{}` changed identity during startup; regenerate the first-release ISO store",
            path.display()
        );
    }
    drop(file);
    fs::remove_file(path).wrap_err_with(|| {
        format!(
            "failed to remove stable ISO bridge {record_kind} writer temp `{}`",
            path.display()
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        eyre::eyre!(
            "ISO bridge {record_kind} writer temp `{}` has no containing directory",
            path.display()
        )
    })?;
    sync_iso_directory(parent).wrap_err_with(|| {
        format!(
            "failed to durably remove ISO bridge {record_kind} writer temp `{}`",
            path.display()
        )
    })
}
fn read_persisted_json_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    let metadata = secure_file_metadata::from_path(path).ok()?;
    read_persisted_json_bounded_with_metadata(path, &metadata, max_bytes).map(|(text, _)| text)
}
fn read_persisted_json_bounded_with_metadata(
    path: &Path,
    expected_metadata: &SecureMetadata,
    max_bytes: u64,
) -> Option<(String, u64)> {
    if !persisted_metadata_is_direct_regular(expected_metadata)
        || expected_metadata.len() > max_bytes
    {
        return None;
    }
    let mut file = open_persisted_file_no_follow(path).ok()?;
    let opened_metadata = secure_file_metadata::from_file(&file).ok()?;
    if !persisted_metadata_is_direct_regular(&opened_metadata)
        || !persisted_metadata_unchanged(expected_metadata, &opened_metadata)
    {
        return None;
    }
    let initial_capacity = usize::try_from(opened_metadata.len()).ok()?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(initial_capacity).ok()?;
    let mut reader = (&mut file).take(max_bytes.saturating_add(1));
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        let next_len = bytes.len().checked_add(read)?;
        if u64::try_from(next_len).ok()? > max_bytes {
            return None;
        }
        bytes.try_reserve_exact(read).ok()?;
        bytes.extend_from_slice(&chunk[..read]);
    }
    drop(reader);
    let actual_bytes = u64::try_from(bytes.len()).ok()?;
    if actual_bytes != opened_metadata.len() {
        return None;
    }
    let after_metadata = secure_file_metadata::from_file(&file).ok()?;
    let named_after_metadata = secure_file_metadata::from_path(path).ok()?;
    if !persisted_metadata_unchanged(&opened_metadata, &after_metadata)
        || !persisted_metadata_unchanged(&after_metadata, &named_after_metadata)
    {
        return None;
    }
    String::from_utf8(bytes)
        .ok()
        .map(|text| (text, actual_bytes))
}
#[cfg(unix)]
fn open_persisted_file_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY);
    options.open(path)
}
#[cfg(windows)]
fn open_persisted_file_no_follow(path: &Path) -> std::io::Result<fs::File> {
    secure_file_metadata::open_direct_file(path)
}
#[cfg(not(any(unix, windows)))]
fn open_persisted_file_no_follow(_path: &Path) -> std::io::Result<fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "stable direct-file opens are unavailable on this platform",
    ))
}
fn persisted_metadata_is_direct_regular(metadata: &SecureMetadata) -> bool {
    secure_file_metadata::is_direct_file(metadata)
        && secure_file_metadata::number_of_links(metadata) == Some(1)
}
fn persisted_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    secure_file_metadata::unchanged(left, right)
}
fn sync_iso_directory(path: &Path) -> std::io::Result<()> {
    crate::durable_fs::sync_direct_directory(path)
}
fn remove_lifecycle_journal_file(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)?;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ISO lifecycle journal has no containing directory",
        )
    })?;
    sync_iso_directory(parent)
}
fn write_iso_record_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ISO record path has no parent directory",
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ISO record path has no UTF-8 file name",
            )
        })?;
    let sequence = ISO_RECORD_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(iso_record_temp_filename(
        file_name,
        std::process::id(),
        sequence,
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_SHARE_READ_DELETE: u32 = 0x0000_0001 | 0x0000_0004;
            options.share_mode(FILE_SHARE_READ_DELETE);
        }
        let mut file = options.open(&temp_path)?;
        let created = secure_file_metadata::from_file(&file)?;
        let named_created = secure_file_metadata::from_path(&temp_path)?;
        if !persisted_metadata_is_direct_regular(&created)
            || !persisted_metadata_unchanged(&created, &named_created)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ISO writer temp is not the newly-created private filesystem object",
            ));
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        let written = secure_file_metadata::from_file(&file)?;
        let named_written = secure_file_metadata::from_path(&temp_path)?;
        if !persisted_metadata_is_direct_regular(&written)
            || !secure_file_metadata::same_file(&created, &written)
            || !persisted_metadata_unchanged(&written, &named_written)
            || written.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ISO writer temp changed while it was being prepared",
            ));
        }
        drop(file);
        fs::rename(&temp_path, path)?;
        let published = secure_file_metadata::from_path(path)?;
        if !persisted_metadata_is_direct_regular(&published)
            || !secure_file_metadata::same_file(&written, &published)
            || published.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ISO publication changed identity before durability was established",
            ));
        }
        sync_iso_directory(parent)?;
        let durable = secure_file_metadata::from_path(path)?;
        if !persisted_metadata_unchanged(&published, &durable) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ISO publication changed while its directory was being synchronized",
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    result
}
fn is_real_directory(path: &Path) -> bool {
    secure_file_metadata::from_path(path)
        .is_ok_and(|metadata| secure_file_metadata::is_direct_directory(&metadata))
}
fn prepare_iso_persistence_layout(
    store_dir: Option<&Path>,
    audit_export_dir: Option<&Path>,
) -> std::io::Result<(Option<PathBuf>, Option<PathBuf>)> {
    let store_dir = if let Some(store_dir) = store_dir {
        prepare_real_directory(store_dir)?;
        let store_dir = fs::canonicalize(store_dir)?;
        prepare_real_directory(&store_dir.join("messages"))?;
        prepare_real_directory(&store_dir.join(ISO_PERSISTED_REPLAY_TOMBSTONE_DIR))?;
        prepare_real_directory(&store_dir.join(ISO_PERSISTED_LIFECYCLE_OPERATION_DIR))?;
        prepare_real_directory(&store_dir.join(ISO_PERSISTED_AUDIT_DIR))?;
        Some(store_dir)
    } else {
        None
    };
    let audit_export_dir = if let Some(audit_export_dir) = audit_export_dir {
        prepare_real_directory(audit_export_dir)?;
        let audit_export_dir = fs::canonicalize(audit_export_dir)?;
        prepare_real_directory(&audit_export_dir.join(ISO_AUDIT_EXPORT_ANCHOR_DIR))?;
        Some(audit_export_dir)
    } else {
        None
    };
    Ok((store_dir, audit_export_dir))
}
fn prepare_real_directory(path: &Path) -> std::io::Result<()> {
    prepare_real_directory_with_sync(path, sync_iso_directory)
}
fn prepare_real_directory_with_sync(
    path: &Path,
    mut sync_directory: impl FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ISO persistence directory must have a containing directory",
        )
    })?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let requested_parent = secure_file_metadata::from_path(parent)?;
    if !secure_file_metadata::is_direct_directory(&requested_parent) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ISO persistence parent is not a direct directory",
        ));
    }
    let durable_parent = fs::canonicalize(parent)?;
    let durable_parent_before = secure_file_metadata::from_path(&durable_parent)?;
    if !secure_file_metadata::is_direct_directory(&durable_parent_before)
        || !secure_file_metadata::same_file(&requested_parent, &durable_parent_before)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ISO persistence parent is not a real directory",
        ));
    }
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ISO persistence directory has no final path component",
        )
    })?;
    let durable_path = durable_parent.join(file_name);
    match secure_file_metadata::from_path(&durable_path) {
        Ok(metadata) if secure_file_metadata::is_direct_directory(&metadata) => {}
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ISO persistence path is not a real directory",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&durable_path)?
        }
        Err(error) => {
            #[cfg(unix)]
            if error.raw_os_error() == Some(libc::ELOOP) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ISO persistence path is not a real directory",
                ));
            }
            return Err(error);
        }
    }
    let prepared = secure_file_metadata::from_path(&durable_path)?;
    let requested = secure_file_metadata::from_path(path)?;
    let requested_parent_after_create = secure_file_metadata::from_path(parent)?;
    let durable_parent_after_create = secure_file_metadata::from_path(&durable_parent)?;
    if !secure_file_metadata::is_direct_directory(&prepared)
        || !secure_file_metadata::is_direct_directory(&requested)
        || !secure_file_metadata::same_file(&prepared, &requested)
        || !secure_file_metadata::same_file(&requested_parent, &requested_parent_after_create)
        || !secure_file_metadata::same_file(&durable_parent_before, &durable_parent_after_create)
        || !secure_file_metadata::same_file(
            &requested_parent_after_create,
            &durable_parent_after_create,
        )
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ISO persistence path or parent changed while it was being prepared",
        ));
    }
    // Sync the directory itself first, then the directory containing its name. Repeating both
    // operations when the directory already exists repairs an interrupted first-use attempt.
    sync_directory(&durable_path)?;
    sync_directory(&durable_parent)?;
    let durable_prepared = secure_file_metadata::from_path(&durable_path)?;
    let durable_parent_after_sync = secure_file_metadata::from_path(&durable_parent)?;
    let requested_parent_after_sync = secure_file_metadata::from_path(parent)?;
    if !secure_file_metadata::unchanged(&prepared, &durable_prepared)
        // Sibling stores may create or remove their own names while this one is
        // synchronized. Pin the parent object and permissions, not its entry
        // timestamps; the prepared store itself must remain unchanged.
        || !secure_file_metadata::same_file(
            &durable_parent_after_create,
            &durable_parent_after_sync,
        )
        || !secure_file_metadata::same_file(
            &requested_parent_after_create,
            &requested_parent_after_sync,
        )
        || !secure_file_metadata::is_direct_directory(&durable_parent_after_sync)
        || !secure_file_metadata::is_direct_directory(&requested_parent_after_sync)
        || durable_parent_after_create.permissions() != durable_parent_after_sync.permissions()
        || requested_parent_after_create.permissions() != requested_parent_after_sync.permissions()
        || !secure_file_metadata::same_file(
            &requested_parent_after_sync,
            &durable_parent_after_sync,
        )
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ISO persistence path changed while its namespace was being synchronized",
        ));
    }
    Ok(())
}
fn context_value(context: &IsoMessageContext) -> JsonValue {
    let mut map = norito::json::Map::new();
    map.insert(
        "ledger_id".to_owned(),
        string_or_null(context.ledger_id.as_deref()),
    );
    map.insert(
        "source_account_id".to_owned(),
        string_or_null(context.source_account_id.as_deref()),
    );
    map.insert(
        "source_account_address".to_owned(),
        string_or_null(context.source_account_address.as_deref()),
    );
    map.insert(
        "target_account_id".to_owned(),
        string_or_null(context.target_account_id.as_deref()),
    );
    map.insert(
        "target_account_address".to_owned(),
        string_or_null(context.target_account_address.as_deref()),
    );
    map.insert(
        "asset_definition_id".to_owned(),
        string_or_null(context.asset_definition_id.as_deref()),
    );
    map.insert(
        "asset_id".to_owned(),
        string_or_null(context.asset_id.as_deref()),
    );
    map.insert(
        "settlement_amount".to_owned(),
        string_or_null(context.settlement_amount.as_deref()),
    );
    map.insert(
        "settlement_currency".to_owned(),
        string_or_null(context.settlement_currency.as_deref()),
    );
    map.insert(
        "settlement_date".to_owned(),
        string_or_null(context.settlement_date.as_deref()),
    );
    map.insert(
        "settlement_quantity".to_owned(),
        string_or_null(context.settlement_quantity.as_deref()),
    );
    map.insert(
        "settlement_movement_type".to_owned(),
        string_or_null(context.settlement_movement_type.as_deref()),
    );
    map.insert(
        "settlement_payment_type".to_owned(),
        string_or_null(context.settlement_payment_type.as_deref()),
    );
    map.insert(
        "security_instrument_id".to_owned(),
        string_or_null(context.security_instrument_id.as_deref()),
    );
    map.insert(
        "collateral_obligation_id".to_owned(),
        string_or_null(context.collateral_obligation_id.as_deref()),
    );
    map.insert(
        "collateral_original_amount".to_owned(),
        string_or_null(context.collateral_original_amount.as_deref()),
    );
    map.insert(
        "collateral_original_currency".to_owned(),
        string_or_null(context.collateral_original_currency.as_deref()),
    );
    map.insert(
        "collateral_original_instrument_id".to_owned(),
        string_or_null(context.collateral_original_instrument_id.as_deref()),
    );
    map.insert(
        "collateral_substitute_amount".to_owned(),
        string_or_null(context.collateral_substitute_amount.as_deref()),
    );
    map.insert(
        "collateral_substitute_currency".to_owned(),
        string_or_null(context.collateral_substitute_currency.as_deref()),
    );
    map.insert(
        "collateral_substitute_instrument_id".to_owned(),
        string_or_null(context.collateral_substitute_instrument_id.as_deref()),
    );
    map.insert(
        "collateral_effective_date".to_owned(),
        string_or_null(context.collateral_effective_date.as_deref()),
    );
    map.insert(
        "collateral_substitution_type".to_owned(),
        string_or_null(context.collateral_substitution_type.as_deref()),
    );
    map.insert(
        "collateral_haircut".to_owned(),
        string_or_null(context.collateral_haircut.as_deref()),
    );
    map.insert(
        "collateral_reason_code".to_owned(),
        string_or_null(context.collateral_reason_code.as_deref()),
    );
    map.insert(
        "plan_execution_order".to_owned(),
        string_or_null(context.plan_execution_order.as_deref()),
    );
    map.insert(
        "plan_atomicity".to_owned(),
        string_or_null(context.plan_atomicity.as_deref()),
    );
    JsonValue::Object(map)
}
fn context_from_value(value: &JsonValue) -> Option<IsoMessageContext> {
    let obj = value.as_object()?;
    if !json_object_has_exact_keys(obj, PERSISTED_CONTEXT_REQUIRED_KEYS) {
        return None;
    }
    Some(IsoMessageContext {
        ledger_id: required_nullable_string(obj, "ledger_id")?,
        source_account_id: required_nullable_string(obj, "source_account_id")?,
        source_account_address: required_nullable_string(obj, "source_account_address")?,
        target_account_id: required_nullable_string(obj, "target_account_id")?,
        target_account_address: required_nullable_string(obj, "target_account_address")?,
        asset_definition_id: required_nullable_string(obj, "asset_definition_id")?,
        asset_id: required_nullable_string(obj, "asset_id")?,
        settlement_amount: required_nullable_string(obj, "settlement_amount")?,
        settlement_currency: required_nullable_string(obj, "settlement_currency")?,
        settlement_date: required_nullable_string(obj, "settlement_date")?,
        settlement_quantity: required_nullable_string(obj, "settlement_quantity")?,
        settlement_movement_type: required_nullable_string(obj, "settlement_movement_type")?,
        settlement_payment_type: required_nullable_string(obj, "settlement_payment_type")?,
        security_instrument_id: required_nullable_string(obj, "security_instrument_id")?,
        collateral_obligation_id: required_nullable_string(obj, "collateral_obligation_id")?,
        collateral_original_amount: required_nullable_string(obj, "collateral_original_amount")?,
        collateral_original_currency: required_nullable_string(
            obj,
            "collateral_original_currency",
        )?,
        collateral_original_instrument_id: required_nullable_string(
            obj,
            "collateral_original_instrument_id",
        )?,
        collateral_substitute_amount: required_nullable_string(
            obj,
            "collateral_substitute_amount",
        )?,
        collateral_substitute_currency: required_nullable_string(
            obj,
            "collateral_substitute_currency",
        )?,
        collateral_substitute_instrument_id: required_nullable_string(
            obj,
            "collateral_substitute_instrument_id",
        )?,
        collateral_effective_date: required_nullable_string(obj, "collateral_effective_date")?,
        collateral_substitution_type: required_nullable_string(
            obj,
            "collateral_substitution_type",
        )?,
        collateral_haircut: required_nullable_string(obj, "collateral_haircut")?,
        collateral_reason_code: required_nullable_string(obj, "collateral_reason_code")?,
        plan_execution_order: required_nullable_string(obj, "plan_execution_order")?,
        plan_atomicity: required_nullable_string(obj, "plan_atomicity")?,
    })
}
fn metadata_value(metadata: &IsoMessageMetadata) -> JsonValue {
    let mut map = norito::json::Map::new();
    map.insert(
        "profile_id".to_owned(),
        string_or_null(metadata.profile_id.as_deref()),
    );
    map.insert(
        "message_type".to_owned(),
        string_or_null(metadata.message_type.as_deref()),
    );
    map.insert(
        "business_service".to_owned(),
        string_or_null(metadata.business_service.as_deref()),
    );
    map.insert(
        "business_message_id".to_owned(),
        string_or_null(metadata.business_message_id.as_deref()),
    );
    map.insert("uetr".to_owned(), string_or_null(metadata.uetr.as_deref()));
    map.insert(
        "payload_hash".to_owned(),
        string_or_null(metadata.payload_hash.as_deref()),
    );
    map.insert(
        "reference_snapshot_id".to_owned(),
        string_or_null(metadata.reference_snapshot_id.as_deref()),
    );
    map.insert(
        "embedded_signature_detected".to_owned(),
        JsonValue::from(metadata.embedded_signature_detected),
    );
    JsonValue::Object(map)
}
fn metadata_from_value(value: &JsonValue) -> Option<IsoMessageMetadata> {
    let obj = value.as_object()?;
    if !json_object_has_exact_keys(obj, PERSISTED_METADATA_REQUIRED_KEYS) {
        return None;
    }
    Some(IsoMessageMetadata {
        profile_id: required_nullable_string(obj, "profile_id")?,
        message_type: required_nullable_string(obj, "message_type")?,
        business_service: required_nullable_string(obj, "business_service")?,
        business_message_id: required_nullable_string(obj, "business_message_id")?,
        uetr: required_nullable_string(obj, "uetr")?,
        payload_hash: required_nullable_string(obj, "payload_hash")?,
        reference_snapshot_id: required_nullable_string(obj, "reference_snapshot_id")?,
        embedded_signature_detected: obj.get("embedded_signature_detected")?.as_bool()?,
    })
}
fn parties_value(parties: &IsoRecordParties) -> JsonValue {
    let mut map = norito::json::Map::new();
    map.insert(
        "originator_participant_id".to_owned(),
        JsonValue::from(parties.originator_participant_id.as_str()),
    );
    map.insert(
        "counterparty_participant_id".to_owned(),
        JsonValue::from(parties.counterparty_participant_id.as_str()),
    );
    map.insert(
        "admitting_participant_id".to_owned(),
        JsonValue::from(parties.admitting_participant_id.as_str()),
    );
    map.insert(
        "admitting_operator_key".to_owned(),
        JsonValue::from(parties.admitting_operator_key.as_str()),
    );
    map.insert(
        "originator_financial_id".to_owned(),
        JsonValue::from(parties.originator_financial_id.as_str()),
    );
    map.insert(
        "counterparty_financial_id".to_owned(),
        JsonValue::from(parties.counterparty_financial_id.as_str()),
    );
    map.insert(
        "pinned_profile_id".to_owned(),
        JsonValue::from(parties.pinned_profile_id.as_str()),
    );
    map.insert(
        "pinned_signature_policy".to_owned(),
        JsonValue::from(parties.pinned_signature_policy.as_str()),
    );
    map.insert(
        "pinned_profile_policy_sha256".to_owned(),
        JsonValue::from(parties.pinned_profile_policy_sha256.as_str()),
    );
    JsonValue::Object(map)
}
fn parties_from_value(value: &JsonValue) -> Option<IsoRecordParties> {
    let obj = value.as_object()?;
    if !json_object_has_exact_keys(obj, PERSISTED_PARTIES_REQUIRED_KEYS) {
        return None;
    }
    let pinned_signature_policy = required_clean_string(obj, "pinned_signature_policy")?;
    if !matches!(
        pinned_signature_policy.as_str(),
        "record_only" | "reject_unsupported" | "require_verified"
    ) {
        return None;
    }
    let pinned_profile_policy_sha256 = required_clean_string(obj, "pinned_profile_policy_sha256")?;
    if !is_canonical_sha256_hex(&pinned_profile_policy_sha256) {
        return None;
    }
    Some(IsoRecordParties {
        originator_participant_id: required_clean_string(obj, "originator_participant_id")?,
        counterparty_participant_id: required_clean_string(obj, "counterparty_participant_id")?,
        admitting_participant_id: required_clean_string(obj, "admitting_participant_id")?,
        admitting_operator_key: required_clean_string(obj, "admitting_operator_key")?,
        originator_financial_id: required_clean_string(obj, "originator_financial_id")?,
        counterparty_financial_id: required_clean_string(obj, "counterparty_financial_id")?,
        pinned_profile_id: required_clean_string(obj, "pinned_profile_id")?,
        pinned_signature_policy,
        pinned_profile_policy_sha256,
    })
}
fn history_value(entry: &IsoStatusHistoryEntry) -> JsonValue {
    let mut map = norito::json::Map::new();
    map.insert("status".to_owned(), JsonValue::from(entry.status_label()));
    map.insert(
        "pacs002_code".to_owned(),
        JsonValue::from(entry.pacs002_code()),
    );
    map.insert(
        "updated_at_ms".to_owned(),
        JsonValue::from(system_time_to_ms(entry.updated_at())),
    );
    map.insert("detail".to_owned(), string_or_null(entry.detail()));
    map.insert(
        "reason_code".to_owned(),
        string_or_null(entry.reason_code()),
    );
    JsonValue::Object(map)
}
fn status_history_encoded_len(entries: &[IsoStatusHistoryEntry]) -> Option<usize> {
    entries
        .iter()
        .enumerate()
        .try_fold(2usize, |encoded_bytes, (index, entry)| {
            let separator_bytes = usize::from(index != 0);
            encoded_bytes
                .checked_add(separator_bytes)
                .and_then(|bytes| {
                    status_history_entry_encoded_len(
                        entry.status,
                        entry.pacs002_code,
                        entry.updated_at,
                        entry.detail.as_deref(),
                        entry.reason_code.as_deref(),
                    )
                    .and_then(|entry_bytes| bytes.checked_add(entry_bytes))
                })
        })
}
fn change_reason_codes_encoded_len(codes: &[String]) -> Option<usize> {
    codes
        .iter()
        .enumerate()
        .try_fold(2usize, |encoded_bytes, (index, code)| {
            encoded_bytes
                .checked_add(usize::from(index != 0))
                .and_then(|bytes| {
                    json_string_encoded_len(code)
                        .and_then(|code_bytes| bytes.checked_add(code_bytes))
                })
        })
}
fn status_history_entry_encoded_len(
    status: IsoMessageState,
    pacs002_code: Pacs002Status,
    updated_at: SystemTime,
    detail: Option<&str>,
    reason_code: Option<&str>,
) -> Option<usize> {
    let fields = [
        ("status", Some(json_string_encoded_len(status.label())?)),
        (
            "pacs002_code",
            Some(json_string_encoded_len(pacs002_code.code())?),
        ),
        (
            "updated_at_ms",
            Some(unsigned_decimal_encoded_len(system_time_to_ms(updated_at))),
        ),
        ("detail", nullable_json_string_encoded_len(detail)),
        ("reason_code", nullable_json_string_encoded_len(reason_code)),
    ];
    fields
        .into_iter()
        .enumerate()
        .try_fold(2usize, |encoded_bytes, (index, (key, value_len))| {
            encoded_bytes
                .checked_add(usize::from(index != 0))
                .and_then(|bytes| bytes.checked_add(json_string_encoded_len(key)?))
                .and_then(|bytes| bytes.checked_add(1))
                .and_then(|bytes| bytes.checked_add(value_len?))
        })
}
fn nullable_json_string_encoded_len(value: Option<&str>) -> Option<usize> {
    value.map_or(Some(4), json_string_encoded_len)
}
fn json_string_encoded_len(value: &str) -> Option<usize> {
    value.chars().try_fold(2usize, |encoded_bytes, ch| {
        let char_bytes = match ch {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0C}' => 2,
            ch if (ch as u32) < 0x20 => 6,
            ch => ch.len_utf8(),
        };
        encoded_bytes.checked_add(char_bytes)
    })
}
fn unsigned_decimal_encoded_len(mut value: u64) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}
fn history_from_value(value: &JsonValue) -> Option<IsoStatusHistoryEntry> {
    let obj = value.as_object()?;
    if !json_object_has_exact_keys(obj, PERSISTED_HISTORY_REQUIRED_KEYS) {
        return None;
    }
    Some(IsoStatusHistoryEntry {
        status: state_from_label(obj.get("status")?.as_str()?)?,
        pacs002_code: pacs002_from_code(obj.get("pacs002_code")?.as_str()?)?,
        updated_at: obj
            .get("updated_at_ms")?
            .as_u64()
            .and_then(system_time_from_ms)?,
        detail: required_nullable_string(obj, "detail")?,
        reason_code: required_nullable_string(obj, "reason_code")?,
    })
}
fn string_or_null(value: Option<&str>) -> JsonValue {
    value.map_or(JsonValue::Null, JsonValue::from)
}
fn message_filename(message_id: &str) -> String {
    format!("{}.json", sha256_hex(message_id.as_bytes()))
}
fn lifecycle_journal_filename() -> String {
    message_filename(ISO_PERSISTED_LIFECYCLE_OPERATION_ID)
}
fn lifecycle_journal_path(store_dir: &Path) -> PathBuf {
    store_dir
        .join(ISO_PERSISTED_LIFECYCLE_OPERATION_DIR)
        .join(lifecycle_journal_filename())
}
fn system_time_to_ms(time: SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
fn system_time_from_ms(ms: u64) -> Option<SystemTime> {
    std::time::UNIX_EPOCH.checked_add(Duration::from_millis(ms))
}
fn state_from_label(value: &str) -> Option<IsoMessageState> {
    match value {
        "Pending" => Some(IsoMessageState::Pending),
        "Accepted" => Some(IsoMessageState::Accepted),
        "Rejected" => Some(IsoMessageState::Rejected),
        _ => None,
    }
}
fn pacs002_from_code(value: &str) -> Option<Pacs002Status> {
    match value {
        "ACTC" => Some(Pacs002Status::Actc),
        "ACSP" => Some(Pacs002Status::Acsp),
        "ACSC" => Some(Pacs002Status::Acsc),
        "ACWC" => Some(Pacs002Status::Acwc),
        "PDNG" => Some(Pacs002Status::Pdng),
        "RJCT" => Some(Pacs002Status::Rjct),
        _ => None,
    }
}
fn message_definition_id<'a>(parsed: &'a ParsedMessage, message_type: &'a str) -> Option<&'a str> {
    field_text_by_suffix(parsed, &["AppHdr/MsgDefIdr", "MsgDefIdr"]).or(Some(message_type))
}
fn app_header_business_message_id(parsed: &ParsedMessage) -> Option<&str> {
    field_text_by_suffix(parsed, &["AppHdr/BizMsgIdr", "BizMsgIdr"])
}
fn app_header_message_definition_id(parsed: &ParsedMessage) -> Option<&str> {
    field_text_by_suffix(parsed, &["AppHdr/MsgDefIdr", "MsgDefIdr"])
}
fn app_header_creation_date(parsed: &ParsedMessage) -> Option<&str> {
    field_text_by_suffix(
        parsed,
        &["AppHdr/CreDt", "CreDt", "AppHdr/CreDtTm", "CreDtTm"],
    )
}
#[derive(Clone, Copy)]
enum AppHeaderParty {
    From,
    To,
}
fn app_header_financial_identifier(
    parsed: &ParsedMessage,
    party: AppHeaderParty,
) -> Result<Option<String>, IsoAdmissionError> {
    let suffixes: &[&str] = match party {
        AppHeaderParty::From => &[
            "AppHdr/Fr/FIId/FinInstnId/BICFI",
            "AppHdr/Fr/FIId/FinInstnId/LEI",
            "AppHdr/Fr/FIId/FinInstnId/ClrSysMmbId/MmbId",
            "AppHdr/Fr/OrgId/Id/OrgId/Othr/Id",
        ],
        AppHeaderParty::To => &[
            "AppHdr/To/FIId/FinInstnId/BICFI",
            "AppHdr/To/FIId/FinInstnId/LEI",
            "AppHdr/To/FIId/FinInstnId/ClrSysMmbId/MmbId",
            "AppHdr/To/OrgId/Id/OrgId/Othr/Id",
        ],
    };
    let mut identifiers = BTreeSet::new();
    for (field, value) in parsed.iter() {
        if !suffixes
            .iter()
            .any(|suffix| field_matches_suffix(field, suffix))
        {
            continue;
        }
        let value = core::str::from_utf8(value)
            .ok()
            .and_then(normalise_financial_identifier)
            .ok_or(IsoAdmissionError::NotAuthorized)?;
        identifiers.insert(value);
    }
    if identifiers.len() > 1 {
        return Err(IsoAdmissionError::NotAuthorized);
    }
    Ok(identifiers.into_iter().next())
}
const fn signature_policy_label(policy: EmbeddedSignaturePolicy) -> &'static str {
    match policy {
        EmbeddedSignaturePolicy::RecordOnly => "record_only",
        EmbeddedSignaturePolicy::RejectUnsupported => "reject_unsupported",
        EmbeddedSignaturePolicy::RequireVerified => "require_verified",
    }
}
fn profile_policy_sha256(profile: &TradfiRailProfile) -> String {
    persisted_record_digest(&canonical_profile_policy_value(profile))
}
fn canonical_profile_policy_value(profile: &TradfiRailProfile) -> JsonValue {
    let mut root = norito::json::Map::new();
    root.insert(
        "schema".to_owned(),
        JsonValue::from("iroha.iso20022.profile-policy.v1"),
    );
    root.insert("id".to_owned(), JsonValue::from(profile.id.as_str()));
    root.insert("rail".to_owned(), JsonValue::from(profile.rail.as_str()));
    root.insert(
        "embedded_signature_policy".to_owned(),
        JsonValue::from(profile.embedded_signature_policy.as_str()),
    );
    root.insert(
        "signature_public_key_sha256_pins".to_owned(),
        canonical_policy_string_array(&profile.signature_public_key_sha256_pins, false),
    );
    root.insert(
        "x509_trust_anchor_sha256_pins".to_owned(),
        canonical_policy_string_array(&profile.x509_trust_anchor_sha256_pins, false),
    );
    root.insert(
        "x509_required_certificate_policy_oids".to_owned(),
        canonical_policy_string_array(&profile.x509_required_certificate_policy_oids, false),
    );
    root.insert(
        "x509_require_crl_revocation_check".to_owned(),
        JsonValue::from(profile.x509_require_crl_revocation_check),
    );
    root.insert(
        "x509_crl_der_base64".to_owned(),
        canonical_policy_string_array(&profile.x509_crl_der_base64, false),
    );
    root.insert(
        "x509_require_ocsp_revocation_check".to_owned(),
        JsonValue::from(profile.x509_require_ocsp_revocation_check),
    );
    root.insert(
        "x509_ocsp_response_der_base64".to_owned(),
        canonical_policy_string_array(&profile.x509_ocsp_response_der_base64, false),
    );
    root.insert(
        "revoked_certificate_sha256".to_owned(),
        canonical_policy_string_array(&profile.revoked_certificate_sha256, false),
    );
    let mut required_reference_datasets = profile
        .required_reference_datasets
        .iter()
        .map(|requirement| requirement.as_str())
        .collect::<Vec<_>>();
    required_reference_datasets.sort_unstable();
    root.insert(
        "required_reference_datasets".to_owned(),
        JsonValue::Array(
            required_reference_datasets
                .into_iter()
                .map(JsonValue::from)
                .collect(),
        ),
    );
    let mut message_profiles = profile
        .message_profiles
        .iter()
        .map(|message_profile| {
            (
                format!(
                    "{}\u{0}{}",
                    message_profile.message_type.to_ascii_lowercase(),
                    message_profile.direction.as_str()
                ),
                canonical_message_profile_policy_value(message_profile),
            )
        })
        .collect::<Vec<_>>();
    message_profiles.sort_by(|left, right| left.0.cmp(&right.0));
    root.insert(
        "message_profiles".to_owned(),
        JsonValue::Array(
            message_profiles
                .into_iter()
                .map(|(_, value)| value)
                .collect(),
        ),
    );
    JsonValue::Object(root)
}
fn canonical_message_profile_policy_value(profile: &MessageProfile) -> JsonValue {
    let mut value = norito::json::Map::new();
    value.insert(
        "message_type".to_owned(),
        JsonValue::from(profile.message_type.to_ascii_lowercase()),
    );
    value.insert(
        "direction".to_owned(),
        JsonValue::from(profile.direction.as_str()),
    );
    value.insert(
        "versions".to_owned(),
        canonical_policy_string_array(&profile.versions, true),
    );
    value.insert(
        "business_services".to_owned(),
        canonical_policy_string_array(&profile.business_services, true),
    );
    value.insert(
        "require_app_header".to_owned(),
        JsonValue::from(profile.require_app_header),
    );
    value.insert(
        "require_business_service".to_owned(),
        JsonValue::from(profile.require_business_service),
    );
    value.insert(
        "require_uetr".to_owned(),
        JsonValue::from(profile.require_uetr),
    );
    value.insert(
        "structured_address_mode".to_owned(),
        JsonValue::from(profile.structured_address_mode.as_str()),
    );
    value.insert(
        "supplementary_data_max_bytes".to_owned(),
        JsonValue::from(u64::try_from(profile.supplementary_data_max_bytes).unwrap_or(u64::MAX)),
    );
    value.insert(
        "amount_minor_units".to_owned(),
        JsonValue::Array(
            profile
                .amount_minor_units
                .iter()
                .map(|(currency, minor_units)| {
                    let mut entry = norito::json::Map::new();
                    entry.insert("currency".to_owned(), JsonValue::from(currency.as_str()));
                    entry.insert(
                        "minor_units".to_owned(),
                        JsonValue::from(u64::from(*minor_units)),
                    );
                    JsonValue::Object(entry)
                })
                .collect(),
        ),
    );
    JsonValue::Object(value)
}
fn canonical_policy_string_array(values: &[String], lowercase: bool) -> JsonValue {
    let mut values = values
        .iter()
        .map(|value| {
            if lowercase {
                value.to_ascii_lowercase()
            } else {
                value.clone()
            }
        })
        .collect::<Vec<_>>();
    values.sort();
    JsonValue::Array(values.into_iter().map(JsonValue::from).collect())
}
fn is_canonical_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
}
fn business_service(parsed: &ParsedMessage) -> Option<&str> {
    field_text_by_suffix(parsed, &["AppHdr/BizSvc", "BizSvc"])
}
fn business_message_id(parsed: &ParsedMessage) -> Option<&str> {
    field_text_by_suffix(parsed, &["AppHdr/BizMsgIdr", "BizMsgIdr"])
        .or_else(|| parsed.field_text("MsgId"))
}
fn uetr(parsed: &ParsedMessage) -> Option<&str> {
    field_text_by_suffix(parsed, &["UETR"]).filter(|value| !value.trim().is_empty())
}
fn lifecycle_referenced_message_id<'a>(
    message_type: &str,
    parsed: &'a ParsedMessage,
) -> Result<Option<&'a str>, MsgError> {
    match message_type {
        "pacs.002" => unique_field_text_by_suffix(parsed, &["OrgnlMsgId"], "OrgnlMsgId"),
        "pacs.004" | "camt.056" => {
            unique_field_text_by_suffix(parsed, &["OrgnlGrpInf/OrgnlMsgId"], "OrgnlMsgId")
        }
        "sese.024" | "sese.025" => unique_field_text_by_suffix(parsed, &["TxId"], "TxId"),
        "sese.023" => Ok(None),
        "colr.012" => Ok(None),
        _ => Ok(None),
    }
}
fn canonical_lifecycle_referenced_message_id(
    message_type: &str,
    parsed: &ParsedMessage,
) -> Result<Option<String>, MsgError> {
    Ok(
        lifecycle_referenced_message_id(message_type, parsed)?.map(|id| {
            if matches!(message_type, "sese.024" | "sese.025") {
                format!("sese.023:{id}")
            } else {
                id.to_owned()
            }
        }),
    )
}
fn lifecycle_status_code<'a>(message_type: &str, parsed: &'a ParsedMessage) -> Option<&'a str> {
    match message_type {
        "pacs.002" => parsed.field_text("TxSts"),
        "pacs.004" => Some("RJCT"),
        "camt.056" => Some("PDNG"),
        "sese.024" => field_text_by_suffix(
            parsed,
            &[
                "SttlmSts",
                "TxSts",
                "SttlmTxSts/Sts/Cd",
                "SttlmTxSts/Sts/Prtry",
            ],
        ),
        "sese.025" => parsed.field_text("ConfSts"),
        "sese.023" => Some("ACTC"),
        "colr.012" => Some("ACSC"),
        _ => None,
    }
    .filter(|value| !value.trim().is_empty())
}
fn is_settlement_status_code(code: &str) -> bool {
    matches!(
        code.trim().to_ascii_uppercase().as_str(),
        "ACSC" | "ACCP" | "SETT" | "SETTLED"
    )
}
fn lifecycle_reason_code(parsed: &ParsedMessage) -> Option<&str> {
    field_text_by_suffix(
        parsed,
        &[
            "RsnCd",
            "RtrdRsn/Cd",
            "RtrdRsn/Prtry",
            "CxlRsnInf/Rsn/Cd",
            "CxlRsnInf/Rsn/Prtry",
            "StsRsnInf/Rsn/Cd",
            "StsRsnInf/Rsn/Prtry",
            "Substitution/ReasonCd",
        ],
    )
    .filter(|value| !value.trim().is_empty())
}
fn lifecycle_detail(
    message_type: &str,
    parsed: &ParsedMessage,
    status_code: Option<&str>,
) -> Option<String> {
    field_text_by_suffix(parsed, &["AddtlInf", "AddtlInf[*]", "CxlRsnInf/AddtlInf"])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| match (message_type, status_code) {
            ("pacs.004", _) => Some("payment returned by inbound pacs.004".to_owned()),
            (_, Some(code)) => Some(format!("ISO 20022 lifecycle status {code}")),
            _ => None,
        })
}
fn lifecycle_update_matches_original(lifecycle_type: &str, original_type: Option<&str>) -> bool {
    let Some(original_type) = original_type
        .map(str::trim)
        .filter(|message_type| !message_type.is_empty())
    else {
        return false;
    };
    match lifecycle_type {
        "pacs.002" | "pacs.004" | "camt.056" => {
            is_iso_family(original_type, "pacs.008") || is_iso_family(original_type, "pacs.009")
        }
        "sese.024" | "sese.025" => is_iso_family(original_type, "sese.023"),
        "colr.012" => false,
        _ => false,
    }
}
fn is_iso_family(message_type: &str, family: &str) -> bool {
    let message_type = message_type.trim();
    message_type == family
        || message_type
            .strip_prefix(family)
            .is_some_and(|suffix| suffix.starts_with('.'))
}
fn lifecycle_context(message_type: &str, parsed: &ParsedMessage) -> Option<IsoMessageContext> {
    let mut context = IsoMessageContext::default();
    match message_type {
        "sese.023" => {
            context.settlement_date = parsed_text(parsed, "SttlmDt");
            context.settlement_movement_type =
                parsed_text(parsed, "SttlmTpAndAddtlParams/SctiesMvmntTp");
            context.settlement_payment_type = parsed_text(parsed, "SttlmTpAndAddtlParams/Pmt");
            context.settlement_quantity = parsed_text(parsed, "SctiesLeg/Qty");
            context.security_instrument_id = parsed_text(parsed, "SctiesLeg/FinInstrmId");
            context.settlement_amount = parsed_text(parsed, "CashLeg/Amt");
            context.settlement_currency = parsed_text(parsed, "CashLeg/Ccy");
            context.plan_execution_order = parsed_text(parsed, "Plan/ExecutionOrder");
            context.plan_atomicity = parsed_text(parsed, "Plan/Atomicity");
        }
        "sese.025" => {
            context.settlement_date = parsed_text(parsed, "SttlmDt");
            context.settlement_movement_type =
                parsed_text(parsed, "SttlmTpAndAddtlParams/SctiesMvmntTp");
            context.settlement_payment_type = parsed_text(parsed, "SttlmTpAndAddtlParams/Pmt");
            context.settlement_quantity = parsed_text(parsed, "SttlmQty");
            context.security_instrument_id = parsed_text(parsed, "SctiesLeg/FinInstrmId");
            context.settlement_amount = parsed_text(parsed, "SttlmAmt");
            context.settlement_currency = parsed_text(parsed, "SttlmCcy");
            context.plan_execution_order = parsed_text(parsed, "Plan/ExecutionOrder");
            context.plan_atomicity = parsed_text(parsed, "Plan/Atomicity");
        }
        "colr.012" => {
            context.collateral_obligation_id = parsed_text(parsed, "OblgtnId");
            context.collateral_original_amount = parsed_text(parsed, "Substitution/OriginalAmt");
            context.collateral_original_currency = parsed_text(parsed, "Substitution/OriginalCcy");
            context.collateral_original_instrument_id =
                parsed_text(parsed, "Substitution/OriginalFinInstrmId");
            context.collateral_substitute_amount =
                parsed_text(parsed, "Substitution/SubstituteAmt");
            context.collateral_substitute_currency =
                parsed_text(parsed, "Substitution/SubstituteCcy");
            context.collateral_substitute_instrument_id =
                parsed_text(parsed, "Substitution/SubstituteFinInstrmId");
            context.collateral_effective_date = parsed_text(parsed, "Substitution/EffectiveDt");
            context.collateral_substitution_type = parsed_text(parsed, "Substitution/Type");
            context.collateral_haircut = parsed_text(parsed, "Substitution/Haircut");
            context.collateral_reason_code = parsed_text(parsed, "Substitution/ReasonCd");
        }
        _ => return None,
    }
    [
        context.settlement_date.as_deref(),
        context.settlement_movement_type.as_deref(),
        context.settlement_payment_type.as_deref(),
        context.settlement_quantity.as_deref(),
        context.security_instrument_id.as_deref(),
        context.settlement_amount.as_deref(),
        context.settlement_currency.as_deref(),
        context.collateral_obligation_id.as_deref(),
        context.collateral_original_amount.as_deref(),
        context.collateral_original_currency.as_deref(),
        context.collateral_original_instrument_id.as_deref(),
        context.collateral_substitute_amount.as_deref(),
        context.collateral_substitute_currency.as_deref(),
        context.collateral_substitute_instrument_id.as_deref(),
        context.collateral_effective_date.as_deref(),
        context.collateral_substitution_type.as_deref(),
        context.collateral_haircut.as_deref(),
        context.collateral_reason_code.as_deref(),
        context.plan_execution_order.as_deref(),
        context.plan_atomicity.as_deref(),
    ]
    .iter()
    .any(|value| value.is_some())
    .then_some(context)
}
fn parsed_text(parsed: &ParsedMessage, field: &str) -> Option<String> {
    parsed
        .field_text(field)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
fn is_instrument_reference_field(field: &str) -> bool {
    matches!(
        field,
        "SctiesLeg/FinInstrmId"
            | "Substitution/OriginalFinInstrmId"
            | "Substitution/SubstituteFinInstrmId"
    ) || field.ends_with("/SctiesLeg/FinInstrmId")
        || field.ends_with("/Substitution/OriginalFinInstrmId")
        || field.ends_with("/Substitution/SubstituteFinInstrmId")
}
fn is_settlement_venue_field(field: &str) -> bool {
    field == "PlcOfSttlm/MktId" || field.ends_with("/PlcOfSttlm/MktId")
}
fn is_settlement_party_bic_field(field: &str) -> bool {
    matches!(field, "DlvrgSttlmPties/Pty/Bic" | "RcvgSttlmPties/Pty/Bic")
        || field.ends_with("/DlvrgSttlmPties/Pty/Bic")
        || field.ends_with("/RcvgSttlmPties/Pty/Bic")
}
fn field_text_by_suffix<'a>(parsed: &'a ParsedMessage, suffixes: &[&str]) -> Option<&'a str> {
    suffixes.iter().find_map(|suffix| {
        parsed.field_text(suffix).or_else(|| {
            parsed.iter().find_map(|(field, value)| {
                field_matches_suffix(field, suffix)
                    .then(|| core::str::from_utf8(value).ok())
                    .flatten()
            })
        })
    })
}
fn unique_field_text_by_suffix<'a>(
    parsed: &'a ParsedMessage,
    suffixes: &[&str],
    field_name: &str,
) -> Result<Option<&'a str>, MsgError> {
    let mut selected = None;
    for (field, value) in parsed.iter() {
        if !suffixes
            .iter()
            .any(|suffix| field_matches_suffix(field, suffix))
        {
            continue;
        }
        let text = core::str::from_utf8(value).map_err(|_| MsgError::InvalidValue {
            field: field_name.to_owned(),
            kind: InvalidValueKind::Utf8,
        })?;
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        if let Some(previous) = selected {
            if previous != text {
                return Err(MsgError::ValidationFailed);
            }
        } else {
            selected = Some(text);
        }
    }
    Ok(selected)
}
fn field_matches_suffix(field: &str, suffix: &str) -> bool {
    field == suffix
        || field
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('/'))
}
fn is_unstructured_postal_address_field(field: &str) -> bool {
    matches!(field, "AdrLine" | "PstlAdr/AdrLine")
        || field.starts_with("AdrLine[")
        || field.ends_with("/AdrLine")
        || field.contains("/AdrLine[")
}
fn has_embedded_signature_marker(parsed: &ParsedMessage) -> bool {
    parsed.iter().any(|(field, _)| {
        field.contains("Sgntr")
            || field.contains("Signature")
            || field.ends_with("/@ignored")
            || field.contains("SignedInfo")
            || field.contains("QualifyingProperties")
    })
}
#[derive(Debug, Clone, Copy)]
struct XmlElementSpan {
    start: usize,
    opening_end: usize,
    content_start: usize,
    content_end: usize,
    end: usize,
}
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";
const XMLDSIG_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const XMLDSIG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const XMLDSIG_ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
const XADES_SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
const XML_C14N_1_0: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const XML_C14N_1_1: &str = "http://www.w3.org/2006/12/xml-c14n11";
const XML_EXCLUSIVE_C14N_1_0: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const XMLDSIG_P256_NAMED_CURVE: &str = "urn:oid:1.2.840.10045.3.1.7";
const P256_XMLDSIG_SIGNATURE_LEN: usize = 64;
const P256_UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN: usize = 65;
const X509_EKU_DOCUMENT_SIGNING_OID: &str = "1.3.6.1.5.5.7.3.36";
const X509_ANY_POLICY_OID: &str = "2.5.29.32.0";
const XMLDSIG_MAX_X509_CERTIFICATES: usize = 8;
const XML_SIGNATURE_MAX_X509_CERTIFICATES: usize = XMLDSIG_MAX_X509_CERTIFICATES;
const XMLDSIG_MAX_X509_CRLS: usize = 8;
const XMLDSIG_MAX_X509_CRL_BYTES: usize = 1024 * 1024;
const XMLDSIG_MAX_X509_OCSP_RESPONSES: usize = 8;
const XMLDSIG_MAX_X509_OCSP_RESPONSE_BYTES: usize = 1024 * 1024;
const OID_ECDSA_WITH_SHA256_DER: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_OCSP_BASIC_RESPONSE_DER: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
const OID_SHA256_DER: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
fn payload_has_embedded_signature(payload: &[u8]) -> bool {
    std::str::from_utf8(payload).is_ok_and(|text| {
        find_first_xml_element(text, "Signature").is_some()
            || find_first_xml_element(text, "Sgntr").is_some()
    })
}
fn verify_embedded_xml_signature(
    payload: &[u8],
    profile: &TradfiRailProfile,
    parsed: &ParsedMessage,
) -> Result<bool, MsgError> {
    let text = std::str::from_utf8(payload).map_err(|_| MsgError::InvalidFormat)?;
    let Some(signature_carrier) = xml_signature_carrier(text)? else {
        return Ok(false);
    };
    let signature_span = signature_carrier.signature_span;
    if !profile.has_xml_signature_trust_anchors() {
        return Err(MsgError::ValidationFailed);
    }
    let signature_xml = &text[signature_span.start..signature_span.end];
    let signature_children = xml_signature_direct_child_spans_with_namespaces(
        signature_xml,
        &signature_carrier.inherited_namespaces,
    )?;
    let signature_root_span = required_single_xml_element(signature_xml, "Signature")?;
    let signature_namespaces = xml_element_namespace_scope(
        signature_xml,
        signature_root_span,
        &signature_carrier.inherited_namespaces,
    )?;
    let signed_info_xml =
        &signature_xml[signature_children.signed_info.start..signature_children.signed_info.end];
    let signed_info_root_span = required_single_xml_element(signed_info_xml, "SignedInfo")?;
    let signed_info_namespaces = xml_element_namespace_scope(
        signed_info_xml,
        signed_info_root_span,
        &signature_namespaces,
    )?;
    let signed_info_children =
        xml_signed_info_direct_child_spans_with_namespaces(signed_info_xml, &signature_namespaces)?;
    let c14n_method_span = signed_info_children.canonicalization_method;
    ensure_xml_element_attributes_allowed(signed_info_xml, c14n_method_span, &["Algorithm"])?;
    ensure_xml_element_content_empty(signed_info_xml, c14n_method_span)?;
    let c14n_algorithm = element_attr(signed_info_xml, c14n_method_span, "Algorithm")
        .ok_or(MsgError::ValidationFailed)?;
    let c14n_mode = xml_canonicalization_mode(&c14n_algorithm)?;
    let signature_method_span = signed_info_children.signature_method;
    ensure_xml_element_attributes_allowed(signed_info_xml, signature_method_span, &["Algorithm"])?;
    ensure_xml_element_content_empty(signed_info_xml, signature_method_span)?;
    let signature_algorithm = element_attr(signed_info_xml, signature_method_span, "Algorithm")
        .ok_or(MsgError::ValidationFailed)?;
    if signature_algorithm != XMLDSIG_ECDSA_SHA256 {
        return Err(MsgError::ValidationFailed);
    }
    let inherited_namespaces = inherited_namespace_attributes_from_scope(&signature_namespaces);
    let canonical_signed_info =
        canonicalize_supported_xml_with_mode(signed_info_xml, &inherited_namespaces, c14n_mode)?;
    let reference_verification = verify_xml_signature_references(
        text,
        signature_span,
        signature_carrier.carrier_span,
        signature_xml,
        signed_info_xml,
        &signed_info_namespaces,
    )?;
    if !parsed.fields_are_covered_by_xml_range(
        payload,
        reference_verification.payload_span.start..reference_verification.payload_span.end,
    ) {
        return Err(MsgError::ValidationFailed);
    }
    let signature_value =
        decode_direct_child_base64(signature_xml, signature_children.signature_value)?;
    let evaluation_time = xml_signature_evaluation_time_for_verified_properties(
        parsed,
        reference_verification.signed_properties.as_ref(),
    )?;
    let key_info_xml =
        &signature_xml[signature_children.key_info.start..signature_children.key_info.end];
    let embedded_revocation =
        xml_signature_x509_revocation_values_with_namespaces(key_info_xml, &signature_namespaces)?;
    let key_material = xml_signature_key_material_for_profile_with_namespaces(
        key_info_xml,
        evaluation_time,
        &signature_namespaces,
        profile,
        &embedded_revocation.crls,
        &embedded_revocation.ocsp_responses,
    )?;
    if let Some(signed_properties) = reference_verification.signed_properties.as_ref() {
        verify_xades_signing_certificate_v2_binding_with_namespaces(
            signed_properties.xml,
            &signed_properties.inherited_namespaces,
            &key_material,
        )?;
    }
    if !profile.has_xml_signature_trust_anchors()
        || !profile.accepts_xml_signature_key(
            &sha256_hex(&key_material.public_key),
            &key_material.certificate_sha256,
        )
    {
        return Err(MsgError::ValidationFailed);
    }
    let verifying_key = parse_p256_verifying_key(&key_material.public_key)?;
    let signature = decode_p256_xmldsig_signature(&signature_value)?;
    if verifying_key
        .verify(canonical_signed_info.as_bytes(), &signature)
        .is_err()
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok(true)
}
#[derive(Debug)]
struct XmlSignatureCarrier {
    carrier_span: XmlElementSpan,
    signature_span: XmlElementSpan,
    inherited_namespaces: Vec<CanonicalXmlNamespaceBinding>,
}
fn xml_signature_carrier(text: &str) -> Result<Option<XmlSignatureCarrier>, MsgError> {
    let signature = find_first_xml_element(text, "Signature");
    let sgntr = find_first_xml_element(text, "Sgntr");
    match (signature, sgntr) {
        (None, None) => Ok(None),
        (Some(signature_span), None) => {
            ensure_no_xml_signature_carrier_outside_span(text, signature_span)?;
            let inherited_namespaces =
                xml_namespace_bindings_before_offset(text, signature_span.start)?;
            Ok(Some(XmlSignatureCarrier {
                carrier_span: signature_span,
                signature_span,
                inherited_namespaces,
            }))
        }
        (_, Some(sgntr_span)) => {
            ensure_xml_element_attributes_allowed(text, sgntr_span, &[])?;
            ensure_direct_xml_child_elements(text, sgntr_span, &["Signature"])?;
            let signature_span = required_direct_xml_child_element(text, sgntr_span, "Signature")?;
            ensure_no_xml_signature_carrier_outside_span(text, sgntr_span)?;
            if find_xml_element_outside_span(text, signature_span, "Signature") {
                return Err(MsgError::ValidationFailed);
            }
            let sgntr_inherited_namespaces =
                xml_namespace_bindings_before_offset(text, sgntr_span.start)?;
            let inherited_namespaces =
                xml_element_namespace_scope(text, sgntr_span, &sgntr_inherited_namespaces)?;
            Ok(Some(XmlSignatureCarrier {
                carrier_span: sgntr_span,
                signature_span,
                inherited_namespaces,
            }))
        }
    }
}
fn ensure_no_xml_signature_carrier_outside_span(
    text: &str,
    allowed_span: XmlElementSpan,
) -> Result<(), MsgError> {
    for carrier in ["Signature", "Sgntr"] {
        if find_xml_element_outside_span(text, allowed_span, carrier) {
            return Err(MsgError::ValidationFailed);
        }
    }
    Ok(())
}
fn decode_p256_xmldsig_signature(signature_value: &[u8]) -> Result<P256Signature, MsgError> {
    if !signature_value.is_empty() && signature_value.iter().all(|byte| *byte == 0) {
        return Err(MsgError::ValidationFailed);
    }
    let signature = if signature_value.len() == P256_XMLDSIG_SIGNATURE_LEN {
        P256Signature::from_slice(signature_value).map_err(|_| MsgError::ValidationFailed)
    } else {
        P256Signature::from_der(signature_value).map_err(|_| MsgError::ValidationFailed)
    }?;
    if signature.normalize_s().is_some() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(signature)
}
fn decode_p256_der_signature(signature_value: &[u8]) -> Result<P256Signature, MsgError> {
    if !signature_value.is_empty() && signature_value.iter().all(|byte| *byte == 0) {
        return Err(MsgError::ValidationFailed);
    }
    let signature =
        P256Signature::from_der(signature_value).map_err(|_| MsgError::ValidationFailed)?;
    if signature.normalize_s().is_some() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(signature)
}
fn parse_p256_verifying_key(public_key: &[u8]) -> Result<P256VerifyingKey, MsgError> {
    if p256_public_key_has_zero_coordinate_material(public_key) {
        return Err(MsgError::ValidationFailed);
    }
    P256VerifyingKey::from_sec1_bytes(public_key).map_err(|_| MsgError::ValidationFailed)
}
fn p256_public_key_has_zero_coordinate_material(public_key: &[u8]) -> bool {
    public_key.len() == P256_UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN
        && public_key.first().copied() == Some(0x04)
        && public_key[1..].iter().all(|byte| *byte == 0)
}
#[derive(Debug)]
struct XmlSignatureDirectChildSpans {
    signed_info: XmlElementSpan,
    signature_value: XmlElementSpan,
    key_info: XmlElementSpan,
}
#[cfg(test)]
fn xml_signature_direct_child_spans(
    signature_xml: &str,
) -> Result<XmlSignatureDirectChildSpans, MsgError> {
    xml_signature_direct_child_spans_with_namespaces(signature_xml, &[])
}
fn xml_signature_direct_child_spans_with_namespaces(
    signature_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<XmlSignatureDirectChildSpans, MsgError> {
    let signature_span = required_single_xml_element(signature_xml, "Signature")?;
    if signature_span.start != 0 || signature_span.end != signature_xml.len() {
        return Err(MsgError::ValidationFailed);
    }
    ensure_xml_element_prefixed_namespace(
        signature_xml,
        signature_span,
        inherited_namespaces,
        XMLDSIG_NS,
    )?;
    let signature_namespaces =
        xml_element_namespace_scope(signature_xml, signature_span, inherited_namespaces)?;
    ensure_xml_element_attributes_allowed(signature_xml, signature_span, &["Id"])?;
    ensure_direct_xml_child_elements(
        signature_xml,
        signature_span,
        &["SignedInfo", "SignatureValue", "KeyInfo", "Object"],
    )?;
    let signed_info =
        required_direct_xml_child_element(signature_xml, signature_span, "SignedInfo")?;
    let signature_value =
        required_direct_xml_child_element(signature_xml, signature_span, "SignatureValue")?;
    let key_info = required_direct_xml_child_element(signature_xml, signature_span, "KeyInfo")?;
    let object = optional_direct_xml_child_element(signature_xml, signature_span, "Object")?;
    for child_span in [signed_info, signature_value, key_info] {
        ensure_xml_element_prefixed_namespace(
            signature_xml,
            child_span,
            &signature_namespaces,
            XMLDSIG_NS,
        )?;
    }
    if let Some(object) = object {
        ensure_xml_element_prefixed_namespace(
            signature_xml,
            object,
            &signature_namespaces,
            XMLDSIG_NS,
        )?;
    }
    if !(signed_info.start < signature_value.start && signature_value.start < key_info.start)
        || object.is_some_and(|object| key_info.start > object.start)
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok(XmlSignatureDirectChildSpans {
        signed_info,
        signature_value,
        key_info,
    })
}
#[derive(Debug)]
struct XmlSignedInfoDirectChildSpans {
    canonicalization_method: XmlElementSpan,
    signature_method: XmlElementSpan,
}
fn xml_signed_info_direct_child_spans_with_namespaces(
    signed_info_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<XmlSignedInfoDirectChildSpans, MsgError> {
    let signed_info_span = required_single_xml_element(signed_info_xml, "SignedInfo")?;
    if signed_info_span.start != 0 || signed_info_span.end != signed_info_xml.len() {
        return Err(MsgError::ValidationFailed);
    }
    ensure_xml_element_prefixed_namespace(
        signed_info_xml,
        signed_info_span,
        inherited_namespaces,
        XMLDSIG_NS,
    )?;
    let signed_info_namespaces =
        xml_element_namespace_scope(signed_info_xml, signed_info_span, inherited_namespaces)?;
    ensure_direct_xml_child_elements_allowing_comments(
        signed_info_xml,
        signed_info_span,
        &["CanonicalizationMethod", "SignatureMethod", "Reference"],
    )?;
    let canonicalization_method = required_direct_xml_child_element_allowing_comments(
        signed_info_xml,
        signed_info_span,
        "CanonicalizationMethod",
    )?;
    let signature_method = required_direct_xml_child_element_allowing_comments(
        signed_info_xml,
        signed_info_span,
        "SignatureMethod",
    )?;
    ensure_xml_element_prefixed_namespace(
        signed_info_xml,
        canonicalization_method,
        &signed_info_namespaces,
        XMLDSIG_NS,
    )?;
    ensure_xml_element_prefixed_namespace(
        signed_info_xml,
        signature_method,
        &signed_info_namespaces,
        XMLDSIG_NS,
    )?;
    let first_reference =
        find_first_xml_element(signed_info_xml, "Reference").ok_or(MsgError::ValidationFailed)?;
    ensure_xml_element_prefixed_namespace(
        signed_info_xml,
        first_reference,
        &signed_info_namespaces,
        XMLDSIG_NS,
    )?;
    if !(canonicalization_method.start < signature_method.start
        && signature_method.start < first_reference.start)
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok(XmlSignedInfoDirectChildSpans {
        canonicalization_method,
        signature_method,
    })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CanonicalXmlMode {
    Inclusive,
    Exclusive,
}
fn xml_canonicalization_mode(algorithm: &str) -> Result<CanonicalXmlMode, MsgError> {
    match algorithm {
        XML_C14N_1_0 | XML_C14N_1_1 => Ok(CanonicalXmlMode::Inclusive),
        XML_EXCLUSIVE_C14N_1_0 => Ok(CanonicalXmlMode::Exclusive),
        _ => Err(MsgError::ValidationFailed),
    }
}
struct XmlSignatureReferenceVerification<'a> {
    signed_properties: Option<VerifiedSignedProperties<'a>>,
    payload_span: XmlElementSpan,
}
struct VerifiedSignedProperties<'a> {
    xml: &'a str,
    inherited_namespaces: Vec<CanonicalXmlNamespaceBinding>,
}
fn verify_xml_signature_references<'a>(
    full_xml: &str,
    signature_span: XmlElementSpan,
    carrier_span: XmlElementSpan,
    signature_xml: &'a str,
    signed_info_xml: &str,
    signed_info_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<XmlSignatureReferenceVerification<'a>, MsgError> {
    let mut unsigned = String::with_capacity(full_xml.len());
    unsigned.push_str(&full_xml[..signature_span.start]);
    unsigned.push_str(&full_xml[signature_span.end..]);
    if unsigned.as_str() != unsigned.trim() {
        return Err(MsgError::ValidationFailed);
    }
    let mut cursor = 0usize;
    let mut payload_reference_seen = false;
    let mut payload_span = None;
    let mut signed_properties = None;
    let mut reference_count = 0usize;
    while cursor < signed_info_xml.len() {
        let Some(span) = find_first_xml_element(&signed_info_xml[cursor..], "Reference") else {
            break;
        };
        let reference_span = XmlElementSpan {
            start: cursor + span.start,
            opening_end: cursor + span.opening_end,
            content_start: cursor + span.content_start,
            content_end: cursor + span.content_end,
            end: cursor + span.end,
        };
        reference_count += 1;
        ensure_xml_element_prefixed_namespace(
            signed_info_xml,
            reference_span,
            signed_info_namespaces,
            XMLDSIG_NS,
        )?;
        let reference_xml = &signed_info_xml[reference_span.start..reference_span.end];
        let uri = element_attr(signed_info_xml, reference_span, "URI").unwrap_or_default();
        match element_attr(signed_info_xml, reference_span, "Type").as_deref() {
            None => {
                if payload_reference_seen {
                    return Err(MsgError::ValidationFailed);
                }
                payload_reference_seen = true;
                payload_span = Some(verify_xml_signature_payload_reference(
                    full_xml,
                    &unsigned,
                    carrier_span,
                    reference_xml,
                    &uri,
                    signed_info_namespaces,
                )?);
            }
            Some(XADES_SIGNED_PROPERTIES_TYPE) => {
                if signed_properties.is_some() {
                    return Err(MsgError::ValidationFailed);
                }
                signed_properties = Some(verify_xml_signature_signed_properties_reference(
                    signature_xml,
                    reference_xml,
                    &uri,
                    signed_info_namespaces,
                )?);
            }
            Some(_) => return Err(MsgError::ValidationFailed),
        }
        cursor = reference_span.end;
    }
    if reference_count == 0 || !payload_reference_seen {
        return Err(MsgError::ValidationFailed);
    }
    ensure_xades_signed_properties_reference_coverage(
        signature_xml,
        signed_properties.as_ref().map(|properties| properties.xml),
    )?;
    if signed_properties.is_some() {
        ensure_xades_qualifying_properties_target(signature_xml)?;
    }
    Ok(XmlSignatureReferenceVerification {
        signed_properties,
        payload_span: payload_span.ok_or(MsgError::ValidationFailed)?,
    })
}
fn verify_xml_signature_payload_reference(
    full_xml: &str,
    unsigned_xml: &str,
    carrier_span: XmlElementSpan,
    reference_xml: &str,
    uri: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<XmlElementSpan, MsgError> {
    let c14n_mode = supported_xml_signature_reference_c14n_mode_with_namespaces(
        reference_xml,
        inherited_namespaces,
    )?;
    let payload_span =
        ensure_xml_signature_payload_reference_covers_carrier(full_xml, uri, carrier_span)?;
    let referenced_xml = xml_signature_reference_target(unsigned_xml, uri)?;
    let canonical_referenced_xml = canonicalize_supported_xml_with_mode(
        referenced_xml.xml,
        &referenced_xml.inherited_namespaces,
        c14n_mode,
    )?;
    verify_xml_signature_reference_digest_with_namespaces(
        reference_xml,
        &canonical_referenced_xml,
        inherited_namespaces,
    )?;
    Ok(payload_span)
}
fn ensure_xml_signature_payload_reference_covers_carrier(
    full_xml: &str,
    uri: &str,
    carrier_span: XmlElementSpan,
) -> Result<XmlElementSpan, MsgError> {
    if uri.is_empty() {
        return Ok(XmlElementSpan {
            start: 0,
            opening_end: 0,
            content_start: 0,
            content_end: full_xml.len(),
            end: full_xml.len(),
        });
    }
    let reference_id = uri
        .strip_prefix('#')
        .filter(|reference_id| !reference_id.is_empty())
        .ok_or(MsgError::ValidationFailed)?;
    ensure_supported_same_document_reference_id(reference_id)?;
    let target = find_xml_element_by_reference_id(full_xml, reference_id)?;
    if target.span.start < carrier_span.start && carrier_span.end < target.span.end {
        Ok(target.span)
    } else {
        Err(MsgError::ValidationFailed)
    }
}
fn verify_xml_signature_signed_properties_reference<'a>(
    signature_xml: &'a str,
    reference_xml: &str,
    uri: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<VerifiedSignedProperties<'a>, MsgError> {
    let c14n_mode =
        signed_properties_reference_c14n_mode_with_namespaces(reference_xml, inherited_namespaces)?;
    let referenced_xml = xml_signature_reference_target(signature_xml, uri)?;
    let signed_properties_namespaces =
        namespace_bindings_from_attributes(&referenced_xml.inherited_namespaces);
    ensure_signed_properties_reference_target_with_namespaces(
        referenced_xml.xml,
        &signed_properties_namespaces,
    )?;
    let canonical_referenced_xml = canonicalize_supported_xml_with_mode(
        referenced_xml.xml,
        &referenced_xml.inherited_namespaces,
        c14n_mode,
    )?;
    verify_xml_signature_reference_digest_with_namespaces(
        reference_xml,
        &canonical_referenced_xml,
        inherited_namespaces,
    )?;
    Ok(VerifiedSignedProperties {
        xml: referenced_xml.xml,
        inherited_namespaces: signed_properties_namespaces,
    })
}
fn verify_xml_signature_reference_digest_with_namespaces(
    reference_xml: &str,
    canonical_referenced_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(), MsgError> {
    let reference_span = required_single_xml_element(reference_xml, "Reference")?;
    let reference_namespaces =
        xml_element_namespace_scope(reference_xml, reference_span, inherited_namespaces)?;
    let digest_method_span = required_single_xml_element(reference_xml, "DigestMethod")?;
    ensure_xml_element_prefixed_namespace(
        reference_xml,
        digest_method_span,
        &reference_namespaces,
        XMLDSIG_NS,
    )?;
    ensure_xml_element_attributes_allowed(reference_xml, digest_method_span, &["Algorithm"])?;
    ensure_xml_element_content_empty(reference_xml, digest_method_span)?;
    let digest_algorithm = element_attr(reference_xml, digest_method_span, "Algorithm")
        .ok_or(MsgError::ValidationFailed)?;
    if digest_algorithm != XMLDSIG_SHA256 {
        return Err(MsgError::ValidationFailed);
    }
    let digest_value_span = required_single_xml_element(reference_xml, "DigestValue")?;
    ensure_xml_element_prefixed_namespace(
        reference_xml,
        digest_value_span,
        &reference_namespaces,
        XMLDSIG_NS,
    )?;
    let expected_digest = decode_direct_child_base64(reference_xml, digest_value_span)?;
    let digest = Sha256::digest(canonical_referenced_xml.as_bytes());
    if expected_digest.as_slice() != &digest[..] {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn supported_xml_signature_reference_c14n_mode_with_namespaces(
    reference_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<CanonicalXmlMode, MsgError> {
    ensure_xml_signature_reference_shape_with_namespaces(
        reference_xml,
        &["URI"],
        inherited_namespaces,
    )?;
    let transform_algorithms = xml_signature_reference_transform_algorithms_with_namespaces(
        reference_xml,
        inherited_namespaces,
    )?;
    match transform_algorithms.as_slice() {
        [transform] if transform == XMLDSIG_ENVELOPED_SIGNATURE => Ok(CanonicalXmlMode::Exclusive),
        [transform, c14n_algorithm] if transform == XMLDSIG_ENVELOPED_SIGNATURE => {
            xml_canonicalization_mode(c14n_algorithm)
        }
        _ => Err(MsgError::ValidationFailed),
    }
}
fn signed_properties_reference_c14n_mode_with_namespaces(
    reference_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<CanonicalXmlMode, MsgError> {
    ensure_xml_signature_reference_shape_with_namespaces(
        reference_xml,
        &["URI", "Type"],
        inherited_namespaces,
    )?;
    let transform_algorithms = xml_signature_reference_transform_algorithms_with_namespaces(
        reference_xml,
        inherited_namespaces,
    )?;
    let mut c14n_mode = None;
    for algorithm in transform_algorithms {
        let mode = xml_canonicalization_mode(&algorithm)?;
        if c14n_mode.replace(mode).is_some() {
            return Err(MsgError::ValidationFailed);
        }
    }
    c14n_mode.ok_or(MsgError::ValidationFailed)
}
fn ensure_xml_signature_reference_shape_with_namespaces(
    reference_xml: &str,
    allowed_attributes: &[&str],
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(), MsgError> {
    let reference_span = required_single_xml_element(reference_xml, "Reference")?;
    if reference_span.start != 0 || reference_span.end != reference_xml.len() {
        return Err(MsgError::ValidationFailed);
    }
    ensure_xml_element_prefixed_namespace(
        reference_xml,
        reference_span,
        inherited_namespaces,
        XMLDSIG_NS,
    )?;
    let reference_namespaces =
        xml_element_namespace_scope(reference_xml, reference_span, inherited_namespaces)?;
    ensure_xml_element_attributes_allowed(reference_xml, reference_span, allowed_attributes)?;
    ensure_direct_xml_child_elements_allowing_comments(
        reference_xml,
        reference_span,
        &["Transforms", "DigestMethod", "DigestValue"],
    )?;
    let transforms = required_direct_xml_child_element_allowing_comments(
        reference_xml,
        reference_span,
        "Transforms",
    )?;
    let digest_method = optional_direct_xml_child_element_allowing_comments(
        reference_xml,
        reference_span,
        "DigestMethod",
    )?;
    let digest_value = optional_direct_xml_child_element_allowing_comments(
        reference_xml,
        reference_span,
        "DigestValue",
    )?;
    ensure_xml_element_prefixed_namespace(
        reference_xml,
        transforms,
        &reference_namespaces,
        XMLDSIG_NS,
    )?;
    if let Some(digest_method) = digest_method {
        ensure_xml_element_prefixed_namespace(
            reference_xml,
            digest_method,
            &reference_namespaces,
            XMLDSIG_NS,
        )?;
    }
    if let Some(digest_value) = digest_value {
        ensure_xml_element_prefixed_namespace(
            reference_xml,
            digest_value,
            &reference_namespaces,
            XMLDSIG_NS,
        )?;
    }
    if digest_method.is_some_and(|digest_method| transforms.start > digest_method.start)
        || digest_value.is_some_and(|digest_value| transforms.start > digest_value.start)
        || digest_method
            .zip(digest_value)
            .is_some_and(|(digest_method, digest_value)| digest_method.start > digest_value.start)
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn xml_signature_reference_transform_algorithms_with_namespaces(
    reference_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<Vec<String>, MsgError> {
    let reference_span = required_single_xml_element(reference_xml, "Reference")?;
    let reference_namespaces =
        xml_element_namespace_scope(reference_xml, reference_span, inherited_namespaces)?;
    let transforms_span = required_single_xml_element(reference_xml, "Transforms")?;
    ensure_xml_element_prefixed_namespace(
        reference_xml,
        transforms_span,
        &reference_namespaces,
        XMLDSIG_NS,
    )?;
    let transforms_namespaces =
        xml_element_namespace_scope(reference_xml, transforms_span, &reference_namespaces)?;
    ensure_xml_element_attributes_allowed(reference_xml, transforms_span, &[])?;
    ensure_direct_xml_child_elements_allowing_comments(
        reference_xml,
        transforms_span,
        &["Transform"],
    )?;
    if find_first_xml_element(&reference_xml[..transforms_span.start], "Transform").is_some()
        || find_first_xml_element(&reference_xml[transforms_span.end..], "Transform").is_some()
    {
        return Err(MsgError::ValidationFailed);
    }
    let transforms_xml = &reference_xml[transforms_span.content_start..transforms_span.content_end];
    let mut cursor = 0usize;
    let mut transform_algorithms = Vec::new();
    while cursor < transforms_xml.len() {
        let Some(span) = find_first_xml_element(&transforms_xml[cursor..], "Transform") else {
            break;
        };
        let absolute = XmlElementSpan {
            start: cursor + span.start,
            opening_end: cursor + span.opening_end,
            content_start: cursor + span.content_start,
            content_end: cursor + span.content_end,
            end: cursor + span.end,
        };
        ensure_xml_element_prefixed_namespace(
            transforms_xml,
            absolute,
            &transforms_namespaces,
            XMLDSIG_NS,
        )?;
        ensure_xml_element_attributes_allowed(transforms_xml, absolute, &["Algorithm"])?;
        ensure_xml_element_content_empty(transforms_xml, absolute)?;
        transform_algorithms.push(
            element_attr(transforms_xml, absolute, "Algorithm")
                .ok_or(MsgError::ValidationFailed)?,
        );
        cursor = absolute.end;
    }
    Ok(transform_algorithms)
}
fn ensure_signed_properties_reference_target_with_namespaces(
    target_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(), MsgError> {
    let span =
        find_first_xml_element(target_xml, "SignedProperties").ok_or(MsgError::ValidationFailed)?;
    if span.start == 0 && span.end == target_xml.len() {
        ensure_xades_element_prefixed_namespace(target_xml, span, inherited_namespaces)?;
        Ok(())
    } else {
        Err(MsgError::ValidationFailed)
    }
}
fn ensure_xades_signed_properties_reference_coverage(
    signature_xml: &str,
    referenced_signed_properties_xml: Option<&str>,
) -> Result<(), MsgError> {
    let Some(signed_properties_span) = find_first_xml_element(signature_xml, "SignedProperties")
    else {
        return if referenced_signed_properties_xml.is_none() {
            Ok(())
        } else {
            Err(MsgError::ValidationFailed)
        };
    };
    let signed_properties_xml =
        &signature_xml[signed_properties_span.start..signed_properties_span.end];
    if Some(signed_properties_xml) != referenced_signed_properties_xml {
        return Err(MsgError::ValidationFailed);
    }
    if find_first_xml_element(
        &signature_xml[signed_properties_span.end..],
        "SignedProperties",
    )
    .is_some()
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn ensure_xades_qualifying_properties_target(signature_xml: &str) -> Result<(), MsgError> {
    let signature_span =
        find_first_xml_element(signature_xml, "Signature").ok_or(MsgError::ValidationFailed)?;
    if signature_span.start != 0 || signature_span.end != signature_xml.len() {
        return Err(MsgError::ValidationFailed);
    }
    let signature_namespaces = xml_element_namespace_scope(signature_xml, signature_span, &[])?;
    let signature_id = element_attr(signature_xml, signature_span, "Id")
        .filter(|id| !id.is_empty())
        .ok_or(MsgError::ValidationFailed)?;
    let object_span = required_direct_xml_child_element(signature_xml, signature_span, "Object")?;
    let object_namespaces =
        xml_element_namespace_scope(signature_xml, object_span, &signature_namespaces)?;
    ensure_xml_element_attributes_allowed(signature_xml, object_span, &[])?;
    ensure_direct_xml_child_elements(signature_xml, object_span, &["QualifyingProperties"])?;
    let qualifying_properties_span =
        required_direct_xml_child_element(signature_xml, object_span, "QualifyingProperties")?;
    ensure_xades_element_prefixed_namespace(
        signature_xml,
        qualifying_properties_span,
        &object_namespaces,
    )?;
    let qualifying_properties_namespaces = xml_element_namespace_scope(
        signature_xml,
        qualifying_properties_span,
        &object_namespaces,
    )?;
    if find_xml_element_outside_span(signature_xml, object_span, "QualifyingProperties") {
        return Err(MsgError::ValidationFailed);
    }
    ensure_xml_element_attributes_allowed(signature_xml, qualifying_properties_span, &["Target"])?;
    ensure_direct_xml_child_elements(
        signature_xml,
        qualifying_properties_span,
        &["SignedProperties"],
    )?;
    required_direct_xml_child_element(
        signature_xml,
        qualifying_properties_span,
        "SignedProperties",
    )
    .and_then(|signed_properties_span| {
        ensure_xades_element_prefixed_namespace(
            signature_xml,
            signed_properties_span,
            &qualifying_properties_namespaces,
        )
    })?;
    let target = element_attr(signature_xml, qualifying_properties_span, "Target")
        .ok_or(MsgError::ValidationFailed)?;
    if target == format!("#{signature_id}") {
        Ok(())
    } else {
        Err(MsgError::ValidationFailed)
    }
}
#[cfg(test)]
fn verify_xades_signing_certificate_v2_binding(
    signed_properties_xml: &str,
    key_material: &XmlSignatureKeyMaterial,
) -> Result<(), MsgError> {
    verify_xades_signing_certificate_v2_binding_with_namespaces(
        signed_properties_xml,
        &[],
        key_material,
    )
}
fn verify_xades_signing_certificate_v2_binding_with_namespaces(
    signed_properties_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
    key_material: &XmlSignatureKeyMaterial,
) -> Result<(), MsgError> {
    let signed_signature_properties = xades_signed_signature_properties_with_namespaces(
        signed_properties_xml,
        inherited_namespaces,
    )?;
    let signed_signature_properties_xml = signed_signature_properties.xml;
    let signed_signature_properties_span =
        required_single_xml_element(signed_signature_properties_xml, "SignedSignatureProperties")?;
    let Some(signing_certificate_span) = optional_direct_xml_child_element(
        signed_signature_properties_xml,
        signed_signature_properties_span,
        "SigningCertificateV2",
    )?
    else {
        if key_material.certificate_sha256.is_empty() {
            return Ok(());
        }
        return Err(MsgError::ValidationFailed);
    };
    if key_material.certificate_sha256.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    ensure_xades_element_prefixed_namespace(
        signed_signature_properties_xml,
        signing_certificate_span,
        &signed_signature_properties.namespaces,
    )?;
    let signing_certificate_xml = &signed_signature_properties_xml
        [signing_certificate_span.start..signing_certificate_span.end];
    let certificate_digests = xades_signing_certificate_v2_digests_with_namespaces(
        signing_certificate_xml,
        &signed_signature_properties.namespaces,
    )?;
    ensure_xades_signing_certificate_v2_chain_prefix(
        &certificate_digests,
        &key_material.certificate_sha256,
    )
}
fn ensure_xades_signing_certificate_v2_chain_prefix(
    certificate_digests: &[String],
    verified_certificate_sha256: &[String],
) -> Result<(), MsgError> {
    if certificate_digests.is_empty()
        || certificate_digests.len() > verified_certificate_sha256.len()
    {
        return Err(MsgError::ValidationFailed);
    }
    let mut seen = HashSet::new();
    for (index, digest) in certificate_digests.iter().enumerate() {
        if !seen.insert(digest.as_str()) {
            return Err(MsgError::ValidationFailed);
        }
        match verified_certificate_sha256.get(index) {
            Some(expected) if expected == digest => {}
            _ => return Err(MsgError::ValidationFailed),
        }
    }
    Ok(())
}
#[cfg(test)]
fn xades_signed_signature_properties_xml(signed_properties_xml: &str) -> Result<&str, MsgError> {
    Ok(xades_signed_signature_properties_with_namespaces(signed_properties_xml, &[])?.xml)
}
struct XadesSignedSignatureProperties<'a> {
    xml: &'a str,
    namespaces: Vec<CanonicalXmlNamespaceBinding>,
}
fn xades_signed_signature_properties_with_namespaces<'a>(
    signed_properties_xml: &'a str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<XadesSignedSignatureProperties<'a>, MsgError> {
    let signed_properties_span =
        required_single_xml_element(signed_properties_xml, "SignedProperties")?;
    if signed_properties_span.start != 0
        || signed_properties_span.end != signed_properties_xml.len()
    {
        return Err(MsgError::ValidationFailed);
    }
    ensure_xades_element_prefixed_namespace(
        signed_properties_xml,
        signed_properties_span,
        inherited_namespaces,
    )?;
    let signed_properties_namespaces = xml_element_namespace_scope(
        signed_properties_xml,
        signed_properties_span,
        inherited_namespaces,
    )?;
    ensure_xml_element_attributes_allowed(signed_properties_xml, signed_properties_span, &["Id"])?;
    ensure_direct_xml_child_elements(
        signed_properties_xml,
        signed_properties_span,
        &["SignedSignatureProperties"],
    )?;
    let signed_signature_properties_span = optional_direct_xml_child_element(
        signed_properties_xml,
        signed_properties_span,
        "SignedSignatureProperties",
    )?
    .ok_or(MsgError::ValidationFailed)?;
    ensure_xades_element_prefixed_namespace(
        signed_properties_xml,
        signed_signature_properties_span,
        &signed_properties_namespaces,
    )?;
    let signed_signature_properties_namespaces = xml_element_namespace_scope(
        signed_properties_xml,
        signed_signature_properties_span,
        &signed_properties_namespaces,
    )?;
    ensure_xml_element_attributes_allowed(
        signed_properties_xml,
        signed_signature_properties_span,
        &[],
    )?;
    ensure_direct_xml_child_elements(
        signed_properties_xml,
        signed_signature_properties_span,
        &["SigningTime", "SigningCertificateV2"],
    )?;
    for xades_child in ["SigningTime", "SigningCertificateV2"] {
        if let Some(child_span) = optional_direct_xml_child_element(
            signed_properties_xml,
            signed_signature_properties_span,
            xades_child,
        )? {
            ensure_xades_element_prefixed_namespace(
                signed_properties_xml,
                child_span,
                &signed_signature_properties_namespaces,
            )?;
        }
    }
    Ok(XadesSignedSignatureProperties {
        xml: &signed_properties_xml
            [signed_signature_properties_span.start..signed_signature_properties_span.end],
        namespaces: signed_signature_properties_namespaces,
    })
}
#[cfg(test)]
fn xades_signing_certificate_v2_digests(
    signing_certificate_xml: &str,
) -> Result<Vec<String>, MsgError> {
    xades_signing_certificate_v2_digests_with_namespaces(signing_certificate_xml, &[])
}
fn xades_signing_certificate_v2_digests_with_namespaces(
    signing_certificate_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<Vec<String>, MsgError> {
    let signing_certificate_span =
        required_single_xml_element(signing_certificate_xml, "SigningCertificateV2")?;
    if signing_certificate_span.start != 0
        || signing_certificate_span.end != signing_certificate_xml.len()
    {
        return Err(MsgError::ValidationFailed);
    }
    ensure_xades_element_prefixed_namespace(
        signing_certificate_xml,
        signing_certificate_span,
        inherited_namespaces,
    )?;
    let signing_certificate_namespaces = xml_element_namespace_scope(
        signing_certificate_xml,
        signing_certificate_span,
        inherited_namespaces,
    )?;
    ensure_xml_element_attributes_allowed(signing_certificate_xml, signing_certificate_span, &[])?;
    ensure_direct_xml_child_elements(signing_certificate_xml, signing_certificate_span, &["Cert"])?;
    let mut cursor = 0usize;
    let mut digests = Vec::new();
    while cursor < signing_certificate_xml.len() {
        let Some(span) = find_first_xml_element(&signing_certificate_xml[cursor..], "Cert") else {
            break;
        };
        let cert_span = XmlElementSpan {
            start: cursor + span.start,
            opening_end: cursor + span.opening_end,
            content_start: cursor + span.content_start,
            content_end: cursor + span.content_end,
            end: cursor + span.end,
        };
        ensure_xades_element_prefixed_namespace(
            signing_certificate_xml,
            cert_span,
            &signing_certificate_namespaces,
        )?;
        let cert_xml = &signing_certificate_xml[cert_span.start..cert_span.end];
        digests.push(xades_cert_digest_sha256_with_namespaces(
            cert_xml,
            &signing_certificate_namespaces,
        )?);
        cursor = cert_span.end;
    }
    Ok(digests)
}
#[cfg(test)]
fn xades_cert_digest_sha256(cert_xml: &str) -> Result<String, MsgError> {
    xades_cert_digest_sha256_with_namespaces(cert_xml, &[])
}
fn xades_cert_digest_sha256_with_namespaces(
    cert_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<String, MsgError> {
    let cert_span = required_single_xml_element(cert_xml, "Cert")?;
    if cert_span.start != 0 || cert_span.end != cert_xml.len() {
        return Err(MsgError::ValidationFailed);
    }
    ensure_xades_element_prefixed_namespace(cert_xml, cert_span, inherited_namespaces)?;
    let cert_namespaces = xml_element_namespace_scope(cert_xml, cert_span, inherited_namespaces)?;
    ensure_xml_element_attributes_allowed(cert_xml, cert_span, &[])?;
    ensure_direct_xml_child_elements(cert_xml, cert_span, &["CertDigest"])?;
    let cert_digest_span = required_single_xml_element(cert_xml, "CertDigest")?;
    ensure_xades_element_prefixed_namespace(cert_xml, cert_digest_span, &cert_namespaces)?;
    let cert_digest_namespaces =
        xml_element_namespace_scope(cert_xml, cert_digest_span, &cert_namespaces)?;
    ensure_xml_element_attributes_allowed(cert_xml, cert_digest_span, &[])?;
    ensure_direct_xml_child_elements(cert_xml, cert_digest_span, &["DigestMethod", "DigestValue"])?;
    let cert_digest_xml = &cert_xml[cert_digest_span.start..cert_digest_span.end];
    let digest_method_span = required_single_xml_element(cert_digest_xml, "DigestMethod")?;
    ensure_xml_element_prefixed_namespace(
        cert_digest_xml,
        digest_method_span,
        &cert_digest_namespaces,
        XMLDSIG_NS,
    )?;
    ensure_xml_element_attributes_allowed(cert_digest_xml, digest_method_span, &["Algorithm"])?;
    ensure_xml_element_content_empty(cert_digest_xml, digest_method_span)?;
    let digest_algorithm = element_attr(cert_digest_xml, digest_method_span, "Algorithm")
        .ok_or(MsgError::ValidationFailed)?;
    if digest_algorithm != XMLDSIG_SHA256 {
        return Err(MsgError::ValidationFailed);
    }
    let digest_value_span = required_single_xml_element(cert_digest_xml, "DigestValue")?;
    ensure_xml_element_prefixed_namespace(
        cert_digest_xml,
        digest_value_span,
        &cert_digest_namespaces,
        XMLDSIG_NS,
    )?;
    let digest = decode_direct_child_base64(cert_digest_xml, digest_value_span)?;
    if digest.len() != 32 {
        return Err(MsgError::ValidationFailed);
    }
    Ok(lower_hex(&digest))
}
#[derive(Debug)]
struct XmlSignatureReferenceTarget<'a> {
    xml: &'a str,
    inherited_namespaces: Vec<CanonicalXmlAttribute>,
}
fn xml_signature_reference_target<'a>(
    unsigned_xml: &'a str,
    uri: &str,
) -> Result<XmlSignatureReferenceTarget<'a>, MsgError> {
    if uri.is_empty() {
        return Ok(XmlSignatureReferenceTarget {
            xml: unsigned_xml,
            inherited_namespaces: Vec::new(),
        });
    }
    let reference_id = uri
        .strip_prefix('#')
        .filter(|reference_id| !reference_id.is_empty())
        .ok_or(MsgError::ValidationFailed)?;
    ensure_supported_same_document_reference_id(reference_id)?;
    let target = find_xml_element_by_reference_id(unsigned_xml, reference_id)?;
    Ok(XmlSignatureReferenceTarget {
        xml: &unsigned_xml[target.span.start..target.span.end],
        inherited_namespaces: target.inherited_namespaces,
    })
}
fn ensure_supported_same_document_reference_id(reference_id: &str) -> Result<(), MsgError> {
    ensure_supported_xml_name(reference_id)?;
    if reference_id.contains(':') {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
#[derive(Debug)]
struct XmlReferenceTarget {
    span: XmlElementSpan,
    inherited_namespaces: Vec<CanonicalXmlAttribute>,
}
fn xml_namespace_bindings_before_offset(
    text: &str,
    target_start: usize,
) -> Result<Vec<CanonicalXmlNamespaceBinding>, MsgError> {
    let mut cursor = 0usize;
    let mut namespace_scope_lengths = Vec::new();
    let mut in_scope_namespaces = Vec::new();
    while cursor < text.len() {
        let Some(start_offset) = text[cursor..].find('<') else {
            break;
        };
        let start = cursor + start_offset;
        if start == target_start {
            return Ok(in_scope_namespaces);
        }
        if start > target_start {
            return Err(MsgError::ValidationFailed);
        }
        if text[start..].starts_with("<!--") {
            cursor = find_supported_xml_comment_end(text, start)? + 3;
            continue;
        }
        if text[start..].starts_with("<?") {
            cursor = text[start + 2..]
                .find("?>")
                .map(|offset| start + 2 + offset + 2)
                .ok_or(MsgError::ValidationFailed)?;
            continue;
        }
        let tag_start = start + 1;
        let opening_end =
            find_xml_tag_end(text.as_bytes(), tag_start).ok_or(MsgError::ValidationFailed)?;
        let raw_tag = text[tag_start..opening_end].trim();
        if raw_tag.starts_with('/') {
            let namespace_scope_len = namespace_scope_lengths
                .pop()
                .ok_or(MsgError::ValidationFailed)?;
            in_scope_namespaces.truncate(namespace_scope_len);
            cursor = opening_end + 1;
            continue;
        }
        if raw_tag.starts_with('!') {
            return Err(MsgError::ValidationFailed);
        }
        let self_closing = raw_tag.ends_with('/');
        let tag_body = raw_tag.trim_end_matches('/').trim_end();
        let (name, attributes) = split_supported_xml_tag(tag_body)?;
        ensure_supported_xml_name(name)?;
        let mut attributes = parse_supported_xml_attributes(attributes)?;
        sort_and_validate_canonical_xml_attributes(&mut attributes, &in_scope_namespaces)?;
        if !self_closing {
            namespace_scope_lengths.push(in_scope_namespaces.len());
            in_scope_namespaces.extend(
                attributes
                    .iter()
                    .filter_map(namespace_binding_from_attribute),
            );
        }
        cursor = opening_end + 1;
    }
    Err(MsgError::ValidationFailed)
}
fn find_xml_element_by_reference_id(
    text: &str,
    reference_id: &str,
) -> Result<XmlReferenceTarget, MsgError> {
    let mut cursor = 0usize;
    let mut found = None;
    let mut namespace_scope_lengths = Vec::new();
    let mut in_scope_namespaces = Vec::new();
    while cursor < text.len() {
        let Some(start_offset) = text[cursor..].find('<') else {
            break;
        };
        let start = cursor + start_offset;
        let tag_start = start + 1;
        let opening_end =
            find_xml_tag_end(text.as_bytes(), tag_start).ok_or(MsgError::ValidationFailed)?;
        let raw_tag = text[tag_start..opening_end].trim();
        if raw_tag.starts_with('/')
            || raw_tag.starts_with('?')
            || raw_tag.starts_with("!--")
            || raw_tag.starts_with("![CDATA[")
        {
            if raw_tag.starts_with('/') {
                let namespace_scope_len = namespace_scope_lengths
                    .pop()
                    .ok_or(MsgError::ValidationFailed)?;
                in_scope_namespaces.truncate(namespace_scope_len);
            }
            cursor = opening_end + 1;
            continue;
        }
        let self_closing = raw_tag.ends_with('/');
        let tag_body = raw_tag.trim_end_matches('/').trim_end();
        let (name, attributes) = split_supported_xml_tag(tag_body)?;
        ensure_supported_xml_name(name)?;
        let mut attributes = parse_supported_xml_attributes(attributes)?;
        sort_and_validate_canonical_xml_attributes(&mut attributes, &in_scope_namespaces)?;
        if same_document_reference_id_matches(raw_tag, reference_id) {
            if found.is_some() {
                return Err(MsgError::ValidationFailed);
            }
            let inherited_namespaces =
                inherited_namespace_attributes_from_scope(&in_scope_namespaces);
            let span = if self_closing {
                XmlElementSpan {
                    start,
                    opening_end,
                    content_start: opening_end + 1,
                    content_end: opening_end + 1,
                    end: opening_end + 1,
                }
            } else {
                let (content_end, end) = find_xml_element_end(text, opening_end + 1, name)
                    .ok_or(MsgError::ValidationFailed)?;
                XmlElementSpan {
                    start,
                    opening_end,
                    content_start: opening_end + 1,
                    content_end,
                    end,
                }
            };
            found = Some(XmlReferenceTarget {
                span,
                inherited_namespaces,
            });
        }
        if !self_closing {
            namespace_scope_lengths.push(in_scope_namespaces.len());
            in_scope_namespaces.extend(
                attributes
                    .iter()
                    .filter_map(namespace_binding_from_attribute),
            );
        }
        cursor = opening_end + 1;
    }
    found.ok_or(MsgError::ValidationFailed)
}
fn same_document_reference_id_matches(opening: &str, reference_id: &str) -> bool {
    ["Id", "ID", "id", "xml:id"]
        .iter()
        .any(|attr| attr_value_exact(opening, attr).as_deref() == Some(reference_id))
}
#[derive(Debug)]
struct XmlSignatureKeyMaterial {
    public_key: Vec<u8>,
    certificate_sha256: Vec<String>,
}
struct XmlSignatureEmbeddedRevocationValues {
    crls: Vec<String>,
    ocsp_responses: Vec<String>,
}
#[cfg(test)]
fn xml_signature_key_material_with_namespaces(
    signature_xml: &str,
    evaluation_time: Option<ASN1Time>,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<XmlSignatureKeyMaterial, MsgError> {
    xml_signature_key_material_with_policy(
        signature_xml,
        evaluation_time,
        inherited_namespaces,
        None,
        &[],
        &[],
    )
}
fn xml_signature_key_material_for_profile_with_namespaces(
    signature_xml: &str,
    evaluation_time: Option<ASN1Time>,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
    profile: &TradfiRailProfile,
    embedded_crl_values: &[String],
    embedded_ocsp_response_values: &[String],
) -> Result<XmlSignatureKeyMaterial, MsgError> {
    xml_signature_key_material_with_policy(
        signature_xml,
        evaluation_time,
        inherited_namespaces,
        Some(profile),
        embedded_crl_values,
        embedded_ocsp_response_values,
    )
}
fn xml_signature_key_material_with_policy(
    signature_xml: &str,
    evaluation_time: Option<ASN1Time>,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
    profile: Option<&TradfiRailProfile>,
    embedded_crl_values: &[String],
    embedded_ocsp_response_values: &[String],
) -> Result<XmlSignatureKeyMaterial, MsgError> {
    let key_info_span = required_single_xml_element(signature_xml, "KeyInfo")?;
    ensure_xml_element_prefixed_namespace(
        signature_xml,
        key_info_span,
        inherited_namespaces,
        XMLDSIG_NS,
    )?;
    let key_info_namespaces =
        xml_element_namespace_scope(signature_xml, key_info_span, inherited_namespaces)?;
    for key_material_element in [
        "PublicKey",
        "X509Certificate",
        "X509CRL",
        "OCSPResponse",
        "EncapsulatedOCSPValue",
    ] {
        if find_xml_element_outside_span(signature_xml, key_info_span, key_material_element) {
            return Err(MsgError::ValidationFailed);
        }
    }
    let key_info_xml = &signature_xml[key_info_span.start..key_info_span.end];
    let public_key = optional_single_child_text_compact(key_info_xml, "PublicKey")?;
    let has_certificate = find_first_xml_element(key_info_xml, "X509Certificate").is_some();
    if public_key.is_some() && has_certificate {
        return Err(MsgError::ValidationFailed);
    }
    if let Some(public_key) = public_key {
        ensure_xml_signature_public_key_info_shape_with_namespaces(
            key_info_xml,
            &key_info_namespaces,
        )?;
        let public_key = BASE64_STANDARD
            .decode(public_key)
            .map_err(|_| MsgError::ValidationFailed)?;
        ensure_xml_signature_p256_public_key(&public_key)?;
        if let Some(profile) = profile
            && (profile.x509_require_crl_revocation_check
                || !profile.x509_crl_der_base64.is_empty()
                || !embedded_crl_values.is_empty()
                || profile.x509_require_ocsp_revocation_check
                || !profile.x509_ocsp_response_der_base64.is_empty()
                || !embedded_ocsp_response_values.is_empty()
                || !profile.x509_required_certificate_policy_oids.is_empty())
        {
            return Err(MsgError::ValidationFailed);
        }
        return Ok(XmlSignatureKeyMaterial {
            public_key,
            certificate_sha256: Vec::new(),
        });
    }
    let certificates =
        xml_signature_x509_certificates_with_namespaces(key_info_xml, &key_info_namespaces)?;
    ensure_xml_signature_certificate_chain_bounds(&certificates)?;
    let evaluation_time = evaluation_time.ok_or(MsgError::ValidationFailed)?;
    let parsed_certificates = certificates
        .iter()
        .map(|certificate| {
            X509Certificate::from_der(certificate)
                .map(|(_, cert)| cert)
                .map_err(|_| MsgError::ValidationFailed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (index, certificate) in parsed_certificates.iter().enumerate() {
        ensure_xml_signature_supported_certificate_algorithm(certificate)?;
        let role = if index == 0 {
            XmlSignatureCertificateRole::Leaf
        } else {
            XmlSignatureCertificateRole::Issuer
        };
        ensure_xml_signature_supported_critical_extensions(certificate, role)?;
    }
    let public_key = parsed_certificates[0]
        .public_key()
        .subject_public_key
        .data
        .to_vec();
    ensure_xml_signature_certificate_valid_at(&parsed_certificates[0], evaluation_time)?;
    ensure_xml_signature_leaf_certificate_policy(&parsed_certificates[0])?;
    let mut certificate_sha256 = vec![sha256_hex(&certificates[0])];
    for (subordinate_ca_count, (certificates_der, chain_pair)) in certificates[1..]
        .iter()
        .zip(parsed_certificates.windows(2))
        .enumerate()
    {
        ensure_xml_signature_certificate_valid_at(&chain_pair[1], evaluation_time)?;
        ensure_xml_signature_issuer_certificate_policy(&chain_pair[1])?;
        ensure_xml_signature_issuer_path_len(&chain_pair[1], subordinate_ca_count)?;
        ensure_xml_signature_certificate_issued_by(&chain_pair[0], &chain_pair[1])?;
        chain_pair[0]
            .verify_signature(Some(chain_pair[1].public_key()))
            .map_err(|_| MsgError::ValidationFailed)?;
        certificate_sha256.push(sha256_hex(certificates_der));
    }
    if let Some(profile) = profile {
        if let (Some(terminal_certificate), Some(terminal_certificate_sha256)) =
            (parsed_certificates.last(), certificate_sha256.last())
        {
            let terminal_is_trust_anchor = profile
                .x509_trust_anchor_sha256_pins
                .iter()
                .any(|pin| pin == terminal_certificate_sha256);
            if terminal_is_trust_anchor && !x509_certificate_is_ca(terminal_certificate)? {
                return Err(MsgError::ValidationFailed);
            }
        }
        if !x509_certificate_satisfies_policy_oids(
            &parsed_certificates[0],
            &profile.x509_required_certificate_policy_oids,
        )? {
            return Err(MsgError::ValidationFailed);
        }
        validate_x509_required_certificate_policy_path(
            &parsed_certificates,
            &profile.x509_required_certificate_policy_oids,
        )?;
        validate_x509_name_constraints(&certificates)?;
        validate_x509_leaf_revocation(
            &certificates,
            evaluation_time,
            embedded_crl_values,
            profile.x509_require_crl_revocation_check,
            &profile.x509_crl_der_base64,
            embedded_ocsp_response_values,
            profile.x509_require_ocsp_revocation_check,
            &profile.x509_ocsp_response_der_base64,
        )?;
    }
    Ok(XmlSignatureKeyMaterial {
        public_key,
        certificate_sha256,
    })
}
fn xml_signature_x509_revocation_values_with_namespaces(
    key_info_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<XmlSignatureEmbeddedRevocationValues, MsgError> {
    let Some(x509_data_span) = find_first_xml_element(key_info_xml, "X509Data") else {
        return Ok(XmlSignatureEmbeddedRevocationValues {
            crls: Vec::new(),
            ocsp_responses: Vec::new(),
        });
    };
    let key_info_span = required_single_xml_element(key_info_xml, "KeyInfo")?;
    if find_xml_element_outside_span(key_info_xml, key_info_span, "X509Data") {
        return Err(MsgError::ValidationFailed);
    }
    let key_info_namespaces =
        xml_element_namespace_scope(key_info_xml, key_info_span, inherited_namespaces)?;
    ensure_xml_element_prefixed_namespace(
        key_info_xml,
        x509_data_span,
        &key_info_namespaces,
        XMLDSIG_NS,
    )?;
    let x509_data_namespaces =
        xml_element_namespace_scope(key_info_xml, x509_data_span, &key_info_namespaces)?;
    let x509_data_xml = &key_info_xml[x509_data_span.start..x509_data_span.end];
    let crls = child_base64_text_values_with_namespaces(
        x509_data_xml,
        "X509CRL",
        &x509_data_namespaces,
        &[XMLDSIG_NS],
    )?;
    let mut ocsp_responses = child_base64_text_values_with_namespaces(
        x509_data_xml,
        "OCSPResponse",
        &x509_data_namespaces,
        &[XMLDSIG_NS],
    )?;
    ocsp_responses.extend(child_base64_text_values_with_namespaces(
        x509_data_xml,
        "EncapsulatedOCSPValue",
        &x509_data_namespaces,
        &[XMLDSIG_NS, XADES_NS],
    )?);
    Ok(XmlSignatureEmbeddedRevocationValues {
        crls,
        ocsp_responses,
    })
}
fn validate_x509_name_constraints(certificate_chain: &[Vec<u8>]) -> Result<(), MsgError> {
    let parsed_chain = certificate_chain
        .iter()
        .map(|certificate| parse_x509_certificate_der(certificate))
        .collect::<Result<Vec<_>, _>>()?;
    for issuer_index in 1..parsed_chain.len() {
        let Some(name_constraints) = parsed_chain[issuer_index]
            .name_constraints()
            .map_err(|_| MsgError::ValidationFailed)?
        else {
            continue;
        };
        if !name_constraints.critical {
            return Err(MsgError::ValidationFailed);
        }
        validate_x509_name_constraint_bases(name_constraints.value)?;
        for certificate in &parsed_chain[..issuer_index] {
            validate_x509_certificate_against_name_constraints(
                certificate,
                name_constraints.value,
            )?;
        }
    }
    Ok(())
}
fn validate_x509_name_constraint_bases(constraints: &NameConstraints<'_>) -> Result<(), MsgError> {
    if let Some(permitted_subtrees) = &constraints.permitted_subtrees {
        for subtree in permitted_subtrees {
            x509_constraint_kind(&subtree.base)?;
        }
    }
    if let Some(excluded_subtrees) = &constraints.excluded_subtrees {
        for subtree in excluded_subtrees {
            x509_constraint_kind(&subtree.base)?;
        }
    }
    Ok(())
}
fn validate_x509_certificate_against_name_constraints(
    certificate: &X509Certificate<'_>,
    constraints: &NameConstraints<'_>,
) -> Result<(), MsgError> {
    let names = x509_certificate_presented_names(certificate)?;
    if let Some(excluded_subtrees) = &constraints.excluded_subtrees {
        for subtree in excluded_subtrees {
            for name in &names {
                if x509_presented_name_kind(name) == x509_constraint_kind(&subtree.base)?
                    && x509_presented_name_matches_constraint(name, &subtree.base)?
                {
                    return Err(MsgError::ValidationFailed);
                }
            }
        }
    }
    if let Some(permitted_subtrees) = &constraints.permitted_subtrees {
        let permitted_kinds = permitted_subtrees
            .iter()
            .map(|subtree| x509_constraint_kind(&subtree.base))
            .collect::<Result<HashSet<_>, _>>()?;
        for kind in permitted_kinds {
            for name in names
                .iter()
                .filter(|name| x509_presented_name_kind(name) == kind)
            {
                let permitted = permitted_subtrees.iter().any(|subtree| {
                    x509_constraint_kind(&subtree.base).is_ok_and(|constraint_kind| {
                        constraint_kind == kind
                            && x509_presented_name_matches_constraint(name, &subtree.base)
                                .unwrap_or(false)
                    })
                });
                if !permitted {
                    return Err(MsgError::ValidationFailed);
                }
            }
        }
    }
    Ok(())
}
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum X509GeneralNameKind {
    DirectoryName,
    Dns,
    Ip,
    Rfc822,
    Uri,
}
enum X509PresentedName {
    DirectoryName(String),
    Dns(String),
    Ip(Vec<u8>),
    Rfc822(String),
    Uri(String),
}
fn x509_certificate_presented_names(
    certificate: &X509Certificate<'_>,
) -> Result<Vec<X509PresentedName>, MsgError> {
    let mut names = vec![X509PresentedName::DirectoryName(
        certificate.subject().to_string(),
    )];
    if let Some(subject_alternative_name) = certificate
        .subject_alternative_name()
        .map_err(|_| MsgError::ValidationFailed)?
    {
        for name in &subject_alternative_name.value.general_names {
            names.push(match name {
                GeneralName::DirectoryName(name) => {
                    X509PresentedName::DirectoryName(name.to_string())
                }
                GeneralName::DNSName(name) => X509PresentedName::Dns((*name).to_owned()),
                GeneralName::IPAddress(name) => X509PresentedName::Ip((*name).to_vec()),
                GeneralName::RFC822Name(name) => X509PresentedName::Rfc822((*name).to_owned()),
                GeneralName::URI(name) => X509PresentedName::Uri((*name).to_owned()),
                GeneralName::Invalid(_, _) => return Err(MsgError::ValidationFailed),
                GeneralName::EDIPartyName(_)
                | GeneralName::OtherName(_, _)
                | GeneralName::RegisteredID(_)
                | GeneralName::X400Address(_) => return Err(MsgError::ValidationFailed),
            });
        }
    }
    Ok(names)
}
fn x509_presented_name_kind(name: &X509PresentedName) -> X509GeneralNameKind {
    match name {
        X509PresentedName::DirectoryName(_) => X509GeneralNameKind::DirectoryName,
        X509PresentedName::Dns(_) => X509GeneralNameKind::Dns,
        X509PresentedName::Ip(_) => X509GeneralNameKind::Ip,
        X509PresentedName::Rfc822(_) => X509GeneralNameKind::Rfc822,
        X509PresentedName::Uri(_) => X509GeneralNameKind::Uri,
    }
}
fn x509_constraint_kind(base: &GeneralName<'_>) -> Result<X509GeneralNameKind, MsgError> {
    match base {
        GeneralName::DirectoryName(_) => Ok(X509GeneralNameKind::DirectoryName),
        GeneralName::DNSName(_) => Ok(X509GeneralNameKind::Dns),
        GeneralName::IPAddress(_) => Ok(X509GeneralNameKind::Ip),
        GeneralName::RFC822Name(_) => Ok(X509GeneralNameKind::Rfc822),
        GeneralName::URI(_) => Ok(X509GeneralNameKind::Uri),
        GeneralName::Invalid(_, _)
        | GeneralName::EDIPartyName(_)
        | GeneralName::OtherName(_, _)
        | GeneralName::RegisteredID(_)
        | GeneralName::X400Address(_) => Err(MsgError::ValidationFailed),
    }
}
fn x509_presented_name_matches_constraint(
    name: &X509PresentedName,
    base: &GeneralName<'_>,
) -> Result<bool, MsgError> {
    match (name, base) {
        (X509PresentedName::DirectoryName(name), GeneralName::DirectoryName(base)) => {
            Ok(name == &base.to_string())
        }
        (X509PresentedName::Dns(name), GeneralName::DNSName(base)) => {
            dns_name_matches_constraint(name, base)
        }
        (X509PresentedName::Ip(name), GeneralName::IPAddress(base)) => {
            ip_address_matches_constraint(name, base)
        }
        (X509PresentedName::Rfc822(name), GeneralName::RFC822Name(base)) => {
            rfc822_name_matches_constraint(name, base)
        }
        (X509PresentedName::Uri(name), GeneralName::URI(base)) => {
            uri_name_matches_constraint(name, base)
        }
        _ => Ok(false),
    }
}
fn dns_name_matches_constraint(name: &str, base: &str) -> Result<bool, MsgError> {
    let name = normalise_dns_constraint_name(name, false)?;
    let base = normalise_dns_constraint_name(base, true)?;
    if let Some(suffix) = base.strip_prefix('.') {
        return Ok(name.len() > suffix.len() && name.ends_with(&base));
    }
    Ok(name == base || name.ends_with(&format!(".{base}")))
}
fn normalise_dns_constraint_name(value: &str, allow_leading_dot: bool) -> Result<String, MsgError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.contains('*') {
        return Err(MsgError::ValidationFailed);
    }
    let labels = if allow_leading_dot {
        value.strip_prefix('.').unwrap_or(&value)
    } else {
        value.as_str()
    };
    if labels.is_empty()
        || labels.split('.').any(str::is_empty)
        || !labels
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.')
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok(value)
}
fn ip_address_matches_constraint(name: &[u8], base: &[u8]) -> Result<bool, MsgError> {
    let (address, mask) = match (name.len(), base.len()) {
        (4, 8) => (&base[..4], &base[4..]),
        (16, 32) => (&base[..16], &base[16..]),
        _ => return Err(MsgError::ValidationFailed),
    };
    Ok(name
        .iter()
        .zip(address.iter().zip(mask.iter()))
        .all(|(value, (base, mask))| value & mask == base & mask))
}
fn rfc822_name_matches_constraint(name: &str, base: &str) -> Result<bool, MsgError> {
    let name = name.trim().to_ascii_lowercase();
    let base = base.trim().to_ascii_lowercase();
    if name.is_empty() || base.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    if base.contains('@') {
        return Ok(name == base);
    }
    let Some((_, domain)) = name.rsplit_once('@') else {
        return Err(MsgError::ValidationFailed);
    };
    dns_name_matches_constraint(domain, &base)
}
fn uri_name_matches_constraint(name: &str, base: &str) -> Result<bool, MsgError> {
    let Some(host) = uri_host(name) else {
        return Err(MsgError::ValidationFailed);
    };
    dns_name_matches_constraint(host, base)
}
fn uri_host(uri: &str) -> Option<&str> {
    let (_, authority_and_path) = uri.split_once("://")?;
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(authority_and_path);
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.starts_with('[') {
        return host_port
            .strip_prefix('[')
            .and_then(|rest| rest.split_once(']'))
            .map(|(host, _)| host);
    }
    host_port.split(':').next().filter(|host| !host.is_empty())
}
fn validate_x509_leaf_revocation(
    certificate_chain: &[Vec<u8>],
    evaluation_time: ASN1Time,
    embedded_crl_values: &[String],
    x509_require_crl_revocation_check: bool,
    x509_crl_der_base64: &[String],
    embedded_ocsp_response_values: &[String],
    x509_require_ocsp_revocation_check: bool,
    x509_ocsp_response_der_base64: &[String],
) -> Result<(), MsgError> {
    let has_crl_material = !embedded_crl_values.is_empty() || !x509_crl_der_base64.is_empty();
    let has_ocsp_material =
        !embedded_ocsp_response_values.is_empty() || !x509_ocsp_response_der_base64.is_empty();
    if !has_crl_material && !has_ocsp_material {
        return if x509_require_crl_revocation_check || x509_require_ocsp_revocation_check {
            Err(MsgError::ValidationFailed)
        } else {
            Ok(())
        };
    }
    let leaf = parse_x509_certificate_der(&certificate_chain[0])?;
    let issuer = x509_leaf_issuer_certificate(certificate_chain)?;
    if has_crl_material || x509_require_crl_revocation_check {
        validate_x509_leaf_crl_revocation(
            &leaf,
            &issuer,
            evaluation_time,
            embedded_crl_values,
            x509_require_crl_revocation_check,
            x509_crl_der_base64,
        )?;
    }
    if has_ocsp_material || x509_require_ocsp_revocation_check {
        validate_x509_leaf_ocsp_revocation(
            &leaf,
            &issuer,
            evaluation_time,
            embedded_ocsp_response_values,
            x509_require_ocsp_revocation_check,
            x509_ocsp_response_der_base64,
        )?;
    }
    Ok(())
}
fn validate_x509_leaf_crl_revocation(
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    evaluation_time: ASN1Time,
    embedded_crl_values: &[String],
    x509_require_crl_revocation_check: bool,
    x509_crl_der_base64: &[String],
) -> Result<(), MsgError> {
    if embedded_crl_values.is_empty() && x509_crl_der_base64.is_empty() {
        return if x509_require_crl_revocation_check {
            Err(MsgError::ValidationFailed)
        } else {
            Ok(())
        };
    }
    if !x509_certificate_allows_crl_sign(issuer)? {
        return Err(MsgError::ValidationFailed);
    }
    let crl_der_values = decode_x509_crls(embedded_crl_values, x509_crl_der_base64)?;
    let mut matching_crl_seen = false;
    for crl_der in &crl_der_values {
        let crl = parse_x509_crl_der(crl_der)?;
        validate_x509_crl_freshness(&crl, evaluation_time)?;
        if crl.issuer() != issuer.subject() {
            continue;
        }
        matching_crl_seen = true;
        verify_x509_crl_signature(&crl, &issuer)?;
        if crl
            .iter_revoked_certificates()
            .any(|revoked| revoked.raw_serial() == leaf.raw_serial())
        {
            return Err(MsgError::ValidationFailed);
        }
    }
    if !matching_crl_seen {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn validate_x509_leaf_ocsp_revocation(
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    evaluation_time: ASN1Time,
    embedded_ocsp_response_values: &[String],
    x509_require_ocsp_revocation_check: bool,
    x509_ocsp_response_der_base64: &[String],
) -> Result<(), MsgError> {
    if embedded_ocsp_response_values.is_empty() && x509_ocsp_response_der_base64.is_empty() {
        return if x509_require_ocsp_revocation_check {
            Err(MsgError::ValidationFailed)
        } else {
            Ok(())
        };
    }
    let ocsp_response_der_values =
        decode_x509_ocsp_responses(embedded_ocsp_response_values, x509_ocsp_response_der_base64)?;
    let mut matching_good_response_seen = false;
    for ocsp_response_der in &ocsp_response_der_values {
        match validate_ocsp_response_for_leaf(ocsp_response_der, leaf, issuer, evaluation_time)? {
            OcspLeafStatus::Good => matching_good_response_seen = true,
            OcspLeafStatus::Revoked | OcspLeafStatus::Unknown => {
                return Err(MsgError::ValidationFailed);
            }
            OcspLeafStatus::NotForLeaf => {}
        }
    }
    if !matching_good_response_seen {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn decode_x509_crls(
    embedded_crl_values: &[String],
    x509_crl_der_base64: &[String],
) -> Result<Vec<Vec<u8>>, MsgError> {
    let crl_count = embedded_crl_values.len() + x509_crl_der_base64.len();
    if crl_count == 0 || crl_count > XMLDSIG_MAX_X509_CRLS {
        return Err(MsgError::ValidationFailed);
    }
    let mut seen = HashSet::new();
    let mut crls = Vec::with_capacity(crl_count);
    for value in embedded_crl_values.iter().chain(x509_crl_der_base64.iter()) {
        let crl = BASE64_STANDARD
            .decode(value)
            .map_err(|_| MsgError::ValidationFailed)?;
        if crl.is_empty() || crl.len() > XMLDSIG_MAX_X509_CRL_BYTES {
            return Err(MsgError::ValidationFailed);
        }
        if !seen.insert(sha256_hex(&crl)) {
            return Err(MsgError::ValidationFailed);
        }
        crls.push(crl);
    }
    Ok(crls)
}
fn decode_x509_ocsp_responses(
    embedded_ocsp_response_values: &[String],
    x509_ocsp_response_der_base64: &[String],
) -> Result<Vec<Vec<u8>>, MsgError> {
    let response_count = embedded_ocsp_response_values.len() + x509_ocsp_response_der_base64.len();
    if response_count == 0 || response_count > XMLDSIG_MAX_X509_OCSP_RESPONSES {
        return Err(MsgError::ValidationFailed);
    }
    let mut seen = HashSet::new();
    let mut responses = Vec::with_capacity(response_count);
    for value in embedded_ocsp_response_values
        .iter()
        .chain(x509_ocsp_response_der_base64.iter())
    {
        let response = BASE64_STANDARD
            .decode(value)
            .map_err(|_| MsgError::ValidationFailed)?;
        if response.is_empty() || response.len() > XMLDSIG_MAX_X509_OCSP_RESPONSE_BYTES {
            return Err(MsgError::ValidationFailed);
        }
        if !seen.insert(sha256_hex(&response)) {
            return Err(MsgError::ValidationFailed);
        }
        responses.push(response);
    }
    Ok(responses)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OcspCertStatus {
    Good,
    Revoked,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OcspLeafStatus {
    Good,
    Revoked,
    Unknown,
    NotForLeaf,
}
struct ParsedOcspResponse<'a> {
    responder_id: OcspResponderId<'a>,
    produced_at: ASN1Time,
    responses: Vec<ParsedOcspSingleResponse<'a>>,
    tbs_response_data: &'a [u8],
    signature_algorithm_oid: &'a [u8],
    signature_value: &'a [u8],
    responder_certificates: Vec<&'a [u8]>,
}
struct ParsedOcspSingleResponse<'a> {
    issuer_name_hash: &'a [u8],
    issuer_key_hash: &'a [u8],
    serial: &'a [u8],
    status: OcspCertStatus,
    this_update: ASN1Time,
    next_update: ASN1Time,
}
enum OcspResponderId<'a> {
    ByName(&'a [u8]),
    ByKey(&'a [u8]),
}
fn validate_ocsp_response_for_leaf(
    ocsp_response_der: &[u8],
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    evaluation_time: ASN1Time,
) -> Result<OcspLeafStatus, MsgError> {
    let response = parse_ocsp_response_der(ocsp_response_der)?;
    validate_ocsp_response_signature(&response, issuer, evaluation_time)?;
    let mut matched_status = None;
    for single_response in &response.responses {
        if !ocsp_cert_id_matches_leaf(single_response, leaf, issuer) {
            continue;
        }
        validate_ocsp_response_freshness(response.produced_at, single_response, evaluation_time)?;
        if matched_status.replace(single_response.status).is_some() {
            return Err(MsgError::ValidationFailed);
        }
    }
    Ok(match matched_status {
        Some(OcspCertStatus::Good) => OcspLeafStatus::Good,
        Some(OcspCertStatus::Revoked) => OcspLeafStatus::Revoked,
        Some(OcspCertStatus::Unknown) => OcspLeafStatus::Unknown,
        None => OcspLeafStatus::NotForLeaf,
    })
}
fn ensure_xml_signature_certificate_chain_bounds(certificates: &[Vec<u8>]) -> Result<(), MsgError> {
    if certificates.is_empty() || certificates.len() > XML_SIGNATURE_MAX_X509_CERTIFICATES {
        return Err(MsgError::ValidationFailed);
    }
    let mut seen = HashSet::new();
    for certificate in certificates {
        if !seen.insert(sha256_hex(certificate)) {
            return Err(MsgError::ValidationFailed);
        }
    }
    Ok(())
}
fn ensure_xml_signature_p256_public_key(public_key: &[u8]) -> Result<(), MsgError> {
    if public_key.len() != P256_UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN
        || public_key.first().copied() != Some(0x04)
    {
        return Err(MsgError::ValidationFailed);
    }
    parse_p256_verifying_key(public_key).map(|_| ())
}
fn ensure_xml_signature_public_key_info_shape_with_namespaces(
    key_info_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(), MsgError> {
    if find_first_xml_element(key_info_xml, "X509Data").is_some() {
        return Err(MsgError::ValidationFailed);
    }
    let key_info_span = required_single_xml_element(key_info_xml, "KeyInfo")?;
    ensure_xml_element_prefixed_namespace(
        key_info_xml,
        key_info_span,
        inherited_namespaces,
        XMLDSIG_NS,
    )?;
    let key_info_namespaces =
        xml_element_namespace_scope(key_info_xml, key_info_span, inherited_namespaces)?;
    ensure_xml_element_attributes_allowed(key_info_xml, key_info_span, &[])?;
    ensure_direct_xml_child_elements(key_info_xml, key_info_span, &["KeyValue"])?;
    let key_value_span = required_single_xml_element(key_info_xml, "KeyValue")?;
    ensure_xml_element_prefixed_namespace(
        key_info_xml,
        key_value_span,
        &key_info_namespaces,
        XMLDSIG_NS,
    )?;
    let key_value_namespaces =
        xml_element_namespace_scope(key_info_xml, key_value_span, &key_info_namespaces)?;
    ensure_xml_element_attributes_allowed(key_info_xml, key_value_span, &[])?;
    ensure_direct_xml_child_elements(key_info_xml, key_value_span, &["ECKeyValue"])?;
    for key_value_element in ["ECKeyValue", "NamedCurve", "PublicKey"] {
        if find_xml_element_outside_span(key_info_xml, key_value_span, key_value_element) {
            return Err(MsgError::ValidationFailed);
        }
    }
    let key_value_xml = &key_info_xml[key_value_span.start..key_value_span.end];
    let ec_key_value_span = required_single_xml_element(key_value_xml, "ECKeyValue")?;
    ensure_xml_element_prefixed_namespace(
        key_value_xml,
        ec_key_value_span,
        &key_value_namespaces,
        XMLDSIG_NS,
    )?;
    let ec_key_value_namespaces =
        xml_element_namespace_scope(key_value_xml, ec_key_value_span, &key_value_namespaces)?;
    ensure_xml_element_attributes_allowed(key_value_xml, ec_key_value_span, &[])?;
    ensure_direct_xml_child_elements(
        key_value_xml,
        ec_key_value_span,
        &["NamedCurve", "PublicKey"],
    )?;
    for ec_key_value_element in ["NamedCurve", "PublicKey"] {
        if find_xml_element_outside_span(key_value_xml, ec_key_value_span, ec_key_value_element) {
            return Err(MsgError::ValidationFailed);
        }
    }
    let ec_key_value_xml = &key_value_xml[ec_key_value_span.start..ec_key_value_span.end];
    let named_curve_span = required_single_xml_element(ec_key_value_xml, "NamedCurve")?;
    ensure_xml_element_prefixed_namespace(
        ec_key_value_xml,
        named_curve_span,
        &ec_key_value_namespaces,
        XMLDSIG_NS,
    )?;
    ensure_xml_element_attributes_allowed(ec_key_value_xml, named_curve_span, &["URI"])?;
    ensure_xml_element_content_empty(ec_key_value_xml, named_curve_span)?;
    if element_attr(ec_key_value_xml, named_curve_span, "URI").as_deref()
        != Some(XMLDSIG_P256_NAMED_CURVE)
    {
        return Err(MsgError::ValidationFailed);
    }
    let public_key_span = required_single_xml_element(ec_key_value_xml, "PublicKey")?;
    ensure_xml_element_prefixed_namespace(
        ec_key_value_xml,
        public_key_span,
        &ec_key_value_namespaces,
        XMLDSIG_NS,
    )?;
    ensure_xml_element_attributes_allowed(ec_key_value_xml, public_key_span, &[])?;
    ensure_xml_element_text_only(ec_key_value_xml, public_key_span)?;
    required_single_child_text_compact(ec_key_value_xml, "PublicKey")?;
    Ok(())
}
fn xml_signature_x509_certificates_with_namespaces(
    key_info_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<Vec<Vec<u8>>, MsgError> {
    if find_first_xml_element(key_info_xml, "KeyValue").is_some()
        || find_first_xml_element(key_info_xml, "PublicKey").is_some()
    {
        return Err(MsgError::ValidationFailed);
    }
    let key_info_span = required_single_xml_element(key_info_xml, "KeyInfo")?;
    ensure_xml_element_prefixed_namespace(
        key_info_xml,
        key_info_span,
        inherited_namespaces,
        XMLDSIG_NS,
    )?;
    let key_info_namespaces =
        xml_element_namespace_scope(key_info_xml, key_info_span, inherited_namespaces)?;
    ensure_xml_element_attributes_allowed(key_info_xml, key_info_span, &[])?;
    ensure_direct_xml_child_elements(key_info_xml, key_info_span, &["X509Data"])?;
    let x509_data_span = required_single_xml_element(key_info_xml, "X509Data")?;
    ensure_xml_element_prefixed_namespace(
        key_info_xml,
        x509_data_span,
        &key_info_namespaces,
        XMLDSIG_NS,
    )?;
    let x509_data_namespaces =
        xml_element_namespace_scope(key_info_xml, x509_data_span, &key_info_namespaces)?;
    ensure_xml_element_attributes_allowed(key_info_xml, x509_data_span, &[])?;
    ensure_direct_xml_child_elements(
        key_info_xml,
        x509_data_span,
        &[
            "X509Certificate",
            "X509CRL",
            "OCSPResponse",
            "EncapsulatedOCSPValue",
        ],
    )?;
    for x509_child in [
        "X509Certificate",
        "X509CRL",
        "OCSPResponse",
        "EncapsulatedOCSPValue",
    ] {
        if find_xml_element_outside_span(key_info_xml, x509_data_span, x509_child) {
            return Err(MsgError::ValidationFailed);
        }
    }
    let x509_data_xml = &key_info_xml[x509_data_span.start..x509_data_span.end];
    decode_child_base64_values_with_namespaces(
        x509_data_xml,
        "X509Certificate",
        &x509_data_namespaces,
    )
}
fn find_xml_element_outside_span(container: &str, allowed: XmlElementSpan, local: &str) -> bool {
    find_first_xml_element(&container[..allowed.start], local).is_some()
        || find_first_xml_element(&container[allowed.end..], local).is_some()
}
fn validate_ocsp_response_signature(
    response: &ParsedOcspResponse<'_>,
    issuer: &X509Certificate<'_>,
    evaluation_time: ASN1Time,
) -> Result<(), MsgError> {
    if response.signature_algorithm_oid != OID_ECDSA_WITH_SHA256_DER {
        return Err(MsgError::ValidationFailed);
    }
    if ocsp_responder_id_matches_certificate(&response.responder_id, issuer)? {
        return verify_ocsp_signature_with_certificate(response, issuer);
    }
    for certificate_der in &response.responder_certificates {
        let responder = parse_x509_certificate_der(certificate_der)?;
        validate_x509_certificate_critical_extensions(&responder)?;
        if !responder.validity().is_valid_at(evaluation_time)
            || responder.issuer() != issuer.subject()
            || !x509_certificate_allows_ocsp_signing(&responder)?
            || !ocsp_responder_id_matches_certificate(&response.responder_id, &responder)?
        {
            continue;
        }
        verify_x509_certificate_signature(&responder, issuer)?;
        verify_ocsp_signature_with_certificate(response, &responder)?;
        return Ok(());
    }
    Err(MsgError::ValidationFailed)
}
fn verify_ocsp_signature_with_certificate(
    response: &ParsedOcspResponse<'_>,
    signer: &X509Certificate<'_>,
) -> Result<(), MsgError> {
    let public_key = signer.public_key().subject_public_key.data.to_vec();
    let verifying_key = parse_p256_verifying_key(&public_key)?;
    let signature = decode_p256_der_signature(response.signature_value)?;
    verifying_key
        .verify(response.tbs_response_data, &signature)
        .map_err(|_| MsgError::ValidationFailed)
}
fn x509_certificate_allows_ocsp_signing(
    certificate: &X509Certificate<'_>,
) -> Result<bool, MsgError> {
    let Some(eku) = certificate
        .extended_key_usage()
        .map_err(|_| MsgError::ValidationFailed)?
    else {
        return Ok(false);
    };
    let Some(key_usage) = certificate
        .key_usage()
        .map_err(|_| MsgError::ValidationFailed)?
    else {
        return Ok(false);
    };
    if !key_usage.critical {
        return Ok(false);
    }
    Ok(eku.value.ocsp_signing && key_usage.value.digital_signature())
}
fn ocsp_responder_id_matches_certificate(
    responder_id: &OcspResponderId<'_>,
    certificate: &X509Certificate<'_>,
) -> Result<bool, MsgError> {
    match responder_id {
        OcspResponderId::ByName(name) => Ok(*name == certificate.subject().as_raw()),
        OcspResponderId::ByKey(key_hash) => {
            let public_key = certificate.public_key().subject_public_key.data.as_ref();
            let digest = Sha1::digest(public_key);
            Ok(*key_hash == &digest[..])
        }
    }
}
fn ocsp_cert_id_matches_leaf(
    response: &ParsedOcspSingleResponse<'_>,
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> bool {
    let issuer_name_hash = Sha256::digest(issuer.subject().as_raw());
    let issuer_key_hash = Sha256::digest(issuer.public_key().subject_public_key.data.as_ref());
    response.serial == leaf.raw_serial()
        && response.issuer_name_hash == &issuer_name_hash[..]
        && response.issuer_key_hash == &issuer_key_hash[..]
}
fn validate_ocsp_response_freshness(
    produced_at: ASN1Time,
    response: &ParsedOcspSingleResponse<'_>,
    evaluation_time: ASN1Time,
) -> Result<(), MsgError> {
    if produced_at > evaluation_time
        || response.this_update > evaluation_time
        || response.next_update < evaluation_time
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn parse_ocsp_response_der(ocsp_response_der: &[u8]) -> Result<ParsedOcspResponse<'_>, MsgError> {
    let response = der_expect_single(ocsp_response_der, 0x30)?;
    let mut response_content = response.value;
    let response_status = der_read_required_integer(&mut response_content, 0x0A)?;
    if response_status != 0 {
        return Err(MsgError::ValidationFailed);
    }
    let response_bytes = der_read_required(&mut response_content, 0xA0)?;
    if !response_content.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    let response_bytes = der_expect_single(response_bytes.value, 0x30)?;
    let mut response_bytes_content = response_bytes.value;
    let response_type = der_read_required(&mut response_bytes_content, 0x06)?;
    if response_type.value != OID_OCSP_BASIC_RESPONSE_DER {
        return Err(MsgError::ValidationFailed);
    }
    let basic_response = der_read_required(&mut response_bytes_content, 0x04)?;
    if !response_bytes_content.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    parse_ocsp_basic_response_der(basic_response.value)
}
fn parse_ocsp_basic_response_der(
    basic_response_der: &[u8],
) -> Result<ParsedOcspResponse<'_>, MsgError> {
    let basic_response = der_expect_single(basic_response_der, 0x30)?;
    let mut content = basic_response.value;
    let tbs_response_data = der_read_required(&mut content, 0x30)?;
    let (responder_id, produced_at, responses) = parse_ocsp_response_data(tbs_response_data.value)?;
    let signature_algorithm_oid = der_read_algorithm_identifier(&mut content)?;
    let signature_value = der_read_bit_string(&mut content)?;
    let responder_certificates = if content.first() == Some(&0xA0) {
        parse_ocsp_responder_certificates(der_read_required(&mut content, 0xA0)?.value)?
    } else {
        Vec::new()
    };
    if !content.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(ParsedOcspResponse {
        responder_id,
        produced_at,
        responses,
        tbs_response_data: tbs_response_data.full,
        signature_algorithm_oid,
        signature_value,
        responder_certificates,
    })
}
fn parse_ocsp_response_data<'a>(
    response_data: &'a [u8],
) -> Result<
    (
        OcspResponderId<'a>,
        ASN1Time,
        Vec<ParsedOcspSingleResponse<'a>>,
    ),
    MsgError,
> {
    let mut content = response_data;
    if content.first() == Some(&0xA0) {
        let _version = der_read_required(&mut content, 0xA0)?;
    }
    let responder_id = parse_ocsp_responder_id(&mut content)?;
    let produced_at = der_read_asn1_time(&mut content, 0x18)?;
    let responses = der_read_required(&mut content, 0x30)?;
    let responses = parse_ocsp_single_responses(responses.value)?;
    if content.first() == Some(&0xA1) {
        return Err(MsgError::ValidationFailed);
    }
    if !content.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    Ok((responder_id, produced_at, responses))
}
fn parse_ocsp_responder_id<'a>(content: &mut &'a [u8]) -> Result<OcspResponderId<'a>, MsgError> {
    let element = der_read_element(content)?;
    match element.tag {
        0xA1 => {
            let name = der_expect_single(element.value, 0x30)?;
            Ok(OcspResponderId::ByName(name.full))
        }
        0x82 => Ok(OcspResponderId::ByKey(element.value)),
        0xA2 => {
            let key_hash = der_expect_single(element.value, 0x04)?;
            Ok(OcspResponderId::ByKey(key_hash.value))
        }
        _ => Err(MsgError::ValidationFailed),
    }
}
fn parse_ocsp_single_responses(
    responses_der: &[u8],
) -> Result<Vec<ParsedOcspSingleResponse<'_>>, MsgError> {
    let mut responses_content = responses_der;
    let mut responses = Vec::new();
    while !responses_content.is_empty() {
        let response = der_read_required(&mut responses_content, 0x30)?;
        responses.push(parse_ocsp_single_response(response.value)?);
    }
    if responses.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(responses)
}
fn parse_ocsp_single_response(
    response_der: &[u8],
) -> Result<ParsedOcspSingleResponse<'_>, MsgError> {
    let mut content = response_der;
    let cert_id = der_read_required(&mut content, 0x30)?;
    let (issuer_name_hash, issuer_key_hash, serial) = parse_ocsp_cert_id(cert_id.value)?;
    let status = parse_ocsp_cert_status(&mut content)?;
    let this_update = der_read_asn1_time(&mut content, 0x18)?;
    let next_update = if content.first() == Some(&0xA0) {
        let next_update = der_read_required(&mut content, 0xA0)?;
        der_read_asn1_time_single(next_update.value, 0x18)?
    } else {
        return Err(MsgError::ValidationFailed);
    };
    if content.first() == Some(&0xA1) {
        return Err(MsgError::ValidationFailed);
    }
    if !content.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(ParsedOcspSingleResponse {
        issuer_name_hash,
        issuer_key_hash,
        serial,
        status,
        this_update,
        next_update,
    })
}
fn parse_ocsp_cert_id(cert_id_der: &[u8]) -> Result<(&[u8], &[u8], &[u8]), MsgError> {
    let mut content = cert_id_der;
    let hash_algorithm_oid = der_read_algorithm_identifier(&mut content)?;
    if hash_algorithm_oid != OID_SHA256_DER {
        return Err(MsgError::ValidationFailed);
    }
    let issuer_name_hash = der_read_required(&mut content, 0x04)?;
    let issuer_key_hash = der_read_required(&mut content, 0x04)?;
    let serial = der_read_required(&mut content, 0x02)?;
    if issuer_name_hash.value.is_empty()
        || issuer_key_hash.value.is_empty()
        || serial.value.is_empty()
        || !content.is_empty()
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok((issuer_name_hash.value, issuer_key_hash.value, serial.value))
}
fn parse_ocsp_cert_status(content: &mut &[u8]) -> Result<OcspCertStatus, MsgError> {
    let status = der_read_element(content)?;
    match status.tag {
        0x80 => {
            if !status.value.is_empty() {
                return Err(MsgError::ValidationFailed);
            }
            Ok(OcspCertStatus::Good)
        }
        0xA1 | 0x81 => Ok(OcspCertStatus::Revoked),
        0x82 => {
            if !status.value.is_empty() {
                return Err(MsgError::ValidationFailed);
            }
            Ok(OcspCertStatus::Unknown)
        }
        _ => Err(MsgError::ValidationFailed),
    }
}
fn parse_ocsp_responder_certificates(certs_der: &[u8]) -> Result<Vec<&[u8]>, MsgError> {
    let certs = der_expect_single(certs_der, 0x30)?;
    let mut content = certs.value;
    let mut certificates = Vec::new();
    while !content.is_empty() {
        let certificate = der_read_required(&mut content, 0x30)?;
        parse_x509_certificate_der(certificate.full)?;
        certificates.push(certificate.full);
    }
    Ok(certificates)
}
#[derive(Clone, Copy, Debug)]
struct DerElement<'a> {
    tag: u8,
    value: &'a [u8],
    full: &'a [u8],
}
fn der_expect_single(input: &[u8], tag: u8) -> Result<DerElement<'_>, MsgError> {
    let mut content = input;
    let element = der_read_required(&mut content, tag)?;
    if !content.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(element)
}
fn der_read_required<'a>(input: &mut &'a [u8], tag: u8) -> Result<DerElement<'a>, MsgError> {
    let element = der_read_element(input)?;
    if element.tag != tag {
        return Err(MsgError::ValidationFailed);
    }
    Ok(element)
}
fn der_read_element<'a>(input: &mut &'a [u8]) -> Result<DerElement<'a>, MsgError> {
    if input.len() < 2 {
        return Err(MsgError::ValidationFailed);
    }
    let start = *input;
    let tag = start[0];
    let length_byte = start[1];
    let (length, header_len) = if length_byte & 0x80 == 0 {
        (usize::from(length_byte), 2)
    } else {
        let length_len = usize::from(length_byte & 0x7F);
        if length_len == 0 || length_len > 4 || start.len() < 2 + length_len {
            return Err(MsgError::ValidationFailed);
        }
        if length_len > 1 && start[2] == 0 {
            return Err(MsgError::ValidationFailed);
        }
        let mut length = 0usize;
        for byte in &start[2..2 + length_len] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(MsgError::ValidationFailed)?;
        }
        if length < 128 {
            return Err(MsgError::ValidationFailed);
        }
        (length, 2 + length_len)
    };
    let end = header_len
        .checked_add(length)
        .ok_or(MsgError::ValidationFailed)?;
    if start.len() < end {
        return Err(MsgError::ValidationFailed);
    }
    let full = &start[..end];
    *input = &start[end..];
    Ok(DerElement {
        tag,
        value: &start[header_len..end],
        full,
    })
}
fn der_read_required_integer(input: &mut &[u8], tag: u8) -> Result<u64, MsgError> {
    let element = der_read_required(input, tag)?;
    der_integer_value(element.value)
}
fn der_integer_value(value: &[u8]) -> Result<u64, MsgError> {
    if value.is_empty() || value.len() > 8 || value[0] & 0x80 != 0 {
        return Err(MsgError::ValidationFailed);
    }
    if value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
        return Err(MsgError::ValidationFailed);
    }
    let mut result = 0u64;
    for byte in value {
        result = result
            .checked_mul(256)
            .and_then(|current| current.checked_add(u64::from(*byte)))
            .ok_or(MsgError::ValidationFailed)?;
    }
    Ok(result)
}
fn der_read_algorithm_identifier<'a>(content: &mut &'a [u8]) -> Result<&'a [u8], MsgError> {
    let algorithm = der_read_required(content, 0x30)?;
    let mut algorithm_content = algorithm.value;
    let oid = der_read_required(&mut algorithm_content, 0x06)?;
    if !algorithm_content.is_empty() {
        let null = der_read_required(&mut algorithm_content, 0x05)?;
        if !null.value.is_empty() || !algorithm_content.is_empty() {
            return Err(MsgError::ValidationFailed);
        }
    }
    Ok(oid.value)
}
fn der_read_bit_string<'a>(content: &mut &'a [u8]) -> Result<&'a [u8], MsgError> {
    let bit_string = der_read_required(content, 0x03)?;
    if bit_string.value.first() != Some(&0) {
        return Err(MsgError::ValidationFailed);
    }
    Ok(&bit_string.value[1..])
}
fn der_read_asn1_time(content: &mut &[u8], tag: u8) -> Result<ASN1Time, MsgError> {
    let time = der_read_required(content, tag)?;
    der_asn1_time(time)
}
fn der_read_asn1_time_single(content: &[u8], tag: u8) -> Result<ASN1Time, MsgError> {
    let time = der_expect_single(content, tag)?;
    der_asn1_time(time)
}
fn der_asn1_time(time: DerElement<'_>) -> Result<ASN1Time, MsgError> {
    let (remaining, time) =
        ASN1Time::from_der(time.full).map_err(|_| MsgError::ValidationFailed)?;
    if !remaining.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(time)
}
fn x509_leaf_issuer_certificate<'a>(
    certificate_chain: &'a [Vec<u8>],
) -> Result<X509Certificate<'a>, MsgError> {
    let leaf = parse_x509_certificate_der(&certificate_chain[0])?;
    if let Some(issuer_der) = certificate_chain.get(1) {
        let issuer = parse_x509_certificate_der(issuer_der)?;
        if leaf.issuer() != issuer.subject() || !x509_certificate_is_ca(&issuer)? {
            return Err(MsgError::ValidationFailed);
        }
        verify_x509_certificate_signature(&leaf, &issuer)?;
        return Ok(issuer);
    }
    if leaf.issuer() == leaf.subject() {
        verify_x509_certificate_signature(&leaf, &leaf)?;
        return Ok(leaf);
    }
    Err(MsgError::ValidationFailed)
}
fn validate_x509_crl_freshness(
    crl: &CertificateRevocationList<'_>,
    evaluation_time: ASN1Time,
) -> Result<(), MsgError> {
    if crl.last_update() > evaluation_time {
        return Err(MsgError::ValidationFailed);
    }
    let Some(next_update) = crl.next_update() else {
        return Err(MsgError::ValidationFailed);
    };
    if next_update < evaluation_time {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn parse_x509_certificate_der(certificate_der: &[u8]) -> Result<X509Certificate<'_>, MsgError> {
    let (remaining, certificate) =
        X509Certificate::from_der(certificate_der).map_err(|_| MsgError::ValidationFailed)?;
    if !remaining.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(certificate)
}
fn parse_x509_crl_der(crl_der: &[u8]) -> Result<CertificateRevocationList<'_>, MsgError> {
    let (remaining, crl) =
        CertificateRevocationList::from_der(crl_der).map_err(|_| MsgError::ValidationFailed)?;
    if !remaining.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(crl)
}
fn x509_certificate_is_ca(certificate: &X509Certificate<'_>) -> Result<bool, MsgError> {
    let Some(basic_constraints) = certificate
        .basic_constraints()
        .map_err(|_| MsgError::ValidationFailed)?
    else {
        return Ok(false);
    };
    if !basic_constraints.critical {
        return Ok(false);
    }
    if !basic_constraints.value.ca {
        return Ok(false);
    }
    let Some(key_usage) = certificate
        .key_usage()
        .map_err(|_| MsgError::ValidationFailed)?
    else {
        return Ok(false);
    };
    if !key_usage.critical {
        return Ok(false);
    }
    Ok(key_usage.value.key_cert_sign())
}
fn x509_certificate_allows_crl_sign(certificate: &X509Certificate<'_>) -> Result<bool, MsgError> {
    let Some(key_usage) = certificate
        .key_usage()
        .map_err(|_| MsgError::ValidationFailed)?
    else {
        return Ok(false);
    };
    Ok(key_usage.value.crl_sign())
}
fn x509_certificate_allows_xml_signature_purpose(
    certificate: &X509Certificate<'_>,
) -> Result<bool, MsgError> {
    let Some(eku) = certificate
        .extended_key_usage()
        .map_err(|_| MsgError::ValidationFailed)?
    else {
        return Ok(true);
    };
    Ok(eku.value.any
        || eku.value.code_signing
        || eku
            .value
            .other
            .iter()
            .any(|oid| oid.to_string() == X509_EKU_DOCUMENT_SIGNING_OID))
}
fn x509_certificate_satisfies_policy_oids(
    certificate: &X509Certificate<'_>,
    required_policy_oids: &[String],
) -> Result<bool, MsgError> {
    if required_policy_oids.is_empty() {
        return Ok(true);
    }
    let Some(present) = x509_certificate_policy_oids(certificate)? else {
        return Ok(false);
    };
    Ok(required_policy_oids
        .iter()
        .all(|required| present.contains(required)))
}
fn validate_x509_required_certificate_policy_path(
    certificate_chain: &[X509Certificate<'_>],
    required_policy_oids: &[String],
) -> Result<(), MsgError> {
    if required_policy_oids.is_empty() || certificate_chain.len() <= 2 {
        return Ok(());
    }
    for intermediate in &certificate_chain[1..certificate_chain.len() - 1] {
        let Some(present) = x509_certificate_policy_oids(intermediate)? else {
            return Err(MsgError::ValidationFailed);
        };
        if present.contains(X509_ANY_POLICY_OID) {
            continue;
        }
        if !required_policy_oids
            .iter()
            .all(|required| present.contains(required))
        {
            return Err(MsgError::ValidationFailed);
        }
    }
    Ok(())
}
fn x509_certificate_policy_oids(
    certificate: &X509Certificate<'_>,
) -> Result<Option<HashSet<String>>, MsgError> {
    let mut policy_extension_count = 0usize;
    let mut present = HashSet::new();
    for extension in certificate.extensions() {
        if let ParsedExtension::CertificatePolicies(policies) = extension.parsed_extension() {
            policy_extension_count += 1;
            for policy in policies {
                if !present.insert(policy.policy_id.to_string()) {
                    return Err(MsgError::ValidationFailed);
                }
            }
        }
    }
    match policy_extension_count {
        0 => Ok(None),
        1 => Ok(Some(present)),
        _ => Err(MsgError::ValidationFailed),
    }
}
fn validate_x509_certificate_critical_extensions(
    certificate: &X509Certificate<'_>,
) -> Result<(), MsgError> {
    ensure_no_unsupported_x509_policy_processing_extensions(certificate)?;
    for extension in certificate.extensions() {
        if !extension.critical {
            continue;
        }
        match extension.parsed_extension() {
            ParsedExtension::UnsupportedExtension { .. }
            | ParsedExtension::ParseError { .. }
            | ParsedExtension::Unparsed => return Err(MsgError::ValidationFailed),
            _ => {}
        }
    }
    Ok(())
}
fn ensure_no_unsupported_x509_policy_processing_extensions(
    certificate: &X509Certificate<'_>,
) -> Result<(), MsgError> {
    for extension in certificate.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::PolicyMappings(_)
            | ParsedExtension::PolicyConstraints(_)
            | ParsedExtension::InhibitAnyPolicy(_) => return Err(MsgError::ValidationFailed),
            _ => {}
        }
    }
    Ok(())
}
fn verify_x509_certificate_signature(
    certificate: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), MsgError> {
    if certificate.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256
        || certificate.tbs_certificate.signature.algorithm != OID_SIG_ECDSA_WITH_SHA256
    {
        return Err(MsgError::ValidationFailed);
    }
    let issuer_public_key = issuer.public_key().subject_public_key.data.to_vec();
    let verifying_key = parse_p256_verifying_key(&issuer_public_key)?;
    let signature = decode_p256_der_signature(&certificate.signature_value.data)?;
    verifying_key
        .verify(certificate.tbs_certificate.as_ref(), &signature)
        .map_err(|_| MsgError::ValidationFailed)
}
fn verify_x509_crl_signature(
    crl: &CertificateRevocationList<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), MsgError> {
    if crl.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256
        || crl.tbs_cert_list.signature.algorithm != OID_SIG_ECDSA_WITH_SHA256
    {
        return Err(MsgError::ValidationFailed);
    }
    let issuer_public_key = issuer.public_key().subject_public_key.data.to_vec();
    let verifying_key = parse_p256_verifying_key(&issuer_public_key)?;
    let signature = decode_p256_der_signature(&crl.signature_value.data)?;
    verifying_key
        .verify(crl.tbs_cert_list.as_ref(), &signature)
        .map_err(|_| MsgError::ValidationFailed)
}
#[cfg(test)]
fn decode_required_child_base64(container: &str, child: &str) -> Result<Vec<u8>, MsgError> {
    let span = required_single_xml_element(container, child)?;
    ensure_xml_element_attributes_allowed(container, span, &[])?;
    ensure_xml_element_text_only(container, span)?;
    let value: String = container[span.content_start..span.content_end]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    BASE64_STANDARD
        .decode(value)
        .map_err(|_| MsgError::ValidationFailed)
}
fn decode_child_base64_values_with_namespaces(
    container: &str,
    child: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<Vec<Vec<u8>>, MsgError> {
    child_base64_text_values_with_namespaces(container, child, inherited_namespaces, &[XMLDSIG_NS])?
        .into_iter()
        .map(|value| {
            BASE64_STANDARD
                .decode(value)
                .map_err(|_| MsgError::ValidationFailed)
        })
        .collect()
}
fn child_base64_text_values_with_namespaces(
    container: &str,
    child: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
    allowed_namespaces: &[&str],
) -> Result<Vec<String>, MsgError> {
    let mut values = Vec::new();
    let mut cursor = 0usize;
    while cursor < container.len() {
        let Some(span) = find_first_xml_element(&container[cursor..], child) else {
            break;
        };
        let absolute = XmlElementSpan {
            start: cursor + span.start,
            opening_end: cursor + span.opening_end,
            content_start: cursor + span.content_start,
            content_end: cursor + span.content_end,
            end: cursor + span.end,
        };
        ensure_xml_element_any_namespace(
            container,
            absolute,
            inherited_namespaces,
            allowed_namespaces,
        )?;
        ensure_xml_element_attributes_allowed(container, absolute, &[])?;
        ensure_xml_element_text_only(container, absolute)?;
        let value: String = container[absolute.content_start..absolute.content_end]
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        values.push(value);
        cursor = absolute.end;
    }
    Ok(values)
}
fn ensure_xml_element_any_namespace(
    container: &str,
    span: XmlElementSpan,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
    allowed_namespaces: &[&str],
) -> Result<(), MsgError> {
    if allowed_namespaces.iter().any(|namespace| {
        ensure_xml_element_prefixed_namespace(container, span, inherited_namespaces, namespace)
            .is_ok()
    }) {
        Ok(())
    } else {
        Err(MsgError::ValidationFailed)
    }
}
#[cfg(test)]
fn xml_signature_evaluation_time(
    parsed: &ParsedMessage,
    signed_properties_xml: Option<&str>,
) -> Result<Option<ASN1Time>, MsgError> {
    let signed_properties = signed_properties_xml.map(|xml| VerifiedSignedProperties {
        xml,
        inherited_namespaces: Vec::new(),
    });
    xml_signature_evaluation_time_for_verified_properties(parsed, signed_properties.as_ref())
}
fn xml_signature_evaluation_time_for_verified_properties(
    parsed: &ParsedMessage,
    signed_properties: Option<&VerifiedSignedProperties<'_>>,
) -> Result<Option<ASN1Time>, MsgError> {
    let signed_properties_time = signed_properties
        .map(|properties| {
            xades_signed_properties_signing_time_with_namespaces(
                properties.xml,
                &properties.inherited_namespaces,
            )
        })
        .transpose()?
        .flatten();
    signed_properties_time
        .or_else(|| app_header_creation_date(parsed).map(ToOwned::to_owned))
        .map(|value| parse_iso_datetime_as_asn1_time(&value))
        .transpose()
}
#[cfg(test)]
fn xades_signed_properties_signing_time(
    signed_properties_xml: &str,
) -> Result<Option<String>, MsgError> {
    xades_signed_properties_signing_time_with_namespaces(signed_properties_xml, &[])
}
fn xades_signed_properties_signing_time_with_namespaces(
    signed_properties_xml: &str,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<Option<String>, MsgError> {
    let signed_signature_properties = xades_signed_signature_properties_with_namespaces(
        signed_properties_xml,
        inherited_namespaces,
    )?;
    let signed_signature_properties_xml = signed_signature_properties.xml;
    let signed_signature_properties_span =
        required_single_xml_element(signed_signature_properties_xml, "SignedSignatureProperties")?;
    let Some(signing_time) = optional_direct_xml_child_element(
        signed_signature_properties_xml,
        signed_signature_properties_span,
        "SigningTime",
    )?
    else {
        return Ok(None);
    };
    ensure_xades_element_prefixed_namespace(
        signed_signature_properties_xml,
        signing_time,
        &signed_signature_properties.namespaces,
    )?;
    ensure_xml_element_attributes_allowed(signed_signature_properties_xml, signing_time, &[])?;
    ensure_xml_element_text_only(signed_signature_properties_xml, signing_time)?;
    Ok(Some(
        signed_signature_properties_xml[signing_time.content_start..signing_time.content_end]
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect(),
    ))
}
fn parse_iso_datetime_as_asn1_time(value: &str) -> Result<ASN1Time, MsgError> {
    let value = value.trim();
    let (date_part, rest) = value.split_once('T').ok_or(MsgError::ValidationFailed)?;
    let date_bytes = date_part.as_bytes();
    if date_bytes.len() != 10 || date_bytes[4] != b'-' || date_bytes[7] != b'-' {
        return Err(MsgError::ValidationFailed);
    }
    let year: i32 = parse_ascii_decimal(&date_bytes[0..4])?;
    let month: u8 = parse_ascii_decimal(&date_bytes[5..7])?;
    let day: u8 = parse_ascii_decimal(&date_bytes[8..10])?;
    let (time_part, offset) = if let Some(time_part) = rest.strip_suffix('Z') {
        (time_part, UtcOffset::UTC)
    } else if let Some(offset_idx) = rest.rfind(['+', '-']) {
        let offset_literal = &rest[offset_idx..];
        let offset_bytes = offset_literal.as_bytes();
        if offset_bytes.len() != 6
            || !matches!(offset_bytes[0], b'+' | b'-')
            || offset_bytes[3] != b':'
        {
            return Err(MsgError::ValidationFailed);
        }
        let sign = if offset_bytes[0] == b'-' { -1 } else { 1 };
        let hours: i8 = parse_ascii_decimal(&offset_bytes[1..3])?;
        let minutes: i8 = parse_ascii_decimal(&offset_bytes[4..6])?;
        let offset = UtcOffset::from_hms(sign * hours, sign * minutes, 0)
            .map_err(|_| MsgError::ValidationFailed)?;
        (&rest[..offset_idx], offset)
    } else {
        return Err(MsgError::ValidationFailed);
    };
    let mut pieces = time_part.split(':');
    let hour_literal = pieces
        .next()
        .filter(|value| value.len() == 2)
        .ok_or(MsgError::ValidationFailed)?;
    let hour: u8 = parse_ascii_decimal(hour_literal.as_bytes())?;
    let minute_literal = pieces
        .next()
        .filter(|value| value.len() == 2)
        .ok_or(MsgError::ValidationFailed)?;
    let minute: u8 = parse_ascii_decimal(minute_literal.as_bytes())?;
    let second_fragment = pieces.next().ok_or(MsgError::ValidationFailed)?;
    if pieces.next().is_some() {
        return Err(MsgError::ValidationFailed);
    }
    let second_literal = if let Some((second, fraction)) = second_fragment.split_once('.') {
        if fraction.is_empty() || !fraction.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(MsgError::ValidationFailed);
        }
        second
    } else {
        second_fragment
    };
    if second_literal.len() != 2 {
        return Err(MsgError::ValidationFailed);
    }
    let second: u8 = parse_ascii_decimal(second_literal.as_bytes())?;
    let date = Date::from_calendar_date(
        year,
        Month::try_from(month).map_err(|_| MsgError::ValidationFailed)?,
        day,
    )
    .map_err(|_| MsgError::ValidationFailed)?;
    let time = Time::from_hms(hour, minute, second).map_err(|_| MsgError::ValidationFailed)?;
    let timestamp = PrimitiveDateTime::new(date, time)
        .assume_offset(offset)
        .to_offset(UtcOffset::UTC)
        .unix_timestamp();
    ASN1Time::from_timestamp(timestamp).map_err(|_| MsgError::ValidationFailed)
}
fn parse_ascii_decimal<T: std::str::FromStr>(value: &[u8]) -> Result<T, MsgError> {
    if value.is_empty() || !value.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(MsgError::ValidationFailed);
    }
    std::str::from_utf8(value)
        .map_err(|_| MsgError::ValidationFailed)?
        .parse()
        .map_err(|_| MsgError::ValidationFailed)
}
fn ensure_xml_signature_leaf_certificate_policy(
    certificate: &X509Certificate<'_>,
) -> Result<(), MsgError> {
    if matches!(
        certificate
            .basic_constraints()
            .map_err(|_| MsgError::ValidationFailed)?,
        Some(basic_constraints) if basic_constraints.value.ca
    ) {
        return Err(MsgError::ValidationFailed);
    }
    let leaf_allows_signature_purpose = x509_certificate_allows_xml_signature_purpose(certificate)?;
    match certificate
        .key_usage()
        .map_err(|_| MsgError::ValidationFailed)?
    {
        Some(key_usage)
            if key_usage.critical
                && key_usage.value.digital_signature()
                && leaf_allows_signature_purpose =>
        {
            Ok(())
        }
        _ => Err(MsgError::ValidationFailed),
    }
}
fn ensure_xml_signature_certificate_valid_at(
    certificate: &X509Certificate<'_>,
    evaluation_time: ASN1Time,
) -> Result<(), MsgError> {
    certificate
        .validity()
        .is_valid_at(evaluation_time)
        .then_some(())
        .ok_or(MsgError::ValidationFailed)
}
fn ensure_xml_signature_certificate_issued_by(
    certificate: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), MsgError> {
    (certificate.issuer().as_raw() == issuer.subject().as_raw())
        .then_some(())
        .ok_or(MsgError::ValidationFailed)
}
fn ensure_xml_signature_supported_certificate_algorithm(
    certificate: &X509Certificate<'_>,
) -> Result<(), MsgError> {
    if certificate.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256 {
        return Err(MsgError::ValidationFailed);
    }
    let public_key = certificate.public_key();
    let public_key_algorithm = &public_key.algorithm;
    if public_key_algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return Err(MsgError::ValidationFailed);
    }
    match public_key_algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
    {
        Some(curve_oid) if curve_oid == OID_EC_P256 => {
            ensure_xml_signature_p256_public_key(public_key.subject_public_key.data.as_ref())
        }
        _ => Err(MsgError::ValidationFailed),
    }
}
fn ensure_xml_signature_issuer_certificate_policy(
    certificate: &X509Certificate<'_>,
) -> Result<(), MsgError> {
    match certificate
        .basic_constraints()
        .map_err(|_| MsgError::ValidationFailed)?
    {
        Some(basic_constraints) if basic_constraints.critical && basic_constraints.value.ca => {}
        _ => return Err(MsgError::ValidationFailed),
    }
    match certificate
        .key_usage()
        .map_err(|_| MsgError::ValidationFailed)?
    {
        Some(key_usage) if key_usage.critical && key_usage.value.key_cert_sign() => Ok(()),
        _ => Err(MsgError::ValidationFailed),
    }
}
fn ensure_xml_signature_issuer_path_len(
    certificate: &X509Certificate<'_>,
    subordinate_ca_count: usize,
) -> Result<(), MsgError> {
    let Some(basic_constraints) = certificate
        .basic_constraints()
        .map_err(|_| MsgError::ValidationFailed)?
    else {
        return Err(MsgError::ValidationFailed);
    };
    match basic_constraints.value.path_len_constraint {
        Some(path_len_constraint) if subordinate_ca_count > path_len_constraint as usize => {
            Err(MsgError::ValidationFailed)
        }
        _ => Ok(()),
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum XmlSignatureCertificateRole {
    Leaf,
    Issuer,
}
fn ensure_xml_signature_supported_critical_extensions(
    certificate: &X509Certificate<'_>,
    role: XmlSignatureCertificateRole,
) -> Result<(), MsgError> {
    ensure_no_unsupported_x509_policy_processing_extensions(certificate)?;
    for extension in certificate.extensions() {
        if !extension.critical {
            continue;
        }
        match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(_) | ParsedExtension::KeyUsage(_) => {}
            ParsedExtension::ExtendedKeyUsage(_) if role == XmlSignatureCertificateRole::Leaf => {}
            ParsedExtension::UnsupportedExtension { .. }
            | ParsedExtension::ParseError { .. }
            | ParsedExtension::Unparsed => return Err(MsgError::ValidationFailed),
            _ => return Err(MsgError::ValidationFailed),
        }
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CanonicalXmlAttributeKind {
    Namespace,
    Attribute,
}
#[derive(Debug, Clone)]
struct CanonicalXmlAttribute {
    name: String,
    value: String,
    kind: CanonicalXmlAttributeKind,
}
#[derive(Debug, Clone)]
struct CanonicalXmlNamespaceBinding {
    prefix: String,
    uri: String,
}
#[cfg(test)]
fn canonicalize_supported_xml(xml: &str) -> Result<String, MsgError> {
    canonicalize_supported_xml_with_inherited_namespaces(xml, &[])
}
#[cfg(test)]
fn canonicalize_supported_xml_with_inherited_namespaces(
    xml: &str,
    inherited_namespaces: &[CanonicalXmlAttribute],
) -> Result<String, MsgError> {
    canonicalize_supported_xml_with_mode(xml, inherited_namespaces, CanonicalXmlMode::Exclusive)
}
fn canonicalize_supported_xml_with_mode(
    xml: &str,
    inherited_namespaces: &[CanonicalXmlAttribute],
    mode: CanonicalXmlMode,
) -> Result<String, MsgError> {
    if xml.is_empty()
        || xml.trim() != xml
        || xml.contains("<?")
        || xml.contains("<![CDATA[")
        || xml.contains("]]>")
        || xml.contains('\r')
    {
        return Err(MsgError::ValidationFailed);
    }
    let mut cursor = 0usize;
    let mut output = String::with_capacity(xml.len());
    let mut stack = Vec::new();
    let mut namespace_scope_lengths = Vec::new();
    let mut in_scope_namespaces = Vec::new();
    let mut root_seen = false;
    while cursor < xml.len() {
        let Some(tag_start) = xml[cursor..].find('<').map(|offset| cursor + offset) else {
            let text = &xml[cursor..];
            if stack.is_empty() && !text.is_empty() {
                return Err(MsgError::ValidationFailed);
            }
            push_canonical_xml_text(text, &mut output)?;
            break;
        };
        let text = &xml[cursor..tag_start];
        if stack.is_empty() && !text.is_empty() {
            return Err(MsgError::ValidationFailed);
        }
        push_canonical_xml_text(text, &mut output)?;
        if xml[tag_start..].starts_with("<!--") {
            cursor = find_supported_xml_comment_end(xml, tag_start)? + 3;
            continue;
        }
        let raw_start = tag_start + 1;
        let tag_end =
            find_xml_tag_end(xml.as_bytes(), raw_start).ok_or(MsgError::ValidationFailed)?;
        let raw_tag_literal = &xml[raw_start..tag_end];
        if raw_tag_literal
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
        {
            return Err(MsgError::ValidationFailed);
        }
        let raw_tag = raw_tag_literal.trim();
        if raw_tag.is_empty() || raw_tag.starts_with('?') || raw_tag.starts_with('!') {
            return Err(MsgError::ValidationFailed);
        }
        if let Some(closing_tag) = raw_tag.strip_prefix('/') {
            let name = closing_tag.trim();
            if name.is_empty() || name.split_once(char::is_whitespace).is_some() {
                return Err(MsgError::ValidationFailed);
            }
            ensure_supported_xml_name(name)?;
            match stack.pop() {
                Some(open_name) if open_name == name => {}
                _ => return Err(MsgError::ValidationFailed),
            }
            let namespace_scope_len = namespace_scope_lengths
                .pop()
                .ok_or(MsgError::ValidationFailed)?;
            in_scope_namespaces.truncate(namespace_scope_len);
            output.push_str("</");
            output.push_str(name);
            output.push('>');
        } else {
            let self_closing = raw_tag.ends_with('/');
            let tag_body = if self_closing {
                raw_tag.trim_end_matches('/').trim_end()
            } else {
                raw_tag
            };
            let (name, attributes) = split_supported_xml_tag(tag_body)?;
            ensure_supported_xml_name(name)?;
            let mut attributes = parse_supported_xml_attributes(attributes)?;
            if stack.is_empty() {
                apply_inherited_root_namespaces(name, &mut attributes, inherited_namespaces, mode)?;
            }
            ensure_supported_xml_element_namespace(name, &attributes, &in_scope_namespaces)?;
            sort_and_validate_canonical_xml_attributes(&mut attributes, &in_scope_namespaces)?;
            if stack.is_empty() {
                if root_seen {
                    return Err(MsgError::ValidationFailed);
                }
                root_seen = true;
            }
            push_canonical_xml_start_tag(name, &attributes, &mut output)?;
            if self_closing {
                output.push_str("</");
                output.push_str(name);
                output.push('>');
            } else {
                namespace_scope_lengths.push(in_scope_namespaces.len());
                in_scope_namespaces.extend(
                    attributes
                        .iter()
                        .filter_map(namespace_binding_from_attribute),
                );
                stack.push(name);
            }
        }
        cursor = tag_end + 1;
    }
    if !root_seen || !stack.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(output)
}
fn find_supported_xml_comment_end(xml: &str, start: usize) -> Result<usize, MsgError> {
    let Some(comment_body_start) = xml[start..].strip_prefix("<!--").map(|_| start + 4) else {
        return Err(MsgError::ValidationFailed);
    };
    let comment_end = xml[comment_body_start..]
        .find("-->")
        .map(|offset| comment_body_start + offset)
        .ok_or(MsgError::ValidationFailed)?;
    let comment_body = &xml[comment_body_start..comment_end];
    if comment_body.contains("--") || comment_body.ends_with('-') {
        return Err(MsgError::ValidationFailed);
    }
    Ok(comment_end)
}
fn split_supported_xml_tag(tag_body: &str) -> Result<(&str, &str), MsgError> {
    if let Some((name, attributes)) = tag_body.split_once(char::is_whitespace) {
        if name.is_empty() {
            return Err(MsgError::ValidationFailed);
        }
        Ok((name, attributes))
    } else if tag_body.is_empty() {
        Err(MsgError::ValidationFailed)
    } else {
        Ok((tag_body, ""))
    }
}
fn parse_supported_xml_attributes(
    attributes: &str,
) -> Result<Vec<CanonicalXmlAttribute>, MsgError> {
    let mut parsed = Vec::new();
    let mut cursor = attributes.trim();
    while !cursor.is_empty() {
        let name_end = cursor
            .find(|ch: char| ch.is_whitespace() || ch == '=')
            .ok_or(MsgError::ValidationFailed)?;
        let name = &cursor[..name_end];
        ensure_supported_xml_name(name)?;
        let kind = if name == "xmlns" || name.starts_with("xmlns:") {
            CanonicalXmlAttributeKind::Namespace
        } else {
            CanonicalXmlAttributeKind::Attribute
        };
        cursor = cursor[name_end..].trim_start();
        cursor = cursor
            .strip_prefix('=')
            .ok_or(MsgError::ValidationFailed)?
            .trim_start();
        let quote = cursor
            .chars()
            .next()
            .filter(|quote| matches!(quote, '"' | '\''))
            .ok_or(MsgError::ValidationFailed)?;
        cursor = &cursor[quote.len_utf8()..];
        let value_end = cursor.find(quote).ok_or(MsgError::ValidationFailed)?;
        let value = &cursor[..value_end];
        ensure_supported_xml_attribute_value(value)?;
        if kind == CanonicalXmlAttributeKind::Namespace {
            ensure_supported_xml_namespace_declaration(name, value)?;
        }
        parsed.push(CanonicalXmlAttribute {
            name: name.to_owned(),
            value: value.to_owned(),
            kind,
        });
        cursor = cursor[value_end + quote.len_utf8()..].trim_start();
    }
    Ok(parsed)
}
fn apply_inherited_root_namespaces(
    name: &str,
    attributes: &mut Vec<CanonicalXmlAttribute>,
    inherited_namespaces: &[CanonicalXmlAttribute],
    mode: CanonicalXmlMode,
) -> Result<(), MsgError> {
    match mode {
        CanonicalXmlMode::Inclusive => {
            for namespace in inherited_namespaces {
                if !attributes
                    .iter()
                    .any(|attribute| attribute.name == namespace.name)
                {
                    attributes.push(namespace.clone());
                }
            }
        }
        CanonicalXmlMode::Exclusive => {
            if let Some((prefix, _)) = name.split_once(':') {
                let namespace_name = format!("xmlns:{prefix}");
                apply_inherited_namespace(attributes, inherited_namespaces, &namespace_name);
            } else if !attributes.iter().any(|attribute| attribute.name == "xmlns") {
                if let Some(namespace) = inherited_namespaces
                    .iter()
                    .find(|attribute| attribute.name == "xmlns" && !attribute.value.is_empty())
                {
                    attributes.push(namespace.clone());
                }
            }
            let visibly_used_attribute_namespaces = attributes
                .iter()
                .filter(|attribute| attribute.kind == CanonicalXmlAttributeKind::Attribute)
                .filter_map(|attribute| attribute.name.split_once(':').map(|(prefix, _)| prefix))
                .filter(|prefix| *prefix != "xml")
                .map(|prefix| format!("xmlns:{prefix}"))
                .collect::<Vec<_>>();
            for namespace_name in visibly_used_attribute_namespaces {
                apply_inherited_namespace(attributes, inherited_namespaces, &namespace_name);
            }
        }
    }
    Ok(())
}
fn apply_inherited_namespace(
    attributes: &mut Vec<CanonicalXmlAttribute>,
    inherited_namespaces: &[CanonicalXmlAttribute],
    namespace_name: &str,
) {
    if attributes
        .iter()
        .any(|attribute| attribute.name == namespace_name)
    {
        return;
    }
    if let Some(namespace) = inherited_namespaces
        .iter()
        .find(|attribute| attribute.name == namespace_name)
    {
        attributes.push(namespace.clone());
    }
}
fn sort_and_validate_canonical_xml_attributes(
    parsed: &mut Vec<CanonicalXmlAttribute>,
    in_scope_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(), MsgError> {
    ensure_supported_xml_attribute_namespaces(parsed, in_scope_namespaces)?;
    ensure_unique_canonical_xml_attribute_names(parsed, in_scope_namespaces)?;
    let lookup = parsed.clone();
    parsed.sort_by(|left, right| match (left.kind, right.kind) {
        (CanonicalXmlAttributeKind::Namespace, CanonicalXmlAttributeKind::Namespace) => {
            namespace_attribute_sort_key(&left.name).cmp(namespace_attribute_sort_key(&right.name))
        }
        (CanonicalXmlAttributeKind::Namespace, CanonicalXmlAttributeKind::Attribute) => {
            std::cmp::Ordering::Less
        }
        (CanonicalXmlAttributeKind::Attribute, CanonicalXmlAttributeKind::Namespace) => {
            std::cmp::Ordering::Greater
        }
        (CanonicalXmlAttributeKind::Attribute, CanonicalXmlAttributeKind::Attribute) => {
            canonical_xml_attribute_sort_key(&left.name, &lookup, in_scope_namespaces)
                .expect("attribute namespaces are validated before sorting")
                .cmp(
                    &canonical_xml_attribute_sort_key(&right.name, &lookup, in_scope_namespaces)
                        .expect("attribute namespaces are validated before sorting"),
                )
        }
    });
    if parsed
        .windows(2)
        .any(|attrs| attrs[0].name.as_str() == attrs[1].name.as_str())
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn namespace_attribute_sort_key(name: &str) -> &str {
    name.strip_prefix("xmlns:").unwrap_or_default()
}
fn canonical_xml_attribute_sort_key(
    name: &str,
    attributes: &[CanonicalXmlAttribute],
    in_scope_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(String, String), MsgError> {
    if let Some((prefix, local)) = name.split_once(':') {
        let namespace_uri = namespace_uri_for_prefix(prefix, attributes, in_scope_namespaces)
            .ok_or(MsgError::ValidationFailed)?;
        Ok((namespace_uri.to_owned(), local.to_owned()))
    } else {
        Ok((String::new(), name.to_owned()))
    }
}
fn namespace_binding_from_attribute(
    attribute: &CanonicalXmlAttribute,
) -> Option<CanonicalXmlNamespaceBinding> {
    if attribute.kind != CanonicalXmlAttributeKind::Namespace {
        return None;
    }
    let prefix = if attribute.name == "xmlns" {
        ""
    } else {
        attribute.name.strip_prefix("xmlns:")?
    };
    if prefix == "xml" {
        return None;
    }
    Some(CanonicalXmlNamespaceBinding {
        prefix: prefix.to_owned(),
        uri: attribute.value.clone(),
    })
}
fn namespace_bindings_from_attributes(
    attributes: &[CanonicalXmlAttribute],
) -> Vec<CanonicalXmlNamespaceBinding> {
    attributes
        .iter()
        .filter_map(namespace_binding_from_attribute)
        .collect()
}
fn inherited_namespace_attributes_from_scope(
    in_scope_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Vec<CanonicalXmlAttribute> {
    let mut inherited = Vec::new();
    for binding in in_scope_namespaces.iter().rev() {
        let name = if binding.prefix.is_empty() {
            "xmlns".to_owned()
        } else {
            format!("xmlns:{}", binding.prefix)
        };
        if inherited
            .iter()
            .any(|attribute: &CanonicalXmlAttribute| attribute.name == name)
        {
            continue;
        }
        inherited.push(CanonicalXmlAttribute {
            name,
            value: binding.uri.clone(),
            kind: CanonicalXmlAttributeKind::Namespace,
        });
    }
    inherited.reverse();
    inherited
}
fn namespace_uri_for_prefix<'a>(
    prefix: &str,
    attributes: &'a [CanonicalXmlAttribute],
    in_scope_namespaces: &'a [CanonicalXmlNamespaceBinding],
) -> Option<&'a str> {
    if prefix == "xml" {
        return Some(XML_NS);
    }
    if prefix == "xmlns" {
        return None;
    }
    attributes
        .iter()
        .rev()
        .find(|attribute| namespace_prefix_from_attribute(attribute) == Some(prefix))
        .map(|attribute| attribute.value.as_str())
        .or_else(|| {
            in_scope_namespaces
                .iter()
                .rev()
                .find(|binding| binding.prefix == prefix)
                .map(|binding| binding.uri.as_str())
        })
}
fn namespace_prefix_from_attribute(attribute: &CanonicalXmlAttribute) -> Option<&str> {
    if attribute.kind != CanonicalXmlAttributeKind::Namespace {
        return None;
    }
    if attribute.name == "xmlns" {
        Some("")
    } else {
        attribute.name.strip_prefix("xmlns:")
    }
}
fn ensure_supported_xml_attribute_namespaces(
    attributes: &[CanonicalXmlAttribute],
    in_scope_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(), MsgError> {
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.kind == CanonicalXmlAttributeKind::Attribute)
    {
        let Some((prefix, _)) = attribute.name.split_once(':') else {
            continue;
        };
        namespace_uri_for_prefix(prefix, attributes, in_scope_namespaces)
            .ok_or(MsgError::ValidationFailed)?;
    }
    Ok(())
}
fn ensure_unique_canonical_xml_attribute_names(
    attributes: &[CanonicalXmlAttribute],
    in_scope_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(), MsgError> {
    let mut expanded_names = Vec::new();
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.kind == CanonicalXmlAttributeKind::Attribute)
    {
        let expanded_name =
            canonical_xml_attribute_sort_key(&attribute.name, attributes, in_scope_namespaces)?;
        if expanded_names
            .iter()
            .any(|existing| existing == &expanded_name)
        {
            return Err(MsgError::ValidationFailed);
        }
        expanded_names.push(expanded_name);
    }
    Ok(())
}
fn ensure_supported_xml_namespace_declaration(name: &str, value: &str) -> Result<(), MsgError> {
    if name == "xmlns:xml" {
        return if value == XML_NS {
            Ok(())
        } else {
            Err(MsgError::ValidationFailed)
        };
    }
    if name.starts_with("xmlns:") && value.is_empty() {
        return Err(MsgError::ValidationFailed);
    }
    let reserved_prefix = name
        .strip_prefix("xmlns:")
        .is_some_and(|prefix| matches!(prefix, "xml" | "xmlns"));
    let reserved_namespace = matches!(value, XML_NS | XMLNS_NS);
    if reserved_prefix || reserved_namespace {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn ensure_supported_xml_name(name: &str) -> Result<(), MsgError> {
    if name.starts_with(':') || name.ends_with(':') || name.matches(':').count() > 1 {
        return Err(MsgError::ValidationFailed);
    }
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(MsgError::ValidationFailed);
    };
    if !matches!(first, b'A'..=b'Z' | b'a'..=b'z' | b'_' | b':') {
        return Err(MsgError::ValidationFailed);
    }
    if bytes.all(|byte| {
        matches!(
            byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b':'
        )
    }) {
        Ok(())
    } else {
        Err(MsgError::ValidationFailed)
    }
}
fn ensure_supported_xml_element_namespace(
    name: &str,
    attributes: &[CanonicalXmlAttribute],
    in_scope_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(), MsgError> {
    let Some((prefix, _)) = name.split_once(':') else {
        return Ok(());
    };
    if namespace_uri_for_prefix(prefix, attributes, in_scope_namespaces).is_some() {
        Ok(())
    } else {
        Err(MsgError::ValidationFailed)
    }
}
fn ensure_supported_xml_attribute_value(value: &str) -> Result<(), MsgError> {
    if value.contains('<') || value.contains('\r') || value.contains('\n') || value.contains('\t') {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}
fn push_canonical_xml_start_tag(
    name: &str,
    attributes: &[CanonicalXmlAttribute],
    output: &mut String,
) -> Result<(), MsgError> {
    output.push('<');
    output.push_str(name);
    for attribute in attributes {
        if attribute.name == "xmlns:xml" && attribute.value == XML_NS {
            continue;
        }
        output.push(' ');
        output.push_str(&attribute.name);
        output.push_str("=\"");
        push_canonical_xml_attribute_value(&attribute.value, output)?;
        output.push('"');
    }
    output.push('>');
    Ok(())
}
fn push_canonical_xml_text(value: &str, output: &mut String) -> Result<(), MsgError> {
    push_canonical_xml_value(value, output, push_canonical_xml_text_char)
}
fn push_canonical_xml_attribute_value(value: &str, output: &mut String) -> Result<(), MsgError> {
    push_canonical_xml_value(value, output, push_canonical_xml_attribute_char)
}
fn push_canonical_xml_value(
    value: &str,
    output: &mut String,
    push_char: fn(char, &mut String) -> Result<(), MsgError>,
) -> Result<(), MsgError> {
    let mut cursor = 0usize;
    while cursor < value.len() {
        let Some(entity_start) = value[cursor..].find('&').map(|offset| cursor + offset) else {
            push_raw_canonical_xml_chars(&value[cursor..], output, push_char)?;
            return Ok(());
        };
        push_raw_canonical_xml_chars(&value[cursor..entity_start], output, push_char)?;
        let reference_start = entity_start + 1;
        let reference_end = value[reference_start..]
            .find(';')
            .map(|offset| reference_start + offset)
            .ok_or(MsgError::ValidationFailed)?;
        let ch = decode_supported_xml_character_reference(&value[reference_start..reference_end])?;
        push_char(ch, output)?;
        cursor = reference_end + 1;
    }
    Ok(())
}
fn push_raw_canonical_xml_chars(
    value: &str,
    output: &mut String,
    push_char: fn(char, &mut String) -> Result<(), MsgError>,
) -> Result<(), MsgError> {
    for ch in value.chars() {
        push_char(ch, output)?;
    }
    Ok(())
}
fn push_canonical_xml_text_char(ch: char, output: &mut String) -> Result<(), MsgError> {
    ensure_supported_xml_char(ch)?;
    match ch {
        '&' => output.push_str("&amp;"),
        '<' => output.push_str("&lt;"),
        '>' => output.push_str("&gt;"),
        '\r' => output.push_str("&#xD;"),
        _ => output.push(ch),
    }
    Ok(())
}
fn push_canonical_xml_attribute_char(ch: char, output: &mut String) -> Result<(), MsgError> {
    ensure_supported_xml_char(ch)?;
    match ch {
        '&' => output.push_str("&amp;"),
        '<' => output.push_str("&lt;"),
        '"' => output.push_str("&quot;"),
        '\t' => output.push_str("&#x9;"),
        '\n' => output.push_str("&#xA;"),
        '\r' => output.push_str("&#xD;"),
        _ => output.push(ch),
    }
    Ok(())
}
fn decode_supported_xml_character_reference(reference: &str) -> Result<char, MsgError> {
    match reference {
        "amp" => return Ok('&'),
        "lt" => return Ok('<'),
        "gt" => return Ok('>'),
        "quot" => return Ok('"'),
        "apos" => return Ok('\''),
        _ => {}
    }
    let codepoint = if let Some(hex) = reference.strip_prefix("#x") {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(MsgError::ValidationFailed);
        }
        u32::from_str_radix(hex, 16).map_err(|_| MsgError::ValidationFailed)?
    } else if let Some(decimal) = reference.strip_prefix('#') {
        if decimal.is_empty() || !decimal.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(MsgError::ValidationFailed);
        }
        decimal
            .parse::<u32>()
            .map_err(|_| MsgError::ValidationFailed)?
    } else {
        return Err(MsgError::ValidationFailed);
    };
    let ch = char::from_u32(codepoint).ok_or(MsgError::ValidationFailed)?;
    ensure_supported_xml_char(ch)?;
    Ok(ch)
}
fn ensure_supported_xml_char(ch: char) -> Result<(), MsgError> {
    if matches!(ch, '\u{9}' | '\u{a}' | '\u{d}')
        || ('\u{20}'..='\u{d7ff}').contains(&ch)
        || ('\u{e000}'..='\u{fffd}').contains(&ch)
        || ('\u{10000}'..='\u{10ffff}').contains(&ch)
    {
        Ok(())
    } else {
        Err(MsgError::ValidationFailed)
    }
}
fn required_single_xml_element(container: &str, local: &str) -> Result<XmlElementSpan, MsgError> {
    let span = find_first_xml_element(container, local).ok_or(MsgError::ValidationFailed)?;
    ensure_supported_xml_element_span_name(container, span)?;
    if find_first_xml_element(&container[span.end..], local).is_some() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(span)
}
fn ensure_xml_element_content_empty(container: &str, span: XmlElementSpan) -> Result<(), MsgError> {
    if container[span.content_start..span.content_end]
        .trim()
        .is_empty()
    {
        Ok(())
    } else {
        Err(MsgError::ValidationFailed)
    }
}
fn ensure_xml_element_text_only(container: &str, span: XmlElementSpan) -> Result<(), MsgError> {
    if container[span.content_start..span.content_end].contains('<') {
        Err(MsgError::ValidationFailed)
    } else {
        Ok(())
    }
}
fn ensure_direct_xml_child_elements(
    container: &str,
    parent_span: XmlElementSpan,
    allowed_children: &[&str],
) -> Result<(), MsgError> {
    ensure_direct_xml_child_elements_with_comment_policy(
        container,
        parent_span,
        allowed_children,
        false,
    )
}
fn ensure_direct_xml_child_elements_allowing_comments(
    container: &str,
    parent_span: XmlElementSpan,
    allowed_children: &[&str],
) -> Result<(), MsgError> {
    ensure_direct_xml_child_elements_with_comment_policy(
        container,
        parent_span,
        allowed_children,
        true,
    )
}
fn ensure_direct_xml_child_elements_with_comment_policy(
    container: &str,
    parent_span: XmlElementSpan,
    allowed_children: &[&str],
    allow_comments: bool,
) -> Result<(), MsgError> {
    let mut cursor = parent_span.content_start;
    while cursor < parent_span.content_end {
        let Some(offset) = container[cursor..parent_span.content_end].find('<') else {
            return if container[cursor..parent_span.content_end].trim().is_empty() {
                Ok(())
            } else {
                Err(MsgError::ValidationFailed)
            };
        };
        let start = cursor + offset;
        if !container[cursor..start].trim().is_empty() {
            return Err(MsgError::ValidationFailed);
        }
        let tag_start = start + 1;
        let tag_end =
            find_xml_tag_end(container.as_bytes(), tag_start).ok_or(MsgError::ValidationFailed)?;
        if tag_end > parent_span.content_end {
            return Err(MsgError::ValidationFailed);
        }
        if allow_comments && container[start..].starts_with("<!--") {
            let comment_end = find_supported_xml_comment_end(container, start)? + 3;
            if comment_end > parent_span.content_end {
                return Err(MsgError::ValidationFailed);
            }
            cursor = comment_end;
            continue;
        }
        let raw_tag = container[tag_start..tag_end].trim();
        if raw_tag.starts_with('/')
            || raw_tag.starts_with('?')
            || raw_tag.starts_with("!--")
            || raw_tag.starts_with("![CDATA[")
        {
            return Err(MsgError::ValidationFailed);
        }
        let self_closing = raw_tag.ends_with('/');
        let tag_body = raw_tag.trim_end_matches('/').trim_end();
        let (name, _) = tag_body
            .split_once(char::is_whitespace)
            .unwrap_or((tag_body, ""));
        ensure_supported_xml_name(name)?;
        let local = xml_local_name(name);
        if !allowed_children
            .iter()
            .any(|allowed_child| local == *allowed_child)
        {
            return Err(MsgError::ValidationFailed);
        }
        cursor = if self_closing {
            tag_end + 1
        } else {
            let (_, end) = find_xml_element_end(container, tag_end + 1, name)
                .ok_or(MsgError::ValidationFailed)?;
            if end > parent_span.content_end {
                return Err(MsgError::ValidationFailed);
            }
            end
        };
    }
    Ok(())
}
fn optional_direct_xml_child_element(
    container: &str,
    parent_span: XmlElementSpan,
    child: &str,
) -> Result<Option<XmlElementSpan>, MsgError> {
    optional_direct_xml_child_element_with_comment_policy(container, parent_span, child, false)
}
fn optional_direct_xml_child_element_allowing_comments(
    container: &str,
    parent_span: XmlElementSpan,
    child: &str,
) -> Result<Option<XmlElementSpan>, MsgError> {
    optional_direct_xml_child_element_with_comment_policy(container, parent_span, child, true)
}
fn optional_direct_xml_child_element_with_comment_policy(
    container: &str,
    parent_span: XmlElementSpan,
    child: &str,
    allow_comments: bool,
) -> Result<Option<XmlElementSpan>, MsgError> {
    let mut cursor = parent_span.content_start;
    let mut found = None;
    while cursor < parent_span.content_end {
        let Some(offset) = container[cursor..parent_span.content_end].find('<') else {
            return if container[cursor..parent_span.content_end].trim().is_empty() {
                Ok(found)
            } else {
                Err(MsgError::ValidationFailed)
            };
        };
        let start = cursor + offset;
        if !container[cursor..start].trim().is_empty() {
            return Err(MsgError::ValidationFailed);
        }
        let tag_start = start + 1;
        let tag_end =
            find_xml_tag_end(container.as_bytes(), tag_start).ok_or(MsgError::ValidationFailed)?;
        if tag_end > parent_span.content_end {
            return Err(MsgError::ValidationFailed);
        }
        if allow_comments && container[start..].starts_with("<!--") {
            let comment_end = find_supported_xml_comment_end(container, start)? + 3;
            if comment_end > parent_span.content_end {
                return Err(MsgError::ValidationFailed);
            }
            cursor = comment_end;
            continue;
        }
        let raw_tag = container[tag_start..tag_end].trim();
        if raw_tag.starts_with('/')
            || raw_tag.starts_with('?')
            || raw_tag.starts_with("!--")
            || raw_tag.starts_with("![CDATA[")
        {
            return Err(MsgError::ValidationFailed);
        }
        let self_closing = raw_tag.ends_with('/');
        let tag_body = raw_tag.trim_end_matches('/').trim_end();
        let (name, _) = tag_body
            .split_once(char::is_whitespace)
            .unwrap_or((tag_body, ""));
        ensure_supported_xml_name(name)?;
        let local = xml_local_name(name);
        let child_span = if self_closing {
            XmlElementSpan {
                start,
                opening_end: tag_end,
                content_start: tag_end + 1,
                content_end: tag_end + 1,
                end: tag_end + 1,
            }
        } else {
            let (content_end, end) = find_xml_element_end(container, tag_end + 1, name)
                .ok_or(MsgError::ValidationFailed)?;
            if end > parent_span.content_end {
                return Err(MsgError::ValidationFailed);
            }
            XmlElementSpan {
                start,
                opening_end: tag_end,
                content_start: tag_end + 1,
                content_end,
                end,
            }
        };
        if local == child && found.replace(child_span).is_some() {
            return Err(MsgError::ValidationFailed);
        }
        cursor = child_span.end;
    }
    Ok(found)
}
fn required_direct_xml_child_element(
    container: &str,
    parent_span: XmlElementSpan,
    child: &str,
) -> Result<XmlElementSpan, MsgError> {
    optional_direct_xml_child_element(container, parent_span, child)?
        .ok_or(MsgError::ValidationFailed)
}
fn required_direct_xml_child_element_allowing_comments(
    container: &str,
    parent_span: XmlElementSpan,
    child: &str,
) -> Result<XmlElementSpan, MsgError> {
    optional_direct_xml_child_element_allowing_comments(container, parent_span, child)?
        .ok_or(MsgError::ValidationFailed)
}
fn decode_direct_child_base64(
    container: &str,
    child_span: XmlElementSpan,
) -> Result<Vec<u8>, MsgError> {
    ensure_xml_element_attributes_allowed(container, child_span, &[])?;
    ensure_xml_element_text_only(container, child_span)?;
    let value: String = container[child_span.content_start..child_span.content_end]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    BASE64_STANDARD
        .decode(value)
        .map_err(|_| MsgError::ValidationFailed)
}
fn ensure_xml_element_attributes_allowed(
    container: &str,
    span: XmlElementSpan,
    allowed_attributes: &[&str],
) -> Result<(), MsgError> {
    let (_, attributes) = validated_xml_element_name_and_attributes(container, span, &[])?;
    for attribute in attributes {
        if attribute.kind == CanonicalXmlAttributeKind::Namespace {
            continue;
        }
        if !allowed_attributes
            .iter()
            .any(|allowed_attribute| attribute.name == *allowed_attribute)
        {
            return Err(MsgError::ValidationFailed);
        }
    }
    Ok(())
}
fn ensure_xml_element_prefixed_namespace(
    container: &str,
    span: XmlElementSpan,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
    expected_namespace: &str,
) -> Result<(), MsgError> {
    let (name, attributes) =
        validated_xml_element_name_and_attributes(container, span, inherited_namespaces)?;
    let Some((prefix, _)) = name.split_once(':') else {
        return (namespace_uri_for_prefix("", &attributes, inherited_namespaces)
            == Some(expected_namespace))
        .then_some(())
        .ok_or(MsgError::ValidationFailed);
    };
    if namespace_uri_for_prefix(prefix, &attributes, inherited_namespaces)
        == Some(expected_namespace)
    {
        Ok(())
    } else {
        Err(MsgError::ValidationFailed)
    }
}
fn ensure_xades_element_prefixed_namespace(
    container: &str,
    span: XmlElementSpan,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(), MsgError> {
    ensure_xml_element_prefixed_namespace(container, span, inherited_namespaces, XADES_NS)
}
fn xml_element_namespace_scope(
    container: &str,
    span: XmlElementSpan,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<Vec<CanonicalXmlNamespaceBinding>, MsgError> {
    let (_, attributes) =
        validated_xml_element_name_and_attributes(container, span, inherited_namespaces)?;
    let mut scope = inherited_namespaces.to_vec();
    scope.extend(
        attributes
            .iter()
            .filter_map(namespace_binding_from_attribute),
    );
    Ok(scope)
}
fn validated_xml_element_name_and_attributes<'a>(
    container: &'a str,
    span: XmlElementSpan,
    inherited_namespaces: &[CanonicalXmlNamespaceBinding],
) -> Result<(&'a str, Vec<CanonicalXmlAttribute>), MsgError> {
    let opening = container[span.start + 1..span.opening_end].trim();
    let tag_body = opening.trim_end_matches('/').trim_end();
    let (name, attributes) = split_supported_xml_tag(tag_body)?;
    ensure_supported_xml_name(name)?;
    let mut attributes = parse_supported_xml_attributes(attributes)?;
    sort_and_validate_canonical_xml_attributes(&mut attributes, inherited_namespaces)?;
    Ok((name, attributes))
}
fn ensure_supported_xml_element_span_name(
    container: &str,
    span: XmlElementSpan,
) -> Result<(), MsgError> {
    let opening = container[span.start + 1..span.opening_end].trim();
    let tag_body = opening.trim_end_matches('/').trim_end();
    let (name, _) = split_supported_xml_tag(tag_body)?;
    ensure_supported_xml_name(name)
}
fn required_single_child_text_compact(container: &str, child: &str) -> Result<String, MsgError> {
    optional_single_child_text_compact(container, child)?.ok_or(MsgError::ValidationFailed)
}
fn optional_single_child_text_compact(
    container: &str,
    child: &str,
) -> Result<Option<String>, MsgError> {
    let Some(span) = find_first_xml_element(container, child) else {
        return Ok(None);
    };
    if find_first_xml_element(&container[span.end..], child).is_some() {
        return Err(MsgError::ValidationFailed);
    }
    Ok(Some(
        container[span.content_start..span.content_end]
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect(),
    ))
}
fn element_attr(container: &str, span: XmlElementSpan, attr: &str) -> Option<String> {
    let opening = &container[span.start + 1..span.opening_end];
    attr_value_exact(opening, attr)
}
fn attr_value_exact(opening: &str, attr: &str) -> Option<String> {
    attr_value_matching(opening, |name| name == attr)
}
#[cfg(test)]
fn attr_value(opening: &str, attr: &str) -> Option<String> {
    attr_value_exact(opening, attr)
}
fn attr_value_matching(
    opening: &str,
    mut name_matches: impl FnMut(&str) -> bool,
) -> Option<String> {
    let mut cursor = opening.trim();
    if let Some((_, rest)) = cursor.split_once(char::is_whitespace) {
        cursor = rest.trim();
    } else {
        return None;
    }
    if cursor.ends_with('/') {
        cursor = cursor.trim_end_matches('/').trim_end();
    }
    while !cursor.is_empty() {
        let eq_idx = cursor.find('=')?;
        let name = cursor[..eq_idx].trim();
        let mut remainder = cursor[eq_idx + 1..].trim_start();
        if remainder.is_empty() {
            return None;
        }
        let quote = remainder.as_bytes()[0];
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        remainder = &remainder[1..];
        let end_idx = remainder.find(quote as char)?;
        if name_matches(name) {
            return Some(remainder[..end_idx].to_owned());
        }
        remainder = remainder[end_idx + 1..].trim_start();
        cursor = remainder;
    }
    None
}
fn find_first_xml_element(text: &str, local: &str) -> Option<XmlElementSpan> {
    let mut cursor = 0usize;
    while cursor < text.len() {
        let start = cursor + text[cursor..].find('<')?;
        let tag_start = start + 1;
        let opening_end = find_xml_tag_end(text.as_bytes(), tag_start)?;
        let raw_tag = text[tag_start..opening_end].trim();
        if raw_tag.starts_with('/')
            || raw_tag.starts_with('?')
            || raw_tag.starts_with("!--")
            || raw_tag.starts_with("![CDATA[")
        {
            cursor = opening_end + 1;
            continue;
        }
        let self_closing = raw_tag.ends_with('/');
        let tag_body = raw_tag.trim_end_matches('/').trim_end();
        let (name, _) = tag_body
            .split_once(char::is_whitespace)
            .unwrap_or((tag_body, ""));
        if xml_local_name(name) == local {
            if self_closing {
                return Some(XmlElementSpan {
                    start,
                    opening_end,
                    content_start: opening_end + 1,
                    content_end: opening_end + 1,
                    end: opening_end + 1,
                });
            }
            let (content_end, end) = find_xml_element_end(text, opening_end + 1, name)?;
            return Some(XmlElementSpan {
                start,
                opening_end,
                content_start: opening_end + 1,
                content_end,
                end,
            });
        }
        cursor = opening_end + 1;
    }
    None
}
fn find_xml_element_end(
    text: &str,
    mut cursor: usize,
    opening_name: &str,
) -> Option<(usize, usize)> {
    let mut depth = 1usize;
    while cursor < text.len() {
        let start = cursor + text[cursor..].find('<')?;
        let tag_start = start + 1;
        let tag_end = find_xml_tag_end(text.as_bytes(), tag_start)?;
        let raw_tag = text[tag_start..tag_end].trim();
        if raw_tag.starts_with('?') || raw_tag.starts_with("!--") || raw_tag.starts_with("![CDATA[")
        {
            cursor = tag_end + 1;
            continue;
        }
        let closing = raw_tag.starts_with('/');
        let tag_body = if closing {
            raw_tag.trim_start_matches('/').trim()
        } else {
            raw_tag
        };
        let self_closing = !closing && tag_body.ends_with('/');
        let tag_body = tag_body.trim_end_matches('/').trim_end();
        let (name, _) = tag_body
            .split_once(char::is_whitespace)
            .unwrap_or((tag_body, ""));
        if name == opening_name {
            if closing {
                depth -= 1;
                if depth == 0 {
                    return Some((start, tag_end + 1));
                }
            } else if !self_closing {
                depth += 1;
            }
        }
        cursor = tag_end + 1;
    }
    None
}
fn find_xml_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut quote = None;
    while i < bytes.len() {
        match quote {
            Some(q) if bytes[i] == q => quote = None,
            None if bytes[i] == b'"' || bytes[i] == b'\'' => quote = Some(bytes[i]),
            None if bytes[i] == b'>' => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}
fn xml_local_name(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}
fn amount_fraction_digits(amount: &str) -> usize {
    amount
        .trim()
        .split_once('.')
        .map(|(_, fraction)| fraction.len())
        .unwrap_or(0)
}
fn normalise_uetr(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
fn is_valid_uetr(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    for (idx, byte) in value.bytes().enumerate() {
        match idx {
            8 | 13 | 18 | 23 if byte == b'-' => {}
            8 | 13 | 18 | 23 => return false,
            _ if byte.is_ascii_hexdigit() => {}
            _ => return false,
        }
    }
    true
}
fn normalise_business_message_id(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    lower_hex(&digest)
}
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
fn normalise_identifier(kind: IdentifierKind, value: &str) -> String {
    match kind {
        IdentifierKind::Iban => normalise_iban(value),
        IdentifierKind::Currency => normalise_currency(value),
        IdentifierKind::Isin
        | IdentifierKind::Cusip
        | IdentifierKind::Lei
        | IdentifierKind::Bic
        | IdentifierKind::Mic => value.trim().to_ascii_uppercase(),
    }
}
fn require_identifier(field: &str, kind: IdentifierKind, value: &str) -> Result<String, MsgError> {
    let normalised = normalise_identifier(kind, value);
    if normalised.is_empty() || !ivm::iso20022::validate_identifier(kind, &normalised) {
        return Err(MsgError::InvalidIdentifier {
            field: field.to_owned(),
            kind,
        });
    }
    Ok(normalised)
}
fn normalise_iban(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}
fn normalise_currency(input: &str) -> String {
    input.trim().to_ascii_uppercase()
}
fn validate_asset_definition_selector(input: &str) -> eyre::Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        eyre::bail!("asset definition selector must not be empty");
    }
    if AssetDefinitionId::parse_address_literal(trimmed).is_ok()
        || AssetDefinitionAlias::from_str(trimmed).is_ok()
    {
        return Ok(trimmed.to_owned());
    }
    eyre::bail!(
        "invalid asset definition selector `{trimmed}`; expected canonical Base58 asset definition id or on-chain asset alias literal"
    );
}
fn resolve_asset_definition_selector(
    world: &impl WorldReadOnly,
    selector: &str,
    now_ms: u64,
) -> Option<AssetDefinitionId> {
    let literal = selector.trim();
    if literal.is_empty() {
        return None;
    }
    AssetDefinitionId::parse_address_literal(literal)
        .ok()
        .or_else(|| {
            AssetDefinitionAlias::from_str(literal)
                .ok()
                .and_then(|alias| world.asset_definition_id_by_alias_at(&alias, now_ms))
        })
}
fn insert_metadata_value(metadata: &mut Metadata, key: &str, value: &str) -> Result<(), MsgError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let name = Name::from_str(key).map_err(|_| MsgError::ValidationFailed)?;
    let json = Json::try_new(JsonValue::String(trimmed.to_owned()))
        .map_err(|_| MsgError::ValidationFailed)?;
    metadata.insert(name, json);
    Ok(())
}
#[cfg(test)]
mod tests {
    use iroha_model_base::domain::DomainId;
    include!("iso20022_bridge_tests.rs");
    /// Cross-rail MDR/XSD and checked-in securities lifecycle fixture coverage.
    mod live_profile_fixture_tests;
}
