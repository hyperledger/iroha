//! Native ISO intent and separate carrier/business projections in the existing lifecycle journal.

use super::*;
use iroha_data_model::{
    block::consensus::NexusFeeReceipt,
    isi::{SettleAtomic, SettlementDetails, SettlementReceipt},
};

/// Complete independently retained intent; encoded projections alone grant no authenticity.
#[derive(Clone, Debug)]
pub(super) struct IsoNativePayment {
    intent_frame: String,
    carrier: Option<IsoNativeCarrierOutcome>,
    settlement: Option<IsoNativeBusinessSettlement>,
    conflicting_intent: bool,
    // Derived only from this process's canonical reader. Never serialized or accepted on decode.
    verified_this_process: bool,
}

/// Exact canonical outcome of this gateway's immutable attempted transaction hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsoNativeCarrierOutcome {
    /// Native committed carrier height.
    pub(crate) height: u64,
    /// Whether this exact attempted carrier executed successfully.
    pub(crate) applied: bool,
    /// Canonical rejection description; absent for Applied.
    pub(crate) rejection: Option<String>,
}

/// Projection of an authenticated original business effect; retained bytes are recovery data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsoNativeBusinessSettlement {
    /// Original successful signed carrier, distinct from a retry's attempted carrier.
    pub(crate) transaction_hash: String,
    receipt_frame: String,
    nexus_fee_frame: Option<String>,
}

fn encode_frame<T: norito::core::NoritoSerialize>(value: &T) -> Result<String, MsgError> {
    let frame = norito::encode_canonical(value).map_err(|_| MsgError::ValidationFailed)?;
    let frame = BASE64_STANDARD.encode(frame);
    if frame.len() > ISO_PERSISTED_RECORD_MAX_BYTES as usize {
        return Err(MsgError::ValidationFailed);
    }
    Ok(frame)
}
fn decode_frame<T>(value: &str) -> Option<T>
where
    T: norito::core::NoritoSerialize,
    for<'de> T: norito::core::NoritoDeserialize<'de>,
{
    if value.len() > ISO_PERSISTED_RECORD_MAX_BYTES as usize {
        return None;
    }
    let bytes = BASE64_STANDARD.decode(value).ok()?;
    if BASE64_STANDARD.encode(&bytes) != value {
        return None;
    }
    norito::decode_canonical(&bytes).ok()
}

impl IsoNativePayment {
    pub(super) fn new(intent: &SettleAtomic) -> Result<Self, MsgError> {
        validate_iso_intent(intent)?;
        Ok(Self {
            intent_frame: encode_frame(intent)?,
            carrier: None,
            settlement: None,
            conflicting_intent: false,
            verified_this_process: false,
        })
    }
    pub(super) fn intent(&self) -> Result<SettleAtomic, MsgError> {
        let intent = decode_frame(&self.intent_frame).ok_or(MsgError::ValidationFailed)?;
        validate_iso_intent(&intent)?;
        Ok(intent)
    }
    pub(super) fn unresolved(&self, has_attempt: bool) -> bool {
        !self.verified_this_process
            || self.settlement.is_none() && !self.conflicting_intent
            || has_attempt && self.carrier.is_none()
    }
    pub(super) fn verified(&self) -> bool {
        self.verified_this_process
    }
    pub(super) fn requires_reauthentication(&self) -> bool {
        !self.verified_this_process
            && (self.carrier.is_some() || self.settlement.is_some() || self.conflicting_intent)
    }
    pub(super) fn business_hash(&self) -> Option<&str> {
        self.settlement
            .as_ref()
            .map(|settlement| settlement.transaction_hash.as_str())
    }
}

fn validate_iso_intent(intent: &SettleAtomic) -> Result<(), MsgError> {
    intent.validate().map_err(|_| MsgError::ValidationFailed)?;
    let [movement] = intent.movements.as_slice() else {
        return Err(MsgError::ValidationFailed);
    };
    if movement.source.account() != intent.settlement_id.owner()
        || *movement.source.scope() != iroha_data_model::asset::AssetBalanceScope::Global
        || intent.metadata.iter().next().is_some()
        || !is_valid_uetr(intent.settlement_id.reference().as_ref())
        || normalise_uetr(intent.settlement_id.reference().as_ref())
            != intent.settlement_id.reference().as_ref()
    {
        return Err(MsgError::ValidationFailed);
    }
    Ok(())
}

impl IsoNativeBusinessSettlement {
    /// Retain an already authenticated exact source projection; this function adds no proof authority.
    pub(crate) fn from_canonical_projection(
        transaction_hash: String,
        receipt: &SettlementReceipt,
        fee: Option<&NexusFeeReceipt>,
    ) -> Result<Self, MsgError> {
        crate::parse_signed_transaction_hash(&transaction_hash)
            .map_err(|_| MsgError::ValidationFailed)?;
        Ok(Self {
            transaction_hash,
            receipt_frame: encode_frame(receipt)?,
            nexus_fee_frame: fee.map(encode_frame).transpose()?,
        })
    }
    pub(crate) fn receipt(&self) -> Option<SettlementReceipt> {
        decode_frame(&self.receipt_frame)
    }
    fn matches(&self, intent: &SettleAtomic) -> bool {
        let Some(receipt) = self.receipt() else {
            return false;
        };
        let SettlementDetails::Atomic(details) = receipt.details else {
            return false;
        };
        crate::parse_signed_transaction_hash(&self.transaction_hash).is_ok()
            && receipt.block_height >= 2
            && receipt.metadata == intent.metadata
            && intent
                .intent_hash()
                .is_ok_and(|hash| hash == details.intent_hash)
            && intent
                .movements
                .resolve()
                .is_ok_and(|movements| movements == details.movements)
            && self.nexus_fee_frame.as_deref().is_none_or(|frame| {
                decode_frame::<NexusFeeReceipt>(frame)
                    .is_some_and(|fee| fee.block_height == receipt.block_height)
            })
    }
}

pub(super) fn original_business_hash(record: &IsoMessageRecordV2) -> Option<&str> {
    record.context.native_payment.as_ref().map_or_else(
        || record.transaction_hash.as_deref(),
        IsoNativePayment::business_hash,
    )
}

pub(super) fn native_payment_value(payment: Option<&IsoNativePayment>) -> JsonValue {
    let Some(payment) = payment else {
        return JsonValue::Null;
    };
    let mut value = norito::json::Map::new();
    value.insert(
        "intent_frame".into(),
        JsonValue::from(payment.intent_frame.clone()),
    );
    let carrier = payment.carrier.as_ref().map_or(JsonValue::Null, |carrier| {
        let mut value = norito::json::Map::new();
        value.insert("height".into(), JsonValue::from(carrier.height));
        value.insert("applied".into(), JsonValue::from(carrier.applied));
        value.insert(
            "rejection".into(),
            string_or_null(carrier.rejection.as_deref()),
        );
        JsonValue::Object(value)
    });
    value.insert("carrier".into(), carrier);
    let settlement = payment
        .settlement
        .as_ref()
        .map_or(JsonValue::Null, |settlement| {
            let mut value = norito::json::Map::new();
            value.insert(
                "transaction_hash".into(),
                JsonValue::from(settlement.transaction_hash.clone()),
            );
            value.insert(
                "receipt_frame".into(),
                JsonValue::from(settlement.receipt_frame.clone()),
            );
            value.insert(
                "nexus_fee_frame".into(),
                string_or_null(settlement.nexus_fee_frame.as_deref()),
            );
            JsonValue::Object(value)
        });
    value.insert("business_settlement".into(), settlement);
    value.insert(
        "conflicting_intent".into(),
        JsonValue::from(payment.conflicting_intent),
    );
    JsonValue::Object(value)
}

pub(super) fn native_payment_from_value(
    value: &JsonValue,
) -> Result<Option<IsoNativePayment>, InvalidPersistedNullableField> {
    match value {
        JsonValue::Null => Ok(None),
        value => value
            .as_object()
            .and_then(native_payment_from_object)
            .map(Some)
            .ok_or(InvalidPersistedNullableField::InvalidValue),
    }
}

fn native_payment_from_object(object: &norito::json::Map) -> Option<IsoNativePayment> {
    if !json_object_has_exact_keys(
        object,
        &[
            "intent_frame",
            "carrier",
            "business_settlement",
            "conflicting_intent",
        ],
    ) {
        return None;
    }
    let carrier = match object.get("carrier")? {
        JsonValue::Null => None,
        value => {
            let value = value.as_object()?;
            if !json_object_has_exact_keys(value, &["height", "applied", "rejection"]) {
                return None;
            }
            let carrier = IsoNativeCarrierOutcome {
                height: value.get("height")?.as_u64()?,
                applied: value.get("applied")?.as_bool()?,
                rejection: required_nullable_string(value, "rejection").ok()?,
            };
            if carrier.height < 2 || carrier.applied == carrier.rejection.is_some() {
                return None;
            }
            Some(carrier)
        }
    };
    let settlement = match object.get("business_settlement")? {
        JsonValue::Null => None,
        value => {
            let value = value.as_object()?;
            if !json_object_has_exact_keys(
                value,
                &["transaction_hash", "receipt_frame", "nexus_fee_frame"],
            ) {
                return None;
            }
            Some(IsoNativeBusinessSettlement {
                transaction_hash: required_clean_string(value, "transaction_hash")?,
                receipt_frame: required_clean_string(value, "receipt_frame")?,
                nexus_fee_frame: required_nullable_string(value, "nexus_fee_frame").ok()?,
            })
        }
    };
    let payment = IsoNativePayment {
        intent_frame: required_clean_string(object, "intent_frame")?,
        carrier,
        settlement,
        conflicting_intent: object.get("conflicting_intent")?.as_bool()?,
        verified_this_process: false,
    };
    let intent = payment.intent().ok()?;
    if payment
        .settlement
        .as_ref()
        .is_some_and(|settlement| payment.conflicting_intent || !settlement.matches(&intent))
    {
        return None;
    }
    Some(payment)
}

/// Exact journal request captured before canonical reads; rechecked before durable publication.
#[derive(Clone, Debug)]
pub struct IsoNativePaymentRequest {
    incarnation: IsoRecordIncarnation,
    /// Existing lifecycle journal identity.
    pub(crate) message_id: String,
    /// Independently retained complete monetary intent.
    pub(crate) intent: SettleAtomic,
    /// This gateway's original signed attempt, which may differ from the successful business carrier.
    pub(crate) attempted_hash: Option<String>,
}

impl Iso20022BridgeRuntime {
    /// Capture bounded unresolved native journal work in deterministic identity order.
    pub(crate) fn native_payment_requests(&self) -> Result<Vec<IsoNativePaymentRequest>, MsgError> {
        let _guard = self.state_lock.lock();
        let mut requests = self
            .records
            .iter()
            .filter_map(|entry| {
                let payment = entry.context.native_payment.as_ref()?;
                (payment.unresolved(entry.transaction_hash.is_some())
                    || self.pending_return_originals.contains_key(entry.key()))
                .then(|| {
                    Ok(IsoNativePaymentRequest {
                        incarnation: entry.incarnation.clone(),
                        message_id: entry.key().clone(),
                        intent: payment.intent()?,
                        attempted_hash: entry.transaction_hash.clone(),
                    })
                })
            })
            .collect::<Result<Vec<_>, MsgError>>()?;
        requests.sort_by(|left, right| left.message_id.cmp(&right.message_id));
        Ok(requests)
    }

    /// Bind a lifecycle reader to the same original incarnation and complete retained payment.
    pub(crate) fn native_payment_for_lifecycle(
        &self,
        authorization: &IsoLifecycleAuthorization,
    ) -> Result<Option<IsoNativePaymentRequest>, MsgError> {
        let Some(binding) = authorization.original.as_ref() else {
            return Ok(None);
        };
        let _guard = self.state_lock.lock();
        let original = self
            .records
            .get(&binding.message_id)
            .ok_or(MsgError::ValidationFailed)?;
        if original.incarnation != binding.incarnation
            || original.transaction_hash != binding.transaction_hash
        {
            return Err(MsgError::ValidationFailed);
        }
        original
            .context
            .native_payment
            .as_ref()
            .map(|payment| {
                Ok(IsoNativePaymentRequest {
                    incarnation: original.incarnation.clone(),
                    message_id: binding.message_id.clone(),
                    intent: payment.intent()?,
                    attempted_hash: original.transaction_hash.clone(),
                })
            })
            .transpose()
    }

    /// Persist exact outcomes only after the caller authenticates their original canonical sources.
    /// The attempted carrier and successful business carrier remain distinct journal facts.
    pub(crate) fn publish_native_payment_projection(
        &self,
        request: &IsoNativePaymentRequest,
        carrier: Option<IsoNativeCarrierOutcome>,
        settlement: Option<IsoNativeBusinessSettlement>,
        conflicting_intent: bool,
    ) -> Result<(), IsoStatusHistoryLimitError> {
        let _guard = self.state_lock.lock();
        let previous = self
            .records
            .get(&request.message_id)
            .map(|record| record.clone())
            .ok_or(IsoStatusHistoryLimitError::MissingReservation)?;
        let retained = previous
            .context
            .native_payment
            .as_ref()
            .ok_or(IsoStatusHistoryLimitError::MissingReservation)?;
        if previous.incarnation != request.incarnation
            || retained.intent().ok().as_ref() != Some(&request.intent)
            || previous.transaction_hash != request.attempted_hash
            || settlement
                .as_ref()
                .is_some_and(|effect| conflicting_intent || !effect.matches(&request.intent))
            || carrier.as_ref().is_some_and(|outcome| {
                request.attempted_hash.is_none() || outcome.applied && settlement.is_none()
            })
        {
            return Err(IsoStatusHistoryLimitError::MissingReservation);
        }
        // A decoded successful projection must be reauthenticated, never silently demoted on missing proof.
        if retained.settlement.is_some() && retained.settlement != settlement {
            return Err(IsoStatusHistoryLimitError::MissingReservation);
        }
        if retained.carrier.is_some() && retained.carrier != carrier {
            return Err(IsoStatusHistoryLimitError::MissingReservation);
        }
        if retained.conflicting_intent && !conflicting_intent {
            return Err(IsoStatusHistoryLimitError::MissingReservation);
        }
        let settled_at = settlement
            .as_ref()
            .map(|effect| {
                let receipt = effect
                    .receipt()
                    .ok_or(IsoStatusHistoryLimitError::MissingReservation)?;
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_millis(receipt.executed_at_ms))
                    .ok_or(IsoStatusHistoryLimitError::MissingReservation)
            })
            .transpose()?;
        if retained.carrier == carrier
            && retained.settlement == settlement
            && retained.conflicting_intent == conflicting_intent
            && retained.verified_this_process
        {
            return Ok(());
        }
        let rejected_attempt = carrier.as_ref().filter(|outcome| !outcome.applied).cloned();
        let mut payment = retained.clone();
        if carrier.is_some() {
            payment.carrier = carrier;
        }
        payment.settlement = settlement;
        payment.conflicting_intent = conflicting_intent;
        payment.verified_this_process = true;
        let mut candidate = previous.clone();
        candidate.try_transition(|record| {
            record.context.native_payment = Some(payment);
            record.updated_at = SystemTime::now();
            record.last_seen = Instant::now();
            if let Some(settled_at) = settled_at {
                record.state = IsoMessageState::Accepted;
                record.settled_at = Some(settled_at);
                record.ledger_tx_queued = false;
                record.rejection_reason_code = None;
                record.hold_reason_code = None;
                record.detail = Some(
                    "exact native business payment settled; carrier outcome recorded separately"
                        .to_owned(),
                );
            } else if conflicting_intent {
                record.state = IsoMessageState::Rejected;
                record.settled_at = None;
                record.ledger_tx_queued = false;
                record.rejection_reason_code = Some("PRTRY:PAYMENT_INTENT_CONFLICT".to_owned());
                record.detail = Some(
                    "payer reference already settled with different exact native terms".to_owned(),
                );
            } else if let Some(outcome) = rejected_attempt {
                record.state = IsoMessageState::Rejected;
                record.settled_at = None;
                record.ledger_tx_queued = false;
                record.hold_reason_code = None;
                record.rejection_reason_code = Some("PRTRY:NATIVE_CARRIER_REJECTED".to_owned());
                record.detail = outcome.rejection;
            }
        })?;
        if !self.commit_record_candidate(&request.message_id, Some(&previous), candidate) {
            return Err(IsoStatusHistoryLimitError::Persistence);
        }
        Ok(())
    }

    /// Finish pending reports only after the original native business effect has been authenticated.
    pub(crate) fn resolve_native_payment_return_reports(
        &self,
        original_id: &str,
    ) -> Result<(), IsoStatusHistoryLimitError> {
        let _guard = self.state_lock.lock();
        let original = self
            .records
            .get(original_id)
            .ok_or(IsoStatusHistoryLimitError::MissingReservation)?;
        let payment = original
            .context
            .native_payment
            .as_ref()
            .ok_or(IsoStatusHistoryLimitError::MissingReservation)?;
        if !payment.verified_this_process {
            return Ok(());
        }
        let hash = payment.business_hash().map(ToOwned::to_owned);
        let conflicting = payment.conflicting_intent;
        drop(original);
        let mut reports = self
            .records
            .iter()
            .filter_map(|entry| {
                (pending_return_original(entry.value()) == Some(original_id))
                    .then(|| entry.key().clone())
            })
            .collect::<Vec<_>>();
        reports.sort_unstable();
        if let Some(hash) = hash {
            return self.resolve_pending_return_reports(&hash, &reports, true);
        }
        // TODO: close an unsuccessful native intent only from authenticated committed
        // absence at its expiry. One rejected attempted carrier is not that evidence.
        if conflicting {
            for id in reports {
                let previous = self
                    .records
                    .get(&id)
                    .map(|entry| entry.clone())
                    .ok_or(IsoStatusHistoryLimitError::MissingReservation)?;
                let report = previous
                    .context
                    .reported_return
                    .clone()
                    .ok_or(IsoStatusHistoryLimitError::MissingReservation)?;
                self.commit_resolved_return_report(
                    &id,
                    previous,
                    report,
                    IsoReturnReportDisposition::InvalidTerms,
                )?;
            }
        }
        Ok(())
    }
}

pub(super) fn original_success_is_verified(record: &IsoMessageRecordV2) -> bool {
    record.is_settled()
        && record.state == IsoMessageState::Accepted
        && record
            .context
            .native_payment
            .as_ref()
            .is_none_or(|payment| payment.verified_this_process && payment.settlement.is_some())
}

pub(super) fn build_native_iso_payment_intent(
    parsed: &ParsedMessage,
    network_id: iroha_data_model::NetworkId,
    source: AssetId,
    quantity: Quantity,
    recipient: AccountId,
) -> Result<iroha_data_model::isi::SettleAtomic, MsgError> {
    use iroha_data_model::isi::{
        AtomicSettlementMovement, AtomicSettlementMovements, SettleAtomic, SettlementId,
    };
    use std::num::NonZeroU64;
    // Existing UETR is the payer's reference. Message envelope IDs and terms never replace it.
    let uetr = unique_field_text_by_suffix(parsed, &["UETR"], "UETR")?
        .ok_or(MsgError::MissingField("UETR"))?;
    if !is_valid_uetr(uetr) {
        return Err(MsgError::ValidationFailed);
    }
    let reference: Name = normalise_uetr(uetr)
        .parse()
        .map_err(|_| MsgError::ValidationFailed)?;
    let supplied_network: iroha_data_model::NetworkId = parsed
        .field_text("NexusSettlement/NetworkId")
        .ok_or(MsgError::MissingField("NexusSettlement/NetworkId"))?
        .parse()
        .map_err(|_| MsgError::ValidationFailed)?;
    if supplied_network != network_id {
        return Err(MsgError::ValidationFailed);
    }
    let expiry_text = parsed
        .field_text("NexusSettlement/ExpiresAtHeight")
        .ok_or(MsgError::MissingField("NexusSettlement/ExpiresAtHeight"))?;
    let expiry: NonZeroU64 = expiry_text
        .parse()
        .map_err(|_| MsgError::ValidationFailed)?;
    if expiry.to_string() != expiry_text {
        return Err(MsgError::ValidationFailed);
    }
    // These signed canonical identities own the terms. Gateway IBAN/currency mappings
    // may validate them but cannot select another payer, recipient, or asset.
    for (field, expected) in [
        (
            "NexusSettlement/SourceAccountId",
            source.account().to_string(),
        ),
        ("NexusSettlement/TargetAccountId", recipient.to_string()),
        (
            "NexusSettlement/AssetDefinitionId",
            source.definition().to_string(),
        ),
    ] {
        let supplied = parsed
            .field_text(field)
            .ok_or(MsgError::MissingField(field))?;
        if supplied != expected {
            return Err(MsgError::InvalidValue {
                field: field.to_owned(),
                kind: InvalidValueKind::Enum,
            });
        }
    }
    // The existing source already names its explicit Global bucket. Reject any ambient scope.
    if *source.scope() != iroha_data_model::asset::AssetBalanceScope::Global {
        return Err(MsgError::ValidationFailed);
    }
    let id = SettlementId::new(source.account().clone(), reference);
    let movements = AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
        source,
        recipient,
        quantity,
    }])
    .map_err(|_| MsgError::ValidationFailed)?;
    let intent = SettleAtomic::new(network_id, id, movements, expiry, Metadata::default());
    intent.validate().map_err(|_| MsgError::ValidationFailed)?;
    Ok(intent)
}
