//! One immutable native request, quoted payload and signed envelope under the journal lock.
//!
//! Inspection grants no current-state authority. Only explicit preparation can complete a retained
//! payload; submission remains a separate once-only transition after exact signed bytes are durable.
use super::*;
use iroha_data_model::transaction::{TransactionDomain, TransactionPayload};
use iroha_operation_journal::{MAX_JOURNAL_BYTES, NativeRecord, canonical_bytes};
use sha2::{Digest as _, Sha256};

const PAYLOAD_MAX: usize = 1024 * 1024;
// Norito counts raw byte vectors as sequence elements. Bound them by the admitted journal
// frame; the closed purpose validators independently enforce fee/committee cardinalities.
pub(super) const LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    MAX_JOURNAL_BYTES,
    MAX_JOURNAL_BYTES,
    MAX_JOURNAL_BYTES,
    64 * 1024 * 1024,
    64,
);

/// Inspected durable preparation phase; never inclusion or permission evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePreparationPhase {
    /// No canonical journal exists at the selected name.
    Missing,
    /// The original request exists; no payload has been retained.
    RequestOnly,
    /// The exact unsigned payload and validated quote are durable.
    PayloadRetained,
    /// Exact signed bytes and every preceding preparation stage are durable.
    Signed,
    /// This request was explicitly retired before any payload existed.
    Retired,
}

/// Verified local preparation with a private constructor and no dispatch authority.
pub struct VerifiedNativePreparation {
    phase: NativePreparationPhase,
    request_sha256: Option<String>,
    signed: Option<SignedTransaction>,
    unprepared: Option<OperationStatus>,
}
impl core::fmt::Debug for VerifiedNativePreparation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedNativePreparation")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
impl VerifiedNativePreparation {
    fn missing() -> Self {
        Self {
            phase: NativePreparationPhase::Missing,
            request_sha256: None,
            signed: None,
            unprepared: None,
        }
    }

    /// Local durable phase, independent of network inclusion.
    #[must_use]
    pub const fn phase(&self) -> NativePreparationPhase {
        self.phase
    }
    /// Canonical commitment to the exact original request authenticated by this inspector.
    /// Missing preparation has no request. This is local custody evidence, not native authority.
    #[must_use]
    pub fn request_sha256(&self) -> Option<&str> {
        self.request_sha256.as_deref()
    }
    /// Exact retained signed bytes, only when all preparation stages verify.
    #[must_use]
    pub fn signed_transaction(&self) -> Option<&SignedTransaction> {
        self.signed.as_ref()
    }
    /// Local partial status evaluated from the original request and exact retained payload TTL.
    /// Missing, Signed and Retired have no unprepared status.
    #[must_use]
    pub const fn unprepared_status(&self) -> Option<OperationStatus> {
        self.unprepared
    }
    /// Extract the exact signed transaction for independent historical verification.
    /// # Errors
    /// Refuses missing, partial or retired preparations.
    pub fn into_signed_transaction(self) -> Result<SignedTransaction> {
        self.signed
            .ok_or_else(|| eyre!("native operation has no retained signed transaction"))
    }
}

/// Local proof that one exact request retired under its original journal lock before any payload.
/// This grants no authority to replace a parent intent or renew a spending authorization.
#[derive(Debug)]
pub struct RetiredNativeRequest {
    journal: std::path::PathBuf,
    request_sha256: String,
}
impl RetiredNativeRequest {
    /// Exact canonical namespace whose held lock authorized retirement.
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal
    }
    /// Commitment to the exact immutable request; not an authorization for a replacement.
    #[must_use]
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
}

pub(super) struct Selection<'a> {
    pub(super) operation: &'a NativeOperation,
    pub(super) requested_fee: &'a FeePaymentIntent,
    pub(super) deadline_ms: u64,
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Request {
    schema: String,
    torii_url: String,
    chain_id: String,
    network_id: NetworkId,
    chain_discriminant: u16,
    account_id: AccountId,
    operation: NativeOperation,
    requested_fee: FeePaymentIntent,
    deadline_ms: u64,
}
impl Request {
    fn new(
        config: &Config,
        operation: NativeOperation,
        requested_fee: FeePaymentIntent,
    ) -> Result<Self> {
        requested_fee.validate()?;
        eyre::ensure!(
            requested_fee.charge_limits().len() <= 16,
            "too many fee limits"
        );
        let mut deadline_ms = current_unix_ms()?
            .checked_add(u64::try_from(config.transaction_ttl.as_millis())?)
            .ok_or_else(|| eyre!("preparation deadline overflow"))?;
        if let Some(terms) = operation.bounded_terms() {
            deadline_ms = deadline_ms.min(terms.deadline_ms);
        }
        if let NativeOperation::AliasSetup { plan, .. } = &operation {
            deadline_ms = deadline_ms.min(plan.body.valid_until_ms);
        }
        let value = Self {
            schema: "iroha.wallet.native-preparation.v1".into(),
            torii_url: config.torii_api_url.to_string(),
            chain_id: config.chain.to_string(),
            network_id: config.network_id,
            chain_discriminant: config.account_chain_discriminant,
            account_id: config.account.clone(),
            operation,
            requested_fee,
            deadline_ms,
        };
        value.verify(config)?;
        value.ensure_live()?;
        Ok(value)
    }
    fn selection(&self) -> Selection<'_> {
        Selection {
            operation: &self.operation,
            requested_fee: &self.requested_fee,
            deadline_ms: self.deadline_ms,
        }
    }
    fn verify(&self, config: &Config) -> Result<()> {
        eyre::ensure!(
            self.schema == "iroha.wallet.native-preparation.v1"
                && self.torii_url == config.torii_api_url.as_str()
                && self.chain_id == config.chain.as_str()
                && self.network_id == config.network_id
                && self.chain_discriminant == config.account_chain_discriminant
                && self.account_id == config.account
                && self.deadline_ms > 0
                && self.deadline_ms != u64::MAX,
            "preparation differs from the original wallet identity or finite authorization"
        );
        eyre::ensure!(
            self.requested_fee.charge_limits().len() <= 16,
            "too many fee limits"
        );
        self.requested_fee.validate()?;
        self.operation.instructions(config)?;
        if let Some(terms) = self.operation.bounded_terms() {
            eyre::ensure!(
                self.deadline_ms <= terms.deadline_ms,
                "preparation exceeds original deadline"
            );
        }
        if let NativeOperation::AliasSetup { plan, .. } = &self.operation {
            eyre::ensure!(
                self.deadline_ms <= plan.body.valid_until_ms,
                "preparation exceeds alias plan interval"
            );
        }
        Ok(())
    }
    fn ensure_live(&self) -> Result<()> {
        eyre::ensure!(
            current_unix_ms()? < self.deadline_ms,
            "original preparation deadline elapsed"
        );
        Ok(())
    }
    fn commitment(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(canonical_bytes(self)?)))
    }
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Payload {
    schema: String,
    request_sha256: String,
    payload_hex: String,
    quote: FeeQuoteResponse,
}
impl Payload {
    fn new(
        request: &Request,
        payload: &TransactionPayload,
        quote: FeeQuoteResponse,
    ) -> Result<Self> {
        let bytes = encode_payload(payload)?;
        Ok(Self {
            schema: "iroha.wallet.native-payload.v1".into(),
            request_sha256: request.commitment()?,
            payload_hex: bounded_hex(&bytes)?,
            quote,
        })
    }
    fn verify(&self, request: &Request, config: &Config) -> Result<TransactionPayload> {
        eyre::ensure!(
            self.schema == "iroha.wallet.native-payload.v1"
                && self.request_sha256 == request.commitment()?,
            "payload differs from original request"
        );
        let bytes = decode_hex(&self.payload_hex, PAYLOAD_MAX)?;
        let payload: TransactionPayload = bounded::decode_bounded(&bytes, PAYLOAD_MAX)?;
        verify_payload(request.selection(), &self.quote, &payload, config)?;
        Ok(payload)
    }
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Retirement {
    schema: String,
    request_sha256: String,
}

pub(super) struct Retained {
    request: Request,
    payload: Option<Payload>,
    record: Option<TransactionJournal>,
    signed: Option<SignedTransaction>,
    retired: bool,
    authorization_deadline_ms: u64,
}
impl Retained {
    /// Borrow the original request only after the sole reader has verified every retained phase.
    /// The selection is local custody, not permission, finality or a renewed authorization.
    pub(super) fn selection(&self) -> Selection<'_> {
        self.request.selection()
    }
    pub(super) fn read(journal: &Journal, config: &Config) -> Result<Self> {
        journal.verify_native_inventory()?;
        journal.read_native_scope(|reader| {
            let request: Request = reader
                .read_native(NativeRecord::Request)?
                .ok_or_else(|| eyre!("native journal requires its original preparation record"))?;
            request.verify(config)?;
            let payload: Option<Payload> = reader.read_native(NativeRecord::Payload)?;
            let record: Option<TransactionJournal> = reader.read_native(NativeRecord::Operation)?;
            let retirement: Option<Retirement> = reader.read_native(NativeRecord::Retired)?;
            let has_dispatch = reader.has_dispatch_evidence()?;
            if let Some(retirement) = &retirement {
                eyre::ensure!(
                    retirement.schema == "iroha.wallet.native-retirement.v1"
                        && retirement.request_sha256 == request.commitment()?
                        && payload.is_none()
                        && record.is_none()
                        && !has_dispatch,
                    "retirement conflicts with native preparation history"
                );
            }
            let decoded = payload
                .as_ref()
                .map(|value| value.verify(&request, config))
                .transpose()?;
            let signed = match &record {
                Some(record) => {
                    let payload = payload
                        .as_ref()
                        .ok_or_else(|| eyre!("signed journal is missing its original payload"))?;
                    eyre::ensure!(
                        canonical_bytes(&record.operation)? == canonical_bytes(&request.operation)?
                            && record.requested_fee == request.requested_fee
                            && record.deadline_ms <= request.deadline_ms
                            && canonical_bytes(&record.quote)? == canonical_bytes(&payload.quote)?,
                        "signed journal changed original request or quote"
                    );
                    let signed = record.verify(config)?;
                    eyre::ensure!(
                        Some(signed.payload()) == decoded.as_ref(),
                        "signed journal changed original retained payload"
                    );
                    // A marker must identify this exact retained signed operation even during inspection.
                    let marked = reader.submission_recorded(record)?;
                    eyre::ensure!(
                        !has_dispatch || marked,
                        "applied evidence has no original submission marker"
                    );
                    Some(signed)
                }
                None => {
                    eyre::ensure!(!has_dispatch, "dispatch evidence has no signed operation");
                    None
                }
            };
            let authorization_deadline_ms = decoded
                .as_ref()
                .map(payload_deadline)
                .transpose()?
                .unwrap_or(request.deadline_ms)
                .min(request.deadline_ms);
            Ok(Self {
                request,
                payload,
                record,
                signed,
                retired: retirement.is_some(),
                authorization_deadline_ms,
            })
        })
    }
    pub(super) fn verify_selection(
        &self,
        expected: NativeOperationKind,
        expectation: Option<&OperationExpectation<'_>>,
    ) -> Result<()> {
        eyre::ensure!(
            self.request.operation.kind() == expected,
            "different native preparation purpose"
        );
        match expectation {
            Some(value) => value.verify(&self.request.selection()),
            None if self.request.operation.bounded_terms().is_some() => {
                eyre::bail!("bounded operation requires its exact selected request")
            }
            None => Ok(()),
        }
    }
    fn phase(&self) -> NativePreparationPhase {
        if self.retired {
            NativePreparationPhase::Retired
        } else if self.signed.is_some() {
            NativePreparationPhase::Signed
        } else if self.payload.is_some() {
            NativePreparationPhase::PayloadRetained
        } else {
            NativePreparationPhase::RequestOnly
        }
    }
    pub(super) fn into_inspection(self) -> Result<VerifiedNativePreparation> {
        let unprepared = if self.signed.is_none() && !self.retired {
            Some(self.partial_status()?)
        } else {
            None
        };
        Ok(VerifiedNativePreparation {
            phase: self.phase(),
            request_sha256: Some(self.request.commitment()?),
            signed: self.signed,
            unprepared,
        })
    }
    fn partial_status(&self) -> Result<OperationStatus> {
        Ok(if current_unix_ms()? >= self.authorization_deadline_ms {
            OperationStatus::Expired
        } else {
            OperationStatus::Absent
        })
    }
    pub(super) fn into_record(self) -> Result<(TransactionJournal, SignedTransaction)> {
        eyre::ensure!(!self.retired, "native preparation was retired");
        Ok((
            self.record
                .ok_or_else(|| eyre!("native preparation has no signed operation"))?,
            self.signed
                .ok_or_else(|| eyre!("native preparation has no signed transaction"))?,
        ))
    }
    pub(super) fn partial_report(&self, journal: &Journal) -> Result<Option<OperationReport>> {
        if self.signed.is_some() {
            return Ok(None);
        }
        eyre::ensure!(!self.retired, "native preparation was retired");
        let status = self.partial_status()?;
        Ok(Some(OperationReport {
            status,
            data: norito::json!({
                "schema": "iroha.wallet.native-preparation-result.v1",
                "status": (status.as_str()),
                "journal": (journal.path().display().to_string()),
                "phase": (if self.payload.is_some() { "PayloadRetained" } else { "RequestOnly" }),
                "transaction_hash": null
            }),
        }))
    }
}

impl AccountService {
    /// Purpose owners use this before selecting a new plan/time; existing request bytes remain
    /// canonical, including PayloadRetained/Signed and expired historical inspection.
    pub(super) fn inspect_existing_preparation(
        &self,
        path: &Path,
        kind: NativeOperationKind,
        expected: Option<OperationExpectation<'_>>,
    ) -> Result<Option<VerifiedNativePreparation>> {
        self.inspect_existing_preparation_with(kind, expected, || Journal::open_optional(path))
    }

    // Both legitimate input boundaries use this one original inspection recipe. A borrowed
    // native parent replaces only absolute ancestry acquisition, never record admission.
    fn inspect_existing_preparation_with(
        &self,
        kind: NativeOperationKind,
        expected: Option<OperationExpectation<'_>>,
        open: impl FnOnce() -> Result<Option<Journal>>,
    ) -> Result<Option<VerifiedNativePreparation>> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        norito::core::with_decode_limits_scope(LIMITS, || {
            let Some(journal) = open()? else {
                return Ok(None);
            };
            let retained = Retained::read(&journal, &self.config)?;
            retained.verify_selection(kind, expected.as_ref())?;
            retained.into_inspection().map(Some)
        })
    }

    /// Publish only the exact first request under the canonical journal owner. This cannot build
    /// a transaction payload, access a quote/funding endpoint, sign or dispatch.
    pub(super) fn retain_native_request(
        &self,
        operation: NativeOperation,
        requested_fee: FeePaymentIntent,
        path: &Path,
    ) -> Result<VerifiedNativePreparation> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        norito::core::with_decode_limits_scope(LIMITS, || {
            let (_journal, retained) =
                self.publish_native_request(operation, requested_fee, path)?;
            retained.into_inspection()
        })
    }

    fn publish_native_request(
        &self,
        operation: NativeOperation,
        requested_fee: FeePaymentIntent,
        path: &Path,
    ) -> Result<(Journal, Retained)> {
        self.ensure_deadline()?;
        let request = Request::new(&self.config, operation, requested_fee)?;
        let journal = Journal::create_preparation(path, &request)?;
        let authorization_deadline_ms = request.deadline_ms;
        Ok((
            journal,
            Retained {
                request,
                payload: None,
                record: None,
                signed: None,
                retired: false,
                authorization_deadline_ms,
            },
        ))
    }

    pub(super) fn inspect_preparation(
        &self,
        path: &Path,
        kind: NativeOperationKind,
        expected: Option<OperationExpectation<'_>>,
    ) -> Result<VerifiedNativePreparation> {
        Ok(self
            .inspect_existing_preparation(path, kind, expected)?
            .unwrap_or_else(VerifiedNativePreparation::missing))
    }

    pub(super) fn inspect_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        kind: NativeOperationKind,
        expected: Option<OperationExpectation<'_>>,
    ) -> Result<VerifiedNativePreparation> {
        Ok(self
            .inspect_existing_preparation_with(kind, expected, || {
                Journal::open_optional_child(parent, name)
            })?
            .unwrap_or_else(VerifiedNativePreparation::missing))
    }

    pub(super) fn retire_preparation(
        &self,
        path: &Path,
        kind: NativeOperationKind,
        expected: OperationExpectation<'_>,
    ) -> Result<RetiredNativeRequest> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        norito::core::with_decode_limits_scope(LIMITS, || {
            let journal = Journal::open(path)?;
            let retained = Retained::read(&journal, &self.config)?;
            retained.verify_selection(kind, Some(&expected))?;
            eyre::ensure!(
                retained.payload.is_none()
                    && retained.record.is_none()
                    && !journal.has_dispatch_evidence()?,
                "only an exact RequestOnly preparation can retire"
            );
            journal.require_request_only_inventory()?;
            let request_sha256 = retained.request.commitment()?;
            if !retained.retired {
                journal.write_native(
                    NativeRecord::Retired,
                    &Retirement {
                        schema: "iroha.wallet.native-retirement.v1".into(),
                        request_sha256: request_sha256.clone(),
                    },
                )?;
            }
            Ok(RetiredNativeRequest {
                journal: journal.path().to_owned(),
                request_sha256,
            })
        })
    }

    /// Finish an existing exact request before fresh plan/time selection. Holds its lock through signing.
    pub(super) fn finish_existing_preparation(
        &self,
        path: &Path,
        kind: NativeOperationKind,
        expected: Option<OperationExpectation<'_>>,
    ) -> Result<Option<OperationReport>> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        norito::core::with_decode_limits_scope(LIMITS, || {
            let Some(journal) = Journal::open_optional(path)? else {
                return Ok(None);
            };
            let retained = Retained::read(&journal, &self.config)?;
            retained.verify_selection(kind, expected.as_ref())?;
            self.finish_preparation(journal, retained).map(Some)
        })
    }

    pub(super) fn prepare_native(
        &self,
        operation: NativeOperation,
        requested_fee: FeePaymentIntent,
        path: &Path,
    ) -> Result<OperationReport> {
        norito::core::with_decode_limits_scope(LIMITS, || {
            let (journal, retained) =
                self.publish_native_request(operation, requested_fee, path)?;
            self.finish_preparation(journal, retained)
        })
    }

    fn finish_preparation(
        &self,
        journal: Journal,
        mut retained: Retained,
    ) -> Result<OperationReport> {
        eyre::ensure!(!retained.retired, "native preparation was retired");
        if let Some(record) = &retained.record {
            let status = if journal.submission_recorded(record)? {
                OperationStatus::Pending
            } else {
                OperationStatus::Prepared
            };
            return Ok(transfer_report(&journal, record, status, None));
        }
        self.ensure_deadline()?;
        retained.request.ensure_live()?;
        let payload = if let Some(payload) = &retained.payload {
            payload.verify(&retained.request, &self.config)?
        } else {
            self.client
                .refresh_capabilities()
                .wrap_err("wallet transaction submission compatibility")?;
            let instructions = retained.request.operation.instructions(&self.config)?;
            let draft = AccountTransactionDraft::new(
                instructions,
                retained.request.requested_fee.clone(),
                Metadata::default(),
            );
            let mut payload = self.client.account_client().prepare_transaction(draft)?;
            let remaining = retained
                .request
                .deadline_ms
                .checked_sub(payload.creation_time_ms)
                .and_then(std::num::NonZeroU64::new)
                .ok_or_else(|| eyre!("original preparation deadline elapsed"))?;
            payload.time_to_live_ms = Some(
                payload
                    .time_to_live_ms
                    .map_or(remaining, |ttl| ttl.min(remaining)),
            );
            let quote = self
                .client
                .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })?;
            verify_quote_limits(&retained.request.requested_fee, &quote)?;
            if let Some(terms) = retained.request.operation.bounded_terms() {
                terms.verify_quote(&quote)?;
            }
            self.client.check_funding(
                &retained.request.operation.principal(&self.config.account)?,
                std::slice::from_ref(&quote),
            )?;
            payload.fee_payment = quote.intent.clone();
            verify_payload(retained.request.selection(), &quote, &payload, &self.config)?;
            let original = Payload::new(&retained.request, &payload, quote)?;
            self.ensure_deadline()?;
            retained.request.ensure_live()?;
            journal.write_native(NativeRecord::Payload, &original)?;
            retained.payload = Some(original);
            payload
        };
        self.ensure_deadline()?;
        retained.request.ensure_live()?;
        eyre::ensure!(
            payload_deadline(&payload)? > current_unix_ms()?,
            "original retained payload expired"
        );
        // This is the sole local signature boundary. The exact payload is already durable, and
        // no dispatch is possible until operation.json and the original marker are durable.
        let signed = self.client.account_client().sign_transaction(payload)?;
        let original = retained
            .payload
            .ok_or_else(|| eyre!("missing retained payload"))?;
        let request = retained.request;
        let record = TransactionJournal {
            schema: "iroha.wallet.native-transaction.v1".into(),
            torii_url: request.torii_url,
            chain_id: request.chain_id,
            network_id: request.network_id,
            chain_discriminant: request.chain_discriminant,
            account_id: request.account_id,
            operation: request.operation,
            requested_fee: request.requested_fee,
            quote: original.quote,
            transaction_hash: signed.try_hash_as_entrypoint()?.to_string(),
            signed_transaction_hex: bounded_hex(&encode_signed(&signed)?)?,
            deadline_ms: transaction_deadline(&signed)?,
        };
        record.verify(&self.config)?;
        journal.write_operation(&record)?;
        Ok(transfer_report(
            &journal,
            &record,
            OperationStatus::Prepared,
            None,
        ))
    }
}

pub(super) fn verify_payload(
    selection: Selection<'_>,
    quote: &FeeQuoteResponse,
    payload: &TransactionPayload,
    config: &Config,
) -> Result<()> {
    let deadline = payload_deadline(payload)?;
    let Executable::Instructions(instructions) = &payload.instructions else {
        eyre::bail!("native preparation must contain instructions");
    };
    eyre::ensure!(
        payload.domain == TransactionDomain::Network(config.network_id)
            && payload.authority == config.account
            && instructions.as_ref() == selection.operation.instructions(config)?.as_slice()
            && payload.metadata == Metadata::default()
            && payload.attachments.is_none()
            && deadline <= selection.deadline_ms
            && payload.fee_payment == quote.intent,
        "retained payload differs from original request, authority, fee or deadline"
    );
    verify_quote_limits(selection.requested_fee, quote)?;
    if let Some(terms) = selection.operation.bounded_terms() {
        terms.verify_quote(quote)?;
        eyre::ensure!(
            deadline <= terms.deadline_ms,
            "payload exceeds original bounded operation lifetime"
        );
    }
    if let NativeOperation::AliasSetup { plan, .. } = selection.operation {
        eyre::ensure!(
            deadline <= plan.body.valid_until_ms,
            "payload exceeds original alias plan lifetime"
        );
    }
    quote
        .validate_for_draft(payload)
        .map_err(|error| eyre!(error))?;
    Ok(())
}
fn payload_deadline(payload: &TransactionPayload) -> Result<u64> {
    payload
        .creation_time_ms
        .checked_add(
            payload
                .time_to_live_ms
                .ok_or_else(|| eyre!("missing original TTL"))?
                .get(),
        )
        .ok_or_else(|| eyre!("payload deadline overflow"))
}
fn encode_payload(payload: &TransactionPayload) -> Result<Vec<u8>> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let length = norito::canonical_frame_len(payload)?;
    eyre::ensure!(length <= PAYLOAD_MAX, "payload exceeds its byte bound");
    norito::core::to_bytes_bounded(payload, length).map_err(|error| match error {
        norito::core::BoundedEncodeError::Serialization(error)
            if error.decode_resource_error().is_some() =>
        {
            error.into()
        }
        error => eyre!("bounded payload encoding: {error:?}"),
    })
}
fn bounded_hex(bytes: &[u8]) -> Result<String> {
    let length = bytes
        .len()
        .checked_mul(2)
        .ok_or_else(|| eyre!("hex length overflow"))?;
    eyre::ensure!(
        length <= 2 * PAYLOAD_MAX,
        "native wire exceeds its byte bound"
    );
    norito::core::reserve_decode_allocation(length)?;
    let mut out = Vec::new();
    out.try_reserve_exact(length)?;
    out.resize(length, 0);
    hex::encode_to_slice(bytes, &mut out)?;
    Ok(String::from_utf8(out)?)
}
pub(super) fn decode_hex(value: &str, max: usize) -> Result<Vec<u8>> {
    eyre::ensure!(
        !value.is_empty()
            && value.len() % 2 == 0
            && value.len() / 2 <= max
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "noncanonical or oversized native hex"
    );
    let len = value.len() / 2;
    norito::core::reserve_decode_allocation(len)?;
    let mut out = Vec::new();
    out.try_reserve_exact(len)?;
    out.resize(len, 0);
    hex::decode_to_slice(value, &mut out)?;
    Ok(out)
}

/// Exact existing versioned wire: canonical version byte and canonical Norito payload owner.
pub(super) fn encode_signed(signed: &SignedTransaction) -> Result<Vec<u8>> {
    Ok(signed.wire_plan_v1()?.into_vec_bounded(PAYLOAD_MAX)?)
}

#[cfg(test)]
pub(super) fn retain_signed_fixture(path: &Path, record: &TransactionJournal) -> Result<Journal> {
    // Historical tests select actual signed bytes and retain the complete canonical preparation
    // chain. This does not manufacture inclusion or a current-state capability.
    let signed =
        SignedTransaction::decode_all_versioned(&hex::decode(&record.signed_transaction_hex)?)?;
    let request = Request {
        schema: "iroha.wallet.native-preparation.v1".into(),
        torii_url: record.torii_url.clone(),
        chain_id: record.chain_id.clone(),
        network_id: record.network_id,
        chain_discriminant: record.chain_discriminant,
        account_id: record.account_id.clone(),
        operation: record.operation.clone(),
        requested_fee: record.requested_fee.clone(),
        deadline_ms: record.deadline_ms,
    };
    let payload = Payload::new(&request, signed.payload(), record.quote.clone())?;
    let journal = Journal::create_preparation(path, &request)?;
    journal.write_native(NativeRecord::Payload, &payload)?;
    journal.write_operation(record)?;
    Ok(journal)
}
#[cfg(test)]
#[path = "operations_preparation_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "operations_byte_frame_tests.rs"]
mod byte_frame_tests;

#[cfg(test)]
#[path = "operations_preparation_scope_tests.rs"]
mod scope_tests;
