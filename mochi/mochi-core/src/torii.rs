//! Torii client utilities used by MOCHI.
//!
//! The client focuses on generating canonical endpoints and providing async
//! helpers for common HTTP interactions. Ledger streams use the account-bound
//! Rust SDK; Mochi owns only summaries, fanout and local reconnect policy.
use crate::compose::{InstructionPermission, SigningAuthority};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::future::join_all;
use iroha::client::AccountClient;
use iroha_crypto::{HashOf, KeyPair};
use iroha_data_model::{
    Identifiable,
    asset::{AssetDefinitionId, AssetId},
    block::{
        SignedBlock, consensus::SumeragiDiagnosticsStatus, execution_output::ExecutionOutputV1,
    },
    events::{
        EventBox, EventFilterBox,
        data::{DataEvent, DataEventFilter, prelude::*, sorafs},
        execute_trigger::ExecuteTriggerEventFilter,
        pipeline::{
            BlockEventFilter, PipelineEventBox, TransactionEventFilter, WitnessEventFilter,
        },
        time::{ExecutionTime, TimeEventFilter},
        trigger_completed::TriggerCompletedEventFilter,
    },
    isi::{SetKeyValue, SetParameter},
    nexus::{LaneLifecycleParameterV1, LaneLifecyclePlan, LaneLifecycleStatusV1},
    parameter::Parameter,
    prelude::{AccountId, NetworkId},
    query::{QueryOutput, QueryRequest, SignedQuery},
    sumeragi::SumeragiStatus,
    transaction::{SignedTransaction, TransactionBuilder, TransactionEntrypoint},
};
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_torii_shared::status::Status as TelemetryStatus;
use iroha_torii_shared::{ErrorEnvelope, mcp as torii_mcp, route_catalog as torii_routes};
use iroha_version::codec::EncodeVersioned;
use norito::json;
use rand::{TryRngCore as _, rngs::OsRng};
use reqwest::{Client, Response, StatusCode, header::HeaderMap};
use std::{
    convert::TryFrom,
    future::Future,
    num::{NonZeroU32, NonZeroU64},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    runtime::Handle,
    sync::{
        Mutex,
        broadcast::{self, error::RecvError},
        watch,
    },
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_stream::StreamExt;
use url::Url;
mod operator_auth;
pub use operator_auth::OperatorSigningContext;
use operator_auth::build_operator_get_request;
include!("torii/sumeragi_response_bounds.rs");
/// Convenience result alias for Torii client operations.
pub type ToriiResult<T> = std::result::Result<T, ToriiError>;
/// Errors emitted by the Torii client.
#[derive(thiserror::Error, Debug)]
pub enum ToriiError {
    /// Base URL could not be parsed or was not in the canonical first-release form.
    #[error("invalid Torii base URL: {0}")]
    InvalidBaseUrl(String),
    /// Endpoint URL composition failed.
    #[error("invalid Torii endpoint URL: {0}")]
    InvalidEndpoint(url::ParseError),
    /// A scheme other than HTTP(S) was supplied.
    #[error("unsupported Torii URL scheme `{scheme}`")]
    UnsupportedScheme { scheme: String },
    /// HTTP-level failure when talking to Torii.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    /// A response exceeded its route-specific retained-body budget or could
    /// not reserve memory within that budget.
    #[error("Torii {context} response exceeded its {maximum}-byte resource budget")]
    ResponseResourceLimit {
        /// Stable route family used for diagnostics without reflecting a URL.
        context: &'static str,
        /// Maximum complete response body admitted for the route family.
        maximum: usize,
    },
    /// Torii answered with a non-success status code.
    #[error("unexpected Torii status code {status}")]
    UnexpectedStatus {
        /// HTTP status code returned by Torii.
        status: StatusCode,
        /// Optional Torii reject code header value.
        reject_code: Option<String>,
        /// Optional error message decoded from the response body.
        message: Option<String>,
    },
    /// Torii throttled the request and may have supplied a retry delay.
    #[error("Torii request was rate limited")]
    RateLimited {
        /// Server-provided `Retry-After` delay, when it was a valid delta in seconds.
        retry_after: Option<Duration>,
    },
    /// Builder received an invalid header value.
    #[error("invalid HTTP header `{name}`: {source}")]
    InvalidHeader {
        /// Name of the header that failed to parse.
        name: String,
        /// Concrete header parse error.
        #[source]
        source: reqwest::header::InvalidHeaderValue,
    },
    /// Structured failure from the canonical account SDK.
    #[error("SDK error: {0}")]
    Sdk(#[source] Arc<iroha::Error>),
    /// Norito decoding failed.
    #[error("norito decode error: {0}")]
    Decode(String),
    /// Signed-query context could not be constructed safely.
    #[error("signed query context error: {0}")]
    SignedQueryContext(String),
    /// Timed out while waiting for Torii to produce a response.
    #[error("timeout while waiting for Torii: {context}")]
    Timeout { context: String },
    /// A smoke transaction was rejected (or expired) before commitment.
    #[error("smoke transaction {hash} rejected: {reason}")]
    SmokeRejected { hash: String, reason: String },
    /// Torii could not prove whether the exact smoke transaction was admitted.
    #[error("smoke transaction admission outcome remains unknown for {hash}")]
    SmokeAdmissionOutcomeUnknown { hash: String },
}
/// High-level classification for [`ToriiError`] variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToriiErrorKind {
    /// Invalid or unparsable base URL was supplied.
    InvalidBaseUrl,
    /// Derived endpoint URL was invalid.
    InvalidEndpoint,
    /// Unsupported URL scheme was supplied.
    UnsupportedScheme,
    /// Invalid HTTP header configuration.
    InvalidHeader,
    /// Transport-level HTTP failure before receiving a response body.
    HttpTransport,
    /// Torii response exceeded a route-specific memory budget.
    ResponseResourceLimit,
    /// Torii responded with an unexpected status code.
    UnexpectedStatus,
    /// The canonical account SDK rejected or failed an operation.
    Sdk,
    /// Norito payload decoding failed.
    Decode,
    /// Signed-query network, time, nonce, or signing context was unavailable.
    SignedQueryContext,
    /// Operation exceeded the configured timeout.
    Timeout,
    /// Smoke transaction was rejected or expired.
    SmokeRejected,
    /// Smoke transaction admission remained ambiguous after exact-hash reconciliation.
    SmokeAdmissionOutcomeUnknown,
}
/// Summary of a [`ToriiError`] capturing its user-facing message and kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToriiErrorInfo {
    /// Classified error kind.
    pub kind: ToriiErrorKind,
    /// Human-readable message suitable for UI surfaces.
    pub message: String,
    /// Optional detail string providing additional context (e.g., status code).
    pub detail: Option<String>,
    /// Optional Torii reject code attached to the response.
    pub reject_code: Option<String>,
}
impl ToriiErrorInfo {
    /// Construct a summary with no additional detail.
    #[must_use]
    pub fn new(kind: ToriiErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: None,
            reject_code: None,
        }
    }
    /// Construct a summary with an accompanying detail string.
    #[must_use]
    pub fn with_detail(
        kind: ToriiErrorKind,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: Some(detail.into()),
            reject_code: None,
        }
    }
}
impl ToriiError {
    /// Produce a classified summary of the error for display or logging purposes.
    #[must_use]
    pub fn summarize(&self) -> ToriiErrorInfo {
        match self {
            Self::InvalidBaseUrl(err) => ToriiErrorInfo::with_detail(
                ToriiErrorKind::InvalidBaseUrl,
                "Invalid Torii base URL",
                err.to_string(),
            ),
            Self::InvalidEndpoint(err) => ToriiErrorInfo::with_detail(
                ToriiErrorKind::InvalidEndpoint,
                "Invalid Torii endpoint URL",
                err.to_string(),
            ),
            Self::UnsupportedScheme { scheme } => ToriiErrorInfo::with_detail(
                ToriiErrorKind::UnsupportedScheme,
                "Unsupported Torii URL scheme",
                scheme.clone(),
            ),
            Self::Http(err) => ToriiErrorInfo::with_detail(
                ToriiErrorKind::HttpTransport,
                "HTTP transport error while contacting Torii",
                err.to_string(),
            ),
            Self::ResponseResourceLimit { context, maximum } => ToriiErrorInfo::with_detail(
                ToriiErrorKind::ResponseResourceLimit,
                "Torii response exceeded its memory budget",
                format!("{context} response limit: {maximum} bytes"),
            ),
            Self::UnexpectedStatus {
                status,
                reject_code,
                message,
            } => {
                let mut detail = status.to_string();
                if let Some(message) = message
                    && !message.is_empty()
                {
                    detail = format!("{detail} - {message}");
                }
                let mut info = ToriiErrorInfo::with_detail(
                    ToriiErrorKind::UnexpectedStatus,
                    format!("Unexpected Torii status code {status}"),
                    detail,
                );
                info.reject_code = reject_code.clone();
                info
            }
            Self::RateLimited { retry_after } => {
                let detail = retry_after.map_or_else(
                    || "HTTP 429 without a valid Retry-After hint".to_owned(),
                    |delay| format!("HTTP 429; retry after {delay:?}"),
                );
                ToriiErrorInfo::with_detail(
                    ToriiErrorKind::UnexpectedStatus,
                    "Torii request was rate limited",
                    detail,
                )
            }
            Self::InvalidHeader { name, source } => ToriiErrorInfo::with_detail(
                ToriiErrorKind::InvalidHeader,
                format!("Invalid HTTP header `{name}`"),
                source.to_string(),
            ),
            Self::Sdk(err) => ToriiErrorInfo::with_detail(
                ToriiErrorKind::Sdk,
                "Account SDK operation failed",
                err.to_string(),
            ),
            Self::Decode(err) => ToriiErrorInfo::with_detail(
                ToriiErrorKind::Decode,
                "Failed to decode Norito payload from Torii",
                err.clone(),
            ),
            Self::SignedQueryContext(err) => ToriiErrorInfo::with_detail(
                ToriiErrorKind::SignedQueryContext,
                "Failed to construct a replay-safe signed query",
                err.clone(),
            ),
            Self::Timeout { context } => ToriiErrorInfo::with_detail(
                ToriiErrorKind::Timeout,
                "Timed out while waiting for Torii",
                context.clone(),
            ),
            Self::SmokeRejected { hash, reason } => ToriiErrorInfo::with_detail(
                ToriiErrorKind::SmokeRejected,
                format!("Smoke transaction {hash} was rejected"),
                reason.clone(),
            ),
            Self::SmokeAdmissionOutcomeUnknown { hash } => ToriiErrorInfo::with_detail(
                ToriiErrorKind::SmokeAdmissionOutcomeUnknown,
                format!("Smoke transaction admission outcome remains unknown for {hash}"),
                "Reconcile or resubmit only the byte-identical signed transaction".to_owned(),
            ),
        }
    }
    fn is_transaction_dispatch_outcome_unknown(&self) -> bool {
        matches!(
            self,
            Self::UnexpectedStatus {
                reject_code: Some(code),
                ..
            } if code == TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE
        )
    }
    fn confirms_existing_submission(&self) -> bool {
        matches!(
            self,
            Self::UnexpectedStatus {
                reject_code: Some(code),
                ..
            } if matches!(
                code.as_str(),
                "PRTRY:ALREADY_ENQUEUED" | "PRTRY:ALREADY_COMMITTED"
            )
        )
    }
    /// Return the server-provided retry delay for a throttled request.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => *retry_after,
            _ => None,
        }
    }
}
include!("torii/response_error_headers.rs");
fn response_status_error(response: &reqwest::Response) -> ToriiError {
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        ToriiError::RateLimited {
            retry_after: retry_after_from_headers(response.headers()),
        }
    } else {
        ToriiError::UnexpectedStatus {
            status: response.status(),
            reject_code: reject_code_from_headers(response.headers()),
            message: None,
        }
    }
}
impl From<iroha::Error> for ToriiError {
    fn from(error: iroha::Error) -> Self {
        Self::Sdk(Arc::new(error))
    }
}
fn error_message_from_body(body: &[u8]) -> Option<String> {
    if let Ok(envelope) = decode_norito::<ErrorEnvelope>(body) {
        return Some(if envelope.code.is_empty() {
            envelope.message
        } else {
            format!("{}: {}", envelope.code, envelope.message)
        });
    }
    if let Ok(value) = norito::json::from_slice::<json::Value>(body)
        && let Some(message) = value
            .get("message")
            .or_else(|| value.get("error"))
            .and_then(json::Value::as_str)
    {
        let code = value.get("code").and_then(json::Value::as_str);
        return Some(match code {
            Some(code) if !code.is_empty() => format!("{code}: {message}"),
            _ => message.to_owned(),
        });
    }
    let text = String::from_utf8_lossy(body).trim().to_owned();
    if text.is_empty() { None } else { Some(text) }
}
fn decode_bounded_json_response(bytes: &[u8], context: &'static str) -> ToriiResult<json::Value> {
    const MAX_VALUES: usize = 262_144;
    const MAX_STRING_BYTES: usize = 1024 * 1024;
    const MAX_CONTAINER_ENTRIES: usize = 65_536;
    const MAX_DEPTH: usize = 64;
    let limits = norito::json::JsonPreflightLimits::new(
        MAX_JSON_RESPONSE_BYTES,
        MAX_VALUES,
        MAX_JSON_RESPONSE_BYTES,
        MAX_STRING_BYTES,
        MAX_JSON_RESPONSE_BYTES,
        MAX_CONTAINER_ENTRIES,
        MAX_VALUES,
        MAX_VALUES,
        MAX_VALUES,
        MAX_DEPTH,
    );
    norito::json::preflight_slice(bytes, limits).map_err(|_| {
        ToriiError::Decode(format!(
            "{context} response failed bounded JSON syntax/resource preflight"
        ))
    })?;
    json::from_slice(bytes)
        .map_err(|_| ToriiError::Decode(format!("{context} response failed JSON decoding")))
}
async fn read_bounded_json_response(
    response: Response,
    context: &'static str,
) -> ToriiResult<json::Value> {
    let bytes = read_bounded_response(response, MAX_JSON_RESPONSE_BYTES, context).await?;
    decode_bounded_json_response(&bytes, context)
}
fn compose_base_urls(base_url: &str) -> ToriiResult<(Url, Url)> {
    let http_base =
        Url::parse(base_url).map_err(|error| ToriiError::InvalidBaseUrl(error.to_string()))?;
    if !http_base.username().is_empty() || http_base.password().is_some() {
        return Err(ToriiError::InvalidBaseUrl(
            "embedded URL credentials are not allowed".to_owned(),
        ));
    }
    if http_base.query().is_some() || http_base.fragment().is_some() {
        return Err(ToriiError::InvalidBaseUrl(
            "base URL query and fragment components are not allowed".to_owned(),
        ));
    }
    let scheme = http_base.scheme().to_owned();
    let ws_scheme = match scheme.as_str() {
        "http" => "ws",
        "https" => "wss",
        other => {
            return Err(ToriiError::UnsupportedScheme {
                scheme: other.to_owned(),
            });
        }
    };
    let mut ws_base = http_base.clone();
    ws_base
        .set_scheme(ws_scheme)
        .map_err(|_| ToriiError::UnsupportedScheme {
            scheme: scheme.clone(),
        })?;
    Ok((http_base, ws_base))
}
/// Options for waiting until a peer responds to `/status`.
#[derive(Debug, Clone, Copy)]
pub struct ReadinessOptions {
    /// Maximum duration to wait before giving up.
    pub timeout: Duration,
    /// Delay between successive probes while waiting for readiness.
    pub poll_interval: Duration,
}
/// A managed Torii peer that failed to report a committed genesis block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPeerGenesisFailure {
    /// Stable peer alias from the managed topology.
    pub alias: String,
    /// Torii base URL that was probed.
    pub base_url: String,
    /// Classified failure returned by the peer's readiness probe.
    pub error: ToriiErrorInfo,
}
/// Failure of the all-managed-peer genesis readiness gate.
#[derive(Debug, thiserror::Error)]
pub enum ManagedPeerGenesisReadinessError {
    /// No managed peers were supplied to the gate.
    #[error("cannot wait for committed genesis because no managed Torii peers were supplied")]
    NoManagedPeers,
    /// One or more managed peers failed to report committed genesis before the deadline.
    #[error("not every managed Torii peer reported committed genesis: {diagnostics}")]
    PeerFailures {
        /// Actionable alias, endpoint, and error details for every failed peer.
        diagnostics: String,
        /// Structured failures for callers that render their own diagnostics.
        failures: Vec<ManagedPeerGenesisFailure>,
    },
}
impl ManagedPeerGenesisReadinessError {
    /// Structured per-peer failures, or an empty slice when no peers were supplied.
    #[must_use]
    pub fn failures(&self) -> &[ManagedPeerGenesisFailure] {
        match self {
            Self::NoManagedPeers => &[],
            Self::PeerFailures { failures, .. } => failures,
        }
    }
}
/// Wait concurrently until every managed Torii peer reports at least one committed block.
///
/// Each peer receives the same bounded readiness deadline. Running the probes concurrently keeps
/// the topology-wide gate bounded by that deadline rather than multiplying it by the peer count.
/// No transaction should be submitted to a managed multi-peer network before this gate succeeds.
pub async fn wait_for_all_managed_peers_genesis(
    peers: Vec<(String, ToriiClient)>,
    options: ReadinessOptions,
) -> Result<Vec<(String, ToriiStatusSnapshot)>, ManagedPeerGenesisReadinessError> {
    if peers.is_empty() {
        return Err(ManagedPeerGenesisReadinessError::NoManagedPeers);
    }
    let probes = peers.into_iter().map(|(alias, client)| async move {
        let base_url = client.base_url().to_owned();
        let result = client.wait_for_genesis_commit(options).await;
        (alias, base_url, result)
    });
    let mut committed = Vec::new();
    let mut failures = Vec::new();
    for (alias, base_url, result) in join_all(probes).await {
        match result {
            Ok(snapshot) => committed.push((alias, snapshot)),
            Err(error) => failures.push(ManagedPeerGenesisFailure {
                alias,
                base_url,
                error: error.summarize(),
            }),
        }
    }
    if failures.is_empty() {
        return Ok(committed);
    }
    let diagnostics = failures
        .iter()
        .map(|failure| {
            let detail = failure
                .error
                .detail
                .as_deref()
                .map_or_else(String::new, |detail| format!(" ({detail})"));
            format!(
                "{} at {}: {}{}",
                failure.alias, failure.base_url, failure.error.message, detail
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Err(ManagedPeerGenesisReadinessError::PeerFailures {
        diagnostics,
        failures,
    })
}
impl ReadinessOptions {
    /// Create a readiness configuration with the supplied timeout and a default poll interval.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            poll_interval: Duration::from_millis(250),
        }
    }
    /// Override the poll interval used when waiting for readiness.
    #[must_use]
    pub const fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }
}
/// Options for waiting until a submitted transaction is observed in the committed block stream.
#[derive(Debug, Clone, Copy)]
pub struct SmokeCommitOptions {
    /// Maximum duration for stream setup, submission, and commit observation.
    pub timeout: Duration,
}
impl SmokeCommitOptions {
    /// Create options with the provided timeout.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}
impl Default for SmokeCommitOptions {
    fn default() -> Self {
        Self::new(Duration::from_secs(15))
    }
}
fn smoke_commit_deadline(started: Instant, timeout: Duration) -> ToriiResult<Instant> {
    started.checked_add(timeout).ok_or_else(|| {
        ToriiError::Decode(
            "smoke commit timeout exceeds the platform monotonic-clock range".to_owned(),
        )
    })
}
async fn await_torii_before_deadline<T>(
    deadline: Instant,
    context: &str,
    operation: impl Future<Output = ToriiResult<T>>,
) -> ToriiResult<T> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ToriiError::Timeout {
            context: context.to_owned(),
        });
    }
    timeout(remaining, operation)
        .await
        .map_err(|_| ToriiError::Timeout {
            context: context.to_owned(),
        })?
}
/// Successful observation of a committed smoke transaction.
#[derive(Debug, Clone)]
pub struct SmokeCommitSnapshot {
    /// Hash of the submitted transaction.
    pub tx_hash: HashOf<SignedTransaction>,
    /// Height of the block that carried the transaction.
    pub block_height: u64,
    /// Elapsed time between submission and commitment observation.
    pub elapsed: Duration,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum SmokeTransactionStatus {
    Queued,
    Committed(u64),
    Rejected(String),
    Expired,
}
/// Options governing a full readiness smoke probe (status poll + commit check).
#[derive(Debug, Clone)]
pub struct ReadinessSmokePlan {
    /// `/status` probe options used before submitting the smoke transaction.
    pub status_options: ReadinessOptions,
    /// Commit wait options for each attempt.
    pub commit_options: SmokeCommitOptions,
    /// Backoff applied between attempts.
    pub backoff: Duration,
    /// Transactions to try in order (one per attempt).
    pub transactions: Vec<SignedTransaction>,
    /// Recipe used to renew Mochi-generated transactions after genesis readiness.
    ///
    /// Callers that provide pre-signed transactions through [`Self::new`] retain
    /// exact-envelope semantics and are never re-signed.
    factory: Option<ReadinessSmokeFactory>,
}
#[derive(Debug, Clone)]
struct ReadinessSmokeFactory {
    network_id: NetworkId,
    signer: SigningAuthority,
    attempts: usize,
    nonce_offset: usize,
}
impl ReadinessSmokeFactory {
    fn build_transactions(
        &self,
        creation_time: Duration,
        ttl: Duration,
    ) -> Result<Vec<SignedTransaction>, ReadinessSmokeBuildError> {
        (0..self.attempts)
            .map(|attempt| {
                build_readiness_smoke_transaction_at(
                    self.network_id,
                    &self.signer,
                    attempt + self.nonce_offset,
                    creation_time,
                    ttl,
                )
            })
            .collect()
    }
}
impl ReadinessSmokePlan {
    /// Construct a plan using the provided transactions and default timeouts/backoff.
    #[must_use]
    pub fn new(transactions: Vec<SignedTransaction>) -> Self {
        Self {
            status_options: ReadinessOptions::default(),
            commit_options: SmokeCommitOptions::default(),
            backoff: Duration::from_millis(400),
            transactions,
            factory: None,
        }
    }
    /// Build an exact-network plan that updates metadata on the signing account.
    ///
    /// Each attempt carries a unique nonce so retries do not collide.
    pub fn for_signer_with_attempts(
        network_id: NetworkId,
        signer: &SigningAuthority,
        attempts: usize,
    ) -> Result<Self, ReadinessSmokeBuildError> {
        Self::for_signer_with_attempts_and_offset(network_id, signer, attempts, 0)
    }
    /// Build an exact-network plan with unique nonces derived from the provided offset.
    pub fn for_signer_with_attempts_and_offset(
        network_id: NetworkId,
        signer: &SigningAuthority,
        attempts: usize,
        nonce_offset: usize,
    ) -> Result<Self, ReadinessSmokeBuildError> {
        let attempts = attempts.max(1);
        let factory = ReadinessSmokeFactory {
            network_id,
            signer: signer.clone(),
            attempts,
            nonce_offset,
        };
        let transactions = factory.build_transactions(unix_time_now(), SMOKE_TTL)?;
        Ok(Self {
            factory: Some(factory),
            ..Self::new(transactions)
        })
    }
    /// Build a single-attempt exact-network plan using the provided signer.
    pub fn for_signer(
        network_id: NetworkId,
        signer: &SigningAuthority,
    ) -> Result<Self, ReadinessSmokeBuildError> {
        Self::for_signer_with_attempts(network_id, signer, 1)
    }
    /// Iterator over the hashes of the configured smoke transactions.
    pub fn tx_hashes(&self) -> impl Iterator<Item = HashOf<SignedTransaction>> + '_ {
        self.transactions.iter().map(SignedTransaction::hash)
    }
    fn renew_generated_transactions_if_needed(
        &mut self,
        now: Duration,
    ) -> Result<(), ReadinessSmokeBuildError> {
        let Some(factory) = &self.factory else {
            return Ok(());
        };
        let required_lifetime = self.required_submission_lifetime();
        let required_ttl = required_lifetime.max(SMOKE_TTL);
        let renew_before = now.saturating_add(required_lifetime);
        let remains_fresh = self.transactions.iter().all(|transaction| {
            transaction
                .time_to_live()
                .and_then(|ttl| transaction.creation_time().checked_add(ttl))
                .is_some_and(|expires_at| expires_at >= renew_before)
        });
        if remains_fresh {
            return Ok(());
        }
        self.transactions = factory.build_transactions(now, required_ttl)?;
        Ok(())
    }
    fn required_submission_lifetime(&self) -> Duration {
        let attempts = u32::try_from(self.transactions.len().max(1)).unwrap_or(u32::MAX);
        let mut lifetime = self.commit_options.timeout.saturating_mul(attempts);
        let mut backoff = self.backoff.max(Duration::from_millis(50)).min(MAX_BACKOFF);
        for _ in 1..attempts {
            lifetime = lifetime.saturating_add(backoff);
            backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        }
        lifetime.saturating_add(SMOKE_SUBMISSION_MARGIN)
    }
}
/// Errors that can occur while constructing a readiness smoke plan.
#[derive(Debug, thiserror::Error)]
pub enum ReadinessSmokeBuildError {
    /// Failed to construct the smoke domain identifier.
    #[error("invalid readiness smoke domain `{0}`")]
    InvalidDomain(String),
    /// Failed to sign a smoke transaction.
    #[error("failed to sign readiness smoke transaction: {reason}")]
    Signing {
        /// Human readable failure reason.
        reason: String,
    },
}
/// Result of a readiness smoke probe.
#[derive(Debug, Clone)]
pub struct ReadinessSmokeOutcome {
    /// Zero-based elapsed time for the full probe (including retries and status polling).
    pub total_elapsed: Duration,
    /// Attempt number (1-indexed) that yielded a commit.
    pub attempt: usize,
    /// Snapshot of the commit location for the smoke transaction.
    pub commit: SmokeCommitSnapshot,
    /// Optional status snapshot captured after the commit to surface queue depth.
    pub status: Option<ToriiStatusSnapshot>,
}
/// Summary of a local Torii MCP probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMcpProbeResult {
    /// Native MCP protocol version confirmed by `server/discover`.
    pub protocol_version: String,
    /// Optional server toolset version hash returned by `tools/list`.
    pub toolset_version: Option<String>,
    /// Number of visible tools in the local MCP catalog.
    pub tool_count: usize,
    /// Visible tool names returned by `tools/list`.
    pub tool_names: Vec<String>,
}
impl LocalMcpProbeResult {
    fn from_documents(discovery: &json::Value, tools_list: &json::Value) -> ToriiResult<Self> {
        let discovery_result = discovery
            .as_object()
            .and_then(|doc| doc.get("result"))
            .and_then(json::Value::as_object)
            .ok_or_else(|| decode_error("mcp server/discover", "missing result object"))?;
        if discovery_result
            .get("resultType")
            .and_then(json::Value::as_str)
            != Some("complete")
        {
            return Err(decode_error(
                "mcp server/discover result",
                "resultType must be complete",
            ));
        }
        let supports_native_protocol = discovery_result
            .get("supportedVersions")
            .and_then(json::Value::as_array)
            .is_some_and(|versions| {
                versions.len() == 1
                    && versions[0].as_str() == Some(torii_mcp::MODERN_PROTOCOL_VERSION)
            });
        if !supports_native_protocol {
            return Err(decode_error(
                "mcp server/discover result",
                format!(
                    "supportedVersions must contain only protocol version {}",
                    torii_mcp::MODERN_PROTOCOL_VERSION
                ),
            ));
        }
        let tools_result = tools_list
            .as_object()
            .and_then(|doc| doc.get("result"))
            .and_then(json::Value::as_object)
            .ok_or_else(|| decode_error("mcp tools/list", "missing result object"))?;
        if tools_result.get("resultType").and_then(json::Value::as_str) != Some("complete") {
            return Err(decode_error(
                "mcp tools/list result",
                "resultType must be complete",
            ));
        }
        let tools = tools_result
            .get("tools")
            .and_then(json::Value::as_array)
            .ok_or_else(|| decode_error("mcp tools/list result", "missing tools array"))?;
        let mut tool_names = Vec::with_capacity(tools.len());
        for (index, tool) in tools.iter().enumerate() {
            let tool_obj = tool.as_object().ok_or_else(|| {
                decode_error(
                    "mcp tools/list result.tools",
                    format!("tool {index} must be an object"),
                )
            })?;
            tool_names.push(parse_required_string(
                tool_obj,
                "name",
                "mcp tools/list result.tools[].name",
            )?);
        }
        if !tool_names.iter().any(|name| name.starts_with("iroha.")) {
            return Err(decode_error(
                "mcp tools/list result",
                "expected curated iroha.* tools to be exposed",
            ));
        }
        if tool_names.iter().any(|name| name.starts_with("torii.")) {
            return Err(decode_error(
                "mcp tools/list result",
                "raw torii.* tools must stay hidden for local Mochi sandboxes",
            ));
        }
        Ok(Self {
            protocol_version: torii_mcp::MODERN_PROTOCOL_VERSION.to_owned(),
            toolset_version: tools_result
                .get("_meta")
                .and_then(json::Value::as_object)
                .and_then(|meta| meta.get("iroha"))
                .and_then(json::Value::as_object)
                .and_then(|iroha| iroha.get("toolsetVersion"))
                .and_then(json::Value::as_str)
                .map(str::to_owned),
            tool_count: tool_names.len(),
            tool_names,
        })
    }
}
const SMOKE_TTL: Duration = Duration::from_secs(30);
const SMOKE_SUBMISSION_MARGIN: Duration = Duration::from_secs(5);
const SMOKE_EXACT_RESUBMIT_DELAY: Duration = Duration::from_millis(250);
const SMOKE_EXACT_RESUBMIT_INTERVAL: Duration = Duration::from_secs(1);
const TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE: &str =
    "transaction_dispatch_outcome_unknown";
fn encode_lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(*byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(*byte & 0x0f)] as char);
    }
    encoded
}
fn unix_time_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}
fn smoke_transaction_result_in_block(
    block: &SignedBlock,
    tx_hash: &HashOf<SignedTransaction>,
) -> Option<ToriiResult<u64>> {
    if !block.has_results() {
        return None;
    }
    block
        .network_entrypoints()
        .enumerate()
        .find_map(|(input_index, entrypoint)| {
            let is_match = match entrypoint {
                TransactionEntrypoint::External(transaction) => transaction.hash() == *tx_hash,
                TransactionEntrypoint::SealedReveal(reveal) => {
                    reveal.signed_transaction().hash() == *tx_hash
                }
                TransactionEntrypoint::SealedCommitment(_)
                | TransactionEntrypoint::AnonymousBallot(_) => false,
            };
            if !is_match {
                return None;
            }
            let (_, output) = block.network_output_at(u32::try_from(input_index).ok()?)?;
            Some(match output.result.as_ref() {
                Ok(_) => Ok(block.header().height().get()),
                Err(reason) => Err(ToriiError::SmokeRejected {
                    hash: encode_lower_hex(tx_hash.as_ref()),
                    reason: format!("{reason:?}"),
                }),
            })
        })
}
#[derive(Debug, Default)]
struct ReadinessSmokeAttemptCursor {
    next_index: usize,
    pinned_index: Option<usize>,
}
impl ReadinessSmokeAttemptCursor {
    fn current_index(&self) -> usize {
        self.pinned_index.unwrap_or(self.next_index)
    }
    fn record_failure(&mut self, index: usize, error: &ToriiError) {
        if self.pinned_index.is_some() {
            return;
        }
        if matches!(error, ToriiError::SmokeAdmissionOutcomeUnknown { .. }) {
            self.pinned_index = Some(index);
        } else {
            self.next_index = index.saturating_add(1);
        }
    }
    fn is_pinned(&self) -> bool {
        self.pinned_index.is_some()
    }
}
fn build_lane_lifecycle_transaction(
    network_id: NetworkId,
    signer: &SigningAuthority,
    status: &LaneLifecycleStatusV1,
    plan: LaneLifecyclePlan,
) -> ToriiResult<SignedTransaction> {
    if !signer.allows_permission(InstructionPermission::SetParameters) {
        return Err(ToriiError::Decode(format!(
            "signer `{}` is not configured with CanSetParameters",
            signer.label()
        )));
    }
    let catalog = status
        .validate()
        .map_err(|err| ToriiError::Decode(format!("invalid lane lifecycle status: {err}")))?;
    let custom = LaneLifecycleParameterV1::new(&catalog, &status.incarnations, plan)
        .map_err(|err| ToriiError::Decode(format!("invalid lane incarnation binding: {err}")))?
        .into_custom_parameter();
    let mut builder = TransactionBuilder::new(
        network_id,
        signer.account_id().clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([SetParameter::new(Parameter::Custom(custom))]);
    builder.set_ttl(SMOKE_TTL);
    builder
        .try_sign(signer.key_pair().private_key())
        .map_err(|err| {
            ToriiError::Decode(format!("failed to sign lane lifecycle transaction: {err}"))
        })
}
fn build_readiness_smoke_transaction_at(
    network_id: NetworkId,
    signer: &SigningAuthority,
    attempt: usize,
    creation_time: Duration,
    ttl: Duration,
) -> Result<SignedTransaction, ReadinessSmokeBuildError> {
    let now_ms = creation_time.as_millis();
    let key = "mochi_smoke"
        .parse()
        .expect("readiness smoke metadata key is valid");
    let value = Json::new(format!("{now_ms}:{attempt}"));
    let quantity = u32::try_from(attempt + 1).unwrap_or(u32::MAX);
    let authority = signer.account_id().clone();
    let mut builder = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([SetKeyValue::account(authority, key, value)]);
    if let Some(nonce) = NonZeroU32::new(quantity) {
        builder.set_nonce(nonce);
    }
    builder.set_creation_time(creation_time);
    builder.set_ttl(ttl);
    builder
        .try_sign(signer.key_pair().private_key())
        .map_err(|err| ReadinessSmokeBuildError::Signing {
            reason: err.to_string(),
        })
}
impl Default for ReadinessOptions {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}
/// Fixed first-release timeout for individual Torii HTTP requests.
const TORII_HTTP_REQUEST_TIMEOUT_V1: Duration = Duration::from_secs(10);
/// Builder for [`ToriiClient`] authentication and network-lineage settings.
#[derive(Debug)]
pub struct ToriiClientBuilder {
    http_base: Url,
    ws_base: Url,
    network_id: Option<NetworkId>,
    api_token: Option<iroha::secrecy::SecretString>,
    operator_signing_context: Option<OperatorSigningContext>,
}
impl ToriiClientBuilder {
    /// Create a builder targeting the provided Torii base URL.
    pub fn new(base_url: impl AsRef<str>) -> ToriiResult<Self> {
        let (http_base, ws_base) = compose_base_urls(base_url.as_ref())?;
        Ok(Self {
            http_base,
            ws_base,
            network_id: None,
            api_token: None,
            operator_signing_context: None,
        })
    }
    /// Bind all signed queries produced by this client to one exact genesis lineage.
    pub fn with_network_id(mut self, network_id: NetworkId) -> Self {
        self.network_id = Some(network_id);
        self
    }
    /// Install immutable operator signing material bound to one exact network.
    #[must_use]
    pub fn with_operator_signing_context(mut self, context: OperatorSigningContext) -> Self {
        self.operator_signing_context = Some(context);
        self
    }
    /// Install the runtime-only private listener credential on every HTTP request.
    #[must_use]
    pub fn with_api_token(mut self, token: Option<iroha::secrecy::SecretString>) -> Self {
        self.api_token = token;
        self
    }
    /// Consume the builder and construct a [`ToriiClient`].
    pub fn build(self) -> ToriiResult<ToriiClient> {
        let network_id = match (self.network_id, self.operator_signing_context.as_ref()) {
            (Some(configured), Some(context)) if configured != context.network_id() => {
                return Err(ToriiError::SignedQueryContext(format!(
                    "operator signing context network id `{}` does not match client network id `{configured}`",
                    context.network_id()
                )));
            }
            (Some(configured), _) => Some(configured),
            (None, Some(context)) => Some(context.network_id()),
            (None, None) => None,
        };
        // Signed query bodies are one-shot. A redirect could replay the same
        // nonce after the original endpoint already admitted the request.
        let mut headers = HeaderMap::new();
        if let Some(token) = self.api_token {
            let mut value = reqwest::header::HeaderValue::from_str(token.expose_secret())
                .map_err(|_| ToriiError::Decode("invalid private listener credential".into()))?;
            value.set_sensitive(true);
            headers.insert("x-api-token", value);
        }
        let http = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(TORII_HTTP_REQUEST_TIMEOUT_V1)
            .build()?;
        Ok(ToriiClient {
            http_base: self.http_base,
            ws_base: self.ws_base,
            network_id,
            operator_signing_context: self.operator_signing_context.map(Arc::new),
            http,
            status_state: Arc::new(Mutex::new(StatusState::default())),
        })
    }
}
/// Metrics derived from consecutive Torii status samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatusMetrics {
    /// Latest commit latency in milliseconds.
    pub commit_latency_ms: u64,
    /// Current transaction queue depth.
    pub queue_size: u64,
    /// Change in queue depth compared to the previous sample.
    pub queue_delta: i64,
    /// Number of blocks committed since the previous sample.
    pub block_delta: u64,
    /// Number of non-empty blocks committed since the previous sample.
    pub blocks_non_empty_delta: u64,
    /// Approved transaction increase since the previous sample.
    pub tx_approved_delta: u64,
    /// Rejected transaction increase since the previous sample.
    pub tx_rejected_delta: u64,
    /// View-change count increase since the previous sample.
    pub view_change_delta: u32,
    /// Milliseconds elapsed between this snapshot and the previous sample.
    pub sample_interval_ms: u64,
}
impl StatusMetrics {
    /// Compute derived metrics using the previous and current telemetry snapshots.
    #[must_use]
    pub fn from_samples(previous: Option<&TelemetryStatus>, current: &TelemetryStatus) -> Self {
        let queue_delta = previous
            .map(|prev| current.queue_size as i64 - prev.queue_size as i64)
            .unwrap_or_default();
        let (block_delta, blocks_non_empty_delta) = previous
            .map(|prev| {
                (
                    current.blocks.saturating_sub(prev.blocks),
                    current
                        .blocks_non_empty
                        .saturating_sub(prev.blocks_non_empty),
                )
            })
            .unwrap_or((0, 0));
        let (tx_approved_delta, tx_rejected_delta, view_change_delta) = previous
            .map(|prev| {
                (
                    current.txs_approved.saturating_sub(prev.txs_approved),
                    current.txs_rejected.saturating_sub(prev.txs_rejected),
                    current.view_changes.saturating_sub(prev.view_changes),
                )
            })
            .unwrap_or((0, 0, 0));
        Self {
            commit_latency_ms: current.commit_time_ms,
            queue_size: current.queue_size,
            queue_delta,
            block_delta,
            blocks_non_empty_delta,
            tx_approved_delta,
            tx_rejected_delta,
            view_change_delta,
            sample_interval_ms: 0,
        }
    }
    /// Whether any notable activity occurred between the last two samples.
    #[must_use]
    pub fn has_activity(&self) -> bool {
        self.tx_approved_delta > 0
            || self.tx_rejected_delta > 0
            || self.queue_delta != 0
            || self.block_delta > 0
            || self.blocks_non_empty_delta > 0
            || self.view_change_delta > 0
    }
}
/// Telemetry snapshot enriched with derived metrics.
#[derive(Debug, Clone)]
pub struct ToriiStatusSnapshot {
    /// Instant when the sample was captured.
    pub timestamp: Instant,
    /// Raw telemetry payload returned by Torii.
    pub status: TelemetryStatus,
    /// Derived metrics computed from the last two samples.
    pub metrics: StatusMetrics,
}
impl ToriiStatusSnapshot {
    fn new(timestamp: Instant, status: TelemetryStatus, metrics: StatusMetrics) -> Self {
        Self {
            timestamp,
            status,
            metrics,
        }
    }
}
#[derive(Debug, Default)]
struct StatusState {
    previous: Option<StatusSample>,
}
impl StatusState {
    fn record(&mut self, timestamp: Instant, status: &TelemetryStatus) -> StatusMetrics {
        let mut metrics = StatusMetrics::from_samples(
            self.previous.as_ref().map(|sample| &sample.status),
            status,
        );
        metrics.sample_interval_ms = self
            .previous
            .as_ref()
            .and_then(|sample| timestamp.checked_duration_since(sample.timestamp))
            .map(duration_to_millis)
            .unwrap_or(0);
        self.previous = Some(StatusSample {
            timestamp,
            status: status.clone(),
        });
        metrics
    }
}
#[derive(Debug, Clone)]
struct StatusSample {
    timestamp: Instant,
    status: TelemetryStatus,
}
fn duration_to_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
/// Selected gauges sampled from the `/metrics` Prometheus endpoint.
#[derive(Debug, Clone)]
pub struct ToriiMetricsSnapshot {
    /// Instant when the metrics payload was fetched.
    pub timestamp: Instant,
    /// Size of the transaction queue reported by telemetry.
    pub queue_size: Option<f64>,
    /// Number of view changes recorded in consensus.
    pub view_changes: Option<f64>,
    /// Transactions observed in the consensus queue.
    pub sumeragi_tx_queue_depth: Option<f64>,
    /// Configured consensus queue capacity.
    pub sumeragi_tx_queue_capacity: Option<f64>,
    /// Saturation flag emitted by consensus (0 = healthy, 1 = saturated).
    pub sumeragi_tx_queue_saturated: Option<f64>,
    /// Number of entries retained in the tiered-state hot tier.
    pub state_tiered_hot_entries: Option<f64>,
    /// Number of entries spilled to the tiered-state cold tier.
    pub state_tiered_cold_entries: Option<f64>,
    /// Bytes written to the tiered-state cold tier in the latest snapshot.
    pub state_tiered_cold_bytes: Option<f64>,
    /// Milliseconds elapsed since genesis according to telemetry.
    pub uptime_since_genesis_ms: Option<f64>,
}
/// Pagination metadata returned by Explorer APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplorerPaginationMeta {
    /// Current page number (1-indexed).
    pub page: u64,
    /// Items per page configured by the backend.
    pub per_page: u64,
    /// Total number of available pages.
    pub total_pages: u64,
    /// Total number of items available on the backend.
    pub total_items: u64,
}
impl ExplorerPaginationMeta {
    fn from_json(value: &json::Value) -> ToriiResult<Self> {
        let record = value
            .as_object()
            .ok_or_else(|| decode_error("explorer blocks pagination", "must be a JSON object"))?;
        require_exact_explorer_fields(
            record,
            &["page", "per_page", "total_pages", "total_items"],
            "explorer blocks pagination",
        )?;
        let page = parse_u64_field(record, "page", false, "explorer blocks pagination.page")?;
        let per_page = parse_u64_field(
            record,
            "per_page",
            false,
            "explorer blocks pagination.per_page",
        )?;
        if per_page > EXPLORER_HISTORY_MAX_PER_PAGE {
            return Err(decode_error(
                "explorer blocks pagination.per_page",
                format!("must be between 1 and {EXPLORER_HISTORY_MAX_PER_PAGE}"),
            ));
        }
        let total_pages = parse_u64_field(
            record,
            "total_pages",
            true,
            "explorer blocks pagination.total_pages",
        )?;
        let total_items = parse_u64_field(
            record,
            "total_items",
            true,
            "explorer blocks pagination.total_items",
        )?;
        let expected_total_pages = total_items.div_ceil(per_page);
        if total_pages != expected_total_pages {
            return Err(decode_error(
                "explorer blocks pagination.total_pages",
                format!("must equal ceil(total_items / per_page), expected {expected_total_pages}"),
            ));
        }
        Ok(Self {
            page,
            per_page,
            total_pages,
            total_items,
        })
    }
}
const EXPLORER_CURSOR_MAX_LENGTH: usize = 1_424;
const EXPLORER_CURSOR_DEFAULT_LIMIT: u32 = 25;
const EXPLORER_CURSOR_MAX_LIMIT: u32 = 100;
const EXPLORER_HISTORY_DEFAULT_PAGE: u64 = 1;
const EXPLORER_HISTORY_DEFAULT_PER_PAGE: u64 = 10;
const EXPLORER_HISTORY_MAX_PER_PAGE: u64 = 100;
fn require_exact_explorer_fields(
    record: &json::Map,
    expected: &[&str],
    context: &str,
) -> ToriiResult<()> {
    if record.len() != expected.len() || expected.iter().any(|field| !record.contains_key(*field)) {
        return Err(decode_error(
            context,
            format!("must contain exactly these fields: {}", expected.join(", ")),
        ));
    }
    Ok(())
}
fn is_canonical_explorer_rfc3339_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    let decimal = |start: usize, end: usize| {
        bytes
            .get(start..end)?
            .iter()
            .try_fold(0_u32, |value, byte| {
                byte.is_ascii_digit()
                    .then_some(value * 10 + u32::from(*byte - b'0'))
            })
    };
    let Some(year) = decimal(0, 4) else {
        return false;
    };
    let Some(month) = decimal(5, 7) else {
        return false;
    };
    let Some(day) = decimal(8, 10) else {
        return false;
    };
    let Some(hour) = decimal(11, 13) else {
        return false;
    };
    let Some(minute) = decimal(14, 16) else {
        return false;
    };
    let Some(second) = decimal(17, 19) else {
        return false;
    };
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    if !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    match bytes.len() {
        20 => bytes[19] == b'Z',
        22..=30 => {
            bytes[19] == b'.'
                && bytes[bytes.len() - 1] == b'Z'
                && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)
        }
        _ => false,
    }
}
fn validate_explorer_items_len(
    items_len: usize,
    pagination: &ExplorerCursorMeta,
    context: &str,
) -> ToriiResult<()> {
    if items_len > pagination.limit as usize {
        return Err(decode_error(
            context,
            format!(
                "must contain at most {} entries, matching pagination.limit",
                pagination.limit
            ),
        ));
    }
    Ok(())
}
/// Seek-pagination metadata returned by Explorer world-collection APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorerCursorMeta {
    /// Maximum number of entries requested for this page.
    pub limit: u32,
    /// Opaque cursor for the next page, when another page exists.
    pub next_cursor: Option<String>,
    /// Whether another page exists for the same collection and filters.
    pub has_more: bool,
}
impl ExplorerCursorMeta {
    fn from_json(value: &json::Value, context: &str) -> ToriiResult<Self> {
        let record = value
            .as_object()
            .ok_or_else(|| decode_error(context, "must be a JSON object"))?;
        require_exact_explorer_fields(record, &["limit", "next_cursor", "has_more"], context)?;
        let limit_value = record
            .get("limit")
            .ok_or_else(|| decode_error(&format!("{context}.limit"), "missing field"))?;
        let limit = parse_u64_value(limit_value, false, &format!("{context}.limit"))?;
        let limit = u32::try_from(limit)
            .ok()
            .filter(|limit| *limit <= EXPLORER_CURSOR_MAX_LIMIT)
            .ok_or_else(|| {
                decode_error(
                    &format!("{context}.limit"),
                    format!("must be between 1 and {EXPLORER_CURSOR_MAX_LIMIT}"),
                )
            })?;
        let next_cursor = match record.get("next_cursor") {
            Some(value) if value.is_null() => None,
            Some(value) => {
                let cursor = value.as_str().ok_or_else(|| {
                    decode_error(
                        &format!("{context}.next_cursor"),
                        "must be a string or null",
                    )
                })?;
                validate_explorer_cursor(cursor, &format!("{context}.next_cursor"))?;
                Some(cursor.to_owned())
            }
            None => {
                return Err(decode_error(
                    &format!("{context}.next_cursor"),
                    "missing field",
                ));
            }
        };
        let has_more = record
            .get("has_more")
            .and_then(json::Value::as_bool)
            .ok_or_else(|| decode_error(&format!("{context}.has_more"), "must be a boolean"))?;
        if has_more != next_cursor.is_some() {
            return Err(decode_error(
                context,
                "has_more must match next_cursor availability",
            ));
        }
        Ok(Self {
            limit,
            next_cursor,
            has_more,
        })
    }
}
fn validate_explorer_cursor<'a>(cursor: &'a str, context: &str) -> ToriiResult<&'a str> {
    let canonical = !cursor.is_empty()
        && cursor.len() <= EXPLORER_CURSOR_MAX_LENGTH
        && URL_SAFE_NO_PAD
            .decode(cursor)
            .map(|decoded| URL_SAFE_NO_PAD.encode(decoded) == cursor)
            .unwrap_or(false);
    if !canonical {
        return Err(decode_error(
            context,
            format!(
                "must be canonical base64url without padding and at most {EXPLORER_CURSOR_MAX_LENGTH} characters"
            ),
        ));
    }
    Ok(cursor)
}
fn append_explorer_cursor_params(
    params: &mut Vec<(&'static str, String)>,
    cursor: Option<String>,
    limit: Option<u32>,
    context: &str,
) -> ToriiResult<()> {
    if let Some(cursor) = cursor {
        validate_explorer_cursor(&cursor, &format!("{context}.cursor"))?;
        params.push(("cursor", cursor));
    }
    if let Some(limit) = limit {
        if !(1..=EXPLORER_CURSOR_MAX_LIMIT).contains(&limit) {
            return Err(decode_error(
                &format!("{context}.limit"),
                format!("must be between 1 and {EXPLORER_CURSOR_MAX_LIMIT}"),
            ));
        }
        params.push(("limit", limit.to_string()));
    }
    Ok(())
}
/// Explorer block summary returned by `/v1/explorer/blocks`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorerBlockRecord {
    /// Hex-encoded block hash.
    pub hash: String,
    /// Block height (`1`-indexed).
    pub height: u64,
    /// RFC 3339 timestamp recorded by Explorer, when the journal retained it.
    pub created_at: Option<String>,
    /// Optional previous block hash.
    pub prev_block_hash: Option<String>,
    /// Optional transactions hash recorded on the block.
    pub transactions_hash: Option<String>,
    /// Count of rejected transactions.
    pub transactions_rejected: u64,
    /// Count of transactions included in the block.
    pub transactions_total: u64,
}
impl ExplorerBlockRecord {
    fn from_json(value: &json::Value) -> ToriiResult<Self> {
        let record = value
            .as_object()
            .ok_or_else(|| decode_error("explorer block record", "must be a JSON object"))?;
        const REQUIRED_FIELDS: [&str; 7] = [
            "hash",
            "height",
            "created_at",
            "prev_block_hash",
            "transactions_hash",
            "transactions_rejected",
            "transactions_total",
        ];
        require_exact_explorer_fields(record, &REQUIRED_FIELDS, "explorer block record")?;
        let hash = parse_hex_field(record, "hash", "explorer block record.hash")?;
        let created_at_value = record
            .get("created_at")
            .and_then(json::Value::as_str)
            .ok_or_else(|| decode_error("explorer block record.created_at", "must be a string"))?;
        let created_at = match created_at_value {
            "" => None,
            value if value.trim() != value => {
                return Err(decode_error(
                    "explorer block record.created_at",
                    "must not contain surrounding whitespace",
                ));
            }
            value if !is_canonical_explorer_rfc3339_utc(value) => {
                return Err(decode_error(
                    "explorer block record.created_at",
                    "must be canonical UTC RFC3339 with at most 9 fractional digits",
                ));
            }
            value => Some(value.to_owned()),
        };
        let transactions_rejected = parse_u64_field(
            record,
            "transactions_rejected",
            true,
            "explorer block record.transactions_rejected",
        )?;
        let transactions_total = parse_u64_field(
            record,
            "transactions_total",
            true,
            "explorer block record.transactions_total",
        )?;
        if transactions_rejected > transactions_total {
            return Err(decode_error(
                "explorer block record.transactions_rejected",
                "must not exceed transactions_total",
            ));
        }
        Ok(Self {
            hash,
            height: parse_u64_field(record, "height", false, "explorer block record.height")?,
            created_at,
            prev_block_hash: parse_optional_hex_field(
                record,
                "prev_block_hash",
                "explorer block record.prev_block_hash",
            )?,
            transactions_hash: parse_optional_hex_field(
                record,
                "transactions_hash",
                "explorer block record.transactions_hash",
            )?,
            transactions_rejected,
            transactions_total,
        })
    }
}
/// Explorer `/v1/explorer/blocks` response model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorerBlocksPage {
    /// Pagination metadata.
    pub pagination: ExplorerPaginationMeta,
    /// Block entries included in this page.
    pub items: Vec<ExplorerBlockRecord>,
}
impl ExplorerBlocksPage {
    fn from_json(value: &json::Value) -> ToriiResult<Self> {
        let record = value
            .as_object()
            .ok_or_else(|| decode_error("explorer blocks response", "must be a JSON object"))?;
        require_exact_explorer_fields(
            record,
            &["pagination", "items"],
            "explorer blocks response",
        )?;
        let pagination = record
            .get("pagination")
            .ok_or_else(|| decode_error("explorer blocks response", "missing pagination field"))
            .and_then(ExplorerPaginationMeta::from_json)?;
        let items_value = record
            .get("items")
            .ok_or_else(|| decode_error("explorer blocks response", "missing items field"))?;
        let items_array = items_value.as_array().ok_or_else(|| {
            decode_error("explorer blocks response.items", "must be a JSON array")
        })?;
        if items_array.len() > pagination.per_page as usize {
            return Err(decode_error(
                "explorer blocks response.items",
                format!(
                    "must contain at most {} entries, matching pagination.per_page",
                    pagination.per_page
                ),
            ));
        }
        let skipped = pagination
            .page
            .saturating_sub(1)
            .saturating_mul(pagination.per_page);
        let expected_items = pagination
            .total_items
            .saturating_sub(skipped)
            .min(pagination.per_page);
        if u64::try_from(items_array.len()).ok() != Some(expected_items) {
            return Err(decode_error(
                "explorer blocks response.items",
                format!(
                    "must contain exactly {expected_items} entries for the declared pagination"
                ),
            ));
        }
        let mut items = Vec::with_capacity(items_array.len());
        for (index, entry) in items_array.iter().enumerate() {
            let record = ExplorerBlockRecord::from_json(entry).map_err(|err| {
                decode_error(
                    "explorer blocks response.items",
                    format!("failed to decode entry {index}: {err}"),
                )
            })?;
            items.push(record);
        }
        Ok(Self { pagination, items })
    }
}
/// Query parameters accepted by `/v1/explorer/blocks`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExplorerBlocksQuery {
    /// One-based page number.
    pub page: Option<u64>,
    /// Maximum number of items to return per page.
    pub per_page: Option<u64>,
}
/// Explorer asset entry returned by `/v1/explorer/assets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorerAssetRecord {
    /// Canonical asset identifier.
    pub id: String,
    /// Definition backing the asset.
    pub definition_id: String,
    /// Owning account identifier.
    pub account_id: String,
    /// Value rendered as a string (mirrors Explorer payload).
    pub value: String,
}
impl ExplorerAssetRecord {
    fn from_json(value: &json::Value) -> ToriiResult<Self> {
        let record = value
            .as_object()
            .ok_or_else(|| decode_error("explorer asset record", "must be a JSON object"))?;
        require_exact_explorer_fields(
            record,
            &["id", "definition_id", "account_id", "value"],
            "explorer asset record",
        )?;
        let id = parse_required_string(record, "id", "explorer asset record.id")?;
        let definition_id = parse_required_string(
            record,
            "definition_id",
            "explorer asset record.definition_id",
        )?;
        let account_id =
            parse_required_string(record, "account_id", "explorer asset record.account_id")?;
        let value = parse_required_string(record, "value", "explorer asset record.value")?;
        let parsed_id = AssetId::parse_literal(&id).map_err(|error| {
            decode_error(
                "explorer asset record.id",
                format!("must be a canonical asset id: {error}"),
            )
        })?;
        if parsed_id.to_string() != id {
            return Err(decode_error(
                "explorer asset record.id",
                "must use the canonical asset-id spelling",
            ));
        }
        let parsed_definition = definition_id
            .parse::<AssetDefinitionId>()
            .map_err(|error| {
                decode_error(
                    "explorer asset record.definition_id",
                    format!("must be a canonical asset-definition id: {error}"),
                )
            })?;
        if parsed_definition.to_string() != definition_id {
            return Err(decode_error(
                "explorer asset record.definition_id",
                "must use the canonical asset-definition-id spelling",
            ));
        }
        let parsed_account = AccountId::parse_encoded(&account_id).map_err(|error| {
            decode_error(
                "explorer asset record.account_id",
                format!("must be a canonical account id: {error}"),
            )
        })?;
        if parsed_account.to_string() != account_id {
            return Err(decode_error(
                "explorer asset record.account_id",
                "must use the canonical account-id spelling",
            ));
        }
        if parsed_id.definition() != &parsed_definition {
            return Err(decode_error(
                "explorer asset record",
                "id does not match definition_id",
            ));
        }
        if parsed_id.account() != &parsed_account {
            return Err(decode_error(
                "explorer asset record",
                "id does not match account_id",
            ));
        }
        let parsed_value = value.parse::<Quantity>().map_err(|error| {
            decode_error(
                "explorer asset record.value",
                format!("must be a canonical quantity: {error}"),
            )
        })?;
        if parsed_value.to_string() != value {
            return Err(decode_error(
                "explorer asset record.value",
                "must use the canonical quantity spelling",
            ));
        }
        Ok(Self {
            id,
            definition_id,
            account_id,
            value,
        })
    }
}
/// Explorer `/v1/explorer/assets` response model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorerAssetsPage {
    /// Seek-pagination metadata returned by Torii.
    pub pagination: ExplorerCursorMeta,
    /// Asset entries in the page.
    pub items: Vec<ExplorerAssetRecord>,
}
impl ExplorerAssetsPage {
    fn from_json(value: &json::Value) -> ToriiResult<Self> {
        let record = value
            .as_object()
            .ok_or_else(|| decode_error("explorer assets response", "must be a JSON object"))?;
        require_exact_explorer_fields(
            record,
            &["pagination", "items"],
            "explorer assets response",
        )?;
        let pagination = record
            .get("pagination")
            .ok_or_else(|| decode_error("explorer assets response", "missing pagination field"))
            .and_then(|value| {
                ExplorerCursorMeta::from_json(value, "explorer assets response.pagination")
            })?;
        let items_value = record
            .get("items")
            .ok_or_else(|| decode_error("explorer assets response", "missing items field"))?;
        let items_array = items_value.as_array().ok_or_else(|| {
            decode_error("explorer assets response.items", "must be a JSON array")
        })?;
        validate_explorer_items_len(
            items_array.len(),
            &pagination,
            "explorer assets response.items",
        )?;
        let mut items = Vec::with_capacity(items_array.len());
        for (index, entry) in items_array.iter().enumerate() {
            let record = ExplorerAssetRecord::from_json(entry).map_err(|err| {
                decode_error(
                    "explorer assets response.items",
                    format!("failed to decode entry {index}: {err}"),
                )
            })?;
            items.push(record);
        }
        Ok(Self { pagination, items })
    }
}
/// Parameters accepted by `/v1/explorer/assets`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExplorerAssetsQuery {
    /// Opaque cursor returned by the preceding page.
    pub cursor: Option<String>,
    /// Maximum number of entries to return (1 through 100).
    pub limit: Option<u32>,
    /// Optional owning account filter.
    pub owned_by: Option<String>,
    /// Optional definition filter (`definition#domain` literal).
    pub definition: Option<String>,
}
fn validate_explorer_filter(value: Option<String>, context: &str) -> ToriiResult<Option<String>> {
    value
        .map(|value| {
            if value.is_empty() || value.trim() != value {
                return Err(decode_error(
                    context,
                    "must be non-empty and contain no surrounding whitespace",
                ));
            }
            Ok(value)
        })
        .transpose()
}
fn validate_explorer_account_filter(value: Option<String>) -> ToriiResult<Option<String>> {
    let value = validate_explorer_filter(value, "explorer assets query.owned_by")?;
    if let Some(literal) = value.as_ref() {
        let account = AccountId::parse_encoded(literal).map_err(|error| {
            decode_error(
                "explorer assets query.owned_by",
                format!("must be a canonical account id: {error}"),
            )
        })?;
        if account.to_string() != *literal {
            return Err(decode_error(
                "explorer assets query.owned_by",
                "must use the canonical account-id spelling",
            ));
        }
    }
    Ok(value)
}
fn validate_explorer_definition_filter(value: Option<String>) -> ToriiResult<Option<String>> {
    let value = validate_explorer_filter(value, "explorer assets query.definition")?;
    if let Some(literal) = value.as_ref() {
        let definition = literal.parse::<AssetDefinitionId>().map_err(|error| {
            decode_error(
                "explorer assets query.definition",
                format!("must be a canonical asset-definition id: {error}"),
            )
        })?;
        if definition.to_string() != *literal {
            return Err(decode_error(
                "explorer assets query.definition",
                "must use the canonical asset-definition-id spelling",
            ));
        }
    }
    Ok(value)
}
fn decode_error(context: &str, message: impl Into<String>) -> ToriiError {
    ToriiError::Decode(format!("{context}: {}", message.into()))
}
fn parse_required_string(record: &json::Map, key: &str, context: &str) -> ToriiResult<String> {
    let value = record
        .get(key)
        .and_then(json::Value::as_str)
        .ok_or_else(|| decode_error(context, "expected non-empty string"))?;
    if value.is_empty() {
        return Err(decode_error(context, "value cannot be empty"));
    }
    if value.trim() != value {
        return Err(decode_error(
            context,
            "value must not contain surrounding whitespace",
        ));
    }
    Ok(value.to_owned())
}
fn parse_hex_field(record: &json::Map, key: &str, context: &str) -> ToriiResult<String> {
    let value = parse_required_string(record, key, context)?;
    require_exact_iroha_hash(&value, context)?;
    Ok(value)
}
fn parse_optional_hex_field(
    record: &json::Map,
    key: &str,
    context: &str,
) -> ToriiResult<Option<String>> {
    let value = record
        .get(key)
        .ok_or_else(|| decode_error(context, "missing field"))?;
    if value.is_null() {
        return Ok(None);
    }
    let string_value = value
        .as_str()
        .ok_or_else(|| decode_error(context, "value must be a string"))?;
    if string_value.is_empty() {
        return Err(decode_error(context, "value cannot be empty"));
    }
    if string_value.trim() != string_value {
        return Err(decode_error(
            context,
            "value must not contain surrounding whitespace",
        ));
    }
    require_exact_iroha_hash(string_value, context)?;
    Ok(Some(string_value.to_owned()))
}
fn parse_u64_field(
    record: &json::Map,
    key: &str,
    allow_zero: bool,
    context: &str,
) -> ToriiResult<u64> {
    let value = record
        .get(key)
        .ok_or_else(|| decode_error(context, "missing field"))?;
    parse_u64_value(value, allow_zero, context)
}
fn parse_u64_value(value: &json::Value, allow_zero: bool, context: &str) -> ToriiResult<u64> {
    let parsed = value
        .as_u64()
        .ok_or_else(|| decode_error(context, "value must be an unsigned integer"))?;
    if parsed == 0 && !allow_zero {
        return Err(decode_error(context, "value must be greater than zero"));
    }
    Ok(parsed)
}
fn require_exact_smoke_status_fields(
    record: &json::Map,
    expected: &[&str],
    context: &str,
) -> ToriiResult<()> {
    if record.len() != expected.len() || expected.iter().any(|field| !record.contains_key(*field)) {
        return Err(decode_error(
            context,
            format!("must contain exactly these fields: {}", expected.join(", ")),
        ));
    }
    Ok(())
}
fn require_exact_iroha_hash<'a>(value: &'a str, context: &str) -> ToriiResult<&'a str> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
        || !matches!(
            value.as_bytes()[63],
            b'1' | b'3' | b'5' | b'7' | b'9' | b'b' | b'd' | b'f'
        )
    {
        return Err(decode_error(
            context,
            "must be exactly 64 lowercase hexadecimal characters with the canonical Iroha hash marker",
        ));
    }
    Ok(value)
}
fn parse_pipeline_smoke_status(
    value: &json::Value,
    expected_hash: &str,
) -> ToriiResult<SmokeTransactionStatus> {
    require_exact_iroha_hash(expected_hash, "pipeline transaction request hash")?;
    let record = value
        .as_object()
        .ok_or_else(|| decode_error("pipeline transaction status", "must be a JSON object"))?;
    require_exact_smoke_status_fields(
        record,
        &["hash", "status", "scope", "resolved_from"],
        "pipeline transaction status",
    )?;
    let response_hash = record
        .get("hash")
        .and_then(json::Value::as_str)
        .ok_or_else(|| decode_error("pipeline transaction status.hash", "must be a string"))?;
    require_exact_iroha_hash(response_hash, "pipeline transaction status.hash")?;
    if response_hash != expected_hash {
        return Err(decode_error(
            "pipeline transaction status.hash",
            "does not match the requested transaction hash",
        ));
    }
    if record.get("scope").and_then(json::Value::as_str) != Some("global") {
        return Err(decode_error(
            "pipeline transaction status.scope",
            "must be exactly `global`",
        ));
    }
    let resolved_from = record
        .get("resolved_from")
        .and_then(json::Value::as_str)
        .ok_or_else(|| {
            decode_error(
                "pipeline transaction status.resolved_from",
                "must be a string",
            )
        })?;
    if !matches!(resolved_from, "queue" | "cache" | "state") {
        return Err(decode_error(
            "pipeline transaction status.resolved_from",
            "must be exactly `queue`, `cache`, or `state`",
        ));
    }
    let status = record
        .get("status")
        .and_then(json::Value::as_object)
        .ok_or_else(|| {
            decode_error(
                "pipeline transaction status.status",
                "must be a JSON object",
            )
        })?;
    if !status.contains_key("kind")
        || status.len() > 2
        || status
            .keys()
            .any(|field| !matches!(field.as_str(), "kind" | "block_height"))
    {
        return Err(decode_error(
            "pipeline transaction status.status",
            "must contain `kind` and only the optional `block_height` field",
        ));
    }
    let kind = status
        .get("kind")
        .and_then(json::Value::as_str)
        .ok_or_else(|| decode_error("pipeline transaction status.kind", "must be a string"))?;
    if !matches!(
        kind,
        "Queued" | "Approved" | "Committed" | "Applied" | "Rejected" | "Expired"
    ) {
        return Err(decode_error(
            "pipeline transaction status.kind",
            "is not a first-release pipeline status kind",
        ));
    }
    let height = status
        .get("block_height")
        .map(|value| {
            value.as_u64().filter(|height| *height > 0).ok_or_else(|| {
                decode_error(
                    "pipeline transaction status.block_height",
                    "must be a positive integer",
                )
            })
        })
        .transpose()?;
    if resolved_from != "state" {
        return Ok(SmokeTransactionStatus::Queued);
    }
    match kind {
        "Applied" => height
            .map(SmokeTransactionStatus::Committed)
            .ok_or_else(|| {
                decode_error(
                    "pipeline transaction status.block_height",
                    "is required for state-resolved Applied status",
                )
            }),
        "Rejected" => Ok(SmokeTransactionStatus::Rejected("rejected".to_owned())),
        "Expired" => Ok(SmokeTransactionStatus::Expired),
        "Queued" | "Approved" | "Committed" => Ok(SmokeTransactionStatus::Queued),
        _ => unreachable!("pipeline status kind was validated above"),
    }
}
impl ToriiMetricsSnapshot {
    /// Parse a Prometheus plaintext payload into a structured snapshot.
    #[must_use]
    pub fn from_prometheus(now: Instant, body: &str) -> Self {
        let mut snapshot = Self {
            timestamp: now,
            queue_size: None,
            view_changes: None,
            sumeragi_tx_queue_depth: None,
            sumeragi_tx_queue_capacity: None,
            sumeragi_tx_queue_saturated: None,
            state_tiered_hot_entries: None,
            state_tiered_cold_entries: None,
            state_tiered_cold_bytes: None,
            uptime_since_genesis_ms: None,
        };
        for line in body.lines() {
            if let Some((name, value)) = parse_scalar_metric(line) {
                match name {
                    "queue_size" => snapshot.queue_size = Some(value),
                    "view_changes" => snapshot.view_changes = Some(value),
                    "sumeragi_tx_queue_depth" => snapshot.sumeragi_tx_queue_depth = Some(value),
                    "sumeragi_tx_queue_capacity" => {
                        snapshot.sumeragi_tx_queue_capacity = Some(value)
                    }
                    "sumeragi_tx_queue_saturated" => {
                        snapshot.sumeragi_tx_queue_saturated = Some(value)
                    }
                    "state_tiered_hot_entries" => snapshot.state_tiered_hot_entries = Some(value),
                    "state_tiered_cold_entries" => snapshot.state_tiered_cold_entries = Some(value),
                    "state_tiered_cold_bytes" => snapshot.state_tiered_cold_bytes = Some(value),
                    "uptime_since_genesis_ms" => snapshot.uptime_since_genesis_ms = Some(value),
                    _ => {}
                }
            }
        }
        snapshot
    }
    /// Ratio (0–1) representing how full the consensus queue is.
    ///
    /// Returns `None` when either the depth or capacity gauges were missing or the backend reported
    /// a zero/negative capacity (should never happen on healthy Torii deployments).
    #[must_use]
    pub fn queue_utilization(&self) -> Option<f64> {
        let depth = self.sumeragi_tx_queue_depth?;
        let capacity = self.sumeragi_tx_queue_capacity?;
        if capacity <= 0.0 {
            return None;
        }
        Some((depth / capacity).clamp(0.0, 1.0))
    }
    /// Boolean saturation flag derived from the exporter gauge.
    ///
    /// Returns `None` when the exporter did not emit the flag or reported an unexpected value
    /// (non-zero/non-one) so UI surfaces can retain a tri-state indicator.
    #[must_use]
    pub fn queue_saturation_flag(&self) -> Option<bool> {
        let value = self.sumeragi_tx_queue_saturated?;
        if value <= 0.0 {
            Some(false)
        } else if value >= 1.0 {
            Some(true)
        } else {
            None
        }
    }
    /// Percentage of entries that spilled into the cold tier (0–1).
    ///
    /// Returns `None` when the exporter lacks hot/cold counters or when the
    /// tiers report no entries (preventing division by zero).
    #[must_use]
    pub fn cold_entry_ratio(&self) -> Option<f64> {
        let hot = self.state_tiered_hot_entries?;
        let cold = self.state_tiered_cold_entries?;
        let total = hot + cold;
        if total <= 0.0 {
            return None;
        }
        Some((cold / total).clamp(0.0, 1.0))
    }
}
fn parse_scalar_metric(line: &str) -> Option<(&str, f64)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains('{') {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let name = parts.next()?;
    let value = parts.next()?;
    let parsed = value.parse::<f64>().ok()?;
    Some((name, parsed))
}
fn lag_to_usize(skipped: u64) -> usize {
    usize::try_from(skipped).unwrap_or(usize::MAX)
}
/// Decode one complete Norito frame under payload-derived resource limits.
pub fn decode_norito<T>(bytes: &[u8]) -> Result<T, ToriiError>
where
    T: norito::NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de>,
{
    norito::decode_from_bytes_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .map_err(|error| ToriiError::Decode(error.to_string()))
}
/// Torii HTTP adapter supporting local supervisor workflows.
#[derive(Clone, Debug)]
pub struct ToriiClient {
    http_base: Url,
    ws_base: Url,
    network_id: Option<NetworkId>,
    operator_signing_context: Option<Arc<OperatorSigningContext>>,
    http: Client,
    status_state: Arc<Mutex<StatusState>>,
}
#[cfg(test)]
pub(crate) fn test_network_id() -> NetworkId {
    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
        .parse()
        .expect("test network id")
}
fn canonical_event_filters() -> Vec<EventFilterBox> {
    vec![
        EventFilterBox::Pipeline(TransactionEventFilter::default().into()),
        EventFilterBox::Pipeline(BlockEventFilter::default().into()),
        EventFilterBox::Pipeline(WitnessEventFilter::default().into()),
        EventFilterBox::Data(DataEventFilter::Any),
        EventFilterBox::Time(TimeEventFilter::new(ExecutionTime::PreCommit)),
        EventFilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new()),
        EventFilterBox::TriggerCompleted(TriggerCompletedEventFilter::new()),
    ]
}
impl ToriiClient {
    /// Construct a client pointing at the supplied Torii HTTP base URL.
    pub fn new(base_url: impl AsRef<str>) -> ToriiResult<Self> {
        Self::builder(base_url)?.build()
    }
    /// Construct a client whose signed-query context is bound to one exact genesis lineage.
    pub fn new_for_network(base_url: impl AsRef<str>, network_id: NetworkId) -> ToriiResult<Self> {
        Self::builder(base_url)?.with_network_id(network_id).build()
    }
    /// Start constructing a [`ToriiClient`] with custom options.
    pub fn builder(base_url: impl AsRef<str>) -> ToriiResult<ToriiClientBuilder> {
        ToriiClientBuilder::new(base_url)
    }
    /// HTTP base URL used for REST calls (e.g., `http://127.0.0.1:8080`).
    pub fn base_url(&self) -> &str {
        self.http_base.as_str()
    }
    /// Return the immutable genesis lineage configured for signed queries.
    pub fn network_id(&self) -> Option<NetworkId> {
        self.network_id
    }
    fn validate_stream_reader(&self, reader: &AccountClient) -> ToriiResult<()> {
        if reader.endpoint() != &self.http_base
            || *reader.network_id() != self.require_network_id()?
        {
            return Err(ToriiError::SignedQueryContext(
                "stream reader must match the exact Torii endpoint and genesis network".to_owned(),
            ));
        }
        Ok(())
    }
    fn require_network_id(&self) -> ToriiResult<NetworkId> {
        self.network_id.ok_or_else(|| {
            ToriiError::SignedQueryContext(
                "client has no exact genesis network_id configured for signed requests".to_owned(),
            )
        })
    }
    /// Build and sign a fresh one-shot query request for this client's network.
    pub fn sign_query(
        &self,
        request: QueryRequest,
        authority: AccountId,
        key_pair: &KeyPair,
    ) -> ToriiResult<SignedQuery> {
        const QUERY_TTL_MS: u64 = 100_000;
        let network_id = self.require_network_id()?;
        let creation_time_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| ToriiError::SignedQueryContext(error.to_string()))?
            .as_millis()
            .try_into()
            .map_err(|_| {
                ToriiError::SignedQueryContext("Unix timestamp does not fit u64".to_owned())
            })?;
        let mut nonce = [0_u8; 32];
        for _ in 0..16 {
            OsRng.try_fill_bytes(&mut nonce).map_err(|error| {
                ToriiError::SignedQueryContext(format!("OS nonce generation failed: {error}"))
            })?;
            if nonce != [0_u8; 32] {
                return request
                    .with_authority(
                        network_id,
                        authority,
                        creation_time_ms,
                        NonZeroU64::new(QUERY_TTL_MS).expect("signed-query TTL is nonzero"),
                        nonce,
                    )
                    .try_sign(key_pair)
                    .map_err(|error| ToriiError::SignedQueryContext(error.to_string()));
            }
        }
        Err(ToriiError::SignedQueryContext(
            "OS RNG repeatedly returned an all-zero query nonce".to_owned(),
        ))
    }
    /// URL of the canonical `/v1/pipeline/transactions` endpoint.
    pub fn transaction_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint(torii_routes::pipeline::TRANSACTION.path())
    }
    /// URL of the canonical `/v1/query` endpoint.
    pub fn query_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint(torii_routes::pipeline::QUERY.path())
    }
    /// URL of the canonical `/v1/blocks/stream` WebSocket endpoint.
    pub fn block_stream_endpoint(&self) -> ToriiResult<Url> {
        self.ws_endpoint(torii_routes::streaming::BLOCKS_WS.path())
    }
    /// URL of the canonical `/v1/events/ws` WebSocket endpoint.
    pub fn events_stream_endpoint(&self) -> ToriiResult<Url> {
        self.ws_endpoint(torii_routes::streaming::SUBSCRIPTION_WS.path())
    }
    /// URL of the `/status` endpoint.
    pub fn status_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint("status")
    }
    /// URL of the `/v1/sumeragi/status` endpoint.
    pub fn sumeragi_status_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint("v1/sumeragi/status")
    }
    /// URL of the `/v1/sumeragi/diagnostics` endpoint.
    pub fn sumeragi_diagnostics_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint("v1/sumeragi/diagnostics")
    }
    /// URL of the `/metrics` endpoint.
    pub fn metrics_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint("metrics")
    }
    /// URL of the native `/v1/mcp` endpoint.
    pub fn mcp_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint("v1/mcp")
    }
    fn explorer_blocks_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint(torii_routes::application_api::EXPLORER_BLOCKS_GET.path())
    }
    fn explorer_assets_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint(torii_routes::application_api::EXPLORER_ASSETS_GET.path())
    }
    /// URL of the `/v1/pipeline/transactions/status` endpoint.
    pub fn pipeline_transaction_status_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint(torii_routes::pipeline::TRANSACTION_STATUS.path())
    }
    /// Probe `/status` until the peer responds or the timeout elapses.
    pub async fn wait_for_ready(
        &self,
        options: ReadinessOptions,
    ) -> ToriiResult<ToriiStatusSnapshot> {
        let mut backoff = options
            .poll_interval
            .max(Duration::from_millis(10))
            .min(MAX_BACKOFF);
        let start = Instant::now();
        let deadline = start
            .checked_add(options.timeout)
            .unwrap_or_else(|| start + options.timeout);
        loop {
            match self
                .fetch_status_snapshot_before(deadline, "peer readiness")
                .await
            {
                Ok(snapshot) => return Ok(snapshot),
                Err(err @ ToriiError::Timeout { .. }) => return Err(err),
                Err(err) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(err);
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    sleep(backoff.min(remaining)).await;
                    backoff = (backoff.saturating_mul(2)).min(MAX_BACKOFF);
                }
            }
        }
    }
    /// Probe `/status` until the chain has committed its genesis block.
    ///
    /// A responsive height-zero peer is still bootstrapping and cannot yet admit transactions
    /// against committed validator authority. Transient status failures and height-zero responses
    /// share one bounded [`ReadinessOptions`] deadline and exponential backoff.
    pub async fn wait_for_genesis_commit(
        &self,
        options: ReadinessOptions,
    ) -> ToriiResult<ToriiStatusSnapshot> {
        let mut backoff = options
            .poll_interval
            .max(Duration::from_millis(10))
            .min(MAX_BACKOFF);
        let start = Instant::now();
        let deadline = start
            .checked_add(options.timeout)
            .unwrap_or_else(|| start + options.timeout);
        let mut saw_zero_height = false;
        loop {
            let poll_error = match self
                .fetch_status_snapshot_before(deadline, "genesis commitment")
                .await
            {
                Ok(snapshot) if snapshot.status.blocks > 0 => return Ok(snapshot),
                Ok(_) => {
                    saw_zero_height = true;
                    None
                }
                Err(ToriiError::Timeout { .. }) if saw_zero_height => {
                    return Err(ToriiError::Timeout {
                        context: "genesis commitment (status remained at zero committed blocks)"
                            .to_owned(),
                    });
                }
                Err(err @ ToriiError::Timeout { .. }) => return Err(err),
                Err(err) => Some(err),
            };
            let now = Instant::now();
            if now >= deadline {
                return match poll_error {
                    Some(err) => Err(err),
                    None => Err(ToriiError::Timeout {
                        context: "genesis commitment (status remained at zero committed blocks)"
                            .to_owned(),
                    }),
                };
            }
            let remaining = deadline.saturating_duration_since(now);
            sleep(backoff.min(remaining)).await;
            backoff = (backoff.saturating_mul(2)).min(MAX_BACKOFF);
        }
    }
    /// Run a readiness smoke probe that waits for `/status`, submits a smoke transaction,
    /// and observes its commitment with retries/backoff.
    pub async fn wait_for_readiness_smoke(
        &self,
        reader: &AccountClient,
        mut plan: ReadinessSmokePlan,
    ) -> ToriiResult<ReadinessSmokeOutcome> {
        if plan.transactions.is_empty() {
            return Err(ToriiError::Decode(
                "readiness smoke plan must include at least one transaction".to_owned(),
            ));
        }
        self.validate_stream_reader(reader)?;
        self.wait_for_genesis_commit(plan.status_options).await?;
        plan.renew_generated_transactions_if_needed(unix_time_now())
            .map_err(|err| {
                ToriiError::Decode(format!(
                    "failed to renew readiness smoke transactions after genesis commitment: {err}"
                ))
            })?;
        let attempts = plan.transactions.len();
        let started = Instant::now();
        let mut backoff = plan.backoff.max(Duration::from_millis(50)).min(MAX_BACKOFF);
        let mut cursor = ReadinessSmokeAttemptCursor::default();
        for attempt in 1..=attempts {
            let transaction_index = cursor.current_index();
            let transaction = &plan.transactions[transaction_index];
            match self
                .submit_and_wait_for_commit(reader, transaction, plan.commit_options)
                .await
            {
                Ok(commit) => {
                    let status = self.fetch_status_snapshot().await.ok();
                    return Ok(ReadinessSmokeOutcome {
                        total_elapsed: started.elapsed(),
                        attempt,
                        commit,
                        status,
                    });
                }
                Err(err @ ToriiError::SmokeRejected { .. }) if cursor.is_pinned() => {
                    return Err(err);
                }
                Err(err) if attempt < attempts => {
                    cursor.record_failure(transaction_index, &err);
                    sleep(backoff).await;
                    backoff = (backoff.saturating_mul(2)).min(MAX_BACKOFF);
                }
                Err(err) => return Err(err),
            }
        }
        Err(ToriiError::Timeout {
            context: format!("smoke readiness attempts exhausted ({attempts})"),
        })
    }
    /// URL of the canonical `/v1/configuration` endpoint.
    pub fn configuration_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint(torii_routes::core::CONFIGURATION_GET.path())
    }
    /// URL of the read-only `/v1/nexus/lifecycle` status endpoint.
    pub fn nexus_lifecycle_endpoint(&self) -> ToriiResult<Url> {
        self.http_endpoint("v1/nexus/lifecycle")
    }
    /// Submit a Norito-encoded transaction to Torii.
    pub async fn submit_transaction(&self, payload: &[u8]) -> ToriiResult<()> {
        let url = self.transaction_endpoint()?;
        let response = self
            .http
            .post(url)
            .header("Content-Type", NORITO_MIME_TYPE)
            .body(payload.to_vec())
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let reject_code = reject_code_from_headers(response.headers());
            let body =
                read_bounded_response(response, MAX_ERROR_RESPONSE_BYTES, "transaction error")
                    .await?;
            let message = error_message_from_body(body.as_ref());
            return Err(ToriiError::UnexpectedStatus {
                status,
                reject_code,
                message,
            });
        }
        Ok(())
    }
    /// Submit a Norito-encoded query to Torii and return the raw response body.
    pub async fn submit_query(&self, payload: &[u8]) -> ToriiResult<Vec<u8>> {
        let url = self.query_endpoint()?;
        let response = self
            .http
            .post(url)
            .header("Content-Type", NORITO_MIME_TYPE)
            .body(payload.to_vec())
            .send()
            .await?;
        if response.status().is_success() {
            return read_bounded_response(response, MAX_QUERY_RESPONSE_BYTES, "query").await;
        }
        let status = response.status();
        let reject_code = reject_code_from_headers(response.headers());
        let body = read_bounded_response(response, MAX_ERROR_RESPONSE_BYTES, "query error").await?;
        let message = error_message_from_body(body.as_ref());
        Err(ToriiError::UnexpectedStatus {
            status,
            reject_code,
            message,
        })
    }
    /// Submit a signed transaction and wait until local Torii reports it as committed.
    ///
    /// This helper is primarily intended for readiness smoke checks in local tooling.
    pub async fn submit_and_wait_for_commit(
        &self,
        reader: &AccountClient,
        transaction: &SignedTransaction,
        options: SmokeCommitOptions,
    ) -> ToriiResult<SmokeCommitSnapshot> {
        self.validate_stream_reader(reader)?;
        let tx_hash = transaction.hash();
        let tx_hash_str = encode_lower_hex(tx_hash.as_ref());
        let started = Instant::now();
        let deadline = smoke_commit_deadline(started, options.timeout)?;
        let deadline_context = format!("smoke commit {tx_hash_str}");
        // Stream notifications are latency optimizations for this exact-hash
        // readiness check. Torii may temporarily throttle WebSocket handshakes
        // while all peers start; keep the canonical HTTP status reconciliation
        // authoritative instead of failing an otherwise healthy localnet.
        let block_stream = match await_torii_before_deadline(deadline, &deadline_context, async {
            reader
                .blocks()
                .subscribe(NonZeroU64::MIN)
                .await
                .map(BlockStream::new)
                .map_err(ToriiError::from)
        })
        .await
        {
            Ok(stream) => Some(stream),
            Err(ToriiError::Sdk(error))
                if matches!(error.as_ref(), iroha::Error::Http { status: 429, .. }) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        let events_stream = match await_torii_before_deadline(deadline, &deadline_context, async {
            reader
                .events()
                .subscribe(canonical_event_filters())
                .await
                .map(EventStream::new)
                .map_err(ToriiError::from)
        })
        .await
        {
            Ok(stream) => Some(stream),
            Err(ToriiError::Sdk(error))
                if matches!(error.as_ref(), iroha::Error::Http { status: 429, .. }) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        let mut block_rx = block_stream.as_ref().map(BlockStream::subscribe);
        let mut event_rx = events_stream.as_ref().map(EventStream::subscribe);
        let signed_bytes = transaction.encode_versioned();
        let submission = await_torii_before_deadline(
            deadline,
            &deadline_context,
            self.submit_transaction(&signed_bytes),
        )
        .await;
        let mut admission_outcome_unknown = match submission {
            Ok(()) => false,
            Err(err) if err.confirms_existing_submission() => false,
            Err(err) if err.is_transaction_dispatch_outcome_unknown() => true,
            Err(ToriiError::Timeout { .. }) => {
                return Err(ToriiError::SmokeAdmissionOutcomeUnknown { hash: tx_hash_str });
            }
            Err(err) => return Err(err),
        };
        let wait = async {
            let mut status_poll = tokio::time::interval(Duration::from_millis(250));
            let retry_start = tokio::time::Instant::now() + SMOKE_EXACT_RESUBMIT_DELAY;
            let mut exact_resubmit =
                tokio::time::interval_at(retry_start, SMOKE_EXACT_RESUBMIT_INTERVAL);
            exact_resubmit.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = status_poll.tick() => {
                        let status = match self
                            .fetch_smoke_transaction_status(tx_hash_str.as_str())
                            .await
                        {
                            Ok(status) => status,
                            Err(_err) if admission_outcome_unknown => None,
                            Err(err) => return Err(err),
                        };
                        if let Some(status) = status {
                            match status {
                                SmokeTransactionStatus::Queued => {
                                    admission_outcome_unknown = false;
                                }
                                SmokeTransactionStatus::Committed(height) => return Ok(height),
                                SmokeTransactionStatus::Rejected(reason) => {
                                    return Err(ToriiError::SmokeRejected {
                                        hash: tx_hash_str.clone(),
                                        reason,
                                    });
                                }
                                SmokeTransactionStatus::Expired => {
                                    return Err(ToriiError::SmokeRejected {
                                        hash: tx_hash_str.clone(),
                                        reason: "expired".to_owned(),
                                    });
                                }
                            }
                        }
                    }
                    _ = exact_resubmit.tick(), if admission_outcome_unknown => {
                        match self.submit_transaction(&signed_bytes).await {
                            Ok(()) => admission_outcome_unknown = false,
                            Err(err) if err.confirms_existing_submission() => {
                                admission_outcome_unknown = false;
                            }
                            Err(_err) => {}
                        }
                    }
                    message = async {
                        match &mut block_rx {
                            Some(receiver) => receiver.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        match message {
                            Ok(BlockStreamEvent::Block { block, .. }) => {
                                if let Some(result) =
                                    smoke_transaction_result_in_block(block.as_ref(), &tx_hash)
                                {
                                    return result;
                                }
                            }
                            Ok(BlockStreamEvent::DecodeError { error }) => {
                                if !admission_outcome_unknown {
                                    return Err(error.source.map_or_else(|| ToriiError::Decode(error.message), ToriiError::Sdk));
                                }
                            }
                            Ok(BlockStreamEvent::Closed) => { block_rx = None; }
                            Ok(BlockStreamEvent::Lagged { .. } | BlockStreamEvent::Text { .. }) => {}
                            Err(RecvError::Lagged(_)) => {}
                            Err(RecvError::Closed) => { block_rx = None; }
                        }
                    }
                    message = async {
                        match &mut event_rx {
                            Some(receiver) => receiver.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        match message {
                            Ok(EventStreamEvent::Event { event, .. }) => {
                                if let EventBox::Pipeline(PipelineEventBox::Transaction(tx_event)) = event.as_ref()
                                    && tx_event.hash() == &tx_hash
                                {
                                    match tx_event.status() {
                                        iroha_data_model::events::pipeline::TransactionStatus::Rejected(reason) => {
                                            return Err(ToriiError::SmokeRejected {
                                                hash: tx_hash_str.clone(),
                                                reason: format!("{reason:?}"),
                                            });
                                        }
                                        iroha_data_model::events::pipeline::TransactionStatus::Expired => {
                                            return Err(ToriiError::SmokeRejected {
                                                hash: tx_hash_str.clone(),
                                                reason: "expired".to_owned(),
                                            });
                                        }
                                        iroha_data_model::events::pipeline::TransactionStatus::Approved => {
                                            if let Some(height) =
                                                tx_event.block_height().map(std::num::NonZeroU64::get)
                                            {
                                                return Ok(height);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            Ok(EventStreamEvent::DecodeError { error }) => {
                                if !admission_outcome_unknown {
                                    return Err(error.source.map_or_else(|| ToriiError::Decode(error.message), ToriiError::Sdk));
                                }
                            }
                            Ok(EventStreamEvent::Closed) => { event_rx = None; }
                            Ok(EventStreamEvent::Lagged { .. } | EventStreamEvent::Text { .. }) => {}
                            Err(RecvError::Lagged(_)) => {}
                            Err(RecvError::Closed) => { event_rx = None; }
                        }
                    }
                }
            }
        };
        let result = match await_torii_before_deadline(deadline, &deadline_context, wait).await {
            Err(ToriiError::Timeout { .. }) if admission_outcome_unknown => {
                Err(ToriiError::SmokeAdmissionOutcomeUnknown {
                    hash: tx_hash_str.clone(),
                })
            }
            Err(ToriiError::Timeout { .. }) => Err(ToriiError::Timeout {
                context: deadline_context,
            }),
            result => result,
        };
        drop(block_stream);
        drop(events_stream);
        match result {
            Ok(height) => Ok(SmokeCommitSnapshot {
                tx_hash,
                block_height: height,
                elapsed: started.elapsed(),
            }),
            Err(err) => Err(match err {
                ToriiError::Timeout { .. } => ToriiError::Timeout {
                    context: format!("smoke commit {tx_hash_str}"),
                },
                other => other,
            }),
        }
    }
    async fn fetch_smoke_transaction_status(
        &self,
        tx_hash: &str,
    ) -> ToriiResult<Option<SmokeTransactionStatus>> {
        self.fetch_pipeline_transaction_status(tx_hash).await
    }
    async fn fetch_pipeline_transaction_status(
        &self,
        tx_hash: &str,
    ) -> ToriiResult<Option<SmokeTransactionStatus>> {
        require_exact_iroha_hash(tx_hash, "pipeline transaction request hash")?;
        let url = self.pipeline_transaction_status_endpoint()?;
        let response = self
            .http
            .get(url)
            .query(&[("hash", tx_hash), ("scope", "global")])
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status() != StatusCode::OK {
            return Err(ToriiError::UnexpectedStatus {
                status: response.status(),
                reject_code: None,
                message: None,
            });
        }
        let bytes =
            read_bounded_response(response, MAX_JSON_RESPONSE_BYTES, "pipeline status").await?;
        let value = decode_bounded_json_response(&bytes, "pipeline status")?;
        parse_pipeline_smoke_status(&value, tx_hash).map(Some)
    }
    /// Submit a signed query and decode the response into a typed [`QueryOutput`].
    pub async fn execute_query(&self, query: &SignedQuery) -> ToriiResult<QueryOutput> {
        let response = self.submit_query(&query.encode_versioned()).await?;
        decode_norito(&response)
    }
    /// Fetch the Torii status snapshot.
    pub async fn fetch_status(&self) -> ToriiResult<TelemetryStatus> {
        let url = self.status_endpoint()?;
        let response = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, NORITO_MIME_TYPE)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ToriiError::UnexpectedStatus {
                status: response.status(),
                reject_code: None,
                message: None,
            });
        }
        let body = read_bounded_response(response, MAX_STATUS_RESPONSE_BYTES, "status").await?;
        decode_norito(body.as_ref())
    }
    /// Fetch a telemetry snapshot together with derived metrics.
    pub async fn fetch_status_snapshot(&self) -> ToriiResult<ToriiStatusSnapshot> {
        let status = self.fetch_status().await?;
        let timestamp = Instant::now();
        let metrics = {
            let mut guard = self.status_state.lock().await;
            guard.record(timestamp, &status)
        };
        Ok(ToriiStatusSnapshot::new(timestamp, status, metrics))
    }
    async fn fetch_status_snapshot_before(
        &self,
        deadline: Instant,
        context: &'static str,
    ) -> ToriiResult<ToriiStatusSnapshot> {
        await_torii_before_deadline(deadline, context, self.fetch_status_snapshot()).await
    }
    /// Fetch the exact native Sumeragi v1 status snapshot.
    pub async fn fetch_sumeragi_status(&self) -> ToriiResult<SumeragiStatus> {
        let url = self.sumeragi_status_endpoint()?;
        let request = build_operator_get_request(
            &self.http,
            self.network_id,
            self.operator_signing_context.as_deref(),
            url,
        )?;
        let response = self.http.execute(request).await?;
        if !response.status().is_success() {
            return Err(ToriiError::UnexpectedStatus {
                status: response.status(),
                reject_code: None,
                message: None,
            });
        }
        let body = read_bounded_sumeragi_response(response).await?;
        let status: SumeragiStatus = decode_norito(&body)?;
        if status.protocol_version != iroha_data_model::sumeragi::PROTOCOL_VERSION {
            return Err(ToriiError::Decode(
                "unsupported Sumeragi protocol version".to_owned(),
            ));
        }
        Ok(status)
    }
    /// Fetch non-authoritative Sumeragi pipeline, queue, election, and lane diagnostics.
    pub async fn fetch_sumeragi_diagnostics(&self) -> ToriiResult<SumeragiDiagnosticsStatus> {
        let url = self.sumeragi_diagnostics_endpoint()?;
        let request = build_operator_get_request(
            &self.http,
            self.network_id,
            self.operator_signing_context.as_deref(),
            url,
        )?;
        let response = self.http.execute(request).await?;
        if !response.status().is_success() {
            return Err(ToriiError::UnexpectedStatus {
                status: response.status(),
                reject_code: None,
                message: None,
            });
        }
        let body = read_bounded_sumeragi_response(response).await?;
        let diagnostics: SumeragiDiagnosticsStatus = decode_norito(&body)?;
        if let Some(npos) = diagnostics.npos {
            npos.validate()
                .map_err(|reason| ToriiError::Decode(reason.to_owned()))?;
        }
        Ok(diagnostics)
    }
    /// Fetch the Torii node configuration as a Norito JSON value.
    pub async fn fetch_configuration(&self) -> ToriiResult<json::Value> {
        let url = self.configuration_endpoint()?;
        self.fetch_json(url).await
    }
    /// Run the local Mochi MCP smoke sequence against `/v1/mcp`.
    pub async fn validate_local_mcp(&self) -> ToriiResult<LocalMcpProbeResult> {
        let discovery = self.mcp_discover().await?;
        let tools = self.mcp_tools_list().await?;
        LocalMcpProbeResult::from_documents(&discovery, &tools)
    }
    /// Fetch and validate the exact current Nexus lane catalog commitment.
    pub async fn fetch_lane_lifecycle_status(&self) -> ToriiResult<LaneLifecycleStatusV1> {
        let url = self.nexus_lifecycle_endpoint()?;
        let response = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, NORITO_MIME_TYPE)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let reject_code = reject_code_from_headers(response.headers());
            let body =
                read_bounded_response(response, MAX_ERROR_RESPONSE_BYTES, "lane lifecycle error")
                    .await?;
            let message = error_message_from_body(body.as_ref());
            return Err(ToriiError::UnexpectedStatus {
                status,
                reject_code,
                message,
            });
        }
        let body =
            read_bounded_response(response, MAX_STATUS_RESPONSE_BYTES, "lane lifecycle").await?;
        let status: LaneLifecycleStatusV1 = decode_norito(body.as_ref())?;
        status
            .validate()
            .map_err(|err| ToriiError::Decode(format!("invalid lane lifecycle status: {err}")))?;
        Ok(status)
    }
    /// Submit and wait for a consensus-replayed Nexus lane lifecycle transaction.
    ///
    /// The transaction is bound to the exact network configured on this client.
    ///
    /// The status commitment is fetched once. A stale catalog or missing
    /// `CanSetParameters` permission is surfaced as a transaction rejection and
    /// is never silently retried against a different topology.
    pub async fn apply_lane_lifecycle(
        &self,
        reader: &AccountClient,
        network_id: NetworkId,
        signer: &SigningAuthority,
        plan: LaneLifecyclePlan,
    ) -> ToriiResult<SmokeCommitSnapshot> {
        self.validate_stream_reader(reader)?;
        let configured_network_id = self.require_network_id()?;
        if network_id != configured_network_id {
            return Err(ToriiError::SignedQueryContext(format!(
                "lane lifecycle network id `{network_id}` does not match the configured client network id `{configured_network_id}`"
            )));
        }
        let status = self.fetch_lane_lifecycle_status().await?;
        let current_catalog = status
            .validate()
            .map_err(|err| ToriiError::Decode(format!("invalid lane lifecycle status: {err}")))?;
        let expected_catalog = current_catalog
            .apply_lifecycle(&plan)
            .map_err(|err| ToriiError::Decode(format!("invalid lane lifecycle plan: {err}")))?;
        let previous_incarnation_root = status.incarnation_root;
        let transaction = build_lane_lifecycle_transaction(network_id, signer, &status, plan)?;
        let options = SmokeCommitOptions::default();
        let committed = self
            .submit_and_wait_for_commit(reader, &transaction, options)
            .await?;
        // Block persistence precedes WSV publication. Do not report success to
        // storage-reset callers until the committed catalog and its fresh
        // incarnation root are visible through the state-generation snapshot.
        let deadline = tokio::time::Instant::now() + options.timeout;
        loop {
            let observed = self.fetch_lane_lifecycle_status().await?;
            let observed_catalog = observed.validate().map_err(|err| {
                ToriiError::Decode(format!("invalid post-commit lifecycle status: {err}"))
            })?;
            if observed_catalog == expected_catalog
                && observed.incarnation_root != previous_incarnation_root
            {
                return Ok(committed);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ToriiError::Timeout {
                    context: format!(
                        "lane lifecycle apply {} (committed at block {})",
                        committed.tx_hash, committed.block_height
                    ),
                });
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
    /// Fetch the exposed metrics payload as plain text (Prometheus format).
    pub async fn fetch_metrics(&self) -> ToriiResult<String> {
        let url = self.metrics_endpoint()?;
        let response = self.http.get(url).send().await?;
        if !response.status().is_success() {
            return Err(ToriiError::UnexpectedStatus {
                status: response.status(),
                reject_code: None,
                message: None,
            });
        }
        let body = read_bounded_response(response, MAX_METRICS_RESPONSE_BYTES, "metrics").await?;
        String::from_utf8(body)
            .map_err(|_| ToriiError::Decode("metrics response is not UTF-8".to_owned()))
    }
    /// Fetch and parse the Prometheus metrics payload into a structured snapshot.
    pub async fn fetch_metrics_snapshot(&self) -> ToriiResult<ToriiMetricsSnapshot> {
        let body = self.fetch_metrics().await?;
        Ok(ToriiMetricsSnapshot::from_prometheus(Instant::now(), &body))
    }
    /// List blocks from the Explorer API using optional pagination parameters.
    pub async fn fetch_blocks_page(
        &self,
        query: ExplorerBlocksQuery,
    ) -> ToriiResult<ExplorerBlocksPage> {
        let requested_page = query.page.unwrap_or(EXPLORER_HISTORY_DEFAULT_PAGE);
        let requested_per_page = query.per_page.unwrap_or(EXPLORER_HISTORY_DEFAULT_PER_PAGE);
        if requested_page == 0 {
            return Err(decode_error(
                "explorer blocks query.page",
                "must be at least 1",
            ));
        }
        if !(1..=EXPLORER_HISTORY_MAX_PER_PAGE).contains(&requested_per_page) {
            return Err(decode_error(
                "explorer blocks query.per_page",
                format!("must be between 1 and {EXPLORER_HISTORY_MAX_PER_PAGE}"),
            ));
        }
        let url = self.explorer_blocks_endpoint()?;
        let request = self.http.get(url).query(&[
            ("page", requested_page.to_string()),
            ("per_page", requested_per_page.to_string()),
        ]);
        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(ToriiError::UnexpectedStatus {
                status: response.status(),
                reject_code: None,
                message: None,
            });
        }
        let value = read_bounded_json_response(response, "Explorer blocks").await?;
        let page = ExplorerBlocksPage::from_json(&value)?;
        if page.pagination.page != requested_page {
            return Err(decode_error(
                "explorer blocks response.pagination.page",
                "does not match the requested page",
            ));
        }
        if page.pagination.per_page != requested_per_page {
            return Err(decode_error(
                "explorer blocks response.pagination.per_page",
                "does not match the requested per_page",
            ));
        }
        Ok(page)
    }
    /// Fetch Explorer asset summaries from `/v1/explorer/assets`.
    pub async fn fetch_explorer_assets_page(
        &self,
        query: ExplorerAssetsQuery,
    ) -> ToriiResult<ExplorerAssetsPage> {
        let ExplorerAssetsQuery {
            cursor,
            limit,
            owned_by,
            definition,
        } = query;
        let requested_limit = limit.unwrap_or(EXPLORER_CURSOR_DEFAULT_LIMIT);
        let url = self.explorer_assets_endpoint()?;
        let mut request = self.http.get(url);
        let mut params: Vec<(&str, String)> = Vec::new();
        append_explorer_cursor_params(
            &mut params,
            cursor,
            Some(requested_limit),
            "explorer assets query",
        )?;
        let owned_by = validate_explorer_account_filter(owned_by)?;
        if let Some(owned_by) = owned_by.as_ref() {
            params.push(("owned_by", owned_by.clone()));
        }
        let definition = validate_explorer_definition_filter(definition)?;
        if let Some(definition) = definition.as_ref() {
            params.push(("definition", definition.clone()));
        }
        if !params.is_empty() {
            request = request.query(&params);
        }
        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(ToriiError::UnexpectedStatus {
                status: response.status(),
                reject_code: None,
                message: None,
            });
        }
        let value = read_bounded_json_response(response, "Explorer assets").await?;
        let page = ExplorerAssetsPage::from_json(&value)?;
        if page.pagination.limit != requested_limit {
            return Err(decode_error(
                "explorer assets response.pagination.limit",
                "does not match the requested limit",
            ));
        }
        for item in &page.items {
            if owned_by
                .as_ref()
                .is_some_and(|expected| item.account_id != *expected)
            {
                return Err(decode_error(
                    "explorer assets response.items[].account_id",
                    "does not match the requested owned_by filter",
                ));
            }
            if definition
                .as_ref()
                .is_some_and(|expected| item.definition_id != *expected)
            {
                return Err(decode_error(
                    "explorer assets response.items[].definition_id",
                    "does not match the requested definition filter",
                ));
            }
        }
        Ok(page)
    }
    fn http_endpoint(&self, path: &str) -> ToriiResult<Url> {
        self.http_base
            .join(path.trim_start_matches('/'))
            .map_err(ToriiError::InvalidEndpoint)
    }
    fn ws_endpoint(&self, path: &str) -> ToriiResult<Url> {
        self.ws_base
            .join(path.trim_start_matches('/'))
            .map_err(ToriiError::InvalidEndpoint)
    }
    async fn fetch_json(&self, url: Url) -> ToriiResult<json::Value> {
        let response = self.http.get(url).send().await?;
        if !response.status().is_success() {
            return Err(response_status_error(&response));
        }
        read_bounded_json_response(response, "JSON API").await
    }
    async fn post_mcp_json(
        &self,
        url: Url,
        method: &'static str,
        name: Option<&str>,
        payload: &json::Value,
    ) -> ToriiResult<json::Value> {
        let body = json::to_vec(payload).map_err(|err| ToriiError::Decode(err.to_string()))?;
        let mut request = self
            .http
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header(
                torii_mcp::HEADER_PROTOCOL_VERSION,
                torii_mcp::MODERN_PROTOCOL_VERSION,
            )
            .header(torii_mcp::HEADER_METHOD, method);
        if let Some(name) = name {
            request = request.header(
                torii_mcp::HEADER_NAME,
                torii_mcp::encode_mirrored_header_value(name),
            );
        }
        let response = request.body(body).send().await?;
        if !response.status().is_success() {
            return Err(response_status_error(&response));
        }
        read_bounded_json_response(response, "JSON API").await
    }
    async fn mcp_discover(&self) -> ToriiResult<json::Value> {
        let url = self.mcp_endpoint()?;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": (torii_mcp::MODERN_PROTOCOL_VERSION),
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "mochi-local-sandbox",
                        "version": "1"
                    }
                }
            }
        });
        self.post_mcp_json(url, "server/discover", None, &payload)
            .await
    }
    async fn mcp_tools_list(&self) -> ToriiResult<json::Value> {
        let url = self.mcp_endpoint()?;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": (torii_mcp::MODERN_PROTOCOL_VERSION),
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "mochi-local-sandbox",
                        "version": "1"
                    }
                }
            }
        });
        self.post_mcp_json(url, "tools/list", None, &payload).await
    }
}

#[cfg(test)]
include!("torii/commit_wait_test_support.rs");
/// Stage of decoding when a failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockDecodeStage {
    /// Failed to parse the Norito frame.
    Frame,
    /// Underlying WebSocket stream aborted.
    Stream,
}
/// Details about a block stream decoding failure.
#[derive(Debug, Clone)]
pub struct BlockStreamDecodeError {
    /// Stage where decoding failed.
    pub stage: BlockDecodeStage,
    /// Length of the raw frame that triggered the error, if known.
    pub raw_len: Option<usize>,
    /// Human-readable error description.
    pub message: String,
    /// Structured SDK error when the failure originated from a subscription.
    pub source: Option<Arc<iroha::Error>>,
}
impl BlockStreamDecodeError {
    fn new(stage: BlockDecodeStage, raw_len: Option<usize>, message: impl Into<String>) -> Self {
        Self {
            stage,
            raw_len,
            message: message.into(),
            source: None,
        }
    }
}
/// Lightweight view over fields commonly displayed for blocks in the UI.
#[derive(Debug, Clone)]
pub struct BlockSummary {
    /// Block height (`1`-indexed).
    pub height: u64,
    /// Hex-encoded block hash.
    pub hash_hex: String,
    /// Number of ordinary or native network transaction inputs in the block.
    pub transaction_count: usize,
    /// Number of rejected transactions recorded in the block results.
    pub rejected_transaction_count: usize,
    /// Number of scheduled invocations recorded in the block's typed outputs.
    pub time_trigger_count: usize,
    /// Number of validator signatures attached to the block.
    pub signature_count: usize,
    /// View change index recorded by Sumeragi.
    pub view_change_index: u64,
    /// Unix timestamp of block creation in milliseconds.
    pub creation_time_ms: u64,
    /// Whether the block is the genesis block.
    pub is_genesis: bool,
}
impl BlockSummary {
    fn from_block(block: &SignedBlock) -> Self {
        let header = block.header();
        let transaction_count = block.network_entrypoint_count();
        let time_trigger_count = block
            .execution_outputs()
            .iter()
            .filter(|output| matches!(output, ExecutionOutputV1::Time(_)))
            .count();
        let rejected_transaction_count = block
            .execution_outputs()
            .iter()
            .filter(|output| {
                matches!(output, ExecutionOutputV1::Network(row) if row.result.as_ref().is_err())
            })
            .count();
        let signature_count = block.signatures().len();
        Self {
            height: header.height().get(),
            hash_hex: block.hash().to_string(),
            transaction_count,
            rejected_transaction_count,
            time_trigger_count,
            signature_count,
            view_change_index: header.view_change_index(),
            creation_time_ms: header
                .creation_time()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            is_genesis: header.is_genesis(),
        }
    }
}
/// Events emitted by the decoded block stream helper.
#[derive(Debug, Clone)]
pub enum BlockStreamEvent {
    /// Successfully decoded block payload.
    Block {
        /// Summary used by UI presenters.
        summary: BlockSummary,
        /// Shared block instance for richer viewers.
        block: Arc<SignedBlock>,
        /// Length of the raw frame before decoding.
        raw_len: usize,
    },
    /// Local lifecycle notice, including reconnection notices with peer aliases.
    Text { text: String },
    /// Decoding or transport error.
    DecodeError { error: BlockStreamDecodeError },
    /// Broadcast receiver lagged behind the producer.
    Lagged { skipped: usize },
    /// Stream closed cleanly.
    Closed,
}
include!("torii/block_stream_runtime.rs");
/// Categories of events emitted by Torii.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventCategory {
    /// Pipeline event (blocks, transactions, warnings).
    Pipeline,
    /// Data event reflecting state changes.
    Data,
    /// Time trigger event.
    Time,
    /// Trigger execution request event.
    ExecuteTrigger,
    /// Trigger completion event.
    TriggerCompleted,
}
impl EventCategory {
    pub fn label(self) -> &'static str {
        match self {
            EventCategory::Pipeline => "Pipeline",
            EventCategory::Data => "Data",
            EventCategory::Time => "Time",
            EventCategory::ExecuteTrigger => "Execute Trigger",
            EventCategory::TriggerCompleted => "Trigger Completed",
        }
    }
}
/// Lightweight summary of a decoded Torii event.
#[derive(Debug, Clone)]
pub struct EventSummary {
    /// Event category used for grouping in the UI.
    pub category: EventCategory,
    /// Short label describing the specific variant.
    pub label: String,
    /// Optional human-readable detail string.
    pub detail: Option<String>,
}
impl EventSummary {
    fn from_event(event: &EventBox) -> Self {
        match event {
            EventBox::Pipeline(pipeline) => {
                let (label, detail) = pipeline_summary(pipeline);
                Self {
                    category: EventCategory::Pipeline,
                    label,
                    detail,
                }
            }
            EventBox::PipelineBatch(events) => Self {
                category: EventCategory::Pipeline,
                label: "Pipeline Batch".to_owned(),
                detail: Some(format!("count={}", events.len())),
            },
            EventBox::Data(data) => {
                let (label, detail) = data_summary(data.as_ref());
                Self {
                    category: EventCategory::Data,
                    label,
                    detail: Some(detail),
                }
            }
            EventBox::Time(time_event) => {
                let interval = time_event.interval();
                let since_ms = interval.since().as_millis();
                let length_ms = interval.length().as_millis();
                Self {
                    category: EventCategory::Time,
                    label: "Interval".to_owned(),
                    detail: Some(format!("since={since_ms}ms length={length_ms}ms")),
                }
            }
            EventBox::ExecuteTrigger(exec) => {
                let trigger = exec.trigger_id();
                let authority = exec.authority();
                Self {
                    category: EventCategory::ExecuteTrigger,
                    label: format!("Trigger {trigger:?}"),
                    detail: Some(format!("authority={authority:?}")),
                }
            }
            EventBox::TriggerCompleted(completed) => Self {
                category: EventCategory::TriggerCompleted,
                label: "Outcome".to_owned(),
                detail: Some(format!("{completed:?}")),
            },
        }
    }
}
fn pipeline_summary(event: &PipelineEventBox) -> (String, Option<String>) {
    match event {
        PipelineEventBox::Transaction(transaction) => {
            let status = transaction.status();
            let height = transaction
                .block_height()
                .map(|h| h.get().to_string())
                .unwrap_or_else(|| "—".to_owned());
            let detail = format!("hash={:?} height={height}", transaction.hash());
            (format!("Transaction {status:?}"), Some(detail))
        }
        PipelineEventBox::Block(block) => {
            let header = block.header();
            let detail = format!(
                "height={} view={}",
                header.height().get(),
                header.view_change_index(),
            );
            (
                format!("Block {status:?}", status = block.status()),
                Some(detail),
            )
        }
        PipelineEventBox::Warning(warning) => ("Warning".to_owned(), Some(format!("{warning:?}"))),
        PipelineEventBox::Witness(witness) => ("Witness".to_owned(), Some(format!("{witness:?}"))),
    }
}
#[allow(unreachable_patterns)]
fn data_summary(event: &DataEvent) -> (String, String) {
    match event {
        DataEvent::Peer(peer) => peer_event_summary(peer),
        DataEvent::Domain(domain) => domain_event_summary(domain),
        DataEvent::Account(account) => account_event_summary(account),
        DataEvent::Asset(asset) => asset_event_summary(asset),
        DataEvent::AssetDefinition(definition) => asset_definition_event_summary(definition),
        DataEvent::Trigger(trigger) => ("Trigger".to_owned(), format!("{trigger:?}")),
        DataEvent::Role(role) => ("Role".to_owned(), format!("{role:?}")),
        DataEvent::Configuration(config) => ("Configuration".to_owned(), format!("{config:?}")),
        DataEvent::Executor(executor) => ("Executor".to_owned(), format!("{executor:?}")),
        DataEvent::Proof(proof) => ("Proof".to_owned(), format!("{proof:?}")),
        DataEvent::VerifyingKey(key) => ("VerifyingKey".to_owned(), format!("{key:?}")),
        DataEvent::RuntimeUpgrade(upgrade) => ("RuntimeUpgrade".to_owned(), format!("{upgrade:?}")),
        DataEvent::SmartContract(contract) => ("SmartContract".to_owned(), format!("{contract:?}")),
        DataEvent::Soradns(event) => ("Soradns".to_owned(), format!("{event:?}")),
        DataEvent::Sorafs(event) => sorafs_event_summary(event),
        DataEvent::SpaceDirectory(directory) => {
            ("SpaceDirectory".to_owned(), format!("{directory:?}"))
        }
        _ => ("Data".to_owned(), format!("{event:?}")),
    }
}
fn peer_event_summary(event: &PeerEvent) -> (String, String) {
    match event {
        PeerEvent::Added(peer) => ("Peer added".to_owned(), format!("{peer}")),
        PeerEvent::Removed(peer) => ("Peer removed".to_owned(), format!("{peer}")),
    }
}
fn domain_event_summary(event: &DomainEvent) -> (String, String) {
    match event {
        DomainEvent::Created(domain) => ("Domain created".to_owned(), domain.id().to_string()),
        DomainEvent::Deleted(id) => ("Domain deleted".to_owned(), id.to_string()),
        DomainEvent::Account(account) => account_event_summary(&account.event),
        DomainEvent::Asset(asset) => asset_event_summary(&asset.event),
        DomainEvent::AssetDefinition(definition) => {
            asset_definition_event_summary(&definition.event)
        }
        DomainEvent::Nft(nft) => nft_event_summary(nft),
        DomainEvent::MetadataInserted(change) => (
            "Domain metadata inserted".to_owned(),
            format!("domain={} key={}", change.target(), change.key()),
        ),
        DomainEvent::MetadataRemoved(change) => (
            "Domain metadata removed".to_owned(),
            format!("domain={} key={}", change.target(), change.key()),
        ),
        DomainEvent::OwnerChanged(change) => {
            ("Domain owner changed".to_owned(), format!("{change:?}"))
        }
        other => ("Domain event".to_owned(), format!("{other:?}")),
    }
}
fn account_event_summary(event: &AccountEvent) -> (String, String) {
    match event {
        AccountEvent::Created(account) => (
            "Account created".to_owned(),
            account.account.id().to_string(),
        ),
        AccountEvent::Deleted(id) => ("Account deleted".to_owned(), id.to_string()),
        AccountEvent::ControllerReplaced(change) => (
            "Account controller replaced".to_owned(),
            format!(
                "account={} previous_account={} previous_controller={} new_controller={}",
                change.account,
                change.previous_account,
                change.previous_controller,
                change.new_controller
            ),
        ),
        AccountEvent::PermissionAdded(change) => (
            "Account permission granted".to_owned(),
            format!("{change:?}"),
        ),
        AccountEvent::PermissionRemoved(change) => (
            "Account permission revoked".to_owned(),
            format!("{change:?}"),
        ),
        AccountEvent::RoleGranted(change) => {
            ("Account role granted".to_owned(), format!("{change:?}"))
        }
        AccountEvent::RoleRevoked(change) => {
            ("Account role revoked".to_owned(), format!("{change:?}"))
        }
        AccountEvent::MetadataInserted(change) => (
            "Account metadata inserted".to_owned(),
            format!("account={} key={}", change.target(), change.key()),
        ),
        AccountEvent::MetadataRemoved(change) => (
            "Account metadata removed".to_owned(),
            format!("account={} key={}", change.target(), change.key()),
        ),
        AccountEvent::Recovery(recovery_event) => account_recovery_event_summary(recovery_event),
        AccountEvent::Repo(repo_event) => repo_account_event_summary(repo_event),
    }
}
fn account_recovery_event_summary(event: &AccountRecoveryEvent) -> (String, String) {
    match event {
        AccountRecoveryEvent::PolicySet(payload) => (
            "Account recovery policy set".to_owned(),
            format!(
                "account={} alias={} guardians={} quorum={} timelock_ms={}",
                payload.account,
                account_alias_detail(&payload.alias),
                payload.policy.guardians().len(),
                payload.policy.quorum(),
                payload.policy.timelock_ms().get()
            ),
        ),
        AccountRecoveryEvent::PolicyCleared(payload) => (
            "Account recovery policy cleared".to_owned(),
            format!(
                "account={} alias={}",
                payload.account,
                account_alias_detail(&payload.alias)
            ),
        ),
        AccountRecoveryEvent::Proposed(payload) => (
            "Account recovery proposed".to_owned(),
            format!(
                "account={} alias={} proposed_by={} proposed_controller={} execute_after_ms={} approvals={}",
                payload.account,
                account_alias_detail(&payload.alias),
                payload.request.proposed_by,
                payload.request.proposed_controller,
                payload.request.execute_after_ms,
                payload.request.approvals.len()
            ),
        ),
        AccountRecoveryEvent::Approved(payload) => (
            "Account recovery approved".to_owned(),
            format!(
                "account={} alias={} approver={} approvals={}",
                payload.account,
                account_alias_detail(&payload.alias),
                payload.approver,
                payload.request.approvals.len()
            ),
        ),
        AccountRecoveryEvent::CancellationApproved(payload) => (
            "Account recovery cancellation approved".to_owned(),
            format!(
                "account={} alias={} approver={} cancellation_approvals={} status={:?}",
                payload.account,
                account_alias_detail(&payload.alias),
                payload.approver,
                payload.request.cancellation_approvals.len(),
                payload.request.status
            ),
        ),
        AccountRecoveryEvent::Cancelled(payload) => (
            "Account recovery cancelled".to_owned(),
            format!(
                "account={} alias={} cancelled_by={} status={:?}",
                payload.account,
                account_alias_detail(&payload.alias),
                payload.cancelled_by,
                payload.request.status
            ),
        ),
        AccountRecoveryEvent::Finalized(payload) => (
            "Account recovery finalized".to_owned(),
            format!(
                "account={} previous_account={} alias={} status={:?}",
                payload.account,
                payload.previous_account,
                account_alias_detail(&payload.alias),
                payload.request.status
            ),
        ),
    }
}
fn account_alias_detail(alias: &iroha_data_model::account::AccountAlias) -> String {
    let domain = alias
        .domain
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "-".to_owned());
    format!(
        "label={} domain={} dataspace={}",
        alias.label, domain, alias.dataspace
    )
}
fn repo_account_event_summary(event: &RepoAccountEvent) -> (String, String) {
    match event {
        RepoAccountEvent::Initiated(payload) => (
            "Repo agreement initiated".to_owned(),
            format!(
                "account={} counterparty={} agreement={}",
                payload.account(),
                payload.counterparty(),
                payload.agreement().id()
            ),
        ),
        RepoAccountEvent::Settled(payload) => (
            "Repo agreement settled".to_owned(),
            format!(
                "account={} agreement={} cash_leg={:?}",
                payload.account(),
                payload.agreement_id(),
                payload.cash_leg()
            ),
        ),
        RepoAccountEvent::MarginCalled(payload) => (
            "Repo margin call".to_owned(),
            format!(
                "account={} agreement={} timestamp_ms={}",
                payload.account(),
                payload.agreement_id(),
                payload.margin_timestamp_ms()
            ),
        ),
    }
}
fn asset_event_summary(event: &AssetEvent) -> (String, String) {
    match event {
        AssetEvent::Created(asset) => ("Asset created".to_owned(), asset.id().to_string()),
        AssetEvent::Deleted(id) => ("Asset deleted".to_owned(), id.to_string()),
        AssetEvent::Added(change) => (
            "Asset balance increased".to_owned(),
            format!("asset={} amount={}", change.asset(), change.amount()),
        ),
        AssetEvent::Removed(change) => (
            "Asset balance decreased".to_owned(),
            format!("asset={} amount={}", change.asset(), change.amount()),
        ),
        AssetEvent::Transferred(transfer) => (
            "Asset transferred".to_owned(),
            format!(
                "source={} destination={} amount={}",
                transfer.source(),
                transfer.destination(),
                transfer.amount()
            ),
        ),
        AssetEvent::MetadataInserted(change) => (
            "Asset metadata inserted".to_owned(),
            format!("asset={} key={}", change.target(), change.key()),
        ),
        AssetEvent::MetadataRemoved(change) => (
            "Asset metadata removed".to_owned(),
            format!("asset={} key={}", change.target(), change.key()),
        ),
        AssetEvent::BatchTransferOutcome(outcome) => (
            "Asset batch transfer leg".to_owned(),
            format!(
                "leg_index={} leg_id={} asset={} destination={} amount={} status={:?}",
                outcome.leg_index,
                outcome.leg_id,
                outcome.asset,
                outcome.destination,
                outcome.amount,
                outcome.status
            ),
        ),
    }
}
fn asset_definition_event_summary(event: &AssetDefinitionEvent) -> (String, String) {
    match event {
        AssetDefinitionEvent::Created(definition) => (
            "Asset definition created".to_owned(),
            definition.id().to_string(),
        ),
        AssetDefinitionEvent::Deleted(id) => {
            ("Asset definition deleted".to_owned(), id.to_string())
        }
        AssetDefinitionEvent::MetadataInserted(change) => (
            "Asset definition metadata inserted".to_owned(),
            format!("definition={} key={}", change.target(), change.key()),
        ),
        AssetDefinitionEvent::MetadataRemoved(change) => (
            "Asset definition metadata removed".to_owned(),
            format!("definition={} key={}", change.target(), change.key()),
        ),
        AssetDefinitionEvent::MintabilityChanged(id) => (
            "Asset definition mintability changed".to_owned(),
            id.to_string(),
        ),
        AssetDefinitionEvent::MintabilityChangedDetailed(change) => (
            "Asset definition mintability exhausted".to_owned(),
            format!("{change:?}"),
        ),
        AssetDefinitionEvent::TotalQuantityChanged(change) => (
            "Asset definition supply updated".to_owned(),
            format!("{change:?}"),
        ),
        AssetDefinitionEvent::OwnerChanged(change) => (
            "Asset definition owner changed".to_owned(),
            format!("{change:?}"),
        ),
    }
}
fn nft_event_summary(event: &NftEvent) -> (String, String) {
    match event {
        NftEvent::Created(nft) => ("NFT created".to_owned(), nft.id().to_string()),
        NftEvent::Deleted(id) => ("NFT deleted".to_owned(), id.to_string()),
        NftEvent::MetadataInserted(change) => (
            "NFT metadata inserted".to_owned(),
            format!("nft={} key={}", change.target(), change.key()),
        ),
        NftEvent::MetadataRemoved(change) => (
            "NFT metadata removed".to_owned(),
            format!("nft={} key={}", change.target(), change.key()),
        ),
        NftEvent::OwnerChanged(change) => ("NFT owner changed".to_owned(), format!("{change:?}")),
    }
}
fn sorafs_event_summary(event: &sorafs::SorafsGatewayEvent) -> (String, String) {
    match event {
        sorafs::SorafsGatewayEvent::GarViolation(payload) => {
            ("SoraFS GAR violation".to_owned(), format!("{payload:?}"))
        }
        sorafs::SorafsGatewayEvent::ProofHealth(alert) => {
            ("SoraFS proof health alert".to_owned(), format!("{alert:?}"))
        }
        sorafs::SorafsGatewayEvent::RepairLedger(payload) => (
            "SoraFS repair ledger event".to_owned(),
            format!("{payload:?}"),
        ),
        sorafs::SorafsGatewayEvent::ModerationLedger(payload) => (
            "SoraFS moderation ledger event".to_owned(),
            format!("{payload:?}"),
        ),
        sorafs::SorafsGatewayEvent::OrderbookLedger(payload) => (
            "SoraFS orderbook ledger event".to_owned(),
            format!("{payload:?}"),
        ),
        sorafs::SorafsGatewayEvent::ReserveLedger(payload) => (
            "SoraFS reserve ledger event".to_owned(),
            format!("{payload:?}"),
        ),
        sorafs::SorafsGatewayEvent::ReputationJournal(payload) => (
            "SoraFS reputation journal event".to_owned(),
            format!("{payload:?}"),
        ),
    }
}
/// Stage of decoding when a Torii event failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDecodeStage {
    /// Failed to parse the Norito frame.
    Frame,
    /// Underlying WebSocket stream aborted.
    Stream,
}
/// Details about a Torii event stream decoding failure.
#[derive(Debug, Clone)]
pub struct EventStreamDecodeError {
    /// Stage where decoding failed.
    pub stage: EventDecodeStage,
    /// Length of the raw frame that triggered the error, if known.
    pub raw_len: Option<usize>,
    /// Human-readable error description.
    pub message: String,
    /// Structured SDK error when the failure originated from a subscription.
    pub source: Option<Arc<iroha::Error>>,
}
impl EventStreamDecodeError {
    fn new(stage: EventDecodeStage, raw_len: Option<usize>, message: impl Into<String>) -> Self {
        Self {
            stage,
            raw_len,
            message: message.into(),
            source: None,
        }
    }
}
/// Events emitted by the decoded Torii event stream helper.
#[derive(Debug, Clone)]
pub enum EventStreamEvent {
    /// Successfully decoded event payload.
    Event {
        /// Summary used by UI presenters.
        summary: EventSummary,
        /// Shared event instance for richer viewers.
        event: Arc<EventBox>,
        /// Length of the raw frame before decoding.
        raw_len: usize,
    },
    /// Local lifecycle notice, including reconnection notices with peer aliases.
    Text { text: String },
    /// Decoding or transport error.
    DecodeError { error: EventStreamDecodeError },
    /// Broadcast receiver lagged behind the producer.
    Lagged { skipped: usize },
    /// Stream closed cleanly.
    Closed,
}
include!("torii/event_stream_runtime.rs");
include!("torii/managed_streams.rs");
#[cfg(test)]
mod tests {
    include!("torii/tests_part1.rs");
    include!("torii/tests_part2.rs");
}
