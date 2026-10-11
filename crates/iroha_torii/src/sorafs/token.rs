//! Stream token issuance helpers for Torii chunk-range gateways.
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use iroha_config::parameters::actual;
use iroha_core::state::{State as CoreState, StateReadOnly};
use iroha_crypto::PublicKey;
use rand::{rand_core::TryCryptoRng, rngs::OsRng};
use sorafs_manifest::token::{
    STREAM_TOKEN_MAX_RATE_LIMIT_BYTES_V1, STREAM_TOKEN_MAX_REQUESTS_PER_MINUTE_V1,
    STREAM_TOKEN_MAX_STREAMS_V1, StreamTokenBodyError, validate_token_body,
};
use sorafs_manifest::{
    STREAM_TOKEN_MAX_BASE64_BYTES_V1, STREAM_TOKEN_MAX_TTL_SECS_V1, STREAM_TOKEN_MAX_WIRE_BYTES_V1,
    StreamTokenBodyV1, StreamTokenError, StreamTokenV1,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use thiserror::Error;
/// Fixed rolling window applied to authenticated-subject issuance quotas.
const ISSUANCE_QUOTA_WINDOW: Duration = Duration::from_mins(1);
/// Maximum number of active authenticated issuance subjects retained by one gateway.
const MAX_ISSUANCE_SUBJECTS: usize = 4_096;
/// Maximum accepted encoded token header length.
pub(crate) const MAX_STREAM_TOKEN_BASE64_BYTES: usize = STREAM_TOKEN_MAX_BASE64_BYTES_V1;
/// Maximum accepted decoded token frame length.
const MAX_STREAM_TOKEN_WIRE_BYTES: usize = STREAM_TOKEN_MAX_WIRE_BYTES_V1;
/// Maximum issuance client identifier bytes.
pub(crate) const MAX_CLIENT_ID_BYTES: usize = 128;
/// Maximum echoed issuance nonce bytes.
pub(crate) const MAX_NONCE_BYTES: usize = 128;
#[cfg(any(test, feature = "test-fixtures"))]
#[path = "token/native_issuer_test_fixture.rs"]
pub mod native_issuer_test_fixture;
mod signer_binding;
mod signer_completed_finality;
mod signer_finality;
mod signer_lifecycle;
mod signer_pins;
mod signer_transport;
#[cfg(test)]
use rand::rand_core::TryRngCore;
use signer_finality::CoreFinalityV1;
use signer_lifecycle::{SignerDriverV1, SystemSignerClockV1};
pub use signer_pins::StreamTokenSignerPinsV1;
pub use signer_transport::{
    StreamTokenApprovedCustodyAnchorV1, StreamTokenObserverReplyV1, StreamTokenSignerCallErrorV1,
    StreamTokenSignerClientV1, StreamTokenSignerReceiptV1, StreamTokenStateObserverClientV1,
};
/// Issuer used to sign stream tokens with configured defaults.
pub struct StreamTokenIssuer {
    signer: SignerDriverV1,
    verifying_key: VerifyingKey,
    defaults: TokenDefaults,
    issuance_budgets: Mutex<BTreeMap<StreamTokenQuotaSubject, IssuanceBudget>>,
    max_issuance_budgets: usize,
    max_seen_epoch: AtomicU64,
}
/// Opaque, non-secret identity used for stream-token issuance accounting.
///
/// The subject is derived only after the exact-network operator signature has been authenticated.
/// Display labels such as `X-SoraFS-Client` must never be used to construct quota identities.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct StreamTokenQuotaSubject([u8; 32]);
impl StreamTokenQuotaSubject {
    const DERIVATION_CONTEXT: &'static str =
        "iroha.torii.sorafs.stream-token.issuance-quota-subject.v1";
    /// Derive a non-reversible quota subject from an authenticated operator public key.
    pub(crate) fn from_authenticated_operator(public_key: &PublicKey) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(Self::DERIVATION_CONTEXT);
        hasher.update(public_key.to_string().as_bytes());
        Self(*hasher.finalize().as_bytes())
    }
    /// Separate quota namespace for a canonical authenticated network account.
    pub(crate) fn from_authenticated_account(
        network: iroha_data_model::NetworkId,
        account: &iroha_data_model::account::AccountId,
    ) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(
            "iroha.torii.sorafs.stream-token.account-quota-subject.v1",
        );
        hasher.update(network.as_bytes());
        hasher.update(account.to_string().as_bytes());
        Self(*hasher.finalize().as_bytes())
    }
}
/// Default limits applied when overrides are not supplied.
#[derive(Debug, Clone, Copy)]
struct TokenDefaults {
    /// Key version embedded in issued tokens.
    key_version: u32,
    /// Default time-to-live in seconds.
    ttl_secs: u64,
    /// Default concurrent stream limit.
    max_streams: u16,
    /// Default per-token byte budget.
    rate_limit_bytes: u64,
    /// Default per-authenticated-subject issuance quota (requests per minute).
    requests_per_minute: u32,
}
/// Quota accounting snapshot for one authenticated issuance subject.
#[derive(Debug, Clone, Copy)]
struct IssuanceBudget {
    /// Start timestamp of the active quota window.
    window_start: Instant,
    /// Issuances already consumed within the window.
    used: u32,
}
/// Overrides supplied when minting a token.
#[derive(Copy, Clone, Debug, Default)]
pub struct TokenOverrides {
    /// Optional override for the token time-to-live in seconds.
    pub ttl_secs: Option<u64>,
    /// Optional override for the number of concurrent streams allowed.
    pub max_streams: Option<u16>,
    /// Optional override for the per-token byte rate limit.
    pub rate_limit_bytes: Option<u64>,
    /// Optional override for the per-token request quota (requests per minute).
    pub requests_per_minute: Option<u32>,
}
/// Result of a successful token issuance.
#[derive(Debug)]
pub struct TokenIssue {
    /// Signed stream token.
    pub token: StreamTokenV1,
    /// Remaining issuance quota within the current window.
    pub remaining_quota: u32,
}
impl StreamTokenIssuer {
    /// Construct an issuer from the Torii configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StreamTokenIssuerError`] if configuration and the injected
    /// runtime signer do not form one exact, safe binding.
    pub fn from_config(
        storage: &actual::SorafsStorage,
        chain_id: &str,
        network_id: [u8; 32],
        client: Option<Arc<dyn StreamTokenSignerClientV1>>,
        observer: Option<Arc<dyn StreamTokenStateObserverClientV1>>,
        approved: Option<StreamTokenApprovedCustodyAnchorV1>,
        state: Arc<CoreState>,
    ) -> Result<Option<Self>, StreamTokenIssuerError> {
        let pins = StreamTokenSignerPinsV1::from_config(storage, chain_id, network_id)?;
        let Some(pins) = pins else {
            return if client.is_none() && observer.is_none() && approved.is_none() {
                Ok(None)
            } else {
                Err(StreamTokenIssuerError::UnexpectedSignerDependency)
            };
        };
        let client = client.ok_or(StreamTokenIssuerError::MissingSignerClient)?;
        let observer = observer.ok_or(StreamTokenIssuerError::MissingStateObserver)?;
        let approved = approved.ok_or(StreamTokenIssuerError::MissingApprovedAnchor)?;
        {
            let view = state.view();
            if view.chain_id().as_ref() != chain_id || view.network_id().as_bytes() != &network_id {
                return Err(StreamTokenIssuerError::SignerBindingMismatch);
            }
        }
        // Validate local defaults before any observer I/O or private operation.
        Self::configured_defaults(&storage.stream_tokens, &pins)?.validate()?;
        let finality = Arc::new(CoreFinalityV1::new(state, pins.clone()));
        let driver = SignerDriverV1::new(
            pins,
            client,
            observer,
            approved,
            finality,
            Arc::new(SystemSignerClockV1),
        )?;
        Self::from_signer(&storage.stream_tokens, driver).map(Some)
    }
    fn configured_defaults(
        config: &actual::SorafsTokenConfig,
        pins: &StreamTokenSignerPinsV1,
    ) -> Result<TokenDefaults, StreamTokenIssuerError> {
        Ok(TokenDefaults {
            key_version: u32::try_from(pins.binding().key_revision)
                .map_err(|_| StreamTokenIssuerError::InvalidSignerConfig)?,
            ttl_secs: config.default_ttl_secs,
            max_streams: config.default_max_streams,
            rate_limit_bytes: config.default_rate_limit_bytes,
            requests_per_minute: config.default_requests_per_minute,
        })
    }
    fn from_signer(
        config: &actual::SorafsTokenConfig,
        signer: SignerDriverV1,
    ) -> Result<Self, StreamTokenIssuerError> {
        let defaults = Self::configured_defaults(config, signer.pins())?;
        defaults.validate()?;
        let bytes: [u8; 32] = signer
            .pins()
            .binding()
            .public_key
            .to_bytes()
            .1
            .try_into()
            .map_err(|_| StreamTokenIssuerError::InvalidSignerConfig)?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| StreamTokenIssuerError::InvalidSignerConfig)?;
        Ok(Self {
            signer,
            verifying_key,
            defaults,
            issuance_budgets: Mutex::new(BTreeMap::new()),
            max_issuance_budgets: MAX_ISSUANCE_SUBJECTS,
            max_seen_epoch: AtomicU64::new(0),
        })
    }
    /// Shared issuer with optional explicit admitted account-read ceilings.
    /// The caller authenticates and revalidates the policy against native state.
    pub(crate) fn issue_token(
        &self,
        quota_subject: StreamTokenQuotaSubject,
        manifest_cid: Vec<u8>,
        provider_id: [u8; 32],
        profile_handle: String,
        overrides: TokenOverrides,
        policy: Option<&sorafs_manifest::provider_advert::account_read::RegisteredAccountReadV1>,
    ) -> Result<TokenIssue, StreamTokenIssuerError> {
        let mut limits = self.defaults;
        if let Some(policy) = policy {
            policy
                .validate()
                .map_err(|_| StreamTokenIssuerError::InvalidPolicy {
                    field: "account_read",
                    reason: "invalid admitted policy".into(),
                })?;
            limits.ttl_secs = limits.ttl_secs.min(policy.ttl_secs);
            limits.max_streams = limits.max_streams.min(policy.max_streams);
            limits.rate_limit_bytes = limits.rate_limit_bytes.min(policy.rate_limit_bytes);
            limits.requests_per_minute = limits.requests_per_minute.min(policy.requests_per_minute);
        }
        let ttl_secs = checked_override("ttl_secs", overrides.ttl_secs, limits.ttl_secs)?;
        let max_streams =
            checked_override("max_streams", overrides.max_streams, limits.max_streams)?;
        let rate_limit_bytes = checked_override(
            "rate_limit_bytes",
            overrides.rate_limit_bytes,
            limits.rate_limit_bytes,
        )?;
        let requests_per_minute = checked_override(
            "requests_per_minute",
            overrides.requests_per_minute,
            limits.requests_per_minute,
        )?;
        let now = self.signer.now_unix_ms()? / 1_000;
        self.observe_epoch(now)?;
        let ttl_epoch = now
            .checked_add(ttl_secs)
            .ok_or(StreamTokenIssuerError::TimeOverflow)?;
        let body = StreamTokenBodyV1 {
            token_id: new_token_id()?,
            manifest_cid,
            provider_id,
            profile_handle,
            max_streams,
            ttl_epoch,
            rate_limit_bytes,
            issued_at: now,
            requests_per_minute,
            token_pk_version: self.defaults.key_version,
        };
        validate_token_body(&body)?;
        // Refuse before charging issuance quota when finalized completed-operation proof has
        // no production source. The signer repeats this check before provider I/O.
        self.signer.require_completed_proof_source()?;
        let remaining_quota = self.reserve_issuance_budget(
            quota_subject,
            Instant::now(),
            limits.requests_per_minute,
        )?;
        let token = self.signer.sign(body)?;
        Ok(TokenIssue {
            token,
            remaining_quota,
        })
    }
    /// Fresh signer custody authorization for this serving request, after static token checks.
    /// Returns the trusted final admission time; no qualification is cached for later requests.
    pub(crate) fn before_admission(
        &self,
        body: &StreamTokenBodyV1,
    ) -> Result<u64, StreamTokenIssuerError> {
        self.signer.before_admission(body)
    }
    /// Return the Ed25519 verifying key bytes.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
    /// Return a reference to the verifying key used for stream tokens.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
    /// Return the default key version embedded in issued tokens.
    #[must_use]
    pub fn key_version(&self) -> u32 {
        self.defaults.key_version
    }
    fn reserve_issuance_budget(
        &self,
        quota_subject: StreamTokenQuotaSubject,
        now: Instant,
        limit: u32,
    ) -> Result<u32, StreamTokenIssuerError> {
        let mut budgets = self
            .issuance_budgets
            .lock()
            .map_err(|_| StreamTokenIssuerError::IssuanceQuotaStateUnavailable)?;
        budgets.retain(|_, budget| {
            now.saturating_duration_since(budget.window_start) < ISSUANCE_QUOTA_WINDOW
        });
        if let Some(budget) = budgets.get_mut(&quota_subject) {
            let elapsed = now.saturating_duration_since(budget.window_start);
            if budget.used >= limit {
                let remaining =
                    ISSUANCE_QUOTA_WINDOW.saturating_sub(elapsed.min(ISSUANCE_QUOTA_WINDOW));
                let retry_after_secs = remaining
                    .as_secs()
                    .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                    .max(1);
                return Err(StreamTokenIssuerError::IssuanceQuotaExceeded {
                    limit,
                    retry_after_secs,
                });
            }
            budget.used += 1;
            return Ok(limit - budget.used);
        }
        if budgets.len() >= self.max_issuance_budgets {
            return Err(StreamTokenIssuerError::IssuanceQuotaCapacityExceeded {
                capacity: self.max_issuance_budgets,
            });
        }
        budgets.insert(
            quota_subject,
            IssuanceBudget {
                window_start: now,
                used: 1,
            },
        );
        Ok(limit - 1)
    }
    fn observe_epoch(&self, now: u64) -> Result<(), StreamTokenIssuerError> {
        let previous = self.max_seen_epoch.fetch_max(now, Ordering::SeqCst);
        if now < previous {
            return Err(StreamTokenIssuerError::ClockRollback {
                observed_epoch: previous,
                current_epoch: now,
            });
        }
        Ok(())
    }
}
impl TokenDefaults {
    fn validate(self) -> Result<(), StreamTokenIssuerError> {
        validate_bounded_nonzero("key_version", self.key_version, u32::MAX)?;
        validate_bounded_nonzero(
            "default_ttl_secs",
            self.ttl_secs,
            STREAM_TOKEN_MAX_TTL_SECS_V1,
        )?;
        validate_bounded_nonzero(
            "default_max_streams",
            self.max_streams,
            STREAM_TOKEN_MAX_STREAMS_V1,
        )?;
        validate_bounded_nonzero(
            "default_rate_limit_bytes",
            self.rate_limit_bytes,
            STREAM_TOKEN_MAX_RATE_LIMIT_BYTES_V1,
        )?;
        validate_bounded_nonzero(
            "default_requests_per_minute",
            self.requests_per_minute,
            STREAM_TOKEN_MAX_REQUESTS_PER_MINUTE_V1,
        )
    }
}
fn validate_bounded_nonzero<T>(
    field: &'static str,
    value: T,
    maximum: T,
) -> Result<(), StreamTokenIssuerError>
where
    T: Copy + Default + Ord + std::fmt::Display,
{
    if value == T::default() || value > maximum {
        return Err(StreamTokenIssuerError::InvalidPolicy {
            field,
            reason: format!("must be between 1 and {maximum} (found {value})"),
        });
    }
    Ok(())
}
fn checked_override<T>(
    field: &'static str,
    requested: Option<T>,
    ceiling: T,
) -> Result<T, StreamTokenIssuerError>
where
    T: Copy + Default + Ord + std::fmt::Display,
{
    let value = requested.unwrap_or(ceiling);
    if value == T::default() || value > ceiling {
        return Err(StreamTokenIssuerError::InvalidPolicy {
            field,
            reason: format!("must be between 1 and the configured ceiling {ceiling}"),
        });
    }
    Ok(value)
}
fn new_token_id() -> Result<String, StreamTokenIssuerError> {
    let mut rng = OsRng;
    new_token_id_with_rng(&mut rng)
}
fn new_token_id_with_rng<R: TryCryptoRng>(rng: &mut R) -> Result<String, StreamTokenIssuerError> {
    let mut bytes = [0u8; 16];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|err| StreamTokenIssuerError::RandomBytes {
            operation: "issuing stream token id",
            message: err.to_string(),
        })?;
    Ok(hex::encode(bytes))
}
/// Errors encountered while configuring or issuing stream tokens.
#[derive(Debug, Error)]
pub enum StreamTokenIssuerError {
    /// Disabled issuance received an unrequested client, observer or approved state pin.
    #[error("stream-token signer dependency injected while issuance is disabled")]
    UnexpectedSignerDependency,
    /// Enabled issuance requires the exact configured signer client.
    #[error("stream-token signer client is missing")]
    MissingSignerClient,
    /// Enabled issuance requires the independently authenticated observer transport.
    #[error("stream-token state observer is missing")]
    MissingStateObserver,
    /// Startup requires separately approved finalized custody control state.
    #[error("stream-token approved custody anchor is missing")]
    MissingApprovedAnchor,
    /// Public configuration was incomplete, noncanonical or lacked independent trust.
    #[error("invalid stream-token signer configuration")]
    InvalidSignerConfig,
    /// Client routing, immutable pins or authenticated chain context was substituted.
    #[error("stream-token signer binding mismatch")]
    SignerBindingMismatch,
    /// Signed custody, current-state or immutable completion evidence failed verification.
    #[error("stream-token signer evidence is invalid")]
    SignerEvidenceInvalid,
    /// Current custody, finality or concurrent publication state drifted.
    #[error("stream-token signer state changed")]
    SignerStateChanged,
    /// Exact local committed history and its authenticated finality were unavailable.
    #[error("stream-token signer finality is unavailable")]
    SignerFinalityUnavailable,
    /// The independently observed millisecond clock moved backwards.
    #[error("stream-token signer clock moved backwards")]
    SignerClockRollback,
    /// The bounded operation or its read-only recovery was unavailable.
    #[error("stream-token signer runtime unavailable")]
    RuntimeSignerUnavailable,
    /// The service refused the prepared operation.
    #[error("stream-token signer runtime refused request")]
    RuntimeSignerRefused,
    /// The bounded returned signature or transport shape was invalid.
    #[error("stream-token signer runtime produced invalid output")]
    RuntimeSignerOutputInvalid,
    /// A configured or requested token policy was zero, unsafe, or above its ceiling.
    #[error("invalid stream-token policy {field}: {reason}")]
    InvalidPolicy {
        /// Policy field that failed validation.
        field: &'static str,
        /// Human-readable constraint violation.
        reason: String,
    },
    /// The generated token body failed canonical structural validation.
    #[error("invalid stream-token body: {0}")]
    InvalidBody(#[from] StreamTokenBodyError),
    /// System clock produced a timestamp prior to the Unix epoch.
    #[error("system time before UNIX epoch")]
    TimeOverflow,
    /// The system wall clock moved backwards after a later issuance was observed.
    #[error("stream-token issuance clock moved backwards from {observed_epoch} to {current_epoch}")]
    ClockRollback {
        /// Greatest epoch previously observed by this issuer.
        observed_epoch: u64,
        /// Epoch observed for the current issuance attempt.
        current_epoch: u64,
    },
    /// Serialising the canonical stream-token body failed.
    #[error("failed to create stream token: {0}")]
    StreamToken(#[from] StreamTokenError),
    /// Random byte generation failed during stream token issuance.
    #[error("random byte generation failed while {operation}: {message}")]
    RandomBytes {
        /// Operation that requested random bytes.
        operation: &'static str,
        /// Underlying RNG error message.
        message: String,
    },
    /// The authenticated issuance subject exceeded its per-minute token quota.
    #[error("authenticated subject exceeded token issuance quota ({limit} requests/minute)")]
    IssuanceQuotaExceeded {
        /// Configured quota limit in requests per minute.
        limit: u32,
        /// Recommended retry delay in seconds before issuing another token.
        retry_after_secs: u64,
    },
    /// The bounded set of active issuance subjects is full.
    #[error("stream-token issuance state capacity exhausted ({capacity} active subjects)")]
    IssuanceQuotaCapacityExceeded {
        /// Maximum active issuance budgets retained by this process.
        capacity: usize,
    },
    /// The issuance accounting lock was poisoned; issuance fails closed.
    #[error("stream-token issuance quota state is unavailable")]
    IssuanceQuotaStateUnavailable,
}
/// Errors produced while decoding stream tokens from client headers.
#[derive(Debug, Error)]
pub enum StreamTokenHeaderError {
    /// The encoded header exceeded the strict transport ceiling.
    #[error("stream token header exceeds {maximum} bytes")]
    HeaderTooLong {
        /// Maximum accepted encoded header length.
        maximum: usize,
    },
    /// Header value was not valid base64.
    #[error("stream token header must be base64-encoded")]
    InvalidEncoding,
    /// Base64 text was valid but not in the canonical padded representation.
    #[error("stream token header must use canonical padded base64")]
    NonCanonicalEncoding,
    /// The decoded token frame exceeded the strict wire ceiling.
    #[error("decoded stream token exceeds {maximum} bytes")]
    PayloadTooLong {
        /// Maximum accepted decoded token length.
        maximum: usize,
    },
    /// The decoded token payload failed Norito deserialisation.
    #[error("invalid stream token payload: {0}")]
    InvalidPayload(norito::Error),
    /// The token body or signature shape violated canonical v1 constraints.
    #[error("invalid stream token body: {0}")]
    InvalidBody(#[from] StreamTokenBodyError),
    /// The Ed25519 signature did not have its fixed canonical length.
    #[error("stream token signature must be exactly 64 bytes")]
    InvalidSignatureLength,
}
/// Encode a stream token into base64 suitable for transport headers.
///
/// # Errors
///
/// Returns [`StreamTokenError`] when Norito encoding fails.
pub fn encode_token_base64(token: &StreamTokenV1) -> Result<String, StreamTokenError> {
    let bytes = norito::encode_canonical(token)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}
/// Decode a stream token provided in a transport header.
///
/// # Errors
///
/// Returns [`StreamTokenHeaderError`] when the payload is not valid base64 or fails Norito decoding.
pub fn decode_token_base64(value: &str) -> Result<StreamTokenV1, StreamTokenHeaderError> {
    if value.is_empty() {
        return Err(StreamTokenHeaderError::InvalidEncoding);
    }
    if value.len() > MAX_STREAM_TOKEN_BASE64_BYTES {
        return Err(StreamTokenHeaderError::HeaderTooLong {
            maximum: MAX_STREAM_TOKEN_BASE64_BYTES,
        });
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|_| StreamTokenHeaderError::InvalidEncoding)?;
    if base64::engine::general_purpose::STANDARD.encode(&bytes) != value {
        return Err(StreamTokenHeaderError::NonCanonicalEncoding);
    }
    if bytes.len() > MAX_STREAM_TOKEN_WIRE_BYTES {
        return Err(StreamTokenHeaderError::PayloadTooLong {
            maximum: MAX_STREAM_TOKEN_WIRE_BYTES,
        });
    }
    let token = decode_token_wire(&bytes)?;
    validate_token_body(&token.body)?;
    if token.signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(StreamTokenHeaderError::InvalidSignatureLength);
    }
    Ok(token)
}
// Same finite shape dimensions as the shared prepared body, with the sole fixed 64-byte
// signature leaf. The wire ceiling is checked before allocation; nested caller budgets intersect.
fn decode_token_wire(bytes: &[u8]) -> Result<StreamTokenV1, StreamTokenHeaderError> {
    if bytes.len() > MAX_STREAM_TOKEN_WIRE_BYTES {
        return Err(StreamTokenHeaderError::PayloadTooLong {
            maximum: MAX_STREAM_TOKEN_WIRE_BYTES,
        });
    }
    let allocation = 64 * 1024 + 8 * bytes.len(); // At most 80 KiB after the 2048-byte admission.
    norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(128, bytes.len(), 2048, allocation, 16),
    )
    .map_err(StreamTokenHeaderError::InvalidPayload)
}
#[cfg(test)]
#[path = "token/signer_finality_native_custody_tests.rs"]
mod signer_finality_native_custody_tests;
#[cfg(test)]
#[path = "token/signer_finality_tests.rs"]
mod signer_finality_tests;
#[cfg(test)]
#[path = "token/signer_pins_tests.rs"]
mod signer_pins_tests;
#[cfg(test)]
#[path = "token/signer_test_support.rs"]
pub(crate) mod signer_test_support;
#[cfg(test)]
#[path = "token/signer_wire_tests.rs"]
mod signer_wire_tests;
#[cfg(test)]
#[path = "token/signer_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "token/signer_admission_tests.rs"]
mod signer_admission_tests;
